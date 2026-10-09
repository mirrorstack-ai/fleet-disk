"""Build the MirrorStack fleet's L1 disk: `fleet-disk.py <serial>`, run by .github/workflows/disk.yml on a GitHub-hosted
runner. It fetches Ubuntu's noble cloud image of that serial with its SHA256SUMS and SHA256SUMS.gpg, checks the
signature with gpgv against the cloud-image key PINNED BY FINGERPRINT below, the image's sha256 against the signed line
and its qcow2 magic, converts it with `qemu-img convert -O vhdx` (Hyper-V) and `-O qcow2 -o compat=1.1`, uncompressed
(Linux L1), publishes both as the release assets of tag disk-noble-<serial> in this repo and prints the three lock
entries to paste into the fleet's carrier.lock.json: `disk_input` (the signed upstream image), `disk` (the VHDX) and
`disk_qcow2` (the qcow2, with its size; qemu-img's output is not promised byte-reproducible, so the owner's signature
over the lock is what vouches for each). It never edits the lock and refuses to overwrite a tag.
`fleet-disk.py arm64 <serial>` (the macOS lane) takes the same chain for Ubuntu's noble arm64 image at the ONE
pinned serial: the signed sha must equal the pinned one, vfkit's upstream bytes are re-checked against their pin, the
image becomes a raw GPT disk with an EFI System Partition (what vfkit's EFI boot needs) and a zstd of it is the one
release asset of disk-noble-arm64-<serial>; the lock entries are `disk_arm64_input`, `disk_arm64` and `vfkit`.
Standalone stdlib. An error names the rule and never echoes a value; every refusal is exit 1, a bad command line 2."""
from __future__ import annotations

import calendar
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Protocol

CLOUDIMAGE_KEY_FPR = 'D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81'  # UEC Image Automatic Signing Key, owner-confirmed
KEYRING = '/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg'  # the ubuntu-keyring package's; trust is the fingerprint
GPGV, QEMU_IMG, GH, ZSTD = '/usr/bin/gpgv', '/usr/bin/qemu-img', '/usr/bin/gh', '/usr/bin/zstd'
BASE = 'https://cloud-images.ubuntu.com/noble/'
IMAGE = 'noble-server-cloudimg-amd64.img'
IMAGE_ARM64 = 'noble-server-cloudimg-arm64.img'
ARM64_SERIAL = '20260926'  # the one serial the arm64 build accepts: another serial is a PR that changes this and both pins
ARM64_IMAGE_SHA256 = '1d6bffe64b848468ac97f821d369a4846d983de1800ccf6b5ec8853e85cefc55'  # noble-server-cloudimg-arm64.img
# in that serial's SHA256SUMS; the build still checks the list's signature, so a wrong pin fails closed
VFKIT_VERSION, VFKIT_SIZE = 'v0.6.4', 66431936
VFKIT_URL = f'https://github.com/crc-org/vfkit/releases/download/{VFKIT_VERSION}/vfkit'  # upstream's own, ad-hoc signed
VFKIT_SHA256 = '0ed83fc8ca7aa708598835480dba1362406aa7cd1dab3b27464eb76327d9652d'  # the digest GitHub lists for that asset
ESP_TYPE = bytes.fromhex('28732ac11ff8d211ba4b00a0c93ec93b')  # C12A7328-F81F-11D2-BA4B-00A0C93EC93B in GPT byte order
SECTOR = 512
ARCHES = ('amd64', 'arm64')
QCOW2_MAGIC = b'QFI\xfb'
SERIAL = re.compile(r'[0-9]{8}(?:\.[0-9]{1,2})?', re.ASCII)  # Ubuntu's build serials: 20260930 or 20260930.1
FPR = re.compile(r'[0-9A-F]{40}', re.ASCII)
REPO = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}', re.ASCII)
MAX_SUMS, MAX_IMAGE = 1 << 20, 2 << 30  # a longer SHA256SUMS or image is refused, not read to the end
MAX_RAW = 8 << 30  # the raw arm64 disk is sparse (about 3.5 GiB): one that is longer is refused
VHDX_OPTS = 'subformat=dynamic,block_size=1M'  # see build(): the smallest block Hyper-V's VHDX allows
QCOW2_OPTS = 'compat=1.1'  # the Linux disk, uncompressed and with no backing file; nothing relies on byte-for-byte rebuilds:
# the release pins the sha256 this run produced, and the carrier checks that
MAX_ASSET = 2 << 30  # GitHub release assets must be under 2 GiB: refuse here rather than fail at upload
CHUNK = 1 << 20
TOOL_TIMEOUT, CONVERT_TIMEOUT = 600, 1800  # seconds: gpgv and gh, qemu-img; a hung tool must not hold the job
FETCH_DEADLINE = 1500  # seconds for one whole download; urlopen's timeout is only per socket read
MAX_SKEW = 86400  # a signature stamped more than a day ahead of the clock is refused
USAGE, REFUSED = 2, 1


class Refused(ValueError):
    """A rule that stopped the build; the message is the rule's slug, never a value."""


class Io(Protocol):
    """The two things the build does to the world, so a test can fake both (no network, no qemu)."""

    def fetch(self, url: str, dest: Path, limit: int) -> str:
        """Write url's body to dest, at most limit bytes, and return its sha256 hex."""

    def run(self, argv: list[str], env: dict[str, str], timeout: int = TOOL_TIMEOUT) -> tuple[int, str]:
        """Run argv (absolute, no shell, no stdin) under exactly env, at most timeout seconds (default TOOL_TIMEOUT);
        return (exit status, stdout). A tool that outlives its timeout is Refused('tool-timeout')."""


class Real:
    def fetch(self, url: str, dest: Path, limit: int) -> str:
        digest, size, end = hashlib.sha256(), 0, time.monotonic() + FETCH_DEADLINE
        try:
            with urllib.request.urlopen(url, timeout=60) as src, dest.open('wb') as out:  # BASE: https, a constant
                while True:
                    if time.monotonic() > end:  # between reads; read1 returns after one recv, so a slow drip counts
                        raise Refused('fetch-timeout')
                    if not (chunk := src.read1(CHUNK)):
                        break
                    size += len(chunk)
                    if size > limit:
                        raise Refused('too-large')
                    digest.update(chunk)
                    out.write(chunk)
        except OSError:  # URLError, HTTPError and timeouts: the message would name the url
            raise Refused('fetch-failed') from None
        return digest.hexdigest()

    def run(self, argv: list[str], env: dict[str, str], timeout: int = TOOL_TIMEOUT) -> tuple[int, str]:
        try:
            done = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, shell=False,
                                  start_new_session=True, check=False, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise Refused('tool-timeout') from None
        except OSError:
            raise Refused('tool-missing') from None
        return done.returncode, done.stdout


BAD_STATUS = frozenset({'BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG'})  # gpgv exits 0 on these


def status_words(status: str) -> list[list[str]]:
    """gpgv's --status-fd lines that are `[GNUPG:] <KEYWORD> ...`, each as its words after the prefix."""
    return [words[1:] for words in (line.split() for line in status.splitlines()) if words[:1] == ['[GNUPG:]']]


def valid_sigs(status: str) -> list[tuple[set[str], str]]:
    """Each VALIDSIG in gpgv's --status-fd output as (its signing key and primary key, its signature timestamp word)."""
    return [({words[1].upper(), words[10].upper()}, words[3])
            for words in status_words(status) if words[:1] == ['VALIDSIG'] and len(words) >= 11]


def valid_fingerprints(status: str) -> set[str]:
    """The fingerprints gpgv's --status-fd output vouches for: each VALIDSIG's signing key and its primary key."""
    return set().union(*(fprs for fprs, _ in valid_sigs(status)))


def fresh_enough(stamp: str, serial: str, now: float) -> bool:
    """A signature stamped (epoch seconds) on or after the serial's date at 00:00 UTC and not more than MAX_SKEW ahead
    of now: SHA256SUMS does not name its serial, so an old signed list replayed under a newer serial fails here."""
    if not re.fullmatch(r'[0-9]{1,12}', stamp, re.ASCII):
        return False
    built = calendar.timegm(time.strptime(serial[:8], '%Y%m%d'))
    return built <= int(stamp) <= now + MAX_SKEW


def verify_signature(io: Io, sums: Path, sig: Path, fpr: str, serial: str, now: float) -> None:
    """SHA256SUMS is signed by the pinned key: gpgv must accept it, report a GOODSIG and no BADSIG, ERRSIG, EXPSIG,
    EXPKEYSIG or REVKEYSIG (an expired or revoked key still exits 0 with a VALIDSIG), AND a VALIDSIG of exactly fpr
    stamped no earlier than the serial's date (not a replayed older list) and not in the future."""
    code, status = io.run([GPGV, '--keyring', KEYRING, '--status-fd', '1', str(sig), str(sums)], {'PATH': '/usr/bin'})
    keywords = {words[0] for words in status_words(status) if words}
    if code != 0 or keywords & BAD_STATUS:
        raise Refused('bad-signature')
    if fpr not in valid_fingerprints(status):
        raise Refused('wrong-key')
    if 'GOODSIG' not in keywords:
        raise Refused('bad-signature')
    if not all(fresh_enough(stamp, serial, now) for fprs, stamp in valid_sigs(status) if fpr in fprs):
        raise Refused('stale-signature')


def signed_sha(sums: bytes, name: str) -> str:
    """The sha256 the signed SHA256SUMS lists for name (`<hex> *<name>`), exactly one line, or Refused."""
    lines = sums.decode('ascii', errors='replace').splitlines()
    found = [m[1] for m in (re.fullmatch(r'([0-9a-f]{64}) [ *](\S+)', line) for line in lines) if m and m[2] == name]
    if len(found) != 1:
        raise Refused('no-signed-sum')
    return found[0]


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def json_out(io: Io, argv: list[str], env: dict[str, str], kind: type, slug: str = 'tag-check-failed'):
    """argv's stdout parsed as JSON of the given type, or Refused(slug): a nonzero exit or any other shape refuses."""
    code, out = io.run(argv, env)
    try:
        data = json.loads(out) if code == 0 else None
    except ValueError:
        data = None
    if not isinstance(data, kind):
        raise Refused(slug)
    return data


def release_env(serial: str, fpr: str, repo: str, sha: str, token: str) -> dict[str, str]:
    """A bad serial, an unpinned key or a missing release environment is refused before any network call; return
    the environment gh runs under (the only one that sees the token)."""
    if not SERIAL.fullmatch(serial):
        raise Refused('serial')
    if not FPR.fullmatch(fpr):
        raise Refused('unpinned-key')
    if not (REPO.fullmatch(repo) and re.fullmatch(r'[0-9a-f]{40}', sha) and token):
        raise Refused('release-env')
    return {'PATH': '/usr/bin', 'GH_TOKEN': token, 'GH_REPO': repo, 'GH_PROMPT_DISABLED': '1'}


def tag_is_free(io: Io, repo: str, tag: str, env: dict[str, str]) -> None:
    """A release (drafts included) or a bare tag of that name exists: Refused. Fail closed: any answer but a clean
    "no such" (a 5xx, a rate limit, a timeout, unreadable output) is tag-check-failed, never "not found"."""
    refs = json_out(io, [GH, 'api', f'repos/{repo}/git/matching-refs/tags/{tag}'], env, list)  # a PREFIX match
    releases = json_out(io, [GH, 'release', 'list', '--limit', '1000', '--json', 'tagName,isDraft'], env, list)
    if (any(isinstance(r, dict) and r.get('ref') == f'refs/tags/{tag}' for r in refs)
            or any(isinstance(r, dict) and r.get('tagName') == tag for r in releases)):
        raise Refused('tag-exists')


def signed_image_sum(io: Io, base: str, name: str, work: Path, fpr: str, serial: str, now: float | None) -> str:
    """Fetch SHA256SUMS and its signature, check them against the pinned key, return the signed sha256 of name."""
    sums, sig = work / 'SHA256SUMS', work / 'SHA256SUMS.gpg'
    io.fetch(base + 'SHA256SUMS', sums, MAX_SUMS)
    io.fetch(base + 'SHA256SUMS.gpg', sig, MAX_SUMS)
    verify_signature(io, sums, sig, fpr, serial, time.time() if now is None else now)
    return signed_sha(sums.read_bytes(), name)


def fetch_image(io: Io, base: str, name: str, work: Path, want: str) -> Path:
    """Fetch the cloud image: its sha256 must be the signed one, and it must be a qcow2 (the second line of defense)."""
    image = work / name
    if io.fetch(base + name, image, MAX_IMAGE) != want:
        raise Refused('sum-mismatch')
    with image.open('rb') as f:
        if f.read(len(QCOW2_MAGIC)) != QCOW2_MAGIC:
            raise Refused('not-qcow2')
    return image


def convert(io: Io, image: Path, out: Path, fmt: str, opts: str = '') -> int:
    """qemu-img converts the verified qcow2 image to out in fmt; return the size written (a size, never a secret)."""
    argv = [QEMU_IMG, 'convert', '-f', 'qcow2', '-O', fmt, *(['-o', opts] if opts else []), str(image), str(out)]
    if io.run(argv, {'PATH': '/usr/bin'}, CONVERT_TIMEOUT)[0] != 0:
        raise Refused('convert-failed')
    print(f'fleet-disk: {fmt} {out.stat().st_size} bytes', file=sys.stderr, flush=True)
    return out.stat().st_size


def publish(io: Io, repo: str, tag: str, sha: str, env: dict[str, str], assets: list[Path], notes: str) -> dict[str, str]:
    """Create the release with exactly these assets, then read GitHub's digests back: they must be the files' own.
    Return each asset's sha256 by name; on a mismatch nothing is printed to sign."""
    digests = {a.name: file_sha(a) for a in assets}
    if io.run([GH, 'release', 'create', tag, *map(str, assets), '--target', sha, '--title', tag, '--notes', notes],
              env)[0] != 0:
        raise Refused('publish-failed')
    published = json_out(io, [GH, 'api', f'repos/{repo}/releases/tags/{tag}'], env, dict, 'publish-mismatch')
    got = published.get('assets')
    if not (isinstance(got, list) and len(got) == len(digests) and all(isinstance(a, dict) for a in got)
            and {a.get('name'): a.get('digest') for a in got} == {n: f'sha256:{d}' for n, d in digests.items()}):
        raise Refused('publish-mismatch')  # what GitHub now serves is not what was hashed
    return digests


def build(io: Io, serial: str, work: Path, repo: str, sha: str, token: str, fpr: str,
          now: float | None = None) -> dict:
    """Fetch, verify, convert and publish serial's disks; return the lock entries. Refusals come before any
    network call (serial, key, repo), then an existing tag or release (a check that cannot be answered refuses too),
    then in the order the evidence is strongest (signature, sum, magic), then each asset's size; after the upload the
    published assets are read back and must carry the digests the lock entries will state."""
    env = release_env(serial, fpr, repo, sha, token)
    tag = f'disk-noble-{serial}'
    tag_is_free(io, repo, tag, env)
    base = f'{BASE}{serial}/'
    want = signed_image_sum(io, base, IMAGE, work, fpr, serial, now)
    image = fetch_image(io, base, IMAGE, work, want)
    vhdx, qcow2 = work / f'noble-{serial}.vhdx', work / f'noble-{serial}.qcow2'
    # a dynamic VHDX allocates whole blocks: the default 32 MiB block over a sparse 3.5 GiB disk passed 2 GiB (the
    # first build, 2026-10-05); 1 MiB blocks keep the file near the data actually written
    for out, fmt, opts in ((vhdx, 'vhdx', VHDX_OPTS), (qcow2, 'qcow2', QCOW2_OPTS)):  # both from the one verified input
        if convert(io, image, out, fmt, opts) >= MAX_ASSET:
            raise Refused('too-big')
    digests = publish(io, repo, tag, sha, env, [vhdx, qcow2], f'Ubuntu noble {serial} as VHDX and qcow2')
    url = f'https://github.com/{repo}/releases/download/{tag}/'
    return {'disk_input': {'url': base + IMAGE, 'sha256': want},
            'disk': {'url': url + vhdx.name, 'sha256': digests[vhdx.name]},
            'disk_qcow2': {'url': url + qcow2.name, 'sha256': digests[qcow2.name], 'size': qcow2.stat().st_size}}


def has_esp(raw: Path) -> bool:
    """The raw disk is what vfkit's EFI boot needs: a protective MBR, a GPT header at LBA 1, an EFI System Partition.
    A header that points past what a file offset can hold is not such a disk (False), never an exception."""
    try:
        with raw.open('rb') as f:
            head = f.read(2 * SECTOR)
            if len(head) < 2 * SECTOR or head[510:512] != b'\x55\xaa' or head[SECTOR:SECTOR + 8] != b'EFI PART':
                return False
            lba, count, size = struct.unpack_from('<QII', head, SECTOR + 72)  # the entry table's LBA, count, entry size
            if not (lba >= 2 and size >= 128 and 0 < count * size <= 1 << 16):
                return False
            f.seek(lba * SECTOR)
            table = f.read(count * size)
    except (OverflowError, ValueError, OSError):
        return False
    return any(table[i:i + 16] == ESP_TYPE for i in range(0, len(table) - size + 1, size))


def build_arm64(io: Io, serial: str, work: Path, repo: str, sha: str, token: str, fpr: str,
                now: float | None = None) -> dict:
    """The macOS lane's disk: the pinned serial's signed noble arm64 image as a zstd'd raw GPT/EFI disk, the one asset
    of disk-noble-arm64-<serial>; vfkit's upstream bytes are re-checked on the way. Refusals come before any network
    call (serial and its pin, key, repo), then an existing tag, then signature, signed sum (it must be
    ARM64_IMAGE_SHA256), vfkit (sha and size), image, raw layout, asset size and round trip; the upload is read back."""
    env = release_env(serial, fpr, repo, sha, token)
    if serial != ARM64_SERIAL:
        raise Refused('serial-not-pinned')
    tag = f'disk-noble-arm64-{serial}'
    tag_is_free(io, repo, tag, env)
    base = f'{BASE}{serial}/'
    want = signed_image_sum(io, base, IMAGE_ARM64, work, fpr, serial, now)
    if want != ARM64_IMAGE_SHA256:
        raise Refused('image-pin-mismatch')
    vfkit = work / 'vfkit'  # never run here: only the bytes upstream serves are hashed and measured
    if io.fetch(VFKIT_URL, vfkit, VFKIT_SIZE) != VFKIT_SHA256 or vfkit.stat().st_size != VFKIT_SIZE:
        raise Refused('vfkit-mismatch')  # the size the lock entry states is the fetched file's own
    image = fetch_image(io, base, IMAGE_ARM64, work, want)
    raw, zst, again = work / f'noble-arm64-{serial}.raw', work / f'noble-arm64-{serial}.raw.zst', work / 'again.raw'
    if convert(io, image, raw, 'raw') > MAX_RAW:
        raise Refused('too-big')
    if not has_esp(raw):
        raise Refused('not-efi-disk')
    raw_sha, raw_size = file_sha(raw), raw.stat().st_size
    if io.run([ZSTD, '-19', '-T0', '-q', '-o', str(zst), str(raw)], {'PATH': '/usr/bin'}, CONVERT_TIMEOUT)[0] != 0:
        raise Refused('compress-failed')
    if zst.stat().st_size >= MAX_ASSET:
        raise Refused('too-big')
    if io.run([ZSTD, '-d', '-q', '-o', str(again), str(zst)], {'PATH': '/usr/bin'}, CONVERT_TIMEOUT)[0] != 0 \
            or file_sha(again) != raw_sha:  # the asset must expand to exactly the raw sha the lock will state
        raise Refused('roundtrip-mismatch')
    digests = publish(io, repo, tag, sha, env, [zst], f'Ubuntu noble arm64 {serial} as a raw disk, zstd, for vfkit')
    return {'disk_arm64_input': {'url': base + IMAGE_ARM64, 'sha256': want},
            'disk_arm64': {'url': f'https://github.com/{repo}/releases/download/{tag}/{zst.name}',
                           'sha256': digests[zst.name], 'size': zst.stat().st_size,
                           'raw_sha256': raw_sha, 'raw_size': raw_size},
            'vfkit': {'version': VFKIT_VERSION, 'url': VFKIT_URL, 'sha256': VFKIT_SHA256, 'size': VFKIT_SIZE}}


def main(argv: list[str], environ: dict[str, str], io: Io) -> int:
    """`fleet-disk.py [amd64|arm64] <serial>`, with GITHUB_REPOSITORY, GITHUB_SHA and GH_TOKEN in the environment."""
    args = argv[1:]
    arch = args.pop(0) if len(args) == 2 and args[0] in ARCHES else 'amd64'
    if len(args) != 1:
        sys.stderr.write('usage: fleet-disk.py [amd64|arm64] <serial>\n')
        return USAGE
    try:
        with tempfile.TemporaryDirectory(dir=environ.get('RUNNER_TEMP') or None) as tmp:
            job = (io, args[0], Path(tmp), environ.get('GITHUB_REPOSITORY', ''), environ.get('GITHUB_SHA', ''),
                   environ.get('GH_TOKEN', ''), CLOUDIMAGE_KEY_FPR)
            entries = build_arm64(*job) if arch == 'arm64' else build(*job)
    except Refused as why:
        sys.stderr.write(f'fleet-disk: refused {why}\n')
        return REFUSED
    sys.stdout.write("paste into the fleet's carrier.lock.json, then sign the lock:\n"
                     + json.dumps(entries, indent=1, sort_keys=True, ensure_ascii=True) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv, dict(os.environ), Real()))
