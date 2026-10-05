"""Build the MirrorStack fleet's L1 disk: `fleet-disk.py <serial>`, run by .github/workflows/disk.yml on a GitHub-hosted
runner. It fetches Ubuntu's noble cloud image of that serial with its SHA256SUMS and SHA256SUMS.gpg, checks the
signature with gpgv against the cloud-image key PINNED BY FINGERPRINT below, the image's sha256 against the signed line
and its qcow2 magic, converts it with `qemu-img convert -O vhdx`, publishes the VHDX as the release asset of tag
disk-noble-<serial> in this repo and prints the two lock entries to paste into the fleet's carrier.lock.json:
`disk_input` (the signed upstream image) and `disk` (the artifact; qemu-img's VHDX is not byte-reproducible, so the
owner's signature over the lock is what vouches for it). It never edits the lock and refuses to overwrite a tag.
Standalone stdlib. An error names the rule and never echoes a value; every refusal is exit 1, a bad command line 2."""
from __future__ import annotations

import calendar
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Protocol

CLOUDIMAGE_KEY_FPR = 'D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81'  # UEC Image Automatic Signing Key, owner-confirmed
KEYRING = '/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg'  # the ubuntu-keyring package's; trust is the fingerprint
GPGV, QEMU_IMG, GH = '/usr/bin/gpgv', '/usr/bin/qemu-img', '/usr/bin/gh'
BASE = 'https://cloud-images.ubuntu.com/noble/'
IMAGE = 'noble-server-cloudimg-amd64.img'
QCOW2_MAGIC = b'QFI\xfb'
SERIAL = re.compile(r'[0-9]{8}(?:\.[0-9]{1,2})?', re.ASCII)  # Ubuntu's build serials: 20260930 or 20260930.1
FPR = re.compile(r'[0-9A-F]{40}', re.ASCII)
REPO = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}', re.ASCII)
SHA = re.compile(r'[0-9a-f]{64}', re.ASCII)
MAX_SUMS, MAX_IMAGE = 1 << 20, 2 << 30  # a longer SHA256SUMS or image is refused, not read to the end
VHDX_OPTS = 'subformat=dynamic,block_size=1M'  # see build(): the smallest block Hyper-V's VHDX allows
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


def build(io: Io, serial: str, work: Path, repo: str, sha: str, token: str, fpr: str,
          now: float | None = None) -> dict:
    """Fetch, verify, convert and publish serial's disk; return the two lock entries. Refusals come before any
    network call (serial, key, repo), then an existing tag or release (a check that cannot be answered refuses too),
    then in the order the evidence is strongest (signature, sum, magic), then the asset's size; after the upload the
    published asset is read back and must carry the digest the lock entry will state."""
    if not SERIAL.fullmatch(serial):
        raise Refused('serial')
    if not FPR.fullmatch(fpr):
        raise Refused('unpinned-key')
    if not (REPO.fullmatch(repo) and re.fullmatch(r'[0-9a-f]{40}', sha) and token):
        raise Refused('release-env')
    tag = f'disk-noble-{serial}'
    env = {'PATH': '/usr/bin', 'GH_TOKEN': token, 'GH_REPO': repo, 'GH_PROMPT_DISABLED': '1'}
    # a release (drafts included) or a bare tag of that name exists: refuse. Fail closed: any answer but a clean
    # "no such" (a 5xx, a rate limit, a timeout, unreadable output) is tag-check-failed, never "not found".
    refs = json_out(io, [GH, 'api', f'repos/{repo}/git/matching-refs/tags/{tag}'], env, list)  # a PREFIX match
    releases = json_out(io, [GH, 'release', 'list', '--limit', '1000', '--json', 'tagName,isDraft'], env, list)
    if (any(isinstance(r, dict) and r.get('ref') == f'refs/tags/{tag}' for r in refs)
            or any(isinstance(r, dict) and r.get('tagName') == tag for r in releases)):
        raise Refused('tag-exists')
    base = f'{BASE}{serial}/'
    sums, sig, image, vhdx = work / 'SHA256SUMS', work / 'SHA256SUMS.gpg', work / IMAGE, work / f'noble-{serial}.vhdx'
    io.fetch(base + 'SHA256SUMS', sums, MAX_SUMS)
    io.fetch(base + 'SHA256SUMS.gpg', sig, MAX_SUMS)
    verify_signature(io, sums, sig, fpr, serial, time.time() if now is None else now)
    want = signed_sha(sums.read_bytes(), IMAGE)
    if io.fetch(base + IMAGE, image, MAX_IMAGE) != want:
        raise Refused('sum-mismatch')
    with image.open('rb') as f:
        if f.read(len(QCOW2_MAGIC)) != QCOW2_MAGIC:
            raise Refused('not-qcow2')
    # a dynamic VHDX allocates whole blocks: the default 32 MiB block over a sparse 3.5 GiB disk passed 2 GiB (the
    # first build, 2026-10-05); 1 MiB blocks keep the file near the data actually written
    if io.run([QEMU_IMG, 'convert', '-f', 'qcow2', '-O', 'vhdx', '-o', VHDX_OPTS, str(image), str(vhdx)],
              {'PATH': '/usr/bin'}, CONVERT_TIMEOUT)[0] != 0:
        raise Refused('convert-failed')
    size = vhdx.stat().st_size
    print(f'fleet-disk: vhdx {size} bytes', file=sys.stderr, flush=True)  # a size, never a secret: how close the limit is
    if size >= MAX_ASSET:
        raise Refused('too-big')
    disk = file_sha(vhdx)
    if io.run([GH, 'release', 'create', tag, str(vhdx), '--target', sha, '--title', tag,
               '--notes', f'Ubuntu noble {serial} as VHDX'], env)[0] != 0:
        raise Refused('publish-failed')
    published = json_out(io, [GH, 'api', f'repos/{repo}/releases/tags/{tag}'], env, dict, 'publish-mismatch')
    assets = published.get('assets')
    if not (isinstance(assets, list) and len(assets) == 1 and isinstance(assets[0], dict)
            and assets[0].get('name') == vhdx.name and assets[0].get('digest') == f'sha256:{disk}'):
        raise Refused('publish-mismatch')  # what GitHub now serves is not what was hashed: nothing is printed to sign
    return {'disk_input': {'url': base + IMAGE, 'sha256': want},
            'disk': {'url': f'https://github.com/{repo}/releases/download/{tag}/{vhdx.name}', 'sha256': disk}}


def main(argv: list[str], environ: dict[str, str], io: Io) -> int:
    """`fleet-disk.py <serial>`, with GITHUB_REPOSITORY, GITHUB_SHA and GH_TOKEN in the environment (the job's)."""
    if len(argv) != 2:
        sys.stderr.write('usage: fleet-disk.py <serial>\n')
        return USAGE
    try:
        with tempfile.TemporaryDirectory(dir=environ.get('RUNNER_TEMP') or None) as tmp:
            entries = build(io, argv[1], Path(tmp), environ.get('GITHUB_REPOSITORY', ''),
                            environ.get('GITHUB_SHA', ''), environ.get('GH_TOKEN', ''), CLOUDIMAGE_KEY_FPR)
    except Refused as why:
        sys.stderr.write(f'fleet-disk: refused {why}\n')
        return REFUSED
    sys.stdout.write("paste into the fleet's carrier.lock.json, then sign the lock:\n"
                     + json.dumps(entries, indent=1, sort_keys=True, ensure_ascii=True) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv, dict(os.environ), Real()))
