"""Build the MirrorStack fleet's L1 disk: `fleet-disk.py <serial>`, run by .github/workflows/disk.yml on a GitHub-hosted
runner. It fetches Ubuntu's noble cloud image of that serial with its SHA256SUMS and SHA256SUMS.gpg, checks the
signature with gpgv against the cloud-image key PINNED BY FINGERPRINT below, the image's sha256 against the signed line
and its qcow2 magic, converts it with `qemu-img convert -O vhdx`, publishes the VHDX as the release asset of tag
disk-noble-<serial> in this repo and prints the two lock entries to paste into the fleet's carrier.lock.json:
`disk_input` (the signed upstream image) and `disk` (the artifact; qemu-img's VHDX is not byte-reproducible, so the
owner's signature over the lock is what vouches for it). It never edits the lock and refuses to overwrite a tag.
Standalone stdlib. An error names the rule and never echoes a value; every refusal is exit 1, a bad command line 2."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
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
MAX_ASSET = 2 << 30  # GitHub release assets must be under 2 GiB: refuse here rather than fail at upload
CHUNK = 1 << 20
USAGE, REFUSED = 2, 1


class Refused(ValueError):
    """A rule that stopped the build; the message is the rule's slug, never a value."""


class Io(Protocol):
    """The two things the build does to the world, so a test can fake both (no network, no qemu)."""

    def fetch(self, url: str, dest: Path, limit: int) -> str:
        """Write url's body to dest, at most limit bytes, and return its sha256 hex."""

    def run(self, argv: list[str], env: dict[str, str]) -> tuple[int, str]:
        """Run argv (absolute, no shell, no stdin) under exactly env; return (exit status, stdout)."""


class Real:
    def fetch(self, url: str, dest: Path, limit: int) -> str:
        digest, size = hashlib.sha256(), 0
        try:
            with urllib.request.urlopen(url, timeout=60) as src, dest.open('wb') as out:  # BASE: https, a constant
                while chunk := src.read(CHUNK):
                    size += len(chunk)
                    if size > limit:
                        raise Refused('too-large')
                    digest.update(chunk)
                    out.write(chunk)
        except OSError:  # URLError, HTTPError and timeouts: the message would name the url
            raise Refused('fetch-failed') from None
        return digest.hexdigest()

    def run(self, argv: list[str], env: dict[str, str]) -> tuple[int, str]:
        try:
            done = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, shell=False,
                                  start_new_session=True, check=False)
        except OSError:
            raise Refused('tool-missing') from None
        return done.returncode, done.stdout


BAD_STATUS = frozenset({'BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG'})  # gpgv exits 0 on these


def status_words(status: str) -> list[list[str]]:
    """gpgv's --status-fd lines that are `[GNUPG:] <KEYWORD> ...`, each as its words after the prefix."""
    return [words[1:] for words in (line.split() for line in status.splitlines()) if words[:1] == ['[GNUPG:]']]


def valid_fingerprints(status: str) -> set[str]:
    """The fingerprints gpgv's --status-fd output vouches for: each VALIDSIG's signing key and its primary key."""
    out: set[str] = set()
    for words in status_words(status):
        if words[:1] == ['VALIDSIG'] and len(words) >= 11:
            out |= {words[1].upper(), words[10].upper()}
    return out


def verify_signature(io: Io, sums: Path, sig: Path, fpr: str) -> None:
    """SHA256SUMS is signed by the pinned key: gpgv must accept it, report a GOODSIG and no BADSIG, ERRSIG, EXPSIG,
    EXPKEYSIG or REVKEYSIG (an expired or revoked key still exits 0 with a VALIDSIG), AND a VALIDSIG of exactly fpr."""
    code, status = io.run([GPGV, '--keyring', KEYRING, '--status-fd', '1', str(sig), str(sums)], {'PATH': '/usr/bin'})
    keywords = {words[0] for words in status_words(status) if words}
    if code != 0 or keywords & BAD_STATUS:
        raise Refused('bad-signature')
    if fpr not in valid_fingerprints(status):
        raise Refused('wrong-key')
    if 'GOODSIG' not in keywords:
        raise Refused('bad-signature')


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


def build(io: Io, serial: str, work: Path, repo: str, sha: str, token: str, fpr: str) -> dict:
    """Fetch, verify, convert and publish serial's disk; return the two lock entries. Refusals come before any
    network call (serial, key, repo), then an existing tag, then in the order the evidence is strongest (signature,
    sum, magic), then the asset's size."""
    if not SERIAL.fullmatch(serial):
        raise Refused('serial')
    if not FPR.fullmatch(fpr):
        raise Refused('unpinned-key')
    if not (REPO.fullmatch(repo) and re.fullmatch(r'[0-9a-f]{40}', sha) and token):
        raise Refused('release-env')
    tag = f'disk-noble-{serial}'
    env = {'PATH': '/usr/bin', 'GH_TOKEN': token, 'GH_REPO': repo, 'GH_PROMPT_DISABLED': '1'}
    # a release or a bare tag of that name already exists (exit 0): releases are immutable once pinned
    if (io.run([GH, 'release', 'view', tag], env)[0] == 0
            or io.run([GH, 'api', f'repos/{repo}/git/ref/tags/{tag}'], env)[0] == 0):
        raise Refused('tag-exists')
    base = f'{BASE}{serial}/'
    sums, sig, image, vhdx = work / 'SHA256SUMS', work / 'SHA256SUMS.gpg', work / IMAGE, work / f'noble-{serial}.vhdx'
    io.fetch(base + 'SHA256SUMS', sums, MAX_SUMS)
    io.fetch(base + 'SHA256SUMS.gpg', sig, MAX_SUMS)
    verify_signature(io, sums, sig, fpr)
    want = signed_sha(sums.read_bytes(), IMAGE)
    if io.fetch(base + IMAGE, image, MAX_IMAGE) != want:
        raise Refused('sum-mismatch')
    with image.open('rb') as f:
        if f.read(len(QCOW2_MAGIC)) != QCOW2_MAGIC:
            raise Refused('not-qcow2')
    if io.run([QEMU_IMG, 'convert', '-f', 'qcow2', '-O', 'vhdx', str(image), str(vhdx)], {'PATH': '/usr/bin'})[0] != 0:
        raise Refused('convert-failed')
    if vhdx.stat().st_size >= MAX_ASSET:
        raise Refused('too-big')
    disk = file_sha(vhdx)
    if io.run([GH, 'release', 'create', tag, str(vhdx), '--target', sha, '--title', tag,
               '--notes', f'Ubuntu noble {serial} as VHDX'], env)[0] != 0:
        raise Refused('publish-failed')
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
