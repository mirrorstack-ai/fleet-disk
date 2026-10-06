"""Publish the MirrorStack fleet's owner-signed install set: `fleet-install-publish.py publish <dir> --owner-pub <path>
--min-serial N`, run by .github/workflows/install.yml on a GitHub-hosted runner (`verify <dir> ...` does the local
half only, with no network and no gh). <dir> is release/install-<serial>, committed here by PR. Everything the
release will carry is checked first, offline: install.json.sig verifies against the owner's public key under namespace
mirrorstack-fleet-install, every file's sha256 equals the signed one, no file is unlisted, deploy-pin.json is there with
its shape, signature and (when the bundle is in the release) the bundle's head and tree, and install.json is valid for at
least 30 more days. Each file is copied once into a private stage; the checks
and the upload use that copy. Only then does it refuse an existing tag install-<serial>, require
GitHub's Immutable releases setting, create the release with exactly those assets, read GitHub's digests back and
require the release to say immutable and not draft.
Standalone stdlib. An error names the rule and never echoes a value; a refusal is exit 1, a bad command line 2.

Section 1 is a vendored copy of the install.json verifier of the fleet's private repo (fleet/install/manifest.py, at
commit 433018e55d94a31afb42ec07670393ae3e8b9fae, the I01 merge): same schema, bounds, namespace, principal and refusal
codes. Two things differ and nothing else: its two helpers from that repo (strict JSON and the UTC time parser) are
inlined as _loads_strict and _parse_utc. tests/test_install_publish.py freezes the constants and the codes, so a
drift in either copy is a red test, not a silent fork. When I01's file changes, copy it again and move the commit id."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol

# ---------------------------------------------------------------------------------------------------------------
# 1. The vendored install.json verifier (see the top of the file for the commit it copies)
# ---------------------------------------------------------------------------------------------------------------

NS, PRINCIPAL = 'mirrorstack-fleet-install', 'owner'  # the pin's namespace is mirrorstack-fleet-pin: one per file kind
SSH_KEYGEN = 'C:\\Windows\\System32\\OpenSSH\\ssh-keygen.exe' if os.name == 'nt' else '/usr/bin/ssh-keygen'
KIND = 'install'
MAX_BYTES = 8192  # a manifest is ~700 bytes; a bigger file is refused before ssh-keygen sees it
MAX_BUNDLE = 1 << 30  # the bundle's byte cap, verify-archive's MAX_BYTES
MAX_COUNT = 1 << 31  # the cap of a serial
CODES = ('size', 'key', 'sig', 'form', 'kind', 'expired', 'rollback', 'tree')  # the word after REFUSED; a test pins it
HEX40, HEX64 = re.compile('[0-9a-f]{40}', re.ASCII), re.compile('[0-9a-f]{64}', re.ASCII)
UTC_TIME = re.compile('[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', re.ASCII)  # no fraction
_KEY = re.compile('[A-Za-z0-9+/]{68}', re.ASCII)  # an ssh-ed25519 blob: 51 bytes, no padding
_LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
URL = re.compile(rf'https://({_LABEL}(?:\.{_LABEL})+)/[A-Za-z0-9._~/-]{{1,200}}', re.ASCII)  # https, a host, a path
Run = Callable[[Sequence[str], bytes], tuple[int, bytes]]  # (absolute argv, stdin) -> (exit code, stdout)
InTree = Callable[[str, str], bool]  # (source_head, blob id) -> is that blob in the head's git tree
SCHEMA = ('kind', 'serial', 'valid_until', 'source_head', 'bootstrap', 'kit', 'lock_sha256', 'bundle')
BOOT_KEYS, KIT_KEYS = ('sha256', 'blob'), ('serial', 'kit_json_sha256')
BUNDLE_KEYS = ('head', 'tree', 'url', 'sha256', 'size')
OSES = ('ps1', 'sh')  # the two bootstraps


class Refused(Exception):
    """The word after REFUSED: one of CODES (section 1) or one of PUBLISH_CODES (section 2)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def run_argv(argv: Sequence[str], stdin: bytes) -> tuple[int, bytes]:
    """The one process call: argv as given (no shell, no PATH search), a minute at most; (127, b'') if it can't run."""
    try:
        done = subprocess.run(list(argv), input=stdin, capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return 127, b''
    return done.returncode, done.stdout


def _loads_strict(text: bytes) -> object:
    """Strict JSON (inlined from the private repo's fleet.core.canon.loads_strict): UTF-8 with no BOM, no NaN or
    Infinity (nor a number like 1e400 that reads as one), no duplicate key. Any refusal is `form`."""
    if text.startswith(b'\xef\xbb\xbf'):
        raise Refused('form')

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        obj: dict[str, object] = {}
        for key, value in items:
            if key in obj:
                raise ValueError('duplicate key')
            obj[key] = value
        return obj

    def constant(name: str) -> object:
        raise ValueError(name)

    def number(s: str) -> float:
        f = float(s)
        if not math.isfinite(f):
            raise ValueError('number too large')
        return f

    try:
        return json.loads(text.decode('utf-8'), parse_constant=constant, parse_float=number, object_pairs_hook=pairs)
    except (ValueError, RecursionError):  # UnicodeDecodeError and JSONDecodeError are ValueErrors
        raise Refused('form') from None


def _parse_utc(s: str) -> datetime:
    """A time like 2026-12-01T00:00:00Z (inlined from fleet.core.clock.parse_utc): ValueError if it is not one."""
    if not UTC_TIME.fullmatch(s):
        raise ValueError('not a UTC time')
    return datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def verify_signature(text: bytes, sig: bytes, owner_pub: bytes, run: Run = run_argv) -> None:
    """text counts only when sig verifies against the owner's one ssh-ed25519 line under NS and PRINCIPAL; else `key`
    (the key line is off-shape) or `sig`."""
    words = owner_pub.decode('ascii', 'replace').split()
    if len(words) < 2 or words[0] != 'ssh-ed25519' or not _KEY.fullmatch(words[1]):
        raise Refused('key')
    with tempfile.TemporaryDirectory(prefix='fleet-install-') as tmp:
        allowed, armor = os.path.join(tmp, 'allowed_signers'), os.path.join(tmp, 'install.sig')
        with open(allowed, 'wb') as f:  # bytes: text mode would end the line in CRLF on Windows
            f.write(f'{PRINCIPAL} namespaces="{NS}" ssh-ed25519 {words[1]}\n'.encode('ascii'))
        with open(armor, 'wb') as f:
            f.write(sig)
        code, out = run((SSH_KEYGEN, '-Y', 'verify', '-f', allowed, '-I', PRINCIPAL, '-n', NS, '-s', armor), text)
    if code != 0 or not out.startswith(f'Good "{NS}" signature for {PRINCIPAL} with '.encode()):
        raise Refused('sig')


def _obj(v: object, keys: Sequence[str]) -> dict:
    """v when it is an object holding exactly keys; else `form`."""
    if not isinstance(v, dict) or set(v) != set(keys):
        raise Refused('form')
    return v


def _match(v: object, rx: re.Pattern[str]) -> str:
    if type(v) is not str or not rx.fullmatch(v):
        raise Refused('form')
    return v


def _count(v: object, lo: int, hi: int) -> int:
    if type(v) is not int or not lo <= v <= hi:
        raise Refused('form')
    return v


def parse_install(text: bytes) -> dict[str, object]:
    """The exact shape of SCHEMA (P+ I01) from strict JSON: hashes lower-case hex, an https URL with a host name, a
    valid_until like 2026-12-01T00:00:00Z; kind other than `install` is `kind`, any other misfit `form`."""
    doc = _loads_strict(text)
    if not isinstance(doc, dict) or doc.get('kind') != KIND:
        raise Refused('kind')
    _obj(doc, SCHEMA)
    _count(doc['serial'], 0, MAX_COUNT)
    try:
        _parse_utc(_match(doc['valid_until'], UTC_TIME))
    except ValueError:
        raise Refused('form') from None
    _match(doc['source_head'], HEX40)
    _match(doc['lock_sha256'], HEX64)
    boot = _obj(doc['bootstrap'], OSES)
    for name in OSES:
        entry = _obj(boot[name], BOOT_KEYS)
        _match(entry['sha256'], HEX64)
        _match(entry['blob'], HEX40)
    kit = _obj(doc['kit'], KIT_KEYS)
    _count(kit['serial'], 0, MAX_COUNT)
    _match(kit['kit_json_sha256'], HEX64)
    bundle = _obj(doc['bundle'], BUNDLE_KEYS)
    _match(bundle['head'], HEX40)
    _match(bundle['tree'], HEX40)
    _match(bundle['url'], URL)
    _match(bundle['sha256'], HEX64)
    _count(bundle['size'], 1, MAX_BUNDLE)
    return doc


def signed_install(text: bytes, sig: bytes, owner_pub: bytes, *, min_serial: int, now: datetime, in_tree: InTree,
                   run: Run = run_argv) -> dict[str, object]:
    """The manifest's value once the signature holds (before any parsing), the schema fits, now is before valid_until,
    serial is at least min_serial (the caller's own floor, never a field of the file) and in_tree(source_head, blob)
    holds for both bootstrap blobs; else Refused with the code."""
    if len(text) > MAX_BYTES:
        raise Refused('size')
    verify_signature(text, sig, owner_pub, run)
    doc = parse_install(text)
    if _parse_utc(doc['valid_until']) <= now:
        raise Refused('expired')
    if doc['serial'] < min_serial:
        raise Refused('rollback')
    if not all(in_tree(doc['source_head'], doc['bootstrap'][name]['blob']) for name in OSES):
        raise Refused('tree')
    return doc


# ---------------------------------------------------------------------------------------------------------------
# 2. The publisher
# ---------------------------------------------------------------------------------------------------------------

GH = '/usr/bin/gh'
PIN_NS = 'mirrorstack-fleet-pin'  # kit.json and deploy-pin.json are signed under the pin's namespace (VERIFY.txt)
MIN_DAYS = 30  # install.json must stay valid this long after the publish
KIT_FILES = ('carrier-check.py', 'check.ps1', 'carrier-check.sh', 'verify-archive.py', 'VERIFY.txt')  # the five
# every asset but the kit files and the (optional) bundle, in publish order
FIXED = ('install.json', 'install.json.sig', 'kit.json', 'kit.json.sig', 'deploy-pin.json', 'deploy-pin.json.sig',
         '.gitattributes', 'bootstrap.ps1', 'bootstrap.sh')
MAX_SMALL = 1 << 20  # kit.json, the pin, signatures, .gitattributes: far below this; a bigger one is refused
MAX_ATTR = 4096
MAX_KIT = 16 << 20  # one kit file (a script): far above the real ones, refused beyond it
# .gitattributes carries no signature and decides the line endings of the checked-out bootstraps, so it is compared with
# this committed constant: changing it is a reviewed change to this file, never a release folder's data.
GITATTRIBUTES = b'* text=auto eol=lf\n*.ps1 eol=crlf\n'
CHUNK = 1 << 20
TOOL_TIMEOUT, UPLOAD_TIMEOUT = 600, 1800  # seconds: gh queries; the release upload with the bundle in it
USAGE, REFUSED = 2, 1
USAGE_TEXT = ('usage: fleet-install-publish.py publish|verify <dir> --owner-pub <path> --min-serial N\n'
              '  <dir> is release/install-<serial>; both verbs need GITHUB_REPOSITORY (the bundle URL is checked against it);\n'
              '  publish also needs GITHUB_SHA and GH_TOKEN\n')
DIR_NAME = re.compile(r'install-(0|[1-9][0-9]{0,9})', re.ASCII)  # canonical decimal: install-007 is not install-7
INSTALL_TAG = re.compile(r'install-(0|[1-9][0-9]{0,9})', re.ASCII)
REPO = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}', re.ASCII)
PUBLISH_CODES = ('serial', 'dir', 'missing', 'no-deploy-pin', 'pin-mismatch', 'hash', 'unlisted', 'kit', 'short-validity',
                 'release-env', 'tag-check-failed', 'tag-exists', 'not-newer', 'immutable-off', 'immutable-unreadable',
                 'immutable-not-set', 'attributes', 'tool-missing', 'tool-timeout', 'publish-failed', 'publish-mismatch')


class Io(Protocol):
    """The one thing the publish does to the world, so a test can fake it (no network, no real gh)."""

    def run(self, argv: list[str], env: dict[str, str], timeout: int = TOOL_TIMEOUT) -> tuple[int, str]:
        """Run argv (absolute, no shell, no stdin) under exactly env, at most timeout seconds; return (exit status,
        stdout). A tool that outlives its timeout is Refused('tool-timeout')."""


class Real:
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


class Asset:
    """One file of the release: where it is, its name, sha256 and size."""

    def __init__(self, path: Path, digest: str, size: int) -> None:
        self.path, self.name, self.sha256, self.size = path, path.name, digest, size


class Plan:
    """What `check_dir` proved: the tag, the manifest and the assets in publish order. The assets are the private
    copy under `stage` that was verified, never the folder it was copied from."""

    def __init__(self, tag: str, doc: dict, assets: list[Asset], key_fpr: str, stage: Path) -> None:
        self.tag, self.doc, self.assets, self.key_fpr, self.stage = tag, doc, assets, key_fpr, stage

    def cleanup(self) -> None:
        """Remove the private copy of the files (the assets live there); safe to call twice."""
        shutil.rmtree(self.stage, ignore_errors=True)


def snapshot(src: Path, stage: Path, limit: int) -> Asset:
    """Copy src into the private stage in ONE read, hashing the very bytes written: the sha256 and size of the Asset
    describe the copy, and the copy is what is verified and uploaded (nothing re-reads the source). A link, a
    non-regular file or one over `limit` bytes is refused."""
    try:
        fd = os.open(src, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    except OSError:
        raise Refused('unlisted') from None
    dst, digest, size = stage / src.name, hashlib.sha256(), 0
    with os.fdopen(fd, 'rb') as f, open(dst, 'xb') as out:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Refused('unlisted')
        while chunk := f.read(CHUNK):
            size += len(chunk)
            if size > limit:
                raise Refused('size')
            digest.update(chunk)
            out.write(chunk)
    return Asset(dst, digest.hexdigest(), size)


def check_pin(data: bytes, bundle: dict | None) -> None:
    """deploy-pin.json has verify-archive's signed_pin shape: exactly serial (an integer), head and tree (40 hex).
    `bundle` is install.json's signed bundle object when this release carries the bundle, else None. The pin names
    exactly the commit and tree the bundle was built from, so with a bundle its head and tree must equal the bundle's,
    else Refused('pin-mismatch'). Without a bundle the pin is only shape-checked here (and signature-checked by the
    caller), not compared. The pin's serial is never compared with install.json: the PC's verify-archive enforces its
    own floor."""
    pin = _loads_strict(data)
    if (not isinstance(pin, dict) or set(pin) != {'serial', 'head', 'tree'} or type(pin['serial']) is not int
            or not 0 <= pin['serial'] <= MAX_COUNT
            or not all(type(pin[k]) is str and HEX40.fullmatch(pin[k]) for k in ('head', 'tree'))):
        raise Refused('form')
    if bundle is not None and (pin['head'] != bundle['head'] or pin['tree'] != bundle['tree']):
        raise Refused('pin-mismatch')


def blob_ids(data: bytes) -> set[str]:
    """The git blob ids this file can have in the source tree: its bytes as they are, and with CRLF read as LF (a
    .ps1 is checked out CRLF by .gitattributes but stored LF)."""
    return {hashlib.sha1(b'blob %d\0' % len(body) + body).hexdigest() for body in (data, data.replace(b'\r\n', b'\n'))}


def key_fingerprint(owner_pub: bytes) -> str:
    """SHA256:<base64> of the key blob, the form ssh-keygen -l prints, so the log shows which key was trusted."""
    blob = base64.b64decode(owner_pub.split()[1] + b'=')
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def verify_pin_signature(text: bytes, sig: bytes, owner_pub: bytes, run: Run) -> None:
    """kit.json and deploy-pin.json: the owner's signature under the pin's namespace, else `sig`."""
    words = owner_pub.decode('ascii', 'replace').split()
    with tempfile.TemporaryDirectory(prefix='fleet-install-') as tmp:
        allowed, armor = os.path.join(tmp, 'allowed_signers'), os.path.join(tmp, 'file.sig')
        with open(allowed, 'wb') as f:
            f.write(f'{PRINCIPAL} namespaces="{PIN_NS}" ssh-ed25519 {words[1]}\n'.encode('ascii'))
        with open(armor, 'wb') as f:
            f.write(sig)
        code, out = run((SSH_KEYGEN, '-Y', 'verify', '-f', allowed, '-I', PRINCIPAL, '-n', PIN_NS, '-s', armor), text)
    if code != 0 or not out.startswith(f'Good "{PIN_NS}" signature for {PRINCIPAL} with '.encode()):
        raise Refused('sig')


def bundle_name(doc: dict, repo: str, tag: str) -> str | None:
    """The bundle's file name when its signed URL is a download of this very release, else None (not public here)."""
    prefix = f'https://github.com/{repo}/releases/download/{tag}/'
    url = doc['bundle']['url']
    return url[len(prefix):] if repo and url.startswith(prefix) and '/' not in url[len(prefix):] else None


def check_dir(d: Path, owner_pub: bytes, min_serial: int, now: datetime, repo: str, run: Run = run_argv) -> Plan:
    """Offline: everything the release would carry is proven, or Refused with the code. `d` must be exactly
    release/install-<serial> (relative, canonical serial). Each file is read once into a private stage; every check and
    the later upload use that copy. Order: the folder's shape, install.json.sig, the manifest's own rules, validity of
    30 days, the bootstraps, the kit, the pin, .gitattributes, the bundle, and last that no file is unlisted."""
    m = DIR_NAME.fullmatch(d.name)
    if not m or d != Path('release') / d.name:
        raise Refused('dir')
    stage = Path(tempfile.mkdtemp(prefix='fleet-install-'))
    try:
        return _check_staged(d, m.group(0), int(m[1]), stage, owner_pub, min_serial, now, repo, run)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _check_staged(d: Path, tag: str, folder_serial: int, stage: Path, owner_pub: bytes, min_serial: int, now: datetime,
                  repo: str, run: Run) -> Plan:
    try:
        entries = {e.name: os.lstat(e.path) for e in os.scandir(d)}
    except OSError:
        raise Refused('dir') from None
    if any(not stat.S_ISREG(st.st_mode) for st in entries.values()):  # a link, a folder, a device
        raise Refused('unlisted')
    if 'deploy-pin.json' not in entries:
        raise Refused('no-deploy-pin')
    if not all(name in entries for name in FIXED + KIT_FILES):
        raise Refused('missing')
    limits = {name: MAX_KIT if name in KIT_FILES else MAX_SMALL for name in FIXED + KIT_FILES}
    limits.update({'install.json': MAX_BYTES, '.gitattributes': MAX_ATTR})
    snap = {name: snapshot(d / name, stage, limits[name]) for name in FIXED + KIT_FILES}
    data = lambda name: snap[name].path.read_bytes()  # noqa: E731  (the private copy, whose hash is snap[name].sha256)
    text, sig = data('install.json'), data('install.json.sig')
    # signed_install's tree rule asks whether a blob is in source_head's tree, which only the private repo can answer;
    # here the question is answered below, per file: the bootstrap carries the signed blob id (and the signed sha256)
    doc = signed_install(text, sig, owner_pub, min_serial=min_serial, now=now, in_tree=lambda head, blob: True, run=run)
    if doc['serial'] != folder_serial:
        raise Refused('serial')
    if _parse_utc(doc['valid_until']) < now + timedelta(days=MIN_DAYS):
        raise Refused('short-validity')
    for name in OSES:  # each bootstrap is the signed one: its sha256 and its own blob id, not the other's
        want, boot = doc['bootstrap'][name], snap[f'bootstrap.{name}']
        if boot.sha256 != want['sha256']:
            raise Refused('hash')
        if want['blob'] not in blob_ids(boot.path.read_bytes()):
            raise Refused('tree')
    if snap['kit.json'].sha256 != doc['kit']['kit_json_sha256']:
        raise Refused('hash')
    verify_pin_signature(data('kit.json'), data('kit.json.sig'), owner_pub, run)
    kit = _loads_strict(data('kit.json'))
    files = kit.get('files') if isinstance(kit, dict) else None
    if (not isinstance(files, list) or kit.get('serial') != doc['kit']['serial']
            or not all(isinstance(f, dict) and set(f) == {'path', 'sha256'} and type(f['path']) is str for f in files)
            or sorted(f['path'] for f in files) != sorted(KIT_FILES)):
        raise Refused('kit')
    for f in files:
        if snap[f['path']].sha256 != f['sha256']:
            raise Refused('hash')
    verify_pin_signature(data('deploy-pin.json'), data('deploy-pin.json.sig'), owner_pub, run)
    bundle = bundle_name(doc, repo, tag)  # the bundle's file name when this release carries it, else None
    check_pin(data('deploy-pin.json'), doc['bundle'] if bundle is not None else None)
    if data('.gitattributes') != GITATTRIBUTES:
        raise Refused('attributes')
    names = list(FIXED + KIT_FILES)
    if bundle is not None:
        if bundle not in entries or bundle in names:
            raise Refused('missing' if bundle not in entries else 'unlisted')
        snap[bundle] = snapshot(d / bundle, stage, MAX_BUNDLE)
        if snap[bundle].size != doc['bundle']['size'] or snap[bundle].sha256 != doc['bundle']['sha256']:
            raise Refused('hash')
        names.append(bundle)
    if set(entries) != set(names):  # a file the signed manifest does not account for
        raise Refused('unlisted')
    # every asset's sha256 is that of the verified copy: where the owner signed a hash (bootstraps, kit files, kit.json,
    # the bundle) it was compared above and is that very value; the rest is covered by a signature over the same bytes
    return Plan(tag, doc, [snap[n] for n in names], key_fingerprint(owner_pub), stage)


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


def published_name(name: str) -> str:
    """The name GitHub serves an asset under: it rewrites a leading dot to `default.` (unverified until the first
    publish, so the read-back accepts either spelling and prints the one it found)."""
    return 'default' + name if name.startswith('.') else name


def publish(io: Io, plan: Plan, repo: str, sha: str, token: str, confirmed: str = '') -> list[str]:
    """Refuse an existing tag, require Immutable releases, create the release with exactly the plan's assets and read
    GitHub's digests back; return one line per asset (name, sha256, url). Every check that cannot be answered refuses
    (fail closed)."""
    if not (REPO.fullmatch(repo) and re.fullmatch(r'[0-9a-f]{40}', sha) and token):
        raise Refused('release-env')
    tag = plan.tag
    env = {'PATH': '/usr/bin', 'GH_TOKEN': token, 'GH_REPO': repo, 'GH_PROMPT_DISABLED': '1'}
    # a release (drafts included) or a bare tag of that name exists: refuse. Any answer but a clean "no such" (a 5xx,
    # a rate limit, a timeout, unreadable output) is tag-check-failed, never "not found".
    refs = json_out(io, [GH, 'api', f'repos/{repo}/git/matching-refs/tags/{tag}'], env, list)  # a PREFIX match
    releases = json_out(io, [GH, 'release', 'list', '--limit', '1000', '--json', 'tagName,isDraft'], env, list)
    if (any(isinstance(r, dict) and r.get('ref') == f'refs/tags/{tag}' for r in refs)
            or any(isinstance(r, dict) and r.get('tagName') == tag for r in releases)):
        raise Refused('tag-exists')
    # rollback floor, derived here and not only dispatched: never a serial at or below an install-N release that exists
    # (min_serial stays an additional floor)
    newest = max((int(m[1]) for r in releases if isinstance(r, dict) and isinstance(r.get('tagName'), str)
                  and (m := INSTALL_TAG.fullmatch(r['tagName']))), default=-1)
    if plan.doc['serial'] <= newest:
        raise Refused('not-newer')
    # Immutable releases covers only releases created after it is on, so it is read BEFORE the release exists. The
    # job token cannot always read it: then only the owner's recorded confirmation (confirmed == 'yes') goes on.
    code, out = io.run([GH, 'api', f'repos/{repo}/immutable-releases'], env)
    try:
        setting = json.loads(out).get('enabled') if code == 0 else None
    except (ValueError, AttributeError):
        setting = None
    if setting is False:
        raise Refused('immutable-off')
    if setting is not True:
        if confirmed != 'yes':
            raise Refused('immutable-unreadable')
        print('fleet-install-publish: Immutable releases is unreadable by this token; going on the owner\'s recorded'
              ' confirmation', file=sys.stderr, flush=True)
    notes = f'Owner-signed install set {tag}. Verify install.json with ssh-keygen -Y verify -n {NS} -I {PRINCIPAL}.'
    if io.run([GH, 'release', 'create', tag, *(str(a.path) for a in plan.assets), '--target', sha, '--title', tag,
               '--notes', notes], env, UPLOAD_TIMEOUT)[0] != 0:
        raise Refused('publish-failed')
    published = json_out(io, [GH, 'api', f'repos/{repo}/releases/tags/{tag}'], env, dict, 'publish-mismatch')
    # the setting read and the owner's variable are only an early stop: what the created release says is the proof
    if published.get('immutable') is not True or published.get('draft') is not False:
        raise Refused('immutable-not-set')
    got = published.get('assets')
    want = {a.name: a for a in plan.assets}
    served: dict[str, dict] = {}
    for asset in got if isinstance(got, list) else []:
        if not isinstance(asset, dict) or not isinstance(asset.get('name'), str) or asset['name'] in served:
            raise Refused('publish-mismatch')
        served[asset['name']] = asset
    lines = []
    for name, a in want.items():
        found = served.pop(name, None) or served.pop(published_name(name), None)
        if not found or found.get('digest') != f'sha256:{a.sha256}' or found.get('size', a.size) != a.size:
            raise Refused('publish-mismatch')  # what GitHub now serves is not what was checked
        lines.append(f'{found["name"]} sha256:{a.sha256} https://github.com/{repo}/releases/download/{tag}/{found["name"]}')
    if served:  # an asset nobody listed
        raise Refused('publish-mismatch')
    return lines


def parse_args(argv: list[str]) -> tuple[str, Path, str, int] | None:
    """(verb, dir, owner-pub path, min serial) from `verb <dir> --owner-pub P --min-serial N`, or None."""
    if len(argv) != 7 or argv[1] not in ('publish', 'verify') or argv[3] != '--owner-pub' or argv[5] != '--min-serial':
        return None
    if not argv[6].isascii() or not argv[6].isdigit():
        return None
    return argv[1], Path(argv[2]), argv[4], int(argv[6])


def main(argv: list[str], environ: dict[str, str], io: Io, run: Run = run_argv, now: datetime | None = None) -> int:
    """0 done, 1 refused, 2 usage. publish also needs GITHUB_REPOSITORY, GITHUB_SHA and GH_TOKEN (the job's), and
    optionally IMMUTABLE_CONFIRMED=yes."""
    args = parse_args(argv)
    if args is None:
        sys.stderr.write(USAGE_TEXT)
        return USAGE
    verb, d, key_path, min_serial = args
    repo = environ.get('GITHUB_REPOSITORY', '')
    plans: list[Plan] = []
    try:
        try:
            owner_pub = Path(key_path).read_bytes()
        except OSError:
            raise Refused('key') from None
        plan = check_dir(d, owner_pub, min_serial, now or datetime.now(timezone.utc), repo, run)
        plans.append(plan)
        print(f'fleet-install-publish: {plan.tag} verified against {plan.key_fpr}, {len(plan.assets)} assets,'
              f' valid until {plan.doc["valid_until"]}', file=sys.stderr, flush=True)
        if verb == 'verify':
            lines = [f'{a.name} sha256:{a.sha256}' for a in plan.assets]
        else:
            lines = publish(io, plan, repo, environ.get('GITHUB_SHA', ''), environ.get('GH_TOKEN', ''),
                            environ.get('IMMUTABLE_CONFIRMED', ''))
    except Refused as why:
        sys.stderr.write(f'fleet-install-publish: refused {why.code}\n')
        print(f'REFUSED {why.code}')
        return REFUSED
    finally:
        for staged in plans:
            staged.cleanup()
    print(f'OK {plan.tag}')
    print('\n'.join(lines))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv, dict(os.environ), Real()))
