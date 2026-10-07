"""Publish the MirrorStack fleet's owner-signed install set: `fleet-install-publish.py publish <dir> --owner-pub <path>
--min-serial N`, run by .github/workflows/install.yml on a GitHub-hosted runner (`verify <dir> ...` does the local
half only, with no network and no gh). <dir> is release/install-<serial>, committed here by PR. The owner's public key
is never read from this repo: the workflow writes it from the release environment's variable OWNER_PIN_PUB to a
private temp file, and the script refuses `key` unless that file is exactly one `ssh-ed25519 <base64>[ comment]` line
and, when OWNER_PIN_SHA256 is set, its `ssh-keygen -lf` fingerprint equals it. Everything the
release will carry is checked first, offline: install.json.sig verifies against the owner's public key under namespace
mirrorstack-fleet-install, every file's sha256 equals the signed one, no file is unlisted, deploy-pin.json is there with
its shape, signature and the signed bundle's head and tree, the bundle's URL is the invite-gated kit host's for this serial
(the bundle is never a file of this release), and install.json is valid for at
least 30 more days. Each file is copied once into a private stage; the checks
and the upload use that copy. The two bootstraps are held to the one-hash rule (ASCII, LF only, no CR, no
BOM: the asset is the git blob) and must carry the baked values (the owner's key, the one that verified install.json, and
an expiry no earlier than valid_until and 30 days out); every asset is held to a size cap no larger than the bootstraps' own. Only then does it refuse an existing tag install-<serial>, require
GitHub's Immutable releases setting, create the release with exactly those assets, read GitHub's digests back and
require the release to say immutable and not draft.
Standalone stdlib. An error names the rule and never echoes a value; a refusal is exit 1, a bad command line 2.

The install.json rules are not written here: vendor/manifest.py is the one verifier, a byte-identical copy of the fleet's
install manifest, pinned by vendor/manifest.sha256. It is loaded at start and the script stops with `REFUSED form` unless
the file's sha256 is that pin (a changed copy needs a new pin, in the same change). The two helpers it imports (strict JSON
and the UTC time reader) are the stand-ins under vendor/standin; nothing in the copy is altered to run here.
tests/test_install_publish.py freezes the constants and the codes of the copy, so a drift is a red test."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Protocol

# ---------------------------------------------------------------------------------------------------------------
# 1. The vendored install.json verifier (vendor/manifest.py, pinned by vendor/manifest.sha256)
# ---------------------------------------------------------------------------------------------------------------

VENDOR = Path(__file__).resolve().parent.parent / 'vendor'
_STAND_INS = ('fleet', 'fleet.core', 'fleet.core.canon', 'fleet.core.clock')  # what the copy imports, found under standin/


def load_vendored(root: Path) -> ModuleType:
    """root/manifest.py as a module, once its sha256 is the pin in root/manifest.sha256 (one lower-case hex line);
    ValueError if the pin or the file is unreadable or they differ. The copy's own imports resolve to root/standin
    for the length of the load only: the path and the module table are put back as they were."""
    try:
        data = (root / 'manifest.py').read_bytes()
        pin = (root / 'manifest.sha256').read_text(encoding='ascii')
    except (OSError, UnicodeDecodeError):
        raise ValueError('vendor') from None
    if not re.fullmatch(r'[0-9a-f]{64}\n', pin) or hashlib.sha256(data).hexdigest() != pin[:64]:
        raise ValueError('vendor')
    held = {name: sys.modules.pop(name) for name in _STAND_INS if name in sys.modules}
    sys.path.insert(0, str(root / 'standin'))
    try:
        module = ModuleType('install_manifest')
        module.__file__ = str(root / 'manifest.py')
        exec(compile(data, module.__file__, 'exec'), module.__dict__)  # the bytes that were hashed, not a second read
        return module
    finally:
        sys.path.remove(str(root / 'standin'))
        for name in _STAND_INS:
            sys.modules.pop(name, None)
        sys.modules.update(held)


try:
    manifest = load_vendored(VENDOR)
except ValueError:  # fail closed, and say it the way a refusal is said
    sys.stderr.write('fleet-install-publish: refused form\n')
    print('REFUSED form')
    sys.exit(1)

Refused, Run, InTree = manifest.Refused, manifest.Run, manifest.InTree
NS, PRINCIPAL, SSH_KEYGEN, MAX_BYTES, MAX_COUNT = (manifest.NS, manifest.PRINCIPAL, manifest.SSH_KEYGEN,
                                                    manifest.MAX_BYTES, manifest.MAX_COUNT)
HEX40, HEX64, OSES = manifest.HEX40, manifest.HEX64, manifest.OSES
run_argv, parse_install, signed_install = manifest.run_argv, manifest.parse_install, manifest.signed_install
_parse_utc = manifest.clock.parse_utc


def _loads_strict(text: bytes) -> object:
    """Strict JSON (the copy's reader) for kit.json and the pin; any refusal is `form`."""
    try:
        return manifest.canon.loads_strict(text)
    except manifest.canon.SchemaError:
        raise Refused('form') from None

# ---------------------------------------------------------------------------------------------------------------
# 2. The publisher
# ---------------------------------------------------------------------------------------------------------------

GH = '/usr/bin/gh'
PIN_NS = 'mirrorstack-fleet-pin'  # kit.json and deploy-pin.json are signed under the pin's namespace (VERIFY.txt)
MIN_DAYS = 30  # install.json must stay valid this long after the publish
KIT_FILES = ('carrier-check.py', 'check.ps1', 'carrier-check.sh', 'verify-archive.py', 'VERIFY.txt')  # the five
# every asset but the kit files, in publish order
FIXED = ('install.json', 'install.json.sig', 'kit.json', 'kit.json.sig', 'deploy-pin.json', 'deploy-pin.json.sig',
         '.gitattributes', 'bootstrap.ps1', 'bootstrap.sh')
MAX_SMALL = 1 << 20  # the pin and the two bootstraps (the bootstraps never fetch them): far below this; a bigger one is refused
MAX_ATTR = 4096
# the caps below are never above what the bootstraps' own downloads allow (curl --max-filesize): install.json is MAX_BYTES
MAX_SIG = 4096  # install.json.sig (the bootstraps' cap); the other two signatures are held to it too
MAX_KIT_JSON = 65536  # kit.json
MAX_KIT = 4 << 20  # one kit file (the bootstraps' cap)
MAX_CARRIER_SH = 262144  # carrier-check.sh, the one kit file the POSIX bootstrap fetches, on a lower cap
# .gitattributes carries no signature and decides the line endings of the checked-out bootstraps, so it is compared with
# this committed constant: changing it is a reviewed change to this file, never a release folder's data.
# It is a published copy of the fleet repo's file, byte for byte (its `*.ps1 eol=crlf` line is deliberate there); the
# bootstraps' own LF-only rule is enforced on the bootstrap assets (BOOT_BYTES), not on this file.
GITATTRIBUTES = b'* text=auto eol=lf\n*.ps1 eol=crlf\n'
MIN_DAYS_BAKED = MIN_DAYS  # the baked expiry is at least this many days past the publish
BAKED = {  # per bootstrap: the strict one-line assignments of the baked key and expiry, and the variable names whose
    # every write (see _writes) must be that one line, so a later or hidden second assignment is refused
    'ps1': (re.compile(r"^\$OwnerKey = '([^'\n]*)'$", re.M), re.compile(r"^\$Expires = '([^'\n]*)'$", re.M),
            'OwnerKey', 'Expires'),
    'sh': (re.compile(r"^OWNER_KEY='([^'\n]*)'$", re.M), re.compile(r'^EXPIRES=([^\n]*)$', re.M), 'OWNER_KEY', 'EXPIRES'),
}
PYTHON_VERSION = re.compile(r'\d{1,2}\.\d{1,2}\.\d{1,2}', re.ASCII)  # ASCII digits only: \d alone takes Arabic-Indic ones too
CHUNK = 1 << 20
TOOL_TIMEOUT, UPLOAD_TIMEOUT = 600, 1800  # seconds: gh queries; the release upload
USAGE, REFUSED = 2, 1
USAGE_TEXT = ('usage: fleet-install-publish.py publish|verify <dir> --owner-pub <path> --min-serial N\n'
              '  <dir> is release/install-<serial>;\n'
              '  OWNER_PIN_SHA256 (optional) is the fingerprint the key file must have;\n'
              '  publish also needs GITHUB_REPOSITORY, GITHUB_SHA and GH_TOKEN\n')
DIR_NAME = re.compile(r'install-(0|[1-9][0-9]{0,9})', re.ASCII)  # canonical decimal: install-007 is not install-7
INSTALL_TAG = re.compile(r'install-(0|[1-9][0-9]{0,9})', re.ASCII)
OWNER_LINE = re.compile(r'ssh-ed25519 [A-Za-z0-9+/]{68}(?: [ -~]*)?', re.ASCII)  # one key line, an optional comment
FPR = re.compile(r'SHA256:[A-Za-z0-9+/]{43}', re.ASCII)  # what ssh-keygen -l prints for an ed25519 key
REPO = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}', re.ASCII)
PUBLISH_CODES = ('serial', 'dir', 'missing', 'no-deploy-pin', 'pin-mismatch', 'hash', 'unlisted', 'kit', 'short-validity',
                 'release-env', 'tag-check-failed', 'tag-exists', 'not-newer', 'immutable-off', 'immutable-unreadable',
                 'immutable-not-set', 'attributes', 'boot-bytes', 'baked', 'tool-missing', 'tool-timeout', 'publish-failed', 'publish-mismatch')


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
        fd = os.open(src, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
                     | getattr(os, 'O_NONBLOCK', 0))  # a FIFO swapped in must not block the open
    except OSError:
        raise Refused('unlisted') from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):  # a folder or a FIFO swapped in after the scan
            raise Refused('unlisted')
    except BaseException:
        os.close(fd)
        raise
    dst, digest, size = stage / src.name, hashlib.sha256(), 0
    with os.fdopen(fd, 'rb') as f, open(dst, 'xb') as out:
        while chunk := f.read(CHUNK):
            size += len(chunk)
            if size > limit:
                raise Refused('size')
            digest.update(chunk)
            out.write(chunk)
    return Asset(dst, digest.hexdigest(), size)


def check_pin(data: bytes, bundle: dict) -> None:
    """deploy-pin.json has verify-archive's signed_pin shape: exactly serial (an integer), head and tree (40 hex). The
    pin names exactly the commit and tree the bundle was built from, so its head and tree must equal install.json's
    signed bundle.head and bundle.tree, else Refused('pin-mismatch'); the bundle itself is not in this release. The
    pin's serial is never compared with install.json: the PC's verify-archive enforces its own floor."""
    pin = _loads_strict(data)
    if (not isinstance(pin, dict) or set(pin) != {'serial', 'head', 'tree'} or type(pin['serial']) is not int
            or not 0 <= pin['serial'] <= MAX_COUNT
            or not all(type(pin[k]) is str and HEX40.fullmatch(pin[k]) for k in ('head', 'tree'))):
        raise Refused('form')
    if pin['head'] != bundle['head'] or pin['tree'] != bundle['tree']:
        raise Refused('pin-mismatch')


def blob_ids(data: bytes) -> set[str]:
    """The git blob id of this file's raw bytes (the only one: the asset is the blob, a CRLF copy is not the asset)."""
    return {hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest()}


def check_boot_bytes(data: bytes) -> None:
    """A bootstrap asset is ASCII with LF only: no BOM, no CR (a CRLF working-tree copy is not the release asset),
    else Refused('boot-bytes')."""
    if not data or not data.isascii() or b'\r' in data or data.startswith(b'\xef\xbb\xbf'):
        raise Refused('boot-bytes')


_COMMENT_LINE = re.compile(r'^[ \t]*#[^\n]*', re.M)  # a line whose first non-blank character is `#` (both languages)
_READ_PREFIX = re.compile(r'\$\{?(?:\w+:)?$')  # `$`, `${`, `$script:` or `${global:` right before a name: a read, unless an
# assignment follows it (below); a bare name is `Set-Variable OwnerKey`, `-OutVariable OwnerKey`, `read OWNER_KEY`, `NAME=`
_PS_WRITE = re.compile(r'\}?[ \t]*[-+*/%]?=')  # `$Name = ...`, `$Name += ...`, `${Name} = ...`
_PS_LOOP = re.compile(r'\bfor(?:each)?[ \t]*\([ \t]*\$\{?(?:\w+:)?$', re.I)  # `foreach ($Name in ...)` sets it too
_PS_REF = re.compile(r'\[ref\][ \t]*\$\{?(?:\w+:)?$', re.I)  # `[ref]$Name` hands it to code that can set it


def _writes(name: str, data: str, var: str) -> int:
    """How many places in the bootstrap (outside comment lines) can set `var`: every mention that is not a plain read,
    in any position and any case on Windows (PowerShell variables are case-insensitive: $ownerkey, $script:OwnerKey,
    Set-Variable OwnerKey, [ref]$OwnerKey), and `NAME=` after `;`, `&&`, `export`, `readonly` or in an `eval` on
    POSIX (also `read NAME`, `export NAME` and `${NAME:=x}`). A read (`$VAR`, `${VAR}`, `$script:VAR`) is not
    counted; a part of a longer name (`Get-OwnerKey`, `MY_OWNER_KEY`) and a property (`.Expires`) are not mentions.
    The one baked assignment line is the 1 that is expected."""
    code = _COMMENT_LINE.sub('', data)
    ps1, count = name == 'ps1', 0
    for m in re.finditer(rf'(?<![\w]){re.escape(var)}(?![\w])', code, re.I if ps1 else 0):
        before, after = code[:m.start()][-40:], code[m.end():m.end() + 8]
        if ps1:
            if before.endswith(('.', '-')):
                continue
            write = (not _READ_PREFIX.search(before) or _PS_WRITE.match(after) or _PS_LOOP.search(before)
                     or _PS_REF.search(before))
        else:
            write = (not _READ_PREFIX.search(before)
                     or (before.endswith('${') and re.match(r':?=', after) is not None))
        count += bool(write)
    return count


def baked_values(name: str, data: bytes) -> tuple[str, str]:
    """(key, expires) from the bootstrap's one assignment line each, or Refused('baked') unless exactly one line of
    each kind is there, nothing follows the value on it and nothing else in the file can set either variable (an
    indented, repeated, differently spelled or scoped assignment counts as another)."""
    key_rx, exp_rx, key_var, exp_var = BAKED[name]
    text = data.decode('ascii', 'replace')
    keys, exps = key_rx.findall(text), exp_rx.findall(text)
    if len(keys) != 1 or len(exps) != 1 or _writes(name, text, key_var) != 1 or _writes(name, text, exp_var) != 1:
        raise Refused('baked')
    return keys[0], exps[0]


def check_baked(name: str, data: bytes, owner_pub: bytes, valid_until: datetime, now: datetime) -> None:
    """The baked key must be the one that verified install.json (type and base64) and the baked expiry must be a UTC
    time of valid_until's shape that is not before valid_until and not before now + 30 days; else Refused('baked').
    The unbaked placeholders (key UNBAKED, expiry 1970) fail both."""
    key, expires = baked_values(name, data)
    words = owner_pub.decode('ascii', 'replace').split()
    if len(words) < 2 or key != f'{words[0]} {words[1]}':
        raise Refused('baked')
    try:
        until = _parse_utc(expires)
    except ValueError:
        raise Refused('baked') from None
    if until < valid_until or until < now + timedelta(days=MIN_DAYS_BAKED):
        raise Refused('baked')


def owner_key(path: str, want_fpr: str = '', run: Run = run_argv) -> bytes:
    """The owner's public key from the file the workflow wrote out of the release environment, or Refused('key'): the
    file must be there and be exactly one `ssh-ed25519 <base64>[ comment]` line (one final newline allowed), and when
    want_fpr is given (OWNER_PIN_SHA256) the `ssh-keygen -lf` fingerprint must equal it. Nothing in this repo is a key."""
    try:
        with open(path, 'rb') as f:
            data = f.read(4097)
    except OSError:
        raise Refused('key') from None
    text = data.decode('ascii', 'replace')
    if len(data) > 4096 or not OWNER_LINE.fullmatch(text[:-1] if text.endswith('\n') else text):
        raise Refused('key')
    if want_fpr:
        code, out = run((SSH_KEYGEN, '-l', '-f', path), b'')
        words = out.decode('ascii', 'replace').split()
        if not FPR.fullmatch(want_fpr) or code != 0 or len(words) < 2 or words[1] != want_fpr:
            raise Refused('key')
    return data


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


# the bundle is served by the invite-gated kit host, never by GitHub: its URL is https://<kit-host>/v1/kit/<serial>/bundle.tar
NOT_KIT_HOSTS = ('github.com', 'githubusercontent.com')  # the host itself or any name below it


def check_bundle_url(doc: dict) -> None:
    """install.json's signed bundle.url must be the kit host's download of this very serial, https://<host>/v1/kit/<serial>/
    bundle.tar, and the host must not be GitHub's; else Refused('form'). The bundle is never a file of this release."""
    host, _, path = doc['bundle']['url'].removeprefix('https://').partition('/')
    if path != f'v1/kit/{doc["serial"]}/bundle.tar' or any(host == h or host.endswith('.' + h) for h in NOT_KIT_HOSTS):
        raise Refused('form')


def check_dir(d: Path, owner_pub: bytes, min_serial: int, now: datetime, run: Run = run_argv) -> Plan:
    """Offline: everything the release would carry is proven, or Refused with the code. `d` must be exactly
    release/install-<serial> (relative, canonical serial). Each file is read once into a private stage; every check and
    the later upload use that copy. Order: the folder's shape, install.json.sig, the manifest's own rules, validity of
    30 days, the bootstraps, the kit, the pin, .gitattributes, and last that no file is unlisted (the bundle is not a file
    of this release, so one in the folder is unlisted)."""
    m = DIR_NAME.fullmatch(d.name)
    if not m or d != Path('release') / d.name:
        raise Refused('dir')
    stage = Path(tempfile.mkdtemp(prefix='fleet-install-'))
    try:
        return _check_staged(d, m.group(0), int(m[1]), stage, owner_pub, min_serial, now, run)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _check_staged(d: Path, tag: str, folder_serial: int, stage: Path, owner_pub: bytes, min_serial: int, now: datetime,
                  run: Run) -> Plan:
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
    limits.update({'install.json': MAX_BYTES, 'install.json.sig': MAX_SIG, 'kit.json': MAX_KIT_JSON,
                   'kit.json.sig': MAX_SIG, 'deploy-pin.json.sig': MAX_SIG, 'carrier-check.sh': MAX_CARRIER_SH,
                   '.gitattributes': MAX_ATTR})
    snap = {name: snapshot(d / name, stage, limits[name]) for name in FIXED + KIT_FILES}
    data = lambda name: snap[name].path.read_bytes()  # noqa: E731  (the private copy, whose hash is snap[name].sha256)
    text, sig = data('install.json'), data('install.json.sig')
    # signed_install's tree rule asks whether a blob is in source_head's tree, which only the source repo can answer;
    # here the question is answered below, per file: the bootstrap carries the signed blob id (and the signed sha256)
    doc = signed_install(text, sig, owner_pub, min_serial=min_serial, now=now, in_tree=lambda head, blob: True, run=run)
    if doc['serial'] != folder_serial:
        raise Refused('serial')
    check_bundle_url(doc)
    if _parse_utc(doc['valid_until']) < now + timedelta(days=MIN_DAYS):
        raise Refused('short-validity')
    for name in OSES:  # each bootstrap is the signed one: its sha256 and its own blob id, not the other's
        want, boot = doc['bootstrap'][name], snap[f'bootstrap.{name}']
        raw = boot.path.read_bytes()
        check_boot_bytes(raw)
        if boot.sha256 != want['sha256']:
            raise Refused('hash')
        if want['blob'] not in blob_ids(raw):
            raise Refused('tree')
        check_baked(name, raw, owner_pub, _parse_utc(doc['valid_until']), now)
    if snap['kit.json'].sha256 != doc['kit']['kit_json_sha256']:
        raise Refused('hash')
    verify_pin_signature(data('kit.json'), data('kit.json.sig'), owner_pub, run)
    kit = _loads_strict(data('kit.json'))
    files = kit.get('files') if isinstance(kit, dict) else None
    if (not isinstance(files, list) or kit.get('serial') != doc['kit']['serial']
            or not all(isinstance(f, dict) and set(f) == {'path', 'sha256'} and type(f['path']) is str for f in files)
            or sorted(f['path'] for f in files) != sorted(KIT_FILES)):
        raise Refused('kit')
    zipinfo = kit.get('python_zip')  # the Windows bootstrap downloads this exact python.org build and checks its hash
    if (not isinstance(zipinfo, dict) or type(zipinfo.get('version')) is not str
            or not PYTHON_VERSION.fullmatch(zipinfo['version']) or type(zipinfo.get('sha256')) is not str
            or not HEX64.fullmatch(zipinfo['sha256'])):
        raise Refused('form')
    for f in files:
        if snap[f['path']].sha256 != f['sha256']:
            raise Refused('hash')
    verify_pin_signature(data('deploy-pin.json'), data('deploy-pin.json.sig'), owner_pub, run)
    check_pin(data('deploy-pin.json'), doc['bundle'])
    if data('.gitattributes') != GITATTRIBUTES:
        raise Refused('attributes')
    names = list(FIXED + KIT_FILES)
    if set(entries) != set(names):  # a file the signed manifest does not account for
        raise Refused('unlisted')
    # every asset's sha256 is that of the verified copy: where the owner signed a hash (bootstraps, kit files, kit.json)
    # it was compared above and is that very value; the rest is covered by a signature over the same bytes
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
    """The name GitHub serves an asset under: it rewrites a leading dot to `default.` (so the read-back accepts either
    spelling for .gitattributes and prints the one it found)."""
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
        found = served.pop(name, None)
        if found is None and name == '.gitattributes':  # the only name GitHub rewrites here; the rest are exact
            found = served.pop(published_name(name), None)
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
    optionally IMMUTABLE_CONFIRMED=yes; OWNER_PIN_SHA256 (optional, both verbs) pins the key file's fingerprint."""
    args = parse_args(argv)
    if args is None:
        sys.stderr.write(USAGE_TEXT)
        return USAGE
    verb, d, key_path, min_serial = args
    repo = environ.get('GITHUB_REPOSITORY', '')
    plans: list[Plan] = []
    try:
        owner_pub = owner_key(key_path, environ.get('OWNER_PIN_SHA256', ''), run)
        print(f'fleet-install-publish: owner key {key_fingerprint(owner_pub)}', file=sys.stderr, flush=True)
        plan = check_dir(d, owner_pub, min_serial, now or datetime.now(timezone.utc), run)
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
