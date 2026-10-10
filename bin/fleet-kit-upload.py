"""Put a release's bundle and the gateway record on the kit host, signed by CI: `fleet-kit-upload.py bundle <dir> --owner-pub P`
and `fleet-kit-upload.py gateway --owner-pub P`, run by the kit job of .github/workflows/install.yml on a GitHub-hosted
runner, and `fleet-kit-upload.py floor N`, run by its floor job, which needs floor-approve (Environment `kit-floor`, where the owner is the required reviewer once that Environment is set up). There is no Cloudflare key here: the host takes a request only when it carries an Ed25519 signature of the upload
role (KIT_UPLOAD_KEY), made with `openssl pkeyutl -rawin` over `kit-admin-v1\\n<role>\\n<ts_ms>\\n<METHOD>\\n<path>\\n<sha256hex(body)>`.

`bundle <dir>`: <dir> holds the signed install.json and install.json.sig. The script checks the signature and the shape (the
vendored verifier), shallow-fetches the commit install.json names (bundle.head) from the private fleet repository with the
runner's read-only deploy key, reads fleet/install/closure.txt at that commit (a list of paths: data, so no private code
runs here), builds the bundle with the vendored packer (vendor/bundle.py) and refuses unless its size, sha256, head and tree
equal install.json (`REFUSED bundle-hash`). Only then does it PUT /_k/file/<serial>/bundle.tar and compare what the host
says it stored.

`gateway`: reads fleet/core/gateway.json and fleet/core/gateway.json.sig from the tip of the fleet `release` branch, checks
the owner's signature under the pin's namespace (ssh-keygen -Y verify) and the shape of the record, and PUTs the pair as one
request, so the host flips to it whole or not at all. These two files are not part of the public release folder and never pass through an artifact.

`floor N`: PUT /_k/floor {"floor": N}, the host's break-glass for a bad serial (it serves nothing below N), and reads the floor
back. It needs only KIT_HOST and the upload key: no fleet repository, no owner key.

This repository is public, so nothing here prints what it built: the build's own output goes to a file in RUNNER_TEMP that is
never printed, the log shows only a size and a sha256, and an error names the rule, never a value. No stack dump is
ever shown. The tar is overwritten and removed at the end. Standalone stdlib; exit 0 done, 1 refused, 2 bad command line.

The packer is not written here: vendor/bundle.py is a byte-identical copy of the fleet's own, pinned by vendor/VENDORED.sha256,
and the two small modules it imports are the stand-ins under vendor/standin-bundle, pinned by one hash over their five files
(vendor/standin-bundle.sha256). The script stops with `REFUSED vendor` unless every hash matches the bytes it then runs."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import http.client
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import ModuleType
from typing import Callable, Protocol

HERE = Path(__file__).resolve().parent
VENDOR = HERE.parent / 'vendor'

# ---------------------------------------------------------------------------------------------------------------
# 1. The publisher's own checks (install.json, the owner key, the pin signature), loaded once from the sibling script
# ---------------------------------------------------------------------------------------------------------------

_spec = importlib.util.spec_from_file_location('fleet_install_publish', HERE / 'fleet-install-publish.py')
fp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fp)  # stops with `REFUSED form` itself if the vendored manifest does not match its pin
Refused = fp.Refused

# ---------------------------------------------------------------------------------------------------------------
# 2. The vendored packer (vendor/bundle.py, pinned by vendor/VENDORED.sha256)
# ---------------------------------------------------------------------------------------------------------------

_PACKER_STAND_INS = ('fleet', 'fleet.core', 'fleet.core.git', 'fleet.install', 'fleet.install.files')  # what the copy imports
_PACKER_STAND_IN_FILES = ('fleet/__init__.py', 'fleet/core/__init__.py', 'fleet/core/git.py', 'fleet/install/__init__.py',
                          'fleet/install/files.py')  # one each, in this order
_PIN_LINE = re.compile(r'[0-9a-f]{64}\n')


def packer_stand_in_digest(files: dict[str, bytes]) -> str:
    """The one sha256 over the five stand-in files: each path and its bytes, in the order of _PACKER_STAND_IN_FILES."""
    digest = hashlib.sha256()
    for rel in _PACKER_STAND_IN_FILES:
        digest.update(rel.encode('ascii') + b'\0' + files[rel] + b'\0')
    return digest.hexdigest()


def load_packer(root: Path) -> ModuleType:
    """root/bundle.py as a module, once its sha256 is the pin in root/VENDORED.sha256 (one lower-case hex line) and the
    stand-ins it imports under root/standin-bundle hash to root/standin-bundle.sha256 (see packer_stand_in_digest);
    ValueError if a pin or a file is unreadable or they differ. Each file is read once and the bytes that were hashed
    are the ones executed. The stand-ins and the module are in the module table for the length of the load only."""
    try:
        data = (root / 'bundle.py').read_bytes()
        pin = (root / 'VENDORED.sha256').read_text(encoding='ascii')
        stand_ins = {rel: (root / 'standin-bundle' / rel).read_bytes() for rel in _PACKER_STAND_IN_FILES}
        stand_in_pin = (root / 'standin-bundle.sha256').read_text(encoding='ascii')
    except (OSError, UnicodeDecodeError):
        raise ValueError('vendor') from None
    if (not _PIN_LINE.fullmatch(pin) or hashlib.sha256(data).hexdigest() != pin[:64]
            or not _PIN_LINE.fullmatch(stand_in_pin) or packer_stand_in_digest(stand_ins) != stand_in_pin[:64]):
        raise ValueError('vendor')
    held = {name: sys.modules.pop(name) for name in (*_PACKER_STAND_INS, 'fleet_bundle') if name in sys.modules}
    try:
        for name, rel in zip(_PACKER_STAND_INS, _PACKER_STAND_IN_FILES):
            stand = ModuleType(name)
            stand.__file__ = str(root / 'standin-bundle' / rel)
            if rel.endswith('__init__.py'):
                stand.__path__ = []
            exec(compile(stand_ins[rel], stand.__file__, 'exec'), stand.__dict__)
            sys.modules[name] = stand
        sys.modules['fleet'].core, sys.modules['fleet'].install = sys.modules['fleet.core'], sys.modules['fleet.install']
        sys.modules['fleet.core'].git = sys.modules['fleet.core.git']
        sys.modules['fleet.install'].files = sys.modules['fleet.install.files']
        module = ModuleType('fleet_bundle')
        module.__file__ = str(root / 'bundle.py')
        sys.modules['fleet_bundle'] = module  # a dataclass looks its own module up by name while it is being made
        exec(compile(data, module.__file__, 'exec'), module.__dict__)  # the bytes that were hashed, not a second read
        return module
    finally:
        for name in (*_PACKER_STAND_INS, 'fleet_bundle'):
            sys.modules.pop(name, None)
        sys.modules.update(held)


try:
    packer = load_packer(VENDOR)
except ValueError:  # fail closed, and say it the way a refusal is said
    sys.stderr.write('fleet-kit-upload: refused vendor\n')
    print('REFUSED vendor')
    sys.exit(1)

# ---------------------------------------------------------------------------------------------------------------
# 3. The uploader
# ---------------------------------------------------------------------------------------------------------------

CODES = ('vendor', 'args', 'env', 'key', 'install', 'kit-host', 'fetch', 'closure', 'bundle-build', 'bundle-hash',
         'bundle-size', 'gateway', 'sig', 'sign', 'net', 'upload', 'conflict', 'replay', 'rollback', 'revoked', 'readback',
         'internal')  # the word after REFUSED
# What the host says (a JSON `error` word, only after it has accepted the signature) and what it is called here: a 409 is
# one of four different things, and only `conflict` means other bytes for the same serial.
HOST_REFUSALS = ('conflict', 'replay', 'rollback', 'revoked')
HOST_WORDS = ('bad-request', 'expired', 'stale', 'forbidden', 'checksum', 'too-large', 'length-required', 'readback',
              'unavailable', 'ceiling-life', 'ceiling-downloads', 'ceiling-open')  # shown after the status, never any other word
ROLE = 'upload'
MESSAGE_TAG = 'kit-admin-v1'
MAX_UPLOAD = fp.MAX_KIT_BUNDLE  # bytes: the publisher's cap (kit-host-size), which plan enforces first; kept here as the last line
MAX_CLOSURE = 65536  # closure.txt, a list of a few dozen paths
MAX_CLOSURE_PATHS = 2000
MAX_INSTALL = 8192  # install.json (the verifier's own cap)
MAX_SIG = 4096
MAX_GATEWAY_JSON, MAX_GATEWAY_SIG = 65536, 4096  # what the host accepts of each file of the pair
MAX_SERIAL = 999999999  # the host's range for a bundle serial
MAX_GATEWAY_SERIAL = MAX_SERIAL  # the host's route takes one to nine digits
MAX_FLOOR = 2 ** 31  # the host's range for a floor (kit/gate-core.js, LIMITS.maxSerial)
FLOOR_RX = re.compile(r'0|[1-9][0-9]{0,9}', re.ASCII)  # canonical decimal
GATEWAY_KEYS = ('serial', 'address', 'cert_sha256', 'manifest_key', 'session_key')  # a gateway record has all of these;
# kit.json and deploy-pin.json, signed under the same namespace by the same key, do not
MAX_ANSWER = 65536  # the most of an answer that is read
CLOSURE_PATH = 'fleet/install/closure.txt'
GATEWAY_PATH, GATEWAY_SIG_PATH = 'fleet/core/gateway.json', 'fleet/core/gateway.json.sig'
FLEET_TIP = 'refs/remotes/origin/release'
GIT = '/usr/bin/git'
OPENSSL = '/usr/bin/openssl'
SHM = '/dev/shm'  # where the key lives for the length of the run
KEY_PEM = re.compile(r'-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9+/=\n]{1,400}-----END PRIVATE KEY-----\n?', re.ASCII)
GIT_TIMEOUT, SIGN_TIMEOUT, NET_TIMEOUT = 600, 60, 900
USAGE_TEXT = ('usage: fleet-kit-upload.py bundle <dir> --owner-pub <path>\n'
              '       fleet-kit-upload.py gateway --owner-pub <path>\n'
              '       fleet-kit-upload.py floor <N>\n')


class Net(Protocol):
    """The one thing the upload does to the world, so a test can fake it (no network)."""

    def request(self, method: str, host: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        """One HTTPS request to host, no redirect followed; (status, at most MAX_ANSWER bytes of the answer). An error
        in the transport is Refused('net')."""


class Real:
    def request(self, method: str, host: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        conn = http.client.HTTPSConnection(host, timeout=NET_TIMEOUT)
        try:
            conn.request(method, path, body=body, headers=headers)
            answer = conn.getresponse()
            return answer.status, answer.read(MAX_ANSWER)
        except (OSError, http.client.HTTPException):
            raise Refused('net') from None
        finally:
            conn.close()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def wipe(path: Path) -> None:
    """Overwrite a file with zeros and remove it; missing is fine. A read-only file (git writes its objects 0444) is made
    writable first, so it is zeroed too."""
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    try:
        size = path.stat().st_size
        with open(path, 'r+b') as f:
            left = size
            while left > 0:
                n = min(left, 1 << 20)
                f.write(bytes(n))
                left -= n
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    with contextlib.suppress(OSError):
        path.unlink()


def wipe_tree(root: Path) -> None:
    """Every file under root overwritten and removed, then the folder itself."""
    for path in sorted(root.rglob('*')) if root.is_dir() else []:
        if path.is_file() and not path.is_symlink():
            wipe(path)
    shutil.rmtree(root, ignore_errors=True)


# --- git ---------------------------------------------------------------------------------------------------------

def git_env(environ: dict[str, str]) -> dict[str, str]:
    """A bare environment for git: nothing of the runner's, except the ssh command the workflow built for the read key."""
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
           'GIT_TERMINAL_PROMPT': '0'}
    if environ.get('GIT_SSH_COMMAND'):
        env['GIT_SSH_COMMAND'] = environ['GIT_SSH_COMMAND']
    return env


def git_run(repo: Path, env: dict[str, str], *args: str, log: Path | None = None) -> bytes:
    """git -C repo args under env; stdout. stderr goes to log (never printed) or nowhere. Any failure is Refused('fetch')."""
    try:
        with open(log or os.devnull, 'ab') as err:
            done = subprocess.run([GIT, '-C', str(repo), *args], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=err, check=False, timeout=GIT_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        raise Refused('fetch') from None
    if done.returncode != 0:
        raise Refused('fetch')
    return done.stdout


def fetch_fleet(remote: str, repo: Path, env: dict[str, str], log: Path, *, head: str | None = None, tip: bool = False) -> None:
    """Into the (already initialised) repo: the commit `head` at depth 1 and/or the tip of the `release` branch at depth 1."""
    if head is not None:
        git_run(repo, env, 'fetch', '-q', '--no-tags', '--depth', '1', '--', remote, head, log=log)
        if git_run(repo, env, 'rev-parse', 'FETCH_HEAD^{commit}', log=log).decode('ascii', 'replace').strip() != head:
            raise Refused('fetch')
    if tip:
        git_run(repo, env, 'fetch', '-q', '--no-tags', '--depth', '1', '--', remote, f'+refs/heads/release:{FLEET_TIP}', log=log)


def parse_closure(data: bytes) -> list[str]:
    """closure.txt: one path a line, LF only, a final newline, no blank line, none twice, at most MAX_CLOSURE bytes; else
    Refused('closure'). The packer itself refuses an unsafe, missing or never-listed path."""
    if not data or len(data) > MAX_CLOSURE:
        raise Refused('closure')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise Refused('closure') from None
    if '\r' in text or not text.endswith('\n'):
        raise Refused('closure')
    paths = text[:-1].split('\n')
    if len(paths) > MAX_CLOSURE_PATHS or '' in paths or len(set(paths)) != len(paths):
        raise Refused('closure')
    return paths


# --- the signed request --------------------------------------------------------------------------------------------

def message(role: str, ts_ms: int, method: str, path: str, body_sha: str) -> bytes:
    """What the key signs, byte for byte: the tag, the role, the time in milliseconds, the method, the path (no host, no
    query) and the sha256 of the body, one to a line and no final newline."""
    return '\n'.join((MESSAGE_TAG, role, str(ts_ms), method, path, body_sha)).encode('ascii')


class Signer:
    """KIT_UPLOAD_KEY in a 0600 file in a private folder (tmpfs where there is one) for the length of the run, and the
    one openssl call that signs with it. The key is never in an argument, a log line or an error."""

    def __init__(self, pem: str, run=subprocess.run, now_ms: Callable[[], int] | None = None) -> None:
        if not KEY_PEM.fullmatch(pem if pem.endswith('\n') else pem + '\n'):
            raise Refused('key')
        base = SHM if os.path.isdir(SHM) and os.access(SHM, os.W_OK) else None
        self.dir = Path(tempfile.mkdtemp(prefix='kit-key.', dir=base))
        self.key = self.dir / 'key'
        self._run, self._now_ms, self._last = run, now_ms or (lambda: int(time.time() * 1000)), 0
        fd = os.open(self.key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='ascii') as f:
            f.write(pem if pem.endswith('\n') else pem + '\n')

    def close(self) -> None:
        wipe_tree(self.dir)

    def sign(self, method: str, path: str, body: bytes) -> dict[str, str]:
        """The headers of one admin call: `Authorization: KitAdmin upload <ts_ms> <signature as 128 lower-case hex>`, and
        X-Kit-Sha256, the hash of the body that the signature covers. The time is strictly later than the one before (the
        host insists)."""
        self._last = ts = max(self._now_ms(), self._last + 1)
        body_sha = sha256_hex(body)
        msg, sig = self.dir / 'msg', self.dir / 'sig'
        msg.write_bytes(message(ROLE, ts, method, path, body_sha))
        try:
            done = self._run([OPENSSL, 'pkeyutl', '-sign', '-rawin', '-inkey', str(self.key), '-in', str(msg), '-out', str(sig)],
                             stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=SIGN_TIMEOUT,
                             env={'PATH': '/usr/bin:/bin'})  # nothing of the runner's environment, which holds the key's source
            raw = sig.read_bytes() if done.returncode == 0 else b''
        except (OSError, subprocess.SubprocessError):
            raw = b''
        finally:
            wipe(sig)
            wipe(msg)
        if len(raw) != 64:  # an Ed25519 signature
            raise Refused('sign')
        return {'Authorization': f'KitAdmin {ROLE} {ts} {raw.hex()}', 'X-Kit-Sha256': body_sha}


def answer_json(raw: bytes) -> dict:
    try:
        doc = fp.manifest.canon.loads_strict(raw)
    except fp.manifest.canon.SchemaError:
        raise Refused('readback') from None
    if not isinstance(doc, dict):
        raise Refused('readback')
    return doc


def stored(doc: object, sha: str, size: int) -> bool:
    """Does the host say it holds exactly sha and size."""
    return isinstance(doc, dict) and doc.get('sha256') == sha and type(doc.get('size')) is int and doc['size'] == size


def host_error(raw: bytes) -> str:
    """The `error` word of the host's JSON reply when it is one the host is known to say, else ''. Nothing else of the
    reply is ever shown."""
    try:
        doc = fp.manifest.canon.loads_strict(raw)
    except Exception:  # a non-JSON reply (the plain 404, a proxy's page) has no word
        return ''
    word = doc.get('error') if isinstance(doc, dict) else None
    return word if isinstance(word, str) and word in (*HOST_REFUSALS, *HOST_WORDS) else ''


def call(net: Net, signer: Signer, host: str, method: str, path: str, body: bytes) -> bytes:
    """One signed call; the answer's body on 200. Otherwise the host's own word decides: conflict, replay, rollback or
    revoked (all four are a 409) are said as they are; another known word follows the status (`upload 401 stale`), and a
    reply without one is `upload <status>`."""
    headers = {**signer.sign(method, path, body), 'Content-Type': 'application/octet-stream'}
    status, raw = net.request(method, host, path, headers, body)
    if status != 200:
        word = host_error(raw)
        if word in HOST_REFUSALS:
            raise Refused(word)
        raise Refused(f'upload {status} {word}' if word else f'upload {status}')
    return raw


# --- the two verbs -------------------------------------------------------------------------------------------------

def read_bounded(path: Path, limit: int) -> bytes:
    try:
        with open(path, 'rb') as f:
            data = f.read(limit + 1)
    except OSError:
        raise Refused('install') from None
    if not data or len(data) > limit:
        raise Refused('install')
    return data


def signed_manifest(folder: Path, owner_pub: bytes, kit_host: str) -> dict:
    """install.json once its signature holds under the owner's key, its shape fits and its bundle url is this host's
    download of this serial; else Refused. Expiry and the bootstrap blobs are the publisher's checks, not this one's."""
    text, sig = read_bounded(folder / 'install.json', MAX_INSTALL), read_bounded(folder / 'install.json.sig', MAX_SIG)
    fp.manifest.verify_signature(text, sig, owner_pub, fp.run_argv)
    doc = fp.parse_install(text)
    if not 1 <= doc['serial'] <= MAX_SERIAL:
        raise Refused('install')
    fp.check_bundle_url(doc, kit_host)
    return doc


def build_bundle(doc: dict, remote: str, work: Path, env: dict[str, str]) -> bytes:
    """The bundle tar for doc's bundle block, built from the commit it names. Every word the build prints (and the whole of
    git's stderr) goes to work/build.log, which nothing prints; a build that fails says only `bundle-build`."""
    log = work / 'build.log'
    block = doc['bundle']
    repo = work / 'fleet'
    repo.mkdir()
    git_run(repo, env, 'init', '-q', log=log)
    fetch_fleet(remote, repo, env, log, head=block['head'])
    try:
        with open(log, 'a', encoding='utf-8') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            try:
                listed = git_run(repo, env, 'cat-file', 'blob', f'{block["head"]}:{CLOSURE_PATH}', log=log)
            except Refused:
                raise Refused('closure') from None  # the list is not in that commit
            closure = packer.cut(repo, block['head'], parse_closure(listed))
            if closure.head != block['head']:
                raise Refused('bundle-hash head')
            if closure.tree != block['tree']:
                raise Refused('bundle-hash tree')
            return packer.pack(closure)
    except Refused:
        raise
    except Exception:  # BundleError and any other: its text can name private paths, so it is not said
        raise Refused('bundle-build') from None


def upload_bundle(folder: Path, owner_pub: bytes, environ: dict[str, str], net: Net, signer: Signer, work: Path) -> str:
    host = fp.check_kit_host(environ.get('KIT_HOST', ''))
    doc = signed_manifest(folder, owner_pub, host)
    block, serial = doc['bundle'], doc['serial']
    tar = build_bundle(doc, environ['FLEET_REPO'], work, git_env(environ))
    if len(tar) > MAX_UPLOAD:
        raise Refused('bundle-size')
    path = work / 'bundle.tar'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(tar)
    sha, size = sha256_hex(tar), len(tar)
    print(f'kit bundle serial={serial} size={size} sha256={sha}', flush=True)
    if size != block['size']:
        raise Refused('bundle-hash size')
    if sha != block['sha256']:
        raise Refused('bundle-hash sha256')
    answer = call(net, signer, host, 'PUT', f'/_k/file/{serial}/bundle.tar', tar)
    if not stored(answer_json(answer), sha, size):
        raise Refused('readback')
    return f'OK bundle serial={serial} size={size} sha256={sha}'


def upload_gateway(owner_pub: bytes, environ: dict[str, str], net: Net, signer: Signer, work: Path) -> str:
    host = fp.check_kit_host(environ.get('KIT_HOST', ''))
    env, repo, log = git_env(environ), work / 'fleet', work / 'fetch.log'
    repo.mkdir()
    git_run(repo, env, 'init', '-q', log=log)
    fetch_fleet(environ['FLEET_REPO'], repo, env, log, tip=True)
    try:
        text = git_run(repo, env, 'cat-file', 'blob', f'{FLEET_TIP}:{GATEWAY_PATH}', log=log)
        sig = git_run(repo, env, 'cat-file', 'blob', f'{FLEET_TIP}:{GATEWAY_SIG_PATH}', log=log)
    except Refused:
        raise Refused('gateway') from None  # the pair is not at the release tip
    if not 0 < len(text) <= MAX_GATEWAY_JSON or not 0 < len(sig) <= MAX_GATEWAY_SIG:
        raise Refused('gateway')
    fp.verify_pin_signature(text, sig, owner_pub, fp.run_argv)  # Refused('sig'): the owner signed this very pair
    try:
        doc = fp.manifest.canon.loads_strict(text)
    except fp.manifest.canon.SchemaError:
        raise Refused('gateway') from None
    if not isinstance(doc, dict) or any(key not in doc for key in GATEWAY_KEYS):
        raise Refused('gateway')  # signed by the owner under this namespace, but not a gateway record
    serial = doc['serial']
    if type(serial) is not int or not 1 <= serial <= MAX_GATEWAY_SERIAL:
        raise Refused('gateway')
    body = json.dumps({'json': base64.b64encode(text).decode('ascii'), 'sig': base64.b64encode(sig).decode('ascii')},
                      sort_keys=True, separators=(',', ':')).encode('ascii')
    answer = answer_json(call(net, signer, host, 'PUT', f'/_k/gateway/{serial}', body))
    if (answer.get('gserial') != serial or not stored(answer.get('json'), sha256_hex(text), len(text))
            or not stored(answer.get('sig'), sha256_hex(sig), len(sig))):
        raise Refused('readback')
    return f'OK gateway serial={serial} json={sha256_hex(text)} sig={sha256_hex(sig)}'


def upload_floor(floor: int, environ: dict[str, str], net: Net, signer: Signer) -> str:
    host = fp.check_kit_host(environ.get('KIT_HOST', ''))
    body = json.dumps({'floor': floor}, separators=(',', ':')).encode('ascii')
    answer = answer_json(call(net, signer, host, 'PUT', '/_k/floor', body))
    if answer.get('ok') is not True or type(answer.get('floor')) is not int or answer['floor'] != floor:
        raise Refused('readback')
    return f'OK floor={floor}'


def parse_args(argv: list[str]) -> tuple[str, Path | int | None, str] | None:
    """(verb, dir or floor or None, owner-pub path) from `bundle <dir> --owner-pub P`, `gateway --owner-pub P` or `floor N`
    (N canonical decimal, at most MAX_FLOOR), or None."""
    if len(argv) == 5 and argv[1] == 'bundle' and argv[3] == '--owner-pub':
        return 'bundle', Path(argv[2]), argv[4]
    if len(argv) == 4 and argv[1] == 'gateway' and argv[2] == '--owner-pub':
        return 'gateway', None, argv[3]
    if len(argv) == 3 and argv[1] == 'floor' and FLOOR_RX.fullmatch(argv[2]) and int(argv[2]) <= MAX_FLOOR:
        return 'floor', int(argv[2]), ''
    return None


def main(argv: list[str], environ: dict[str, str], net: Net | None = None) -> int:
    """0 done, 1 refused, 2 usage. The environment: KIT_HOST (the workflow's constant), KIT_UPLOAD_KEY (the Ed25519 key, PEM),
    FLEET_REPO (the private repository's address; `floor` does not need it), RUNNER_TEMP, OWNER_PIN_SHA256 (the owner key's fingerprint: it is what
    ties --owner-pub to the key the owner pinned, so a run without it is `REFUSED key`) and GIT_SSH_COMMAND (the read
    key's ssh command, optional). KIT_UPLOAD_KEY is taken out of this process's own environment at once, so no child
    process (git, ssh-keygen, openssl) inherits it."""
    args = parse_args(argv)
    if args is None:
        sys.stderr.write(USAGE_TEXT)
        return 2
    verb, folder, pub_path = args
    os.environ.pop('KIT_UPLOAD_KEY', None)
    work = signer = None
    try:
        needed = ('KIT_HOST', 'KIT_UPLOAD_KEY', 'RUNNER_TEMP') + (() if verb == 'floor' else ('FLEET_REPO',))
        if not all(environ.get(k) for k in needed) or not os.path.isdir(environ['RUNNER_TEMP']):
            raise Refused('env')
        if verb == 'floor':  # the upload key and the host, nothing of the fleet repository or the owner key
            signer = Signer(environ['KIT_UPLOAD_KEY'])
            line = upload_floor(folder, environ, net or Real(), signer)
        else:
            if not environ.get('OWNER_PIN_SHA256'):
                raise Refused('key')
            owner_pub = fp.owner_key(pub_path, environ['OWNER_PIN_SHA256'], fp.run_argv)
            work = Path(tempfile.mkdtemp(prefix='kit-', dir=environ['RUNNER_TEMP']))
            signer = Signer(environ['KIT_UPLOAD_KEY'])
            net = net or Real()
            line = (upload_bundle(folder, owner_pub, environ, net, signer, work) if verb == 'bundle'
                    else upload_gateway(owner_pub, environ, net, signer, work))
    except Refused as why:
        sys.stderr.write(f'fleet-kit-upload: refused {why.code.split()[0]}\n')
        print(f'REFUSED {why.code}')
        return 1
    except Exception:  # nothing a failure carries is shown: it can hold a path of the private repository
        sys.stderr.write('fleet-kit-upload: refused internal\n')
        print('REFUSED internal')
        return 1
    finally:
        if signer is not None:
            signer.close()
        if work is not None:
            wipe_tree(work)
    print(line)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv, dict(os.environ)))
