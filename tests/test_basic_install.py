"""basic/install.sh, the public one-line bootstrap of fleet basic mode (the fleet code itself is private and arrives as a per-machine
encrypted invite). The script runs for real under /bin/sh, dash and bash over a sandbox: FB_SANDBOX=1 points every system path into a
temp root and PATH holds only stand-ins (curl serving a local folder, sudo, uname, sw_vers, pkgutil, installer, scutil, plutil, caffeinate,
claude, df, id, a fake `fleet-basic` and a fake source tree inside a REAL invite that the test encrypts with the real openssl and a
throwaway key) plus symlinks to a short list of harmless real tools. Nothing outside the temp dir is touched: the stand-in sudo refuses
(and logs SANDBOX-ESCAPE for) any rm/mv/chmod/mkdir/install outside it. What is proved: the invite is matched against its exact shape
before any command runs; the sha256, the key and the archive (only fleet/, bin/fleet-basic*.py, COMMIT; no link, no `..`, no absolute
name) are checked before anything is unpacked; the Mac base image placeholder refuses before any slow step; the pinned python.org pkg
is checked (sha256, signature) before `installer`; every curl is https-only and follows no redirect by itself (the script follows GitHub's one hop and holds every
hop to github.com / githubusercontent.com); the invite key and the Claude token never reach an argv, a log or the output; every step
resumes (a finished Mac image survives a STOP in step 6 or 7); a STOP kills a running bake; a default host name carries 4 hex of the
machine id; a script cut short runs nothing. The text is public, so
it is also scanned: no secret shape, and no URL but fleet-disk releases, python.org and the one printed Claude line. Plain unittest,
stdlib only; the tests that need a real openssl with -pbkdf2 are skipped without one."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / 'basic/install.sh'
README = ROOT / 'basic/README.md'
TEXT = SCRIPT.read_text(encoding='utf-8')
SYSTEM_PATH = '/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin'
SHELLS = [s for s in ('/bin/sh', '/bin/dash', '/bin/bash') if os.path.exists(s)]


def which(name: str) -> str:
    return shutil.which(name, path=SYSTEM_PATH) or ''


def find_openssl() -> str:
    """An openssl that has -pbkdf2 (LibreSSL 3.x and OpenSSL 1.1.1+ do); '' when there is none."""
    exe = which('openssl')
    if not exe:
        return ''
    probe = subprocess.run([exe, 'enc', '-aes-256-cbc', '-pbkdf2', '-iter', '1000', '-md', 'sha256', '-pass', 'stdin'], input=b'k\nx',
                           capture_output=True)
    return exe if probe.returncode == 0 else ''


OPENSSL = find_openssl()
need_openssl = unittest.skipUnless(OPENSSL, 'no openssl with -pbkdf2')
TOOLS = ('awk basename cat chmod cp cut date dirname env grep gzip head ls mkdir mktemp mv od ps rm rmdir sed sha256sum shasum tail tar tr touch '
         'wc').split()
sha = lambda data: hashlib.sha256(data).hexdigest()  # noqa: E731

PY_SHA_REAL = '286c7018aa2730f6747ca433dccdc2b31be45f078a9ea0ffa44d5f06368fd2d7'
BASE_GZ = b'BASE-RAW-GZ'
BASE_URL = 'https://github.com/mirrorstack-ai/fleet-disk/releases/download/basic-base-1/noble-arm64-base.raw.gz'
RAW_SHA = 'd' * 64
MAC_SEALED = sha(b'mac-sealed')
LINUX_SEALED = sha(b'linux-sealed')
TOKEN = 'tok-' + 'Q' * 40  # what the helper pastes: must never reach an argv, a log or the output
MAC_UUID = '11111111-2222-3333-4444-555555555555'  # IOPlatformUUID of the fake Mac; the default host name ends in 4 hex of sha256('fleet-basic:' + it)
LINUX_MID = 'ab' * 16  # /etc/machine-id of the fake PC
tag = lambda machine_id: sha(f'fleet-basic:{machine_id}'.encode())[:4]  # noqa: E731
MAC_TAG, LINUX_TAG = tag(MAC_UUID), tag(LINUX_MID)


def lock_text(entry) -> str:
    """basic-mac.lock.json with base_raw as given: 'published', 'todo', 'missing', or a dict."""
    lock = {'v': 1, 'platform': 'macos-arm64', 'base': {'sha256': '50e2' + '0' * 60}}
    if entry == 'published':
        lock['base_raw'] = {'url': BASE_URL, 'gz_sha256': sha(BASE_GZ), 'raw_sha256': RAW_SHA, 'source': 'test'}
    elif entry == 'todo':
        lock['base_raw'] = {'url': 'TODO', 'gz_sha256': 'TODO', 'raw_sha256': 'TODO', 'source': 'TODO, NOT PUBLISHED YET'}
    elif isinstance(entry, dict):
        lock['base_raw'] = entry
    return json.dumps(lock, indent=1) + '\n'


# --- the fake fleet tree (inside the real, encrypted invite) --------------------------------------------------------------------
INSTALL_STUB = """#!/bin/sh
echo "install-$OSNAME.sh $*" >>"$FB_LOG"
host=''; while [ $# -gt 0 ]; do [ "$1" = --host ] && host=$2; shift; done
[ -z "${FAKE_INSTALL_FAIL:-}" ] || { echo 'REFUSED python fake'; exit 1; }
mkdir -p "$(dirname "$FB_PATH")" "$FB_STATE"
cp "$FB_STUB" "$FB_PATH"; chmod 755 "$FB_PATH"
echo "$host" >"$FB_STATE/host"
echo 'ok S01 fake'
echo 'DONE install: the switch is OFF.'
"""
GOLDEN_MAC_PY = f'''import os, sys, time
a = sys.argv[1:]
with open(os.environ['FB_LOG'], 'a') as f:
    f.write('golden.py ' + ' '.join(a) + '\\n')
st = os.environ['FB_STATE']
open(os.path.join(st, 'bake-started'), 'w').close()
if os.environ.get('FAKE_BAKE_HANG'):
    open(os.path.join(st, 'bake.pid'), 'w').write(str(os.getpid()))
    time.sleep(30)
if os.environ.get('FAKE_BAKE_FAIL'):
    print('REFUSED no-marker')
    sys.exit(1)
stage = a[a.index('--out') + 1]
assert open(os.path.join(stage, 'base.raw.gz'), 'rb').read() == {BASE_GZ!r}
open(os.path.join(stage, 'noble-arm64.raw'), 'w').write('raw')
print('OK sealed {MAC_SEALED}')
'''
GOLDEN_LINUX_PY = f'''import os, sys
a = sys.argv[1:]
with open(os.environ['FB_LOG'], 'a') as f:
    f.write('golden_linux ' + ' '.join(a) + '\\n')
if a[:2] == ['bake', '--out']:
    open(os.path.join(a[2], 'bake-host.sh'), 'w').write(
        '#!/bin/sh\\ntouch "$FB_STATE/bake-started"\\ncase "${{FAKE_BAKE_FAIL:-}}" in ?*) echo "FLEETBAKE FAILED fake"; exit 1;; esac\\n'
        'printf data >"$1/golden.qcow2"; echo "{LINUX_SEALED}  golden.qcow2" >"$1/golden.qcow2.sha256"\\n')
elif a[0] == 'verify':
    sys.exit(0 if a[2] == '{LINUX_SEALED}' and os.path.exists(a[1]) else 1)
'''
FB_STUB = f"""#!/bin/sh
S=$FB_STATE
echo "fleet-basic $*" >>"$FB_LOG"
case $1 in
  status) echo state=off; echo "host=$(cat "$S/host" 2>/dev/null || echo none)"; echo "shas=$(cat "$S/shas" 2>/dev/null || echo 0)"; echo repos=0
          [ -f "$S/key" ] && echo key=yes || echo key=no; echo apps=yes; [ -f "$S/token" ] && echo token=yes || echo token=no; echo busy=no ;;
  claude-token) w=$(sed -n '/./{{p;q;}}' | tr -d ' '); [ -z "${{FAKE_TOKEN_REFUSE:-}}" ] && [ "${{#w}}" -ge 20 ] || {{ echo 'REFUSED shape'; exit 1; }}
                echo "$w" >"$S/token"; echo 'OK claude.token fingerprint bbbbbbbbbbbb' ;;
  pair) [ -f "$S/key" ] && {{ echo 'OK pair already approved host=x runner=aaaaaaaaaaaa'; exit 0; }}
        [ -z "${{FAKE_PAIR_WAIT_FOR:-}}" ] || {{ i=0; while [ ! -f "$FAKE_PAIR_WAIT_FOR" ] && [ "$i" -lt 100 ]; do sleep 1; i=$((i + 1)); done; }}
        [ -z "${{FAKE_PAIR_FAIL:-}}" ] || {{ echo 'REFUSED pair-timeout no approval'; exit 1; }}
        echo 'PAIR v1 fake-host QUFB'; touch "$S/key"; echo 1 >"$S/shas" ;;
  golden) [ -f "$2" ] || exit 1; mkdir -p "$(dirname "$FB_GOLDEN")"; echo sealed >"$FB_GOLDEN"; echo "DONE golden: sealed $3" ;;
  doctor) echo 'PASS D01 fake'; [ -z "${{FAKE_DOCTOR_FAIL:-}}" ] && echo 'DOCTOR ok' || {{ echo 'DOCTOR 1 failing'; exit 1; }} ;;
  mint-test) echo 'fleet-basic: minted runner=1'; [ -z "${{FAKE_MINT_FAIL:-}}" ] && echo ok || {{ echo 'not-set-up app'; exit 2; }} ;;
  enable) echo 'DONE enable' ;;
  fingerprint) case $2 in runner) echo 'OK runner-app.pem fingerprint aaaaaaaaaaaa' ;; claude) echo 'OK claude.token fingerprint bbbbbbbbbbbb' ;; esac ;;
  *) exit 2 ;;
esac
"""

# --- the stand-ins on PATH -----------------------------------------------------------------------------------------------------
SUDO = """#!/bin/sh
U=''
while [ $# -gt 0 ]; do
  case $1 in
    -v) exit "${FAKE_SUDO_RC:-0}" ;;
    -u) U="-u $2 "; shift 2 ;;
    -*) shift ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || exit 0
case $1 in true | kill) ;; *) echo "sudo $U$*" >>"$FB_LOG" ;; esac
case $1 in rm | mv | chmod | mkdir | install | mktemp)
  for a in "$@"; do case $a in /*) case $a in "$FB_ROOT"/* | "$HOME"/* | "$TMPDIR"/*) ;; *) echo "SANDBOX-ESCAPE $a" >>"$FB_LOG"; exit 99 ;; esac ;; esac; done ;;
esac
exec "$@"
"""
CURL = """#!/bin/sh
echo "curl $*" >>"$FB_LOG"
out='' url='' w=''
while [ $# -gt 0 ]; do case $1 in -o) out=$2; shift ;; -w) w=1; shift ;; esac; url=$1; shift; done
name=${url##*/}
case "${FAKE_CURL_FAIL:-}" in *"$name"*) exit 22 ;; esac
case "${FAKE_REDIRECT:-}" in "$url="*) : >"$out"; [ -z "$w" ] || printf '%s %s' "${FAKE_REDIRECT_CODE:-302}" "${FAKE_REDIRECT#*=}"; exit 0 ;; esac
[ -f "$WEB/$name" ] || exit 22
cp "$WEB/$name" "$out"
[ -z "$w" ] || printf '200 '
"""
INSTALLER = """#!/bin/sh
echo "installer $*" >>"$FB_LOG"
while [ $# -gt 0 ]; do [ "$1" = -applyChoiceChangesXML ] && cp "$2" "$FB_STATE/choices.xml"; shift; done
[ -z "${FAKE_INSTALLER_FAIL:-}" ] || { echo 'installer: failed'; exit 1; }
mkdir -p "$(dirname "$FB_PYM")"
printf '#!/bin/sh\\nexec "$FAKE_PY" "$@"\\n' >"$FB_PYM"; chmod 755 "$FB_PYM"
d=$(dirname "$FB_PYM"); while [ "$d" != "$FB_ROOT" ]; do chmod 755 "$d"; d=$(dirname "$d"); done
"""
INSTALL_PY = """#!/bin/sh
exec "$FAKE_PY" -I -c 'import os, shutil, sys
a, mode, dirs, big_d, rest, i = sys.argv[1:], None, False, False, [], 0
while i < len(a):
    if a[i] in ("-o", "-g"):
        i += 1
    elif a[i] == "-m":
        mode = int(a[i + 1], 8)
        i += 1
    elif a[i] == "-d":
        dirs = True
    elif a[i] == "-D":
        big_d = True
    else:
        rest.append(a[i])
    i += 1
if dirs:
    for d in rest:
        os.makedirs(d, exist_ok=True)
        os.chmod(d, mode or 0o755)
else:
    src, dst = rest
    if big_d:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.exists(dst):
        os.chmod(dst, 0o644)
        os.unlink(dst)
    shutil.copyfile(src, dst)
    os.chmod(dst, mode or 0o755)' "$@"
"""
PLUTIL = """#!/bin/sh
exec "$FAKE_PY" -I -c 'import json, sys
d = json.load(open(sys.argv[2]))
for k in sys.argv[1].split("."):
    d = d[k]
sys.stdout.write(str(d))' "$2" "$6" 2>/dev/null
"""
CLAUDE = """#!/bin/sh
i=0; while [ ! -f "$FB_STATE/bake-started" ] && [ "$i" -lt 100 ]; do sleep 1; i=$((i + 1)); done
echo "claude $* bake-started=$([ -f "$FB_STATE/bake-started" ] && echo yes || echo no)" >>"$FB_LOG"
echo FAKE-CLAUDE-OUTPUT
"""


def stand_ins() -> dict:
    sleep = which('sleep')
    return {
        'sudo': SUDO, 'curl': CURL, 'installer': INSTALLER, 'plutil': PLUTIL, 'claude': CLAUDE,
        'chown': '#!/bin/sh\necho "chown $*" >>"$FB_LOG"\n',
        'install': INSTALL_PY,
        'id': '#!/bin/sh\n[ "$1" = -u ] && echo "${FAKE_UID:-501}"\n',
        'uname': '#!/bin/sh\ncase $1 in -s) echo "$FAKE_OS_S" ;; -m) echo "$FAKE_ARCH" ;; esac\n',
        'sw_vers': '#!/bin/sh\necho "$FAKE_MACOS"\n',
        'scutil': '#!/bin/sh\n[ -n "${FAKE_LOCALHOST+x}" ] && [ -n "$FAKE_LOCALHOST" ] && echo "$FAKE_LOCALHOST" || exit 1\n',
        'hostname': '#!/bin/sh\necho "${FAKE_HOSTNAME:-}"\n',
        'ioreg': '#!/bin/sh\n[ -n "${FAKE_MACHINE_ID+x}" ] && [ -n "$FAKE_MACHINE_ID" ] || exit 1\n'
                 'echo \'    | "IOPlatformUUID" = "\'"$FAKE_MACHINE_ID"\'"\'\n',
        'df': '#!/bin/sh\necho "Filesystem 1024-blocks Used Available Capacity Mounted"\n'
              'echo "fake 1 1 ${FAKE_FREE_KB:-999999999} 1% /"\n',
        'pkgutil': '#!/bin/sh\necho "${FAKE_PKG_SIG:-Package: signed. 1. Developer ID Installer: Python Software Foundation (X)}"\n'
                   'exit "${FAKE_PKG_RC:-0}"\n',
        'caffeinate': '#!/bin/sh\necho "caffeinate $*" >>"$FB_LOG"\n',
        'sleep': f'#!/bin/sh\n[ "$1" = 50 ] && exec {sleep} 2\nexec {sleep} 0.05\n',
        'python3': '#!/bin/sh\nexec "$FAKE_PY" "$@"\n',
    }


def put(path: Path, text: str | bytes, mode: int = 0o755) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text if isinstance(text, bytes) else text.encode())
    path.chmod(mode)
    return path


# --- a real invite -------------------------------------------------------------------------------------------------------------
class Invite:
    def __init__(self, members: dict, commit: str | None = None, key: str | None = None):
        self.commit = commit if commit is not None else sha(secrets.token_bytes(8))[:40]
        self.id, self.key = secrets.token_hex(6), key or secrets.token_urlsafe(32)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            for name, body in {**members, 'COMMIT': (self.commit + '\n').encode()}.items():
                info = tarfile.TarInfo(name)
                info.mtime = 0
                if isinstance(body, tuple):
                    info.type = {'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE}[body[0]]
                    info.linkname = body[1]
                    tar.addfile(info)
                else:
                    data = body if isinstance(body, bytes) else body.encode()
                    info.size, info.mode = len(data), 0o755 if name.endswith(('.sh', '.py')) else 0o644
                    tar.addfile(info, io.BytesIO(data))
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'in.tgz').write_bytes(buf.getvalue())
            subprocess.run([OPENSSL, 'enc', '-aes-256-cbc', '-salt', '-pbkdf2', '-iter', '600000', '-md', 'sha256', '-pass', 'stdin',
                            '-in', str(Path(d) / 'in.tgz'), '-out', str(Path(d) / 'out.enc')], input=(self.key + '\n').encode(), check=True)
            self.enc = (Path(d) / 'out.enc').read_bytes()
        self.digest = sha(self.enc)

    @property
    def line(self) -> str:
        return f'{self.id}.{self.key}.{self.digest}'


def tree(lock='published', **extra) -> dict:
    """The members of a good invite; extra adds (or, with None, drops) members."""
    members = {
        'bin/fleet-basic.py': '# fake\n', 'bin/fleet-basic-golden.py': GOLDEN_MAC_PY, 'fleet/__init__.py': '', 'fleet/basic/__init__.py': '',
        'fleet/basic/install-mac.sh': INSTALL_STUB.replace('$OSNAME', 'mac'), 'fleet/basic/install-linux.sh': INSTALL_STUB.replace('$OSNAME', 'linux'),
        'fleet/basic/basic-mac.lock.json': lock_text(lock), 'fleet/basic/golden_linux.py': GOLDEN_LINUX_PY,
    }
    members.update({k.replace('__', '/'): v for k, v in extra.items()})
    return {k: v for k, v in members.items() if v is not None}


_CACHE: dict = {}


def invite(name: str, **kw) -> Invite:
    """One real invite per variant (the openssl step is the slow one). commit= and key= shape the invite, the rest the tree."""
    if name not in _CACHE:
        own = {k: kw.pop(k) for k in ('commit', 'key', 'members') if k in kw}
        _CACHE[name] = Invite(own.get('members') or tree(**kw), commit=own.get('commit'), key=own.get('key'))
    return _CACHE[name]


# --- the sandbox ---------------------------------------------------------------------------------------------------------------
class Result:
    def __init__(self, proc: subprocess.CompletedProcess, log: str):
        self.rc, self.out, self.log = proc.returncode, proc.stdout + proc.stderr, log

    def stops(self) -> list:
        return [line for line in self.out.splitlines() if line.startswith('STOP ')]

    def calls(self, prefix: str) -> list:
        return [line for line in self.log.splitlines() if line.startswith(prefix)]

    def index(self, prefix: str) -> int:
        found = [i for i, line in enumerate(self.log.splitlines()) if line.startswith(prefix)]
        assert found, f'{prefix!r} not in log:\n{self.log}'
        return found[0]


_SHARED: dict = {}


def shared() -> Path:
    """The stand-ins and tool links, made once per process (a fresh executable is scanned on first use on macOS); the stand-ins read
    everything that differs per test from the environment."""
    if not _SHARED:
        d = Path(tempfile.mkdtemp(prefix='fbi-shared-')).resolve()
        _SHARED['d'] = d
        unittest.addModuleCleanup(shutil.rmtree, d, True)
        stands = stand_ins()
        put(d / 'claude-bin' / 'claude', stands.pop('claude'))
        for name, body in stands.items():
            put(d / 'bin' / name, body)
        (d / 'tools').mkdir()
        for name in TOOLS:
            if which(name):
                (d / 'tools' / name).symlink_to(which(name))
        (d / 'tools/openssl').symlink_to(OPENSSL or '/usr/bin/false')
        put(d / 'stub-fleet-basic', FB_STUB)
        for shell in SHELLS:
            (d / f'sh{shell.replace("/", "_")}').mkdir()
            (d / f'sh{shell.replace("/", "_")}' / 'sh').symlink_to(shell)
    return _SHARED['d']


class Box:
    """A temp world: the root the script's paths are prefixed with, a home, a web folder for curl, a state folder for the fakes."""

    def __init__(self, osname: str = 'mac'):
        self.osname = osname
        self.d = Path(tempfile.mkdtemp(prefix='fbi-')).resolve()
        d = self.d
        for sub in ('root', 'home', 'tmp', 'web', 'cwd', 'state'):
            (d / sub).mkdir()
        self.bin, self.tools, self.has_claude = shared() / 'bin', shared() / 'tools', True
        self.root, self.home, self.state, self.web = d / 'root', d / 'home', d / 'state', d / 'web'
        self.log, self.tty = d / 'log.txt', d / 'tty.txt'
        self.log.write_text('')
        self.tty.write_text('\n' + TOKEN + '\n')
        self.fb = self.root / 'usr/local/sbin/fleet-basic'
        self.pym = self.root / 'Library/Frameworks/Python.framework/Versions/Current/bin/python3'
        self.golden = (self.root / 'Library/Application Support/fleet-basic-vm/golden/noble-arm64.raw' if osname == 'mac'
                       else self.root / 'var/lib/fleet-basic/golden/noble-x86_64.qcow2')
        self.src_parent = (self.root / 'Library/Application Support/fleet-basic-src' if osname == 'mac'
                           else self.root / 'usr/local/share/fleet-basic-src')
        self.stage = self.home / '.fleet-basic-stage' if osname == 'mac' else self.root / 'var/tmp/fb-stage'
        self.env = {'FAKE_OS_S': 'Darwin' if osname == 'mac' else 'Linux', 'FAKE_ARCH': 'arm64' if osname == 'mac' else 'x86_64',
                    'FAKE_MACOS': '15.1', 'FAKE_LOCALHOST': 'Test Mac', 'FAKE_HOSTNAME': 'test-pc', 'FAKE_MACHINE_ID': MAC_UUID}
        if osname == 'mac':
            self.python_ok()
        else:
            put(self.root / 'etc/os-release', 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n', 0o644)
            put(self.root / 'dev/kvm', '', 0o666)
            put(self.root / 'proc/meminfo', 'MemTotal: 16000000 kB\nMemAvailable: 15000000 kB\n', 0o644)
            put(self.root / 'etc/machine-id', LINUX_MID + '\n', 0o444)
            (self.root / 'var/tmp').mkdir(parents=True)

    def python_ok(self) -> None:
        (self.root).chmod(0o755)
        put(self.pym, '#!/bin/sh\nexec "$FAKE_PY" "$@"\n')
        for p in self.pym.parents:
            p.chmod(0o755)
            if p == self.root:
                break

    def installed(self, host: str = 'prior-host', *, token=True, paired=True, golden=True) -> None:
        """The state a finished earlier run left (for the resume tests)."""
        put(self.fb, FB_STUB)
        self.state.mkdir(exist_ok=True)
        (self.state / 'host').write_text(host + '\n')
        if token:
            (self.state / 'token').write_text('x')
        if paired:
            (self.state / 'key').write_text('x')
            (self.state / 'shas').write_text('1\n')
        if golden:
            put(self.golden, 'sealed', 0o444)

    def serve(self, inv: Invite, **files) -> None:
        (self.web / f'inv-{inv.id}.enc').write_bytes(inv.enc)
        (self.web / 'noble-arm64-base.raw.gz').write_bytes(BASE_GZ)
        (self.web / 'python-3.14.10-macos11.pkg').write_bytes(b'FAKE-PKG')
        for name, body in files.items():
            (self.web / name).write_bytes(body)

    def script(self, patch_py_sha: bool = False) -> Path:
        """The script under test; patch_py_sha swaps the pinned pkg sha256 for the fake pkg's (one line, checked)."""
        if not patch_py_sha:
            return SCRIPT
        patched = TEXT.replace(f'PY_SHA={PY_SHA_REAL}', f'PY_SHA={sha(b"FAKE-PKG")}')
        assert patched != TEXT
        return put(self.d / 'install-patched.sh', patched)

    def path(self, shell: str = '/bin/sh') -> str:
        """PATH: the shell as `sh`, the stand-ins, `claude` (unless this box has none), the harmless real tools."""
        parts = [shared() / ('sh' + shell.replace('/', '_')), self.bin]
        if self.has_claude:
            parts.append(shared() / 'claude-bin')
        return ':'.join(str(p) for p in [*parts, self.tools])

    def run(self, line: str | None, *args: str, shell: str = '/bin/sh', pipe: bool = False, patch_py_sha: bool = True, tty: str | None = None,
            timeout: int = 120, **env) -> Result:
        if tty is not None:
            self.tty.write_text(tty)
        base = {
            'PATH': self.path(shell), 'FB_SANDBOX': '1', 'FB_ROOT': str(self.root), 'FB_ROOT_UID': str(os.getuid()),
            'FB_TTY': str(self.tty), 'FB_LOG': str(self.log), 'FB_STATE': str(self.state), 'FB_GOLDEN': str(self.golden), 'FB_PATH': str(self.fb),
            'FB_STUB': str(shared() / 'stub-fleet-basic'), 'FB_PYM': str(self.pym), 'FAKE_PY': sys.executable, 'WEB': str(self.web),
            'HOME': str(self.home), 'TMPDIR': str(self.d / 'tmp'), 'USER': 'helper'}
        script = self.script(patch_py_sha=patch_py_sha and self.osname == 'mac')
        argv = list(args) if line is None else [line, *args]
        if pipe:  # a real pipe, as curl makes it
            proc = subprocess.run([shell, '-s', '--', *argv], input=script.read_bytes(), capture_output=True, cwd=self.d / 'cwd',
                                  env={**base, **self.env, **env}, timeout=timeout)
            proc = subprocess.CompletedProcess(proc.args, proc.returncode, proc.stdout.decode(), proc.stderr.decode())
        else:
            proc = subprocess.run([shell, str(script), *argv], stdin=subprocess.DEVNULL, capture_output=True, text=True, cwd=self.d / 'cwd',
                                  env={**base, **self.env, **env}, timeout=timeout)
        return Result(proc, self.log.read_text())

    def cleanup(self) -> None:
        shutil.rmtree(self.d, ignore_errors=True)


class BoxCase(unittest.TestCase):
    def box(self, osname: str = 'mac') -> Box:
        b = Box(osname)
        self.addCleanup(b.cleanup)
        return b

    def ready(self, osname: str = 'mac', name: str = 'good', **kw) -> tuple:
        b = self.box(osname)
        inv = invite(name, **kw)
        b.serve(inv)
        return b, inv

    def assertStopped(self, res: Result, code: str, calls_before_stop: str | None = None) -> None:
        self.assertNotEqual(res.rc, 0, res.out)
        self.assertEqual(len(res.stops()), 1, res.out)
        self.assertTrue(res.stops()[0].startswith(f'STOP {code}'), res.out)
        self.assertNotIn('FLEET-BASIC READY', res.out)
        self.assertNotIn('SANDBOX-ESCAPE', res.log)


class Static(unittest.TestCase):
    """The public text itself."""
    CODE = '\n'.join(line for line in TEXT.splitlines() if not line.lstrip().startswith('#'))

    def test_syntax_under_every_shell(self):
        for shell in SHELLS:
            with self.subTest(shell=shell):
                self.assertEqual(subprocess.run([shell, '-n', str(SCRIPT)], capture_output=True).returncode, 0)

    def test_everything_is_inside_main_called_last(self):
        lines = [line for line in TEXT.splitlines() if line.strip()]
        self.assertEqual(lines[0], '#!/bin/sh')
        self.assertEqual(lines[-1], 'main "$@"')
        self.assertEqual(TEXT.count('main "$@"'), 1)

    def test_no_secret_shape_and_no_private_name(self):
        for what in (r'BEGIN [A-Z ]*PRIVATE KEY', r'ghp_', r'github_pat_', r'AKIA[0-9A-Z]{8}', r'sk-ant', r'-----BEGIN', r'mirrorstack-fleet', r'mirrorstack-core',
                     r'\bgh api\b', r'GITHUB_TOKEN'):
            for path in (SCRIPT, README):
                if path.exists():
                    self.assertIsNone(re.search(what, path.read_text(encoding='utf-8')), f'{what} in {path.name}')

    def test_only_these_urls(self):
        allowed = re.compile(r'^(https://github\.com/mirrorstack-ai/fleet-disk/releases/download/|https://www\.python\.org/ftp/python/3\.14\.10/'
                             r'python-3\.14\.10-macos11\.pkg$|https://raw\.githubusercontent\.com/mirrorstack-ai/fleet-disk/main/basic/install\.sh|'
                             r'https://claude\.ai/install\.sh|http://www\.apple\.com/DTDs/PropertyList-1\.0\.dtd)')
        urls = re.findall(r'https?://[A-Za-z0-9][^\s\'")|]*', TEXT)  # a URL has a host: the glob patterns of url_ok (`https://*`) are not one
        self.assertGreaterEqual(len(urls), 4)
        for url in urls:
            self.assertTrue(allowed.match(url), url)
        self.assertNotIn('basic-invites', TEXT, 'the shared release is gone: the repo\'s releases are immutable, one release per invite now')
        self.assertIn('fetch "${BASE_PREFIX}inv-$ID/inv-$ID.enc"', TEXT)  # the invite's own release: tag inv-<id>, asset inv-<id>.enc
        self.assertEqual(re.findall(r'https://www\.python\.org\S+', TEXT)[0], 'https://www.python.org/ftp/python/3.14.10/python-3.14.10-macos11.pkg')

    def test_the_pinned_python_pkg(self):
        self.assertIn(f'PY_SHA={PY_SHA_REAL}', TEXT)
        self.assertIn('PY_PKG=python-3.14.10-macos11.pkg', TEXT)
        for choice in ('PythonApplications', 'PythonUnixTools', 'PythonDocumentation', 'PythonProfileChanges', 'PythonInstallPip'):
            self.assertIn(choice, TEXT)

    def test_the_key_only_goes_to_openssl_stdin(self):
        self.assertIn("OPENSSL_ENC='-aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -pass stdin'", TEXT)
        for bad in ('-pass pass:', '-pass env:', ' -k ', '-kfile', 'pass:$'):
            self.assertNotIn(bad, self.CODE)
        self.assertEqual(len(re.findall(r'\bopenssl enc\b', self.CODE)), 1)
        self.assertIn('printf \'%s\\n\' "$KEY" | openssl enc -d $OPENSSL_ENC', self.CODE)
        self.assertNotRegex(self.CODE, r'echo[^\n]*\$KEY')

    def test_curl_is_one_https_only_function(self):
        self.assertEqual(len(re.findall(r'(?m)(?:^\s*|\$\()curl\b', self.CODE)), 1)  # the only invocation, inside fetch()
        self.assertIn('fetch() {', self.CODE)
        self.assertIn("--proto '=https' --tlsv1.2 --max-redirs 0", self.CODE)
        body = re.sub(r'#[^\n]*', '', re.search(r'(?s)\nfetch\(\) \{.*?\n\}\n', TEXT)[0])  # fetch() without its comments (they say "no -L")
        self.assertIsNone(re.search(r'\s-[a-zA-Z]*L\b|--location|--proto-redir', body), 'curl must follow no redirect by itself')
        self.assertIn("-w '%{http_code} %{redirect_url}'", self.CODE)

    def test_no_eval_and_no_shell_from_the_invite(self):
        self.assertIsNone(re.search(r'\beval\b', self.CODE))
        self.assertIsNone(re.search(r'\bsh -c\b|\bbash -c\b', self.CODE))

    def test_readme(self):
        text = README.read_text(encoding='utf-8')
        self.assertIn('curl -fsSL https://raw.githubusercontent.com/mirrorstack-ai/fleet-disk/main/basic/install.sh | sh -s -- <invite>', text)
        for word in ('disable', 'uninstall', 'expires', 'private'):
            self.assertIn(word, text)
        self.assertLessEqual(len(text.split()), 700)


class Functions(BoxCase):
    """Single functions of the script, sourced without main()."""

    def sh(self, snippet: str, **env) -> subprocess.CompletedProcess:
        lib = Path(tempfile.mkdtemp(prefix='fbi-lib-'))
        self.addCleanup(shutil.rmtree, lib, True)
        put(lib / 'lib.sh', TEXT.rsplit('main "$@"', 1)[0])
        box = self.box()
        e = {'PATH': box.path(), 'FAKE_PY': sys.executable, **box.env, **env}
        return subprocess.run(['/bin/sh', '-c', f'. "{lib / "lib.sh"}"; {snippet}'], capture_output=True, text=True, env=e)

    def test_parse_invite(self):
        good = 'a' * 12 + '.' + 'B' * 43 + '.' + 'c' * 64
        self.assertEqual(self.sh(f'parse_invite {good} && echo "$ID $KEY $DIGEST"').stdout.split(), ['a' * 12, 'B' * 43, 'c' * 64])
        for name, bad in (('empty', ''), ('upper id', 'A' * 12 + '.' + 'B' * 43 + '.' + 'c' * 64), ('short id', 'a' * 11 + '.' + 'B' * 44 + '.' + 'c' * 64),
                          ('long key', 'a' * 12 + '.' + 'B' * 44 + '.' + 'c' * 64), ('short digest', 'a' * 12 + '.' + 'B' * 43 + '.' + 'c' * 63),
                          ('upper digest', 'a' * 12 + '.' + 'B' * 43 + '.' + 'C' * 64), ('extra part', good + '.x'),
                          ('key slash', 'a' * 12 + '.' + 'B' * 42 + '/.' + 'c' * 64), ('substitution', 'a' * 12 + '.$(touch x)' + 'B' * 32 + '.' + 'c' * 64),
                          ('semicolon', 'a' * 12 + '.' + 'B' * 42 + ';.' + 'c' * 64), ('newline', good[:20] + '\n' + good[21:]),
                          ('space', good[:20] + ' ' + good[21:]), ('dots only', '.' * 121), ('no dots', 'a' * 121)):
            with self.subTest(name):
                self.assertEqual(self.sh('parse_invite "$1"; echo $?'.replace('"$1"', '"$BAD"'), BAD=bad).stdout.strip(), '1')

    def test_host_names(self):
        # the name is at most 26 characters of the machine's own, '-', and 4 hex of its id (the first run's 31-character cut is gone)
        for local, hostname, os_, base in (
                ("Sheng Kun's MacBook Pro", '', 'mac', 'mac-sheng-kun-s-macbook-pr'), ('MBP', '', 'mac', 'mac-mbp'),
                (None, 'Fallback.local', 'mac', 'mac-fallback-local'), ('---', '', 'mac', 'mac'), ('', '', 'mac', 'mac'),
                ('a' * 50, '', 'mac', 'mac-' + 'a' * 22), ('a' * 21 + '-bbb', '', 'mac', 'mac-' + 'a' * 21), ('9lives', '', 'mac', 'mac-9lives'),
                (None, 'Ubuntu-Box_2', 'linux', 'pc-ubuntu-box-2'), (None, '', 'linux', 'pc')):
            with self.subTest(local=local, hostname=hostname, os=os_):
                env = {'FAKE_HOSTNAME': hostname}
                if local is None:
                    env['FAKE_LOCALHOST'] = ''
                else:
                    env['FAKE_LOCALHOST'] = local
                want = f'{base}-{MAC_TAG if os_ == "mac" else LINUX_TAG}'
                box = self.box(os_)
                out = self.sh(f'OS={os_}; R={box.root}; default_host', **{**box.env, **env}).stdout.strip()
                self.assertEqual(out, want)
                self.assertTrue(self.sh(f'valid_host {want}').returncode == 0, want)
                self.assertLessEqual(len(out), 31)

    def test_two_machines_with_one_name_get_two_host_names(self):
        """Two "MacBook Air"s must not be one identity at the owner (run-name @host, label m-<host>): the id tags them apart."""
        a = self.sh('OS=mac; default_host', FAKE_MACHINE_ID='11111111-0000-0000-0000-000000000001').stdout.strip()
        b = self.sh('OS=mac; default_host', FAKE_MACHINE_ID='11111111-0000-0000-0000-000000000002').stdout.strip()
        again = self.sh('OS=mac; default_host', FAKE_MACHINE_ID='11111111-0000-0000-0000-000000000001').stdout.strip()
        self.assertNotEqual(a, b)
        self.assertEqual((a, a[:-5]), (again, b[:-5]))  # the same machine keeps its name; only the 4-hex tag differs
        self.assertRegex(a, r'^mac-test-mac-[0-9a-f]{4}$')
        for name in (a, b):
            self.assertEqual(self.sh('valid_host "$H"', H=name).returncode, 0)

    def test_the_tag_is_a_hash_never_the_machine_id_and_a_machine_without_an_id_still_gets_one(self):
        out = self.sh('OS=mac; machine_tag; echo; OS=mac; default_host', FAKE_MACHINE_ID=MAC_UUID).stdout
        self.assertNotIn(MAC_UUID, out)
        self.assertNotIn(MAC_UUID[:8], out)
        box = self.box('linux')
        (box.root / 'etc/machine-id').unlink()
        tags = {self.sh(f'OS=linux; R={box.root}; machine_tag', **box.env).stdout for _ in range(6)}
        self.assertTrue(all(re.fullmatch(r'[0-9a-f]{4}', t) for t in tags), tags)
        self.assertGreater(len(tags), 1, 'no id: a random tag, not a constant that every such machine would share')
        self.assertEqual(len(self.sh('OS=mac; machine_tag', FAKE_MACHINE_ID='').stdout), 4)

    def test_url_ok_holds_every_hop_to_github(self):
        for ok in ('https://github.com/mirrorstack-ai/fleet-disk/releases/download/inv-0123456789ab/inv-0123456789ab.enc', 'https://codeload.github.com/x',
                   'https://release-assets.githubusercontent.com/github-production-release-asset/1/a?sp=r&sig=b%2Fc', 'https://objects.githubusercontent.com/x',
                   'https://github.com:443/x', 'https://github.com'):
            self.assertEqual(self.sh('url_ok "$U" gh', U=ok).returncode, 0, ok)
        for ok in ('https://www.python.org/ftp/python/3.14.10/python-3.14.10-macos11.pkg', 'https://python.org/x', 'https://downloads.python.org/x'):
            self.assertEqual(self.sh('url_ok "$U" py', U=ok).returncode, 0, ok)
            self.assertNotEqual(self.sh('url_ok "$U" gh', U=ok).returncode, 0, ok)  # each kind has its own hosts
        for bad in ('', 'http://github.com/x', 'https://evil.example/x', 'https://github.com.evil.example/x', 'https://evilgithub.com/x',
                    'https://user@github.com/x', 'https://github.com@evil.example/x', 'https://github.com:8443/x', 'https://github.com?x=/y',
                    'https://github.com#@evil.example/', 'https://githubusercontent.com/x', 'https://.github.com/x', 'https://GITHUB.COM/x',
                    'https://objects.githubusercontent.com.evil.example/x', 'https:///x', '//github.com/x', 'file:///etc/passwd',
                    'https://github.com\\@evil.example/x', 'ftp://github.com/x'):
            self.assertNotEqual(self.sh('url_ok "$U" gh', U=bad).returncode, 0, bad)
        for bad in ('https://github.com/x', 'https://evilpython.org/x', 'https://python.org.evil.example/x', 'http://www.python.org/x', 'https://www.python.org:8443/x'):
            self.assertNotEqual(self.sh('url_ok "$U" py', U=bad).returncode, 0, bad)

    def test_valid_host(self):
        for ok in ('a', 'mac-1', 'pc', 'a' * 31):
            self.assertEqual(self.sh(f'valid_host {ok}').returncode, 0, ok)
        for bad in ('', '1a', 'A', 'a_b', 'a-', 'a.b', 'a' * 32, '-a', 'a b'):
            self.assertNotEqual(self.sh('valid_host "$H"', H=bad).returncode, 0, bad)


@need_openssl
class Archive(BoxCase):
    """Only the fleet tree's members, only plain files and folders, are unpacked (check_archive), and only after sha256 and key."""

    def check(self, members: dict) -> int:
        d = Path(tempfile.mkdtemp(prefix='fbi-tgz-'))
        self.addCleanup(shutil.rmtree, d, True)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            for name, body in {**members, 'COMMIT': b'a' * 40 + b'\n'}.items():
                info = tarfile.TarInfo(name)
                if isinstance(body, tuple):
                    info.type = {'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE}[body[0]]
                    info.linkname = body[1]
                    tar.addfile(info)
                else:
                    data = body.encode() if isinstance(body, str) else body
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
        (d / 'a.tgz').write_bytes(buf.getvalue())
        lib = d / 'lib.sh'
        put(lib, TEXT.rsplit('main "$@"', 1)[0])
        env = {'PATH': str(self.box().tools)}
        return subprocess.run(['/bin/sh', '-c', f'. "{lib}"; check_archive "{d / "a.tgz"}"'], env=env, capture_output=True).returncode

    def test_good_tree(self):
        self.assertEqual(self.check(tree()), 0)

    def test_bad_members(self):
        for name, extra in (('parent', {'../evil': 'x'}), ('deep parent', {'fleet/../../evil': 'x'}), ('absolute', {'/etc/evil': 'x'}),
                            ('other folder', {'other/file': 'x'}), ('other bin', {'bin/evil.sh': 'x'}), ('dotslash', {'./fleet/x': 'x'}),
                            ('symlink', {'fleet/link': ('symlink', '/etc/passwd')}), ('hardlink', {'fleet/hard': ('hardlink', 'fleet/__init__.py')}),
                            ('bin dir named like a file', {'bin/fleet-basic.py.bak': 'x'}), ('dotdot name', {'..': 'x'})):
            with self.subTest(name):
                self.assertNotEqual(self.check({**tree(), **extra}), 0)

    def test_not_a_tar(self):
        d = Path(tempfile.mkdtemp(prefix='fbi-tgz-'))
        self.addCleanup(shutil.rmtree, d, True)
        put(d / 'a.tgz', b'not a tar', 0o644)
        put(d / 'lib.sh', TEXT.rsplit('main "$@"', 1)[0])
        out = subprocess.run(['/bin/sh', '-c', f'. "{d / "lib.sh"}"; check_archive "{d / "a.tgz"}"'], env={'PATH': str(self.box().tools)}, capture_output=True)
        self.assertNotEqual(out.returncode, 0)


class Early(BoxCase):
    """Everything that must be refused before a single download or sudo."""

    def refused(self, res: Result, code: str) -> None:
        self.assertStopped(res, code)
        self.assertEqual(res.log, '', 'something ran before the refusal:\n' + res.log)

    def test_bad_invites_before_any_command(self):
        b = self.box()
        good = 'a' * 12 + '.' + 'B' * 43 + '.' + 'c' * 64
        for name, bad in (('upper id', 'A' * 12 + good[12:]), ('short', good[:-1]), ('long', good + 'c'), ('substitution', 'a' * 12 + '.$(touch PWNED)' + 'B' * 28 + '.' + 'c' * 64),
                          ('backtick', 'a' * 12 + '.`touch PWNED`' + 'B' * 29 + '.' + 'c' * 64), ('semicolon', good[:30] + ';touch PWNED;' + good[43:]),
                          ('newline', good[:30] + '\ntouch PWNED\n' + good[43:]), ('extra part', good + '.PWNED'), ('slash', good[:30] + '/' + good[31:])):
            with self.subTest(name):
                res = b.run(bad)
                self.refused(res, 'invite-shape')
                self.assertNotIn('PWNED', ''.join(p.name for p in (b.d / 'cwd').iterdir()))
                self.assertFalse((b.d / 'cwd/PWNED').exists())
                self.assertNotIn(bad[12:40] if bad[12:40].strip() else 'zzz', res.out)

    def test_usage(self):
        b = self.box()
        good = 'a' * 12 + '.' + 'B' * 43 + '.' + 'c' * 64
        for name, args in (('no invite', ()), ('option first', ('--evil',)), ('two invites', (good, good)), ('host without a name', (good, '--host')),
                           ('unknown option', (good, '--run'))):
            with self.subTest(name):
                res = b.run(args[0] if args else None, *args[1:])
                self.refused(res, 'usage')

    def test_bad_host_override(self):
        b = self.box()
        good = 'a' * 12 + '.' + 'B' * 43 + '.' + 'c' * 64
        for bad in ('Mac', '1mac', 'a_b', 'x-', 'a' * 32, 'a b', '$(id)'):
            with self.subTest(bad):
                self.refused(b.run(good, '--host', bad), 'host')

    def test_machines_that_are_not_supported(self):
        good = 'a' * 12 + '.' + 'B' * 43 + '.' + 'c' * 64
        cases = (('mac', {'FAKE_UID': '0'}, 'root'), ('mac', {'FAKE_ARCH': 'x86_64'}, 'machine'), ('mac', {'FAKE_MACOS': '13.6'}, 'machine'),
                 ('mac', {'FAKE_MACOS': ''}, 'machine'), ('mac', {'FAKE_OS_S': 'FreeBSD'}, 'machine'), ('linux', {'FAKE_ARCH': 'aarch64'}, 'machine'),
                 ('mac', {'FAKE_FREE_KB': '1000000'}, 'disk'), ('linux', {'FAKE_FREE_KB': '1000000'}, 'disk'))
        for osname, env, code in cases:
            with self.subTest(osname=osname, env=env):
                b = self.box(osname)
                self.refused(b.run(good, **env), code)
        b = self.box('linux')
        (b.root / 'etc/os-release').write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
        self.refused(b.run(good), 'machine')
        (b.root / 'etc/os-release').write_text('ID=debian\nVERSION_ID="12"\n')
        self.refused(b.run(good), 'machine')
        (b.root / 'etc/os-release').write_text('ID=ubuntu\nVERSION_ID="26.04"\n')
        (b.root / 'dev/kvm').unlink()
        self.refused(b.run(good), 'kvm')
        (b.root / 'dev/kvm').write_text('')
        (b.root / 'proc/meminfo').write_text('MemAvailable: 4000000 kB\n')
        self.refused(b.run(good), 'memory')

    def test_no_terminal_no_sudo_no_claude(self):
        good = 'a' * 12 + '.' + 'B' * 43 + '.' + 'c' * 64
        b = self.box()
        self.refused(b.run(good, FB_TTY=str(b.d / 'nope')), 'terminal')
        res = b.run(good, FAKE_SUDO_RC='1')
        self.assertStopped(res, 'sudo')
        self.assertEqual(res.calls('curl'), [])
        b.has_claude = False
        res = b.run(good)
        self.assertStopped(res, 'claude')
        self.assertIn('curl -fsSL https://claude.ai/install.sh | bash', res.out)
        self.assertEqual(res.calls('curl'), [], 'nothing was downloaded before the Claude check')
        self.assertEqual(res.calls('sudo'), [])


@need_openssl
class Fetch(BoxCase):
    """The invite's sha256, its key, its archive and its COMMIT, each refused before anything is unpacked."""

    def unpacked(self, res: Result) -> bool:
        return bool(res.calls('sudo tar'))

    def test_download_refused(self):
        b, inv = self.ready()
        res = b.run(inv.line, FAKE_CURL_FAIL=f'inv-{inv.id}.enc')
        self.assertStopped(res, 'invite-download')
        self.assertIn('expires within one hour', res.out)

    def test_a_redirect_to_githubs_signed_objects_host_is_followed_by_hand_and_curl_follows_nothing(self):
        b, inv = self.ready()
        first = f'https://github.com/mirrorstack-ai/fleet-disk/releases/download/inv-{inv.id}/inv-{inv.id}.enc'
        hop = f'https://release-assets.githubusercontent.com/github-production-release-asset/9/inv-{inv.id}.enc'
        res = b.run(inv.line, FAKE_REDIRECT=f'{first}={hop}')
        self.assertEqual(res.rc, 0, res.out)
        calls = [c for c in res.calls('curl') if f'inv-{inv.id}.enc' in c]
        self.assertEqual([c.rsplit(' ', 1)[1] for c in calls], [first, hop])  # two curls: the release URL, then the hop it named
        for call in calls:
            self.assertIn('--max-redirs 0', call)
            self.assertNotRegex(call, r' -[a-zA-Z]*L\b|--location')

    def test_a_redirect_anywhere_else_is_never_requested(self):
        """Old code (`curl -L --proto-redir =https`) went to ANY https host; every hop must now be github.com or githubusercontent.com."""
        first = lambda inv: f'https://github.com/mirrorstack-ai/fleet-disk/releases/download/inv-{inv.id}/inv-{inv.id}.enc'  # noqa: E731
        for name, target in (('other host', 'https://evil.example/x/inv-ID.enc'), ('plain http', 'http://objects.githubusercontent.com/inv-ID.enc'),
                             ('suffix trick', 'https://github.com.evil.example/inv-ID.enc'), ('userinfo', 'https://github.com@evil.example/inv-ID.enc'),
                             ('port', 'https://objects.githubusercontent.com:8443/inv-ID.enc'), ('empty location', '')):
            with self.subTest(name):
                b, inv = self.ready()
                target = target.replace('ID', inv.id)
                res = b.run(inv.line, FAKE_REDIRECT=f'{first(inv)}={target}')
                self.assertStopped(res, 'invite-download')
                self.assertEqual([c for c in res.calls('curl') if target and c.endswith(target)], [], 'the refused hop was requested')
                self.assertEqual(len(res.calls('curl')), 1)
                self.assertFalse(self.unpacked(res))

    def test_a_redirect_loop_and_a_3xx_that_is_not_a_redirect_stop(self):
        b, inv = self.ready()
        first = f'https://github.com/mirrorstack-ai/fleet-disk/releases/download/inv-{inv.id}/inv-{inv.id}.enc'
        res = b.run(inv.line, FAKE_REDIRECT=f'{first}={first}')
        self.assertStopped(res, 'invite-download')
        self.assertEqual(len(res.calls('curl')), 6)  # the first ask and five hops
        b, inv = self.ready()
        first = f'https://github.com/mirrorstack-ai/fleet-disk/releases/download/inv-{inv.id}/inv-{inv.id}.enc'
        res = b.run(inv.line, FAKE_REDIRECT=f'{first}={first}', FAKE_REDIRECT_CODE='304')
        self.assertStopped(res, 'invite-download')
        self.assertEqual(len(res.calls('curl')), 1)

    def test_other_bytes_than_the_invite_names(self):
        b, inv = self.ready()
        (b.web / f'inv-{inv.id}.enc').write_bytes(inv.enc[:-1] + bytes([inv.enc[-1] ^ 1]))
        res = b.run(inv.line)
        self.assertStopped(res, 'invite-sha')
        self.assertFalse(self.unpacked(res))
        res = b.run(inv.line.rsplit('.', 1)[0] + '.' + '0' * 64)
        self.assertStopped(res, 'invite-sha')

    def test_wrong_key(self):
        b, inv = self.ready()
        key = inv.key[:-1] + ('A' if inv.key[-1] != 'A' else 'B')
        res = b.run(f'{inv.id}.{key}.{inv.digest}')
        self.assertStopped(res, 'invite-decrypt')
        self.assertFalse(self.unpacked(res))
        self.assertNotIn(key, res.out)

    def test_evil_archives_are_not_unpacked(self):
        for name, extra in (('parent', {'../evil': 'x'}), ('absolute', {'/tmp/evil': 'x'}), ('other', {'other/x': 'x'}),
                            ('symlink', {'fleet/l': ('symlink', '/etc')}), ('hardlink', {'fleet/h': ('hardlink', 'fleet/__init__.py')})):
            with self.subTest(name):
                b, inv = self.ready(name=f'evil-{name}', members={**tree(), **extra})
                res = b.run(inv.line)
                self.assertStopped(res, 'archive')
                self.assertFalse(self.unpacked(res))
                self.assertFalse(b.src_parent.exists() and any(b.src_parent.iterdir()))

    def test_commit_shape(self):
        for name, commit in (('upper', 'A' * 40), ('short', 'a' * 39), ('long', 'a' * 41), ('word', 'main')):
            with self.subTest(name):
                b, inv = self.ready(name=f'commit-{name}', commit=commit)
                res = b.run(inv.line)
                self.assertStopped(res, 'commit')
                self.assertEqual(list(b.src_parent.iterdir()), [], 'a rejected tree must not stay behind')

    def test_missing_member(self):
        b, inv = self.ready(name='no-install', fleet__basic__install_mac_sh=None, **{'fleet__basic__install-mac.sh': None})
        res = b.run(inv.line)
        self.assertStopped(res, 'archive')
        self.assertIn('fleet/basic/install-mac.sh', res.out)


@need_openssl
class MacBase(BoxCase):
    """The public Mac base image: refused while it is a placeholder, before any slow step."""

    def test_placeholder_refuses_first(self):
        for name, lock in (('todo', 'todo'), ('missing', 'missing')):
            with self.subTest(name):
                b, inv = self.ready(name=f'lock-{name}', lock=lock)
                (b.pym).unlink()
                res = b.run(inv.line)
                self.assertStopped(res, 'base-raw not published yet')
                self.assertEqual(res.stops()[0], 'STOP base-raw not published yet')
                for slow in ('installer', 'install-mac.sh', 'golden.py', 'caffeinate', 'fleet-basic'):
                    self.assertEqual(res.calls(slow), [], slow)
                self.assertEqual([c for c in res.calls('curl') if 'python' in c or 'raw.gz' in c], [])

    def test_odd_entries(self):
        for name, entry, why in (
                ('outside', {'url': 'https://example.com/a.raw.gz', 'gz_sha256': 'a' * 64, 'raw_sha256': 'b' * 64}, 'outside fleet-disk'),
                ('http', {'url': 'http://github.com/mirrorstack-ai/fleet-disk/releases/download/t/a.gz', 'gz_sha256': 'a' * 64, 'raw_sha256': 'b' * 64}, 'outside fleet-disk'),
                ('dotdot', {'url': BASE_URL.replace('basic-base-1', '../x'), 'gz_sha256': 'a' * 64, 'raw_sha256': 'b' * 64}, 'odd characters'),
                ('shell chars', {'url': BASE_URL + '$(id)', 'gz_sha256': 'a' * 64, 'raw_sha256': 'b' * 64}, 'odd characters'),
                ('bad sha', {'url': BASE_URL, 'gz_sha256': 'A' * 64, 'raw_sha256': 'b' * 64}, 'no sha256 pins'),
                ('half todo', {'url': BASE_URL, 'gz_sha256': 'a' * 64, 'raw_sha256': 'TODO'}, 'not published yet')):
            with self.subTest(name):
                b, inv = self.ready(name=f'odd-{name}', lock=entry)
                res = b.run(inv.line)
                self.assertStopped(res, 'base-raw')
                self.assertIn(why, res.out)
                self.assertEqual(res.calls('installer'), [])
                self.assertEqual(res.calls('install-mac.sh'), [])

    def test_a_placeholder_does_not_block_a_machine_that_has_the_image(self):
        b, inv = self.ready(name='lock-todo', lock='todo')
        b.installed(golden=True)
        b.python_ok()
        res = b.run(inv.line)
        self.assertEqual(res.rc, 0, res.out)
        self.assertEqual(res.calls('golden.py'), [])


@need_openssl
class MacPython(BoxCase):
    """The python.org pkg: pinned sha256, signature, framework only; skipped when a good Python is in place."""

    def run_mac(self, inv, **env):
        b = self.box()
        b.serve(inv)
        (b.pym).unlink()
        return b, b.run(inv.line, **env)

    def test_installs_the_framework_only(self):
        b, inv = self.ready()
        b.pym.unlink()
        res = b.run(inv.line)
        self.assertEqual(res.rc, 0, res.out)
        line = res.calls('installer')[0]
        self.assertRegex(line, r'^installer -pkg \S+python-3\.14\.10-macos11\.pkg -target / -applyChoiceChangesXML \S+py-choices\.xml$')
        xml = (b.state / 'choices.xml').read_text()
        self.assertEqual(sorted(re.findall(r'org\.python\.Python\.(\w+)-3\.14', xml)),
                         ['PythonApplications', 'PythonDocumentation', 'PythonInstallPip', 'PythonProfileChanges', 'PythonUnixTools'])
        self.assertEqual(xml.count('<integer>0</integer>'), 5)
        self.assertLess(res.index('curl'), res.index('installer'))
        self.assertLess(res.index('installer'), res.index('install-mac.sh'))

    def test_the_real_pin_refuses_other_bytes(self):
        b, inv = self.ready()
        b.pym.unlink()
        res = b.run(inv.line, patch_py_sha=False)
        self.assertStopped(res, 'python')
        self.assertIn('not the pinned one', res.out)
        self.assertEqual(res.calls('installer'), [])
        self.assertEqual(res.calls('install-mac.sh'), [])

    def test_signature(self):
        for env, why in (({'FAKE_PKG_RC': '1', 'FAKE_PKG_SIG': 'Status: no signature'}, 'signature is not valid'),
                         ({'FAKE_PKG_SIG': 'Status: signed by Mallory Inc'}, 'not signed by the Python Software Foundation')):
            with self.subTest(why):
                b, inv = self.ready()
                b.pym.unlink()
                res = b.run(inv.line, **env)
                self.assertStopped(res, 'python')
                self.assertIn(why, res.out)
                self.assertEqual(res.calls('installer'), [])

    def test_installer_failure(self):
        b, inv = self.ready()
        b.pym.unlink()
        res = b.run(inv.line, FAKE_INSTALLER_FAIL='1')
        self.assertStopped(res, 'python')
        self.assertEqual(res.calls('install-mac.sh'), [])

    def test_a_good_python_is_left_alone(self):
        b, inv = self.ready()
        res = b.run(inv.line)
        self.assertEqual(res.rc, 0, res.out)
        self.assertEqual(res.calls('installer'), [])
        self.assertEqual([c for c in res.calls('curl') if 'python' in c], [])

    def test_a_writable_or_foreign_python_is_replaced(self):
        b, inv = self.ready()
        b.pym.parent.chmod(0o777)  # a user-writable folder above the Python: the pkg is installed again (it makes root's folders)
        res = b.run(inv.line)
        self.assertEqual(res.rc, 0, res.out)
        self.assertEqual(len(res.calls('installer')), 1)
        b2, inv2 = self.ready()
        res = b2.run(inv2.line, FB_ROOT_UID=str(os.getuid() + 1))  # nothing owned by "root" even after the installer: refused, not trusted
        self.assertStopped(res, 'python')
        self.assertIn('not in place after the installer', res.out)
        self.assertEqual(len(res.calls('installer')), 1)
        self.assertEqual(res.calls('install-mac.sh'), [])


@need_openssl
class Flow(BoxCase):
    """The whole run, as the helper would see it."""
    STEPS = ['[1/8] check this machine', '[2/8] fetch the fleet code', '[3/8] Python', '[4/8] install fleet-basic', '[5/8] build the VM image',
             '[6/8] Claude token', '[7/8] pair with the owner', '[8/8] finish']

    def assertSecretsNeverShown(self, res: Result, inv: Invite) -> None:
        for secret in (inv.key, TOKEN):
            self.assertNotIn(secret, res.out)
            self.assertNotIn(secret, res.log)

    def assertHttpsOnly(self, res: Result) -> None:
        self.assertTrue(res.calls('curl'))
        for call in res.calls('curl'):
            self.assertIn('--proto =https', call)
            self.assertIn('--tlsv1.2', call)
            self.assertIn('--max-redirs 0', call)  # curl follows nothing; install.sh checks each hop itself
            self.assertNotRegex(call, r' -[a-zA-Z]*L\b|--location|--proto-redir')
            self.assertRegex(call, r' https://\S+$')

    def test_mac_end_to_end_under_every_shell(self):
        for shell in SHELLS:
            with self.subTest(shell=shell):
                b, inv = self.ready()
                res = b.run(inv.line, shell=shell)
                self.assertEqual(res.rc, 0, res.out + res.log)
                positions = [res.out.index(step) for step in self.STEPS]
                self.assertEqual(positions, sorted(positions))
                self.assertEqual(res.out.rstrip().splitlines()[-2], f'FLEET-BASIC READY host=mac-test-mac-{MAC_TAG} runner=aaaaaaaaaaaa claude=bbbbbbbbbbbb')
                self.assertEqual(res.stops(), [])
                self.assertSecretsNeverShown(res, inv)
                self.assertHttpsOnly(res)
                self.assertNotIn('SANDBOX-ESCAPE', res.log)
                self.assertIn(f'curl', res.calls('curl')[0])
                first = res.calls('curl')[0]  # the invite, by exact URL, as the last word of the first curl
                self.assertIn(' -o ', first)
                self.assertEqual(first.rsplit(' ', 1)[1], f'https://github.com/mirrorstack-ai/fleet-disk/releases/download/inv-{inv.id}/inv-{inv.id}.enc')
                src = b.src_parent / inv.commit
                self.assertEqual([p.name for p in b.src_parent.iterdir()], [inv.commit])
                self.assertEqual((src / 'COMMIT').read_text(), inv.commit + '\n')
                self.assertEqual(res.calls('install-mac.sh'), [f'install-mac.sh install --host mac-test-mac-{MAC_TAG} --runner-app-id 5208968'])
                self.assertIn(f'sudo sh {src}/fleet/basic/install-mac.sh install', res.log)
                stage = b.stage
                self.assertEqual(res.calls('golden.py'), [f'golden.py bake --out {stage} --run --raw-gz pinned'])
                self.assertRegex(res.calls('caffeinate')[0], r'^caffeinate -i -w \d+$')
                self.assertTrue(res.calls('claude')[0].endswith('bake-started=yes'), 'the bake runs while the token step is on')
                self.assertEqual(res.calls('claude')[0].split()[:2], ['claude', 'setup-token'])
                order = ['install-mac.sh', 'claude setup-token', 'fleet-basic claude-token', 'fleet-basic pair',
                         f'fleet-basic golden {stage}/noble-arm64.raw {MAC_SEALED}', 'fleet-basic doctor', 'fleet-basic mint-test', 'fleet-basic enable']
                idx = [res.index(o) for o in order]
                self.assertEqual(idx, sorted(idx), order)
                self.assertNotIn('FAKE-CLAUDE-OUTPUT', res.out)  # the token word went to the terminal, not into the pipe
                self.assertIn('FAKE-CLAUDE-OUTPUT', b.tty.read_text())
                self.assertFalse(stage.exists(), 'the 20 GB stage is removed')
                self.assertEqual(list((b.d / 'tmp').iterdir()), [], 'the temp folder is removed')
                self.assertEqual((b.state / 'token').read_text().strip(), TOKEN)  # it reached fleet-basic on stdin

    def test_linux_end_to_end(self):
        for shell in SHELLS:
            with self.subTest(shell=shell):
                b, inv = self.ready('linux')
                res = b.run(inv.line, shell=shell)
                self.assertEqual(res.rc, 0, res.out + res.log)
                self.assertEqual(res.out.rstrip().splitlines()[-2], f'FLEET-BASIC READY host=pc-test-pc-{LINUX_TAG} runner=aaaaaaaaaaaa claude=bbbbbbbbbbbb')
                self.assertSecretsNeverShown(res, inv)
                self.assertHttpsOnly(res)
                self.assertEqual(res.calls('installer') + res.calls('caffeinate'), [])
                self.assertEqual([c for c in res.calls('curl') if 'python' in c or 'raw.gz' in c], [])
                self.assertEqual(res.calls('install-linux.sh'), [f'install-linux.sh install --host pc-test-pc-{LINUX_TAG} --runner-app-id 5208968'])
                stage = b.stage
                self.assertEqual(res.calls('golden_linux bake'), [f'golden_linux bake --out {stage}'])
                self.assertIn(f'sudo chown -R msvm:msvm {stage}', res.log)
                self.assertIn(f'sudo -u msvm sh {stage}/bake-host.sh {stage}', res.log)
                self.assertIn(f'sudo install -D -o root -g root -m 0444 {stage}/golden.qcow2 {b.golden}', res.log)
                self.assertEqual(res.calls('golden_linux verify'), [f'golden_linux verify {b.golden} {LINUX_SEALED}'])
                order = [f'sudo -u msvm sh {stage}/bake-host.sh', 'fleet-basic claude-token', 'fleet-basic pair', 'fleet-basic doctor',
                         'fleet-basic mint-test', 'fleet-basic enable']
                idx = [res.index(o) if o.startswith('fleet') else [i for i, l in enumerate(res.log.splitlines()) if l.startswith(o)][0] for o in order]
                self.assertEqual(idx, sorted(idx), order)
                self.assertTrue(b.golden.exists())
                self.assertFalse(stage.exists())
                self.assertEqual([p.name for p in b.src_parent.iterdir()], [inv.commit])

    def test_the_curl_pipe_sh_form(self):
        """Through a pipe the script is stdin: nothing it starts may read it, and it must still finish."""
        b, inv = self.ready()
        res = b.run(inv.line, pipe=True)
        self.assertEqual(res.rc, 0, res.out + res.log)
        self.assertIn(f'FLEET-BASIC READY host=mac-test-mac-{MAC_TAG}', res.out)

    def test_a_script_cut_short_runs_nothing(self):
        b, inv = self.ready()
        cut = TEXT[:TEXT.index('main() {') + 3000]
        for shell in SHELLS:
            with self.subTest(shell=shell):
                proc = subprocess.run([shell, '-s', '--', inv.line], input=cut, capture_output=True, text=True, cwd=b.d / 'cwd',
                                      env={'PATH': b.path(shell), 'FB_LOG': str(b.log)})
                self.assertNotEqual(proc.returncode, 0)
                self.assertEqual(b.log.read_text(), '')
                self.assertNotIn('STOP', proc.stdout)
                self.assertNotIn('[1/8]', proc.stdout)

    def test_host_override(self):
        b, inv = self.ready()
        res = b.run(inv.line, '--host', 'helper-1')
        self.assertEqual(res.rc, 0, res.out)
        self.assertEqual(res.calls('install-mac.sh'), ['install-mac.sh install --host helper-1 --runner-app-id 5208968'])
        self.assertIn('host=helper-1', res.out)

    def test_resume_with_everything_done(self):
        """A finished machine and no `claude`: no bake, no token, no pair, no Python; it still re-checks and enables."""
        b, inv = self.ready()
        b.installed(host='mac-prior')
        b.has_claude = False
        res = b.run(inv.line)
        self.assertEqual(res.rc, 0, res.out + res.log)
        for gone in ('installer', 'golden.py', 'caffeinate', 'claude', 'fleet-basic claude-token', 'fleet-basic golden'):
            self.assertEqual(res.calls(gone), [], gone)
        self.assertEqual([c for c in res.calls('curl') if 'raw.gz' in c or 'python' in c], [])
        self.assertEqual(res.calls('install-mac.sh'), ['install-mac.sh install --host mac-prior --runner-app-id 5208968'], 'the name it chose is kept')
        self.assertEqual(res.calls('fleet-basic pair'), ['fleet-basic pair'], 'pair is idempotent: it answers `already approved` itself')
        self.assertIn('OK pair already approved', res.out)
        self.assertIn('ok the token is already set', res.out)
        self.assertIn('host=mac-prior', res.out)
        order = ['fleet-basic doctor', 'fleet-basic mint-test', 'fleet-basic enable']
        idx = [res.index(o) for o in order]
        self.assertEqual(idx, sorted(idx))

    def test_resume_keeps_a_finished_bake(self):
        b, inv = self.ready()
        b.installed(golden=False)
        b.stage.mkdir(mode=0o700)
        (b.stage / 'noble-arm64.raw').write_text('raw')
        (b.stage / 'baked.sha256').write_text(MAC_SEALED + '\n')
        res = b.run(inv.line)
        self.assertEqual(res.rc, 0, res.out + res.log)
        self.assertEqual(res.calls('golden.py') + res.calls('caffeinate'), [])
        self.assertEqual(res.calls('fleet-basic golden'), [f'fleet-basic golden {b.stage}/noble-arm64.raw {MAC_SEALED}'])
        self.assertFalse(b.stage.exists())

    def test_a_finished_bake_survives_a_stop_in_step_7(self):
        """The owner did not answer the PAIR line in time: the finished 20 GB image stays and the next run installs it. On the first
        run's code baked.sha256 was written only in step 8, the OK-sealed line died with the temp folder, and the re-run baked again."""
        b, inv = self.ready()
        res = b.run(inv.line, FAKE_PAIR_FAIL='1', FAKE_PAIR_WAIT_FOR=str(b.stage / 'baked.sha256'))  # the wait outlasts the bake
        self.assertStopped(res, 'pair')
        self.assertEqual((b.stage / 'baked.sha256').read_text(), MAC_SEALED + '\n')
        self.assertTrue((b.stage / 'noble-arm64.raw').exists())
        self.assertFalse((b.stage / 'baked.sha256.new').exists())
        self.assertEqual(len(res.calls('golden.py')), 1)
        res = b.run(inv.line)  # a new invite in real life; the fake serves the same one
        self.assertEqual(res.rc, 0, res.out + res.log)
        self.assertIn('the image from the earlier run is kept', res.out)
        self.assertEqual(len(res.calls('golden.py')), 1, 'the log holds both runs: still one bake')
        self.assertEqual(res.calls('fleet-basic golden'), [f'fleet-basic golden {b.stage}/noble-arm64.raw {MAC_SEALED}'])
        self.assertFalse(b.stage.exists())

    def test_a_failed_bake_leaves_no_baked_sha256(self):
        b, inv = self.ready()
        res = b.run(inv.line, FAKE_BAKE_FAIL='1')
        self.assertStopped(res, 'bake')
        self.assertFalse((b.stage / 'baked.sha256').exists())

    def test_a_stale_stage_is_rebuilt_from_scratch(self):
        """No baked.sha256 means no finished bake (killed, failed or never started), whatever else is in the stage."""
        b, inv = self.ready()
        b.stage.mkdir(mode=0o700)
        (b.stage / 'noble-arm64.raw').write_text('half')  # a killed bake's partial image
        (b.stage / 'seed.iso').write_text('stale')  # a stale seed.iso makes the real bake refuse
        res = b.run(inv.line)
        self.assertEqual(res.rc, 0, res.out + res.log)
        self.assertEqual(len(res.calls('golden.py')), 1)
        self.assertEqual(res.calls('install-mac.sh'), [f'install-mac.sh install --host mac-test-mac-{MAC_TAG} --runner-app-id 5208968'])
        self.assertEqual((b.stage / 'baked.sha256').exists(), False)  # the finished image went into the VM store, the stage is gone

    def test_each_failure_is_one_stop_line(self):
        for name, env, code, absent in (
                ('install', {'FAKE_INSTALL_FAIL': '1'}, 'install', ('golden.py', 'fleet-basic pair')),
                ('base download', {'FAKE_CURL_FAIL': 'noble-arm64-base.raw.gz'}, 'bake', ('fleet-basic golden', 'fleet-basic enable')),
                ('bake refused', {'FAKE_BAKE_FAIL': '1'}, 'bake', ('fleet-basic golden', 'fleet-basic enable')),
                ('token refused', {'FAKE_TOKEN_REFUSE': '1'}, 'claude', ('fleet-basic pair', 'fleet-basic enable')),
                ('pair no answer', {'FAKE_PAIR_FAIL': '1'}, 'pair', ('fleet-basic golden', 'fleet-basic enable')),
                ('doctor', {'FAKE_DOCTOR_FAIL': '1'}, 'doctor', ('fleet-basic mint-test', 'fleet-basic enable')),
                ('mint-test', {'FAKE_MINT_FAIL': '1'}, 'mint-test', ('fleet-basic enable',))):
            with self.subTest(name):
                b, inv = self.ready()
                res = b.run(inv.line, **env)
                self.assertStopped(res, code)
                for gone in absent:
                    self.assertEqual(res.calls(gone), [], gone)
                self.assertSecretsNeverShown(res, inv)
                self.assertEqual(list((b.d / 'tmp').iterdir()), [], 'the temp folder is removed on STOP too')

    def test_linux_bake_failure(self):
        b, inv = self.ready('linux')
        res = b.run(inv.line, FAKE_BAKE_FAIL='1')
        self.assertStopped(res, 'bake')
        self.assertIn('FLEETBAKE FAILED fake', res.out)
        self.assertFalse(b.golden.exists())
        self.assertEqual(res.calls('fleet-basic enable'), [])

    def test_a_stop_kills_the_background_bake(self):
        b, inv = self.ready()
        pidfile = b.state / 'bake.pid'
        try:
            res = b.run(inv.line, FAKE_BAKE_HANG='1', FAKE_PAIR_FAIL='1')
            self.assertStopped(res, 'pair')
            self.assertTrue(pidfile.exists(), 'the bake had started')
            pid = int(pidfile.read_text())
            for _ in range(60):
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.1)
            else:
                self.fail('the bake process outlived the installer')
        finally:
            if pidfile.exists():
                try:
                    os.kill(int(pidfile.read_text()), 9)
                except (ProcessLookupError, ValueError):
                    pass


if __name__ == '__main__':
    unittest.main()
