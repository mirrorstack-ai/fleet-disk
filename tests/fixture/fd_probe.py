"""PZ03 (G-KH-1): what does `import ctypes` leave open in the system Python, on a real hosted Ubuntu image, and is it the one
descriptor the key holder's rule admits? Run by .github/workflows/fd-probe.yml on four legs (ubuntu-24.04 and ubuntu-24.04-arm as
the controls, ubuntu-26.04 and ubuntu-26.04-arm), stdlib only, as `/usr/bin/python3 -I tests/fixture/fd_probe.py`.

The measuring runs in a child, `/usr/bin/python3 -I -S -c`, so it is the system interpreter and nothing from site-packages or
the environment: every descriptor beyond 0-2 after `import ctypes` is printed (readlink, fstat type, mode and uid, device and
inode, F_GETFL, F_GETFD, the /proc/self/maps lines for the same path and whether their device and inode agree with fstat, and
the filesystem type of the directory), with `dpkg-query -W libffi8`, `sys.version` and `dpkg -S` of the interpreter.

The verdict, against the SHAPE the holder's rule needs (the rule itself is PZ01's `libffi_ok`; the vectors are shared through
fd_golden.json, which test_fd_probe.py runs over `descriptor_reasons`):
  24.04 legs (the controls): zero extra descriptors, else FAIL, so a change on 24.04 is seen too.
  26.04 legs: exactly one extra: a regular file, uid 0, no setuid/setgid/sticky/group-write/other-write bit, O_RDONLY (not O_PATH),
  in /usr/lib/<this leg's architecture>-linux-gnu/ with a basename that fully matches libffi.so(.N){1,3}, and a /proc/self/maps line
  with the same path. F_GETFD and the dev/inode agreement are PRINTED, not judged (Z-S01 and PZ01's seal decide that).
  Zero extras on 26.04 also FAILS: libffi stopped opening it, which is a change to read, never one to pass silently.
  Both: /usr/bin/python3 must be owned by a dpkg package (the probe must measure the system Python, not a toolcache one), and the
  runner's VERSION_ID and machine must be the leg's own (a label that moved is a FAIL, not a measurement of something else).
Exit 0 PASS, 1 FAIL, 2 REFUSED (not a Linux host: nothing was measured). Nothing here is secret or written anywhere."""
from __future__ import annotations

import argparse
import json
import posixpath
import re
import subprocess
import sys
from typing import NamedTuple

PYTHON = '/usr/bin/python3'
O_ACCMODE = 0o3
O_PATH = 0o10000000          # Linux, the same on x86-64 and arm64
MAPS_CAP = 4 * 1024 * 1024   # the holder's cap on /proc/self/maps; over it refuses
LIB_DIRS = {'x86_64': '/usr/lib/x86_64-linux-gnu', 'aarch64': '/usr/lib/aarch64-linux-gnu'}
RELEASES = ('24.04', '26.04')
BASENAME = re.compile(r'libffi\.so(\.[0-9]+){1,3}')

# Runs in the child, before and after nothing else: the imports come first, then `import ctypes`, then measure(). `fds` and `maps`
# are parameters only so that a test can point them at a made-up tree (the descriptor numbers in it are real ones).
INNER = r'''
import fcntl, json, os, stat, sys
CAP = %d
KINDS = ((stat.S_ISREG, 'regular'), (stat.S_ISDIR, 'directory'), (stat.S_ISFIFO, 'fifo'), (stat.S_ISSOCK, 'socket'),
         (stat.S_ISCHR, 'chardev'), (stat.S_ISBLK, 'blockdev'), (stat.S_ISLNK, 'symlink'))

def kind(mode):
    for test, name in KINDS:
        if test(mode):
            return name
    return 'other'

SKIPPED = []   # the descriptors that were listed but could not be read: the verdict allows only the one listdir itself used

def measure(fds='/proc/self/fd', maps='/proc/self/maps'):
    found = []
    del SKIPPED[:]
    for name in os.listdir(fds):
        if not name.isdigit() or int(name) <= 2:
            continue
        n = int(name)
        try:   # the descriptor listdir itself used is gone by now: readlink fails, it is skipped
            target = os.readlink(fds + '/' + name)
            st = os.fstat(n)
            flags = fcntl.fcntl(n, fcntl.F_GETFL)
            fdflags = fcntl.fcntl(n, fcntl.F_GETFD)
        except OSError:
            SKIPPED.append(n)
            continue
        found.append((n, target, st, flags, fdflags))
    try:
        with open(maps, 'rb') as f:
            raw = f.read(CAP + 1)
    except OSError:
        raw = b''
    over = len(raw) > CAP
    lines = [] if over else raw.decode('utf-8', 'replace').splitlines()
    out = []
    for n, target, st, flags, fdflags in sorted(found):
        same = [l for l in lines if l.split(None, 5)[5:6] == [target]]
        agree = None
        if same:
            agree = False
            for l in same:
                dev, ino = l.split(None, 5)[3:5]
                maj, _, mnr = dev.partition(':')
                if (int(maj, 16), int(mnr or '0', 16), int(ino)) == (os.major(st.st_dev), os.minor(st.st_dev), st.st_ino):
                    agree = True
        out.append({'fd': n, 'target': target, 'type': kind(st.st_mode), 'mode': format(stat.S_IMODE(st.st_mode), '04o'),
                    'uid': st.st_uid, 'dev': '%%d:%%d' %% (os.major(st.st_dev), os.minor(st.st_dev)), 'ino': st.st_ino,
                    'flags': flags, 'fdflags': fdflags, 'maps_lines': same, 'maps_has_path': bool(same),
                    'maps_over_cap': over, 'maps_dev_ino_agree': agree})
    return out
''' % MAPS_CAP
# After `import ctypes` the child opens /dev/null itself and must find it in what measure() lists: a positive control that the
# enumeration reads descriptors at all (zero extras on a 24.04 control could otherwise mean "could not read any"). It is dropped from
# `extras`. `realpath` is where sys.executable really points (the toolcache hides behind a /usr/bin/python3 symlink).
PROBE_CODE = INNER + (
    '\nimport ctypes\nsentinel = os.open("/dev/null", os.O_RDONLY)\nfound = measure()\n'
    'seen = [e for e in found if e["fd"] == sentinel and e["target"] == "/dev/null"]\n'
    'print(json.dumps({"executable": sys.executable, "realpath": os.path.realpath(sys.executable), "version": sys.version,\n'
    '                  "sentinel_seen": len(seen) == 1, "skipped": SKIPPED, "extras": [e for e in found if e["fd"] != sentinel]}))\n')


class Verdict(NamedTuple):
    status: str      # PASS | FAIL
    reasons: tuple

    def __str__(self) -> str:
        return 'PASS' if self.status == 'PASS' else 'FAIL(' + '; '.join(self.reasons) + ')'


def descriptor_reasons(d: dict, dirs: tuple[str, ...]) -> list[str]:
    """Why this one extra descriptor is not the libffi one the rule admits (empty: it is). `d` has the fields of a golden row:
    type, uid, mode (octal text), flags, target, maps_has_path and, optionally, maps_over_cap. `dirs` are the directories the
    target may be in (the rule admits both architectures' directories; a leg admits only its own)."""
    why = []
    target = d.get('target')
    if d.get('type') != 'regular':
        why.append(f"type is {d.get('type')}, not a regular file")
    if d.get('uid') != 0:
        why.append(f"uid is {d.get('uid')}, not 0")
    try:
        mode = int(str(d.get('mode')), 8)
    except ValueError:
        mode = None
    if mode is None or mode & 0o7022:
        why.append(f"mode {d.get('mode')} has a setuid, setgid, sticky, group-write or other-write bit (or is unreadable)")
    flags = d.get('flags')
    if not isinstance(flags, int) or flags & O_ACCMODE != 0 or flags & O_PATH:
        why.append(f'flags {flags!r} are not O_RDONLY without O_PATH')
    if not isinstance(target, str) or not target.startswith('/'):
        why.append(f'target {target!r} is not an absolute path')
    elif target.endswith(' (deleted)'):
        why.append(f'target {target!r} is deleted')
    else:
        directory, base = posixpath.dirname(target), posixpath.basename(target)
        if directory not in dirs or target != directory + '/' + base:
            why.append(f'target {target!r} is not directly in ' + ' or '.join(dirs))
        if not BASENAME.fullmatch(base):
            why.append(f'basename {base!r} is not libffi.so(.N){{1,3}}')
    if d.get('maps_over_cap'):
        why.append('/proc/self/maps is over the 4 MiB cap')
    elif not d.get('maps_has_path'):
        why.append('no /proc/self/maps line has the same path')
    return why


def judge(probe, *, expect_release: str, expect_arch: str, release: str | None, arch: str | None, python_owner: str | None,
          realpath_owner: str | None) -> Verdict:
    """The verdict of one leg. `probe` is the child's JSON (None when it printed none), `release` and `arch` what the host says
    it is (VERSION_ID, machine), `python_owner` the `dpkg -S` line of /usr/bin/python3 and `realpath_owner` that of the file the
    child's sys.executable really resolves to (None: no package owns it)."""
    why = []
    if expect_release not in RELEASES:
        why.append(f'leg release {expect_release!r} is not one of {RELEASES}')
    if expect_arch not in LIB_DIRS:
        why.append(f'leg architecture {expect_arch!r} is not one of {tuple(LIB_DIRS)}')
    if release != expect_release or arch != expect_arch:
        why.append(f'leg-mismatch: this leg is {expect_release}/{expect_arch} but the host is {release}/{arch}')
    if not python_owner:
        why.append(f'{PYTHON} is not owned by a dpkg package (a toolcache Python would be measured, not the system one)')
    if not isinstance(probe, dict) or not isinstance(probe.get('extras'), list):
        why.append('the probe printed no readable JSON')
        return Verdict('FAIL', tuple(why))
    if not isinstance(probe.get('realpath'), str) or not realpath_owner:
        why.append(f"the interpreter's real path {probe.get('realpath')!r} is not owned by a dpkg package (a toolcache Python behind a "
                   f'{PYTHON} symlink would be measured, not the system one)')
    if probe.get('sentinel_seen') is not True:
        why.append('the enumeration control failed: a descriptor the child opened itself (/dev/null) was not in its own listing, '
                   'so "zero extras" would mean nothing')
    skipped = probe.get('skipped')
    if not isinstance(skipped, list) or len(skipped) > 1:
        why.append(f'listed descriptors that could not be read: {skipped!r} (only the one listdir itself used may vanish): the count of '
                   'extras is not trustworthy')
    extras = probe['extras']
    if expect_release == '24.04' and extras:
        why.append(f'control leg: {len(extras)} descriptor(s) beyond 0-2 after `import ctypes` on 24.04 (expected none): '
                   + ', '.join(str(e.get('target')) for e in extras))
    elif expect_release == '26.04':
        if not extras:
            why.append('zero descriptors beyond 0-2 on 26.04: libffi no longer leaves one open; a change to read '
                       '(G-KH-1, PZ01 rule), never to pass silently')
        elif len(extras) != 1:
            why.append(f'{len(extras)} descriptors beyond 0-2 on 26.04 (expected exactly one): '
                       + ', '.join(str(e.get('target')) for e in extras))
        else:
            dirs = (LIB_DIRS[expect_arch],) if expect_arch in LIB_DIRS else tuple(LIB_DIRS.values())
            why += [f"fd {extras[0].get('fd')}: {r}" for r in descriptor_reasons(extras[0], dirs)]
    return Verdict('FAIL' if why else 'PASS', tuple(why))


def real_run(argv: list[str], timeout: int = 60) -> tuple[int | None, str, str]:
    """(exit code, stdout, stderr); the code is None on a timeout and 127 when the program is missing."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return None, '', 'timed out'
    except OSError as e:
        return 127, '', str(e)
    return p.returncode, p.stdout, p.stderr


def read_text(path: str) -> str | None:
    try:
        with open(path, encoding='utf-8') as f:
            return f.read()
    except OSError:
        return None


def os_version_id(text: str | None) -> str | None:
    m = re.search(r'(?m)^VERSION_ID="?([^"\n]*)"?\s*$', text or '')
    return m.group(1) if m else None


def probe(expect_release: str, expect_arch: str, *, run=real_run, read=read_text, machine=None, out=print) -> int:
    if machine is None:
        import platform
        machine = platform.machine()
    release = os_version_id(read('/etc/os-release'))
    if release is None or read('/proc/self/maps') is None:
        out('::error::nothing was probed: this is not a Linux host with /etc/os-release and /proc')
        out('REFUSED')
        return 2
    rc, stdout, stderr = run([PYTHON, '-I', '-S', '-c', PROBE_CODE])
    try:
        data = json.loads(stdout.strip().splitlines()[-1]) if rc == 0 and stdout.strip() else None
    except ValueError:
        data = None
    if not isinstance(data, dict) or not isinstance(data.get('extras'), list) or not all(isinstance(e, dict) for e in data['extras']):
        data = None
    out(f'host: VERSION_ID={release} machine={machine} (this leg: {expect_release}/{expect_arch})')
    if data is None:
        out(f'child exit {rc}; stderr: {stderr.strip()[:2000]}')
    else:
        out(f"interpreter: sys.executable={data.get('executable')} realpath={data.get('realpath')}")
        out(f"enumeration control (/dev/null opened by the child, found in its listing): {data.get('sentinel_seen')}; "
            f"listed but unreadable descriptors: {data.get('skipped')}")
        out(f"sys.version: {' '.join(str(data.get('version')).split())}")
        for e in data.get('extras', []):
            directory = posixpath.dirname(e['target']) if isinstance(e.get('target'), str) and e['target'].startswith('/') else None
            if directory:
                _, fs, _ = run(['stat', '-f', '-c', '%T', '--', directory])
                e['fstype'] = fs.strip() or None
    qrc, qout, _ = run(['dpkg-query', '-W', 'libffi8'])
    out('dpkg-query -W libffi8: ' + (' '.join(qout.split()) if qrc == 0 else f'not answered (exit {qrc})'))
    orc, oout, _ = run(['dpkg', '-S', PYTHON])
    owner = oout.strip().splitlines()[0] if orc == 0 and oout.strip() else None
    out(f'dpkg -S {PYTHON}: ' + (owner or f'no owner (exit {orc})'))
    real = data.get('realpath') if data is not None else None
    real_owner = None
    if isinstance(real, str) and real.startswith('/'):
        rrc, rout, _ = run(['dpkg', '-S', real])
        real_owner = rout.strip().splitlines()[0] if rrc == 0 and rout.strip() else None
        out(f'dpkg -S {real}: ' + (real_owner or f'no owner (exit {rrc})'))
    out(f"extra descriptors beyond 0-2 after `import ctypes`: {0 if data is None else len(data.get('extras', []))}")
    if data is not None:
        for e in data.get('extras', []):
            out('  ' + json.dumps(e, sort_keys=True))
    v = judge(data, expect_release=expect_release, expect_arch=expect_arch, release=release, arch=machine, python_owner=owner,
              realpath_owner=real_owner)
    for r in v.reasons:
        out(f'::error::{r}')
    out(f'fd-probe {expect_release}/{expect_arch}: {v}')
    return 0 if v.status == 'PASS' else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('--expect-release', required=True, choices=RELEASES, help='the Ubuntu VERSION_ID this leg must be on')
    p.add_argument('--expect-arch', required=True, choices=tuple(LIB_DIRS), help='the machine this leg must be on')
    a = p.parse_args(argv)
    return probe(a.expect_release, a.expect_arch)


if __name__ == '__main__':
    sys.exit(main())
