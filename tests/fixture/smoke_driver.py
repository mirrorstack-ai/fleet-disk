#!/usr/bin/env python3
"""Runs the fixture's cases against the PR's bootstrap on this machine, stdlib only.
  smoke_driver.py probe                                    the tools this runner has, to the step summary
  smoke_driver.py control --dir D --phase before|after     the OS's own curl must refuse the local certificate before the
                                                           trust step and accept it after (so the step is proven)
  smoke_driver.py fixture --dir D --os ps1|sh [--must-run] every case of that OS: exit, last two lines, info lines,
                                                           requests made, no temp folder left; --must-run: fail when this
                                                           machine would refuse before the cases (a vacuous pass)
  smoke_driver.py real --serial N [--os win|mac|ubuntu]    the REAL one-liner of the published release install-N, taken from its
                                                           notes, on this machine and a throwaway home (PY13, smoke-real.yml)
The expected outcome comes from cases.json, adjusted only for what this machine is (see expect)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import serve  # noqa: E402

WIN = os.name == 'nt'
SYSROOT = os.environ.get('SystemRoot', r'C:\Windows')
POWERSHELL = os.path.join(SYSROOT, r'System32\WindowsPowerShell\v1.0\powershell.exe')
WIN_KEYGEN = os.path.join(SYSROOT, r'System32\OpenSSH\ssh-keygen.exe')
CODE = 'ABCDE 23456 FGHJK MNPQR STVWX YZ012 34567 89ABC'
LEFT = re.compile(r'(mirrorstack-fleet-|fleet-boot\.)')  # what a bootstrap's temp folder is called
INFO = re.compile(r'(bootstrap sha256|key|serial) ')
FLAGS = {'ps1': {'serial': '-Serial', 'min': '-MinSerial', 'ser': '-Ser'},  # `ser`: an abbreviation the line must refuse
         'sh': {'serial': '--serial', 'min': '--min-serial', 'ser': '--ser'}}
LOGICAL = [(serve.REL, lambda m: m[2]), (serve.PY, lambda m: 'python.zip')]


# The Ubuntu releases the loaders admit (D310, exact VERSION_ID). Twin: backends.UBUNTU_OK and bootstrap.sh check_machine in
# mirrorstack-fleet (PV11), each pinned by its own test; the driver must admit at least what the newest release loader admits.
UBUNTU_OK = ('24.04', '26.04')


def machine(osrel: str = '/etc/os-release', arch: str | None = None) -> str | None:
    """The refusal this machine earns before any case-specific step, mirroring the bootstraps' own early checks.
    `osrel` and `arch` are the test seam; the hosted call sites pass nothing."""
    if WIN:
        return None if os.path.exists(WIN_KEYGEN) else 'ssh-keygen'
    if platform.system() != 'Linux':
        return None
    try:
        with open(osrel) as f:
            rel = dict(x.strip().replace('"', '').split('=', 1) for x in f if '=' in x)
    except (OSError, ValueError):  # unreadable, like a missing VERSION_ID: not an admitted Ubuntu
        return 'os'
    if rel.get('ID') != 'ubuntu' or rel.get('VERSION_ID') not in UBUNTU_OK:
        return 'os'
    return None if (platform.machine() if arch is None else arch) in ('x86_64', 'amd64') else 'arch'


def expect(c: dict, mach: str | None, kvm: bool) -> dict:
    """What this case must do here: a machine refusal beats everything but a bad command line; a Linux box without a usable
    /dev/kvm ends the good run in `kvm` (after the code line, which still prints)."""
    code, info, reqs = c['code'], c['info'], c['reqs']
    if mach and code != 'args':
        code, info, reqs = mach, 0, []
    show = code is None
    if show and c['os'] == 'sh' and platform.system() == 'Linux' and not kvm:
        code = 'kvm'
    return {'code': code, 'info': info, 'reqs': reqs, 'show': show}


def logical(path: str) -> str | None:
    for rx, name in LOGICAL:
        if m := rx.fullmatch(path):
            return name(m)
    return None


def outcome_problems(lines: list[str], rc: int, code: str | None) -> list[str]:
    """The exit and the closing lines a run must have: a refusal is exit 1 and, last, `REFUSED <code>` and a sentence; else exit 0."""
    bad = []
    if code:
        tail = lines[-2:]
        if rc != 1:
            bad.append(f'exit {rc}, want 1')
        if len(tail) < 2 or tail[0] != f'REFUSED {code}' or not re.fullmatch(r'\S.*\.', tail[1]):  # `/dev/kvm is missing ...` starts with a slash
            bad.append(f'last two lines {tail}, want REFUSED {code} and a sentence')
    elif rc != 0:
        bad.append(f'exit {rc}, want 0')
    return bad


def code_problems(lines: list[str], want: str, linux: bool) -> list[str]:
    bad = []
    at = lines.index(want) if want in lines else -1
    if at < 0:
        bad.append('no `Your code:` line')
    if linux and not any(x.startswith('warning: Firecracker supports host kernels') and i < at for i, x in enumerate(lines)):
        bad.append('no kernel warning before the code')
    return bad


def judge(c: dict, ex: dict, out: str, rc: int, sha: str, fp: str, log: list, http: list, left: list, linux: bool) -> list[str]:
    """Every way the run differs from what it must do; empty when it is right."""
    lines = [x for x in out.replace('\r', '').split('\n') if x.strip()]
    bad = outcome_problems(lines, rc, ex['code'])
    want = [f'bootstrap sha256 {sha}', f'key {fp}', c['serial_line']][:ex['info']]
    seen = [x for x in lines if INFO.match(x)]
    if seen != want:
        bad.append(f'info lines {seen}, want {want}')
    if ex['show']:
        bad += code_problems(lines, f'Your code: {CODE}', linux)
    names = [n for e in log if (n := logical(e['path']))]
    if names != ex['reqs']:
        bad.append(f'requests {names}, want {ex["reqs"]}')
    if any(not e['ua'].startswith('curl/') for e in log):
        bad.append('a request did not come from curl')
    if any(e['tls'] not in ('TLSv1.2', 'TLSv1.3') for e in log):
        bad.append('a request used TLS below 1.2')
    if [e['path'] for e in http if e['path'] != '/ca.crl']:
        bad.append('a plain-http request (the redirect was followed)')
    if left:
        bad.append(f'temp folder left: {left}')
    return bad


def run_case(c: dict, base: str, fx: serve.Fixture, fp: str, mach: str | None, kvm: bool) -> tuple[list[str], str]:
    run = os.path.join(base, c['id'], 'run', f'bootstrap.{c["os"]}')
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        env = dict(os.environ, TEMP=tmp, TMP=tmp, TMPDIR=tmp)
        flags = FLAGS[c['os']]
        given = [x for kind, v in c.get('argv') or [('serial', c['args'][0]), ('min', c['args'][1])] for x in (flags[kind], v)]
        argv = [POWERSHELL, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', run, *given] if c['os'] == 'ps1' else ['sh', run, *given]
        fx.set_case(c['id'])
        try:
            done = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=1500)
            out, rc = done.stdout.decode('utf-8', 'replace'), done.returncode
        except subprocess.TimeoutExpired:
            out, rc = '', -1
        left = [n for n in os.listdir(tmp) if LEFT.match(n)]
    with open(run, 'rb') as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    ex = expect(c, mach, kvm)
    return judge(c, ex, out, rc, sha, fp, list(fx.log), list(fx.http_log), left, c['os'] == 'sh' and platform.system() == 'Linux'), out


def load(d: str) -> dict:
    with open(os.path.join(d, 'cases.json')) as f:
        return json.load(f)


def curl() -> str:
    return os.path.join(SYSROOT, r'System32\curl.exe') if WIN else (shutil.which('curl') or 'curl')


def cmd_probe(_a) -> int:
    got = subprocess.run([curl(), '--version'], capture_output=True, text=True).stdout.splitlines()[:1]
    rows = [('platform', f'{platform.platform()} {platform.machine()}'), ('curl', got[0] if got else 'missing'),
            ('ssh-keygen', os.path.exists(WIN_KEYGEN if WIN else '/usr/bin/ssh-keygen')), ('kvm usable', os.access('/dev/kvm', os.R_OK | os.W_OK)),
            ('machine refusal', machine())]
    text = '\n'.join(f'| {k} | {v} |' for k, v in rows)
    print(text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
            f.write(f'### runner facts\n| fact | value |\n|---|---|\n{text}\n')
    return 0


def cmd_control(a) -> int:
    meta = load(a.dir)
    fx = serve.Fixture(a.dir, meta['host'], meta['port'], meta['crl_port'])
    try:
        ok = subprocess.run([curl(), '-fsS', '--proto', '=https', '--tlsv1.2', '--max-time', '20', '-o', os.devnull,
                             f'https://{meta["host"]}:{fx.port}/ping']).returncode == 0
    finally:
        fx.close()
    crl = any(e['path'] == '/ca.crl' for e in fx.http_log)  # a diagnosis only: curl builds differ in whether they ask
    print(f'control {a.phase}: the OS curl {"accepts" if ok else "refuses"} the local certificate (CRL requested: {crl})')
    return 0 if ok == (a.phase == 'after') else 1


def cmd_fixture(a) -> int:
    meta = load(a.dir)
    cases = [c for c in meta['cases'] if c['os'] == a.os]
    mach, kvm = machine(), os.access('/dev/kvm', os.R_OK | os.W_OK)
    if a.must_run and mach:  # every refusal is then the machine's, not a case's: nothing would have been proven
        print(f'FAIL this runner must reach the cases but would refuse `{mach}` before any request')
        return 1
    fx = serve.Fixture(a.dir, meta['host'], meta['port'], meta['crl_port'])
    failed = 0
    try:
        for c in cases:
            bad, out = run_case(c, a.dir, fx, meta['fingerprint'], mach, kvm)
            print(f'{"FAIL" if bad else "ok  "} {c["id"]}' + ''.join(f'\n     {b}' for b in bad))
            if bad:
                failed += 1
                print('     output tail: ' + ' | '.join(out.replace('\r', '').strip().split('\n')[-6:]))
    finally:
        fx.close()
    print(f'{len(cases) - failed}/{len(cases)} cases as expected on {platform.platform()} (machine refusal: {mach})')
    return 1 if failed else 0

# --- real mode (PY13, G-I06-1): the published release's own one-liner, judged against values that live on main ----------------
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MAIN_PINS = os.path.join(ROOT, '.github', 'smoke-real-pins.json')  # {"<serial>": {"ps1": <sha256>, "sh": <sha256>}}, a reviewed change per serial
MAIN_KEY_FILE = os.path.join(ROOT, '.github', 'workflows', 'install.yml')  # its constant KEY_SHA256 is the owner key this repo trusts
REAL_REPO = 'mirrorstack-ai/fleet-disk'
OS_BOOT = {'win': 'ps1', 'mac': 'sh', 'ubuntu': 'sh'}  # the bootstrap each OS's line runs; twin: fleet-install-publish.OS_BOOT
KEY_CONST = re.compile(r'(?m)^  KEY_SHA256: (SHA256:[A-Za-z0-9+/]{43})[ \t]*$')
HEX64 = re.compile(r'[0-9a-f]{64}')
SERIAL = re.compile(r'0|[1-9][0-9]{0,9}', re.ASCII)
FIXED_PATHS = ('/var/lib/mirrorstack-fleet', '/Library/LaunchDaemons/ai.mirrorstack.fleet.carrier.plist',
               r'C:\ProgramData\MirrorStack Fleet')  # where an install would write; a check must never create one


class Refused(Exception):
    """A stop before or after the run, printed like a loader's own: `REFUSED <code>` and one sentence, exit 1."""

    def __init__(self, code: str, why: str):
        super().__init__(f'{code}: {why}')
        self.code, self.why = code, why


def serial_arg(v: str) -> str:
    if not SERIAL.fullmatch(v):
        raise argparse.ArgumentTypeError('canonical decimal digits only')
    return v


def host_os() -> str:
    return 'win' if WIN else 'mac' if platform.system() == 'Darwin' else 'ubuntu'


def main_key(path: str = MAIN_KEY_FILE) -> str:
    """The fingerprint of the owner key as main has it: the constant KEY_SHA256 of install.yml, read from the checkout of main."""
    try:
        with open(path, encoding='utf-8') as f:
            found = KEY_CONST.findall(f.read())
    except OSError:
        found = []
    if len(found) != 1:
        raise Refused('no-main-key', 'main has no single KEY_SHA256 fingerprint to hold the release against. Nothing was run.')
    return found[0]


def main_digest(serial: int, kind: str, path: str = MAIN_PINS) -> str:
    """The sha256 main pins for this serial's bootstrap, from a file reviewed on main. No entry is a stop, never a fallback to the release."""
    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError('a key twice')
        return dict(items)
    try:
        with open(path, encoding='utf-8') as f:
            doc = json.load(f, object_pairs_hook=pairs)
        got = doc[str(serial)][kind]
    except (OSError, ValueError, KeyError, TypeError):
        got = None
    if not isinstance(got, str) or not HEX64.fullmatch(got):
        raise Refused('no-main-pin', f'main pins no {kind} bootstrap digest for serial {serial}, and the digest is never read back from '
                                     'the release it checks. Add it to .github/smoke-real-pins.json by a reviewed change. Nothing was run.')
    return got


def parse_notes(body: str, os_name: str) -> tuple[str, str, str]:
    """(key fingerprint, bootstrap sha256, check line) the release notes carry for os_name; the shape release_notes writes
    (bin/fleet-install-publish.py): a `key SHA256:...` line, then `<os> (bootstrap sha256 <hex>):`, a fence, the line, a fence."""
    lines = body.replace('\r', '').split('\n')
    keys = [x for x in lines if re.fullmatch(r'key SHA256:\S+', x)]
    heads = [(i, m[1]) for i, x in enumerate(lines) if (m := re.fullmatch(rf'{os_name} \(bootstrap sha256 ([0-9a-f]{{64}})\):', x))]
    if not heads:
        raise Refused('no-line', f'the release notes have no check line for {os_name}. Nothing was run.')
    if len(keys) != 1 or len(heads) != 1 or lines[heads[0][0] + 1:heads[0][0] + 2] != ['```'] or lines[heads[0][0] + 3:heads[0][0] + 4] != ['```']:
        raise Refused('notes', 'the release notes are not the shape the publisher writes. Nothing was run.')
    return keys[0][4:], heads[0][1], lines[heads[0][0] + 2]


def check_shape(line: str, repo: str, serial: int, kind: str, sha: str, min_serial: int | None) -> int:
    """The line must be the one for this release: one line, this repository's asset URL for this serial, the digest main pins, and
    this serial with a --min-serial (the one asked for, if any). Returns the line's min serial."""
    url = f'https://github.com/{repo}/releases/download/install-{serial}/bootstrap.{kind}'
    flags = (r'-Serial {s} -MinSerial ([0-9]+)(?![0-9])' if kind == 'ps1' else r'--serial {s} --min-serial ([0-9]+)(?![0-9])').format(s=serial)
    m = re.search(flags, line)
    if '\n' in line or not line.strip() or f"'{url}'" not in line or sha not in line or not m or (min_serial is not None and int(m[1]) != min_serial):
        raise Refused('line', f'the check line is not the one for install-{serial} ({url}) with the pinned digest. Nothing was run.')
    return int(m[1])


def gh_run(gh: str, *args: str) -> bytes:
    """`gh release view` and `gh release download` over a public release: the only two calls this verb makes, both reads."""
    assert args[:2] in (('release', 'view'), ('release', 'download')), args
    try:
        done = subprocess.run([gh, *args], env=dict(os.environ, GH_PROMPT_DISABLED='1', GH_NO_UPDATE_NOTIFIER='1'),
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused('fetch', 'the release could not be read. Nothing was run.') from None
    if done.returncode != 0:
        raise Refused('fetch', 'the release could not be read. Nothing was run.')
    return done.stdout


def real_plan(a, os_name: str) -> tuple[str, str, str, str, int]:
    """Every check that needs no run, against main's values; (line, kind, sha, key, serial). Raises Refused."""
    kind, serial = OS_BOOT[os_name], int(a.serial)
    sha = main_digest(serial, kind, a.pins)
    key = main_key(a.install_yml)
    tag = f'install-{serial}'
    body = gh_run(a.gh, 'release', 'view', tag, '--repo', a.repo, '--json', 'body', '--jq', '.body').decode('utf-8', 'replace')
    n_key, n_sha, line = parse_notes(body, os_name)
    if n_key != key:
        raise Refused('key-mismatch', 'the release names a key other than the owner key main trusts. Nothing was run.')
    with tempfile.TemporaryDirectory() as t:
        asset = os.path.join(t, f'bootstrap.{kind}')
        gh_run(a.gh, 'release', 'download', tag, '--repo', a.repo, '--pattern', f'bootstrap.{kind}', '--output', asset)
        with open(asset, 'rb') as f:
            got = hashlib.sha256(f.read()).hexdigest()
    if n_sha != sha or got != sha:  # the notes and the asset may agree with each other: only main's pin counts
        raise Refused('digest-mismatch', f'the release\'s bootstrap is not the one main pins for serial {serial}. Nothing was run.')
    check_shape(line, a.repo, serial, kind, sha, a.min_serial)
    return line, kind, sha, key, serial


def watch_roots() -> list[str]:
    """Where a stray write by the check would land outside the throwaway home: the real home and the real temp folder."""
    return [os.path.expanduser('~'), tempfile.gettempdir()]


def snapshot(roots: list[str]) -> set[str]:
    seen = {p for p in FIXED_PATHS if os.path.lexists(p)}
    for r in roots:
        try:
            seen.update(os.path.join(r, n) for n in os.listdir(r))
        except OSError:
            pass
    return seen


def judge_real(kind: str, out: str, rc: int, sha: str, fp: str, serial: int, mach: str | None, kvm: bool, left: list, outside: list) -> list[str]:
    """Every way the real run differs from what a check must do; the same expectations as a fixture case (see expect)."""
    linux = kind == 'sh' and platform.system() == 'Linux'
    ex = expect({'code': None, 'info': 3, 'reqs': [], 'os': kind}, mach, kvm)
    lines = [x for x in out.replace('\r', '').split('\n') if x.strip()]
    bad = outcome_problems(lines, rc, ex['code'])
    seen = [x for x in lines if INFO.match(x)]
    if ex['info']:  # main's digest and key, then this serial's line (its expiry is the release's own)
        want = [f'bootstrap sha256 {sha}', f'key {fp}']
        if seen[:2] != want or len(seen) != 3 or not re.fullmatch(rf'serial {serial} valid_until \S+', seen[2]):
            bad.append(f'info lines {seen}, want {want} then a `serial {serial} valid_until` line')
    elif seen:
        bad.append(f'info lines {seen}, want none')
    if ex['show']:
        bad += code_problems(lines, next((x for x in lines if re.fullmatch(r'Your code: [A-Z0-9 ]+', x)), 'Your code: '), linux)
    if left:
        bad.append(f'temp folder left: {left}')
    if outside:
        bad.append(f'wrote outside the throwaway home: {sorted(outside)}')
    return bad


def run_real(line: str, kind: str, os_name: str, sha: str, fp: str, serial: int, mach: str | None, kvm: bool) -> tuple[list[str], str]:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as base:
        home, tmp = os.path.join(base, 'home'), os.path.join(base, 'tmp')
        data = [os.path.join(home, n) for n in ('AppData', 'AppData/Local', '.cache', '.config')]
        for d in (home, tmp, *data):
            os.makedirs(d, exist_ok=True)
        env = {k: v for k, v in os.environ.items() if k not in ('GH_TOKEN', 'GITHUB_TOKEN')}  # the release's code never sees the runner's token
        env.update(HOME=home, USERPROFILE=home, APPDATA=data[0], LOCALAPPDATA=data[1], XDG_CACHE_HOME=data[2], XDG_CONFIG_HOME=data[3],
                   TEMP=tmp, TMP=tmp, TMPDIR=tmp)
        roots = watch_roots()
        before, home_before = snapshot(roots), set(os.listdir(home))  # the home as made: the folders a runner's tools expect
        argv = [POWERSHELL, '-NoProfile', '-Command', line] if os_name == 'win' else ['sh', '-c', line]
        try:
            done = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=1500)
            out, rc = done.stdout.decode('utf-8', 'replace'), done.returncode
        except subprocess.TimeoutExpired:
            out, rc = '', -1
        outside = sorted(snapshot(roots) - before)
        left = os.listdir(tmp)
        print(f'made in the throwaway home: {sorted(set(os.listdir(home)) - home_before)}')
    return judge_real(kind, out, rc, sha, fp, serial, mach, kvm, left, outside), out


def cmd_real(a) -> int:
    os_name = a.os or host_os()
    mach, kvm = machine(), os.access('/dev/kvm', os.R_OK | os.W_OK)
    if a.must_run and mach:
        print(f'FAIL this runner must reach the check but would refuse `{mach}` before any request')
        return 1
    try:
        line, kind, sha, key, serial = real_plan(a, os_name)
    except Refused as e:
        print(f'REFUSED {e.code}\n{e.why}')
        return 1
    bad, out = run_real(line, kind, os_name, sha, key, serial, mach, kvm)
    print(f'{"FAIL" if bad else "ok  "} real install-{serial} on {os_name}' + ''.join(f'\n     {b}' for b in bad))
    if bad:
        print('     output tail: ' + ' | '.join(out.replace('\r', '').strip().split('\n')[-6:]))
    return 1 if bad else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    s = p.add_subparsers(dest='verb', required=True)
    s.add_parser('probe')
    for name in ('control', 'fixture'):
        q = s.add_parser(name)
        q.add_argument('--dir', required=True)
        if name == 'control':
            q.add_argument('--phase', choices=('before', 'after'), required=True)
        else:
            q.add_argument('--os', choices=('ps1', 'sh'), required=True)
            q.add_argument('--must-run', action='store_true')
    q = s.add_parser('real')
    q.add_argument('--serial', required=True, type=serial_arg)
    q.add_argument('--min-serial', type=int, default=None)
    q.add_argument('--os', choices=tuple(OS_BOOT))
    q.add_argument('--repo', default=REAL_REPO)
    q.add_argument('--must-run', action='store_true')
    q.add_argument('--gh', default=shutil.which('gh') or 'gh')
    q.add_argument('--pins', default=MAIN_PINS)  # the three below are the test seam; the workflow passes none
    q.add_argument('--install-yml', default=MAIN_KEY_FILE)
    a = p.parse_args(argv)
    return {'probe': cmd_probe, 'control': cmd_control, 'fixture': cmd_fixture, 'real': cmd_real}[a.verb](a)


if __name__ == '__main__':
    sys.exit(main())
