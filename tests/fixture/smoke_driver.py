#!/usr/bin/env python3
"""Runs the fixture's cases against the PR's bootstrap on this machine, stdlib only.
  smoke_driver.py probe                                    the tools this runner has, to the step summary
  smoke_driver.py control --dir D --phase before|after     the OS's own curl must refuse the local certificate before the
                                                           trust step and accept it after (so the step is proven)
  smoke_driver.py fixture --dir D --os ps1|sh [--must-run] every case of that OS: exit, last two lines, info lines,
                                                           requests made, no temp folder left; --must-run: fail when this
                                                           machine would refuse before the cases (a vacuous pass)
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


def machine() -> str | None:
    """The refusal this machine earns before any case-specific step, mirroring the bootstraps' own early checks."""
    if WIN:
        return None if os.path.exists(WIN_KEYGEN) else 'ssh-keygen'
    if platform.system() != 'Linux':
        return None
    rel = dict(x.strip().replace('"', '').split('=', 1) for x in open('/etc/os-release') if '=' in x)
    if rel.get('ID') != 'ubuntu' or rel.get('VERSION_ID') != '24.04':
        return 'os'
    return None if platform.machine() in ('x86_64', 'amd64') else 'arch'


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


def judge(c: dict, ex: dict, out: str, rc: int, sha: str, fp: str, log: list, http: list, left: list, linux: bool) -> list[str]:
    """Every way the run differs from what it must do; empty when it is right."""
    bad = []
    lines = [x for x in out.replace('\r', '').split('\n') if x.strip()]
    if ex['code']:
        tail = lines[-2:]
        if rc != 1:
            bad.append(f'exit {rc}, want 1')
        if len(tail) < 2 or tail[0] != f'REFUSED {ex["code"]}' or not re.fullmatch(r'\S.*\.', tail[1]):  # `/dev/kvm is missing ...` starts with a slash
            bad.append(f'last two lines {tail}, want REFUSED {ex["code"]} and a sentence')
    elif rc != 0:
        bad.append(f'exit {rc}, want 0')
    want = [f'bootstrap sha256 {sha}', f'key {fp}', c['serial_line']][:ex['info']]
    seen = [x for x in lines if INFO.match(x)]
    if seen != want:
        bad.append(f'info lines {seen}, want {want}')
    if ex['show']:
        at = lines.index(f'Your code: {CODE}') if f'Your code: {CODE}' in lines else -1
        if at < 0:
            bad.append('no `Your code:` line')
        if linux and not any(x.startswith('warning: Firecracker supports host kernels') and i < at for i, x in enumerate(lines)):
            bad.append('no kernel warning before the code')
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
    a = p.parse_args(argv)
    return {'probe': cmd_probe, 'control': cmd_control, 'fixture': cmd_fixture}[a.verb](a)


if __name__ == '__main__':
    sys.exit(main())
