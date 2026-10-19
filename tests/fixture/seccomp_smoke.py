#!/usr/bin/env python3
"""Hosted seccomp smoke (PW04): does QEMU start under the L1 unit's SystemCallFilter, and is the control attributed?

  seccomp_smoke.py [--dump-out PATH] [--no-dump-check]       stdlib only; needs systemd as PID 1, QEMU and root (or `sudo -n`)

Five `systemd-run` legs over one QEMU argv (`-machine none -S`, no KVM; stdin carries two QMP commands and QEMU exits 0 on `quit`):
  B   the shipped filter (tests/fixture/l1_unit_filter.txt, the twin of mirrorstack-fleet's unit)   must END Result=success
  C   B plus `SystemCallFilter=~seccomp`, the positive control, ALWAYS run                         must END SIGSYS, attributed
  A   `SystemCallFilter=@system-service` alone, the 24.04 failure                                   SIGSYS (attributed) or success
  Cd  C with `-sandbox off`, ALWAYS run                                                            INFORMATIONAL only
  Ad  A with `-sandbox off`, run only when A died                                                  INFORMATIONAL only
A SIGSYS is not proof that the UNIT's filter killed QEMU, so a death is attributed by ONE thing: a kernel record that appeared DURING
that leg (before/after, `journalctl -k` and `dmesg`): type=1326, comm="qemu-system-x86", sig=31, syscall=317 (seccomp(2)). A death
with no such record is INSTRUMENT-BLIND (FAIL), never a pass. A smoke that could not run is REFUSED, never a pass.
The `-sandbox off` twins attribute nothing and decide nothing: they are printed under `twin (informational): ...`. MEASURED on hosted
ubuntu-24.04 (run 39247567865, QEMU 8.2.2+ds-0ubuntu1.18, systemd 255): QEMU 8.2.2 calls seccomp(2) even under `-sandbox off`, so Cd and
Ad died 31/SYS with a kernel record syscall=317 at the same ip as C and A, and the premise "with -sandbox off QEMU never reaches
seccomp, so the twin must succeed" is FALSE on the real runner; the same run showed the runner logs type=1326 records in both journalctl
-k and dmesg, and that systemd-analyze colorizes its output even when piped (so the dump is run with SYSTEMD_COLORS=0 and NO_COLOR=1 and
its ANSI CSI sequences are stripped before it is printed, compared or written).
The unit's text and QEMU's sandbox word are literals here; each twin repo pins its own copy (the limits are in PW04's entry)."""
from __future__ import annotations

import argparse
import collections
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, NamedTuple

HERE = Path(__file__).resolve().parent
FILTER_FILE = HERE / 'l1_unit_filter.txt'
DUMP_FILE = HERE / 'ubuntu2404-filter-dump.txt'
QEMU = '/usr/bin/qemu-system-x86_64'
SANDBOX = 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny'   # twin of qemu.SANDBOX (fleet qemu.py:39)
QMP_IN = '{"execute":"qmp_capabilities"}\n{"execute":"quit"}\n'
BASE_PROPS = ('User=nobody', 'NoNewPrivileges=yes', 'LimitCORE=0', 'RuntimeMaxSec=20')
DUMP_CMD = ['systemd-analyze', 'syscall-filter', '@system-service', '@sandbox']
LEGS = ('B', 'C', 'Cd', 'A', 'Ad')
UNPINNED = 'UNPINNED'   # the placeholder a dump fixture may hold before a hosted run's dump is committed (it is pinned now; the guard stays)
DUMP_ENV = {'SYSTEMD_COLORS': '0', 'NO_COLOR': '1'}   # systemd-analyze colorizes even when piped (run 39247567865)
ANSI_CSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')   # ESC [ parameter bytes, intermediate bytes, final byte
TWINS = ('Cd', 'Ad')
RECORD_FIELDS = (r'\btype=1326\b', r'\bsig=31\b', r'\bsyscall=317\b', r'\bcomm="qemu-system-x86"')
NOTICE = ("::notice::CONTROL-NOT-REPRODUCED systemd {v}: @sandbox is in @default here (a backport), "
          "the loader's line is redundant on this release and harmless")
ATTRIBUTED = '{leg} attributed by a kernel record (type=1326, comm="qemu-system-x86", sig=31, syscall=317) during the leg'
BLIND = ('INSTRUMENT-BLIND: {leg} died 31/SYS with no kernel record (type=1326, comm="qemu-system-x86", sig=31, syscall=317) '
         'during the leg; the -sandbox off twins do not attribute')


class Result(NamedTuple):
    valid: bool      # the output names a Result= or an exit status; without either nothing was observed
    success: bool
    sys: bool        # SIGSYS
    how: str


class Leg(NamedTuple):
    name: str
    res: Result
    records: tuple   # kernel lines that appeared during this leg


class Verdict(NamedTuple):
    status: str      # PASS | FAIL
    reasons: tuple
    notes: tuple

    def __str__(self) -> str:
        return 'PASS' if self.status == 'PASS' else 'FAIL(' + '; '.join(self.reasons) + ')'


def unit_lines(text: str) -> list[str]:
    lines = [x.strip() for x in text.splitlines() if x.strip() and not x.lstrip().startswith('#')]
    if [x.split('=', 1)[0] for x in lines] != ['SystemCallArchitectures', 'SystemCallFilter']:
        raise ValueError('l1_unit_filter.txt must hold SystemCallArchitectures= and SystemCallFilter=, one per line')
    return lines


def qemu_argv(sandbox: str) -> list[str]:
    return [QEMU, '-nodefaults', '-no-user-config', '-display', 'none', '-machine', 'none', '-S', '-sandbox', sandbox, '-qmp', 'stdio']


def leg_argv(name: str, lines: list[str]) -> list[str]:
    """The systemd-run argv of one leg (without the sudo prefix)."""
    arch, filt = lines
    extra = {'B': [filt], 'C': [filt, 'SystemCallFilter=~seccomp'], 'Cd': [filt, 'SystemCallFilter=~seccomp'],
             'A': ['SystemCallFilter=@system-service'], 'Ad': ['SystemCallFilter=@system-service']}[name]
    argv = ['systemd-run', '--wait', '--collect', '--pipe']
    for p in (*BASE_PROPS, arch, *extra):
        argv += ['-p', p]
    return argv + ['--'] + qemu_argv('off' if name in ('Cd', 'Ad') else SANDBOX)


def parse(out: str) -> Result:
    """Reads what `systemd-run --wait` printed. The exit code alone is not read: an empty output with exit 0 is no observation."""
    m = re.search(r'(?m)^\s*(?:Result=|Finished with result: )(\S+)', out)
    st = re.search(r'code=(?:exited|killed|dumped)[/, ]+status=(\S+)', out) or re.search(r'(?m)^\s*(?:ExecMainStatus|status)=(\S+)', out)
    sig = bool(re.search(r'status=(?:31/)?SYS\b|\bSIGSYS\b|signal=SYS\b', out))
    result = m.group(1) if m else None
    if result is None and st is None and not sig:
        return Result(False, False, False, 'no Result= line and no exit status')
    success = result == 'success' or (result is None and st is not None and st.group(1) == '0')
    how = ' '.join(x for x in (f'Result={result}' if result else '', f'status={st.group(1)}' if st else '') if x) or 'SIGSYS'
    return Result(True, success and not sig, sig, how)


def is_record(line: str) -> bool:
    return all(re.search(f, line) for f in RECORD_FIELDS)


def attributed(leg: Leg) -> bool:
    """The kernel record is the only attribution. The `-sandbox off` twins cannot give one: QEMU 8.2.2 calls seccomp(2) under them too."""
    return any(is_record(x) for x in leg.records)


def twin_lines(legs: dict[str, Leg]) -> list[str]:
    """What the twins did, for the log. Nothing reads them: they neither fail the run nor attribute a death."""
    got = []
    for name in TWINS:
        leg = legs.get(name)
        if leg is not None:
            how = leg.res.how if leg.res.valid else leg.res.how + ' (nothing observed)'
            got.append(f'twin (informational): {name} (-sandbox off) {how}; kernel records during the leg: {len(leg.records)}')
            got.extend(f'  {x}' for x in leg.records)
    return got


def judge(legs: dict[str, Leg], dump: str, version: str) -> Verdict:
    """`dump` is `same`, `differs`, `unpinned`, `empty` or `skipped`."""
    bad, notes = [], []

    def usable(name: str) -> bool:
        leg = legs.get(name)
        if leg is None:
            bad.append(f'{name}: not run')
        elif not leg.res.valid:
            bad.append(f'{name}: {leg.res.how} in the output (nothing observed)')
        return leg is not None and leg.res.valid

    if usable('B'):
        if legs['B'].res.sys:
            bad.append('B: the shipped filter killed QEMU (status=31/SYS)')
        elif not legs['B'].res.success:
            bad.append(f"B: ended {legs['B'].res.how}, not Result=success")
    if usable('C'):
        c = legs['C']
        if c.res.success:
            bad.append('INSTRUMENT-BLIND: the control leg did not die')
        elif not c.res.sys:
            bad.append(f'INSTRUMENT-BLIND: the control leg died but not by SIGSYS ({c.res.how})')
        elif attributed(c):
            notes.append(ATTRIBUTED.format(leg='C'))
        else:
            bad.append(BLIND.format(leg='C'))
    if usable('A'):
        a = legs['A']
        if a.res.success:
            notes.append(NOTICE.format(v=version))
        elif not a.res.sys:
            bad.append(f'A: died but not by SIGSYS ({a.res.how})')
        elif attributed(a):
            notes.append(ATTRIBUTED.format(leg='A'))
        else:
            bad.append(BLIND.format(leg='A'))
    if dump == 'differs':
        bad.append('DUMP-DIFFERS: the syscall-filter dump moved against tests/fixture/ubuntu2404-filter-dump.txt (an image bump changed the tables)')
    elif dump == 'unpinned':
        bad.append('DUMP-UNPINNED: tests/fixture/ubuntu2404-filter-dump.txt is the placeholder; commit the dump this run printed')
    elif dump == 'empty':
        bad.append('DUMP-EMPTY: systemd-analyze syscall-filter printed nothing')
    elif dump == 'skipped':
        notes.append('DUMP-CHECK-SKIPPED (--no-dump-check: not the pinned 24.04 runner)')
    return Verdict('FAIL' if bad else 'PASS', tuple(bad), tuple(notes))


def real_run(argv: list[str], stdin: str | None = None, timeout: int = 120, env: dict[str, str] | None = None) -> tuple[int | None, str]:
    """`env` is added to this process's environment, never a replacement of it."""
    try:
        p = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace', timeout=timeout,
                           env=None if env is None else {**os.environ, **env})
    except FileNotFoundError:
        return 127, ''
    except subprocess.TimeoutExpired as e:
        got = e.stdout or ''
        return None, got.decode('utf-8', 'replace') if isinstance(got, bytes) else got
    return p.returncode, p.stdout


def kernel_records(run: Callable, el: list[str]) -> collections.Counter:
    """The audit lines (type=1326) of qemu being killed (sig=31) at a seccomp(2) call (x86-64 syscall 317): `journalctl -k` and `dmesg`, whole."""
    seen = collections.Counter()
    for argv in (el + ['journalctl', '-k', '--no-pager', '-o', 'short-iso'], el + ['dmesg']):
        for line in run(argv)[1].splitlines():
            if is_record(line):
                seen[line] += 1
    return seen


def strip_ansi(text: str) -> str:
    return ANSI_CSI.sub('', text)


def normal(text: str) -> str:
    return '\n'.join(x.rstrip() for x in text.strip().splitlines())


def smoke(run: Callable = real_run, *, which: Callable = shutil.which, exists: Callable = os.path.exists, euid: int | None = None,
          out: Callable = print, unit_text: str | None = None, dump_fixture: str | None = None, dump_out: str | None = None,
          dump_check: bool = True) -> int:
    """0 PASS, 1 FAIL, 2 REFUSED. `run`, `which`, `exists`, `euid` and `out` are the test seam; the hosted call passes none."""
    el = [] if (os.geteuid() if euid is None else euid) == 0 else ['sudo', '-n']
    lines = unit_lines(FILTER_FILE.read_text(encoding='utf-8') if unit_text is None else unit_text)
    why = None if which('systemd-run') else 'systemd-run is not installed'
    if why is None and not exists('/run/systemd/system'):
        why = 'systemd is not PID 1 here (/run/systemd/system is missing)'
    if why is None and not exists(QEMU):
        why = f'{QEMU} is missing'
    if why is None and el and run(el + ['true'])[0] != 0:
        why = 'sudo -n does not work and this is not root'
    if why:
        out(f'::error::nothing was smoked: {why}')
        out('REFUSED')
        return 2
    out('::group::runner')
    ver = run(['systemd', '--version'])[1].strip().splitlines()[:1] or run(['systemd-analyze', '--version'])[1].strip().splitlines()[:1]
    m = re.match(r'systemd (\d+)', ver[0]) if ver else None
    version = m.group(1) if m else 'unknown'
    out(f'systemd: {ver[0] if ver else "unknown"}')
    qver = (run([QEMU, '--version'])[1].strip().splitlines() or ['unknown'])[0]
    ndef = sum('@sandbox' in x for x in strip_ansi(run(['systemd-analyze', 'syscall-filter', '@default'], env=DUMP_ENV)[1]).splitlines())
    out('kernel: ' + run(['uname', '-r'])[1].strip())
    out(f'qemu: {qver}')
    out(f'@default lines naming @sandbox: {ndef}')
    out('::endgroup::')
    dump_text = normal(strip_ansi(run(DUMP_CMD, env=DUMP_ENV)[1]))
    out('::group::systemd-analyze syscall-filter @system-service @sandbox')
    out(dump_text)
    out('::endgroup::')
    if dump_out:
        Path(dump_out).parent.mkdir(parents=True, exist_ok=True)
        Path(dump_out).write_text(dump_text + '\n', encoding='utf-8')
    if not dump_check:
        dump = 'skipped'
    elif not dump_text:
        dump = 'empty'
    else:
        if dump_fixture is None:
            dump_fixture = DUMP_FILE.read_text(encoding='utf-8') if DUMP_FILE.exists() else ''
        fixture = normal(dump_fixture)
        dump = 'unpinned' if not fixture or fixture.startswith(UNPINNED) else 'same' if fixture == dump_text else 'differs'
    legs: dict[str, Leg] = {}

    def go(name: str) -> Leg:
        before = kernel_records(run, el)
        rc, text = run(el + leg_argv(name, lines), QMP_IN, 90)
        new = tuple((kernel_records(run, el) - before).elements())
        out(f'::group::leg {name} (exit {rc})')
        out(text.rstrip())
        out(f'kernel records during the leg: {len(new)}')
        for x in new:
            out(f'  {x}')
        out('::endgroup::')
        legs[name] = Leg(name, parse(text), new)
        out(f'leg {name}: {legs[name].res.how if legs[name].res.valid else legs[name].res.how + " (nothing observed)"}')
        return legs[name]

    for name in ('B', 'C', 'Cd'):
        go(name)
    a = go('A')
    if a.res.valid and not a.res.success:
        go('Ad')
    verdict = judge(legs, dump, version)
    for n in twin_lines(legs):
        out(n)
    for n in verdict.notes:
        out(n)
    for r in verdict.reasons:
        out(f'::error::{r}')
    out(str(verdict))
    return 0 if verdict.status == 'PASS' else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('--dump-out', help='write the syscall-filter dump here (the workflow uploads it)')
    p.add_argument('--no-dump-check', action='store_true', help="do not compare the dump with the 24.04 fixture (a machine that is not that runner)")
    a = p.parse_args(argv)
    return smoke(dump_out=a.dump_out, dump_check=not a.no_dump_check)


if __name__ == '__main__':
    sys.exit(main())
