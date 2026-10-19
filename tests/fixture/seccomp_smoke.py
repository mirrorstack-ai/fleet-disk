#!/usr/bin/env python3
"""Hosted seccomp smoke (PW04): does QEMU start under the L1 unit's SystemCallFilter, and is the control attributed?

  seccomp_smoke.py [--dump-out PATH] [--no-dump-check]       stdlib only; needs systemd as PID 1, QEMU and root (or `sudo -n`)

Five `systemd-run` legs over one QEMU argv (`-machine none -S`, no KVM; stdin carries two QMP commands and QEMU exits 0 on `quit`):
  B   the shipped filter (tests/fixture/l1_unit_filter.txt, the twin of mirrorstack-fleet's unit)   must END Result=success
  C   B plus `SystemCallFilter=~seccomp`, the positive control, ALWAYS run                         must END SIGSYS, attributed
  Cd  C with `-sandbox off`: QEMU then never calls seccomp(2)                                      must END Result=success
  A   `SystemCallFilter=@system-service` alone, the 24.04 failure                                   SIGSYS (attributed) or success
  Ad  A with `-sandbox off`, run only when A died                                                  must END Result=success
A SIGSYS is not proof that the UNIT's filter killed QEMU (QEMU 8.2.2's own `-sandbox` deny-list also traps), so every death is
attributed by (i) a kernel record (syscall=317, comm="qemu-system-x86") that appeared DURING the leg, or (ii) its `-sandbox off`
twin ending Result=success. A death with neither is INSTRUMENT-BLIND. A smoke that could not run is REFUSED, never a pass.
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
UNPINNED = 'UNPINNED'   # the committed placeholder of the dump fixture, until the first hosted run's dump replaces it
NOTICE = ("::notice::CONTROL-NOT-REPRODUCED systemd {v}: @sandbox is in @default here (a backport), "
          "the loader's line is redundant on this release and harmless")


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


def attribution(leg: Leg, twin: Leg | None) -> list[str]:
    got = []
    if leg.records:
        got.append('(i) kernel record')
    if twin is not None and twin.res.success:
        got.append('(ii) -sandbox off twin ended Result=success')
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
        c, cd = legs['C'], legs.get('Cd')
        if c.res.success:
            bad.append('INSTRUMENT-BLIND: the control leg did not die')
        elif not c.res.sys:
            bad.append(f'INSTRUMENT-BLIND: the control leg died but not by SIGSYS ({c.res.how})')
        else:
            how = attribution(c, cd)
            if how:
                notes.append('C attributed by ' + ' and '.join(how))
            else:
                bad.append('INSTRUMENT-BLIND: C died 31/SYS with no kernel record and its -sandbox off twin did not end Result=success')
    if usable('Cd') and not legs['Cd'].res.success:
        bad.append(f"Cd: the -sandbox off twin ended {legs['Cd'].res.how}, it must end Result=success")
    if usable('A'):
        a, ad = legs['A'], legs.get('Ad')
        if a.res.success:
            notes.append(NOTICE.format(v=version))
        elif not a.res.sys:
            bad.append(f'A: died but not by SIGSYS ({a.res.how})')
        else:
            how = attribution(a, ad)
            if how:
                notes.append('A attributed by ' + ' and '.join(how))
            else:
                bad.append('INSTRUMENT-BLIND: A died 31/SYS with no kernel record and no Result=success from its -sandbox off twin')
        if ad is not None and ad.res.valid and not ad.res.success:
            bad.append(f'Ad: the -sandbox off twin ended {ad.res.how}, it must end Result=success')
        elif ad is not None and not ad.res.valid:
            bad.append(f'Ad: {ad.res.how} in the output (nothing observed)')
    if dump == 'differs':
        bad.append('DUMP-DIFFERS: the syscall-filter dump moved against tests/fixture/ubuntu2404-filter-dump.txt (an image bump changed the tables)')
    elif dump == 'unpinned':
        bad.append('DUMP-UNPINNED: tests/fixture/ubuntu2404-filter-dump.txt is the placeholder; commit the dump this run printed')
    elif dump == 'empty':
        bad.append('DUMP-EMPTY: systemd-analyze syscall-filter printed nothing')
    elif dump == 'skipped':
        notes.append('DUMP-CHECK-SKIPPED (--no-dump-check: not the pinned 24.04 runner)')
    return Verdict('FAIL' if bad else 'PASS', tuple(bad), tuple(notes))


def real_run(argv: list[str], stdin: str | None = None, timeout: int = 120) -> tuple[int | None, str]:
    try:
        p = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace', timeout=timeout)
    except FileNotFoundError:
        return 127, ''
    except subprocess.TimeoutExpired as e:
        got = e.stdout or ''
        return None, got.decode('utf-8', 'replace') if isinstance(got, bytes) else got
    return p.returncode, p.stdout


def kernel_records(run: Callable, el: list[str]) -> collections.Counter:
    """The kernel lines naming a seccomp(2) call (x86-64 syscall 317) by qemu: `journalctl -k` and `dmesg`, whole."""
    seen = collections.Counter()
    for argv in (el + ['journalctl', '-k', '--no-pager', '-o', 'short-iso'], el + ['dmesg']):
        for line in run(argv)[1].splitlines():
            if re.search(r'syscall=317\b', line) and 'comm="qemu-system-x86"' in line:
                seen[line] += 1
    return seen


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
    ndef = sum('@sandbox' in x for x in run(['systemd-analyze', 'syscall-filter', '@default'])[1].splitlines())
    out('kernel: ' + run(['uname', '-r'])[1].strip())
    out(f'qemu: {qver}')
    out(f'@default lines naming @sandbox: {ndef}')
    out('::endgroup::')
    dump_text = normal(run(DUMP_CMD)[1])
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
