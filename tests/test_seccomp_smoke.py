"""PW04: the hosted seccomp smoke's driver over a fake `systemd-run` (no systemd, no QEMU, no sudo), the twin files, and the
workflow's static shape. The red run of the job itself is the hosted runner; these tests pin the judge and the argv."""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tests' / 'fixture'))
import seccomp_smoke as ss  # noqa: E402

WF = (ROOT / '.github' / 'workflows' / 'seccomp-smoke.yml').read_text(encoding='utf-8')
BOOT = (ROOT / '.github' / 'workflows' / 'boot-smoke.yml').read_text(encoding='utf-8')
LINES = ['SystemCallArchitectures=native', 'SystemCallFilter=@system-service @sandbox']
SANDBOX = 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny'   # qemu.SANDBOX of the fleet repo, qemu.py:39
OK = 'Running as unit: run-u1.service\nFinished with result: success\nMain processes terminated with: code=exited/status=0\nService runtime: 80ms\n'
SYS = 'Running as unit: run-u2.service\nFinished with result: signal\nMain processes terminated with: code=killed/status=SYS\nService runtime: 9ms\n'
EXIT1 = 'Running as unit: run-u3.service\nFinished with result: exit-code\nMain processes terminated with: code=exited/status=1\n'
RECORD = 'Oct 19 05:00:01 host kernel: audit: type=1326 audit(1.2:3): uid=65534 comm="qemu-system-x86" sig=31 arch=c000003e syscall=317 compat=0 code=0x80000000'
DUMP = '@system-service\n    # Default set\n    brk\n@sandbox\n    landlock_create_ruleset\n    seccomp\n'


def props(argv):
    return [argv[i + 1] for i, a in enumerate(argv) if a == '-p']


def leg_of(argv):
    """Which leg a systemd-run argv is: read from the argv alone, as a reviewer would."""
    p, off = props(argv), argv[argv.index('-sandbox') + 1] == 'off'
    if 'SystemCallFilter=~seccomp' in p:
        return 'Cd' if off else 'C'
    if 'SystemCallFilter=@system-service' in p:
        return 'Ad' if off else 'A'
    return 'B'


class Fake:
    """A machine: `outcome` maps a leg to what systemd-run printed; a leg listed in `records` logs the kernel line when it ran."""

    def __init__(self, B=OK, C=SYS, Cd=OK, A=SYS, Ad=OK, records=('C', 'A'), version='systemd 255 (255.4-1ubuntu8.6)', dump=DUMP,
                 record=RECORD, dmesg_only=False):
        self.outcome = dict(B=B, C=C, Cd=Cd, A=A, Ad=Ad)
        self.records, self.version, self.dump = set(records), version, dump
        self.record, self.dmesg_only = record, dmesg_only   # the kernel line a dying leg logs; dmesg_only: journalctl -k sees nothing, dmesg does
        self.kernel, self.ran, self.calls, self.stdin = [], [], [], []

    def run(self, argv, stdin=None, timeout=120):
        argv = list(argv)
        self.calls.append(argv)
        if argv[:2] == ['sudo', '-n']:
            argv = argv[2:]
        if argv[0] == 'systemd-run':
            leg = leg_of(argv)
            self.ran.append(leg)
            self.stdin.append(stdin)
            if leg in self.records and self.outcome[leg] != OK:
                self.kernel.append(self.record)
            return 0, self.outcome[leg]
        if argv[0] == 'journalctl':
            return 0, ('' if self.dmesg_only else '\n'.join(['Oct 19 04:00:00 host kernel: unrelated', *self.kernel]) + '\n')
        if argv[0] == 'dmesg':
            return 0, ('\n'.join(self.kernel) + '\n') if self.dmesg_only else ''
        if argv[0] == 'systemd':
            return 0, self.version + '\n+PAM +AUDIT\n'
        if argv[0] == 'systemd-analyze':
            return 0, self.dump if argv[2:] == ['@system-service', '@sandbox'] else '@default\n    @sandbox\n    brk\n'
        if argv[0] == 'uname':
            return 0, '6.11.0-azure\n'
        if argv[0] == ss.QEMU:
            return 0, 'QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1)\n'
        return 0, ''


def smoke(fake, **kw):
    out = []
    args = dict(run=fake.run, which=lambda n: '/usr/bin/' + n, exists=lambda p: True, euid=0, out=out.append,
                unit_text='\n'.join(LINES) + '\n', dump_fixture=DUMP)
    args.update(kw)
    code = ss.smoke(**args)
    return code, out


class Argv(unittest.TestCase):
    def test_the_twin_file_is_exactly_the_two_lines_of_the_unit(self):
        self.assertEqual((ROOT / 'tests/fixture/l1_unit_filter.txt').read_text(encoding='utf-8'), '\n'.join(LINES) + '\n')
        self.assertEqual(ss.unit_lines((ROOT / 'tests/fixture/l1_unit_filter.txt').read_text(encoding='utf-8')), LINES)

    def test_a_twin_file_that_is_not_those_two_lines_is_refused(self):
        for bad in ('SystemCallFilter=@system-service @sandbox\n', LINES[0] + '\n', '\n'.join(LINES[::-1]), LINES[0] + '\n' + LINES[1] + '\nSystemCallFilter=~seccomp\n'):
            with self.assertRaises(ValueError):
                ss.unit_lines(bad)

    def test_b_holds_exactly_the_two_lines_and_no_deny(self):
        p = props(ss.leg_argv('B', LINES))
        self.assertEqual([x for x in p if x.startswith('SystemCall')], LINES)
        self.assertTrue({'User=nobody', 'NoNewPrivileges=yes', 'LimitCORE=0', 'RuntimeMaxSec=20'} <= set(p))

    def test_c_is_b_plus_the_seccomp_deny_and_a_is_the_loaders_line_without_sandbox(self):
        self.assertEqual([x for x in props(ss.leg_argv('C', LINES)) if x.startswith('SystemCall')], LINES + ['SystemCallFilter=~seccomp'])
        a = [x for x in props(ss.leg_argv('A', LINES)) if x.startswith('SystemCall')]
        self.assertEqual(a, [LINES[0], 'SystemCallFilter=@system-service'])

    def test_the_qemu_argv_holds_the_sandbox_word_verbatim_and_the_twins_turn_it_off(self):
        self.assertEqual(ss.SANDBOX, SANDBOX)
        for leg in ('B', 'C', 'A'):
            argv = ss.leg_argv(leg, LINES)
            self.assertEqual(argv[argv.index('-sandbox') + 1], SANDBOX)
        for leg in ('Cd', 'Ad'):
            argv = ss.leg_argv(leg, LINES)
            self.assertEqual(argv[argv.index('-sandbox') + 1], 'off')
            self.assertEqual(props(argv), props(ss.leg_argv(leg[0], LINES)))   # same properties as its leg: only the sandbox differs
        q = ss.leg_argv('B', LINES)
        q = q[q.index('--') + 1:]
        self.assertEqual(q[:9], [ss.QEMU, '-nodefaults', '-no-user-config', '-display', 'none', '-machine', 'none', '-S', '-sandbox'])
        self.assertEqual(q[-2:], ['-qmp', 'stdio'])
        self.assertEqual(ss.leg_argv('B', LINES)[:4], ['systemd-run', '--wait', '--collect', '--pipe'])

    def test_the_legs_get_the_qmp_script_on_stdin(self):
        f = Fake()
        smoke(f)
        self.assertEqual(set(f.stdin), {'{"execute":"qmp_capabilities"}\n{"execute":"quit"}\n'})


class Parse(unittest.TestCase):
    def test_what_systemd_run_prints(self):
        self.assertEqual(ss.parse(OK)[:3], (True, True, False))
        self.assertEqual(ss.parse(SYS)[:3], (True, False, True))
        self.assertEqual(ss.parse('Result=signal\nstatus=31/SYS\n')[:3], (True, False, True))
        self.assertEqual(ss.parse(EXIT1)[:3], (True, False, False))

    def test_no_result_and_no_status_is_nothing_observed(self):
        for out in ('', '\n', '{"QMP": {"version": {}}}\n', 'Running as unit: run-u1.service\n'):
            self.assertFalse(ss.parse(out).valid, out)


class Verdicts(unittest.TestCase):
    def run_smoke(self, **kw):
        fake_kw = {k: kw.pop(k) for k in list(kw) if k in ('B', 'C', 'Cd', 'A', 'Ad', 'records', 'version', 'dump', 'record', 'dmesg_only')}
        f = Fake(**fake_kw)
        code, out = smoke(f, **kw)
        return f, code, out

    def test_b_ok_c_attributed_by_record_a_attributed_by_record_is_pass(self):
        f, code, out = self.run_smoke()
        self.assertEqual((code, out[-1]), (0, 'PASS'))
        self.assertEqual(f.ran, ['B', 'C', 'Cd', 'A', 'Ad'])
        self.assertIn('C attributed by (i) kernel record and (ii) -sandbox off twin ended Result=success', out)

    def test_b_dying_31_sys_is_fail(self):
        _, code, out = self.run_smoke(B=SYS)
        self.assertEqual(code, 1)
        self.assertRegex(out[-1], r'^FAIL\(B: the shipped filter killed QEMU \(status=31/SYS\)')

    def test_b_ending_otherwise_than_success_is_fail(self):
        _, code, out = self.run_smoke(B=EXIT1)
        self.assertEqual(code, 1)
        self.assertIn('B: ended Result=exit-code status=1, not Result=success', out[-1])

    def test_a_control_that_succeeds_is_instrument_blind_even_if_b_and_a_look_right(self):
        _, code, out = self.run_smoke(C=OK)
        self.assertEqual((code, out[-1]), (1, 'FAIL(INSTRUMENT-BLIND: the control leg did not die)'))

    def test_a_control_that_dies_otherwise_than_by_sigsys_is_instrument_blind_even_with_a_record(self):
        _, code, out = self.run_smoke(C=EXIT1)
        self.assertEqual(code, 1)
        self.assertIn('INSTRUMENT-BLIND: the control leg died but not by SIGSYS (Result=exit-code status=1)', out[-1])

    def test_a_control_that_dies_with_no_record_and_a_dying_twin_is_instrument_blind(self):
        _, code, out = self.run_smoke(Cd=SYS, records=())
        self.assertEqual(code, 1)
        self.assertIn('INSTRUMENT-BLIND: C died 31/SYS with no kernel record', out[-1])
        self.assertIn('Cd: the -sandbox off twin ended', out[-1])

    def test_a_control_that_dies_with_no_record_but_a_passing_twin_is_pass_by_attribution_ii(self):
        _, code, out = self.run_smoke(records=())
        self.assertEqual((code, out[-1]), (0, 'PASS'))
        self.assertIn('C attributed by (ii) -sandbox off twin ended Result=success', out)
        self.assertIn('A attributed by (ii) -sandbox off twin ended Result=success', out)

    def test_a_death_attributed_by_a_record_alone_is_pass_when_the_twin_was_not_run(self):
        leg = lambda n, out, rec=(): ss.Leg(n, ss.parse(out), rec)  # noqa: E731
        legs = {'B': leg('B', OK), 'C': leg('C', SYS, (RECORD,)), 'Cd': leg('Cd', OK), 'A': leg('A', SYS, (RECORD,))}
        v = ss.judge(legs, 'same', '255')
        self.assertEqual((v.status, v.notes[-1]), ('PASS', 'A attributed by (i) kernel record'))
        legs['A'] = leg('A', SYS)
        self.assertEqual(ss.judge(legs, 'same', '255').status, 'FAIL')   # no record and no twin result: blind
        del legs['Cd']
        self.assertIn('Cd: not run', ss.judge(legs, 'same', '255').reasons)

    def test_a_dying_with_no_record_and_no_twin_result_is_instrument_blind(self):
        _, code, out = self.run_smoke(records=('C',), Ad=SYS)
        self.assertEqual(code, 1)
        self.assertIn('INSTRUMENT-BLIND: A died 31/SYS with no kernel record', out[-1])

    def test_a_dying_non_sigsys_is_fail(self):
        _, code, out = self.run_smoke(A=EXIT1)
        self.assertEqual(code, 1)
        self.assertIn('A: died but not by SIGSYS', out[-1])

    def test_a_succeeding_too_is_pass_with_the_backport_notice_and_no_ad(self):
        f, code, out = self.run_smoke(A=OK, version='systemd 259 (259.5-1)')
        self.assertEqual((code, out[-1]), (0, 'PASS'))
        self.assertEqual(f.ran, ['B', 'C', 'Cd', 'A'])
        self.assertIn("::notice::CONTROL-NOT-REPRODUCED systemd 259: @sandbox is in @default here (a backport), "
                      "the loader's line is redundant on this release and harmless", out)

    def test_the_backport_does_not_excuse_a_blind_control(self):
        _, code, out = self.run_smoke(A=OK, C=OK)
        self.assertEqual(code, 1)
        self.assertIn('INSTRUMENT-BLIND', out[-1])

    def test_an_output_with_neither_result_nor_status_is_fail_not_pass(self):
        for leg in ('B', 'C', 'Cd', 'A'):
            _, code, out = self.run_smoke(**{leg: ''})
            self.assertEqual(code, 1, leg)
            self.assertIn(f'{leg}: no Result= line and no exit status', out[-1])

    def test_a_record_of_another_leg_is_not_this_legs_record(self):
        # B passes and logs nothing; the record C left must not attribute a later A that died on its own with no record
        f = Fake(records=('C',), Ad=SYS)
        _, out = smoke(f)
        self.assertIn('INSTRUMENT-BLIND: A died', out[-1])

    def test_a_record_that_predates_the_run_is_not_attributed(self):
        f = Fake(records=())
        f.kernel.append(RECORD)   # an old record: present before every leg, so no leg made it
        _, out = smoke(f)
        self.assertEqual(out[-1], 'PASS')   # (ii) attributes through the twins
        self.assertNotIn('(i)', ' '.join(x for x in out if x.startswith('C attributed')))
        f2 = Fake(records=(), Cd=SYS)
        f2.kernel.append(RECORD)
        _, out2 = smoke(f2)
        self.assertIn('INSTRUMENT-BLIND', out2[-1])

    def test_a_kernel_line_of_another_comm_or_another_syscall_is_not_a_record(self):
        for other in (RECORD.replace('comm="qemu-system-x86"', 'comm="bash"'), RECORD.replace('syscall=317', 'syscall=1')):
            _, code, out = self.run_smoke(Cd=SYS, record=other)   # Cd dies too, so (ii) cannot rescue C
            self.assertEqual(code, 1, other)
            self.assertIn('INSTRUMENT-BLIND: C died 31/SYS with no kernel record', out[-1])
            self.assertFalse([x for x in out if x.startswith('C attributed')], other)

    def test_a_record_that_only_dmesg_shows_still_counts(self):
        _, code, out = self.run_smoke(Cd=SYS, dmesg_only=True)
        self.assertIn('C attributed by (i) kernel record', out)
        self.assertNotIn('INSTRUMENT-BLIND: C died', out[-1])

    def test_a_dying_a_whose_twin_printed_nothing_is_fail(self):
        _, code, out = self.run_smoke(Ad='')
        self.assertEqual(code, 1)
        self.assertTrue(out[-1].startswith('FAIL('))
        self.assertIn('Ad: no Result= line and no exit status in the output (nothing observed)', out[-1])

    def test_the_runner_is_printed_first(self):
        _, _, out = self.run_smoke()
        for prefix in ('systemd: systemd 255', 'kernel: 6.11', 'qemu: QEMU emulator', '@default lines naming @sandbox: 1'):
            self.assertTrue(any(x.startswith(prefix) for x in out), prefix)
        self.assertEqual(out[0], '::group::runner')
        self.assertLess(max(out.index(x) for x in out if x.startswith(('systemd: ', 'kernel: ', 'qemu: ', '@default lines'))),
                        out.index('::endgroup::'))


class Dump(unittest.TestCase):
    def test_a_dump_that_differs_from_the_fixture_is_fail(self):
        _, out = smoke(Fake(), dump_fixture=DUMP + '    mseal\n')
        self.assertIn('DUMP-DIFFERS', out[-1])
        self.assertTrue(out[-1].startswith('FAIL('))

    def test_a_dump_that_gained_a_line_against_the_fixture_is_fail(self):
        _, out = smoke(Fake(dump=DUMP + '    mseal\n'))   # an image bump added a call to @sandbox
        self.assertIn('DUMP-DIFFERS', out[-1])
        self.assertTrue(out[-1].startswith('FAIL('))

    def test_trailing_space_and_final_newline_are_not_a_difference(self):
        code, out = smoke(Fake(), dump_fixture=DUMP.replace('brk\n', 'brk   \n') + '\n\n')
        self.assertEqual((code, out[-1]), (0, 'PASS'))

    def test_the_placeholder_fixture_is_fail_unpinned_but_the_legs_still_ran(self):
        f = Fake()
        code, out = smoke(f, dump_fixture='UNPINNED: replace me\n')
        self.assertEqual(code, 1)
        self.assertIn('DUMP-UNPINNED', out[-1])
        self.assertEqual(f.ran, ['B', 'C', 'Cd', 'A', 'Ad'])
        self.assertIn(DUMP.strip(), out)   # the dump is printed so it can be committed

    def test_the_committed_fixture_is_the_placeholder_until_the_first_hosted_run_replaces_it(self):
        text = (ROOT / 'tests/fixture/ubuntu2404-filter-dump.txt').read_text(encoding='utf-8')
        self.assertTrue(text.startswith(ss.UNPINNED) or '@sandbox' in text)

    def test_an_empty_dump_is_fail(self):
        _, out = smoke(Fake(dump=''))
        self.assertIn('DUMP-EMPTY', out[-1])

    def test_no_dump_check_is_a_pc_run_that_says_so(self):
        code, out = smoke(Fake(), dump_check=False, dump_fixture='something else\n')
        self.assertEqual((code, out[-1]), (0, 'PASS'))
        self.assertTrue(any(x.startswith('DUMP-CHECK-SKIPPED') for x in out))

    def test_the_dump_is_written_for_the_artifact(self):
        with tempfile.TemporaryDirectory() as d:
            smoke(Fake(), dump_out=str(Path(d) / 'sub' / 'dump.txt'))
            self.assertEqual((Path(d) / 'sub' / 'dump.txt').read_text(encoding='utf-8'), DUMP.strip() + '\n')


class Main(unittest.TestCase):
    """The workflow reaches the dump comparison and the artifact only through main()'s argparse wiring."""

    def kwargs_of(self, argv):
        with mock.patch.object(ss, 'smoke', return_value=7) as m:
            self.assertEqual(ss.main(argv), 7)   # the exit code is smoke's
        m.assert_called_once()
        self.assertEqual(m.call_args.args, ())
        return m.call_args.kwargs

    def test_the_default_run_compares_the_dump_and_writes_no_file(self):
        self.assertEqual(self.kwargs_of([]), {'dump_out': None, 'dump_check': True})

    def test_the_flags_reach_smoke(self):
        self.assertEqual(self.kwargs_of(['--no-dump-check', '--dump-out', 'x']), {'dump_out': 'x', 'dump_check': False})
        self.assertEqual(self.kwargs_of(['--dump-out', 'seccomp-dump/d.txt']), {'dump_out': 'seccomp-dump/d.txt', 'dump_check': True})


class RealRun(unittest.TestCase):
    """The only function that touches a real process, run on this interpreter."""

    def test_stderr_comes_back_merged_with_stdout_as_systemd_run_logs_there(self):
        code = 'import sys; sys.stderr.write("Finished with result: success\\n")'
        self.assertEqual(ss.real_run([sys.executable, '-c', code]), (0, 'Finished with result: success\n'))
        self.assertEqual(ss.real_run([sys.executable, '-c', 'import sys; sys.stdout.write("o"); sys.stderr.write("e"); sys.exit(3)']), (3, 'oe'))

    def test_a_missing_binary_is_127_never_a_zero(self):
        self.assertEqual(ss.real_run(['/nonexistent-bin']), (127, ''))

    def test_a_timeout_is_none_and_keeps_what_was_printed(self):
        rc, text = ss.real_run([sys.executable, '-u', '-c', 'import time; print("partial"); time.sleep(5)'], timeout=1)
        self.assertIsNone(rc)
        self.assertEqual(text.strip(), 'partial')

    def test_stdin_passes_through(self):
        self.assertEqual(ss.real_run([sys.executable, '-c', 'import sys; sys.stdout.write(sys.stdin.read().upper())'], stdin='qmp\n'), (0, 'QMP\n'))


class Refused(unittest.TestCase):
    def assertRefused(self, code, out, word):
        self.assertEqual((code, out[-1]), (2, 'REFUSED'))
        self.assertTrue(any(x.startswith('::error::nothing was smoked: ') and word in x for x in out), out)

    def test_a_missing_systemd_run_is_refused_never_a_pass(self):
        f = Fake()
        code, out = smoke(f, which=lambda n: None)
        self.assertRefused(code, out, 'systemd-run')
        self.assertEqual(f.ran, [])

    def test_no_pid_1_systemd_is_refused(self):
        code, out = smoke(Fake(), exists=lambda p: p != '/run/systemd/system')
        self.assertRefused(code, out, 'PID 1')

    def test_a_missing_qemu_is_refused(self):
        code, out = smoke(Fake(), exists=lambda p: p != ss.QEMU)
        self.assertRefused(code, out, 'qemu')

    def test_no_sudo_for_a_non_root_run_is_refused_and_a_root_run_never_calls_sudo(self):
        f = Fake()
        f.run_orig = f.run
        code, out = smoke(f, euid=1000, run=lambda argv, *a, **k: (1, '') if argv[:3] == ['sudo', '-n', 'true'] else f.run_orig(argv, *a, **k))
        self.assertRefused(code, out, 'sudo')
        f2 = Fake()
        smoke(f2, euid=0)
        self.assertFalse([c for c in f2.calls if c[0] == 'sudo'])
        f3 = Fake()
        smoke(f3, euid=1000)
        self.assertTrue(all(c[:2] == ['sudo', '-n'] for c in f3.calls if c[0] in ('systemd-run', 'journalctl', 'dmesg')))


class Workflow(unittest.TestCase):
    SMOKE = re.search(r'(?ms)^  smoke:\n(.*?)(?=^  [\w-]+:\n|\Z)', WF)[1]
    REPORT = re.search(r'(?ms)^  report:\n(.*?)(?=^  [\w-]+:\n|\Z)', WF)[1]

    def test_triggers_are_its_own_paths_a_dispatch_and_a_weekly_schedule(self):
        on = re.search(r'(?ms)^on:\n(.*?)^permissions:', WF)[1]
        self.assertEqual(re.findall(r'(?m)^  (\w+):', on), ['pull_request', 'workflow_dispatch', 'schedule'])
        paths = re.findall(r'(?m)^      - (\S+)$', on)
        self.assertEqual(paths, ['.github/workflows/seccomp-smoke.yml', 'tests/fixture/seccomp_smoke.py', 'tests/fixture/l1_unit_filter.txt',
                                 'tests/fixture/ubuntu2404-filter-dump.txt', 'tests/test_seccomp_smoke.py'])
        self.assertEqual(len(re.findall(r"- cron: '[^']+'", on)), 1)
        self.assertRegex(on, r"- cron: '\d+ \d+ \* \* \d'")   # weekly: one minute, one hour, one weekday
        for word in ('push:', 'pull_request_target', 'workflow_run', 'self-hosted'):
            self.assertNotIn(word, WF)

    def test_hosted_ubuntu_24_04_read_only_and_a_ten_minute_smoke(self):
        self.assertRegex(WF, r'(?m)^permissions:\n  contents: read\n')
        self.assertEqual(re.findall(r'runs-on: (\S+)', WF), ['ubuntu-24.04', 'ubuntu-24.04'])
        self.assertIn('    timeout-minutes: 10\n', self.SMOKE)
        self.assertNotIn('permissions:', self.SMOKE)

    def test_actions_are_the_pins_the_repo_already_uses_and_checkout_keeps_no_token(self):
        pins = lambda t: set(re.findall(r'(actions/[\w-]+@[0-9a-f]{40})', t))  # noqa: E731
        used = re.findall(r'uses: (\S+)', WF)
        for use in used:
            self.assertRegex(use, r'^actions/[\w-]+@[0-9a-f]{40}$')
        self.assertEqual(pins(WF) - pins(BOOT), set())   # checkout, setup-python and upload-artifact exactly as boot-smoke.yml pins them
        self.assertEqual(len(used), 3)
        self.assertEqual(WF.count('persist-credentials: false'), WF.count('actions/checkout@'))

    def test_the_smoke_installs_qemu_from_the_archive_and_runs_the_driver_isolated(self):
        self.assertIn('sudo apt-get install -y --no-install-recommends qemu-system-x86', self.SMOKE)
        self.assertRegex(self.SMOKE, r'python3 -I -B tests/fixture/seccomp_smoke\.py --dump-out \S+')
        self.assertNotIn('--no-dump-check', WF)
        self.assertRegex(self.SMOKE, r'(?s)if: always\(\)\n\s+uses: actions/upload-artifact@')

    def test_only_the_report_job_writes_and_only_issues_and_only_on_a_failed_scheduled_run(self):
        self.assertEqual(re.findall(r'(\w[\w-]*): write', WF), ['issues'])
        self.assertIn('    permissions:\n      issues: write\n', self.REPORT)
        self.assertIn("    needs: smoke\n    if: failure() && github.event_name == 'schedule'\n", self.REPORT)
        self.assertNotIn('checkout', self.REPORT)

    def test_the_report_job_searches_for_its_issue_by_the_quoted_title(self):
        # an unquoted `seccomp-smoke: ...` reads as a search qualifier: a duplicate issue every week, or a red report job
        self.assertIn('--search "\\"$title\\" in:title"', self.REPORT)
        self.assertNotIn('--search "$title', self.REPORT)

    def test_no_secret_and_no_expression_reaches_a_run_line_except_through_env(self):
        self.assertNotRegex(WF, r'(?i)secrets\.')
        in_run = False
        for line in WF.splitlines():
            m = re.match(r'(\s*)(?:- )?run:', line)
            if m:
                in_run, indent = True, len(m.group(1))
                self.assertNotIn('${{', line)
            elif in_run and (not line.strip() or len(line) - len(line.lstrip()) > indent):
                self.assertNotIn('${{', line)
            else:
                in_run = False


if __name__ == '__main__':
    unittest.main()
