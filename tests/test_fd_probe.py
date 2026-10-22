"""PZ03 (G-KH-1): the descriptor probe's verdict over the shared golden vectors and over made-up probe JSON, its measuring code over a
made-up /proc tree (real descriptors, so it runs on any POSIX host) and, on Linux only, over the real kernel, its driver over a fake
runner, and the workflow's static shape. The red or green run of the four hosted legs is the real test of the image itself."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tests' / 'fixture'))
import fd_probe as fp  # noqa: E402

GOLDEN_PATH = ROOT / 'tests' / 'fixture' / 'fd_golden.json'
# The key holder's repository carries a byte-identical tests/vm/fd_golden.json and asserts the same constant: change both or neither.
GOLDEN_SHA256 = '8e7606c636f24006e52c140ed375bbe07d97b9aa711db7e8f797bb9d5bf5104b'
GOLDEN = json.loads(GOLDEN_PATH.read_text(encoding='utf-8'))
WF = (ROOT / '.github' / 'workflows' / 'fd-probe.yml').read_text(encoding='utf-8')
TEST_WF = (ROOT / '.github' / 'workflows' / 'test.yml').read_text(encoding='utf-8')
BOTH = tuple(fp.LIB_DIRS.values())
X, A = '/usr/lib/x86_64-linux-gnu/', '/usr/lib/aarch64-linux-gnu/'
OWNER = 'python3-minimal: /usr/bin/python3'


def good(arch='x86_64', **kw):
    d = {'fd': 3, 'type': 'regular', 'uid': 0, 'mode': '0644', 'flags': 0, 'target': fp.LIB_DIRS[arch] + '/libffi.so.8.1.4',
         'maps_has_path': True, 'maps_over_cap': False, 'fdflags': 1, 'maps_dev_ino_agree': True}
    d.update(kw)
    return d


def verdict(extras, release='26.04', arch='x86_64', owner=OWNER, host_release=None, host_arch=None):
    return fp.judge({'executable': '/usr/bin/python3', 'version': '3.14.4', 'extras': extras}, expect_release=release, expect_arch=arch,
                    release=host_release or release, arch=host_arch or arch, python_owner=owner)


class Golden(unittest.TestCase):
    def test_the_copy_is_the_file_the_key_holder_repository_carries(self):
        self.assertEqual(hashlib.sha256(GOLDEN_PATH.read_bytes()).hexdigest(), GOLDEN_SHA256)

    def test_the_table_has_every_clause_of_the_rule_as_a_row_and_the_good_rows(self):
        names = [r['name'] for r in GOLDEN]
        self.assertEqual(len(names), len(set(names)))
        for need in ('good x86_64', 'good aarch64', 'uid 1000', 'mode 0664 (group write)', 'mode 4755 (setuid)', 'type directory',
                     'type fifo', 'type socket', 'type char device', 'O_RDWR', 'O_WRONLY', 'O_PATH', 'target in /tmp',
                     'target in /usr/local/lib', 'target ending (deleted)', 'basename libffi.so', 'basename libffi.so.8.bak',
                     'basename xlibffi.so.8', 'basename libffi.so.8/..', 'basename libffi.so.8.1.4.9', 'basename libffi.so.8.1.4.9.9',
                     'no maps line for the path', 'maps text over the 4 MiB cap', 'relative target'):
            self.assertIn(need, names)
        self.assertEqual({r['expect'] for r in GOLDEN}, {'pass', 'refuse'})
        self.assertEqual([r['name'] for r in GOLDEN if r['expect'] == 'pass'][:2], ['good x86_64', 'good aarch64'])

    def test_every_row_gets_its_verdict_from_the_descriptor_rule(self):
        for r in GOLDEN:
            with self.subTest(r['name']):
                self.assertEqual(not fp.descriptor_reasons(r, BOTH), r['expect'] == 'pass', fp.descriptor_reasons(r, BOTH))

    def test_every_row_gets_the_same_verdict_as_the_one_extra_of_a_26_04_leg_of_its_architecture(self):
        for r in GOLDEN:
            arch = 'aarch64' if '/aarch64-linux-gnu/' in r['target'] else 'x86_64'
            with self.subTest(r['name']):
                v = verdict([dict(r, fd=3)], arch=arch)
                self.assertEqual(v.status, 'PASS' if r['expect'] == 'pass' else 'FAIL', v)

    def test_a_refused_row_says_which_fact_it_failed(self):
        self.assertIn('uid is 1000', ' '.join(fp.descriptor_reasons(good(uid=1000), BOTH)))
        self.assertIn('flags', ' '.join(fp.descriptor_reasons(good(flags=0o10000000), BOTH)))
        self.assertIn('is deleted', ' '.join(fp.descriptor_reasons(good(target=X + 'libffi.so.8.1.4 (deleted)'), BOTH)))
        self.assertIn('not an absolute', ' '.join(fp.descriptor_reasons(good(target='libffi.so.8'), BOTH)))
        self.assertIn('not directly in', ' '.join(fp.descriptor_reasons(good(target='/tmp/libffi.so.8'), BOTH)))
        self.assertIn('4 MiB', ' '.join(fp.descriptor_reasons(good(maps_over_cap=True, maps_has_path=False), BOTH)))
        self.assertIn('basename', ' '.join(fp.descriptor_reasons(good(target=X + 'libffi.so'), BOTH)))


class Verdicts(unittest.TestCase):
    def test_the_good_26_04_descriptor_passes_on_both_architectures(self):
        for arch in ('x86_64', 'aarch64'):
            self.assertEqual(verdict([good(arch)], arch=arch).status, 'PASS', arch)

    def test_a_24_04_control_with_zero_extras_passes_on_both_architectures(self):
        for arch in ('x86_64', 'aarch64'):
            self.assertEqual(verdict([], release='24.04', arch=arch).status, 'PASS')

    def test_two_extras_on_26_04_fail_even_when_both_are_good(self):
        v = verdict([good(fd=3), good(fd=4)])
        self.assertEqual(v.status, 'FAIL')
        self.assertIn('2 descriptors', ' '.join(v.reasons))

    def test_zero_extras_on_26_04_fail_as_a_change_to_read(self):
        v = verdict([])
        self.assertEqual(v.status, 'FAIL')
        self.assertIn('no longer leaves one open', ' '.join(v.reasons))

    def test_one_extra_on_a_24_04_control_fails_even_the_good_one(self):
        for arch in ('x86_64', 'aarch64'):
            v = verdict([good(arch)], release='24.04', arch=arch)
            self.assertEqual(v.status, 'FAIL')
            self.assertIn('control leg', ' '.join(v.reasons))

    def test_the_other_architectures_directory_fails_on_each_leg(self):
        self.assertEqual(verdict([good('aarch64')], arch='x86_64').status, 'FAIL')
        self.assertEqual(verdict([good('x86_64')], arch='aarch64').status, 'FAIL')

    def test_a_target_that_is_not_the_plain_directory_slash_name_fails(self):
        for target in (X + '/libffi.so.8', '/usr/lib//x86_64-linux-gnu/libffi.so.8', X[:-1] + '//libffi.so.8'):
            self.assertEqual(verdict([good(target=target)]).status, 'FAIL', target)

    def test_a_good_descriptor_plus_a_pipe_fails(self):
        self.assertEqual(verdict([good(), good(fd=4, type='fifo', target='pipe:[1]')]).status, 'FAIL')

    def test_cloexec_and_the_device_inode_agreement_are_printed_not_judged(self):
        for fdflags in (0, 1):
            for agree in (True, False, None):
                self.assertEqual(verdict([good(fdflags=fdflags, maps_dev_ino_agree=agree)]).status, 'PASS')

    def test_a_python_no_package_owns_fails_even_with_a_good_descriptor(self):
        for owner in (None, ''):
            v = verdict([good()], owner=owner)
            self.assertEqual(v.status, 'FAIL')
            self.assertIn('not owned by a dpkg package', ' '.join(v.reasons))
        self.assertEqual(verdict([], release='24.04', owner=None).status, 'FAIL')

    def test_a_leg_whose_host_is_another_release_or_machine_fails(self):
        self.assertEqual(verdict([good()], host_release='24.04').status, 'FAIL')
        v = verdict([good()], host_arch='aarch64')
        self.assertEqual(v.status, 'FAIL')
        self.assertIn('leg-mismatch', ' '.join(v.reasons))

    def test_unreadable_output_and_unknown_legs_fail(self):
        for bad in (None, {}, {'extras': 'x'}):
            v = fp.judge(bad, expect_release='26.04', expect_arch='x86_64', release='26.04', arch='x86_64', python_owner=OWNER)
            self.assertEqual(v.status, 'FAIL', bad)
        self.assertEqual(verdict([], release='28.04', arch='x86_64').status, 'FAIL')
        self.assertEqual(verdict([good()], arch='riscv64').status, 'FAIL')


def fake_proc(tmp: Path, files: dict, maps_lines):
    """A made-up /proc/self/fd (symlinks named by REAL descriptor numbers) and a made-up maps file."""
    fds = tmp / 'fd'
    fds.mkdir()
    for n, target in files.items():
        os.symlink(target, fds / str(n))
    maps = tmp / 'maps'
    maps.write_text('\n'.join(maps_lines) + '\n')
    return str(fds), str(maps)


class Measure(unittest.TestCase):
    def setUp(self):
        self.ns = {}
        exec(fp.INNER, self.ns)
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.lib = self.tmp.resolve() / 'libffi.so.8.1.4'   # readlink answers the resolved path
        self.lib.write_bytes(b'x')

    def open(self, path, flags=os.O_RDONLY, inheritable=False):
        fd = os.open(path, flags)
        os.set_inheritable(fd, inheritable)
        self.addCleanup(os.close, fd)
        return fd

    def maps_line(self, fd, target):
        st = os.fstat(fd)
        return f'7f0000000000-7f0000001000 r--p 00000000 {os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x} {st.st_ino}      {target}'

    def test_a_read_only_mapped_file_is_reported_with_every_fact(self):
        fd = self.open(self.lib)
        fds, maps = fake_proc(self.tmp, {0: '/dev/null', 1: '/dev/null', fd: str(self.lib)}, [self.maps_line(fd, str(self.lib))])
        (e,) = self.ns['measure'](fds, maps)
        st = os.fstat(fd)
        self.assertEqual((e['fd'], e['target'], e['type'], e['uid'], e['ino']), (fd, str(self.lib), 'regular', st.st_uid, st.st_ino))
        self.assertEqual(e['mode'], format(st.st_mode & 0o7777, '04o'))
        self.assertEqual(e['flags'] & 3, 0)
        self.assertEqual(e['fdflags'], 1)                       # os.open is close-on-exec by default
        self.assertEqual(e['dev'], f'{os.major(st.st_dev)}:{os.minor(st.st_dev)}')
        self.assertTrue(e['maps_has_path'] and e['maps_dev_ino_agree'] and not e['maps_over_cap'])
        self.assertEqual(len(e['maps_lines']), 1)

    def test_descriptors_0_to_2_non_numbers_and_gone_descriptors_are_not_reported(self):
        fd = self.open(self.lib)
        fds, maps = fake_proc(self.tmp, {0: '/dev/null', 1: '/dev/null', 2: '/dev/null', fd: str(self.lib), 99999: '/gone'}, [])
        os.symlink('/x', Path(fds) / 'notanumber')
        self.assertEqual([e['fd'] for e in self.ns['measure'](fds, maps)], [fd])

    def test_the_flags_and_the_inheritable_bit_are_read_from_the_descriptor(self):
        fd = self.open(self.lib, os.O_RDWR, inheritable=True)
        fds, maps = fake_proc(self.tmp, {fd: str(self.lib)}, [])
        (e,) = self.ns['measure'](fds, maps)
        self.assertEqual((e['flags'] & 3, e['fdflags'], e['maps_has_path'], e['maps_dev_ino_agree']), (2, 0, False, None))

    def test_a_maps_line_with_another_device_or_inode_is_found_but_disagrees(self):
        fd = self.open(self.lib)
        st = os.fstat(fd)
        line = f'7f00-7f01 r--p 00000000 {os.major(st.st_dev) ^ 1:02x}:{os.minor(st.st_dev):02x} {st.st_ino}    {self.lib}'
        fds, maps = fake_proc(self.tmp, {fd: str(self.lib)}, [line])
        (e,) = self.ns['measure'](fds, maps)
        self.assertEqual((e['maps_has_path'], e['maps_dev_ino_agree']), (True, False))
        line = f'7f00-7f01 r--p 00000000 {os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x} {st.st_ino + 1}    {self.lib}'
        Path(maps).write_text(line + '\n')
        (e,) = self.ns['measure'](fds, maps)
        self.assertEqual((e['maps_has_path'], e['maps_dev_ino_agree']), (True, False))

    def test_only_a_line_whose_path_is_the_same_string_counts(self):
        fd = self.open(self.lib)
        other = self.maps_line(fd, str(self.lib) + '.bak')
        fds, maps = fake_proc(self.tmp, {fd: str(self.lib)}, [other, self.maps_line(fd, str(self.lib) + ' (deleted)')])
        (e,) = self.ns['measure'](fds, maps)
        self.assertFalse(e['maps_has_path'])

    def test_a_maps_file_over_the_cap_is_reported_as_over_and_names_no_path(self):
        fd = self.open(self.lib)
        fds, maps = fake_proc(self.tmp, {fd: str(self.lib)}, [])
        with open(maps, 'wb') as f:
            f.write(self.maps_line(fd, str(self.lib)).encode() + b'\n' + b'x' * self.ns['CAP'])
        (e,) = self.ns['measure'](fds, maps)
        self.assertTrue(e['maps_over_cap'])
        self.assertFalse(e['maps_has_path'])
        with open(maps, 'wb') as f:   # exactly at the cap is not over it
            line = self.maps_line(fd, str(self.lib)).encode() + b'\n'
            f.write(line + b'x' * (self.ns['CAP'] - len(line)))
        (e,) = self.ns['measure'](fds, maps)
        self.assertFalse(e['maps_over_cap'])

    def test_the_types_are_named(self):
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        d = self.open(self.tmp)
        fds, maps = fake_proc(self.tmp, {r: 'pipe:[1]', d: str(self.tmp)}, [])
        self.assertEqual({e['fd']: e['type'] for e in self.ns['measure'](fds, maps)}, {r: 'fifo', d: 'directory'})

    @unittest.skipUnless(sys.platform.startswith('linux') and Path('/proc/self/maps').exists(), 'needs the Linux /proc')
    def test_on_the_real_kernel_an_inherited_descriptor_is_seen_and_ctypes_adds_what_it_adds(self):
        fd = self.open(self.lib, inheritable=True)
        p = subprocess.run([sys.executable, '-I', '-S', '-c', fp.PROBE_CODE], pass_fds=(fd,), capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(set(data), {'executable', 'version', 'extras'})
        mine = [e for e in data['extras'] if e['target'] == str(self.lib)]
        self.assertEqual(len(mine), 1, data['extras'])
        self.assertEqual((mine[0]['type'], mine[0]['flags'] & 3, mine[0]['fdflags'], mine[0]['maps_has_path']), ('regular', 0, 0, False))
        self.assertTrue(all(e['fd'] > 2 for e in data['extras']))


class ProbeCode(unittest.TestCase):
    def test_ctypes_is_imported_after_every_other_import_and_before_the_measuring(self):
        code = fp.PROBE_CODE
        self.assertEqual(code.count('import ctypes'), 1)
        before, after = code.split('import ctypes')
        self.assertTrue(before.startswith('\nimport fcntl, json, os, stat, sys\n'))
        self.assertNotIn('import', after)
        self.assertIn('measure()', after)
        self.assertEqual(before.count('measure()'), 0)
        compile(code, 'probe', 'exec')


class Fake:
    """A fake runner: the child's JSON and the answers of stat, dpkg-query and dpkg."""
    def __init__(self, extras, child_rc=0, owner=(0, OWNER + '\n'), fs='ext2/ext3\n', stdout=None):
        self.calls = []
        self.extras = extras
        self.child_rc = child_rc
        self.owner = owner
        self.fs = fs
        self.stdout = stdout

    def __call__(self, argv, timeout=60):
        self.calls.append(argv)
        if argv[0] == fp.PYTHON:
            out = self.stdout if self.stdout is not None else json.dumps({'executable': '/usr/bin/python3', 'version': '3.14.4 (main)\n[GCC 15]', 'extras': self.extras})
            return self.child_rc, out + '\n', 'child stderr'
        if argv[0] == 'stat':
            return 0, self.fs, ''
        if argv[0] == 'dpkg-query':
            return 0, 'libffi8:amd64\t3.5.2-1ubuntu1\n', ''
        if argv[0] == 'dpkg':
            return self.owner[0], self.owner[1], ''
        raise AssertionError(argv)


OSREL = {'/etc/os-release': 'NAME="Ubuntu"\nVERSION_ID="26.04"\n', '/proc/self/maps': 'x'}


class Driver(unittest.TestCase):
    def run_probe(self, fake, release='26.04', arch='x86_64', machine='x86_64', osrel=None):
        out = []
        files = dict(OSREL if osrel is None else osrel)
        rc = fp.probe(release, arch, run=fake, read=files.get, machine=machine, out=out.append)
        return rc, out

    def test_a_good_26_04_leg_prints_every_fact_and_passes(self):
        fake = Fake([good(fd=3)])
        rc, out = self.run_probe(fake)
        self.assertEqual(rc, 0, out)
        text = '\n'.join(out)
        for need in ('VERSION_ID=26.04 machine=x86_64', 'sys.executable=/usr/bin/python3', 'sys.version: 3.14.4 (main) [GCC 15]',
                     'dpkg-query -W libffi8: libffi8:amd64 3.5.2-1ubuntu1', 'dpkg -S /usr/bin/python3: ' + OWNER,
                     'beyond 0-2 after `import ctypes`: 1', '"fstype": "ext2/ext3"', '"fdflags": 1', '"maps_dev_ino_agree": true'):
            self.assertIn(need, text)
        self.assertEqual(out[-1], 'fd-probe 26.04/x86_64: PASS')
        self.assertEqual(fake.calls[0], [fp.PYTHON, '-I', '-S', '-c', fp.PROBE_CODE])
        self.assertIn(['stat', '-f', '-c', '%T', '--', '/usr/lib/x86_64-linux-gnu'], fake.calls)
        self.assertIn(['dpkg', '-S', fp.PYTHON], fake.calls)

    def test_a_bad_descriptor_fails_with_the_facts_in_the_log(self):
        rc, out = self.run_probe(Fake([good(fd=3), good(fd=4, uid=1000)]))
        self.assertEqual(rc, 1)
        self.assertTrue(any(x.startswith('::error::2 descriptors') for x in out), out)
        self.assertTrue(out[-1].startswith('fd-probe 26.04/x86_64: FAIL('))

    def test_a_24_04_control_passes_with_none_and_fails_with_one(self):
        osrel = {'/etc/os-release': 'VERSION_ID="24.04"\n', '/proc/self/maps': ''}
        self.assertEqual(self.run_probe(Fake([]), '24.04', osrel=osrel)[0], 0)
        self.assertEqual(self.run_probe(Fake([good()]), '24.04', osrel=osrel)[0], 1)

    def test_a_python_without_a_dpkg_owner_fails(self):
        rc, out = self.run_probe(Fake([good()], owner=(1, '')))
        self.assertEqual(rc, 1)
        self.assertIn('dpkg -S /usr/bin/python3: no owner (exit 1)', out)

    def test_a_child_that_fails_or_prints_garbage_fails_and_shows_its_stderr(self):
        for fake in (Fake([], child_rc=1), Fake([], stdout='not json')):
            rc, out = self.run_probe(fake)
            self.assertEqual(rc, 1)
            self.assertTrue(any('child stderr' in x for x in out), out)

    def test_a_host_that_is_another_release_or_machine_than_the_leg_fails(self):
        self.assertEqual(self.run_probe(Fake([good()]), release='24.04')[0], 1)
        self.assertEqual(self.run_probe(Fake([good('aarch64')]), arch='aarch64', machine='x86_64')[0], 1)
        self.assertEqual(self.run_probe(Fake([good('aarch64')]), arch='aarch64', machine='aarch64')[0], 0)

    def test_no_os_release_or_no_proc_is_refused_not_passed_and_nothing_runs(self):
        for osrel in ({}, {'/etc/os-release': 'VERSION_ID="26.04"\n'}, {'/proc/self/maps': 'x'}):
            fake = Fake([good()])
            rc, out = self.run_probe(fake, osrel=osrel)
            self.assertEqual((rc, out[-1], fake.calls), (2, 'REFUSED', []))

    def test_the_command_line_takes_only_the_four_legs(self):
        for argv in ([], ['--expect-release', '22.04', '--expect-arch', 'x86_64'], ['--expect-release', '26.04', '--expect-arch', 'riscv64']):
            with self.assertRaises(SystemExit):
                with mock.patch('sys.stderr'):
                    fp.main(argv)


class WorkflowShape(unittest.TestCase):
    def test_the_matrix_is_the_four_legs_with_the_controls_first(self):
        legs = re.findall(r"(?m)^          - runner: (\S+)\n            release: '([\d.]+)'\n            arch: (\w+)\n", WF)
        self.assertEqual(legs, [('ubuntu-24.04', '24.04', 'x86_64'), ('ubuntu-24.04-arm', '24.04', 'aarch64'),
                                ('ubuntu-26.04', '26.04', 'x86_64'), ('ubuntu-26.04-arm', '26.04', 'aarch64')])
        self.assertEqual(WF.count('- runner:'), 4)
        self.assertIn('      fail-fast: false\n', WF)

    def test_it_runs_on_its_own_paths_on_dispatch_and_weekly_and_nothing_else(self):
        on = WF.split('\nname: fd-probe\non:\n', 1)[1].split('\npermissions:', 1)[0]
        self.assertEqual(re.findall(r'(?m)^  (\S+):', on), ['pull_request', 'workflow_dispatch', 'schedule'])
        paths = re.findall(r'(?m)^      - (\S+)$', on)
        self.assertEqual(paths, ['.github/workflows/fd-probe.yml', 'tests/fixture/fd_probe.py', 'tests/fixture/fd_golden.json',
                                 'tests/test_fd_probe.py'])
        for p in paths:
            self.assertTrue((ROOT / p).is_file(), p)
        self.assertRegex(on, r"(?m)^    - cron: '\d+ \d+ \* \* \d'$")

    def test_the_token_is_read_only_and_only_the_scheduled_report_job_can_write_issues(self):
        self.assertIn('\npermissions:\n  contents: read\nconcurrency:', WF)
        self.assertEqual(WF.count('issues: write'), 1)
        self.assertEqual(re.findall(r'(?m)^    permissions:\n((?:      .*\n)+)', WF), ['      issues: write\n'])
        self.assertEqual(len(re.findall(r'- cron: ', WF)), 1)
        self.assertEqual(WF.count('permissions:'), 2)
        report = WF.split('\n  report:\n', 1)[1]
        self.assertIn('    permissions:\n      issues: write\n', report)
        self.assertIn("    needs: probe\n    if: failure() && github.event_name == 'schedule'\n", report)
        self.assertNotIn('issues: write', WF.split('\n  report:\n', 1)[0])
        self.assertNotIn('secrets.', WF)

    def test_every_job_has_a_timeout(self):
        self.assertEqual(WF.count('runs-on:'), 2)
        self.assertEqual(WF.count('runs-on:'), WF.count('timeout-minutes:'))
        self.assertIn('    timeout-minutes: 10\n', WF)

    def test_the_actions_are_the_pinned_ones_the_other_workflows_use_and_keep_no_credentials(self):
        uses = re.findall(r'uses: (\S+)', WF)
        self.assertEqual(len(uses), 1)
        for u in uses:
            self.assertRegex(u, r'^actions/checkout@[0-9a-f]{40}$')
            self.assertIn(u, TEST_WF)
        self.assertEqual(WF.count('persist-credentials: false'), WF.count('actions/checkout@'))
        self.assertNotIn('setup-python', WF)   # the probe measures the system Python

    def test_the_probe_runs_the_system_python_isolated_and_no_expression_is_in_a_script(self):
        self.assertIn('run: /usr/bin/python3 -I tests/fixture/fd_probe.py --expect-release "$EXPECT_RELEASE" --expect-arch "$EXPECT_ARCH"', WF)
        for m in re.finditer(r'(?ms)^\s*(?:- )?run:(.*?)(?=^\s*(?:- )?\w[\w-]*:|\Z)', WF):
            self.assertNotIn('${{', m[1])
        self.assertIn('EXPECT_RELEASE: ${{ matrix.release }}', WF)
        self.assertIn('EXPECT_ARCH: ${{ matrix.arch }}', WF)

    def test_the_readme_says_what_it_measures_and_what_it_does_not(self):
        text = ' '.join((ROOT / 'README.md').read_text(encoding='utf-8').split())
        section = text.split('## Descriptor probe (fd-probe)', 1)[1]
        for need in ('ubuntu-26.04-arm', 'fd_golden.json', 'sudo-rs or uutils', 'does not run the private key holder', '`stat -f`'):
            self.assertIn(need, section)


if __name__ == '__main__':
    unittest.main()
