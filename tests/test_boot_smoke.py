"""The boot smoke's own tests, offline: the judge that decides a run, the workflow's static rules, and a driver run over the
newest real release folder. The key and TLS tests are skipped when ssh-keygen or openssl is missing."""
from __future__ import annotations

import os
import re
import shutil
import socket
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tests' / 'fixture'))
import make_fixture as mf  # noqa: E402
import smoke_driver as sd  # noqa: E402

TOOLS = bool(shutil.which('ssh-keygen') and shutil.which('openssl')) and os.path.exists(mf.PUB.SSH_KEYGEN)
WF = (ROOT / '.github' / 'workflows' / 'boot-smoke.yml').read_text()
INSTALL = (ROOT / '.github' / 'workflows' / 'install.yml').read_text()
SMOKE = re.search(r'(?ms)^  smoke:\n(.*?)(?=^  [\w-]+:\n|\Z)', INSTALL)[1]   # install.yml's gate: the same smoke over the fleet tip's loaders (AF34)


class Fixture(unittest.TestCase):
    def test_the_dummy_kit_code_is_the_one_the_driver_expects(self):
        self.assertEqual(sd.CODE, mf.CODE)

    def test_the_driver_names_a_download_path_by_its_file(self):
        self.assertEqual(sd.logical('/releases/download/install-20/install.json'), 'install.json')


class Judge(unittest.TestCase):
    SHA, FP = 'a' * 64, 'SHA256:fp'
    CASE = {'id': 'sig-x', 'os': 'sh', 'code': 'sig', 'info': 2, 'serial_line': 'serial 20 valid_until T', 'reqs': ['install.json', 'install.json.sig']}
    OUT = f'bootstrap sha256 {SHA}\nkey SHA256:fp\nREFUSED sig\nThe signature did not verify. Nothing was run.\n'
    LOG = [{'path': f'/releases/download/install-20/{n}', 'status': 302, 'ua': 'curl/8.5', 'tls': 'TLSv1.3'} for n in ('install.json', 'install.json.sig')]

    def judge(self, out=OUT, rc=1, log=LOG, http=(), left=(), case=CASE, mach=None):
        return sd.judge(case, sd.expect(case, mach, True), out, rc, self.SHA, self.FP, list(log), list(http), list(left), False)

    def test_the_right_run_passes_and_each_wrong_one_fails(self):
        self.assertEqual(self.judge(), [])
        self.assertEqual(self.judge(out=self.OUT.replace('\n', '\r\n')), [])  # CRLF and blank lines are stripped first
        bad = {
            'order': self.OUT.replace(f'bootstrap sha256 {self.SHA}\nkey SHA256:fp', f'key SHA256:fp\nbootstrap sha256 {self.SHA}'),
            'trailing line': self.OUT + 'extra\n', 'no sentence': self.OUT.rsplit('\n', 2)[0] + '\n',
            'wrong code': self.OUT.replace('REFUSED sig', 'REFUSED fetch'), 'wrong hash': self.OUT.replace(self.SHA, 'b' * 64),
            'no period': self.OUT.replace('Nothing was run.', 'Nothing was run'), 'lower code line': self.OUT.replace('REFUSED', 'refused')}
        for why, out in bad.items():
            self.assertTrue(self.judge(out=out), why)
        self.assertTrue(self.judge(rc=0))
        self.assertTrue(self.judge(log=self.LOG[:1]))
        self.assertTrue(self.judge(log=[{**self.LOG[0], 'ua': 'Mozilla'}, self.LOG[1]]))
        self.assertTrue(self.judge(log=[{**self.LOG[0], 'tls': 'TLSv1.1'}, self.LOG[1]]))
        self.assertTrue(self.judge(http=[{'path': '/install-20/install.json'}]))
        self.assertEqual(self.judge(http=[{'path': '/ca.crl'}]), [])
        self.assertTrue(self.judge(left=['fleet-boot.abc']))

    def test_a_linux_run_without_kvm_is_judged_by_its_real_output(self):  # the sentence starts with a slash
        good = {'id': 'good-sh', 'os': 'sh', 'code': None, 'info': 3, 'serial_line': 'serial 20 valid_until T', 'reqs': []}
        warn = 'warning: Firecracker supports host kernels 5.10, 6.1 and 6.18; this one is 6.8.0 and the Ubuntu stock kernel is not on that list'
        info = f'bootstrap sha256 {self.SHA}\nkey SHA256:fp\nserial 20 valid_until T\n'
        tail = f'Your code: {sd.CODE}\nREFUSED kvm\n/dev/kvm is missing or not readable and writable by you; send your code to the owner.\n'
        run = lambda out: sd.judge(good, ex, out, 1, self.SHA, self.FP, [], [], [], True)  # noqa: E731
        with mock.patch.object(sd.platform, 'system', return_value='Linux'):
            ex = sd.expect(good, None, False)
            self.assertEqual(ex['code'], 'kvm')
            self.assertEqual(run(info + warn + '\n' + tail), [])
            self.assertTrue(run(info + tail.replace('Your code', 'My code')))  # the code line is still required
            self.assertTrue(run(info + tail + warn + '\n'))  # a warning after the code does not count
            self.assertTrue(run(info + warn + '\n' + tail.replace('send your code to the owner.', 'send your code')))

    def test_expect_follows_the_machine(self):
        good = {**self.CASE, 'code': None, 'info': 3, 'reqs': ['install.json']}
        self.assertEqual(sd.expect(good, 'os', True)['code'], 'os')
        self.assertEqual(sd.expect(good, 'os', True)['reqs'], [])
        self.assertEqual(sd.expect({**good, 'code': 'args', 'info': 0}, 'os', True)['code'], 'args')
        self.assertEqual(sd.expect(good, None, True)['code'], None)
        if sd.platform.system() == 'Linux':
            self.assertEqual(sd.expect(good, None, False), {'code': 'kvm', 'info': 3, 'reqs': ['install.json'], 'show': True})

    def test_a_good_run_needs_its_code_line(self):
        good = {**self.CASE, 'code': None, 'info': 3, 'reqs': []}
        out = f'bootstrap sha256 {self.SHA}\nkey SHA256:fp\nserial 20 valid_until T\nYour code: {sd.CODE}\n'
        self.assertEqual(self.judge(out=out, rc=0, log=[], case=good), [])
        self.assertTrue(self.judge(out=out.replace('Your code', 'My code'), rc=0, log=[], case=good))


class Workflow(unittest.TestCase):
    def test_permissions_secrets_and_triggers(self):
        self.assertRegex(WF, r'(?m)^permissions:\n  contents: read\n')
        self.assertNotRegex(WF, r'(?m)^\s+(contents|id-token|actions|pull-requests|packages): write')
        for bad in ('secrets.', 'pull_request_target', 'actions/cache', 'self-hosted', 'environment:'):
            self.assertNotIn(bad, WF)

    def test_actions_are_sha_pinned_and_checkouts_keep_no_credentials(self):
        uses = re.findall(r'uses: (\S+)', WF)
        self.assertGreaterEqual(len(uses), 6)
        for u in uses:
            self.assertRegex(u, r'^actions/[a-z-]+@[0-9a-f]{40}$')
        self.assertEqual(WF.count('persist-credentials: false'), WF.count('actions/checkout@'))

    def test_every_job_has_a_timeout_and_no_expression_is_in_a_script(self):
        self.assertEqual(WF.count('runs-on:'), WF.count('timeout-minutes:'))
        lines, block = WF.split('\n'), None
        for line in lines:
            ind = len(line) - len(line.lstrip())
            if block is not None and line.strip() and ind <= block:
                block = None
            if block is not None:
                self.assertNotIn('${{', line)
            m = re.match(r'\s*(?:- )?run:(.*)', line)
            if m:
                self.assertNotIn('${{', m[1])
                if m[1].strip() == '|':
                    block = ind
        self.assertIn('${{ matrix.os }}', WF)  # reaches the script only through env:

    def test_the_runner_labels_are_the_designed_ones(self):
        got = set(re.findall(r'runner: ([a-z0-9.-]+)', WF))
        self.assertEqual(got, {'windows-2022', 'windows-2025', 'ubuntu-24.04', 'ubuntu-22.04', 'macos-15'})
        self.assertEqual(WF.count('experimental: true'), 1)
        self.assertEqual(len(re.findall(r'os: ps1', WF)), 2)

    def test_only_the_designed_refusal_may_skip_the_cases(self):  # a machine refusal would otherwise pass every case vacuously
        rows = re.findall(r'runner: ([a-z0-9.-]+),.*?must_run: (true|false)', WF)
        self.assertEqual(sorted(rows), sorted([('windows-2022', 'true'), ('windows-2025', 'true'), ('ubuntu-24.04', 'true'),
                                                ('ubuntu-22.04', 'false'), ('macos-15', 'true'), ('macos-15', 'true')]))
        self.assertIn('--must-run', WF)

    # install.yml's `smoke` job runs the same rows and steps over the loaders of the release tip, before `sign` (AF34)

    @staticmethod
    def smoke_rows(text):
        """(runner, os, trust, must_run) of install.yml's block-style rows."""
        return re.findall(r'(?m)^          - runner: ([\w.-]+)(?: +#.*)?\n            os: (\w+)\n            trust: ([\w-]+)\n            must_run: (true|false)\n', text)

    def test_the_release_gate_runs_the_same_rows_as_the_dispatch_but_the_experimental_one(self):
        gate = self.smoke_rows(SMOKE)
        dispatch = [r for r in re.findall(r'runner: ([a-z0-9.-]+), os: (\w+), trust: ([\w-]+), must_run: (true|false), experimental: (true|false)', WF)
                    if r[4] == 'false']
        self.assertEqual(len(gate), 5)
        self.assertEqual(gate, [r[:4] for r in dispatch])   # a row changed in one file and not the other fails here
        self.assertEqual(SMOKE.count('          - runner:'), len(gate))   # no row in another shape
        self.assertNotIn('experimental', SMOKE)
        self.assertNotIn('keychain', SMOKE)

    def test_only_the_designed_refusal_may_skip_the_cases_in_the_release_gate(self):
        self.assertEqual(sorted((r[0], r[3]) for r in self.smoke_rows(SMOKE)),
                         sorted([('windows-2022', 'true'), ('windows-2025', 'true'), ('ubuntu-24.04', 'true'), ('ubuntu-22.04', 'false'), ('macos-15', 'true')]))
        self.assertEqual(len(re.findall(r'os: ps1', SMOKE)), 2)
        self.assertEqual(set(re.findall(r'runner: ([a-z0-9.-]+)', SMOKE)), {'windows-2022', 'windows-2025', 'ubuntu-24.04', 'ubuntu-22.04', 'macos-15'})
        self.assertIn('[ "$BOOT_MUST" = true ] && flag=(--must-run)', SMOKE)
        self.assertIn('BOOT_MUST: ${{ matrix.must_run }}', SMOKE)
        self.assertIn('--os "$BOOT_OS" "${flag[@]}"', SMOKE)

    def test_the_release_gate_and_the_dispatch_run_the_same_driver_and_trust_steps(self):
        for step in ('python tests/fixture/smoke_driver.py probe', 'python tests/fixture/smoke_driver.py control --dir fixture --phase before',
                     'python tests/fixture/smoke_driver.py control --dir fixture --phase after',
                     'Import-Certificate -FilePath fixture\\tls\\ca.cer -CertStoreLocation Cert:\\LocalMachine\\Root',
                     'sudo cp fixture/tls/ca.crt /usr/local/share/ca-certificates/fleet-smoke.crt && sudo update-ca-certificates',
                     'echo "CURL_CA_BUNDLE=$GITHUB_WORKSPACE/fixture/tls/ca.crt" >> "$GITHUB_ENV"',
                     'python tests/fixture/smoke_driver.py fixture --dir fixture --os "$BOOT_OS" "${flag[@]}"'):
            self.assertIn(step + '\n', WF)   # the whole line: a flag added to one copy is not "the same step"
            self.assertIn(step + '\n', SMOKE)
        for cond in ("if: matrix.trust != 'none'", "if: matrix.trust == 'root-store'", "if: matrix.trust == 'ca-certificates'",
                     "if: matrix.trust == 'curl-ca-bundle'"):
            self.assertIn(cond, SMOKE)
            self.assertIn(cond, WF)
        self.assertEqual(SMOKE.count("if: matrix.trust != 'none'"), 2)   # before and after the trust step

    def test_the_release_gate_builds_the_fixture_from_the_loaders_it_was_handed(self):
        self.assertIn('make_fixture.py --out fixture --ps1 loaders/bootstrap.ps1 --sh loaders/bootstrap.sh', SMOKE)
        self.assertNotIn('--boot-dir', SMOKE)   # the tip's folder is not in this checkout: only the two files cross
        self.assertNotIn('--no-verify', SMOKE)
        self.assertIn('name: loaders', SMOKE)

    def test_the_dispatch_stays_and_keeps_the_experimental_row(self):  # its no-loader failure is pinned by the plan-step tests above
        self.assertIn('workflow_dispatch:', WF)
        self.assertIn('keychain, must_run: true, experimental: true', WF)   # the experimental row stays here, not in the gate

    def test_the_manual_input_is_matched_whole_and_written_without_echo(self):
        plan = WF[WF.index('id: plan'):WF.index('python3 tests/fixture/make_fixture.py')]
        self.assertIn('[[ $dir =~ $re ]]', plan)
        self.assertNotIn('grep', plan)
        self.assertNotIn('echo "dir=', plan)

    def test_the_new_actions_are_the_confirmed_releases(self):
        self.assertIn('upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02  # v4.6.2', WF)
        self.assertIn('download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093  # v4.3.0', WF)

    def plan(self, event, files, boot_dir=''):
        """Runs the plan step's script as Actions runs it (bash -e -o pipefail, only these env vars) in a tree holding `files`:
        (return code, stdout, what it wrote to GITHUB_OUTPUT)."""
        import subprocess
        block = WF.split('      - id: plan\n', 1)[1].split('        run: |\n', 1)[1]
        lines = []
        for l in block.split('\n'):
            if not l.startswith('          '):
                break
            lines.append(l[10:])
        bash = shutil.which('bash')
        if not bash:
            self.skipTest('no bash')
        with tempfile.TemporaryDirectory() as d:
            for f in files:
                os.makedirs(os.path.dirname(os.path.join(d, f)), exist_ok=True)
                open(os.path.join(d, f), 'w').close()
            out = os.path.join(d, 'out')
            r = subprocess.run([bash, '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', '\n'.join(lines)], cwd=d,
                               env={'PATH': os.environ['PATH'], 'BOOT_DIR': boot_dir, 'BOOT_EVENT': event, 'GITHUB_OUTPUT': out},
                               capture_output=True, text=True, timeout=30)
            written = Path(out).read_text() if os.path.exists(out) else ''
        return r.returncode, r.stdout, written, r.stderr

    PAIR = ('bootstrap.ps1', 'bootstrap.sh')

    def test_the_plan_step_runs_as_actions_runs_it(self):  # bash -e -o pipefail: a ref with no release folder must skip, not fail
        for event in ('pull_request', 'push'):
            rc, out, written, err = self.plan(event, ())
            self.assertEqual(rc, 0, err)
            self.assertIn('have=false', written)
            self.assertIn('::notice::', out)
            self.assertNotIn('::error::', out)
        for event in ('pull_request', 'workflow_dispatch'):
            files = [f'release/install-{n}/{b}' for n in (3, 12) for b in self.PAIR]
            rc, out, written, err = self.plan(event, files)
            self.assertEqual(rc, 0, err)
            self.assertIn('dir=release/install-12', written)
            self.assertIn('have=true', written)

    def test_a_dispatch_that_would_run_nothing_fails(self):
        rc, out, written, err = self.plan('workflow_dispatch', ())
        self.assertNotEqual(rc, 0)
        self.assertIn('::error::', out)
        self.assertIn('have=false', written)
        rc, out, written, err = self.plan('workflow_dispatch', (), boot_dir='release/install-9')  # a named folder that is not there
        self.assertNotEqual(rc, 0)
        self.assertIn('::error::', out)

    def test_a_release_folder_that_is_not_a_pair_fails_on_a_pull_request_and_on_a_dispatch(self):
        for event in ('pull_request', 'workflow_dispatch'):
            for only in self.PAIR:
                with self.subTest(event=event, only=only):
                    rc, out, written, err = self.plan(event, [f'release/install-3/{only}'])
                    self.assertNotEqual(rc, 0)
                    self.assertIn('::error::', out)
                    self.assertNotIn('dir=', written)

    def test_a_plain_file_named_like_a_release_folder_is_not_a_folder(self):
        rc, out, written, err = self.plan('pull_request', ['release/install-notes.md'])
        self.assertEqual(rc, 0, err)
        self.assertIn('have=false', written)
        self.assertIn('::notice::', out)
        self.assertNotIn('::error::', out)

    def test_the_event_reaches_the_plan_through_env_only(self):
        self.assertIn('BOOT_EVENT: ${{ github.event_name }}', WF)
        self.assertIn('"$BOOT_EVENT"', WF[WF.index('id: plan'):WF.index('python3 tests/fixture/make_fixture.py')])


@unittest.skipUnless(TOOLS and shutil.which('sh') and shutil.which('curl'), 'ssh-keygen, openssl, sh or curl is missing')
class RealBootstrap(unittest.TestCase):
    def test_the_sh_driver_passes_on_the_newest_release_folder(self):  # skipped until a release/install-* folder is committed
        found = sorted(ROOT.glob('release/install-*'), key=lambda p: int(p.name.split('-')[1]))
        if not found or not (found[-1] / 'bootstrap.sh').is_file() or not (found[-1] / 'bootstrap.ps1').is_file():
            self.skipTest('no release folder yet')
        ports = []
        for _ in range(2):
            with socket.socket() as sk:
                sk.bind(('127.0.0.1', 0))
                ports.append(sk.getsockname()[1])
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / 'z.zip').write_bytes(b'PKfake')
            out = Path(t) / 'fx'
            mf.build(out, found[-1] / 'bootstrap.ps1', found[-1] / 'bootstrap.sh', port=ports[0], crl_port=ports[1], zip_path=Path(t) / 'z.zip')
            with mock.patch.dict(os.environ, {'CURL_CA_BUNDLE': str(out / 'tls' / 'ca.crt')}):
                if sd.main(['control', '--dir', str(out), '--phase', 'after']) != 0:
                    self.skipTest('this curl does not take CURL_CA_BUNDLE')
                self.assertEqual(sd.main(['fixture', '--dir', str(out), '--os', 'sh']), 0)


if __name__ == '__main__':
    unittest.main()
