"""The signing side of .github/workflows/install.yml, as a whole (AF08): that every file the kit job or a bootstrap verifies under
the baked key is signed by some job of the same workflow (the gap G-AUD-KIT-PIPELINE-1: gateway.json was verified under that key
and signed by nobody), and that the `gwsign` job's two run: blocks do what they say, run for real under bash over a throwaway key
and a local git repository, with tmpfs stood in by a temp dir and base64 -w0 and sha256sum by stand-ins where this machine lacks them.
Its output is then handed to `fleet-kit-upload.py gateway --sig`, the verb the kit job runs. The signature tests are skipped
when ssh-keygen or git is missing. The mode `pins` (CV05c, D342) is tested the same two ways: PinsStatic reads the four jobs off the text (who
holds which secret, what runs in which mode, the ctl namespace only) and PinsRuns runs their run: blocks for real, plan to publish, over a
local git repository standing in for the fleet and throwaway keys. Plain unittest, stdlib only."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('fleet_kit_upload', ROOT / 'bin/fleet-kit-upload.py')
fk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fk)
fp = fk.fp

TEXT = (ROOT / '.github/workflows/install.yml').read_text(encoding='utf-8')
JOBS = {m[1]: m[2] for m in re.finditer(r'(?ms)^  ([\w-]+):\n(.*?)(?=^  [\w-]+:\n|\Z)', TEXT.split('\njobs:\n', 1)[1])}
HAVE_TOOLS = os.path.exists(fp.SSH_KEYGEN) and os.path.exists(fp.GIT)
GIT_ENV = {'PATH': '/usr/bin:/bin:/opt/homebrew/bin', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
           'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@x', 'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@x'}
sha = lambda data: hashlib.sha256(data).hexdigest()  # noqa: E731
RECORD = json.dumps({'serial': 3, 'address': '203.0.113.9', 'cert_sha256': 'ab' * 32, 'manifest_key': 'MANIFEST-KEY-WORD',
                     'session_key': 'SESSION-KEY-WORD'}).encode() + b'\n'
PLACEHOLDER = (b'{"serial": 0, "address": null, "cert_sha256": null, "manifest_key": null, "session_key": null, "next": null, '
               b'"r9_closed": false}\n')


def step(job: str, step_id: str) -> str:
    found = re.search(rf'(?ms)^      - id: {step_id}\n(.*?)(?=^      - |\Z)', JOBS[job])
    assert found, f'{job} has no step {step_id}'
    return found[1]


def body(job: str, step_id: str) -> str:
    """The step's run: block, dedented."""
    return '\n'.join(line[10:] for line in step(job, step_id).split('        run: |\n', 1)[1].splitlines()) + '\n'


def keygen(folder: Path, name: str) -> Path:
    key = folder / name
    subprocess.run([fp.SSH_KEYGEN, '-q', '-t', 'ed25519', '-N', '', '-C', 'test', '-f', str(key)], check=True)
    return key


def fingerprint(key: Path) -> str:
    return subprocess.run([fp.SSH_KEYGEN, '-l', '-f', str(key) + '.pub'], capture_output=True, text=True, check=True).stdout.split()[1]


def git(repo: Path, *args: str) -> str:
    return subprocess.run([fp.GIT, '-C', str(repo), *args], env=GIT_ENV, check=True, capture_output=True, text=True).stdout.strip()


class Signs(unittest.TestCase):
    """Which file is signed by whom, read off the workflow's own text."""

    # every file a verifier holds the baked key to, and the namespace it is verified in: install.json by the kit job (signed_manifest)
    # and both bootstraps; kit.json and deploy-pin.json by the bootstraps and the publisher; gateway.json by the kit job (the verb
    # `gateway`) and both bootstraps. A new row here is a new file somebody verifies, and fails below until some job signs it.
    VERIFIED = {'install.json': fp.NS, 'kit.json': fp.PIN_NS, 'deploy-pin.json': fp.PIN_NS, 'gateway.json': fp.PIN_NS}

    def sign_calls(self, name: str, namespace: str) -> list[str]:
        """The jobs of install.yml that sign `name` in `namespace`: a call of the sign function, or an ssh-keygen -Y sign of it."""
        found = []
        for job, text in JOBS.items():
            as_function = re.search(rf'(?m)^ +sign {re.escape(name)} {re.escape(namespace)} ', text)
            direct = re.search(rf'-Y sign -f "\$d/key" -n {re.escape(namespace)} "\$d/{re.escape(name)}"', text)
            if as_function or direct:
                found.append(job)
        return found

    def test_every_file_verified_under_the_baked_key_has_a_sign_call_in_a_job_of_install_yml(self):
        for name, namespace in self.VERIFIED.items():
            with self.subTest(name):
                self.assertNotEqual(self.sign_calls(name, namespace), [], f'{name} is verified under the baked key and no job signs it')
        self.assertEqual(self.sign_calls('gateway.json', fp.PIN_NS), ['gwsign'])   # one job, and not the one holding the install files
        self.assertEqual(self.sign_calls('gateway.json', fp.NS), [])   # and never the install namespace
        self.assertEqual([job for job in JOBS if self.sign_calls('install.json', fp.NS) == [job]], ['sign'])

    def test_the_list_holds_what_the_publisher_signs_and_what_the_kit_verb_reads(self):
        self.assertEqual({name: namespace for _, name, namespace in fp.SIGNED}, {k: v for k, v in self.VERIFIED.items() if k != 'gateway.json'})
        self.assertEqual((fk.GATEWAY_PATH, fk.GATEWAY_SIG_PATH), ('fleet/core/gateway.json', 'fleet/core/gateway.json.sig'))

    def test_a_file_nobody_signs_is_found_by_the_check(self):
        self.assertEqual(self.sign_calls('hosts.json', fp.PIN_NS), [])   # the control: the check can say no
        self.assertEqual(self.sign_calls('gateway.json', 'mirrorstack-fleet-other'), [])


@unittest.skipUnless(HAVE_TOOLS, 'ssh-keygen or git is missing')
class GwsignRuns(unittest.TestCase):
    """The two run: blocks of the job `gwsign`, run for real."""

    @classmethod
    def setUpClass(cls):
        cls.keys = Path(tempfile.mkdtemp(prefix='gwsign-test-keys-'))
        cls.baked, cls.stranger = keygen(cls.keys, 'baked'), keygen(cls.keys, 'stranger')
        cls.pin = fingerprint(cls.baked)
        cls.pub = ' '.join((cls.keys / 'baked.pub').read_text().split()[:2])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.keys, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='gwsign-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.shm, self.runner, self.bin = self.tmp / 'shm', self.tmp / 'runner', self.tmp / 'bin'
        for folder in (self.shm, self.runner, self.bin):
            folder.mkdir()
        # the runner is GNU/Linux with /dev/shm; these give this machine base64 -w0 and sha256sum where it has none
        (self.bin / 'base64').write_text('#!/bin/sh\nif [ "$1" = -w0 ]; then /usr/bin/base64 | tr -d "\\n"; else exec /usr/bin/base64 "$@"; fi\n')
        sum_tool = '/usr/bin/shasum -a 256' if os.path.exists('/usr/bin/shasum') else '/usr/bin/sha256sum'
        (self.bin / 'sha256sum').write_text(f'#!/bin/sh\nexec {sum_tool} "$@"\n')
        for tool in ('base64', 'sha256sum'):
            (self.bin / tool).chmod(0o755)
        self.origin = self.tmp / 'origin'
        self.origin.mkdir()
        git(self.origin, 'init', '-q', '-b', 'release')
        self.out = self.runner / 'out'

    # --- the fetch step, over a local repository standing in for the fleet's release branch

    def commit(self, record: bytes | None = RECORD, sig: bytes | None = b'a signature\n', mode: str = 'file') -> str:
        core = self.origin / 'fleet/core'
        shutil.rmtree(core, ignore_errors=True)
        core.mkdir(parents=True)
        if record is not None:
            if mode == 'symlink':
                (core / 'gateway.json').symlink_to('elsewhere')
            else:
                (core / 'gateway.json').write_bytes(record)
                if mode == 'exec':
                    (core / 'gateway.json').chmod(0o755)
        if sig is not None:
            (core / 'gateway.json.sig').write_bytes(sig)
        git(self.origin, 'add', '-A')
        git(self.origin, 'commit', '-q', '--allow-empty', '-m', 'tip')
        return git(self.origin, 'rev-parse', 'HEAD')

    def fetch(self, tip: str, **over):
        script = body('gwsign', 'fetch')
        self.assertIn('/dev/shm/gwfetch.', script)
        env = {**GIT_ENV, 'HOME': str(self.tmp), 'RUNNER_TEMP': str(self.runner), 'GITHUB_OUTPUT': str(self.out), 'SERIES': 'test',
               'GH_HOSTKEY': 'github.com ssh-ed25519 AAAA', 'FLEET_REPO': self.origin.as_uri(), 'FLEET_READ': 'THROWAWAY-READ-KEY', 'TIP': tip}
        env.update(over)
        done = subprocess.run(['/bin/bash', '-c', script.replace('/dev/shm/', f'{self.shm}/')], env=env, capture_output=True, text=True, cwd=self.tmp)
        self.assertEqual(list(self.shm.iterdir()), [], 'the read key is gone on every path')
        self.assertNotIn('THROWAWAY-READ-KEY', done.stdout + done.stderr)
        return done, self.outputs()

    def outputs(self) -> dict[str, str]:
        return dict(line.split('=', 1) for line in self.out.read_text().splitlines()) if self.out.exists() else {}

    @property
    def record_file(self) -> Path:
        return self.runner / 'gwsign/gateway.json'

    def test_the_fetch_step_keeps_a_live_record_in_the_runner_and_prints_a_size_only(self):
        tip = self.commit()
        done, out = self.fetch(tip)
        self.assertEqual((done.returncode, out), (0, {'live': 'yes'}), done.stdout + done.stderr)
        self.assertEqual(self.record_file.read_bytes(), RECORD)
        self.assertEqual(done.stdout, f'gateway record: {len(RECORD)} bytes\n')
        for word in ('MANIFEST-KEY-WORD', 'SESSION-KEY-WORD', '203.0.113.9'):
            self.assertNotIn(word, done.stdout + done.stderr)

    def test_no_signature_file_at_the_tip_is_not_live_and_nothing_is_kept(self):
        for record in (PLACEHOLDER, RECORD, None):
            with self.subTest(record):
                self.out.unlink(missing_ok=True)
                done, out = self.fetch(self.commit(record, None))
                self.assertEqual((done.returncode, out, done.stdout), (0, {'live': 'no'}, 'SKIP gwsign not-live\n'))
                self.assertFalse(self.record_file.exists())

    def test_a_tip_that_moved_since_the_plan_is_refused(self):
        old = self.commit()
        self.commit(RECORD + b'\n')
        done, out = self.fetch(old)
        self.assertEqual((done.returncode, out, done.stdout), (1, {}, 'REFUSED tip-moved\n'))
        self.assertFalse(self.record_file.exists())

    def test_a_signature_without_a_record_or_a_record_that_is_not_a_small_regular_file_is_refused(self):
        for what, kw in (('no record', {'record': None}), ('an empty record', {'record': b''}),
                         ('one byte over the cap', {'record': b'x' * 65537}), ('a symlink', {'mode': 'symlink'}),
                         ('an executable', {'mode': 'exec'})):
            with self.subTest(what):
                self.out.unlink(missing_ok=True)
                done, out = self.fetch(self.commit(**kw))
                self.assertEqual((done.returncode, out, done.stdout), (1, {}, 'REFUSED gateway\n'), what)
                self.assertFalse(self.record_file.exists())
        done, out = self.fetch(self.commit(RECORD.rstrip(b'\n').ljust(65536)))   # the cap itself is taken: the host takes 65536 bytes (a record padded to it: a body must name the record's keys, below)
        self.assertEqual((done.returncode, out), (0, {'live': 'yes'}))
        self.assertEqual(len(self.record_file.read_bytes()), 65536)

    def test_a_body_that_is_not_a_gateway_record_is_refused_and_not_kept(self):
        """Review of AF08, P1: the pin namespace is shared with kit.json and deploy-pin.json, so the job must not sign any file at that path."""
        keys = ('serial', 'address', 'cert_sha256', 'manifest_key', 'session_key')
        whole = json.loads(RECORD)
        bodies = [('another document', b'{"not": "a gateway", "kit": "anything the tip holds"}\n'), ('plain text', b'hello\n'),
                  ('the kit record shape', json.dumps({'serial': 3, 'files': {}}).encode() + b'\n')]
        bodies += [(f'a record without {k}', json.dumps({a: b for a, b in whole.items() if a != k}).encode() + b'\n') for k in keys]
        for what, record in bodies:
            with self.subTest(what):
                self.out.unlink(missing_ok=True)
                done, out = self.fetch(self.commit(record))
                self.assertEqual((done.returncode, out, done.stdout), (1, {}, 'REFUSED gateway\n'), what)
                self.assertFalse(self.record_file.exists())
                self.assertFalse(self.record_file.parent.exists())
        self.out.unlink(missing_ok=True)
        done, out = self.fetch(self.commit(PLACEHOLDER))   # control: the check can say yes; the placeholder names all five keys
        self.assertEqual((done.returncode, out), (0, {'live': 'yes'}))

    def test_a_tip_that_is_not_a_full_lower_case_sha_is_refused_before_anything_is_read(self):
        tip = self.commit()
        for bad in ('', tip[:12], tip.upper(), 'release', tip + ' x', '$(id)'):
            with self.subTest(bad):
                done, out = self.fetch(bad)
                self.assertEqual((done.returncode, out, done.stdout), (1, {}, 'REFUSED gateway tip\n'))

    def test_a_release_series_run_signs_nothing_and_keeps_nothing(self):
        done, out = self.fetch(self.commit(), SERIES='release')
        self.assertEqual((done.returncode, out, done.stdout), (0, {'live': 'no'}, 'SKIP gwsign series\n'))
        self.assertFalse(self.record_file.exists())
        done, out = self.fetch(self.commit(), SERIES='')
        self.assertEqual((done.returncode, done.stdout), (0, 'SKIP gwsign series\n'))   # only the word `test` signs

    # --- the sign step, then the kit verb on what it made

    def sign(self, key: Path | None = None, **over):
        script = body('gwsign', 'sign')
        self.assertIn('/dev/shm/gwsign.', script)
        key = key or self.baked
        env = {'PATH': f'{self.bin}:/usr/bin:/bin', 'HOME': str(self.tmp), 'RUNNER_TEMP': str(self.runner), 'GITHUB_OUTPUT': str(self.out),
               'SERIES': 'test', 'KEY_SHA256': self.pin, 'SIGN_KEY': key.read_text()}
        env.update(over)
        done = subprocess.run(['/bin/bash', '-c', script.replace('/dev/shm/', f'{self.shm}/')], env=env, capture_output=True, text=True, cwd=self.tmp)
        self.assertEqual(list(self.shm.iterdir()), [], 'the key is gone on every path')
        secret = key.read_text().splitlines()[1]
        self.assertNotIn(secret, done.stdout + done.stderr + (self.out.read_text() if self.out.exists() else ''))
        return done, self.outputs()

    def place(self, record: bytes = RECORD) -> None:
        self.record_file.parent.mkdir(exist_ok=True)
        self.record_file.write_bytes(record)

    def kit_check(self, sig: Path, pub_line: str | None = None, record: bytes = RECORD, **kw):
        """`gateway --check --owner-pub P --sig FILE` over a fleet tip that holds the record and no signature of its own."""
        git(self.origin, 'rm', '-rq', '--ignore-unmatch', 'fleet')
        core = self.origin / 'fleet/core'
        core.mkdir(parents=True, exist_ok=True)
        (core / 'gateway.json').write_bytes(record)
        git(self.origin, 'add', '-A')
        git(self.origin, 'commit', '-q', '--allow-empty', '-m', 'tip')
        pub = self.tmp / 'owner.pub'
        pub.write_text((pub_line or self.pub) + '\n')
        env = {'KIT_HOST': 'kit.example.org', 'RUNNER_TEMP': str(self.runner), 'FLEET_REPO': self.origin.as_uri(), 'PATH': os.environ['PATH'],
               'OWNER_PIN_SHA256': self.pin, **kw}
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = fk.main(['x', 'gateway', '--check', '--owner-pub', str(pub), '--sig', str(sig)], env)
        return code, out.getvalue()

    def test_the_sign_step_signs_the_record_in_the_pin_namespace_and_the_kit_verb_takes_it(self):
        self.place()
        done, out = self.sign()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(set(out), {'gateway_sig'})
        self.assertEqual(done.stdout, f'signed gateway.json: {len(RECORD)} bytes, sha256 {sha(RECORD)}, key {self.pin}\n')
        for word in ('MANIFEST-KEY-WORD', 'SESSION-KEY-WORD', '203.0.113.9'):
            self.assertNotIn(word, done.stdout + done.stderr + json.dumps(out))   # not a byte of the record is printed or handed on
        self.assertFalse(self.record_file.parent.exists())   # the record's copy goes with the key
        sig = self.tmp / 'gateway.json.sig'
        sig.write_bytes(base64.b64decode(out['gateway_sig']))
        self.assertEqual(self.kit_check(sig), (0, 'OK gateway-check serial=3\n'))   # what the kit job runs
        allowed = self.tmp / 'allowed'
        for namespace, good in ((fp.PIN_NS, True), (fp.NS, False)):
            allowed.write_text(f'owner namespaces="{namespace}" {self.pub}\n')
            ok = subprocess.run([fp.SSH_KEYGEN, '-Y', 'verify', '-f', str(allowed), '-I', 'owner', '-n', namespace, '-s', str(sig)],
                                input=RECORD, capture_output=True)
            self.assertEqual(ok.returncode == 0, good, namespace)
        self.assertEqual(self.kit_check(sig, record=RECORD + b' '), (1, 'REFUSED sig\n'))   # another record is not covered

    def test_the_sign_step_in_a_release_series_run_or_with_another_key_signs_nothing(self):
        for want, over in (('REFUSED series', {'SERIES': 'release'}), ('REFUSED series', {'SERIES': ''}), ('REFUSED key', {'key': self.stranger}),
                           ('REFUSED key-not-set', {'KEY_SHA256': 'SHA256:NOT-SET-fill-in-after-keygen'})):
            self.place()   # a refused run removes the record with the key, so each starts from a fresh one
            done, out = self.sign(**over)
            self.assertEqual((done.returncode, out, done.stdout), (1, {}, want + '\n'), over)
        self.place()
        done, out = self.sign(SIGN_KEY='not a key\n')
        self.assertNotEqual(done.returncode, 0)   # ssh-keygen cannot read it: set -e stops the step before anything is signed
        self.assertEqual(out, {})

    def test_the_sign_step_refuses_a_record_that_is_missing_empty_over_the_cap_or_a_link(self):
        done, out = self.sign()   # nothing placed
        self.assertEqual((done.returncode, out, done.stdout), (1, {}, 'REFUSED gateway\n'))
        for what, record in (('empty', b''), ('over the cap', b'x' * 65537)):
            self.place(record)
            done, out = self.sign()
            self.assertEqual((done.returncode, out, done.stdout), (1, {}, 'REFUSED gateway\n'), what)
        (self.runner / 'gwsign').mkdir(exist_ok=True)
        self.record_file.unlink(missing_ok=True)
        self.record_file.symlink_to(self.tmp / 'elsewhere')
        done, out = self.sign()
        self.assertEqual((done.returncode, out, done.stdout), (1, {}, 'REFUSED gateway\n'), 'a symlink')

    def test_a_verify_that_fails_stops_the_sign_step_before_a_signature_is_handed_on(self):
        """Review of AF08 (mutant X10: `|| true` after -Y verify survived): a shim stands in for ssh-keygen and fails on -Y verify."""
        self.place()
        shim = self.tmp / 'ssh-keygen-shim'
        shim.write_text(f'#!/bin/sh\ncase "$*" in *"-Y verify"*) exit 1;; esac\nexec {fp.SSH_KEYGEN} "$@"\n')
        shim.chmod(0o755)
        script = body('gwsign', 'sign').replace('/usr/bin/ssh-keygen', str(shim)).replace('/dev/shm/', f'{self.shm}/')
        self.assertEqual(script.count(str(shim)), 4)   # the four calls: -l, -y, -Y sign, -Y verify
        env = {'PATH': f'{self.bin}:/usr/bin:/bin', 'HOME': str(self.tmp), 'RUNNER_TEMP': str(self.runner), 'GITHUB_OUTPUT': str(self.out),
               'SERIES': 'test', 'KEY_SHA256': self.pin, 'SIGN_KEY': self.baked.read_text()}
        done = subprocess.run(['/bin/bash', '-c', script], env=env, capture_output=True, text=True, cwd=self.tmp)
        self.assertNotEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(self.outputs(), {})   # no gateway_sig
        self.assertNotIn('signed gateway.json', done.stdout)
        self.assertEqual(list(self.shm.iterdir()), [])
        # control: the same shim, passing -Y verify through, lets the step finish, so the failure above is the verify's
        shim.write_text(f'#!/bin/sh\nexec {fp.SSH_KEYGEN} "$@"\n')
        self.place()
        done = subprocess.run(['/bin/bash', '-c', script], env=env, capture_output=True, text=True, cwd=self.tmp)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(set(self.outputs()), {'gateway_sig'})

    def test_the_two_steps_in_a_row_over_one_tip_make_a_signature_the_kit_verb_takes(self):
        tip = self.commit()
        self.assertEqual(self.fetch(tip)[0].returncode, 0)
        done, out = self.sign()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        sig = self.tmp / 'gateway.json.sig'
        sig.write_bytes(base64.b64decode(out['gateway_sig']))
        self.assertEqual(self.kit_check(sig, record=RECORD), (0, 'OK gateway-check serial=3\n'))



# ---------------------------------------------------------------------------------------------------------------------------------
# mode pins (CV05c, D342): plan, approve, sign, publish

CTL = 'mirrorstack-fleet-ctl'  # a literal on purpose: a changed namespace in the workflow must fail here
PINS_JOBS = ['pins-plan', 'pins-approve', 'pins-sign', 'pins-publish']
PIN_PATHS = ('fleet/hosts.json', 'fleet/core/gateway.json', 'fleet/core/work-pin.json', 'fleet/core/deploy-pin.json', 'fleet/core/proven.json')
PINS_PLACE = {
    'fleet/hosts.json': b'{"serial": 0, "hosts": []}\n',
    'fleet/core/gateway.json': PLACEHOLDER,
    'fleet/core/work-pin.json': b'{"serial": 0, "pins": [], "sub": null}\n',
    'fleet/core/deploy-pin.json': b'{"serial": 0, "head": null}\n',
    'fleet/core/proven.json': b'{"serial": 0, "digests": {}}\n'}


def job_header(name: str) -> str:
    return JOBS[name].split('    steps:')[0]


def reachable(mode: str) -> set[str]:
    """The jobs that can run in a dispatch of `mode`, from each job's `if:` and `needs:` read off the text. A tiny evaluator: the
    ref is taken as release, a needed job that can run is taken as succeeded, a series output as unknown (true), and any other token
    in an `if:` fails the test, so an expression this does not understand is never read as false."""
    memo: dict[str, bool] = {}

    def run(name: str) -> bool:
        if name not in memo:
            memo[name] = False
            text = JOBS[name]
            needs = re.search(r'(?m)^    needs: \[?([\w, -]+?)\]?$', text)
            needs = [n.strip() for n in needs[1].split(',')] if needs else []
            cond = re.search(r'(?m)^    if: (.*)$', text)[1].strip()
            cond = cond[3:-2].strip() if cond.startswith('${{') else cond
            status = any(w in cond for w in ('always()', '!cancelled()', 'failure()'))
            if needs and not status and not all(run(n) for n in needs):
                return False
            py = re.sub(r"inputs\.mode == '(\w+)'", lambda m: str(m[1] == mode), cond)
            py = re.sub(r"github\.ref == '[^']*'", 'True', py)
            py = re.sub(r"needs\.([\w-]+)\.result == '(\w+)'", lambda m: str(run(m[1]) if m[2] == 'success' else not run(m[1])), py)
            py = re.sub(r"needs\.[\w-]+\.outputs\.series == '\w+'", 'True', py)
            py = py.replace('!cancelled()', 'True').replace('&&', ' and ').replace('||', ' or ')
            assert re.fullmatch(r'[TrueFalsndo() ]+', py), f'{name}: the evaluator does not understand {cond!r} ({py!r})'
            memo[name] = bool(eval(py))  # noqa: S307 - only True, False, and, or and brackets got through the check above
        return memo[name]

    return {name for name in JOBS if run(name)}


class PinsStatic(unittest.TestCase):
    """The four jobs of mode pins, read off the workflow text."""

    def test_pins_is_a_choice_and_the_four_jobs_follow_the_old_ones_each_guarded_by_ref_and_mode(self):
        self.assertRegex(TEXT, r'(?m)^        options: \[sign, pubkey, floor, untag, pins\]\n        default: sign\n')
        self.assertEqual(list(JOBS)[-4:], PINS_JOBS)
        for name in PINS_JOBS:
            cond = re.search(r'(?m)^    if: (.*)$', job_header(name))[1]
            self.assertIn("github.ref == 'refs/heads/release'", cond, name)
            self.assertIn("inputs.mode == 'pins'", cond, name)
        self.assertEqual({n: re.findall(r'(?m)^    environment: (\S+)$', JOBS[n]) for n in PINS_JOBS},
                         {'pins-plan': ['release'], 'pins-approve': ['kit-floor'], 'pins-sign': ['release'], 'pins-publish': []})

    def test_no_job_but_the_pins_jobs_is_reachable_in_mode_pins_and_no_pins_job_in_another_mode(self):
        self.assertEqual(reachable('pins'), set(PINS_JOBS))
        for mode in ('sign', 'pubkey', 'floor', 'untag'):
            self.assertEqual(reachable(mode) & set(PINS_JOBS), set(), mode)
        # the controls: the evaluator can say yes, and the old modes still reach their old jobs
        self.assertEqual(reachable('pubkey'), {'sign'})
        self.assertEqual(reachable('floor'), {'floor-approve', 'floor'})
        self.assertEqual(reachable('untag'), {'untag-check', 'untag-approve', 'untag'})
        self.assertEqual(reachable('sign'), set(JOBS) - set(PINS_JOBS) - {'floor-approve', 'floor', 'untag-check', 'untag-approve', 'untag'})

    def test_pins_sign_waits_for_the_approval_in_a_release_series_run_and_skips_it_only_in_the_test_series(self):
        cond = re.search(r'(?m)^    if: (.*)$', job_header('pins-sign'))[1]
        self.assertIn("needs.pins-plan.result == 'success'", cond)
        self.assertIn("(needs.pins-approve.result == 'success' || (needs.pins-approve.result == 'skipped' && needs.pins-plan.outputs.series == 'test'))", cond)
        self.assertRegex(job_header('pins-sign'), r'(?m)^    needs: \[pins-plan, pins-approve\]$')
        approve = re.search(r'(?m)^    if: (.*)$', job_header('pins-approve'))[1]
        self.assertIn("needs.pins-plan.outputs.series == 'release'", approve)
        self.assertRegex(job_header('pins-publish'), r'(?m)^    needs: \[pins-plan, pins-sign\]$')
        self.assertNotIn('!cancelled()', re.search(r'(?m)^    if: (.*)$', job_header('pins-publish'))[1])  # a failed signer never reaches the upload

    def test_pins_sign_runs_no_action_no_checkout_no_repository_code_and_holds_a_job_token_of_nothing(self):
        job = JOBS['pins-sign']
        for bad in ('uses:', 'checkout', 'python', 'RUNNER_WORKSPACE', 'GITHUB_WORKSPACE', 'github.token', 'bin/fleet', 'vendor/', '/tmp'):
            self.assertNotIn(bad, job)
        self.assertIn('    permissions: {}\n', job)
        self.assertEqual(re.findall(r'secrets\.(\w+)', step('pins-sign', 'fetch')), ['FLEET_READ'])  # the fetch step reads the fleet, signs nothing
        self.assertEqual(re.findall(r'secrets\.(\w+)', step('pins-sign', 'sign')), ['SIGN_KEY'])  # the sign step holds the key and no fleet access
        for bad in ('git ', 'ssh ', 'curl', 'FLEET_READ', 'GIT_SSH_COMMAND'):
            self.assertNotIn(bad, body('pins-sign', 'sign'), bad)

    def test_pins_sign_signs_in_the_ctl_namespace_only_after_the_fingerprint_check(self):
        sign = body('pins-sign', 'sign')
        for need in ('/dev/shm/pinsign.', 'umask 077', 'shred -u', 'REFUSED key-not-set', 'set -euo pipefail', '[ "$fp" = "$KEY_SHA256" ] ||'):
            self.assertIn(need, sign)
        self.assertEqual(re.findall(r'namespaces="([^"]*)"', JOBS['pins-sign']), [CTL])
        calls = [line for line in sign.splitlines() if '-Y ' in line]
        self.assertEqual(len(calls), 2)   # the one -Y sign and the one -Y verify
        for line in calls:
            self.assertIn(f' -n {CTL} ', line)
        self.assertEqual(sign.count('-Y sign'), 1)
        self.assertEqual(sign.count('-Y verify'), 1)
        self.assertNotIn('mirrorstack-fleet-pin', JOBS['pins-sign'])
        self.assertNotIn('mirrorstack-fleet-install', JOBS['pins-sign'])
        self.assertLess(sign.index('[ "$fp" = "$KEY_SHA256" ]'), sign.index('-Y sign'))
        self.assertLess(sign.index('printf \'%s\\n\' "$SIGN_KEY"'), sign.index('-Y sign'))
        self.assertIn('sha256sum "$d/body"', sign)

    def test_the_jobs_pass_each_file_its_own_signature_and_every_job_reads_the_plan_output_it_names(self):
        """Review of CV05c: the run tests give each step its own env, so the job-level `env:` and `outputs:` wiring between the jobs ran nowhere."""
        names = ('hosts', 'gateway', 'work_pin', 'deploy_pin', 'proven')
        for i, n in enumerate(names, 1):
            self.assertIn(f'      {n}_sig: ${{{{ steps.sign.outputs.{n}_sig }}}}\n', JOBS['pins-sign'], n)
            self.assertIn(f'          SIG_{i}: ${{{{ needs.pins-sign.outputs.{n}_sig }}}}\n', JOBS['pins-publish'], n)
        self.assertEqual(JOBS['pins-publish'].count('needs.pins-sign.outputs.'), 7)   # five signatures, the key line and its fingerprint
        self.assertEqual(JOBS['pins-sign'].count('          MANIFEST: ${{ needs.pins-plan.outputs.manifest }}\n'), 2)   # fetch and sign
        for job in ('pins-sign', 'pins-publish', 'pins-approve'):
            self.assertIn('          TIP: ${{ needs.pins-plan.outputs.tip }}\n', JOBS[job], job)

    def test_pins_plan_holds_the_read_key_and_never_the_signing_key_and_the_others_hold_no_secret(self):
        self.assertEqual(re.findall(r'secrets\.(\w+)', JOBS['pins-plan']), ['FLEET_READ'])
        self.assertNotIn('SIGN_KEY', JOBS['pins-plan'])
        for name in ('pins-approve', 'pins-publish'):
            self.assertNotIn('secrets.', JOBS[name], name)
            self.assertNotIn('SIGN_KEY', JOBS[name], name)
        self.assertIn('    permissions: {}\n', JOBS['pins-approve'])
        self.assertIn('    permissions:\n      contents: read\n', JOBS['pins-publish'])
        self.assertIn('    permissions:\n      contents: read\n', JOBS['pins-plan'])
        self.assertIn('/dev/shm/pinsplan.', body('pins-plan', 'plan'))
        self.assertLess(body('pins-plan', 'plan').index("trap 'shred"), body('pins-plan', 'plan').index('"$FLEET_READ"'))  # trap before key
        self.assertIn('"$d/pub"', body('pins-plan', 'plan'))  # the planner is given the public line only

    def test_pins_publish_uploads_one_artifact_named_pins_sigs_for_a_day_with_the_pinned_action(self):
        job = JOBS['pins-publish']
        self.assertEqual(re.findall(r'uses: (\S+)', job), ['actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'])
        for need in ('name: pins-sigs', 'retention-days: 1', 'if-no-files-found: error', 'pins/pins-sigs.json'):
            self.assertIn(need, job)
        self.assertNotIn('checkout', job)

    def test_the_readme_names_the_mode_its_four_jobs_the_artifact_and_the_namespace(self):
        readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        section = readme.split("## The control VM's pin files: mode pins", 1)[1].split('\n## ', 1)[0]
        for need in ('`mode` pins', '**pins-plan**', '**pins-approve**', '**pins-sign**', '**pins-publish**', CTL,
                     '`pins-sigs`', '`KEY_PUB`', '`kit-floor`', 'land PR', 'CV05f', 'ssh-keygen -Y verify -n mirrorstack-fleet-ctl'):
            self.assertIn(need, section)
        self.assertIn('`mode` pins', readme.split('Seven jobs run in order', 1)[0])   # named where the modes are listed

    def test_the_key_pub_constant_is_the_line_of_the_key_fingerprint(self):
        env = dict(re.findall(r'(?m)^  ([A-Z_0-9]+): (.*)$', TEXT.split('\njobs:\n', 1)[0].split('\nenv:\n', 1)[1]))
        self.assertEqual(env['KEY_SHA256'], 'SHA256:16jB0ih9afmAW7rFmgTJVtarDgEv4w/DHA8LKufWhKM')
        if not HAVE_TOOLS:
            self.skipTest('ssh-keygen is missing')
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'pub').write_text(env['KEY_PUB'] + '\n')
            line = subprocess.run([fp.SSH_KEYGEN, '-l', '-f', f'{tmp}/pub'], capture_output=True, text=True, check=True).stdout.split()
        self.assertEqual(line[1], env['KEY_SHA256'])


def fake_output(path: Path) -> dict[str, str]:
    """A GITHUB_OUTPUT file: `k=v` lines and `k<<DELIM` blocks."""
    out, lines = {}, path.read_text().split('\n') if path.exists() else []
    i = 0
    while i < len(lines):
        if '<<' in lines[i] and '=' not in lines[i].split('<<')[0]:
            key, delim = lines[i].split('<<', 1)
            j = lines.index(delim, i + 1)
            out[key] = '\n'.join(lines[i + 1:j])
            i = j
        elif lines[i]:
            k, v = lines[i].split('=', 1)
            out[k] = v
        i += 1
    return out


@unittest.skipUnless(HAVE_TOOLS, 'ssh-keygen or git is missing')
class PinsRuns(unittest.TestCase):
    """The run: blocks of the four pins jobs, run for real under bash over a local git repository standing in for the fleet."""

    @classmethod
    def setUpClass(cls):
        cls.keys = Path(tempfile.mkdtemp(prefix='pins-test-keys-'))
        cls.baked, cls.stranger = keygen(cls.keys, 'baked'), keygen(cls.keys, 'stranger')
        cls.pin = fingerprint(cls.baked)
        cls.pub = ' '.join((cls.keys / 'baked.pub').read_text().split()[:2])
        cls.stranger_pub = ' '.join((cls.keys / 'stranger.pub').read_text().split()[:2])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.keys, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='pins-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.shm, self.runner, self.bin, self.origin = (self.tmp / n for n in ('shm', 'runner', 'bin', 'origin'))
        for folder in (self.shm, self.runner, self.bin, self.origin):
            folder.mkdir()
        (self.bin / 'base64').write_text('#!/bin/sh\nif [ "$1" = -w0 ]; then /usr/bin/base64 | tr -d "\\n"; else exec /usr/bin/base64 "$@"; fi\n')
        sum_tool = '/usr/bin/shasum -a 256' if os.path.exists('/usr/bin/shasum') else '/usr/bin/sha256sum'
        (self.bin / 'sha256sum').write_text(f'#!/bin/sh\nexec {sum_tool} "$@"\n')
        (self.bin / 'python3').symlink_to(__import__('sys').executable)
        for tool in ('base64', 'sha256sum'):
            (self.bin / tool).chmod(0o755)
        git(self.origin, 'init', '-q', '-b', 'main')
        self.out, self.summary = self.runner / 'out', self.runner / 'summary'

    # --- a fleet repository: main and release, the five files

    def commit(self, files: dict[str, bytes | None] | None = None, branch: str = 'release', mode: str = 'file') -> str:
        """Writes `files` (None removes) on top of the placeholders, commits on `branch`, returns its sha."""
        git(self.origin, 'checkout', '-q', '-B', branch)
        for path, data in {**PINS_PLACE, **(files or {})}.items():
            target = self.origin / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.unlink(missing_ok=True)
            if data is None:
                continue
            if mode == 'symlink' and path.endswith('gateway.json'):
                target.symlink_to('elsewhere')
            else:
                target.write_bytes(data)
                if mode == 'exec' and path.endswith('gateway.json'):
                    target.chmod(0o755)
        git(self.origin, 'add', '-A')
        git(self.origin, 'commit', '-q', '--allow-empty', '-m', 'tip')
        return git(self.origin, 'rev-parse', 'HEAD')

    @staticmethod
    def manifest(files: dict[str, bytes] | None = None, actions: dict[str, str] | None = None, serial: int = 0) -> str:
        bodies = {**PINS_PLACE, **(files or {})}
        return '\n'.join(f'{p} {sha(bodies[p])} {serial} {(actions or {}).get(p, "sign")}' for p in PIN_PATHS)

    def run_step(self, job: str, step_id: str, env: dict[str, str], **kw):
        script = body(job, step_id).replace('/dev/shm/', f'{self.shm}/')
        base = {'PATH': f'{self.bin}:/usr/bin:/bin', 'HOME': str(self.tmp), 'RUNNER_TEMP': str(self.runner), 'GITHUB_OUTPUT': str(self.out),
                'GITHUB_STEP_SUMMARY': str(self.summary), 'GITHUB_RUN_ID': '4242', 'SERIES': 'test', 'KEY_SHA256': self.pin, 'KEY_PUB': self.pub,
                'GH_HOSTKEY': 'github.com ssh-ed25519 AAAA', 'FLEET_REPO': str(self.origin), **{k: v for k, v in GIT_ENV.items() if k.startswith('GIT_')}}
        base.update(env)
        done = subprocess.run(['/bin/bash', '-c', script], env=base, capture_output=True, text=True, cwd=kw.get('cwd', self.tmp))
        self.assertEqual(list(self.shm.iterdir()), [], 'the key is gone on every path')
        return done, fake_output(self.out)

    def clear(self):
        self.out.unlink(missing_ok=True)

    # --- pins-plan, over the real planner

    def plan(self, **over):
        env = {'FLEET_READ': 'THROWAWAY-READ-KEY'}
        env.update(over)
        done, out = self.run_step('pins-plan', 'plan', env, cwd=ROOT)
        self.assertNotIn('THROWAWAY-READ-KEY', done.stdout + done.stderr)
        return done, out

    def test_the_plan_step_runs_the_planner_and_outputs_the_tip_the_series_the_head_and_five_rows(self):
        self.commit(branch='main')
        tip = self.commit()
        done, out = self.plan()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(set(out), {'tip', 'series', 'deploy_head', 'manifest'})
        self.assertEqual((out['tip'], out['series'], out['deploy_head']), (tip, 'test', 'null'))
        self.assertEqual(out['manifest'], self.manifest())   # all placeholders: nothing signed before, so all five sign at serial 0
        self.assertIn(f'tip {tip}\n', done.stdout)   # the tip is printed
        self.assertIn('## Control VM pins plan', self.summary.read_text())

    def test_the_plan_step_refuses_a_key_line_of_another_key_a_series_that_is_neither_and_a_planner_refusal(self):
        self.commit(branch='main')
        self.commit()
        for want, over in (('REFUSED key-pub', {'KEY_PUB': self.stranger_pub}), ('REFUSED series', {'SERIES': ''}), ('REFUSED series', {'SERIES': 'Release'})):
            self.clear()
            done, out = self.plan(**over)
            self.assertEqual((done.returncode, out, done.stdout), (1, {}, want + '\n'), over)
        self.commit({'fleet/hosts.json': b'{"serial": "x", "hosts": []}\n'})
        done, out = self.plan()
        self.assertEqual((done.returncode, out), (1, {}))
        self.assertIn('REFUSED shape fleet/hosts.json', done.stdout + done.stderr)   # the planner's word reaches the log; nothing is output
        self.assertNotIn('REFUSED manifest', done.stdout + done.stderr)   # and it is the planner's refusal that stops the step, not a later check

    def test_the_plan_step_refuses_a_manifest_that_is_not_the_five_rows_in_order_whatever_the_planner_says(self):
        """The step re-reads what the planner printed before it hands it on (a stand-in planner here, a real git clone for the head)."""
        self.commit(branch='main')
        tip = self.commit()
        stub = self.tmp / 'stub'
        (stub / 'bin').mkdir(parents=True)
        (stub / 'bin/fleet-pins-plan.py').write_text(
            'import os, subprocess, sys\n'
            'if sys.argv[1] == "clone":\n    subprocess.run(["git", "clone", "-q", sys.argv[2], sys.argv[3]], check=True)\n'
            'else:\n    sys.stdout.write(open(os.environ["STUB_MANIFEST"]).read())\n')
        rows = self.manifest().split('\n')
        head = f'tip {tip}\nrun 4242\n'
        cases = {'rows swapped': [rows[1], rows[0], *rows[2:]], 'a sixth row': rows + [rows[0]], 'four rows': rows[:4],
                 'a path of another file': [rows[0].replace('hosts', 'other'), *rows[1:]], 'a short sha': [rows[0].replace(sha(PINS_PLACE[PIN_PATHS[0]]), 'ab'), *rows[1:]],
                 'an unknown action': [rows[0].replace(' sign', ' maybe'), *rows[1:]], 'a field more': [rows[0] + ' x', *rows[1:]]}
        for what, lines in [('control: the five rows', rows), *cases.items()]:
            with self.subTest(what):
                self.clear()
                shutil.rmtree(self.runner / 'fleet', ignore_errors=True)
                (self.tmp / 'm').write_text(head + '\n'.join(lines) + '\n')
                script = body('pins-plan', 'plan').replace('/dev/shm/', f'{self.shm}/')
                env = {'PATH': f'{self.bin}:/usr/bin:/bin', 'HOME': str(self.tmp), 'RUNNER_TEMP': str(self.runner), 'GITHUB_OUTPUT': str(self.out),
                       'GITHUB_STEP_SUMMARY': str(self.summary), 'GITHUB_RUN_ID': '4242', 'SERIES': 'test', 'KEY_SHA256': self.pin, 'KEY_PUB': self.pub,
                       'GH_HOSTKEY': 'x', 'FLEET_REPO': str(self.origin), 'FLEET_READ': 'K', 'STUB_MANIFEST': str(self.tmp / 'm'),
                       **{k: v for k, v in GIT_ENV.items() if k.startswith('GIT_')}}
                done = subprocess.run(['/bin/bash', '-c', script], env=env, capture_output=True, text=True, cwd=stub)
                if what.startswith('control'):
                    self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                else:
                    self.assertEqual((done.returncode, fake_output(self.out), done.stdout), (1, {}, 'REFUSED manifest\n'))

    # --- pins-approve

    def approve(self, **over):
        env = {'TIP': 'a' * 40, 'MANIFEST': self.manifest(), 'DEPLOY_HEAD': 'null'}
        env.update(over)
        return self.run_step('pins-approve', 'approve', env)[0]

    def test_the_approve_step_prints_each_file_with_serial_sha256_action_and_the_deploy_head(self):
        done = self.approve(DEPLOY_HEAD='b' * 40)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, f'plan for approval in kit-floor (nothing is approved by this line): sign the control VM pins at fleet release tip {"a" * 40}\n{self.manifest()}\ndeploy-pin head: {"b" * 40}\n')

    def test_the_approve_step_refuses_a_manifest_tip_or_head_that_is_not_what_the_plan_prints(self):
        good = self.manifest().split('\n')
        bad = {'a missing row': '\n'.join(good[:4]), 'an extra row': '\n'.join(good + [good[0]]), 'rows out of order': '\n'.join([good[1], good[0], *good[2:]]),
               'a short sha': good[0].replace(sha(PINS_PLACE[PIN_PATHS[0]]), 'ab') + '\n' + '\n'.join(good[1:]),
               'a field more': good[0] + ' x\n' + '\n'.join(good[1:]), 'an unknown action': good[0].replace(' sign', ' maybe') + '\n' + '\n'.join(good[1:]),
               'an empty one': '', 'a workflow command': '::add-mask::x\n' + '\n'.join(good[1:]), 'a leading zero serial': good[0].replace(' 0 ', ' 01 ') + '\n' + '\n'.join(good[1:])}
        for what, text in bad.items():
            with self.subTest(what):
                done = self.approve(MANIFEST=text)
                self.assertEqual((done.returncode, done.stdout), (1, 'REFUSED manifest\n'))
        for over, want in (({'TIP': 'a' * 12}, 'REFUSED tip'), ({'TIP': 'A' * 40}, 'REFUSED tip'), ({'DEPLOY_HEAD': 'main'}, 'REFUSED head'), ({'DEPLOY_HEAD': ''}, 'REFUSED head')):
            done = self.approve(**over)
            self.assertEqual((done.returncode, done.stdout), (1, want + '\n'), over)

    # --- pins-sign, fetch

    @property
    def signdir(self) -> Path:
        return self.runner / 'pinsign'

    def fetch(self, tip: str, manifest: str | None = None, **over):
        shutil.rmtree(self.signdir, ignore_errors=True)   # a runner starts without the folder; one that is there is refused (mkdir)
        env = {'FLEET_READ': 'THROWAWAY-READ-KEY', 'TIP': tip, 'MANIFEST': self.manifest() if manifest is None else manifest}
        env.update(over)
        done, out = self.run_step('pins-sign', 'fetch', env)
        self.assertNotIn('THROWAWAY-READ-KEY', done.stdout + done.stderr)
        return done

    def test_the_fetch_step_keeps_the_planned_files_by_row_number_and_prints_no_value(self):
        hosts = b'{"serial": 4, "hosts": [{"id": "HOST-ID-WORD", "owner": "OWNER-WORD"}]}\n'
        tip = self.commit({'fleet/hosts.json': hosts})
        done = self.fetch(tip, self.manifest({'fleet/hosts.json': hosts}, {'fleet/core/proven.json': 'keep'}, serial=4))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(sorted(p.name for p in self.signdir.iterdir()), ['1', '2', '3', '4'])   # the keep row (proven.json, row 5) is not read
        self.assertEqual((self.signdir / '1').read_bytes(), hosts)
        for word in ('HOST-ID-WORD', 'OWNER-WORD'):
            self.assertNotIn(word, done.stdout + done.stderr)
        self.assertEqual(done.stdout.count('planned fleet/'), 4)

    def test_the_fetch_step_refuses_a_tip_that_moved_and_a_body_that_is_not_the_planned_one_and_keeps_nothing(self):
        old = self.commit()
        new = self.commit({'fleet/core/work-pin.json': b'{"serial": 1, "pins": [], "sub": null}\n'})
        done = self.fetch(old)
        self.assertEqual((done.returncode, done.stdout), (1, 'REFUSED tip-moved\n'))
        self.assertFalse(self.signdir.exists())
        done = self.fetch(new)   # the plan judged the placeholder work-pin; the tip holds another body
        self.assertEqual(done.returncode, 1)
        self.assertTrue(done.stdout.endswith('REFUSED hash fleet/core/work-pin.json\n'), done.stdout)
        self.assertFalse(self.signdir.exists())   # a refused run leaves no file behind

    def test_the_fetch_step_refuses_a_file_that_is_missing_empty_over_the_cap_a_link_or_executable(self):
        for what, files, mode in (('missing', {'fleet/core/gateway.json': None}, 'file'), ('empty', {'fleet/core/gateway.json': b''}, 'file'),
                                  ('over the cap', {'fleet/core/gateway.json': b'x' * (1 << 20 | 1)}, 'file'), ('a symlink', {}, 'symlink'), ('executable', {}, 'exec')):
            with self.subTest(what):
                tip = self.commit(files, mode=mode)
                done = self.fetch(tip, self.manifest(files and {k: v for k, v in files.items() if v is not None}))
                self.assertEqual((done.returncode, done.stdout.splitlines()[-1]), (1, 'REFUSED pins fleet/core/gateway.json'))
                self.assertFalse(self.signdir.exists())

    def test_the_fetch_step_refuses_a_tip_or_a_manifest_that_is_malformed_before_it_reads_anything(self):
        tip = self.commit()
        for bad in ('', tip[:12], tip.upper(), 'release', '$(id)'):
            done = self.fetch(bad)
            self.assertEqual((done.returncode, done.stdout), (1, 'REFUSED pins tip\n'), bad)
        good = self.manifest().split('\n')
        for what, text in (('four rows', '\n'.join(good[:4])), ('a path swapped', good[0].replace('hosts', 'other') + '\n' + '\n'.join(good[1:])),
                           ('a traversal', good[0].replace('fleet/hosts.json', '../x') + '\n' + '\n'.join(good[1:]))):
            done = self.fetch(tip, text)
            self.assertEqual((done.returncode, done.stdout), (1, 'REFUSED manifest\n'), what)
        self.assertFalse(self.signdir.exists())

    def test_the_fetch_step_checks_a_deploy_head_is_an_ancestor_of_the_tip_and_takes_null(self):
        base = self.commit()
        side = self.commit(branch='side')   # a commit the release branch never carried
        git(self.origin, 'checkout', '-q', 'release')
        for what, head, ok in (('an ancestor', base, True), ('a commit off the release branch', side, False), ('null', None, True)):
            with self.subTest(what):
                body_ = (b'{"serial": 1, "head": null}\n' if head is None else
                         json.dumps({'serial': 1, 'head': head, 'tree': 'c' * 40}).encode() + b'\n')
                tip = self.commit({'fleet/core/deploy-pin.json': body_}, branch='release')
                done = self.fetch(tip, self.manifest({'fleet/core/deploy-pin.json': body_}, serial=1))
                self.assertEqual(done.returncode == 0, ok, done.stdout + done.stderr)
                if not ok:
                    self.assertEqual(done.stdout.splitlines()[-1], 'REFUSED head')
                    self.assertFalse(self.signdir.exists())
        # a keep row is never read, so its head is not judged here
        done = self.fetch(tip, self.manifest({'fleet/core/deploy-pin.json': body_}, {'fleet/core/deploy-pin.json': 'keep'}, serial=1))
        self.assertEqual(done.returncode, 0)
        # a body that does not name its head the one way this reads it is refused, not guessed at
        for what, odd in (('no head', b'{"serial": 1}\n'), ('two heads', b'{"head": null, "serial": 1, "x": {"head": null}}\n'),
                          ('a short head', b'{"serial": 1, "head": "abc"}\n')):
            tip = self.commit({'fleet/core/deploy-pin.json': odd}, branch='release')
            done = self.fetch(tip, self.manifest({'fleet/core/deploy-pin.json': odd}, serial=1))
            self.assertEqual((done.returncode, done.stdout.splitlines()[-1]), (1, 'REFUSED head'), what)

    # --- pins-sign, sign

    def place(self, files: dict[str, bytes] | None = None, rows: tuple[int, ...] = (1, 2, 3, 4, 5)) -> dict[str, bytes]:
        bodies = {**PINS_PLACE, **(files or {})}
        self.signdir.mkdir(exist_ok=True)
        for i in rows:
            (self.signdir / str(i)).write_bytes(bodies[PIN_PATHS[i - 1]])
        return bodies

    def sign(self, key: Path | None = None, manifest: str | None = None, **over):
        key = key or self.baked
        env = {'SIGN_KEY': key.read_text(), 'MANIFEST': self.manifest() if manifest is None else manifest}
        env.update(over)
        done, out = self.run_step('pins-sign', 'sign', env)
        secret = key.read_text().splitlines()[1]
        self.assertNotIn(secret, done.stdout + done.stderr + (self.out.read_text() if self.out.exists() else ''))
        return done, out

    def verifies(self, data: bytes, sig_b64: str, namespace: str, pub: str | None = None) -> bool:
        sig, allowed = self.tmp / 'x.sig', self.tmp / 'allowed'
        sig.write_bytes(base64.b64decode(sig_b64))
        allowed.write_text(f'owner namespaces="{namespace}" {pub or self.pub}\n')
        return subprocess.run([fp.SSH_KEYGEN, '-Y', 'verify', '-f', str(allowed), '-I', 'owner', '-n', namespace, '-s', str(sig)],
                              input=data, capture_output=True).returncode == 0

    def test_the_sign_step_signs_each_planned_file_in_the_ctl_namespace_and_in_no_other(self):
        bodies = self.place()
        done, out = self.sign()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(set(out), {'hosts_sig', 'gateway_sig', 'work_pin_sig', 'deploy_pin_sig', 'proven_sig', 'pub', 'fp'})
        self.assertEqual((out['pub'], out['fp']), (self.pub, self.pin))
        for name, path in zip(('hosts', 'gateway', 'work_pin', 'deploy_pin', 'proven'), PIN_PATHS):
            with self.subTest(path):
                self.assertTrue(self.verifies(bodies[path], out[f'{name}_sig'], CTL))
                for other in (fp.PIN_NS, fp.NS):   # a carrier's namespace never takes it, nor the install one
                    self.assertFalse(self.verifies(bodies[path], out[f'{name}_sig'], other), other)
                self.assertFalse(self.verifies(bodies[path] + b' ', out[f'{name}_sig'], CTL))   # another body is not covered
        self.assertEqual(done.stdout.count('signed fleet/'), 5)
        self.assertTrue(done.stdout.endswith(f'signed with key {self.pin}\n'))
        self.assertFalse(self.signdir.exists())   # the copies go with the key

    def test_the_sign_step_signs_only_the_sign_rows_and_a_keep_row_gets_no_signature(self):
        self.place(rows=(1, 3))
        self.clear()
        done, out = self.sign(manifest=self.manifest(actions={p: 'keep' for p in PIN_PATHS if p not in (PIN_PATHS[0], PIN_PATHS[2])}))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(set(out), {'hosts_sig', 'work_pin_sig', 'pub', 'fp'})
        self.clear()
        self.assertEqual(self.sign(manifest=self.manifest(actions={p: 'keep' for p in PIN_PATHS}))[1], {'pub': self.pub, 'fp': self.pin})   # nothing to sign: the key is still proved

    def test_the_sign_step_with_another_key_or_no_pinned_fingerprint_signs_nothing(self):
        for want, over in (('REFUSED key', {'key': self.stranger}), ('REFUSED key-not-set', {'KEY_SHA256': 'SHA256:NOT-SET-fill-in-after-keygen'})):
            self.place()
            done, out = self.sign(**over)
            self.assertEqual((done.returncode, out, done.stdout), (1, {}, want + '\n'), over)
            self.assertFalse(self.signdir.exists())
        self.place()
        done, out = self.sign(SIGN_KEY='not a key\n')
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(out, {})

    def test_the_sign_step_refuses_a_file_that_is_not_the_planned_one_or_not_a_plain_file(self):
        self.place({'fleet/core/work-pin.json': b'{"serial": 0, "pins": [{}], "sub": null}\n'})
        done, out = self.sign()
        self.assertEqual((done.returncode, out, done.stdout.splitlines()[-1]), (1, {}, 'REFUSED hash fleet/core/work-pin.json'))
        self.place(rows=(1, 2, 3, 5))   # row 4 missing
        done, out = self.sign()
        self.assertEqual((done.returncode, done.stdout.splitlines()[-1]), (1, 'REFUSED pins fleet/core/deploy-pin.json'))
        self.place(rows=(1, 2, 3, 5))
        (self.tmp / 'elsewhere').write_bytes(PINS_PLACE[PIN_PATHS[3]])   # a link to a file that exists and holds the planned bytes: only the link test refuses it
        (self.signdir / '4').symlink_to(self.tmp / 'elsewhere')
        done, out = self.sign()
        self.assertEqual((done.returncode, done.stdout.splitlines()[-1]), (1, 'REFUSED pins fleet/core/deploy-pin.json'))
        self.assertEqual(self.sign(manifest='x')[0].stdout, 'REFUSED manifest\n')
        self.assertEqual(self.sign(manifest=self.manifest().replace(' sign', ' maybe', 1))[0].stdout, 'REFUSED manifest\n')

    def test_a_verify_that_fails_stops_the_sign_step_before_a_signature_is_handed_on(self):
        self.place()
        shim = self.tmp / 'ssh-keygen-shim'
        shim.write_text(f'#!/bin/sh\ncase "$*" in *"-Y verify"*) exit 1;; esac\nexec {fp.SSH_KEYGEN} "$@"\n')
        shim.chmod(0o755)
        script = body('pins-sign', 'sign').replace('/usr/bin/ssh-keygen', str(shim)).replace('/dev/shm/', f'{self.shm}/')
        self.assertEqual(script.count(str(shim)), 4)   # -l, -y, -Y sign, -Y verify
        env = {'PATH': f'{self.bin}:/usr/bin:/bin', 'HOME': str(self.tmp), 'RUNNER_TEMP': str(self.runner), 'GITHUB_OUTPUT': str(self.out), 'SERIES': 'test',
               'KEY_SHA256': self.pin, 'SIGN_KEY': self.baked.read_text(), 'MANIFEST': self.manifest()}
        done = subprocess.run(['/bin/bash', '-c', script], env=env, capture_output=True, text=True, cwd=self.tmp)
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(fake_output(self.out), {})
        self.assertEqual(list(self.shm.iterdir()), [])
        shim.write_text(f'#!/bin/sh\nexec {fp.SSH_KEYGEN} "$@"\n')   # control: the shim passing -Y verify through lets it finish
        self.place()
        done = subprocess.run(['/bin/bash', '-c', script], env=env, capture_output=True, text=True, cwd=self.tmp)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_a_file_that_changes_while_it_is_signed_stops_the_sign_step_and_hands_nothing_on(self):
        """Review of CV05c: the re-hash after the signature (`REFUSED changed`) had no test; a shim appends a byte on -Y verify."""
        self.place()
        shim = self.tmp / 'ssh-keygen-shim'
        shim.write_text(f'#!/bin/sh\n{fp.SSH_KEYGEN} "$@" || exit $?\n'
                        'case "$*" in *"-Y verify"*) printf x >> "$(dirname "$(echo "$*" | sed \'s/.*-s //;s/ .*//\')")/body";; esac\n')
        shim.chmod(0o755)
        script = body('pins-sign', 'sign').replace('/usr/bin/ssh-keygen', str(shim)).replace('/dev/shm/', f'{self.shm}/')
        env = {'PATH': f'{self.bin}:/usr/bin:/bin', 'HOME': str(self.tmp), 'RUNNER_TEMP': str(self.runner), 'GITHUB_OUTPUT': str(self.out), 'SERIES': 'test',
               'KEY_SHA256': self.pin, 'SIGN_KEY': self.baked.read_text(), 'MANIFEST': self.manifest()}
        done = subprocess.run(['/bin/bash', '-c', script], env=env, capture_output=True, text=True, cwd=self.tmp)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertTrue(done.stdout.endswith('REFUSED changed fleet/hosts.json\n'), done.stdout)
        self.assertEqual(fake_output(self.out), {})
        self.assertEqual(list(self.shm.iterdir()), [])

    # --- pins-publish

    def publish(self, signed: dict[str, str] | None = None, **over):
        signed = signed if signed is not None else {}
        env = {'TIP': 'a' * 40, 'MANIFEST': self.manifest(), 'PUB': self.pub, 'FP': self.pin,
               **{f'SIG_{i}': signed.get(path, '') for i, path in enumerate(PIN_PATHS, 1)}}
        env.update(over)
        return self.run_step('pins-publish', 'publish', env)[0]

    def real_sigs(self) -> dict[str, str]:
        self.place()
        done, out = self.sign()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.clear()
        return {path: out[f'{n}_sig'] for n, path in zip(('hosts', 'gateway', 'work_pin', 'deploy_pin', 'proven'), PIN_PATHS)}

    @property
    def sigs_file(self) -> Path:
        return self.runner / 'pins/pins-sigs.json'

    def test_the_publish_step_writes_pins_sigs_json_of_tip_run_fingerprint_pub_and_the_signed_entries(self):
        sigs = self.real_sigs()
        done = self.publish(sigs, TIP='d' * 40)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        doc = json.loads(self.sigs_file.read_text())
        self.assertEqual(set(doc), {'tip', 'run', 'fingerprint', 'pub', 'entries'})
        self.assertEqual((doc['tip'], doc['run'], doc['fingerprint'], doc['pub']), ('d' * 40, '4242', self.pin, self.pub))
        self.assertEqual(doc['entries'], [{'path': p, 'sha256': sha(PINS_PLACE[p]), 'serial': 0, 'sig_b64': sigs[p]} for p in PIN_PATHS])
        self.assertEqual(sorted(path.name for path in self.sigs_file.parent.iterdir()), ['pins-sigs.json'])   # the key line file is not left for the upload
        for entry in doc['entries']:   # what the land tool checks: the signature is the key's, in the ctl namespace, over those bytes
            self.assertTrue(self.verifies(PINS_PLACE[entry['path']], entry['sig_b64'], CTL, doc['pub']))
        # a keep row has no entry and no signature
        self.runner.joinpath('pins').rename(self.tmp / 'moved')
        done = self.publish({PIN_PATHS[0]: sigs[PIN_PATHS[0]]}, MANIFEST=self.manifest(actions={p: 'keep' for p in PIN_PATHS[1:]}))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual([e['path'] for e in json.loads(self.sigs_file.read_text())['entries']], [PIN_PATHS[0]])

    def test_the_publish_step_refuses_a_signature_that_is_missing_not_base64_not_an_ssh_signature_or_on_a_keep_row(self):
        sigs = self.real_sigs()
        cases = {'a missing signature': {**sigs, PIN_PATHS[1]: ''}, 'not base64': {**sigs, PIN_PATHS[1]: 'not base64!'},
                 'not an ssh signature': {**sigs, PIN_PATHS[1]: base64.b64encode(b'hello').decode()},
                 'over 4 KiB': {**sigs, PIN_PATHS[1]: base64.b64encode(b'-----BEGIN SSH SIGNATURE-----' + b'x' * 4100).decode()}}
        for what, signed in cases.items():
            with self.subTest(what):
                shutil.rmtree(self.runner / 'pins', ignore_errors=True)
                done = self.publish(signed)
                self.assertEqual(done.returncode, 1)
                self.assertTrue(done.stderr.strip().startswith('REFUSED sig'), done.stderr)
                self.assertFalse(self.sigs_file.exists())
        shutil.rmtree(self.runner / 'pins', ignore_errors=True)
        done = self.publish(sigs, MANIFEST=self.manifest(actions={PIN_PATHS[2]: 'keep'}))   # a signature for a row the plan kept
        self.assertEqual((done.returncode, done.stderr.strip()), (1, f'REFUSED sig {PIN_PATHS[2]}'))

    def test_the_publish_step_refuses_a_key_that_is_not_the_pinned_one_or_a_manifest_or_tip_that_is_malformed(self):
        sigs = self.real_sigs()
        for what, over in (('another fingerprint', {'FP': 'SHA256:' + 'A' * 43}), ('a pub of another key', {'PUB': self.stranger_pub}),
                           ('a consistent pair of another key', {'PUB': self.stranger_pub, 'FP': fingerprint(self.stranger)}),
                           ('a pub that is not one line', {'PUB': self.pub + '\nx'}), ('a short tip', {'TIP': 'a' * 12}),
                           ('a manifest of four rows', {'MANIFEST': '\n'.join(self.manifest().split('\n')[:4])})):
            with self.subTest(what):
                shutil.rmtree(self.runner / 'pins', ignore_errors=True)
                done = self.publish(sigs, **over)
                self.assertEqual(done.returncode, 1, done.stdout)
                self.assertFalse(self.sigs_file.exists())

    # --- plan to publish in a row, the whole of mode pins over one fleet

    def test_the_four_jobs_in_a_row_over_one_fleet_make_signatures_a_root_verifies_in_the_ctl_namespace(self):
        self.commit(branch='main')
        tip = self.commit()
        done, planned = self.plan()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.clear()
        self.assertEqual(self.approve(TIP=planned['tip'], MANIFEST=planned['manifest'], DEPLOY_HEAD=planned['deploy_head']).returncode, 0)
        done = self.fetch(planned['tip'], planned['manifest'])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        done, signed = self.sign(manifest=planned['manifest'])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.clear()
        done = self.run_step('pins-publish', 'publish', {'TIP': tip, 'MANIFEST': planned['manifest'], 'PUB': signed['pub'], 'FP': signed['fp'],
                                                         **{f'SIG_{i}': signed[f'{n}_sig'] for i, n in enumerate(('hosts', 'gateway', 'work_pin', 'deploy_pin', 'proven'), 1)}})[0]
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        doc = json.loads(self.sigs_file.read_text())
        self.assertEqual((doc['tip'], doc['fingerprint']), (tip, self.pin))
        for entry in doc['entries']:
            data = subprocess.run([fp.GIT, '-C', str(self.origin), 'show', f'{tip}:{entry["path"]}'], env=GIT_ENV, capture_output=True, check=True).stdout
            self.assertEqual(sha(data), entry['sha256'])
            self.assertTrue(self.verifies(data, entry['sig_b64'], CTL, doc['pub']), entry['path'])
            self.assertFalse(self.verifies(data, entry['sig_b64'], fp.PIN_NS, doc['pub']), entry['path'])


if __name__ == '__main__':
    unittest.main()
