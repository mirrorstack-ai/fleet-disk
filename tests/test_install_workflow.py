"""The signing side of .github/workflows/install.yml, as a whole (AF08): that every file the kit job or a bootstrap verifies under
the baked key is signed by some job of the same workflow (the gap G-AUD-KIT-PIPELINE-1: gateway.json was verified under that key
and signed by nobody), and that the `gwsign` job's two run: blocks do what they say, run for real under bash over a throwaway key
and a local git repository, with tmpfs stood in by a temp dir and base64 -w0 and sha256sum by stand-ins where this machine lacks them.
Its output is then handed to `fleet-kit-upload.py gateway --sig`, the verb the kit job runs. The signature tests are skipped
when ssh-keygen or git is missing. Plain unittest, stdlib only."""
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


if __name__ == '__main__':
    unittest.main()
