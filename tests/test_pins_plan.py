"""bin/fleet-pins-plan.py (CV05b, D342): the control VM's pin files judged before CI signs them, over real git repositories
in temp folders and a throwaway ed25519 key (built at run time). One table per rule: shapes, keep or sign, the serial from
the last commit that touched the .sig, deploy-pin's head rules (attack M2, M7, M8), hosts and work-pin semantics (M5), nothing
printed that is a value (M3), the clone fallback. Skipped when git or ssh-keygen is missing. Plain unittest, stdlib only."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('fleet_pins_plan', ROOT / 'bin/fleet-pins-plan.py')
pp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pp)

HAVE_TOOLS = os.path.exists(pp.GIT) and os.path.exists(pp.SSH_KEYGEN)
GIT_ENV = {'PATH': '/usr/bin:/bin:/opt/homebrew/bin', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_TERMINAL_PROMPT': '0', 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@x', 'GIT_COMMITTER_NAME': 't',
           'GIT_COMMITTER_EMAIL': 't@x'}
FLEET_HEAD = '754265e031aef3cf12b5767336569b234a1d7294'  # the fleet main vendor/pin-summary.py was copied at
PLACE = {
    'fleet/hosts.json': b'{"serial": 0, "hosts": []}\n',
    'fleet/core/gateway.json': b'{"serial": 0, "address": null, "cert_sha256": null, "manifest_key": null, '
                               b'"session_key": null, "next": null, "r9_closed": false}\n',
    'fleet/core/work-pin.json': b'{"serial": 0, "pins": [], "sub": null}\n',
    'fleet/core/deploy-pin.json': b'{"serial": 0, "head": null}\n',
    'fleet/core/proven.json': b'{"serial": 0, "digests": {}}\n'}
HOSTS, GATEWAY, WORK, DEPLOY, PROVEN = pp.FILES
MODEL = b"SIG_NS = {'pin': 'mirrorstack-fleet-pin', " + pp.CTL_TEXT + b"}\n"
J = lambda doc: json.dumps(doc).encode() + b'\n'  # noqa: E731


def keygen(folder: Path, name: str) -> Path:
    key = folder / name
    subprocess.run([pp.SSH_KEYGEN, '-q', '-t', 'ed25519', '-N', '', '-C', 'test', '-f', str(key)], check=True)
    return key


@unittest.skipUnless(HAVE_TOOLS, 'ssh-keygen or git is missing')
class Plans(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = Path(tempfile.mkdtemp(prefix='pins-plan-keys-'))
        cls.key, cls.other = keygen(cls.keys, 'ci'), keygen(cls.keys, 'other')
        cls.pub = str(cls.key) + '.pub'
        cls.publine = Path(cls.pub).read_text().split()[1]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.keys, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='pins-plan-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = self.tmp / 'fleet'
        self.repo.mkdir()
        self.git('init', '-q', '-b', 'main')
        self.commit({'fleet/slot/model.py': MODEL, **PLACE})
        self.release()

    def git(self, *args: str) -> str:
        return subprocess.run([pp.GIT, '-C', str(self.repo), *args], env=GIT_ENV, check=True, capture_output=True,
                              text=True).stdout.strip()

    def commit(self, files: dict[str, bytes], rm: tuple[str, ...] = ()) -> str:
        for path, data in files.items():
            (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / path).write_bytes(data)
        if files:
            self.git('add', '--', *files)
        if rm:
            self.git('rm', '-q', '--', *rm)
        self.git('commit', '-q', '--allow-empty', '-m', 'c')
        return self.git('rev-parse', 'HEAD')

    def release(self) -> str:
        self.git('branch', '-f', 'release', 'main')
        return self.git('rev-parse', 'release')

    def sig(self, body: bytes, ns: str = pp.NS, key: Path | None = None) -> bytes:
        f = self.tmp / 'body'
        f.write_bytes(body)
        f.with_name('body.sig').unlink(missing_ok=True)  # ssh-keygen asks before it overwrites
        subprocess.run([pp.SSH_KEYGEN, '-Y', 'sign', '-q', '-f', str(key or self.key), '-n', ns, str(f)], check=True)
        return (self.tmp / 'body.sig').read_bytes()

    def sign_set(self, bodies: dict[str, bytes] | None = None, **kw) -> str:
        """Commit bodies (default the placeholders) with their sigs, and release."""
        bodies = bodies or PLACE
        self.commit({**bodies, **{f'{p}.sig': self.sig(b, **kw) for p, b in bodies.items()}})
        return self.release()

    def plan(self, *extra: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = pp.main(['p', 'plan', '--repo', str(self.repo), '--pub', self.pub, '--release', 'release',
                            '--main', 'main', '--run-id', '77', *extra])
        return code, out.getvalue(), err.getvalue()

    def rows(self, out: str) -> dict[str, tuple[str, str]]:
        return {w[0]: (w[2], w[3]) for w in (line.split() for line in out.splitlines()) if w[0].startswith('fleet/')}

    def refused(self, word: str, path: str, *extra: str) -> None:
        code, out, err = self.plan(*extra)
        self.assertEqual((code, out, err), (1, '', f'REFUSED {word} {path}\n'))

    def with_body(self, path: str, body: bytes) -> None:
        self.commit({path: body})
        self.release()

    # ---- keep or sign

    def test_placeholders_at_serial_zero_are_signed_and_the_output_names_the_tip_and_run(self):
        code, out, _ = self.plan()
        self.assertEqual(code, 0)
        self.assertEqual(out.splitlines()[:2], [f'tip {self.git("rev-parse", "release")}', 'run 77'])
        self.assertEqual(self.rows(out), {p: ('0', 'sign') for p in pp.FILES})  # M8: the null-head deploy-pin too
        digest = hashlib.sha256(PLACE[HOSTS]).hexdigest()
        self.assertIn(f'{HOSTS} {digest} 0 sign\n', out)

    def test_an_unchanged_body_with_a_valid_ctl_sig_is_kept_and_another_namespace_or_key_is_unsigned(self):
        self.sign_set()
        self.assertEqual(self.rows(self.plan()[1]), {p: ('0', 'keep') for p in pp.FILES})
        for label, change in (('pin namespace', {'ns': 'mirrorstack-fleet-pin'}), ('other key', {'key': self.other})):
            with self.subTest(label):  # the same bytes may be signed again at their own serial (key switch)
                self.sign_set(**change)
                self.assertEqual(self.rows(self.plan()[1]), {p: ('0', 'sign') for p in pp.FILES})

    def test_serial_equal_or_below_the_previous_signed_one_is_refused(self):
        self.sign_set({PROVEN: J({'serial': 2, 'digests': {}})})
        for serial, floor in ((2, 3), (1, 1)):
            self.with_body(PROVEN, J({'serial': serial, 'digests': {}, 'wire_floor': floor}))
            self.refused('serial', PROVEN)
        self.with_body(PROVEN, J({'serial': 3, 'digests': {}}))
        code, out, err = self.plan()
        self.assertEqual((code, self.rows(out)[PROVEN]), (0, ('3', 'sign')))
        self.assertIn(f'{PROVEN} sha256=', err)
        self.assertIn('(was 2) changed: serial', err)

    def test_a_body_edited_after_its_sig_uses_the_older_serial(self):
        self.sign_set({PROVEN: J({'serial': 2, 'digests': {}})})
        self.with_body(PROVEN, J({'serial': 9, 'digests': {}}))  # never signed
        self.with_body(PROVEN, J({'serial': 3, 'digests': {}}))
        self.assertEqual(self.rows(self.plan()[1])[PROVEN], ('3', 'sign'))

    def test_the_previous_serial_survives_a_key_switch_and_a_deleted_sig(self):
        self.sign_set({PROVEN: J({'serial': 4, 'digests': {}})}, key=self.other)  # the old key: it does not verify now
        self.with_body(PROVEN, J({'serial': 4, 'digests': {}, 'wire_floor': 2}))
        self.refused('serial', PROVEN)
        self.commit({PROVEN: J({'serial': 7, 'digests': {}})}, rm=(f'{PROVEN}.sig',))  # a sig deleted with a newer body
        self.release()
        self.with_body(PROVEN, J({'serial': 5, 'digests': {}}))  # above 4, below the deleted one's body
        self.assertEqual(self.rows(self.plan()[1])[PROVEN], ('5', 'sign'))

    # ---- shapes and sizes

    def test_a_wrong_key_set_or_loader_rule_is_refused_per_file(self):
        sha, key = '1' * 40, self.publine
        live = {'serial': 1, 'address': '203.0.113.9', 'cert_sha256': '2' * 64, 'manifest_key': f'ssh-ed25519 {key}',
                'session_key': f'ssh-ed25519 {key}', 'next': None, 'r9_closed': False}
        bad = {HOSTS: [{'serial': 1, 'hosts': [], 'x': 1}, {'serial': 1}, {'serial': 1, 'hosts': ['a']}],
               GATEWAY: [{k: v for k, v in live.items() if k != 'next'}, {**live, 'upload_port': 443}, {**live, 'address': '01.2.3.4'},
                         {**live, 'manifest_key': 'ssh-rsa AAAA'}],
               WORK: [{'serial': 1, 'pins': [], 'sub': None, 'x': 1}, {'serial': 1, 'pins': [{'work_sha': sha}], 'sub': 's'}],
               DEPLOY: [{'serial': 1, 'head': sha}, {'serial': 1, 'head': None, 'tree': sha}, {'serial': 1, 'head': sha, 'tree': None},
                        {'serial': 1, 'head': sha, 'tree': sha, 'x': 1}],  # M8: no tree beside a head
               PROVEN: [{'serial': 1, 'digests': {'amiga': '2' * 64}}, {'serial': 1, 'digests': {}, 'wire_floor': 0}]}
        for path, docs in bad.items():
            for doc in docs:
                with self.subTest(path=path, doc=doc):
                    self.with_body(path, J(doc))
                    self.refused('shape', path)
                    self.with_body(path, PLACE[path])
        for raw in (b'{"serial": 1.5, "digests": {}}\n', b'{"serial": 1, "serial": 2, "digests": {}}\n', J({'serial': 1, 'digests': {}})[:-1],
                    b'\xef\xbb\xbf' + J({'serial': 1, 'digests': {}}), b'{"serial": true, "digests": {}}\n',
                    b'{"serial": 1, "digests": {"a": [[[[[1]]]]]}}\n'):
            with self.subTest(raw=raw):
                self.with_body(PROVEN, raw)
                self.refused('shape', PROVEN)
        self.with_body(PROVEN, J({'serial': 1, 'digests': {'linux': '2' * 64}, 'wire_floor': 2}))  # the control
        self.assertEqual(self.plan()[0], 0)

    def test_a_body_over_one_mib_is_refused(self):
        for extra, code in ((0, 0), (1, 1)):
            with self.subTest(extra=extra):
                body = b'{"serial": 1, "digests": {}}' + b' ' * (pp.MAX_PIN - 29 + extra) + b'\n'
                self.with_body(PROVEN, body)
                self.assertEqual((len(body), self.plan()[0]), (pp.MAX_PIN + extra, code))

    def test_a_release_tip_that_moved_is_refused(self):
        old = self.git('rev-parse', 'release')
        self.assertEqual(self.plan('--tip', old)[0], 0)
        self.commit({})
        self.release()
        self.refused('tip-moved', '-', '--tip', old)

    # ---- deploy-pin: attack M2, M7, M8

    def chain(self, n: int = 4) -> list[str]:
        heads = [self.commit({'fleet/slot/model.py': MODEL, f'f{i}': b'x'}) for i in range(n)]
        self.release()
        return heads

    def deploy(self, head: str, tree: str | None = None, serial: int = 1) -> None:
        self.with_body(DEPLOY, J({'serial': serial, 'head': head, 'tree': tree or self.git('rev-parse', f'{head}^{{tree}}')}))

    def test_a_deploy_head_in_main_and_the_release_with_its_own_tree_is_signed(self):
        a, b, _, _ = self.chain()
        self.deploy(b)
        self.assertEqual(self.rows(self.plan()[1])[DEPLOY], ('1', 'sign'))

    def test_a_deploy_head_that_fails_a_rule_is_refused_with_its_word(self):
        _, a, _, c = self.chain()
        wrong = self.git('rev-parse', f'{a}^{{tree}}')
        for label, head, tree, word, depth in (('not in the first parents', a, None, 'head', 2), ('wrong tree', c, wrong, 'tree', pp.PIN_DEPTH),
                                               ('unknown commit', '3' * 40, '4' * 40, 'head', pp.PIN_DEPTH)):
            with self.subTest(label), mock.patch.object(pp, 'PIN_DEPTH', depth):
                self.deploy(head, tree)
                self.refused(word, DEPLOY)

    def test_a_deploy_head_not_on_the_release_is_refused_though_main_holds_it(self):  # M2
        _, a, _, c = self.chain()
        self.git('checkout', '-q', '-B', 'rel', a)  # the release tip forks at a: main's c never went through the release merge
        for head, word in ((c, 'head'), (a, None)):
            self.commit({DEPLOY: J({'serial': 1, 'head': head, 'tree': self.git('rev-parse', f'{head}^{{tree}}')})})
            self.git('branch', '-f', 'release', 'rel')
            if word:
                self.refused(word, DEPLOY)
            else:
                self.assertEqual(self.rows(self.plan()[1])[DEPLOY], ('1', 'sign'))
        self.git('checkout', '-q', 'main')

    def test_a_head_without_the_ctl_namespace_text_is_refused(self):  # M7
        old = self.commit({'fleet/slot/model.py': b"SIG_NS = {'pin': 'mirrorstack-fleet-pin'}\n"})
        self.chain(1)
        self.deploy(old)
        self.refused('head', DEPLOY)

    def test_a_previous_head_that_is_not_an_ancestor_is_refused_and_a_descendant_is_signed(self):
        a, b, c, _ = self.chain()
        self.sign_set({DEPLOY: J({'serial': 1, 'head': b, 'tree': self.git('rev-parse', f'{b}^{{tree}}')})})
        self.deploy(a, serial=2)  # an older head: only roll-forward
        self.refused('head', DEPLOY)
        self.deploy(c, serial=2)
        self.assertEqual(self.rows(self.plan()[1])[DEPLOY], ('2', 'sign'))

    # ---- hosts, work-pin (M5), and what is printed (M3)

    def host(self, **change) -> dict:
        key = 'ssh-ed25519 ' + base64.b64encode(pp.ED_HEAD + bytes(32)).decode()
        line = {'id': 'box-1', 'form': 'bare', 'slots': 1, 'host_key': key, 'status_key': None, 'facts': [], 'tier': 'T0',
                'owner': 'owner-a', 'power': 2, 'repos': [], 'customer_ok': False}
        return {**line, **change}

    def test_a_hosts_line_the_vendored_summary_refuses_is_refused_and_one_it_accepts_prints_fingerprints_only(self):
        self.with_body(HOSTS, J({'serial': 1, 'hosts': [self.host(tier='T1', repos=['emat-group/kaohsiung-association'])]}))
        self.refused('shape', HOSTS)
        self.with_body(HOSTS, J({'serial': 1, 'hosts': [self.host()]}))
        code, out, err = self.plan()
        self.assertEqual((code, self.rows(out)[HOSTS]), (0, ('1', 'sign')))
        self.assertRegex(err, r'# hosts new SHA256:\S+ -\n')
        self.assertNotRegex(err + out, r'box-1|owner-a')

    def test_each_work_pin_blob_must_be_the_release_trees_work_yml(self):
        yml = self.commit({'.github/workflows/work.yml': b'name: work\n'})
        blob = self.git('rev-parse', f'{yml}:.github/workflows/work.yml')
        for pin, word in ((blob, None), ('5' * 40, 'blob')):
            with self.subTest(pin=pin):
                self.with_body(WORK, J({'serial': 1, 'pins': [{'work_sha': '6' * 40, 'blob': pin}], 'sub': 'repo:x'}))
                if word:
                    self.refused(word, WORK)
                else:
                    self.assertEqual(self.plan()[0], 0)

    def test_no_value_of_a_body_is_printed(self):
        key = f'ssh-ed25519 {self.publine}'
        self.with_body(GATEWAY, J({'serial': 1, 'address': '203.0.113.9', 'cert_sha256': '2' * 64, 'manifest_key': key,
                                   'session_key': key, 'next': None, 'r9_closed': False}))
        code, out, err = self.plan()
        self.assertEqual(code, 0)
        for value in ('203.0.113.9', '2' * 64, self.publine):
            self.assertNotIn(value, out + err)
        self.assertIn('changed: address cert_sha256 manifest_key next r9_closed serial session_key', err)

    # ---- usage and the clone fallback

    def test_a_bad_command_line_is_usage_and_a_bad_key_is_refused(self):
        for argv in (['p'], ['p', 'plan'], ['p', 'plan', '--repo', 'x', '--pub', 'y', '--run-id', 'a b'],
                     ['p', 'plan', '--repo', 'x', '--pub', 'y', '--tip', 'abc'], ['p', 'plan', '--repo', 'x', '--bogus', 'y']):
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pp.main(argv), 2, argv)
        bad = self.tmp / 'bad.pub'
        bad.write_text('ssh-rsa AAAA\n')
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(pp.main(['p', 'plan', '--repo', str(self.repo), '--pub', str(bad)]), 1)
        self.assertEqual(err.getvalue(), 'REFUSED pub -\n')

    def test_clone_falls_back_to_a_full_clone_when_the_filtered_one_fails(self):
        calls = []

        def stub(*args, **kw):
            calls.append(args)
            return None if '--filter=blob:none' in args and fail else b''
        for fail, mode in ((False, 'filtered'), (True, 'full')):
            calls.clear()
            self.assertEqual(pp.clone('url', str(self.tmp / 'x'), stub), mode)
        self.assertEqual(['--filter=blob:none' in c for c in calls], [True, False])
        with self.assertRaises(pp.Refused):
            pp.clone('url', str(self.tmp / 'x'), lambda *a, **k: None)
        dest = self.tmp / 'real'  # and for real, over a local path
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(pp.main(['p', 'clone', str(self.repo), str(dest)]), 0)
        self.assertRegex(out.getvalue(), r'clone (filtered|full)\n')
        self.assertTrue((dest / '.git').is_dir())


class Vendor(unittest.TestCase):
    def test_the_vendored_summary_is_its_pin_and_runs(self):
        data = (ROOT / 'vendor/pin-summary.py').read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest() + '\n', (ROOT / 'vendor/pin-summary.sha256').read_text())
        self.assertEqual(pp.vendored_summary().check_hosts(PLACE[HOSTS]), {})

    @unittest.skipUnless(os.environ.get('FLEET_REPO'), 'FLEET_REPO (a fleet clone) is not set')
    def test_its_tables_equal_the_fleets_copy_at_the_pinned_head(self):
        theirs = subprocess.run([pp.GIT, '-C', os.environ['FLEET_REPO'], 'show', f'{FLEET_HEAD}:bin/pin-summary.py'],
                                env=GIT_ENV, capture_output=True, check=True).stdout
        mod = pp.types.ModuleType('fleet_pin_summary')
        exec(compile(theirs, 'pin-summary.py', 'exec'), mod.__dict__)
        ours = pp.vendored_summary()
        tables = [n for n in vars(ours) if n.isupper()]
        self.assertGreater(len(tables), 10)
        for name in tables:
            a, b = getattr(ours, name), getattr(mod, name)
            self.assertEqual(getattr(a, 'pattern', a), getattr(b, 'pattern', b), name)
        self.assertEqual(theirs, (ROOT / 'vendor/pin-summary.py').read_bytes())  # and unchanged


if __name__ == '__main__':
    unittest.main()
