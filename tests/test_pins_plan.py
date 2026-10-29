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
FLEET_PIN_SUMMARY_SHA256 = '09d264cce60a7b0cebc2303bfa796a70289f3aabd8e756bc9758d11c97a98d9d'  # sha256 of fleet's bin/pin-summary.py there
CTL_NS = 'mirrorstack-fleet-ctl'  # a literal on purpose: the tests must not follow a changed pp.NS
PLACE = {
    'fleet/hosts.json': b'{"serial": 0, "hosts": []}\n',
    'fleet/core/gateway.json': b'{"serial": 0, "address": null, "cert_sha256": null, "manifest_key": null, '
                               b'"session_key": null, "next": null, "r9_closed": false}\n',
    'fleet/core/work-pin.json': b'{"serial": 0, "pins": [], "sub": null}\n',
    'fleet/core/deploy-pin.json': b'{"serial": 0, "head": null}\n',
    'fleet/core/proven.json': b'{"serial": 0, "digests": {}}\n'}
HOSTS, GATEWAY, WORK, DEPLOY, PROVEN = pp.FILES
MODEL = b"SIG_NS = {'pin': 'mirrorstack-fleet-pin', 'ctl': 'mirrorstack-fleet-ctl'}\n"
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

    def sig(self, body: bytes, ns: str = CTL_NS, key: Path | None = None) -> bytes:
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

    def test_an_older_signed_pair_committed_back_is_no_keep_and_no_lower_serial_signs_after_it(self):
        old = {PROVEN: J({'serial': 2, 'digests': {}})}
        self.sign_set(old)
        self.sign_set({PROVEN: J({'serial': 5, 'digests': {}})})
        self.assertEqual(self.rows(self.plan()[1])[PROVEN], ('5', 'keep'))
        self.sign_set(old)  # the validly signed serial-2 body and sig, back at the tip
        self.refused('serial', PROVEN)
        self.with_body(PROVEN, J({'serial': 3, 'digests': {}}))  # and a fresh serial below the highest ever signed
        self.refused('serial', PROVEN)
        self.with_body(PROVEN, J({'serial': 6, 'digests': {}}))
        self.assertEqual(self.rows(self.plan()[1])[PROVEN], ('6', 'sign'))

    def test_the_serial_history_is_the_release_tips_not_mains(self):
        self.sign_set({PROVEN: J({'serial': 2, 'digests': {}})})
        self.commit({PROVEN: J({'serial': 9, 'digests': {}}), f'{PROVEN}.sig': self.sig(J({'serial': 9, 'digests': {}}))})  # main only
        self.git('checkout', '-q', '-b', 'side', 'release')
        self.commit({PROVEN: J({'serial': 3, 'digests': {}})})
        self.git('branch', '-f', 'release', 'side')
        self.git('checkout', '-q', 'main')
        self.assertEqual(self.rows(self.plan()[1])[PROVEN], ('3', 'sign'))

    # ---- shapes and sizes

    def test_a_wrong_key_set_or_loader_rule_is_refused_per_file(self):
        sha, key = '1' * 40, self.publine
        raw = 'ssh-ed25519 ' + base64.b64encode(bytes(51)).decode()  # key-shaped, but not an ed25519 key blob
        live = {'serial': 1, 'address': '203.0.113.9', 'cert_sha256': '2' * 64, 'manifest_key': f'ssh-ed25519 {key}',
                'session_key': f'ssh-ed25519 {key}', 'next': None, 'r9_closed': False}
        nxt = {k: live[k] for k in ('address', 'cert_sha256', 'manifest_key', 'session_key')}
        bad = {HOSTS: [{'serial': 1, 'hosts': [], 'x': 1}, {'serial': 1}, {'serial': 1, 'hosts': ['a']},
                       {'serial': -1, 'hosts': []}],
               GATEWAY: [{k: v for k, v in live.items() if k != 'next'}, {**live, 'upload_port': 443}, {**live, 'address': '01.2.3.4'},
                         {**live, 'manifest_key': 'ssh-rsa AAAA'}, {**live, 'upload_port': 1023}, {**live, 'upload_port': 8443},
                         {**live, 'upload_port': 65536}, {**live, 'upload_port': True}, {**live, 'address': 'fe80::1%eth0'},
                         {**live, 'r9_closed': 1}, {**live, 'manifest_key': raw}, {**live, 'session_key': raw},
                         {**live, 'next': {**nxt, 'cert_sha256': 'zz'}}, {**live, 'next': {**nxt, 'session_key': raw}},
                         {**live, 'next': {**nxt, 'upload_port': 443}}, {**live, 'next': {**nxt, 'x': 1}}],
               WORK: [{'serial': 1, 'pins': [], 'sub': None, 'x': 1}, {'serial': 1, 'pins': [{'work_sha': sha}], 'sub': 's'},
                      {'serial': 1, 'pins': [{'work_sha': sha, 'blob': sha}, {'work_sha': sha, 'blob': '2' * 40}], 'sub': 's'},
                      {'serial': 1, 'pins': [], 'sub': 's' * 513}, {'serial': 1, 'pins': [{'work_sha': sha, 'blob': sha}], 'sub': None},
                      {'serial': 1, 'pins': [{'work_sha': sha.upper().replace('1', 'A'), 'blob': sha}], 'sub': 's'}],
               DEPLOY: [{'serial': 1, 'head': sha}, {'serial': 1, 'head': None, 'tree': sha}, {'serial': 1, 'head': sha, 'tree': None},
                        {'serial': 1, 'head': sha, 'tree': sha, 'x': 1},  # M8: no tree beside a head
                        {'serial': 1, 'head': 'A' * 40, 'tree': 'A' * 40}, {'serial': 1, 'head': sha, 'tree': 'A' * 40}],
               PROVEN: [{'serial': 1, 'digests': {'amiga': '2' * 64}}, {'serial': 1, 'digests': {}, 'wire_floor': 0},
                        {'serial': 2 ** 63, 'digests': {}}, {'serial': 1, 'digests': {}, 'wire_floor': 256}, {'serial': 1, 'digests': {'linux': 'A' * 64}},
                        {'serial': 1, 'digests': {'linux': '2' * 40}}]}
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

    def test_the_edges_of_each_shape_rule_are_accepted(self):
        key = f'ssh-ed25519 {self.publine}'
        live = {'serial': 1, 'address': '2001:db8::1', 'cert_sha256': '2' * 64, 'manifest_key': key, 'session_key': key,
                'r9_closed': True, 'upload_port': 1024}
        for path, doc in ((PROVEN, {'serial': 2 ** 63 - 1, 'digests': {}, 'wire_floor': 255}),
                          (WORK, {'serial': 1, 'pins': [], 'sub': 's' * 512}),
                          (GATEWAY, {**live, 'next': {**{k: live[k] for k in ('address', 'cert_sha256', 'manifest_key', 'session_key')},
                                                      'upload_port': 65535}})):
            with self.subTest(path=path):
                self.with_body(path, J(doc))
                self.assertEqual(self.plan()[0], 0)
                self.with_body(path, PLACE[path])

    def test_the_loader_caps_integers_at_19_digits_and_nesting_at_5(self):
        for text, ok in ((b'{"serial": 1, "x": 9999999999999999999}\n', True), (b'{"serial": 1, "x": 10000000000000000000}\n', False),
                         (b'{"serial": 1, "x": -999999999999999999}\n', True), (b'{"serial": 1, "x": -9999999999999999999}\n', True),
                         (b'{"serial": 1, "x": -10000000000000000000}\n', False),
                         (b'{"serial": 1, "x": [[[[1]]]]}\n', True), (b'{"serial": 1, "x": [[[[[1]]]]]}\n', False),
                         (b'{"serial": 1, "x": {"y": {"z": [[]]}}}\n', True), (b'{"serial": 1, "x": {"y": {"z": [[{}]]}}}\n', False),
                         (b'{"serial": 1, "x": "[[[[[[[[[[\\"]]]]]]]]]]"}\n', True)):
            with self.subTest(text=text):
                if ok:
                    self.assertEqual(pp.load(text, 'p')['serial'], 1)
                else:
                    with self.assertRaises(pp.Refused):
                        pp.load(text, 'p')
        self.assertEqual(pp.NS, CTL_NS)

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

    def test_a_head_without_the_ctl_namespace_in_its_sig_ns_is_refused(self):  # M7
        real = (b"SIG_NS: Mapping[Literal['manifest', 'pin', 'ctl'], str] = MappingProxyType({  # raw Ed25519\n"
                b"    'pin': 'mirrorstack-fleet-pin',\n    'ctl': 'mirrorstack-fleet-ctl'})\n")  # the fleet's own spelling
        for label, model, ok in (('absent', b"SIG_NS = {'pin': 'mirrorstack-fleet-pin'}\n", False),
                                 ('only a comment', b"# 'ctl': 'mirrorstack-fleet-ctl'\nSIG_NS = {'pin': 'p'}\n", False),
                                 ('only a string', b"X = \"'ctl': 'mirrorstack-fleet-ctl'\"\nSIG_NS = {'pin': 'p'}\n", False),
                                 ('another name', b"OTHER = {'ctl': 'mirrorstack-fleet-ctl'}\nSIG_NS = {'pin': 'p'}\n", False),
                                 ('wrong value', b"SIG_NS = {'ctl': 'mirrorstack-fleet-ctlx'}\n", False),
                                 ('not python', b"SIG_NS = {'ctl': 'mirrorstack-fleet-ctl'\n", False),
                                 ('the real spelling', real, True), ('a bare dict', MODEL, True)):
            with self.subTest(label):
                head = self.commit({'fleet/slot/model.py': model})
                self.chain(1)
                self.deploy(head)
                if ok:
                    self.assertEqual(self.rows(self.plan()[1])[DEPLOY], ('1', 'sign'))
                else:
                    self.refused('head', DEPLOY)

    def test_a_previous_head_that_is_not_an_ancestor_is_refused_and_a_descendant_is_signed(self):
        a, b, c, _ = self.chain()
        self.sign_set({DEPLOY: J({'serial': 1, 'head': b, 'tree': self.git('rev-parse', f'{b}^{{tree}}')})})
        self.deploy(a, serial=2)  # an older head: only roll-forward
        self.refused('head', DEPLOY)
        self.deploy(c, serial=2)
        self.assertEqual(self.rows(self.plan()[1])[DEPLOY], ('2', 'sign'))

    def test_the_roll_forward_rule_holds_across_a_signed_null_head(self):
        a, b, c, d = self.chain()
        tree = lambda h: self.git('rev-parse', f'{h}^{{tree}}')  # noqa: E731
        self.sign_set({DEPLOY: J({'serial': 1, 'head': c, 'tree': tree(c)})})
        self.sign_set({DEPLOY: J({'serial': 2, 'head': None})})
        self.deploy(a, serial=3)  # an older head than the last signed non-null one
        self.refused('head', DEPLOY)
        self.deploy(d, serial=3)
        self.assertEqual(self.rows(self.plan()[1])[DEPLOY], ('3', 'sign'))
        self.sign_set({DEPLOY: J({'serial': 3, 'head': 'xyz', 'tree': tree(d)})})  # a previous head that is no sha
        self.deploy(d, serial=4)
        self.refused('head', DEPLOY)

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
        self.sign_set({HOSTS: J({'serial': 1, 'hosts': [self.host()]})})
        self.with_body(HOSTS, J({'serial': 2, 'hosts': [self.host(owner='owner-b')]}))  # the same box, one line changed
        code, out, err = self.plan()
        self.assertEqual((code, self.rows(out)[HOSTS]), (0, ('2', 'sign')))
        self.assertRegex(err, r'# hosts changed SHA256:\S+ -\n')
        self.assertNotRegex(err + out, r'hosts new|owner-b')

    def test_each_work_pin_blob_must_be_the_release_trees_work_yml(self):
        yml = self.commit({'fleet/work/work.yml': b'name: work\n'})   # the real path in the fleet tree (CV16)
        blob = self.git('rev-parse', f'{yml}:fleet/work/work.yml')
        for pin, word in ((blob, None), ('5' * 40, 'blob')):
            with self.subTest(pin=pin):
                self.with_body(WORK, J({'serial': 1, 'pins': [{'work_sha': '6' * 40, 'blob': pin}], 'sub': 'repo:x'}))
                if word:
                    self.refused(word, WORK)
                else:
                    self.assertEqual(self.plan()[0], 0)

    def test_a_work_yml_only_at_the_old_github_workflows_path_is_not_the_release_trees_work_yml(self):
        # the CV16 bug control: the planner once read .github/workflows/work.yml, which the fleet tree does not have
        yml = self.commit({'.github/workflows/work.yml': b'name: work\n'})
        blob = self.git('rev-parse', f'{yml}:.github/workflows/work.yml')
        self.with_body(WORK, J({'serial': 1, 'pins': [{'work_sha': '6' * 40, 'blob': blob}], 'sub': 'repo:x'}))
        self.refused('blob', WORK)

    def test_empty_work_pins_never_reach_the_blob_check(self):
        self.assertFalse((self.repo / 'fleet/work/work.yml').exists())   # no work.yml at all
        self.with_body(WORK, J({'serial': 1, 'pins': [], 'sub': None}))
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

    # ---- --only (CV05d: install.yml's plan job judges gateway.json alone before gwsign signs it)

    def test_only_judges_and_prints_the_one_file_and_the_other_four_are_not_read(self):
        self.with_body(HOSTS, b'{"serial": "x", "hosts": []}\n')   # a bad file the one-file plan must not look at
        self.refused('shape', HOSTS)   # control: the whole plan stops on it
        code, out, err = self.plan('--only', GATEWAY)
        self.assertEqual(code, 0)
        self.assertEqual(err.count('\n'), 1)   # the review line of this file alone
        self.assertTrue(err.startswith(f'# {GATEWAY} sha256='), err)
        self.assertEqual(out.splitlines()[:2], [f'tip {self.git("rev-parse", "release")}', 'run 77'])
        self.assertEqual(self.rows(out), {GATEWAY: ('0', 'sign')})
        self.assertEqual(len(out.splitlines()), 3)

    def test_only_refuses_the_files_own_faults_with_the_same_words(self):
        key = f'ssh-ed25519 {self.publine}'
        live = {'serial': 3, 'address': '203.0.113.9', 'cert_sha256': 'ab' * 32, 'manifest_key': key, 'session_key': key,
                'next': None, 'r9_closed': False}
        self.with_body(GATEWAY, J({k: v for k, v in live.items() if k != 'r9_closed'}))   # wrong keys
        self.refused('shape', GATEWAY, '--only', GATEWAY)
        self.sign_set({GATEWAY: J({**live, 'serial': 5})})
        self.with_body(GATEWAY, J(live))   # serial not above the previous signed one
        self.refused('serial', GATEWAY, '--only', GATEWAY)
        self.with_body(GATEWAY, J({**live, 'serial': 6}))
        code, out, _ = self.plan('--only', GATEWAY)
        self.assertEqual((code, self.rows(out)), (0, {GATEWAY: ('6', 'sign')}))

    def test_only_names_one_of_the_five_files_and_nothing_else(self):
        for argv in (['--only', 'fleet/core/other.json'], ['--only', ''], ['--only', '../' + GATEWAY], ['--only']):
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pp.main(['p', 'plan', '--repo', str(self.repo), '--pub', self.pub, *argv]), 2, argv)

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

    def test_clone_never_touches_a_folder_that_already_holds_files(self):
        calls = []
        full = self.tmp / 'full'
        full.mkdir()
        (full / 'keep.txt').write_text('mine')
        with self.assertRaises(pp.Refused):
            pp.clone('url', str(full), lambda *a, **k: calls.append(a))
        self.assertEqual((calls, (full / 'keep.txt').read_text()), ([], 'mine'))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(pp.main(['p', 'clone', str(self.repo), str(full)]), 1)
        self.assertEqual((err.getvalue(), (full / 'keep.txt').read_text()), ('REFUSED fetch -\n', 'mine'))
        empty = self.tmp / 'empty'  # an empty folder stays, and stays empty, when both tries fail
        empty.mkdir()
        self.assertTrue(empty.is_dir() and not any(empty.iterdir()))

        def junk(*args, **kw):
            (empty / 'half').write_text('x')
            return None
        with self.assertRaises(pp.Refused):
            pp.clone('url', str(empty), junk)
        self.assertTrue(empty.is_dir() and not any(empty.iterdir()))
        with self.assertRaises(pp.Refused):  # a failed clone into a path the planner would create leaves nothing
            pp.clone('url', str(self.tmp / 'new'), junk)
        self.assertFalse((self.tmp / 'new').exists())

    def test_the_release_and_main_defaults_are_origin_release_and_origin_main(self):
        base = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-q', '-b', 'side', base)
        head = self.commit({'side': b'x'})  # on the release side only
        tree = self.git('rev-parse', f'{head}^{{tree}}')
        deploy = self.commit({DEPLOY: J({'serial': 1, 'head': head, 'tree': tree})})
        self.git('checkout', '-q', 'main')
        plain = self.commit({'plain': b'y'})
        main = self.commit({'m': b'z'})
        run = lambda: self.run_defaults()  # noqa: E731
        self.git('update-ref', 'refs/remotes/origin/main', main)
        self.git('update-ref', 'refs/remotes/origin/release', plain)  # a tip that is not main's
        code, out, err = run()
        self.assertEqual((code, out.splitlines()[0], err), (0, f'tip {plain}', err))
        self.git('update-ref', 'refs/remotes/origin/release', deploy)  # its head is in release but not in main's first parents
        self.assertEqual(run()[::2], (1, 'REFUSED head fleet/core/deploy-pin.json\n'))

    def run_defaults(self) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = pp.main(['p', 'plan', '--repo', str(self.repo), '--pub', self.pub, '--run-id', '1'])
        return code, out.getvalue(), err.getvalue()


class Vendor(unittest.TestCase):
    def test_the_vendored_summary_is_its_pin_and_runs(self):
        data = (ROOT / 'vendor/pin-summary.py').read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest() + '\n', (ROOT / 'vendor/pin-summary.sha256').read_text())
        # the fleet's own digest, held here: a change to the vendored copy (and its .sha256) needs a visible edit of this literal
        self.assertEqual(hashlib.sha256(data).hexdigest(), FLEET_PIN_SUMMARY_SHA256)
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
        self.assertEqual(hashlib.sha256(theirs).hexdigest(), FLEET_PIN_SUMMARY_SHA256)
        self.assertEqual(theirs, (ROOT / 'vendor/pin-summary.py').read_bytes())  # and unchanged


if __name__ == '__main__':
    unittest.main()
