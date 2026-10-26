"""bin/fleet-kit-upload.py and the vendored packer, with no network: the pins of vendor/bundle.py and its stand-ins (a changed
byte is `REFUSED vendor`), the packer's bytes frozen against a golden, the whole `bundle` verb over a real throwaway git
repository, a real ssh-keygen key and a real openssl Ed25519 key (the signature each request carries is verified here, over
the exact message), every refusal one at a time (and that a refusal makes no request), that nothing a build holds reaches the
output, that the key and the tar are gone afterwards, and the `gateway` verb. The host is a fake. Tests that need ssh-keygen or
an openssl with Ed25519 raw signing are skipped when the tool is missing. Plain unittest, stdlib only."""
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
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('fleet_kit_upload', ROOT / 'bin/fleet-kit-upload.py')
fk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fk)
fp = fk.fp

HAVE_KEYGEN = os.path.exists(fp.SSH_KEYGEN)
OPENSSL = next((p for p in (fk.OPENSSL, '/opt/homebrew/bin/openssl', '/usr/local/bin/openssl', '/usr/bin/openssl')
                if os.path.exists(p) and subprocess.run([p, 'genpkey', '-algorithm', 'ed25519'], capture_output=True).returncode == 0
                and 'rawin' in subprocess.run([p, 'pkeyutl', '-help'], capture_output=True, text=True).stderr), None)
fk.OPENSSL = OPENSSL or fk.OPENSSL
HOST = 'kit.example.org'
SERIAL = 7
sha = lambda data: hashlib.sha256(data).hexdigest()  # noqa: E731
AUTH = re.compile(r'KitAdmin (upload|gateway) ([1-9][0-9]{12,15}) ([0-9a-f]{128})')  # copied from the Worker: its only accepted form
GOLDEN_PACK = '6043671935c55bd79ada977327b6fae943b9437ae778f9d2b042d37df49f8f9f'  # the same on 3.11, 3.13 and 3.14
GIT_ENV = {**os.environ, 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@x',
           'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@x', 'GIT_AUTHOR_DATE': '2026-10-10T00:00:00Z',
           'GIT_COMMITTER_DATE': '2026-10-10T00:00:00Z'}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(['git', '-C', str(repo), *args], env=GIT_ENV, check=True, capture_output=True, text=True).stdout.strip()


def keygen(tmp: Path, name: str) -> Path:
    key = tmp / name
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'test', '-f', str(key)], check=True)
    return key


def ssh_sign(key: Path, path: Path, namespace: str) -> None:
    subprocess.run(['ssh-keygen', '-q', '-Y', 'sign', '-f', str(key), '-n', namespace, str(path)], check=True)


def host(status: int, error: str | None) -> tuple[int, bytes, str]:
    """What the Worker answers after the signature is good: {ok: false, error}, and what the uploader says of it."""
    word = error if error in ('conflict', 'replay', 'rollback', 'revoked') else f'upload {status} {error}'
    return status, json.dumps({'ok': False, 'error': error}).encode(), f'REFUSED {word}'


HOST_CASES = (host(409, 'conflict'), host(409, 'replay'), host(409, 'rollback'), host(409, 'revoked'), host(401, 'stale'),
              host(422, 'checksum'), host(503, 'unavailable'), host(400, 'bad-request'),
              (404, b'not found\n', 'REFUSED upload 404'), (409, b'', 'REFUSED upload 409'), (503, b'', 'REFUSED upload 503'),
              (302, b'', 'REFUSED upload 302'),
              (409, b'{"ok":false,"error":"PRIVATE-WORD"}', 'REFUSED upload 409'),  # a word the host is not known to say is not shown
              (500, b'{"error":["conflict"]}', 'REFUSED upload 500'))


class FakeNet:
    """The kit host: it records every request and answers from `answer` (a function of the request) or, by default, as the Worker
    does (kit/worker.js, `gateAdmin`): the Gate's own fields plus what R2 holds."""

    def __init__(self, pub_pem: Path | None = None, answer=None) -> None:
        self.calls: list[dict] = []
        self.pub_pem = pub_pem
        self.answer = answer

    def request(self, method, host, path, headers, body):
        call = {'method': method, 'host': host, 'path': path, 'headers': dict(headers), 'body': body}
        self.calls.append(call)
        if self.answer is not None:
            return self.answer(call)
        if path.startswith('/_k/file/'):
            return 200, json.dumps({'ok': True, 'created': True, 'sha256': sha(body), 'size': len(body)}).encode()
        doc = json.loads(body)
        if path == '/_k/floor':
            return 200, json.dumps({'ok': True, 'floor': doc['floor']}).encode()
        text, sig = base64.b64decode(doc['json']), base64.b64decode(doc['sig'])
        return 200, json.dumps({'ok': True, 'created': True, 'gserial': int(path.rsplit('/', 1)[1]),
                                'json': {'sha256': sha(text), 'size': len(text)},
                                'sig': {'sha256': sha(sig), 'size': len(sig)}}).encode()

    def signature_ok(self, call: dict) -> bool:
        """Does the Authorization header's signature verify, with the public key, over exactly the documented message."""
        match = AUTH.fullmatch(call['headers']['Authorization'])  # the Worker's own grammar (kit/worker.js ADMIN_AUTH)
        if match is None:
            return False
        scheme, role, ts, sig = 'KitAdmin', *match.groups()
        want = fk.message(role, int(ts), call['method'], call['path'], sha(call['body']))
        sig_bytes = bytes.fromhex(sig)
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'm').write_bytes(want)
            (Path(tmp) / 's').write_bytes(sig_bytes)
            done = subprocess.run([fk.OPENSSL, 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', str(self.pub_pem), '-in',
                                   str(Path(tmp) / 'm'), '-sigfile', str(Path(tmp) / 's')], capture_output=True)
        return scheme == 'KitAdmin' and role == 'upload' and call['headers']['X-Kit-Sha256'] == sha(call['body']) and done.returncode == 0


@unittest.skipUnless(HAVE_KEYGEN and OPENSSL and shutil.which('git'), 'ssh-keygen, an Ed25519 openssl or git is missing')
class Fixture(unittest.TestCase):
    """A fake fleet repository (`origin`), an owner key, an upload key, and the release folder, rebuilt for each test."""

    LISTED = ['fleet/install/closure.txt', 'fleet/a.txt', 'fleet/b/c.txt']

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='kit-upload-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.runner = self.tmp / 'runner'
        self.shm = self.tmp / 'shm'
        self.runner.mkdir()
        self.shm.mkdir()
        self.owner = keygen(self.tmp, 'owner')
        self.pub = self.tmp / 'owner.pub'
        self.pub.write_bytes(Path(str(self.owner) + '.pub').read_bytes())
        self.pin = subprocess.run([fp.SSH_KEYGEN, '-l', '-f', str(self.pub)], capture_output=True, text=True).stdout.split()[1]
        self.up_key, self.up_pub = self.tmp / 'up.pem', self.tmp / 'up.pub.pem'
        subprocess.run([fk.OPENSSL, 'genpkey', '-algorithm', 'ed25519', '-out', str(self.up_key)], check=True, capture_output=True)
        subprocess.run([fk.OPENSSL, 'pkey', '-in', str(self.up_key), '-pubout', '-out', str(self.up_pub)], check=True, capture_output=True)
        self.origin = self.tmp / 'origin'
        self.origin.mkdir()
        git(self.origin, 'init', '-q', '-b', 'release')
        git(self.origin, 'config', 'uploadpack.allowAnySHA1InWant', 'true')
        self.write('fleet/install/closure.txt', '\n'.join(self.LISTED) + '\n')
        self.write('fleet/a.txt', 'alpha secret-looking-name\n')
        self.write('fleet/b/c.txt', 'gamma\n')
        self.write('fleet/unlisted-customer-name.txt', 'never in the bundle\n')
        git(self.origin, 'add', '-A')
        git(self.origin, 'commit', '-q', '-m', 'head')
        self.head = git(self.origin, 'rev-parse', 'HEAD')
        self.tree = git(self.origin, 'rev-parse', 'HEAD^{tree}')
        self.write('fleet/core/gateway.json', json.dumps(self.record(3)) + '\n')
        ssh_sign(self.owner, self.origin / 'fleet/core/gateway.json', fp.PIN_NS)
        git(self.origin, 'add', '-A')
        git(self.origin, 'commit', '-q', '-m', 'tip')
        self.remote = self.origin.as_uri()
        closure = fk.packer.cut(self.origin, self.head, self.LISTED)
        self.tar = fk.packer.pack(closure)
        self.folder = self.tmp / 'release'
        self.folder.mkdir()
        self.net = FakeNet(self.up_pub)
        patch = mock.patch.object(fk, 'SHM', str(self.shm))
        patch.start()
        self.addCleanup(patch.stop)
        self.sign_install()

    @staticmethod
    def record(serial: int, **extra) -> dict:
        return {'serial': serial, 'address': '203.0.113.9', 'cert_sha256': 'ab' * 32, 'manifest_key': 'k', 'session_key': 's', **extra}

    def write(self, rel: str, text: str) -> None:
        path = self.origin / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def doc(self, **bundle) -> dict:
        return {'kind': 'install', 'serial': SERIAL, 'valid_until': '2027-01-01T00:00:00Z', 'source_head': 'ab' * 20,
                'bootstrap': {n: {'sha256': 'cd' * 32, 'blob': 'ef' * 20} for n in ('ps1', 'sh')},
                'kit': {'serial': 1, 'kit_json_sha256': '12' * 32}, 'lock_sha256': '34' * 32,
                'bundle': {'head': self.head, 'tree': self.tree, 'url': f'https://{HOST}/v1/kit/{SERIAL}/bundle.tar',
                           'sha256': sha(self.tar), 'size': len(self.tar), **bundle}}

    def sign_install(self, key: Path | None = None, **bundle) -> None:
        path = self.folder / 'install.json'
        path.write_text(json.dumps(self.doc(**bundle)))
        (self.folder / 'install.json.sig').unlink(missing_ok=True)
        ssh_sign(key or self.owner, path, fp.NS)

    def env(self, **over) -> dict:
        env = {'KIT_HOST': HOST, 'KIT_UPLOAD_KEY': self.up_key.read_text(), 'FLEET_REPO': self.remote,
               'RUNNER_TEMP': str(self.runner), 'PATH': os.environ['PATH'], 'OWNER_PIN_SHA256': self.pin}
        env.update(over)
        return {k: v for k, v in env.items() if v is not None}

    def invoke(self, *argv: str, env: dict | None = None, net=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = fk.main(['x', *argv], self.env() if env is None else env, self.net if net is None else net)
        return code, out.getvalue(), err.getvalue()

    def bundle(self, **kw):
        return self.invoke('bundle', str(self.folder), '--owner-pub', str(self.pub), **kw)

    def sig_args(self) -> tuple[str, ...]:
        """`--sig FILE` over the fixture tip's own signature file, as the kit job passes gwsign's (CV05d: the verb never reads the tip's):
        the tip holds an owner signature of the record in the pin namespace, which stands in for gwsign's here; no such file, no option."""
        found = self.origin / 'fleet/core/gateway.json.sig'
        return ('--sig', str(found)) if found.exists() else ()

    def gateway(self, **kw):
        return self.invoke('gateway', '--owner-pub', str(self.pub), *self.sig_args(), **kw)

    def assertClean(self):
        """Nothing is left behind: the runner's temp folder and the key's folder are empty again."""
        self.assertEqual(list(self.runner.iterdir()), [])
        self.assertEqual(list(self.shm.iterdir()), [])


class TestBundle(Fixture):
    def test_uploads_the_bundle_the_signed_manifest_names(self):
        code, out, err = self.bundle()
        self.assertEqual((code, err), (0, ''), out)
        self.assertEqual(out.splitlines(), [f'kit bundle serial={SERIAL} size={len(self.tar)} sha256={sha(self.tar)}',
                                            f'OK bundle serial={SERIAL} size={len(self.tar)} sha256={sha(self.tar)}'])
        (call,) = self.net.calls
        self.assertEqual((call['method'], call['host'], call['path']), ('PUT', HOST, f'/_k/file/{SERIAL}/bundle.tar'))
        self.assertEqual(call['body'], self.tar)
        self.assertTrue(self.net.signature_ok(call))
        self.assertClean()

    def test_the_bundle_holds_the_listed_files_and_not_the_unlisted_one(self):
        self.bundle()
        import tarfile
        names = tarfile.open(fileobj=io.BytesIO(self.net.calls[0]['body'])).getnames()
        self.assertTrue(any(n.endswith('/files/fleet/a.txt') for n in names))
        self.assertFalse(any('unlisted' in n for n in names))  # only a tree body names it, as the packer says it does

    def test_the_output_names_no_file_and_no_key(self):
        _, out, err = self.bundle()
        pem_body = self.up_key.read_text().splitlines()[1]
        for text in (out, err):
            for word in ('a.txt', 'closure', 'customer', 'secret-looking', 'origin', 'Traceback', pem_body, 'PRIVATE KEY'):
                self.assertNotIn(word, text)
        self.assertEqual(len(out.splitlines()), 2)

    def test_the_request_is_signed_by_the_upload_role_with_a_rising_time(self):
        self.bundle()
        self.bundle()
        stamps = [int(c['headers']['Authorization'].split()[2]) for c in self.net.calls]
        self.assertEqual(len(stamps), 2)
        self.assertLess(stamps[0], stamps[1])
        self.assertTrue(all(self.net.signature_ok(c) for c in self.net.calls))

    def test_a_wrong_signature_key_is_refused_before_any_fetch_or_request(self):
        other = keygen(self.tmp, 'other')
        self.sign_install(key=other)
        with mock.patch.object(fk, 'fetch_fleet', side_effect=AssertionError('fetched')):
            code, out, _ = self.bundle()
        self.assertEqual((code, out), (1, 'REFUSED sig\n'))
        self.assertEqual(self.net.calls, [])
        self.assertClean()

    def test_an_unsigned_or_missing_manifest_is_refused(self):
        (self.folder / 'install.json.sig').unlink()
        self.assertEqual(self.bundle()[:2], (1, 'REFUSED install\n'))
        (self.folder / 'install.json').unlink()
        self.assertEqual(self.bundle()[:2], (1, 'REFUSED install\n'))
        self.assertEqual(self.net.calls, [])

    def test_a_manifest_with_the_wrong_shape_or_another_host_is_refused(self):
        (self.folder / 'install.json').write_text('{"kind": "install"}')
        (self.folder / 'install.json.sig').unlink()
        ssh_sign(self.owner, self.folder / 'install.json', fp.NS)
        self.assertEqual(self.bundle()[:2], (1, 'REFUSED form\n'))
        self.sign_install(url=f'https://other.example.org/v1/kit/{SERIAL}/bundle.tar')
        self.assertEqual(self.bundle()[:2], (1, 'REFUSED kit-host\n'))
        self.sign_install(url=f'https://{HOST}/v1/kit/{SERIAL + 1}/bundle.tar')
        self.assertEqual(self.bundle()[:2], (1, 'REFUSED form\n'))
        self.assertEqual(self.net.calls, [])

    def test_each_of_size_sha_and_tree_must_equal_the_manifest_and_nothing_is_sent_otherwise(self):
        for field, value, word in (('size', len(self.tar) + 1, 'size'), ('sha256', '00' * 32, 'sha256'), ('tree', '00' * 20, 'tree')):
            self.sign_install(**{field: value})
            code, out, err = self.bundle()
            self.assertEqual((code, out.splitlines()[-1]), (1, f'REFUSED bundle-hash {word}'), field)
            self.assertEqual(err, 'fleet-kit-upload: refused bundle-hash\n')
        self.assertEqual(self.net.calls, [])
        self.assertClean()

    def test_a_head_that_is_not_on_the_remote_is_refused(self):
        self.sign_install(head='99' * 20)
        self.assertEqual(self.bundle()[:2], (1, 'REFUSED fetch\n'))
        self.assertEqual(self.net.calls, [])

    def test_a_packer_that_answers_for_another_head_is_refused(self):
        real = fk.packer.cut
        wrong = lambda repo, head, paths: real(repo, head, paths).__class__('11' * 20, self.tree, {}, {})  # noqa: E731
        with mock.patch.object(fk.packer, 'cut', wrong):
            self.assertEqual(self.bundle()[1], 'REFUSED bundle-hash head\n')

    def test_a_closure_list_that_is_malformed_or_missing_is_refused(self):
        bad = {'no final newline': b'fleet/a.txt', 'a CR': b'fleet/a.txt\r\n', 'a blank line': b'fleet/a.txt\n\nfleet/b/c.txt\n',
               'a path twice': b'fleet/a.txt\nfleet/a.txt\n', 'empty': b'', 'not utf-8': b'\xff\n', 'too big': b'x\n' * 40000}
        for name, data in bad.items():
            with self.assertRaises(fp.Refused, msg=name) as why:
                fk.parse_closure(data)
            self.assertEqual(why.exception.code, 'closure', name)
        self.assertEqual(fk.parse_closure(b'a\nb/c\n'), ['a', 'b/c'])
        git(self.origin, 'rm', '-q', 'fleet/install/closure.txt')
        git(self.origin, 'commit', '-q', '-m', 'no list')
        self.head = git(self.origin, 'rev-parse', 'HEAD')
        self.tree = git(self.origin, 'rev-parse', 'HEAD^{tree}')
        self.sign_install(head=self.head, tree=self.tree)
        self.assertEqual(self.bundle()[:2], (1, 'REFUSED closure\n'))

    def test_a_listed_path_the_packer_refuses_is_a_build_failure_that_says_nothing_more(self):
        for listed in ('fleet/missing-customer.txt', 'fleet/core/gateway.json', '../escape'):
            self.write('fleet/install/closure.txt', f'fleet/a.txt\n{listed}\n')
            git(self.origin, 'add', '-A')
            git(self.origin, 'commit', '-q', '-m', 'list')
            head, tree = git(self.origin, 'rev-parse', 'HEAD'), git(self.origin, 'rev-parse', 'HEAD^{tree}')
            self.sign_install(head=head, tree=tree)
            code, out, err = self.bundle()
            self.assertEqual((code, out, err), (1, 'REFUSED bundle-build\n', 'fleet-kit-upload: refused bundle-build\n'), listed)

    def test_an_error_inside_the_build_never_shows_its_text(self):
        with mock.patch.object(fk.packer, 'cut', side_effect=RuntimeError('private/path/customer.txt line 3')):
            code, out, err = self.bundle()
        self.assertEqual((code, out), (1, 'REFUSED bundle-build\n'))
        self.assertNotIn('customer', out + err)
        with mock.patch.object(fk, 'build_bundle', side_effect=KeyError('private/path/customer.txt')):
            code, out, err = self.bundle()
        self.assertEqual((code, out, err), (1, 'REFUSED internal\n', 'fleet-kit-upload: refused internal\n'))
        self.assertClean()

    def test_what_the_build_prints_goes_to_a_file_not_the_output(self):
        def noisy(repo, head, paths):
            print('PRIVATE-LINE on stdout')
            sys.stderr.write('PRIVATE-LINE on stderr\n')
            return real(repo, head, paths)
        real = fk.packer.cut
        with mock.patch.object(fk.packer, 'cut', noisy):
            code, out, err = self.bundle()
        self.assertEqual(code, 0)
        self.assertNotIn('PRIVATE-LINE', out + err)

    def test_a_bundle_over_the_cap_is_refused_unsent(self):
        with mock.patch.object(fk, 'MAX_UPLOAD', len(self.tar) - 1):
            self.assertEqual(self.bundle()[:2], (1, 'REFUSED bundle-size\n'))
        with mock.patch.object(fk, 'MAX_UPLOAD', len(self.tar)):
            self.assertEqual(self.bundle()[0], 0)
        self.assertEqual(len(self.net.calls), 1)

    def test_the_hosts_answers(self):
        for status, body, line in HOST_CASES:
            code, out, _ = self.bundle(net=FakeNet(self.up_pub, lambda call, s=status, b=body: (s, b)))
            self.assertEqual((code, out.splitlines()[-1]), (1, line), (status, body))
        for name, answer in {'another sha': json.dumps({'sha256': '00' * 32, 'size': len(self.tar)}).encode(),
                             'another size': json.dumps({'sha256': sha(self.tar), 'size': 1}).encode(),
                             'not json': b'ok', 'a list': b'[]', 'a string size': json.dumps({'sha256': sha(self.tar), 'size': str(len(self.tar))}).encode(),
                             'a bool size': json.dumps({'sha256': sha(self.tar), 'size': True}).encode()}.items():
            code, out, _ = self.bundle(net=FakeNet(self.up_pub, lambda call, a=answer: (200, a)))
            self.assertEqual((code, out.splitlines()[-1]), (1, 'REFUSED readback'), name)
        self.assertEqual(self.bundle(net=FakeNet(self.up_pub))[0], 0)  # an identical re-run is a 200 too

    def test_a_transport_error_is_refused_net(self):
        class Down:
            def request(self, *a):
                raise fp.Refused('net')
        code, out, _ = self.bundle(net=Down())
        self.assertEqual((code, out.splitlines()[-1]), (1, 'REFUSED net'))
        self.assertClean()

    def test_the_environment_is_all_required(self):
        for name in ('KIT_HOST', 'KIT_UPLOAD_KEY', 'FLEET_REPO', 'RUNNER_TEMP'):
            self.assertEqual(self.bundle(env=self.env(**{name: None}))[:2], (1, 'REFUSED env\n'), name)
        self.assertEqual(self.bundle(env=self.env(RUNNER_TEMP=str(self.tmp / 'nowhere')))[:2], (1, 'REFUSED env\n'))
        self.assertEqual(self.bundle(env=self.env(KIT_HOST='NOT-SET-fill-in-the-kit-host'))[:2], (1, 'REFUSED kit-host\n'))
        self.assertEqual(self.bundle(env=self.env(KIT_HOST='github.com'))[:2], (1, 'REFUSED kit-host\n'))
        for pem in ('not a key', '-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n', 'x' * 2000):
            self.assertEqual(self.bundle(env=self.env(KIT_UPLOAD_KEY=pem))[:2], (1, 'REFUSED key\n'), pem[:10])
        self.assertEqual(self.net.calls, [])
        self.assertClean()

    def test_a_key_that_is_not_ed25519_cannot_sign(self):
        ec = self.tmp / 'ec.pem'
        subprocess.run([fk.OPENSSL, 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(ec)],
                       check=True, capture_output=True)
        self.assertEqual(self.bundle(env=self.env(KIT_UPLOAD_KEY=ec.read_text()))[1].splitlines()[-1], 'REFUSED sign')
        self.assertEqual(self.net.calls, [])

    def test_the_owner_pin_is_required_and_checked_for_both_verbs(self):
        for run in (self.bundle, self.gateway):
            for pin in (None, '', 'SHA256:' + 'A' * 43, 'not a fingerprint'):
                self.assertEqual(run(env=self.env(OWNER_PIN_SHA256=pin))[:2], (1, 'REFUSED key\n'), (run.__name__, pin))
            self.assertEqual(run(env=self.env(OWNER_PIN_SHA256=self.pin))[0], 0)
        self.assertEqual(len(self.net.calls), 2)  # only the two runs with the owner's own fingerprint reached the host

    def test_the_remote_is_never_read_as_an_option(self):
        self.assertEqual(self.bundle(env=self.env(FLEET_REPO='--upload-pack=touch /tmp/x'))[:2], (1, 'REFUSED fetch\n'))


class TestBundleHygiene(Fixture):
    """What would break a real run, or the public log, without any other test noticing."""

    def cli(self, env: dict | None = None) -> subprocess.CompletedProcess:
        """The script as a process, so what a child writes to the real fd 2 is seen (redirect_stderr cannot see it)."""
        return subprocess.run([sys.executable, str(ROOT / 'bin/fleet-kit-upload.py'), 'bundle', str(self.folder), '--owner-pub', str(self.pub)],
                              capture_output=True, text=True, timeout=300, env=self.env() if env is None else env)

    def test_a_failing_fetch_says_one_line_on_the_real_stderr(self):
        self.sign_install(head='99' * 20)  # not on the remote: git itself prints "not our ref ..." to its stderr
        done = self.cli()
        self.assertEqual((done.returncode, done.stdout, done.stderr), (1, 'REFUSED fetch\n', 'fleet-kit-upload: refused fetch\n'))

    def test_a_failing_build_says_one_line_on_the_real_stderr(self):
        self.write('fleet/install/closure.txt', 'fleet/a.txt\nfleet/missing-customer.txt\n')
        git(self.origin, 'add', '-A')
        git(self.origin, 'commit', '-q', '-m', 'list')
        self.sign_install(head=git(self.origin, 'rev-parse', 'HEAD'), tree=git(self.origin, 'rev-parse', 'HEAD^{tree}'))
        done = self.cli()
        self.assertEqual((done.returncode, done.stdout, done.stderr), (1, 'REFUSED bundle-build\n', 'fleet-kit-upload: refused bundle-build\n'))

    def test_a_fetch_whose_fetch_head_is_another_commit_is_refused(self):
        real = fk.git_run
        other = (self.head[:-1] + ('0' if self.head[-1] != '0' else '1')).encode() + b'\n'
        wrong = lambda repo, env, *args, **kw: other if args[:1] == ('rev-parse',) else real(repo, env, *args, **kw)  # noqa: E731
        with mock.patch.object(fk, 'git_run', wrong):
            self.assertEqual(self.bundle()[:2], (1, 'REFUSED fetch\n'))
        self.assertEqual(self.net.calls, [])

    def test_git_gets_a_bare_environment_with_only_the_ssh_command(self):
        runner = {'KIT_UPLOAD_KEY': 'PEM-SENTINEL', 'GITHUB_TOKEN': 'T', 'GIT_DIR': '/x', 'GIT_SSH_COMMAND': 'ssh -i /k', 'PATH': '/p'}
        env = fk.git_env(runner)
        self.assertEqual(env, {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
                               'GIT_TERMINAL_PROMPT': '0', 'GIT_SSH_COMMAND': 'ssh -i /k'})
        self.assertNotIn('GIT_SSH_COMMAND', fk.git_env({'PATH': '/p'}))
        seen = []
        real = subprocess.run
        with mock.patch.object(subprocess, 'run', lambda argv, **kw: (seen.append((argv, kw.get('env'))), real(argv, **kw))[1]):
            fk.git_run(self.origin, env, 'rev-parse', 'HEAD')
        self.assertEqual(seen[0][1], env)  # exactly that, not the process's own

    def test_the_ssh_command_reaches_the_git_child(self):
        # an ssh:// remote runs GIT_SSH_COMMAND: a script that records that it ran and then fails, so the fetch is refused
        mark = self.tmp / 'ssh-ran'
        script = self.tmp / 'ssh.sh'
        script.write_text(f'#!/bin/sh\necho ran > {mark}\nexit 1\n')
        script.chmod(0o755)
        code, out, err = self.bundle(env=self.env(FLEET_REPO='ssh://git@example.invalid/x.git', GIT_SSH_COMMAND=str(script)))
        self.assertEqual((code, out, err), (1, 'REFUSED fetch\n', 'fleet-kit-upload: refused fetch\n'))
        self.assertTrue(mark.exists())

    def test_the_upload_key_is_in_no_childs_environment(self):
        pem = self.up_key.read_text()
        seen = []
        real = subprocess.run

        def spy(argv, **kw):
            seen.append(kw.get('env') if kw.get('env') is not None else dict(os.environ))
            return real(argv, **kw)
        with mock.patch.dict(os.environ, {'KIT_UPLOAD_KEY': pem}), mock.patch.object(subprocess, 'run', spy):
            code, out, _ = self.bundle()
            self.assertNotIn('KIT_UPLOAD_KEY', os.environ)  # taken out for good, not just hidden from the uploader's own git
        self.assertEqual(code, 0, out)
        self.assertGreater(len(seen), 3)  # git, ssh-keygen (several times) and openssl
        for env in seen:
            self.assertFalse(any(pem.splitlines()[1] in str(v) for v in env.values()))
            self.assertNotIn('KIT_UPLOAD_KEY', env)

    def test_the_constants_the_host_depends_on(self):
        self.assertEqual(fk.MAX_UPLOAD, 90_000_000)
        self.assertEqual((fk.MAX_SERIAL, fk.MAX_GATEWAY_SERIAL), (999_999_999, 999_999_999))  # the host's routes: one to nine digits


class TestGateway(Fixture):
    def test_uploads_the_signed_pair_as_one_request(self):
        code, out, err = self.gateway()
        self.assertEqual((code, err), (0, ''), out)
        text = git(self.origin, 'show', 'HEAD:fleet/core/gateway.json') + '\n'
        sig = (self.origin / 'fleet/core/gateway.json.sig').read_bytes()
        self.assertEqual(out, f'OK gateway serial=3 json={sha(text.encode())} sig={sha(sig)}\n')
        (call,) = self.net.calls
        self.assertEqual((call['method'], call['path']), ('PUT', '/_k/gateway/3'))
        self.assertEqual(json.loads(call['body']), {'json': base64.b64encode(text.encode()).decode(), 'sig': base64.b64encode(sig).decode()})
        self.assertTrue(self.net.signature_ok(call))
        self.assertClean()

    def commit(self, **files) -> None:
        for rel, text in files.items():
            self.write(rel, text)
        git(self.origin, 'add', '-A')
        git(self.origin, 'commit', '-q', '--allow-empty', '-m', 'edit')

    def sign_gateway(self, key: Path, namespace: str) -> None:
        (self.origin / 'fleet/core/gateway.json.sig').unlink(missing_ok=True)
        ssh_sign(key, self.origin / 'fleet/core/gateway.json', namespace)

    def test_the_pair_is_the_one_at_the_release_tip_not_an_older_one(self):
        self.write('fleet/core/gateway.json', json.dumps(self.record(4)) + '\n')
        self.sign_gateway(self.owner, fp.PIN_NS)
        self.commit()
        self.assertIn('serial=4', self.gateway()[1])

    def test_a_pair_the_owner_did_not_sign_under_the_pin_namespace_is_refused(self):
        self.commit(**{'fleet/core/gateway.json': json.dumps(self.record(5)) + '\n'})  # the old signature no longer fits
        self.assertEqual(self.gateway()[:2], (1, 'REFUSED sig\n'))
        self.sign_gateway(self.owner, fp.NS)  # right key, the install namespace
        self.commit()
        self.assertEqual(self.gateway()[:2], (1, 'REFUSED sig\n'))
        other = keygen(self.tmp, 'other')
        self.sign_gateway(other, fp.PIN_NS)
        self.commit()
        self.assertEqual(self.gateway()[:2], (1, 'REFUSED sig\n'))
        self.assertEqual(self.net.calls, [])

    def test_a_missing_pair_or_a_serial_the_host_cannot_hold_is_refused(self):
        git(self.origin, 'rm', '-q', 'fleet/core/gateway.json.sig')
        git(self.origin, 'commit', '-q', '-m', 'no sig')
        self.assertEqual(self.gateway()[:2], (1, 'REFUSED sig\n'))  # a live record and no --sig (CV05d)
        record = json.dumps(self.record(3))
        bodies = [record.replace('"serial": 3', f'"serial": {bad}') for bad in ('0', '"3"', 'true', '3000000000', '1000000000', '3.5')]
        bodies += ['{}', '[]', record.replace('"serial": 3', '"serial": 3, "serial": 4')]
        for body in bodies:
            self.write('fleet/core/gateway.json', body + '\n')
            self.sign_gateway(self.owner, fp.PIN_NS)
            self.commit()
            self.assertEqual(self.gateway()[:2], (1, 'REFUSED gateway\n'), body)
        self.write('fleet/core/gateway.json', record.replace('"serial": 3', '"serial": 999999999') + '\n')
        self.sign_gateway(self.owner, fp.PIN_NS)
        self.commit()
        self.assertEqual(self.gateway()[0], 0)  # the host's route takes up to nine digits
        self.assertEqual(self.net.calls[-1]['path'], '/_k/gateway/999999999')

    def test_a_file_signed_under_the_pin_namespace_that_is_not_a_gateway_record_is_refused(self):
        for name, doc in {'a deploy pin': {'serial': 3, 'sha256': 'ab' * 32}, 'a kit record': {'serial': 3, 'kit_json_sha256': 'ab' * 32},
                          'a record short of one key': {k: v for k, v in self.record(3).items() if k != 'session_key'}}.items():
            self.write('fleet/core/gateway.json', json.dumps(doc) + '\n')
            self.sign_gateway(self.owner, fp.PIN_NS)  # a valid owner signature under the right namespace
            self.commit()
            self.assertEqual(self.gateway()[:2], (1, 'REFUSED gateway\n'), name)
        self.assertEqual(self.net.calls, [])

    def test_the_sizes_the_host_accepts_are_the_limits(self):
        self.write('fleet/core/gateway.json', json.dumps(self.record(3, pad='x' * fk.MAX_GATEWAY_JSON)) + '\n')
        self.sign_gateway(self.owner, fp.PIN_NS)
        self.commit()
        self.assertEqual(self.gateway()[:2], (1, 'REFUSED gateway\n'))
        self.assertEqual((fk.MAX_GATEWAY_JSON, fk.MAX_GATEWAY_SIG), (65536, 4096))

    def test_the_hosts_answers(self):
        for status, body, line in HOST_CASES:
            code, out, _ = self.gateway(net=FakeNet(self.up_pub, lambda call, s=status, b=body: (s, b)))
            self.assertEqual((code, out), (1, line + '\n'), (status, body))
        for answer in ({'gserial': 4, 'json': {}, 'sig': {}}, {'gserial': 3, 'json': {'sha256': '0' * 64, 'size': 1}, 'sig': {}}, [],
                       {'ok': True, 'created': True, 'gserial': 3}):  # the last: no read-back at all
            net = FakeNet(self.up_pub, lambda c, a=answer: (200, json.dumps(a).encode()))
            self.assertEqual(self.gateway(net=net)[:2], (1, 'REFUSED readback\n'), answer)

    # the floor verb: the break-glass for a bad serial, signed by the upload key and nothing else

    def floor(self, n: str = '7', **kw):
        return self.invoke('floor', n, **kw)

    def test_the_floor_is_one_signed_put_and_nothing_of_the_fleet_is_needed(self):
        env = self.env(FLEET_REPO=None, OWNER_PIN_SHA256=None)  # no fleet repository and no owner key for a floor
        code, out, err = self.floor('7', env=env)
        self.assertEqual((code, out, err), (0, 'OK floor=7\n', ''))
        (call,) = self.net.calls
        self.assertEqual((call['method'], call['host'], call['path'], call['body']), ('PUT', HOST, '/_k/floor', b'{"floor":7}'))
        self.assertTrue(self.net.signature_ok(call))
        self.assertEqual(self.floor('0', env=env, net=FakeNet(self.up_pub))[:2], (0, 'OK floor=0\n'))

    def test_the_floor_reads_the_host_s_answer_back(self):
        for answer in ({'ok': True, 'floor': 8}, {'ok': True}, {'floor': 7}, {'ok': True, 'floor': '7'}, {'ok': True, 'floor': True},
                       {'ok': False, 'floor': 7}, []):
            net = FakeNet(self.up_pub, lambda c, a=answer: (200, json.dumps(a).encode()))
            self.assertEqual(self.floor('7', net=net)[:2], (1, 'REFUSED readback\n'), answer)
        for status, body, line in HOST_CASES:
            net = FakeNet(self.up_pub, lambda call, s=status, b=body: (s, b))
            self.assertEqual(self.floor('7', net=net)[:2], (1, line + '\n'), (status, body))

    def test_the_floor_range_is_the_hosts(self):
        self.assertEqual(fk.MAX_FLOOR, 2 ** 31)
        self.assertEqual(fk.parse_args(['x', 'floor', '0']), ('floor', 0, ''))
        self.assertEqual(fk.parse_args(['x', 'floor', str(2 ** 31)]), ('floor', 2 ** 31, ''))
        for bad in ('', '-1', '+1', '007', '01', '1.0', '1e3', 'x', '1 ', '\u0661\u0662', str(2 ** 31 + 1), '99999999999'):
            self.assertIsNone(fk.parse_args(['x', 'floor', bad]), bad)
        self.assertIsNone(fk.parse_args(['x', 'floor']))
        self.assertIsNone(fk.parse_args(['x', 'floor', '7', '8']))
        self.assertIsNone(fk.parse_args(['x', 'floor', '7', '--owner-pub', 'p']))

    def test_a_floor_without_the_key_the_host_or_a_runner_folder_is_refused_env_and_makes_no_request(self):
        for gone in ('KIT_UPLOAD_KEY', 'KIT_HOST', 'RUNNER_TEMP'):
            self.assertEqual(self.floor('7', env=self.env(**{gone: None}))[:2], (1, 'REFUSED env\n'), gone)
        self.assertEqual(self.floor('7', env=self.env(KIT_HOST='NOT-SET-fill-in-the-kit-host'))[:2], (1, 'REFUSED kit-host\n'))
        self.assertEqual(self.net.calls, [])
        self.assertEqual(list(self.shm.iterdir()), [])  # the key file is gone

    def test_the_output_shows_no_address(self):
        _, out, err = self.gateway()
        self.assertNotIn('203.0.113', out + err)


# The placeholder the fleet repository holds while no gateway is live, copied from `fleet/core/gateway.json` on its main branch
# (ledger D309). The not-live tests are built from this text, so the exact test is against the real shape.
PLACEHOLDER = ('{"serial": 0, "address": null, "cert_sha256": null, "manifest_key": null, "session_key": null, "next": null, '
               '"r9_closed": false}')
SKIP_LINE = 'SKIP gateway not-live\n'


class Boom:
    """A host that must never be asked: any request is a failure of the test (and is recorded too)."""

    def __init__(self) -> None:
        self.calls: list = []

    def request(self, *a):
        self.calls.append(a)
        raise AssertionError('the kit host was asked')


class TestGatewayNotLive(Fixture):
    """While no gateway is live the gateway step skips (D309); every other state refuses with the word it had before."""

    def setUp(self):
        super().setUp()
        self.old_sig = (self.origin / 'fleet/core/gateway.json.sig').read_bytes()  # the owner's signature of the serial 3 record

    def tip(self, text: str | None = PLACEHOLDER, sig: str | None = None) -> None:
        """The release tip's pair: `text` as gateway.json (None: no file), and gateway.json.sig as `sig` says: None no file, 'pin' a
        good owner signature, 'install' the right key in another namespace, 'stale' the fixture's old signature, 'empty' a zero-byte
        file, 'dir' a folder of that name."""
        record, sigfile = self.origin / 'fleet/core/gateway.json', self.origin / 'fleet/core/gateway.json.sig'
        shutil.rmtree(sigfile, ignore_errors=True)
        sigfile.unlink(missing_ok=True)
        if text is not None:
            record.write_text(text if text.endswith('\n') or not text else text + '\n')
        if sig == 'stale':
            sigfile.write_bytes(self.old_sig)
        elif sig == 'pin':
            ssh_sign(self.owner, record, fp.PIN_NS)
        elif sig == 'install':
            ssh_sign(self.owner, record, fp.NS)
        elif sig == 'empty':
            sigfile.write_bytes(b'')
        elif sig == 'dir':
            sigfile.mkdir()
            (sigfile / 'x').write_text('x')
        if text is None:
            record.unlink(missing_ok=True)
        git(self.origin, 'add', '-A')
        git(self.origin, 'commit', '-q', '--allow-empty', '-m', 'edit')

    def check(self, **kw):
        return self.invoke('gateway', '--check', '--owner-pub', str(self.pub), *self.sig_args(), **kw)

    def refuses(self, word: str, why: str) -> None:
        for run in (self.gateway, self.check):
            net = Boom()
            code, out, _ = run(net=net)
            self.assertEqual((code, out), (1, f'REFUSED {word}\n'), why)
            self.assertEqual(net.calls, [], why)
        self.assertClean()

    def test_the_placeholder_fixture_is_the_real_placeholder(self):
        self.assertEqual(json.loads(PLACEHOLDER), {'serial': 0, 'address': None, 'cert_sha256': None, 'manifest_key': None,
                                                   'session_key': None, 'next': None, 'r9_closed': False})
        self.assertEqual(PLACEHOLDER, '{"serial": 0, "address": null, "cert_sha256": null, "manifest_key": null, '
                                      '"session_key": null, "next": null, "r9_closed": false}')
        self.assertTrue(all(key in json.loads(PLACEHOLDER) for key in fk.GATEWAY_KEYS))
        self.assertTrue(fk.is_placeholder(PLACEHOLDER.encode()))
        self.assertTrue(fk.is_placeholder((PLACEHOLDER + '\n').encode()))

    def test_no_gateway_live_is_a_skip_and_no_request_is_made(self):
        for text in (PLACEHOLDER, PLACEHOLDER + '\n', json.dumps(json.loads(PLACEHOLDER), separators=(',', ':'))):
            self.tip(text)
            for run in (self.gateway, self.check):
                net = Boom()
                code, out, err = run(net=net)
                self.assertEqual((code, out, err), (0, SKIP_LINE, ''), text)
                self.assertEqual(net.calls, [])
                self.assertClean()
        self.assertEqual(self.net.calls, [])

    def test_a_live_pair_still_uploads_and_reads_back_and_the_check_only_judges_it(self):
        code, out, _ = self.check()
        self.assertEqual((code, out), (0, 'OK gateway-check serial=3\n'))
        self.assertEqual(self.net.calls, [])
        code, out, _ = self.gateway()
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith('OK gateway serial=3 json='))
        (call,) = self.net.calls
        self.assertEqual(call['path'], '/_k/gateway/3')
        self.assertTrue(self.net.signature_ok(call))
        self.assertClean()

    def test_the_check_needs_no_upload_key_and_never_builds_a_signer(self):
        with mock.patch.object(fk, 'Signer', side_effect=AssertionError('a signer was made')):
            code, out, _ = self.check(env=self.env(KIT_UPLOAD_KEY=None))
        self.assertEqual((code, out), (0, 'OK gateway-check serial=3\n'))
        self.tip()
        with mock.patch.object(fk, 'Signer', side_effect=AssertionError('a signer was made')):
            self.assertEqual(self.check(env=self.env(KIT_UPLOAD_KEY=None))[:2], (0, SKIP_LINE))
        self.assertEqual(self.gateway(env=self.env(KIT_UPLOAD_KEY=None))[:2], (1, 'REFUSED env\n'))  # the upload still needs it

    def test_the_check_refuses_a_bad_host_or_a_missing_environment(self):
        self.assertEqual(self.check(env=self.env(KIT_HOST='not a host'))[:2], (1, 'REFUSED kit-host\n'))
        for key in ('KIT_HOST', 'RUNNER_TEMP', 'FLEET_REPO'):
            self.assertEqual(self.check(env=self.env(**{key: None}))[:2], (1, 'REFUSED env\n'), key)
        self.assertEqual(self.check(env=self.env(OWNER_PIN_SHA256=None))[:2], (1, 'REFUSED key\n'))

    def test_a_gateway_file_that_is_missing_is_refused_not_skipped(self):
        self.tip(None, None)
        self.refuses('gateway', 'no record, no signature')
        self.tip(None, 'stale')
        self.refuses('gateway', 'a signature and no record')

    def test_a_signature_beside_a_not_live_record_is_refused(self):
        self.tip(PLACEHOLDER, 'pin')
        self.refuses('gateway', 'a signed placeholder')
        self.tip(PLACEHOLDER, 'stale')
        self.refuses('sig', 'a placeholder with a signature that does not fit')
        self.tip(PLACEHOLDER, 'install')
        self.refuses('sig', 'a placeholder signed in the wrong namespace')
        self.tip(PLACEHOLDER, 'empty')
        self.refuses('sig', 'a placeholder with an empty signature file')
        self.tip(PLACEHOLDER, 'dir')
        self.refuses('sig', 'a placeholder and a folder where the signature should be')
        self.tip(json.dumps({**json.loads(PLACEHOLDER), 'address': '203.0.113.9'}), 'pin')
        self.refuses('gateway', 'a signed serial 0 with an address')

    def test_serial_zero_with_an_address_or_a_null_address_with_a_serial_is_refused_unsigned(self):
        """With no --sig every record that is not the placeholder is `REFUSED sig` (CV05d; it was `REFUSED gateway` while the tip's own file decided)."""
        base = json.loads(PLACEHOLDER)
        for name, edit in {'serial 0 with an address': {'address': '203.0.113.9'},
                           'address null with serial 3': {'serial': 3},
                           'address null with serial 1': {'serial': 1},
                           'a live-looking record': {'serial': 3, 'address': '203.0.113.9', 'cert_sha256': 'ab' * 32}}.items():
            self.tip(json.dumps({**base, **edit}), None)
            self.refuses('sig', name)

    def test_a_record_that_only_looks_like_the_placeholder_is_refused(self):
        """End to end through both verbs, a few of each kind; the whole list is judged by is_placeholder just below."""
        base = json.loads(PLACEHOLDER)
        bodies = {'a list': '[]', 'an empty file': '', 'a bool serial': json.dumps({**base, 'serial': False}),
                  'a negative zero serial': PLACEHOLDER.replace('"serial": 0', '"serial": -0'),
                  'a filled cert_sha256': json.dumps({**base, 'cert_sha256': 'ab' * 32}),
                  'a half-edited record': json.dumps({**base, 'cert_sha256': 'ab' * 32, 'manifest_key': 'k', 'session_key': 's'}),
                  'an extra key': json.dumps({**base, 'extra': 1}),
                  'an oversized record': json.dumps({**base, 'pad': 'x' * fk.MAX_GATEWAY_JSON})}
        for name, body in bodies.items():
            self.tip(body, None)
            self.refuses('gateway' if name in ('an empty file', 'an oversized record') else 'sig', name)  # no record the host takes, or no --sig

    def test_is_placeholder_is_an_exact_match(self):
        base = json.loads(PLACEHOLDER)
        bodies = {'a list': '[]', 'null': 'null', 'a number': '0', 'a string': '"x"', 'an empty object': '{}', 'not json': 'serial 0',
                  'an empty file': '', 'a bool serial': json.dumps({**base, 'serial': False}),
                  'a float serial': json.dumps({**base, 'serial': 0.0}), 'a string serial': json.dumps({**base, 'serial': '0'}),
                  'a null serial': json.dumps({**base, 'serial': None}), 'a negative serial': json.dumps({**base, 'serial': -1}),
                  'a negative zero': PLACEHOLDER.replace('"serial": 0', '"serial": -0'),
                  'a missing address': json.dumps({k: v for k, v in base.items() if k != 'address'}),
                  'a missing key': json.dumps({k: v for k, v in base.items() if k != 'session_key'}),
                  'only the five gateway keys': json.dumps({k: v for k, v in base.items() if k in fk.GATEWAY_KEYS}),
                  'a duplicate serial': PLACEHOLDER.replace('"serial": 0', '"serial": 0, "serial": 0'),
                  'a deploy pin': json.dumps({'serial': 0, 'sha256': 'ab' * 32}),
                  'an extra key': json.dumps({**base, 'extra': 1}),
                  'false address': json.dumps({**base, 'address': False}), 'an empty address': json.dumps({**base, 'address': ''}),
                  'a filled cert_sha256': json.dumps({**base, 'cert_sha256': 'ab' * 32}),
                  'a filled manifest_key': json.dumps({**base, 'manifest_key': 'k'}),
                  'a filled session_key': json.dumps({**base, 'session_key': 's'}),
                  'next set': json.dumps({**base, 'next': {'serial': 5}}), 'r9_closed true': json.dumps({**base, 'r9_closed': True}),
                  'r9_closed 0': json.dumps({**base, 'r9_closed': 0}), 'r9_closed null': json.dumps({**base, 'r9_closed': None})}
        for name, body in bodies.items():
            self.assertFalse(fk.is_placeholder(body.encode()), name)
        self.assertFalse(fk.is_placeholder(PLACEHOLDER.encode(), '100755'), 'an executable file')
        self.assertFalse(fk.is_placeholder(PLACEHOLDER.encode(), '120000'), 'a symlink')

    def test_a_symlink_or_an_executable_record_is_refused_not_skipped(self):
        record = self.origin / 'fleet/core/gateway.json'
        self.tip(PLACEHOLDER)
        record.chmod(0o755)
        git(self.origin, 'add', '-A')
        git(self.origin, 'commit', '-q', '-m', 'mode')
        self.refuses('sig', 'mode 100755')
        record.chmod(0o644)
        record.unlink()
        (self.origin / 'fleet/core/target.json').write_text(PLACEHOLDER + '\n')
        record.symlink_to('target.json')
        git(self.origin, 'add', '-A')
        git(self.origin, 'commit', '-q', '-m', 'symlink')
        self.refuses('sig', 'mode 120000')

    def test_a_signed_record_with_a_null_address_and_a_serial_is_judged_live_as_before(self):
        self.tip(json.dumps({**json.loads(PLACEHOLDER), 'serial': 3}), 'pin')
        self.assertEqual(self.check()[:2], (0, 'OK gateway-check serial=3\n'))
        code, out, _ = self.gateway()
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith('OK gateway serial=3 json='))
        self.assertEqual(len(self.net.calls), 1)

    def test_a_git_failure_while_reading_the_tip_refuses_and_never_skips(self):
        self.tip(PLACEHOLDER)
        real = fk.git_run
        listing = ('ls-tree', fk.FLEET_TIP, '--', fk.GATEWAY_PATH)

        def failing(repo, env, *args, **kw):
            if args == listing:
                raise fk.Refused('fetch')
            return real(repo, env, *args, **kw)

        def strange(repo, env, *args, **kw):
            return b'something else\n' if args == listing else real(repo, env, *args, **kw)

        for name, replacement in (('ls-tree fails', failing), ('ls-tree answers something unexpected', strange)):
            with mock.patch.object(fk, 'git_run', replacement):
                self.refuses('gateway', name)

    def test_the_tips_own_signature_file_is_never_asked_for_in_any_state(self):
        """CV05d: no git call of the verb names fleet/core/gateway.json.sig, whether the record is live, the placeholder or absent, and
        whether a --sig is given or not."""
        real, asked = fk.git_run, []

        def spy(repo, env, *args, **kw):
            asked.append(args)
            return real(repo, env, *args, **kw)

        sig = self.tmp / 'given.sig'
        sig.write_bytes(b'x')
        with mock.patch.object(fk, 'git_run', spy):
            for text, sigkind in ((PLACEHOLDER, 'pin'), (PLACEHOLDER, None), (json.dumps(self.record(3)), 'pin'), (json.dumps(self.record(3)), None), (None, 'pin')):
                self.tip(text, sigkind)
                for extra in ((), ('--sig', str(sig))):
                    for verb in (('gateway',), ('gateway', '--check')):
                        self.invoke(*verb, '--owner-pub', str(self.pub), *extra, net=Boom())
        self.assertGreater(len(asked), 20)
        self.assertEqual([a for a in asked if any(fk.GATEWAY_SIG_PATH in str(x) or str(x).endswith('.sig') for x in a)], [])
        self.assertIn(('ls-tree', fk.FLEET_TIP, '--', fk.GATEWAY_PATH), asked)  # control: the spy sees the record's own listing

    def test_the_placeholder_is_a_skip_whatever_signature_file_the_tip_holds_beside_it(self):
        for kind in ('pin', 'install', 'stale', 'empty', 'dir'):
            self.tip(PLACEHOLDER, kind)
            for verb in (('gateway',), ('gateway', '--check')):
                net = Boom()
                self.assertEqual(self.invoke(*verb, '--owner-pub', str(self.pub), net=net), (0, SKIP_LINE, ''), kind)  # no --sig: the tip's file is not read
                self.assertEqual(net.calls, [])
        self.assertClean()

    def test_a_live_looking_record_with_no_sig_option_is_refused_sig_whatever_the_tip_holds_beside_it(self):
        live = json.dumps(self.record(3))
        for kind in (None, 'pin', 'install', 'stale', 'empty', 'dir'):
            self.tip(live, kind)
            for verb in (('gateway',), ('gateway', '--check')):
                net = Boom()
                self.assertEqual(self.invoke(*verb, '--owner-pub', str(self.pub), net=net)[:2], (1, 'REFUSED sig\n'), (kind, verb))
                self.assertEqual(net.calls, [])
        self.assertClean()

    def test_a_live_looking_record_without_a_signature_or_with_a_bad_one_is_refused(self):
        live = json.dumps(self.record(3))
        self.tip(live, None)
        self.refuses('sig', 'no signature')
        self.tip(json.dumps(self.record(4)), 'stale')  # the stale signature is of the serial 3 record
        self.refuses('sig', 'a signature of other bytes')
        self.tip(live, 'install')
        self.refuses('sig', 'the wrong namespace')
        self.tip(live, 'empty')
        self.refuses('sig', 'an empty signature')
        self.tip(live, 'dir')
        self.refuses('sig', 'a folder of that name')

    def test_the_check_never_uploads_in_any_state(self):
        base = json.loads(PLACEHOLDER)
        states = [(PLACEHOLDER, None), (PLACEHOLDER, 'pin'), (json.dumps(self.record(3)), 'pin'), (json.dumps(self.record(3)), None),
                  (json.dumps({**base, 'serial': 3}), None), (None, None), ('[]', None), (json.dumps(self.record(4)), 'pin')]
        for text, sig in states:
            self.tip(text, sig)
            net = Boom()
            self.check(net=net)
            self.assertEqual(net.calls, [], (text, sig))
            self.assertEqual(self.net.calls, [])

    def test_the_usage_of_the_check(self):
        self.assertEqual(fk.parse_args(['x', 'gateway', '--check', '--owner-pub', 'p']), ('gateway-check', None, 'p'))
        for argv in (['gateway', '--check'], ['gateway', '--check', '--owner-pub'], ['gateway', '--owner-pub', 'p', '--check'],
                     ['gateway', '--check', 'p'], ['gateway', '--check', '--owner-pub', 'p', 'q']):
            with redirect_stderr(io.StringIO()):
                self.assertEqual(fk.main(['x', *argv], {}), 2, argv)

    def test_the_skip_line_is_one_fixed_string(self):
        self.assertEqual(fk.NOT_LIVE, 'SKIP gateway not-live')


class TestGatewayCiSignature(Fixture):
    """`gateway [--check] --owner-pub P --sig FILE` (AF08, the owner's answer of 2026-10-21 to D311: the test series' CI signs the
    record for the kit host). P is the baked key's public line here, the key the job `gwsign` signs with; the fixture's tip holds a
    signature of ANOTHER key (the one the control VM trusts), which must neither be needed nor rescue a bad FILE."""

    def setUp(self):
        super().setUp()
        self.ci = keygen(self.tmp, 'ci')
        self.pub = self.tmp / 'baked.pub'  # the baked key's public line: what the kit job verifies under
        self.pub.write_bytes(Path(str(self.ci) + '.pub').read_bytes())
        self.pin = subprocess.run([fp.SSH_KEYGEN, '-l', '-f', str(self.pub)], capture_output=True, text=True).stdout.split()[1]
        self.record_bytes = git(self.origin, 'show', 'HEAD:fleet/core/gateway.json').encode() + b'\n'
        self.tip_sig = (self.origin / 'fleet/core/gateway.json.sig').read_bytes()  # signed by self.owner, not by the baked key

    def sig_file(self, key: Path | None = None, namespace: str = fp.PIN_NS, body: bytes | None = None) -> Path:
        """What the job `gwsign` makes: ssh-keygen -Y sign of the record's bytes, the armor in a file of its own."""
        folder = Path(tempfile.mkdtemp(prefix='sig-', dir=self.tmp))
        record = folder / 'gateway.json'
        record.write_bytes(self.record_bytes if body is None else body)
        ssh_sign(key or self.ci, record, namespace)
        return folder / 'gateway.json.sig'

    def drop_tip_sig(self) -> None:
        git(self.origin, 'rm', '-q', 'fleet/core/gateway.json.sig')
        git(self.origin, 'commit', '-q', '-m', 'no signature at the tip')

    def with_sig(self, sig: Path | str, check: bool = False, **kw):
        head = ('gateway', '--check') if check else ('gateway',)
        return self.invoke(*head, '--owner-pub', str(self.pub), '--sig', str(sig), **kw)

    def check(self, **kw):
        return self.invoke('gateway', '--check', '--owner-pub', str(self.pub), **kw)

    def refuses_sig(self, sig: Path | str, word: str, why: str) -> None:
        for check in (False, True):
            net = Boom()
            code, out, _ = self.with_sig(sig, check, net=net)
            self.assertEqual((code, out), (1, f'REFUSED {word}\n'), (why, check))
            self.assertEqual(net.calls, [], (why, check))
        self.assertClean()

    def test_a_pair_signed_as_gwsign_signs_it_is_uploaded_with_the_ci_signature(self):
        sig = self.sig_file()
        code, out, err = self.with_sig(sig)
        ci_sig = sig.read_bytes()
        self.assertEqual((code, err), (0, ''), out)
        self.assertEqual(out, f'OK gateway serial=3 json={sha(self.record_bytes)} sig={sha(ci_sig)}\n')
        (call,) = self.net.calls
        self.assertEqual((call['method'], call['path']), ('PUT', '/_k/gateway/3'))
        self.assertEqual(json.loads(call['body']), {'json': base64.b64encode(self.record_bytes).decode(),
                                                    'sig': base64.b64encode(ci_sig).decode()})
        self.assertNotEqual(ci_sig, self.tip_sig)  # the tip's signature is not what went up
        self.assertTrue(self.net.signature_ok(call))
        self.assertClean()

    def test_the_tip_may_hold_no_signature_at_all(self):
        self.drop_tip_sig()
        sig = self.sig_file()
        code, out, _ = self.with_sig(sig)
        self.assertEqual((code, out[:20]), (0, 'OK gateway serial=3 '), out)
        self.assertEqual(json.loads(self.net.calls[0]['body'])['sig'], base64.b64encode(sig.read_bytes()).decode())
        self.assertEqual(self.with_sig(sig, True, net=Boom())[:2], (0, 'OK gateway-check serial=3\n'))

    def test_the_check_with_a_good_signature_is_ok_and_asks_nobody(self):
        net = Boom()
        self.assertEqual(self.with_sig(self.sig_file(), True, net=net)[:2], (0, 'OK gateway-check serial=3\n'))
        self.assertEqual((net.calls, self.net.calls), ([], []))
        self.assertClean()

    def test_without_the_option_a_live_record_is_refused_sig_and_the_tips_own_signature_is_not_read(self):
        # CV05d: it was judged before. The same tip without --sig carries another key's signature: REFUSED sig, as it did
        self.assertEqual(self.invoke('gateway', '--owner-pub', str(self.pub), net=Boom())[:2], (1, 'REFUSED sig\n'))
        self.assertEqual(self.check(net=Boom())[:2], (1, 'REFUSED sig\n'))
        # and a tip signature the baked key made, in the pin namespace (which the verb once took), no longer rescues it
        (self.origin / 'fleet/core/gateway.json.sig').write_bytes(self.sig_file().read_bytes())
        git(self.origin, 'add', '-A')
        git(self.origin, 'commit', '-q', '-m', 'a good pin signature at the tip')
        for verb in (('gateway',), ('gateway', '--check')):
            self.assertEqual(self.invoke(*verb, '--owner-pub', str(self.pub), net=Boom())[:2], (1, 'REFUSED sig\n'), verb)
        self.assertEqual(self.net.calls, [])

    def test_a_tip_signature_in_the_control_namespace_is_ignored_and_the_file_in_the_pin_namespace_passes(self):
        CTL = 'mirrorstack-fleet-' + 'ctl'  # what CV05e puts at the tip: the same key, another namespace; the verb must not touch it
        tip = self.origin / 'fleet/core/gateway.json'
        (self.origin / 'fleet/core/gateway.json.sig').unlink()
        ssh_sign(self.ci, tip, CTL)
        git(self.origin, 'add', '-A')
        git(self.origin, 'commit', '-q', '-m', 'a control namespace signature at the tip')
        self.assertIn(b'BEGIN SSH SIGNATURE', (self.origin / 'fleet/core/gateway.json.sig').read_bytes())
        sig = self.sig_file()
        for check in (True, False):
            code, out, err = self.with_sig(sig, check, net=Boom() if check else None)
            self.assertEqual((code, err), (0, ''), out)
            self.assertTrue(out.startswith('OK gateway-check serial=3' if check else 'OK gateway serial=3 json='), out)
        self.assertEqual(json.loads(self.net.calls[0]['body'])['sig'], base64.b64encode(sig.read_bytes()).decode())  # gwsign's, not the tip's
        self.assertEqual(self.check(net=Boom())[:2], (1, 'REFUSED sig\n'))  # with no --sig, the control signature does not stand in

    def test_a_signature_by_another_key_is_refused_sig(self):
        self.refuses_sig(self.sig_file(key=self.owner), 'sig', 'the control key')
        self.refuses_sig(self.sig_file(key=keygen(self.tmp, 'other')), 'sig', 'a stranger')

    def test_a_signature_in_the_install_namespace_is_refused_sig(self):
        self.refuses_sig(self.sig_file(namespace=fp.NS), 'sig', 'wrong namespace')

    def test_a_signature_over_other_bytes_is_refused_sig(self):
        other = json.dumps(self.record(4)).encode() + b'\n'
        self.refuses_sig(self.sig_file(body=other), 'sig', 'another record')
        self.refuses_sig(self.sig_file(body=self.record_bytes + b' '), 'sig', 'one more byte')

    def test_a_good_signature_at_the_tip_does_not_rescue_a_bad_file(self):
        (self.origin / 'fleet/core/gateway.json.sig').write_bytes(self.sig_file().read_bytes())  # the tip now holds a good CI signature
        git(self.origin, 'add', '-A')
        git(self.origin, 'commit', '-q', '-m', 'ci signature at the tip')
        self.assertEqual(self.check()[:2], (1, 'REFUSED sig\n'))  # control: that tip's signature is not read without --sig either (CV05d)
        self.refuses_sig(self.sig_file(key=self.owner), 'sig', 'bad file, good tip')
        self.refuses_sig(self.sig_file(namespace=fp.NS), 'sig', 'wrong namespace file, good tip')

    def test_a_file_that_is_missing_empty_over_the_cap_or_a_folder_is_refused_sig(self):
        self.refuses_sig(self.tmp / 'no-such-file', 'sig', 'missing')
        empty = self.tmp / 'empty.sig'
        empty.write_bytes(b'')
        self.refuses_sig(empty, 'sig', 'empty')
        big = self.tmp / 'big.sig'
        big.write_bytes(b'x' * (fk.MAX_GATEWAY_SIG + 1))
        self.refuses_sig(big, 'sig', 'over the cap')
        self.refuses_sig(self.tmp, 'sig', 'a folder')
        edge = self.tmp / 'edge.sig'
        edge.write_bytes(b'x' * fk.MAX_GATEWAY_SIG)
        self.refuses_sig(edge, 'sig', 'at the cap but not a signature')

    def test_a_not_live_or_unreadable_record_is_never_a_skip_with_a_file(self):
        placeholder = (PLACEHOLDER + '\n').encode()
        (self.origin / 'fleet/core/gateway.json').write_bytes(placeholder)
        git(self.origin, 'add', '-A')
        git(self.origin, 'commit', '-q', '-m', 'placeholder')
        self.refuses_sig(self.sig_file(body=b'x\n'), 'sig', 'a placeholder, a signature of other bytes')
        self.refuses_sig(self.sig_file(body=placeholder), 'gateway', 'a signed placeholder')
        git(self.origin, 'rm', '-q', 'fleet/core/gateway.json')
        git(self.origin, 'commit', '-q', '-m', 'no record')
        self.refuses_sig(self.sig_file(), 'gateway', 'no record at the tip')

    def test_the_usage_of_the_file_option(self):
        want = {('gateway', '--owner-pub', 'p', '--sig', 'f'): ('gateway', Path('f'), 'p'),
                ('gateway', '--check', '--owner-pub', 'p', '--sig', 'f'): ('gateway-check', Path('f'), 'p'),
                ('gateway', '--owner-pub', 'p'): ('gateway', None, 'p'),
                ('gateway', '--check', '--owner-pub', 'p'): ('gateway-check', None, 'p')}
        for argv, parsed in want.items():
            self.assertEqual(fk.parse_args(['x', *argv]), parsed, argv)
        for argv in (['gateway', '--owner-pub', 'p', '--sig'], ['gateway', '--sig', 'f', '--owner-pub', 'p'],
                     ['gateway', '--owner-pub', 'p', '--sig', ''], ['gateway', '--check', '--owner-pub', 'p', '--sig', 'f', 'g'],
                     ['bundle', 'd', '--owner-pub', 'p', '--sig', 'f'], ['floor', '7', '--sig', 'f'],
                     ['gateway', '--owner-pub', 'p', '--sigs', 'f'], ['gateway', '--owner-pub', 'p', 'q', 'f']):
            self.assertIsNone(fk.parse_args(['x', *argv]), argv)
            with redirect_stderr(io.StringIO()):
                self.assertEqual(fk.main(['x', *argv], {}), 2, argv)


@unittest.skipUnless(OPENSSL, 'no openssl with Ed25519 raw signing')
class TestSigner(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='kit-signer-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.shm = self.tmp / 'shm'
        self.shm.mkdir()
        self.pem = self.tmp / 'k.pem'
        subprocess.run([fk.OPENSSL, 'genpkey', '-algorithm', 'ed25519', '-out', str(self.pem)], check=True, capture_output=True)
        patch = mock.patch.object(fk, 'SHM', str(self.shm))
        patch.start()
        self.addCleanup(patch.stop)

    def test_the_message_is_the_documented_one_byte_for_byte(self):
        self.assertEqual(fk.message('upload', 1760000000000, 'PUT', '/_k/file/7/bundle.tar', 'ab' * 32),
                         b'kit-admin-v1\nupload\n1760000000000\nPUT\n/_k/file/7/bundle.tar\n' + b'ab' * 32)

    def test_the_key_file_is_private_and_gone_after_close(self):
        signer = fk.Signer(self.pem.read_text())
        self.assertEqual(signer.key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(signer.dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(signer.dir.parent, self.shm)
        signer.sign('POST', '/p', b'body')
        self.assertEqual(sorted(p.name for p in signer.dir.iterdir()), ['key'])  # the message and the signature are wiped at once
        signer.close()
        self.assertEqual(list(self.shm.iterdir()), [])

    def test_the_header_is_the_workers_grammar_and_the_default_clock_is_epoch_milliseconds(self):
        signer = fk.Signer(self.pem.read_text())
        self.addCleanup(signer.close)
        before = time.time() * 1000
        auth = signer.sign('PUT', '/_k/file/7/bundle.tar', b'x')['Authorization']
        after = time.time() * 1000
        match = AUTH.fullmatch(auth)  # the Worker takes this form and no other (13 to 16 digits, 128 hex)
        self.assertIsNotNone(match, auth)
        self.assertEqual(match.group(1), 'upload')
        self.assertEqual(len(match.group(2)), 13)
        self.assertTrue(before - 1 <= int(match.group(2)) <= after + 1)

    def test_the_time_rises_even_when_the_clock_does_not(self):
        signer = fk.Signer(self.pem.read_text(), now_ms=lambda: 5000)
        self.addCleanup(signer.close)
        stamps = [int(signer.sign('PUT', '/p', b'')['Authorization'].split()[2]) for _ in range(3)]
        self.assertEqual(stamps, [5000, 5001, 5002])

    def test_openssl_failing_is_sign_and_the_argument_list_holds_no_key(self):
        seen = []

        def fake(argv, **kw):
            seen.append(argv)
            return subprocess.CompletedProcess(argv, 1, b'', b'')
        signer = fk.Signer(self.pem.read_text(), run=fake)
        self.addCleanup(signer.close)
        with self.assertRaises(fp.Refused) as why:
            signer.sign('PUT', '/p', b'')
        self.assertEqual(why.exception.code, 'sign')
        self.assertNotIn(self.pem.read_text().splitlines()[1], ' '.join(seen[0]))
        self.assertEqual(seen[0][:4], [fk.OPENSSL, 'pkeyutl', '-sign', '-rawin'])


class TestVendoredPacker(unittest.TestCase):
    """vendor/bundle.py is the fleet repository's file byte for byte: its pin and its stand-ins' pin, frozen here."""

    def test_the_vendored_file_is_the_one_its_pin_names_and_the_uploader_runs_that_file(self):
        data, pin = (ROOT / 'vendor/bundle.py').read_bytes(), (ROOT / 'vendor/VENDORED.sha256').read_bytes()
        self.assertEqual(pin, sha(data).encode() + b'\n')
        stand_ins = {rel: (ROOT / 'vendor/standin-bundle' / rel).read_bytes() for rel in fk._PACKER_STAND_IN_FILES}
        self.assertEqual((ROOT / 'vendor/standin-bundle.sha256').read_bytes(), fk.packer_stand_in_digest(stand_ins).encode() + b'\n')
        self.assertEqual(fk._PACKER_STAND_IN_FILES, ('fleet/__init__.py', 'fleet/core/__init__.py', 'fleet/core/git.py',
                                                     'fleet/install/__init__.py', 'fleet/install/files.py'))
        self.assertEqual(fk.packer.__file__, str(ROOT / 'vendor/bundle.py'))
        self.assertNotIn('fleet', sys.modules)  # the stand-ins are in the module table only while the copy loads
        self.assertNotIn('fleet_bundle', sys.modules)

    def test_the_manifest_pin_is_a_different_file(self):
        self.assertNotEqual((ROOT / 'vendor/VENDORED.sha256').read_bytes(), (ROOT / 'vendor/manifest.sha256').read_bytes())

    def copy(self, edit=None, pin=None, stand_in_edit=None, stand_in_pin=None) -> Path:
        root = Path(tempfile.mkdtemp(prefix='packer-copy-'))
        self.addCleanup(shutil.rmtree, root, True)
        shutil.copytree(ROOT / 'vendor', root / 'vendor')
        if edit:
            data = edit((root / 'vendor/bundle.py').read_bytes())
            (root / 'vendor/bundle.py').write_bytes(data)
            (root / 'vendor/VENDORED.sha256').write_bytes(pin if pin is not None else sha(data).encode() + b'\n')
        elif pin is not None:
            (root / 'vendor/VENDORED.sha256').write_bytes(pin)
        if stand_in_edit:
            path = root / 'vendor/standin-bundle/fleet/core/git.py'
            path.write_bytes(stand_in_edit(path.read_bytes()))
        if stand_in_pin is not None:
            (root / 'vendor/standin-bundle.sha256').write_bytes(stand_in_pin)
        return root / 'vendor'

    def test_an_unpinned_change_to_the_copy_or_its_stand_ins_is_refused(self):
        good = fk.load_packer(self.copy())
        self.assertEqual(good.MAX_TAR, 1 << 28)
        original = sha((ROOT / 'vendor/bundle.py').read_bytes()).encode() + b'\n'
        for name, root in {
                'a changed byte, old pin': self.copy(edit=lambda d: d.replace(b'MAX_TAR = 1 << 28', b'MAX_TAR = 1 << 29'), pin=original),
                'a changed stand-in, old pin': self.copy(stand_in_edit=lambda d: d.replace(b'core.fsmonitor=false', b'core.fsmonitor=true')),
                'no newline': self.copy(pin=original[:-1]),
                'upper case': self.copy(pin=original.upper()),
                'two lines': self.copy(pin=original + b'\n'),
                'the manifest pin': self.copy(pin=(ROOT / 'vendor/manifest.sha256').read_bytes()),
                'the stand-in pin on the copy': self.copy(stand_in_pin=original),
                'a stand-in pin without newline': self.copy(stand_in_pin=(ROOT / 'vendor/standin-bundle.sha256').read_bytes()[:-1])}.items():
            with self.assertRaises(ValueError, msg=name):
                fk.load_packer(root)
        missing = self.copy()
        (missing / 'VENDORED.sha256').unlink()
        with self.assertRaises(ValueError):
            fk.load_packer(missing)
        missing = self.copy()
        (missing / 'standin-bundle/fleet/install/files.py').unlink()
        with self.assertRaises(ValueError):
            fk.load_packer(missing)

    def test_a_vendor_mismatch_stops_the_script_with_the_refusal_line(self):
        root = Path(tempfile.mkdtemp(prefix='packer-run-'))
        self.addCleanup(shutil.rmtree, root, True)
        shutil.copytree(ROOT / 'bin', root / 'bin', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(ROOT / 'vendor', root / 'vendor')
        (root / 'vendor/bundle.py').write_bytes((ROOT / 'vendor/bundle.py').read_bytes() + b'\n# changed\n')
        done = subprocess.run([sys.executable, str(root / 'bin/fleet-kit-upload.py'), 'bundle', 'x', '--owner-pub', 'y'],
                              capture_output=True, text=True, timeout=60, env={'PATH': '/usr/bin:/bin'})
        self.assertEqual((done.returncode, done.stdout, done.stderr), (1, 'REFUSED vendor\n', 'fleet-kit-upload: refused vendor\n'))

    def test_the_copy_is_the_packer_of_the_fleet_frozen(self):
        p = fk.packer
        self.assertEqual((p.FILE_MODES, p.MAX_TAR), (('100644', '100755'), 1 << 28))
        self.assertEqual(sorted(n for n in dir(p) if not n.startswith('_') and callable(getattr(p, n)) and getattr(p, n).__module__ == 'fleet_bundle'),
                         ['BundleError', 'Closure', 'cut', 'denied', 'names', 'pack', 'rows', 'shown', 'words'])

    def test_pack_bytes_are_frozen(self):
        """The same closure gives the same tar on every Python the tests run on: a drift here is a drift in every bundle."""
        closure = fk.packer.Closure('a' * 40, 'b' * 40, {'c' * 40: b'tree-body'}, {'fleet/x.txt': b'hello\n', 'fleet/y.txt': b''})
        tar = fk.packer.pack(closure)
        self.assertEqual((len(tar), sha(tar)), (10240, GOLDEN_PACK))
        self.assertEqual(fk.packer.pack(closure), tar)

    def test_the_stand_ins_say_what_the_copy_needs(self):
        root = ROOT / 'vendor/standin-bundle/fleet'
        self.assertEqual((root / 'install/files.py').read_text().count("NEVER = ('gateway.json',)"), 1)
        self.assertEqual(fk.packer.NEVER, ('gateway.json',))
        git_text = (root / 'core/git.py').read_text()
        for flag in ("'core.fsmonitor=false'", "'core.quotePath=false'", 'core.hooksPath=', "'GIT_TERMINAL_PROMPT'"):
            self.assertIn(flag, git_text)
        self.assertNotIn('stderr.decode', git_text)  # git's own words never reach an error
        self.assertEqual([p.stat().st_size for p in (root / '__init__.py', root / 'core/__init__.py', root / 'install/__init__.py')], [0, 0, 0])

    def test_the_stand_in_git_error_names_the_verb_and_the_status_only(self):
        ns = {'__file__': str(ROOT / 'vendor/standin-bundle/fleet/core/git.py')}
        exec(compile((ROOT / 'vendor/standin-bundle/fleet/core/git.py').read_bytes(), 'git.py', 'exec'), ns)
        seen = []

        def runner(argv, **kw):
            seen.append(argv)
            return subprocess.CompletedProcess(argv, 128, b'', b'fatal: bad object private/customer.txt')
        with self.assertRaises(ns['GitError']) as why:
            ns['Git'](ROOT, runner=runner).run('cat-file', 'blob', 'x')
        self.assertEqual(str(why.exception), 'git cat-file failed (exit 128)')
        self.assertEqual(seen[0][0], 'git')
        self.assertIn('core.fsmonitor=false', seen[0])

    def test_gitattributes_keeps_every_vendored_file_out_of_line_ending_rewrites(self):
        lines = set((ROOT / '.gitattributes').read_text().split('\n'))
        for want in ('vendor/bundle.py -text', 'vendor/VENDORED.sha256 -text', 'vendor/standin-bundle.sha256 -text',
                     'vendor/standin-bundle/** -text'):
            self.assertIn(want, lines)


class TestScript(unittest.TestCase):
    """The file itself: its command line, its codes, and that it prints nothing it should not."""

    SRC = (ROOT / 'bin/fleet-kit-upload.py').read_text(encoding='utf-8')

    def test_usage_is_exit_2(self):
        for argv in ([], ['bundle'], ['bundle', 'd'], ['bundle', 'd', '--owner-pub'], ['gateway'], ['gateway', 'd', '--owner-pub', 'p'],
                     ['upload', 'd', '--owner-pub', 'p'], ['bundle', 'd', '--pub', 'p']):
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(fk.main(['x', *argv], {}), 2, argv)
            self.assertTrue(err.getvalue().startswith('usage: fleet-kit-upload.py'))
        self.assertEqual(fk.parse_args(['x', 'bundle', 'd', '--owner-pub', 'p']), ('bundle', Path('d'), 'p'))
        self.assertEqual(fk.parse_args(['x', 'gateway', '--owner-pub', 'p']), ('gateway', None, 'p'))
        for argv in (['floor'], ['floor', 'x'], ['floor', '-1'], ['floor', '1', '2']):
            with redirect_stderr(io.StringIO()):
                self.assertEqual(fk.main(['x', *argv], {}), 2, argv)

    def test_a_bare_environment_is_refused_env_before_anything_runs(self):
        done = subprocess.run([sys.executable, str(ROOT / 'bin/fleet-kit-upload.py'), 'gateway', '--owner-pub', '/nonexistent'],
                              capture_output=True, text=True, timeout=60, env={'PATH': '/usr/bin:/bin'})
        self.assertEqual((done.returncode, done.stdout, done.stderr), (1, 'REFUSED env\n', 'fleet-kit-upload: refused env\n'))

    def test_every_refusal_word_the_script_can_say_is_in_the_list(self):
        said = set(re.findall(r"Refused\('([a-z0-9-]+)(?: [^']*)?'\)", self.SRC)) | {'upload'}
        said |= {w.split()[0] for w in re.findall(r"Refused\(f?'([a-z-]+)[ {']", self.SRC)}
        self.assertEqual(sorted(said - set(fk.CODES) - {'form', 'key', 'kit-host', 'sig'}), [])
        self.assertEqual(fk.CODES, ('vendor', 'args', 'env', 'key', 'install', 'kit-host', 'fetch', 'closure', 'bundle-build',
                                    'bundle-hash', 'bundle-size', 'gateway', 'sig', 'sign', 'net', 'upload', 'conflict',
                                    'replay', 'rollback', 'revoked', 'readback', 'internal'))

    def test_the_script_prints_no_traceback_and_no_value(self):
        self.assertNotIn('traceback', self.SRC.lower())
        self.assertNotIn('print_exc', self.SRC)
        for n, line in enumerate(self.SRC.splitlines(), 1):
            if 'print(' in line:
                self.assertRegex(line, r"print\((f'(kit bundle|REFUSED \{why\.code\}|)|line\)|'REFUSED (vendor|internal)'\))", f'line {n}')

    def test_the_public_files_name_no_internal_id_or_private_name(self):
        ids = re.compile(r'\bI\d{2}[a-z]?\b|\bH\d{1,2}\b|\bP\+|\xa7')  # a plan id, a section sign
        banned = re.compile('private ' + 'repo\\b|pho' + 'ne|mirrorstack-fleet-' + 'ctl', re.I)
        for rel in ('bin/fleet-kit-upload.py', 'tests/test_kit_upload.py', 'vendor/standin-bundle/fleet/core/git.py',
                    'vendor/standin-bundle/fleet/install/files.py'):
            for n, line in enumerate((ROOT / rel).read_text(encoding='utf-8').splitlines(), 1):
                self.assertIsNone(ids.search(line), f'{rel}:{n}')
                self.assertIsNone(banned.search(line), f'{rel}:{n}')

    def test_no_secret_shape_is_in_the_files(self):
        shapes = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=]{20,}|ghp_[A-Za-z0-9]{20,}|[0-9a-f]{40}.*token', re.I)
        for rel in ('bin/fleet-kit-upload.py', 'tests/test_kit_upload.py', 'README.md'):
            self.assertIsNone(shapes.search((ROOT / rel).read_text(encoding='utf-8')), rel)

    def test_the_wipe_overwrites_and_removes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'f'
            path.write_bytes(b'x' * 3_000_000)
            seen = []
            real_unlink = Path.unlink
            with mock.patch.object(Path, 'unlink', lambda self, *a, **k: (seen.append(self.read_bytes()), real_unlink(self, *a, **k))):
                fk.wipe(path)
            self.assertEqual(seen, [bytes(3_000_000)])
            self.assertFalse(path.exists())
            fk.wipe(path)  # gone already: fine
            root = Path(tmp) / 'd'
            (root / 'a/b').mkdir(parents=True)
            (root / 'a/b/f').write_bytes(b'k')
            fk.wipe_tree(root)
            self.assertFalse(root.exists())

    def test_the_wipe_zeroes_a_read_only_file_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'object'
            path.write_bytes(b'secret' * 100)
            path.chmod(0o444)  # as git writes its objects
            seen = []
            real_unlink = Path.unlink
            with mock.patch.object(Path, 'unlink', lambda self, *a, **k: (seen.append(self.read_bytes()), real_unlink(self, *a, **k))):
                fk.wipe_tree(Path(tmp))
            self.assertEqual(seen, [bytes(600)])


if __name__ == '__main__':
    unittest.main()
