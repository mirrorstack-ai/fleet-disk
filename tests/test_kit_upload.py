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


class FakeNet:
    """The kit host: it records every request and answers from `answer` (a function of the request) or the right readback."""

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
            return 200, json.dumps({'sha256': sha(body), 'size': len(body)}).encode()
        doc = json.loads(body)
        text, sig = base64.b64decode(doc['json']), base64.b64decode(doc['sig'])
        return 200, json.dumps({'gserial': int(path.rsplit('/', 1)[1]), 'json': {'sha256': sha(text), 'size': len(text)},
                                'sig': {'sha256': sha(sig), 'size': len(sig)}}).encode()

    def signature_ok(self, call: dict) -> bool:
        """Does the Authorization header's signature verify, with the public key, over exactly the documented message."""
        scheme, _, token = call['headers']['Authorization'].partition(' ')
        role, ts, sig = token.split('.')
        want = fk.message(role, int(ts), call['method'], call['path'], sha(call['body']))
        sig_bytes = base64.urlsafe_b64decode(sig + '=' * (-len(sig) % 4))
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
        self.write('fleet/core/gateway.json', json.dumps({'serial': 3, 'address': '203.0.113.9'}) + '\n')
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
               'RUNNER_TEMP': str(self.runner), 'PATH': os.environ['PATH']}
        env.update(over)
        return {k: v for k, v in env.items() if v is not None}

    def invoke(self, *argv: str, env: dict | None = None, net=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = fk.main(['x', *argv], self.env() if env is None else env, self.net if net is None else net)
        return code, out.getvalue(), err.getvalue()

    def bundle(self, **kw):
        return self.invoke('bundle', str(self.folder), '--owner-pub', str(self.pub), **kw)

    def gateway(self, **kw):
        return self.invoke('gateway', '--owner-pub', str(self.pub), **kw)

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
        stamps = [int(c['headers']['Authorization'].split()[1].split('.')[1]) for c in self.net.calls]
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
        cases = ((409, b'', 'REFUSED conflict'), (404, b'not found\n', 'REFUSED upload 404'), (503, b'', 'REFUSED upload 503'),
                 (302, b'', 'REFUSED upload 302'))
        for status, body, line in cases:
            code, out, _ = self.bundle(net=FakeNet(self.up_pub, lambda call, s=status, b=body: (s, b)))
            self.assertEqual((code, out.splitlines()[-1]), (1, line), status)
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

    def test_the_owner_pin_is_checked_when_set(self):
        self.assertEqual(self.bundle(env=self.env(OWNER_PIN_SHA256='SHA256:' + 'A' * 43))[:2], (1, 'REFUSED key\n'))
        mine = subprocess.run([fp.SSH_KEYGEN, '-l', '-f', str(self.pub)], capture_output=True, text=True).stdout.split()[1]
        self.assertEqual(self.bundle(env=self.env(OWNER_PIN_SHA256=mine))[0], 0)

    def test_the_remote_is_never_read_as_an_option(self):
        self.assertEqual(self.bundle(env=self.env(FLEET_REPO='--upload-pack=touch /tmp/x'))[:2], (1, 'REFUSED fetch\n'))


class TestGateway(Fixture):
    def test_uploads_the_signed_pair_as_one_request(self):
        code, out, err = self.gateway()
        self.assertEqual((code, err), (0, ''), out)
        text = git(self.origin, 'show', 'HEAD:fleet/core/gateway.json') + '\n'
        sig = (self.origin / 'fleet/core/gateway.json.sig').read_bytes()
        self.assertEqual(out, f'OK gateway serial=3 json={sha(text.encode())} sig={sha(sig)}\n')
        (call,) = self.net.calls
        self.assertEqual((call['method'], call['path']), ('POST', '/_k/gateway/3'))
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
        self.write('fleet/core/gateway.json', json.dumps({'serial': 4}) + '\n')
        self.sign_gateway(self.owner, fp.PIN_NS)
        self.commit()
        self.assertIn('serial=4', self.gateway()[1])

    def test_a_pair_the_owner_did_not_sign_under_the_pin_namespace_is_refused(self):
        self.commit(**{'fleet/core/gateway.json': json.dumps({'serial': 5}) + '\n'})  # the old signature no longer fits
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
        self.assertEqual(self.gateway()[:2], (1, 'REFUSED gateway\n'))
        for body in ('{"serial": 0}\n', '{"serial": "3"}\n', '{"serial": true}\n', '{"serial": 3000000000}\n', '{}\n', '[]\n',
                     '{"serial": 3, "serial": 4}\n', '{"serial": 3.5}\n'):
            self.write('fleet/core/gateway.json', body)
            self.sign_gateway(self.owner, fp.PIN_NS)
            self.commit()
            self.assertEqual(self.gateway()[:2], (1, 'REFUSED gateway\n'), body)
        self.assertEqual(self.net.calls, [])

    def test_the_sizes_the_host_accepts_are_the_limits(self):
        self.write('fleet/core/gateway.json', json.dumps({'serial': 3, 'pad': 'x' * fk.MAX_GATEWAY_JSON}) + '\n')
        self.sign_gateway(self.owner, fp.PIN_NS)
        self.commit()
        self.assertEqual(self.gateway()[:2], (1, 'REFUSED gateway\n'))
        self.assertEqual((fk.MAX_GATEWAY_JSON, fk.MAX_GATEWAY_SIG), (65536, 4096))

    def test_the_hosts_answers(self):
        self.assertEqual(self.gateway(net=FakeNet(self.up_pub, lambda c: (409, b'')))[:2], (1, 'REFUSED conflict\n'))
        self.assertEqual(self.gateway(net=FakeNet(self.up_pub, lambda c: (404, b'')))[:2], (1, 'REFUSED upload 404\n'))
        for answer in ({'gserial': 4, 'json': {}, 'sig': {}}, {'gserial': 3, 'json': {'sha256': '0' * 64, 'size': 1}, 'sig': {}}, []):
            net = FakeNet(self.up_pub, lambda c, a=answer: (200, json.dumps(a).encode()))
            self.assertEqual(self.gateway(net=net)[:2], (1, 'REFUSED readback\n'), answer)

    def test_the_output_shows_no_address(self):
        _, out, err = self.gateway()
        self.assertNotIn('203.0.113', out + err)


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

    def test_the_time_rises_even_when_the_clock_does_not(self):
        signer = fk.Signer(self.pem.read_text(), now_ms=lambda: 5000)
        self.addCleanup(signer.close)
        stamps = [int(signer.sign('PUT', '/p', b'')['Authorization'].split('.')[1]) for _ in range(3)]
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
                                    'readback', 'internal'))

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


if __name__ == '__main__':
    unittest.main()
