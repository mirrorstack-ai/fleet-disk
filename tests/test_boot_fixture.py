"""The boot fixture's own tests, offline: the fixture builder over small synthetic bootstraps that have the real baked-line and
base-line shapes (and over every real release/install-*/bootstrap.* present in the tree) and the local server. The key and TLS
tests are skipped when ssh-keygen or openssl is missing."""
from __future__ import annotations

import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
import hashlib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tests' / 'fixture'))
import make_fixture as mf  # noqa: E402
import serve  # noqa: E402

TOOLS = bool(shutil.which('ssh-keygen') and shutil.which('openssl')) and os.path.exists(mf.PUB.SSH_KEYGEN)
KEY = 'ssh-ed25519 ' + 'A' * 68
PS1 = ("# the base: https://github.com/mirrorstack-ai/fleet-disk and python.org in a comment\n"
       "$OwnerKey = 'ssh-ed25519 UNBAKED'\n$Expires = '1970-01-01T00:00:00Z'\n"
       "$Release = 'https://github.com/mirrorstack-ai/fleet-disk/releases/download'\n"
       "$PythonUrl = 'https://www.python.org/ftp/python/{0}/python-{0}-embed-amd64.zip'\nWrite-Host $OwnerKey\n").encode()
SH = ("#!/bin/sh\n# https://github.com/mirrorstack-ai/fleet-disk\nOWNER_KEY='ssh-ed25519 UNBAKED'\n"
      "EXPIRES=1970-01-01T00:00:00Z\nRELEASES=https://github.com/mirrorstack-ai/fleet-disk/releases/download\nBASE=\n").encode()
EXPIRES = '2027-02-01T00:00:00Z'


class Rewrite(unittest.TestCase):
    def test_base_and_baked_lines_change_and_nothing_else(self):
        for name, raw, n in (('ps1', PS1, 4), ('sh', SH, 3)):
            copy = mf.prepare(name, raw, '127.0.0.1', 18443, KEY, EXPIRES)
            self.assertEqual(mf.PUB.baked_values(name, copy), (KEY, EXPIRES))
            self.assertIn(b'127.0.0.1:18443', copy)
            self.assertEqual(sum(a != b for a, b in zip(raw.split(b'\n'), copy.split(b'\n'))), n)
            self.assertEqual(len(raw.split(b'\n')), len(copy.split(b'\n')))

    def test_a_renamed_or_repeated_base_line_refuses(self):
        for name, raw, old, new in (('ps1', PS1, b'$Release =', b'$Rel ='), ('ps1', PS1, b'$PythonUrl =', b'$PyUrl ='),
                                    ('sh', SH, b'RELEASES=', b'RELEASE='), ('sh', SH, b'BASE=\n', b'BASE=\nRELEASES=https://github.com/mirrorstack-ai/fleet-disk/releases/download\n')):
            with self.subTest(old=old), self.assertRaises(mf.Refused):
                mf.rewrite(name, raw.replace(old, new), '127.0.0.1', 1)

    def test_a_live_line_naming_github_refuses(self):
        copy = mf.prepare('sh', SH, '127.0.0.1', 1, KEY, EXPIRES)
        with self.assertRaises(mf.Refused):
            mf.check_copy(SH, copy + b'curl https://github.com/x\n', 3)

    def test_the_real_bootstraps_in_the_tree(self):  # vacuous until the first release folder is committed
        for d in ROOT.glob('release/install-*'):
            for name in ('ps1', 'sh'):
                raw = (d / f'bootstrap.{name}').read_bytes()
                mf.prepare(name, raw, '127.0.0.1', 18443, KEY, EXPIRES)


@unittest.skipUnless(TOOLS, 'ssh-keygen or openssl is missing')
class Built(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        (cls.tmp / 'a.ps1').write_bytes(PS1)
        (cls.tmp / 'a.sh').write_bytes(SH)
        (cls.tmp / 'z.zip').write_bytes(b'PKfake')
        cls.out = cls.tmp / 'fx'
        cls.meta = mf.build(cls.out, cls.tmp / 'a.ps1', cls.tmp / 'a.sh', zip_path=cls.tmp / 'z.zip')  # runs the publisher's verify

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_no_secret_key_is_left(self):
        names = {p.name for p in self.out.rglob('*')}
        self.assertFalse(names & {'ca.key', 'owner', 'wrong', 'index.txt', 'openssl.cnf'})
        self.assertTrue(names >= {'leaf.key', 'ca.crt', 'ca.cer', 'ca.crl', 'owner.pub', 'cases.json'})

    def test_every_case_has_a_folder_and_the_table_is_complete(self):
        ids = {c['id'] for c in self.meta['cases']}
        self.assertEqual(len(ids), len(self.meta['cases']))
        self.assertTrue({'good-ps1', 'good-sh', 'redirect-downgrade-sh', 'zip-hash-ps1', 'args-sh'} <= ids)
        self.assertFalse({'zip-hash-sh', 'boot-hash-crlf-sh'} & ids)
        for c in self.meta['cases']:
            self.assertTrue((self.out / c['id'] / 'run' / f'bootstrap.{c["os"]}').is_file(), c['id'])
        self.assertEqual(mf.want_reqs('all', 'sh'), ['install.json', 'install.json.sig', 'kit.json', 'carrier-check.sh'])
        self.assertEqual(mf.want_reqs('files', 'ps1')[-1], 'carrier-check.sh')

    def test_each_negative_is_negative_for_the_stated_reason(self):
        for c in self.meta['cases']:
            if not c['pub']:
                continue
            got = mf.publisher(self.out, c)
            self.assertEqual(got.split(), ['REFUSED', c['pub']], c['id'])

    def rel(self, cid):
        return self.out / cid / 'release' / 'install-20'

    def run_copy(self, cid):
        return (self.out / cid / 'run' / f'bootstrap.{cid.rsplit("-", 1)[1]}').read_bytes()

    def test_the_case_table_is_the_designed_one(self):  # code, info lines before it, how far the fetches get
        want = {
            'good': (None, 3, 'all'), 'good-pretty': (None, 3, 'all'), 'good-kitorder': (None, 3, 'all'),
            'key': ('key', 1, 'none'), 'expired-baked': ('expired', 2, 'none'), 'expired-install': ('expired', 3, 'sig'),
            'sig-wrong-key': ('sig', 2, 'sig'), 'sig-tampered': ('sig', 2, 'sig'), 'sig-namespace': ('sig', 2, 'sig'),
            'rollback': ('rollback', 3, 'sig'), 'serial': ('serial', 3, 'sig'), 'boot-hash': ('boot-hash', 3, 'sig'),
            'boot-hash-crlf': ('boot-hash', 3, 'sig'), 'kit-hash': ('kit-hash', 3, 'kit'), 'file-hash': ('file-hash', 3, 'files'),
            'zip-hash': ('zip-hash', 3, 'all'), 'size-big': ('size', 2, 'install'), 'size-empty': ('size', 2, 'install'),
            'redirect-downgrade': ('fetch', 2, 'install'), 'fetch-missing': ('fetch', 2, 'install'), 'args': ('args', 0, 'none'),
            'args-lt-min': ('args', 0, 'none'), 'args-dup': ('args', 0, 'none'), 'args-missing': ('args', 0, 'none'),
            'args-abbrev': ('args', 0, 'none'), 'kind-wrong': ('kind', 3, 'sig'), 'form-field': ('form', 3, 'sig'),
            'kit-six': ('form', 3, 'kit'), 'size-sig': ('size', 2, 'sig'), 'size-chunked': ('size', 2, 'install'),
            'size-kit-json': ('size', 3, 'kit'), 'size-kit-file': ('size', 3, 'file1'), 'size-zip': ('size', 3, 'all')}
        self.assertEqual({c['id']: (c['code'], c['info'], c['upto']) for c in mf.CASES}, want)
        self.assertEqual(mf.want_reqs('all', 'ps1'), ['install.json', 'install.json.sig', 'kit.json', 'carrier-check.py', 'check.ps1',
                                                      'carrier-check.sh', 'verify-archive.py', 'VERIFY.txt', 'python.zip'])
        self.assertEqual(mf.want_reqs('file1', 'sh'), ['install.json', 'install.json.sig', 'kit.json', 'carrier-check.sh'])

    def test_each_built_case_is_damaged_the_way_it_says(self):
        data = lambda cid, name: (self.rel(cid) / name).read_bytes()  # noqa: E731
        sha = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731
        for osn in ('ps1', 'sh'):
            signed = data(f'good-{osn}', f'bootstrap.{osn}')
            self.assertEqual(self.run_copy(f'good-{osn}'), signed)
            self.assertIn(b'UNBAKED', self.run_copy(f'key-{osn}'))
            self.assertNotIn(b'UNBAKED', signed)
            self.assertIn(b'2020-01-01T00:00:00Z', self.run_copy(f'expired-baked-{osn}'))
            appended = self.run_copy(f'boot-hash-{osn}')
            self.assertTrue(appended.startswith(signed) and appended != signed)
            self.assertGreater(len(data(f'size-big-{osn}', 'install.json')), 8192)
            self.assertEqual(len(data(f'size-empty-{osn}', 'install.json')), 0)
            self.assertGreater(len(data(f'size-sig-{osn}', 'install.json.sig')), 4096)
            self.assertGreater(len(data(f'size-kit-json-{osn}', 'kit.json')), 65536)
            self.assertTrue((self.rel(f'size-chunked-{osn}') / 'install.json.chunked').is_file())
            self.assertFalse((self.out / f'fetch-missing-{osn}' / 'release').exists())
            self.assertGreater(len(data(f'size-kit-file-{osn}', 'carrier-check.sh' if osn == 'sh' else 'carrier-check.py')),
                               262144 if osn == 'sh' else 4 << 20)
            kit = json.loads(data(f'kit-six-{osn}', 'kit.json'))
            self.assertEqual(len(kit['files']), 6)
            self.assertNotIn('valid_until', json.loads(data(f'form-field-{osn}', 'install.json')))
            self.assertEqual(json.loads(data(f'kind-wrong-{osn}', 'install.json'))['kind'], 'other')
            self.assertTrue(data(f'sig-tampered-{osn}', 'install.json').endswith(b'}\n\n'), osn)
        self.assertIn(b'\r\n', self.run_copy('boot-hash-crlf-ps1'))
        self.assertNotIn(b'\r\n', data('boot-hash-crlf-ps1', 'bootstrap.ps1'))
        zipped = self.out / 'python' / '3.12.10' / 'python-3.12.10-embed-amd64.zip'
        self.assertNotEqual(json.loads(data('zip-hash-ps1', 'kit.json'))['python_zip']['sha256'], sha(zipped.read_bytes()))
        self.assertEqual(json.loads(data('good-ps1', 'kit.json'))['python_zip']['sha256'], sha(zipped.read_bytes()))
        bigzip = self.out / 'size-zip-ps1' / 'python' / '3.12.10' / 'python-3.12.10-embed-amd64.zip'
        self.assertGreater(bigzip.stat().st_size, 32 << 20)
        first = lambda cid: list(json.loads(data(cid, 'kit.json'))['files'][0])  # noqa: E731
        self.assertEqual((first('good-ps1'), first('good-kitorder-ps1')), (['path', 'sha256'], ['sha256', 'path']))

    def test_the_dummy_kit_prints_a_code_line_both_bootstraps_accept(self):
        rx = re.compile(r'Code  ((?:[0-9A-Z]{5} ){7}[0-9A-Z]{5})\\n')  # the sh's own pattern, over the stub's source text
        for name in ('carrier-check.sh', 'carrier-check.py'):
            self.assertEqual(rx.search(mf.kit_files()[name].decode())[1], mf.CODE, name)

    def test_the_args_cases_are_the_wrong_lines_they_name(self):
        by = {c['id']: c for c in self.meta['cases']}
        self.assertNotRegex(by['args-sh']['args'][0], r'^(0|[1-9][0-9]*)$')
        lt = by['args-lt-min-sh']['args']
        self.assertLess(int(lt[0]), int(lt[1]))
        self.assertEqual([k for k, _ in by['args-dup-sh']['argv']], ['serial', 'min', 'serial'])
        self.assertEqual([k for k, _ in by['args-missing-ps1']['argv']], ['serial'])
        self.assertEqual(by['args-abbrev-ps1']['argv'][0][0], 'ser')
        self.assertEqual(by['good-sh']['argv'], [('serial', '20'), ('min', '5')])

    def test_the_certificates_start_before_the_build(self):
        now = datetime.now(timezone.utc)
        for name in ('ca.crt', 'leaf.crt'):
            got = subprocess.run(['openssl', 'x509', '-in', str(self.out / 'tls' / name), '-noout', '-startdate'], capture_output=True,
                                 text=True).stdout.strip().split('=')[1]
            self.assertLess((now - datetime.strptime(got, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)).total_seconds() // 60 - 60, 5)
            self.assertGreater((now - datetime.strptime(got, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)).total_seconds(), 3500)

    def test_the_redirect_case_leads_to_a_valid_signed_file_over_plain_http(self):
        d = self.out / 'redirect-downgrade-sh'
        self.assertEqual((d / 'plain' / 'install-20' / 'install.json').read_bytes(), (d / 'release' / 'install-20' / 'install.json').read_bytes())
        self.assertIn('http://127.0.0.1:18444/', (d / 'release' / 'install-20' / 'install.json.redirect').read_text())

    def test_the_server_serves_the_layout_over_the_leaf_certificate(self):
        fx = serve.Fixture(str(self.out), port=0, crl_port=0)
        ctx = ssl.create_default_context(cafile=str(self.out / 'tls' / 'ca.crt'))
        base = f'https://127.0.0.1:{fx.port}'
        try:
            fx.set_case('good-sh')
            body = urllib.request.urlopen(f'{base}/releases/download/install-20/kit.json', context=ctx).read()  # 302 then 200
            self.assertIn(b'carrier-check.sh', body)
            self.assertEqual([e['path'] for e in fx.log], ['/releases/download/install-20/kit.json', '/objects/install-20/kit.json'])
            self.assertEqual(fx.log[0]['status'], 302)
            self.assertIn(fx.log[0]['tls'], ('TLSv1.2', 'TLSv1.3'))
            self.assertEqual(urllib.request.urlopen(f'http://127.0.0.1:{fx.crl_port}/ca.crl').read()[:1], b'\x30')
            with self.assertRaises(urllib.error.HTTPError) as gone:
                urllib.request.urlopen(f'{base}/releases/download/install-99/kit.json', context=ctx)
            gone.exception.close()
            fx.set_case('redirect-downgrade-sh')
            self.assertEqual(urllib.request.urlopen(f'http://127.0.0.1:{fx.crl_port}/install-20/install.json').status, 200)
            for bad in ('/python/../cases.json', '/python/3.12/python-x.zip', '/python/3.12.10/../cases.json'):
                with self.assertRaises(urllib.error.HTTPError, msg=bad) as nope:
                    urllib.request.urlopen(base + bad, context=ctx)
                nope.exception.close()
            self.assertEqual(urllib.request.urlopen(f'{base}/python/3.12.10/python-3.12.10-embed-amd64.zip', context=ctx).read(), b'PKfake')
            fx.set_case('size-chunked-sh')  # a marked asset answers chunked, with no Content-Length
            got = urllib.request.urlopen(f'{base}/objects/install-20/install.json', context=ctx)
            self.assertEqual((got.headers.get('Transfer-Encoding'), got.headers.get('Content-Length'), len(got.read())), ('chunked', None, 9000))
            fx.set_case('good-sh')
            got = urllib.request.urlopen(f'{base}/objects/install-20/install.json', context=ctx)
            self.assertIsNotNone(got.headers.get('Content-Length'))
            got.close()
        finally:
            fx.close()


if __name__ == '__main__':
    unittest.main()
