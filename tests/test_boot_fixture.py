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
# The shipped lines are verbatim from mirrorstack-fleet main 8746da9f (fleet/install/boot/bootstrap.ps1 blob 5711c0ab, bootstrap.sh blob
# fe742a20), the loaders that boot-smoke run 38440004807 refused: the PBS line, the kit-host deny line and the ps1 curl.exe re-fetch.
PS1_CURL = ("$k=[Diagnostics.Process]::Start('C:\\Windows\\System32\\curl.exe','-fsSL --max-redirs 3 --proto =https --proto-redir =https "
            "--tlsv1.2 --max-time 120 --max-filesize 262144 -o '+$d+$f+$d+' "
            "https://github.com/mirrorstack-ai/fleet-disk/releases/download/install-{0}/bootstrap.ps1')")
SH_PBS = "PBS=https://github.com/astral-sh/python-build-standalone/releases/download  # the one place kit.json's python_mac url may point"
SH_DENY = "    '' | .* | *. | *..* | *[!a-z0-9.-]* | github.com | *.github.com | *githubusercontent.com) host= ;;"
PS1 = ("# the base: https://github.com/mirrorstack-ai/fleet-disk and python.org in a comment\n"
       "$OwnerKey = 'ssh-ed25519 UNBAKED'\n$Expires = '1970-01-01T00:00:00Z'\n"
       "$Release = 'https://github.com/mirrorstack-ai/fleet-disk/releases/download'\n"
       "$PythonUrl = 'https://www.python.org/ftp/python/{0}/python-{0}-embed-amd64.zip'\n"
       f"{PS1_CURL}\nWrite-Host $OwnerKey\n").encode()
SH = ("#!/bin/sh\n# https://github.com/mirrorstack-ai/fleet-disk\nOWNER_KEY='ssh-ed25519 UNBAKED'\n"
      f"EXPIRES=1970-01-01T00:00:00Z\nRELEASES=https://github.com/mirrorstack-ai/fleet-disk/releases/download\n{SH_PBS}\n"
      f"case $host in\n{SH_DENY}\n    *) ;;\nesac\nBASE=\n").encode()
EXPIRES = '2027-02-01T00:00:00Z'


class Rewrite(unittest.TestCase):
    def test_base_and_baked_lines_change_and_nothing_else(self):
        for name, raw, n in (('ps1', PS1, 5), ('sh', SH, 4)):
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
        for name, raw in (('sh', SH), ('ps1', PS1)):
            live = raw + b'curl https://github.com/x\n'  # in the original too, so only the live-line check can refuse it
            with self.subTest(name=name), self.assertRaises(mf.Refused):
                mf.prepare(name, live, '127.0.0.1', 1, KEY, EXPIRES)

    def test_the_shipped_loader_lines_are_accepted(self):
        """Pins what the builder knows of the shipped loaders: every live line naming github.com that they carry (the base, the
        PBS root, the curl.exe re-fetch) is rewritten to the fixture host, and only the sh deny line stays. Whether the
        loaders have drifted since is not decided here: AF34's run over the loaders at the release tip catches that."""
        sh = mf.prepare('sh', SH, '127.0.0.1', 18443, KEY, EXPIRES).decode()
        ps1 = mf.prepare('ps1', PS1, '127.0.0.1', 18443, KEY, EXPIRES).decode()
        self.assertIn('PBS=https://127.0.0.1:18443/pbs/releases/download  # the one place', sh)
        self.assertIn(SH_DENY, sh.split('\n'))
        self.assertIn(' https://127.0.0.1:18443/releases/download/install-{0}/bootstrap.ps1\')', ps1)
        for text in (sh, ps1):
            self.assertEqual([x for x in text.split('\n') if not x.startswith('#') and 'github.com' in x and x != SH_DENY], [])
            self.assertEqual(text.count('127.0.0.1:18443'), 3 if text is ps1 else 2)
        for d in ROOT.glob('release/install-*'):
            for name in ('ps1', 'sh'):
                mf.prepare(name, mf.lf((d / f'bootstrap.{name}').read_bytes()), '127.0.0.1', 18443, KEY, EXPIRES)

    def test_the_deny_line_is_excused_only_byte_for_byte_once_and_only_in_sh(self):
        copy = mf.prepare('sh', SH, '127.0.0.1', 1, KEY, EXPIRES)
        mf.check_copy('sh', SH, copy, 4)
        changed = SH.replace(SH_DENY.encode(), SH_DENY.replace('github.com |', 'github.com  |').encode())  # one character added
        with self.assertRaises(mf.Refused):
            mf.prepare('sh', changed, '127.0.0.1', 1, KEY, EXPIRES)
        with self.assertRaises(mf.Refused):  # a second live line naming github.com, in orig and copy alike
            mf.prepare('sh', SH + b'curl https://github.com/x\n', '127.0.0.1', 1, KEY, EXPIRES)
        with self.assertRaises(mf.Refused):  # the deny line twice: only one is excused
            mf.prepare('sh', SH.replace(SH_DENY.encode(), SH_DENY.encode() + b'\n' + SH_DENY.encode()), '127.0.0.1', 1, KEY, EXPIRES)
        with self.assertRaises(mf.Refused):  # a deny line the original did not hold is not excused
            mf.check_copy('sh', b'a\nb', ('a\n' + SH_DENY).encode(), 1)
        mf.check_copy('sh', ('a\n' + SH_DENY).encode(), ('b\n' + SH_DENY).encode(), 1)  # control: one held in both is
        with self.assertRaises(mf.Refused):  # the sh line inside a ps1 is a live line
            mf.prepare('ps1', PS1 + SH_DENY.encode() + b'\n', '127.0.0.1', 1, KEY, EXPIRES)

    def test_a_live_line_naming_githubusercontent_or_spelling_a_host_in_another_case_refuses(self):
        for name, raw in (('sh', SH), ('ps1', PS1)):
            for url in ('https://raw.githubusercontent.com/x', 'https://objects.githubusercontent.com/x', 'https://GitHub.com/x',
                        'https://GITHUB.COM/x', 'https://www.PYTHON.org/x', 'https://github.com/x', 'https://www.python.org/x'):
                with self.subTest(name=name, url=url), self.assertRaises(mf.Refused):
                    mf.prepare(name, raw + f'curl -fsSL {url}\n'.encode(), '127.0.0.1', 1, KEY, EXPIRES)
        mf.prepare('sh', SH + b'echo https://127.0.0.1/x\n', '127.0.0.1', 1, KEY, EXPIRES)  # control: a line naming no such host passes

    def test_a_reshaped_shipped_line_refuses(self):
        for name, raw, old, new in (('sh', SH, b'PBS=', b'PBSX='), ('ps1', PS1, b'/install-{0}/bootstrap.ps1', b'/install-{0}/boot.ps1'),
                                    ('sh', SH, b'download  # the one', b'download/x  # the one')):
            with self.subTest(old=old), self.assertRaises(mf.Refused):
                mf.prepare(name, raw.replace(old, new), '127.0.0.1', 1, KEY, EXPIRES)
        with self.assertRaises(mf.Refused):  # the curl line three times is more elevated re-fetch sites than the loaders carry
            mf.prepare('ps1', PS1.replace(PS1_CURL.encode(), (PS1_CURL.encode() + b'\n') * 2 + PS1_CURL.encode()), '127.0.0.1', 1, KEY, EXPIRES)

    def test_crlf_becomes_lf_and_a_lone_cr_refuses(self):
        crlf = PS1.replace(b'\n', b'\r\n')
        self.assertEqual(mf.lf(crlf), PS1)
        self.assertEqual(mf.prepare('ps1', mf.lf(crlf), '127.0.0.1', 1, KEY, EXPIRES), mf.prepare('ps1', PS1, '127.0.0.1', 1, KEY, EXPIRES))
        with self.assertRaises(mf.Refused):
            mf.lf(PS1.replace(b'Write-Host', b'Write\rHost'))
        with self.assertRaises(mf.Refused):
            mf.rewrite('ps1', crlf, '127.0.0.1', 1)


PINNED = ROOT / 'tests' / 'fixture' / 'pinned'  # mirrorstack-fleet origin/main d7902653 (when pinned) fleet/install/boot/bootstrap.{ps1,sh}, byte for byte
REFETCH_AT = ' https://127.0.0.1:18443/releases/download/install-{0}/bootstrap.ps1\')'


def live_lines(data: bytes):
    """The lines that are not comments and name a host the builder must keep out of the copies."""
    return [x for x in data.decode('ascii').split('\n')
            if not x.lstrip().startswith('#') and any(h in x.lower() for h in mf.HOSTS)]


class TwoRefetchSites(unittest.TestCase):
    """G-PC-16: since AF36 the ps1 loader names the elevated re-fetch twice (the uninstall loader and $RemoveLoader); the builder
    rewrites every such site, up to REFETCH_MAX, and still refuses everything else."""

    @classmethod
    def setUpClass(cls):
        cls.ps1 = (PINNED / 'bootstrap.ps1').read_bytes()
        cls.sh = (PINNED / 'bootstrap.sh').read_bytes()

    def test_the_pinned_loader_really_has_two_sites(self):  # else the tests below prove nothing about two
        self.assertEqual(len(re.findall(mf.REFETCH, self.ps1.decode(), flags=re.M)), 2)

    def test_the_pinned_current_loaders_build_with_both_sites_on_the_fake_host(self):
        ps1 = mf.prepare('ps1', self.ps1, '127.0.0.1', 18443, KEY, EXPIRES)
        sh = mf.prepare('sh', self.sh, '127.0.0.1', 18443, KEY, EXPIRES)
        self.assertEqual(ps1.decode().count(REFETCH_AT), 2)
        self.assertEqual(sum(a != b for a, b in zip(self.ps1.split(b'\n'), ps1.split(b'\n'))), 6)  # base, python, 2 sites, key, expiry
        self.assertEqual(sum(a != b for a, b in zip(self.sh.split(b'\n'), sh.split(b'\n'))), 4)
        self.assertEqual(live_lines(ps1), [])  # nothing live in the copy names github.com, githubusercontent.com or python.org
        self.assertEqual(live_lines(sh), [mf.DENY['sh']])  # but the excused deny line
        self.assertNotIn(b'github.com/mirrorstack-ai', ps1)
        self.assertNotIn(b'python.org/ftp', ps1)

    def test_the_one_site_loader_still_builds_and_each_loader_counts_its_sites(self):  # install-1's loader has one
        _, sites = mf.rewrite_counted('ps1', PS1, '127.0.0.1', 1)
        self.assertEqual(sites, 3)
        self.assertEqual(mf.rewrite_counted('ps1', self.ps1, '127.0.0.1', 1)[1], 4)
        self.assertEqual(mf.rewrite_counted('sh', self.sh, '127.0.0.1', 1)[1], 2)

    def test_an_extra_live_github_line_refuses_rewrite_on_the_pinned_loaders(self):
        for name, raw in (('ps1', self.ps1), ('sh', self.sh)):
            for line in (b'curl https://github.com/x\n', b'curl https://raw.githubusercontent.com/x\n',
                         b"$u = 'https://www.python.org/x'\n"):
                with self.subTest(name=name, line=line), self.assertRaises(mf.Refused) as why:
                    mf.prepare(name, raw + line, '127.0.0.1', 1, KEY, EXPIRES)
                self.assertEqual(str(why.exception), 'rewrite')

    def test_three_sites_refuse_and_zero_sites_refuse(self):
        site = next(x for x in self.ps1.split(b'\n') if b'install-{0}/bootstrap.ps1' in x)
        three = self.ps1 + site + b'\n'
        with self.assertRaises(mf.Refused) as why:
            mf.prepare('ps1', three, '127.0.0.1', 1, KEY, EXPIRES)
        self.assertEqual(str(why.exception), 'rewrite')
        zero = self.ps1.replace(b'/install-{0}/bootstrap.ps1', b'/install-{0}/boot.ps1')
        with self.assertRaises(mf.Refused) as why:  # the rewrite itself, before the live-line check would catch the leftover
            mf.rewrite('ps1', zero, '127.0.0.1', 1)
        self.assertEqual(str(why.exception), 'rewrite')
        with self.assertRaises(mf.Refused) as why:
            mf.rewrite('ps1', three, '127.0.0.1', 1)
        self.assertEqual(str(why.exception), 'rewrite')
        with self.assertRaises(mf.Refused):
            mf.prepare('ps1', zero, '127.0.0.1', 1, KEY, EXPIRES)

    def test_a_site_the_rewrite_skipped_is_caught_by_the_changed_line_count(self):
        copy = mf.prepare('ps1', self.ps1, '127.0.0.1', 1, KEY, EXPIRES)
        mf.check_copy('ps1', self.ps1, copy, 6)
        for wrong in (5, 7):
            with self.subTest(changed=wrong), self.assertRaises(mf.Refused):
                mf.check_copy('ps1', self.ps1, copy, wrong)

    @unittest.skipUnless(TOOLS, 'ssh-keygen or openssl is missing')
    def test_the_whole_fixture_builds_from_the_pinned_loaders(self):  # what the hosted smoke does, with the publisher's own verify
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / 'z.zip').write_bytes(b'PKfake')
        meta = mf.build(tmp / 'fx', PINNED / 'bootstrap.ps1', PINNED / 'bootstrap.sh', zip_path=tmp / 'z.zip')
        self.assertTrue(meta['cases'])
        for p in (tmp / 'fx').rglob('bootstrap.ps1'):
            self.assertEqual(live_lines(p.read_bytes()), [], str(p))


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

    def test_built_copies_hold_no_cr_and_a_crlf_ps1_builds_the_same_copies(self):
        for p in self.out.rglob('bootstrap.*'):
            if p.parent.name == 'run' and p.parent.parent.name != 'boot-hash-crlf-ps1':  # that case is CRLF on purpose
                self.assertNotIn(b'\r', p.read_bytes(), str(p))
        (self.tmp / 'c.ps1').write_bytes(PS1.replace(b'\n', b'\r\n'))
        crlf = mf.build(self.tmp / 'fx-crlf', self.tmp / 'c.ps1', self.tmp / 'a.sh', zip_path=self.tmp / 'z.zip')
        key, exp = mf.PUB.baked_values('ps1', (self.out / 'good-ps1' / 'run' / 'bootstrap.ps1').read_bytes())
        twin = (self.tmp / 'fx-crlf' / 'good-ps1' / 'run' / 'bootstrap.ps1').read_bytes()
        self.assertNotIn(b'\r', twin)
        self.assertEqual(mf.bake('ps1', twin, key, exp), (self.out / 'good-ps1' / 'run' / 'bootstrap.ps1').read_bytes())
        self.assertEqual(len(crlf['cases']), len(self.meta['cases']))

    def test_a_relative_out_as_the_workflow_passes_it_still_verifies(self):
        here = os.getcwd()
        os.chdir(self.tmp)
        try:
            meta = mf.build(Path('fx-rel'), self.tmp / 'a.ps1', self.tmp / 'a.sh', zip_path=self.tmp / 'z.zip')
        finally:
            os.chdir(here)
        self.assertEqual(len(meta['cases']), len(self.meta['cases']))
        self.assertTrue((self.tmp / 'fx-rel' / 'owner.pub').is_file())

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
