"""bin/fleet-install-publish.py over a fake gh and a throwaway ssh-keygen key, with no network: the signature (unsigned,
wrong key, wrong namespace), every hash, an unlisted file, the missing deploy-pin.json, the 30 days of validity, an
existing tag, the immutable setting, GitHub's digests read back, the vendored verifier frozen against I01's schema, and
the workflow's shape. The signature tests are skipped when ssh-keygen is missing. Plain unittest, stdlib only."""
from __future__ import annotations

import contextlib
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
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('fleet_install_publish', ROOT / 'bin/fleet-install-publish.py')
fp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fp)

HAVE_KEYGEN = os.path.exists(fp.SSH_KEYGEN)
REPO, SHA, TOKEN = 'org/repo', 'ab' * 20, 'tok-' + 'x' * 8  # built at runtime, never a secret-shaped literal
NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)
SERIAL = 5
TAG = f'install-{SERIAL}'
BUNDLE = 'fleet-install-bundle.tar'
BUNDLE_URL = f'https://github.com/{REPO}/releases/download/{TAG}/{BUNDLE}'
sha = lambda data: hashlib.sha256(data).hexdigest()  # noqa: E731
blob = lambda data: hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest()  # noqa: E731
utc = lambda dt: dt.strftime('%Y-%m-%dT%H:%M:%SZ')  # noqa: E731
H40, H64 = 'c' * 40, 'd' * 64

KIT = {name: f'kit file {name}\n'.encode() for name in fp.KIT_FILES}
PS1, SH = b'Write-Output "hi"\r\n', b'#!/bin/sh\necho hi\n'
BUNDLE_BYTES = b'tar bytes ' * 100


def keygen(tmp: Path, name: str) -> Path:
    key = tmp / name
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'test', '-f', str(key)], check=True)
    return key


def sign(key: Path, path: Path, namespace: str) -> None:
    """Writes <path>.sig, as `ssh-keygen -Y sign` does."""
    Path(str(path) + '.sig').unlink(missing_ok=True)
    subprocess.run(['ssh-keygen', '-q', '-Y', 'sign', '-f', str(key), '-n', namespace, str(path)], check=True)


def manifest(valid_until: datetime = NOW + timedelta(days=90), **over) -> dict:
    doc = {'kind': 'install', 'serial': SERIAL, 'valid_until': utc(valid_until), 'source_head': H40,
           'bootstrap': {'ps1': {'sha256': sha(PS1), 'blob': blob(PS1.replace(b'\r\n', b'\n'))},
                         'sh': {'sha256': sha(SH), 'blob': blob(SH)}},
           'kit': {'serial': 3, 'kit_json_sha256': 'f' * 64}, 'lock_sha256': H64,
           'bundle': {'head': H40, 'tree': 'e' * 40, 'url': BUNDLE_URL, 'sha256': sha(BUNDLE_BYTES),
                      'size': len(BUNDLE_BYTES)}}
    doc.update(over)
    return doc


class Fixture:
    """A release folder signed by a throwaway key; `build` writes it, a test then breaks one thing."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.key, self.other = keygen(tmp, 'owner-key'), keygen(tmp, 'stranger')
        self.pub = tmp / 'owner.pub'
        shutil.copy(str(self.key) + '.pub', self.pub)
        self.dir = tmp / 'release' / TAG
        self.dir.mkdir(parents=True)

    def put(self, name: str, data: bytes) -> Path:
        path = self.dir / name
        path.write_bytes(data)
        return path

    def build(self, valid_until: datetime = NOW + timedelta(days=90), bundle: bool = True, pin: bool = True,
              **over) -> 'Fixture':
        for name, data in KIT.items():
            self.put(name, data)
        kit = json.dumps({'serial': 3, 'files': [{'path': n, 'sha256': sha(d)} for n, d in KIT.items()],
                          'python_zip': {'version': '3.14.7', 'sha256': H64}}).encode()
        sign(self.key, self.put('kit.json', kit), fp.PIN_NS)
        if pin:
            sign(self.key, self.put('deploy-pin.json', b'{"serial": 0, "head": null}'), fp.PIN_NS)
        self.put('.gitattributes', b'* text=auto eol=lf\n*.ps1 eol=crlf\n')
        self.put('bootstrap.ps1', PS1)
        self.put('bootstrap.sh', SH)
        doc = manifest(valid_until, **over)
        doc['kit']['kit_json_sha256'] = sha(kit)
        if bundle:
            self.put(BUNDLE, BUNDLE_BYTES)
        else:
            doc['bundle']['url'] = 'https://example.org/elsewhere/bundle.tar'
        self.signed_install(doc)
        return self

    def signed_install(self, doc: dict, key: Path | None = None, namespace: str = fp.NS) -> None:
        sign(key or self.key, self.put('install.json', json.dumps(doc).encode()), namespace)

    def check(self, min_serial: int = 0, repo: str = REPO, now: datetime = NOW) -> 'fp.Plan':
        return fp.check_dir(self.dir, self.pub.read_bytes(), min_serial, now, repo)


class FakeGh:
    """The Io of the publish: records every call, answers the four gh queries and serves what `release create` got."""

    def __init__(self, refs=None, releases=None, immutable=(0, '{"enabled": true}'), create_code=0) -> None:
        self.calls: list[list[str]] = []
        self.refs, self.releases = refs if refs is not None else [], releases if releases is not None else []
        self.immutable, self.create_code, self.created = immutable, create_code, []
        self.tweak = lambda assets: assets  # a test edits what GitHub "serves" back
        self.query_code = 0

    def run(self, argv, env, timeout=fp.TOOL_TIMEOUT):
        self.calls.append(list(argv))
        words = argv[1:]
        if words[:1] == ['api'] and 'matching-refs' in words[1]:
            return self.query_code, json.dumps(self.refs)
        if words[:2] == ['release', 'list']:
            return 0, json.dumps(self.releases)
        if words[:1] == ['api'] and words[1].endswith('/immutable-releases'):
            return self.immutable
        if words[:2] == ['release', 'create']:
            self.created = [Path(p) for p in words[3:words.index('--target')]]
            return self.create_code, ''
        if words[:1] == ['api'] and '/releases/tags/' in words[1]:
            assets = [{'name': p.name.replace('.gitattributes', 'default.gitattributes'),
                       'digest': 'sha256:' + sha(p.read_bytes()), 'size': p.stat().st_size} for p in self.created]
            return 0, json.dumps({'assets': self.tweak(assets)})
        raise AssertionError(argv)

    def creates(self) -> list[list[str]]:
        return [c for c in self.calls if c[1:3] == ['release', 'create']]


@unittest.skipUnless(HAVE_KEYGEN, 'ssh-keygen is missing')
class Publish(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.fx = Fixture(Path(self._tmp.name))

    def refuses(self, code: str, gh: FakeGh | None = None, confirmed: str = '', **kw) -> FakeGh:
        gh = gh or FakeGh()
        with self.assertRaises(fp.Refused) as why:
            fp.publish(gh, self.fx.check(**kw), REPO, SHA, TOKEN, confirmed)
        self.assertEqual(why.exception.code, code)
        return gh

    def refuses_locally(self, code: str, **kw) -> None:
        with self.assertRaises(fp.Refused) as why:
            self.fx.check(**kw)
        self.assertEqual(why.exception.code, code)

    # the happy path

    def test_the_happy_path_creates_the_release_with_exactly_the_checked_assets(self):
        self.fx.build()
        gh = FakeGh()
        lines = fp.publish(gh, self.fx.check(), REPO, SHA, TOKEN)
        (create,) = gh.creates()
        self.assertEqual([Path(p).name for p in create[4:create.index('--target')]],
                         list(fp.FIXED + fp.KIT_FILES) + [BUNDLE])
        self.assertEqual(create[create.index('--target') + 1], SHA)
        self.assertEqual(create[4], str(self.fx.dir / 'install.json'))
        self.assertEqual(len(lines), 15)
        self.assertIn(f'bootstrap.sh sha256:{sha(SH)} https://github.com/{REPO}/releases/download/{TAG}/bootstrap.sh',
                      lines)
        self.assertTrue(any(l.startswith('default.gitattributes ') for l in lines))  # the name GitHub served

    def test_everything_local_and_the_two_queries_come_before_the_release_and_immutable_is_read_before_it(self):
        self.fx.build()
        gh = FakeGh()
        fp.publish(gh, self.fx.check(), REPO, SHA, TOKEN)
        kinds = [c[1] + ' ' + c[2] for c in gh.calls]
        self.assertEqual(kinds[-1][:12], 'api repos/or')
        self.assertLess(next(i for i, c in enumerate(gh.calls) if c[2].endswith('/immutable-releases')),
                        next(i for i, c in enumerate(gh.calls) if c[1:3] == ['release', 'create']))

    def test_a_publish_without_a_bundle_here_carries_no_bundle(self):
        self.fx.build(bundle=False)
        gh = FakeGh()
        fp.publish(gh, self.fx.check(), REPO, SHA, TOKEN)
        self.assertEqual(len(gh.created), 14)
        self.assertNotIn(BUNDLE, [p.name for p in gh.created])

    def test_exactly_thirty_days_of_validity_is_enough_and_a_minute_less_is_not(self):
        self.fx.build(valid_until=NOW + timedelta(days=30))
        self.assertEqual(self.fx.check().tag, TAG)
        self.fx.build(valid_until=NOW + timedelta(days=30) - timedelta(minutes=1))
        self.refuses_locally('short-validity')

    # the owner's signature

    def test_unsigned_or_signed_by_another_key_is_refused_sig(self):
        self.fx.build()
        (self.fx.dir / 'install.json.sig').write_bytes(b'')
        self.refuses_locally('sig')
        self.fx.signed_install(manifest(), key=self.fx.other)
        self.refuses_locally('sig')

    def test_a_signature_in_the_pin_namespace_is_not_an_install_signature(self):
        self.fx.build()
        self.fx.signed_install(manifest(), namespace=fp.PIN_NS)
        self.refuses_locally('sig')

    def test_a_tampered_install_json_is_refused_sig(self):
        self.fx.build()
        path = self.fx.dir / 'install.json'
        path.write_bytes(path.read_bytes().replace(b'"serial": 5', b'"serial": 6'))
        self.refuses_locally('sig')

    def test_a_key_file_that_is_not_one_ed25519_line_is_refused_key(self):
        self.fx.build()
        self.fx.pub.write_bytes(b'ssh-rsa AAAA x\n')
        self.refuses_locally('key')

    def test_kit_json_and_the_pin_must_carry_the_owners_signature_too(self):
        self.fx.build()
        sign(self.fx.other, self.fx.dir / 'kit.json', fp.PIN_NS)
        self.refuses_locally('sig')
        self.fx.build()
        sign(self.fx.other, self.fx.dir / 'deploy-pin.json', fp.PIN_NS)
        self.refuses_locally('sig')

    # the manifest's rules

    def test_an_expired_manifest_is_refused_expired_and_a_serial_below_the_floor_rollback(self):
        self.fx.build(valid_until=NOW - timedelta(days=1))
        self.refuses_locally('expired')
        self.fx.build()
        self.refuses_locally('rollback', min_serial=SERIAL + 1)

    def test_the_serial_must_be_the_folders(self):
        self.fx.build(serial=SERIAL + 1)
        self.refuses_locally('serial')

    def test_a_folder_not_named_install_serial_is_refused(self):
        self.fx.build()
        moved = self.fx.dir.parent / 'install-x'
        self.fx.dir.rename(moved)
        self.fx.dir = moved
        self.refuses_locally('dir')

    # every byte is the signed one, and nothing else

    def test_a_changed_bootstrap_is_refused_hash(self):
        self.fx.build()
        self.fx.put('bootstrap.sh', SH + b'echo more\n')
        self.refuses_locally('hash')

    def test_a_bootstrap_with_the_right_hash_but_the_other_blob_is_refused_tree(self):
        self.fx.build()
        doc = manifest()
        doc['bootstrap']['sh']['blob'] = blob(b'not the file')
        doc['kit']['kit_json_sha256'] = sha((self.fx.dir / 'kit.json').read_bytes())
        self.fx.signed_install(doc)
        self.refuses_locally('tree')

    def test_a_changed_kit_file_the_kit_json_or_the_bundle_is_refused_hash(self):
        for name in ('carrier-check.py', 'kit.json', BUNDLE):
            with self.subTest(name):
                self.fx.build()
                path = self.fx.dir / name
                path.write_bytes(path.read_bytes() + b'x')
                self.refuses_locally('hash')

    def test_a_kit_json_that_does_not_list_the_five_files_is_refused_kit(self):
        self.fx.build()
        kit = json.loads((self.fx.dir / 'kit.json').read_bytes())
        kit['files'] = kit['files'][:4]
        data = json.dumps(kit).encode()
        sign(self.fx.key, self.fx.put('kit.json', data), fp.PIN_NS)
        doc = manifest()
        doc['kit']['kit_json_sha256'] = sha(data)
        self.fx.signed_install(doc)
        self.refuses_locally('kit')

    def test_a_file_the_manifest_does_not_account_for_is_refused_unlisted(self):
        self.fx.build()
        self.fx.put('extra.txt', b'x')
        self.refuses_locally('unlisted')

    def test_a_bundle_the_signed_url_does_not_name_is_unlisted(self):
        self.fx.build(bundle=False)
        self.fx.put(BUNDLE, BUNDLE_BYTES)
        self.refuses_locally('unlisted')

    def test_a_link_or_a_folder_in_the_release_folder_is_refused(self):
        self.fx.build()
        (self.fx.dir / 'sub').mkdir()
        self.refuses_locally('unlisted')
        (self.fx.dir / 'sub').rmdir()
        (self.fx.dir / 'link').symlink_to(self.fx.dir / 'bootstrap.sh')
        self.refuses_locally('unlisted')

    def test_a_missing_deploy_pin_is_refused_before_anything_else(self):
        self.fx.build(pin=False)
        self.refuses_locally('no-deploy-pin')
        self.fx.build()
        (self.fx.dir / 'deploy-pin.json.sig').unlink()
        self.refuses_locally('missing')

    def test_a_missing_bundle_that_the_url_names_is_refused_missing(self):
        self.fx.build()
        (self.fx.dir / BUNDLE).unlink()
        self.refuses_locally('missing')

    def test_a_local_refusal_never_reaches_gh(self):
        self.fx.build()
        self.fx.put('extra.txt', b'x')
        gh = FakeGh()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = fp.main(['x', 'publish', str(self.fx.dir), '--owner-pub', str(self.fx.pub), '--min-serial', '0'],
                           {'GITHUB_REPOSITORY': REPO, 'GITHUB_SHA': SHA, 'GH_TOKEN': TOKEN}, gh, now=NOW)
        self.assertEqual((code, out.getvalue().strip()), (1, 'REFUSED unlisted'))
        self.assertEqual(gh.calls, [])

    # the tag

    def test_an_existing_tag_is_refused_whether_a_bare_tag_or_a_release_and_nothing_is_created(self):
        self.fx.build()
        for gh in (FakeGh(refs=[{'ref': f'refs/tags/{TAG}'}]), FakeGh(releases=[{'tagName': TAG, 'isDraft': True}])):
            self.assertEqual(self.refuses('tag-exists', gh).creates(), [])

    def test_another_serial_that_only_starts_with_the_tag_is_not_the_tag(self):
        self.fx.build()
        gh = FakeGh(refs=[{'ref': f'refs/tags/{TAG}0'}], releases=[{'tagName': f'{TAG}0', 'isDraft': False}])
        fp.publish(gh, self.fx.check(), REPO, SHA, TOKEN)
        self.assertEqual(len(gh.creates()), 1)

    def test_a_tag_check_that_cannot_be_answered_refuses(self):
        self.fx.build()
        gh = FakeGh()
        gh.query_code = 1
        self.assertEqual(self.refuses('tag-check-failed', gh).creates(), [])

    def test_a_missing_release_environment_refuses_before_gh(self):
        self.fx.build()
        for repo, sha_, token in (('', SHA, TOKEN), (REPO, 'zz', TOKEN), (REPO, SHA, '')):
            gh = FakeGh()
            with self.assertRaises(fp.Refused) as why:
                fp.publish(gh, self.fx.check(), repo, sha_, token)
            self.assertEqual((why.exception.code, gh.calls), ('release-env', []))

    # immutable releases

    def test_immutable_off_stops_before_the_release_even_with_a_confirmation(self):
        self.fx.build()
        for confirmed in ('', 'yes'):
            gh = self.refuses('immutable-off', FakeGh(immutable=(0, '{"enabled": false}')), confirmed)
            self.assertEqual(gh.creates(), [])

    def test_an_unreadable_immutable_setting_stops_unless_the_owner_confirmed(self):
        self.fx.build()
        for answer in ((1, ''), (0, 'not json'), (0, '[]'), (0, '{"enabled": "true"}'), (0, '{}')):
            with self.subTest(answer):
                self.assertEqual(self.refuses('immutable-unreadable', FakeGh(immutable=answer)).creates(), [])
        self.refuses('immutable-unreadable', FakeGh(immutable=(1, '')), 'maybe')
        gh = FakeGh(immutable=(1, ''))
        with contextlib.redirect_stderr(io.StringIO()):
            fp.publish(gh, self.fx.check(), REPO, SHA, TOKEN, 'yes')
        self.assertEqual(len(gh.creates()), 1)

    # GitHub's digests read back

    def test_a_digest_that_differs_from_the_checked_one_is_refused_publish_mismatch(self):
        self.fx.build()
        gh = FakeGh()
        gh.tweak = lambda assets: [dict(assets[0], digest='sha256:' + '0' * 64)] + assets[1:]
        self.refuses('publish-mismatch', gh)

    def test_a_missing_extra_duplicate_or_resized_asset_is_refused_publish_mismatch(self):
        self.fx.build()
        for tweak in (lambda a: a[1:], lambda a: a + [{'name': 'x', 'digest': 'sha256:' + '0' * 64, 'size': 1}],
                      lambda a: a + [a[0]], lambda a: [dict(a[0], size=1)] + a[1:],
                      lambda a: [dict(x, digest=None) for x in a]):
            gh = FakeGh()
            gh.tweak = tweak
            self.refuses('publish-mismatch', gh)

    def test_a_failed_create_is_refused_publish_failed(self):
        self.fx.build()
        self.refuses('publish-failed', FakeGh(create_code=1))

    # the command line

    def test_main_publishes_and_verify_never_calls_gh(self):
        self.fx.build()
        argv = lambda verb: ['x', verb, str(self.fx.dir), '--owner-pub', str(self.fx.pub), '--min-serial', '5']  # noqa
        env = {'GITHUB_REPOSITORY': REPO, 'GITHUB_SHA': SHA, 'GH_TOKEN': TOKEN}
        gh = FakeGh()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(fp.main(argv('verify'), {'GITHUB_REPOSITORY': REPO}, gh, now=NOW), 0)
            self.assertEqual(gh.calls, [])
            self.assertEqual(fp.main(argv('publish'), env, gh, now=NOW), 0)
        self.assertIn('OK install-5', out.getvalue())
        self.assertIn('verified against SHA256:', err.getvalue())
        self.assertNotIn(TOKEN, out.getvalue() + err.getvalue())

    def test_a_bad_command_line_is_usage_2(self):
        for argv in (['x'], ['x', 'publish', 'd'], ['x', 'nope', 'd', '--owner-pub', 'k', '--min-serial', '1'],
                     ['x', 'publish', 'd', '--owner-pub', 'k', '--min-serial', '-1'],
                     ['x', 'publish', 'd', '--min-serial', '1', '--owner-pub', 'k']):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(fp.main(argv, {}, FakeGh()), 2)

    def test_the_real_script_refuses_a_missing_folder_before_any_network_call(self):
        done = subprocess.run([sys.executable, str(ROOT / 'bin/fleet-install-publish.py'), 'publish',
                               str(Path(self._tmp.name) / 'install-9'), '--owner-pub', str(self.fx.pub),
                               '--min-serial', '0'], capture_output=True, text=True, timeout=60,
                              env={'PATH': '/usr/bin:/bin'})
        self.assertEqual((done.returncode, done.stdout.strip()), (1, 'REFUSED dir'))


class OwnerKey(unittest.TestCase):
    PIN = ('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDVIWCyjvYMcqnICKNrysNOrkMmE3NXHbRFTlQG9fPTZ fleet-pin\n')

    def test_the_committed_key_is_the_owners_one_line_and_its_fingerprint_is_stable(self):
        text = (ROOT / 'keys/owner-pin.pub').read_text(encoding='ascii')
        self.assertEqual(text, self.PIN)
        self.assertEqual(fp.key_fingerprint(text.encode()), 'SHA256:WUdTSPIrp0kNwRkqLVXN7ifG9Gg5pZF95NnPsPDKTfU')
        self.assertNotRegex(text, r'PRIVATE')


class VendoredVerifier(unittest.TestCase):
    """Section 1 against a frozen golden of I01's fleet/install/manifest.py (private repo commit 433018e): a change to
    either side must come with a new copy and a new golden."""

    def test_the_constants_equal_the_golden(self):
        self.assertEqual((fp.NS, fp.PRINCIPAL, fp.KIND), ('mirrorstack-fleet-install', 'owner', 'install'))
        self.assertEqual((fp.MAX_BYTES, fp.MAX_BUNDLE, fp.MAX_COUNT), (8192, 1 << 30, 1 << 31))
        self.assertEqual(fp.CODES, ('size', 'key', 'sig', 'form', 'kind', 'expired', 'rollback', 'tree'))
        self.assertEqual(fp.SCHEMA, ('kind', 'serial', 'valid_until', 'source_head', 'bootstrap', 'kit', 'lock_sha256',
                                     'bundle'))
        self.assertEqual((fp.BOOT_KEYS, fp.KIT_KEYS, fp.BUNDLE_KEYS, fp.OSES),
                         (('sha256', 'blob'), ('serial', 'kit_json_sha256'), ('head', 'tree', 'url', 'sha256', 'size'),
                          ('ps1', 'sh')))
        self.assertEqual((fp.HEX40.pattern, fp.HEX64.pattern, fp.UTC_TIME.pattern, fp._KEY.pattern),
                         ('[0-9a-f]{40}', '[0-9a-f]{64}', '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',
                          '[A-Za-z0-9+/]{68}'))
        label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
        self.assertEqual(fp.URL.pattern, rf'https://({label}(?:\.{label})+)/[A-Za-z0-9._~/-]{{1,200}}')
        self.assertEqual(fp.SSH_KEYGEN, '/usr/bin/ssh-keygen' if os.name != 'nt'
                         else 'C:\\Windows\\System32\\OpenSSH\\ssh-keygen.exe')

    def test_the_top_of_the_file_names_the_copied_commit(self):
        self.assertRegex((ROOT / 'bin/fleet-install-publish.py').read_text(encoding='utf-8')[:2500],
                         r'commit 433018e55d94a31afb42ec07670393ae3e8b9fae')

    def test_a_good_manifest_parses_and_each_misfit_has_its_golden_code(self):
        good = manifest()
        self.assertEqual(fp.parse_install(json.dumps(good).encode()), good)
        cases = {
            'kind': [{**good, 'kind': 'kit'}, {**good, 'kind': 'gateway'}, [1]],
            'form': [{**good, 'extra': 1}, {k: v for k, v in good.items() if k != 'bundle'},
                     {**good, 'serial': -1}, {**good, 'serial': True}, {**good, 'serial': 1.0},
                     {**good, 'serial': 1 << 32}, {**good, 'valid_until': '2026-12-01T00:00:00.5Z'},
                     {**good, 'valid_until': '2026-13-01T00:00:00Z'}, {**good, 'source_head': 'C' * 40},
                     {**good, 'lock_sha256': 'd' * 63}, {**good, 'kit': {**good['kit'], 'x': 1}},
                     {**good, 'bootstrap': {'ps1': good['bootstrap']['ps1']}},
                     {**good, 'bundle': {**good['bundle'], 'url': 'http://example.org/b'}},
                     {**good, 'bundle': {**good['bundle'], 'url': 'https://localhost/b'}},
                     {**good, 'bundle': {**good['bundle'], 'size': 0}},
                     {**good, 'bundle': {**good['bundle'], 'size': (1 << 30) + 1}}],
        }
        for code, docs in cases.items():
            for doc in docs:
                with self.subTest(code=code, doc=str(doc)[:60]), self.assertRaises(fp.Refused) as why:
                    fp.parse_install(json.dumps(doc).encode())
                self.assertEqual(why.exception.code, code)
        self.assertEqual(fp.parse_install(json.dumps({**good, 'serial': (1 << 31)}).encode())['serial'], 1 << 31)
        for raw in (b'\xef\xbb\xbf' + json.dumps(good).encode(), b'\xff', b'{"kind": "install", "kind": "install"}',
                    b'{"kind": NaN}', b'{"kind": 1e999}', b'[' * 5000, b''):
            with self.subTest(raw=raw[:20]), self.assertRaises(fp.Refused) as why:
                fp.parse_install(raw)
            self.assertEqual(why.exception.code, 'form')

    def test_an_oversize_file_is_size_before_ssh_keygen_runs(self):
        def boom(argv, stdin):
            raise AssertionError('ssh-keygen ran')
        with self.assertRaises(fp.Refused) as why:
            fp.signed_install(b'x' * 8193, b'', b'', min_serial=0, now=NOW, in_tree=lambda *_: True, run=boom)
        self.assertEqual(why.exception.code, 'size')

    def test_the_signature_comes_before_the_bytes_are_read(self):
        calls = []
        def deny(argv, stdin):
            calls.append(argv)
            return 255, b''
        key = 'ssh-ed25519 ' + 'A' * 68
        with self.assertRaises(fp.Refused) as why:
            fp.signed_install(b'not json', b'sig', key.encode(), min_serial=0, now=NOW, in_tree=lambda *_: True,
                              run=deny)
        self.assertEqual((why.exception.code, len(calls)), ('sig', 1))
        self.assertEqual(calls[0][0], fp.SSH_KEYGEN)
        self.assertEqual(calls[0][1:3], ('-Y', 'verify'))
        self.assertEqual(calls[0][calls[0].index('-n') + 1], 'mirrorstack-fleet-install')
        self.assertEqual(calls[0][calls[0].index('-I') + 1], 'owner')

    def test_the_publisher_only_adds_codes_the_golden_does_not_have(self):
        self.assertFalse(set(fp.PUBLISH_CODES) & set(fp.CODES))


class Workflow(unittest.TestCase):
    TEXT = (ROOT / '.github/workflows/install.yml').read_text(encoding='utf-8')
    DISK = (ROOT / '.github/workflows/disk.yml').read_text(encoding='utf-8')

    def test_it_is_a_main_only_dispatch_with_two_inputs_in_the_release_environment(self):
        self.assertRegex(self.TEXT, r'(?m)^on:\n  workflow_dispatch:\n    inputs:\n      serial:\n')
        self.assertEqual(re.findall(r'(?m)^      (\w+):\n        (?:description|required)', self.TEXT),
                         ['serial', 'min_serial'])
        self.assertNotIn('pull_request', self.TEXT)
        self.assertNotIn('push:', self.TEXT)
        self.assertIn("if: github.ref == 'refs/heads/main'", self.TEXT)
        self.assertEqual(re.findall(r'(?m)^    environment: (\S+)$', self.TEXT), ['release'])
        self.assertEqual(re.findall(r'runs-on: (\S+)', self.TEXT), ['ubuntu-24.04'])
        self.assertNotIn('self-hosted', self.TEXT)

    def test_only_the_one_job_writes_and_only_contents(self):
        self.assertRegex(self.TEXT, r'(?m)^permissions:\n  contents: read\n')
        self.assertEqual(re.findall(r'(\w[\w-]*): write', self.TEXT), ['contents'])
        self.assertIn('    permissions:\n      contents: write\n', self.TEXT)
        self.assertEqual(self.TEXT.count('jobs:'), 1)
        self.assertEqual(len(re.findall(r'(?m)^  \w+:\n    (?:#.*\n    )*(?:if|environment)', self.TEXT)), 1)

    def test_the_actions_are_sha_pinned_the_same_as_disk_and_no_credential_stays_in_git(self):
        self.assertEqual(re.findall(r'uses: (actions/checkout@\S+)', self.TEXT),
                         re.findall(r'uses: (actions/checkout@\S+)', self.DISK))
        for uses in re.findall(r'uses: (\S+)', self.TEXT):
            self.assertRegex(uses, r'^actions/checkout@[0-9a-f]{40}$')
        self.assertEqual(self.TEXT.count('persist-credentials: false'), self.TEXT.count('actions/checkout@'))

    def test_the_inputs_reach_the_script_only_through_env(self):
        runs = re.findall(r'(?m)^\s+(?:- )?run: (.*)$', self.TEXT)
        self.assertEqual(runs, ['python3 bin/fleet-install-publish.py publish "release/install-$SERIAL"'
                                ' --owner-pub keys/owner-pin.pub --min-serial "$MIN_SERIAL"'])
        for want in ('SERIAL: ${{ inputs.serial }}', 'MIN_SERIAL: ${{ inputs.min_serial }}',
                     'GH_TOKEN: ${{ github.token }}'):
            self.assertIn(want, self.TEXT)
        self.assertNotRegex(self.TEXT, r'(?i)secrets\.')
        self.assertIn('timeout-minutes: 60', self.TEXT)


if __name__ == '__main__':
    unittest.main()
