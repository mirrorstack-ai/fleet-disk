"""bin/fleet-install-publish.py over a fake gh and a throwaway ssh-keygen key, with no network: the signature (unsigned,
wrong key, wrong namespace), every hash, an unlisted file, the missing deploy-pin.json, the 30 days of validity, an
existing tag, the immutable setting, GitHub's digests read back, the exact gh calls, the owner key from the environment,
the copied manifest rules frozen against a golden, and the workflow's shape. The signature tests are skipped when ssh-keygen is missing. Plain unittest, stdlib only."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
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
BUNDLE_TREE = 'e' * 40
PIN_BYTES = json.dumps({'serial': 4, 'head': H40, 'tree': BUNDLE_TREE}).encode()  # the bundle's head and tree


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
           'bundle': {'head': H40, 'tree': BUNDLE_TREE, 'url': BUNDLE_URL, 'sha256': sha(BUNDLE_BYTES),
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
        self.plans: list = []
        self._cwd = os.getcwd()
        os.chdir(tmp)  # check_dir wants the relative release/install-<serial>, as the workflow runs it

    def cleanup(self) -> None:
        for plan in self.plans:
            plan.cleanup()
        os.chdir(self._cwd)

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
            sign(self.key, self.put('deploy-pin.json', PIN_BYTES), fp.PIN_NS)
        self.put('.gitattributes', fp.GITATTRIBUTES)
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
        plan = fp.check_dir(Path('release') / self.dir.name, self.pub.read_bytes(), min_serial, now, repo)
        self.plans.append(plan)
        return plan


class FakeGh:
    """The Io of the publish: records every call, answers the four gh queries and serves what `release create` got."""

    def __init__(self, refs=None, releases=None, immutable=(0, '{"enabled": true}'), create_code=0) -> None:
        self.calls: list[list[str]] = []
        self.envs: list[dict] = []
        self.timeouts: list[int] = []
        self.release_flags = {'immutable': True, 'draft': False}  # what GitHub says about the created release
        self.refs, self.releases = refs if refs is not None else [], releases if releases is not None else []
        self.immutable, self.create_code, self.created = immutable, create_code, []
        self.tweak = lambda assets: assets  # a test edits what GitHub "serves" back
        self.query_code = 0

    def run(self, argv, env, timeout=fp.TOOL_TIMEOUT):
        self.calls.append(list(argv))
        self.envs.append(dict(env))
        self.timeouts.append(timeout)
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
            return 0, json.dumps({'assets': self.tweak(assets), **self.release_flags})
        raise AssertionError(argv)

    def creates(self) -> list[list[str]]:
        return [c for c in self.calls if c[1:3] == ['release', 'create']]


@unittest.skipUnless(HAVE_KEYGEN, 'ssh-keygen is missing')
class Publish(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.fx = Fixture(Path(self._tmp.name))
        self.addCleanup(self.fx.cleanup)  # runs before the temp dir is removed (LIFO)

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
        self.assertEqual(Path(create[4]).name, 'install.json')
        self.assertNotEqual(Path(create[4]).parent, self.fx.dir)  # uploaded from the private copy, not the folder
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
            code = fp.main(['x', 'publish', f'release/{TAG}', '--owner-pub', str(self.fx.pub), '--min-serial', '0'],
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
        gh = FakeGh(refs=[{'ref': f'refs/tags/{TAG}0'}], releases=[{'tagName': 'v1', 'isDraft': False}])
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

    # second review: the pin, the immutable flag, one read per file, the folder, the floor, .gitattributes, test gaps

    def put_pin(self, data: bytes) -> None:
        sign(self.fx.key, self.fx.put('deploy-pin.json', data), fp.PIN_NS)

    def test_the_pin_has_exactly_serial_head_tree_in_verify_archives_shape(self):
        good = {'serial': 4, 'head': 'a' * 40, 'tree': 'b' * 40}
        for bad in (b'[1]', b'"x"', b'null', b'{"serial": 0, "head": null}', json.dumps({**good, 'x': 1}).encode(),
                    json.dumps({k: v for k, v in good.items() if k != 'tree'}).encode(),
                    json.dumps({**good, 'serial': True}).encode(), json.dumps({**good, 'serial': 1.0}).encode(),
                    json.dumps({**good, 'serial': -1}).encode(), json.dumps({**good, 'head': 'A' * 40}).encode(),
                    json.dumps({**good, 'tree': 'b' * 39}).encode(), b'{"serial": 1, "serial": 1}', b'not json'):
            with self.subTest(bad[:30]):
                self.fx.build()
                self.put_pin(bad)
                self.refuses_locally('form')

    def pin_with(self, **over) -> bytes:
        return json.dumps({**json.loads(PIN_BYTES), **over}).encode()

    def test_a_pin_of_the_bundles_head_and_tree_passes_whatever_its_serial(self):
        self.fx.build()
        self.put_pin(self.pin_with(serial=99))  # the serial is the PC's verify-archive floor, not compared here
        self.assertEqual(self.fx.check().tag, TAG)

    def test_a_pin_of_another_head_than_the_bundle_is_refused_pin_mismatch(self):
        self.fx.build()
        self.put_pin(self.pin_with(head='1' * 40))
        self.refuses_locally('pin-mismatch')

    def test_a_pin_of_another_tree_than_the_bundle_is_refused_pin_mismatch(self):
        self.fx.build()
        self.put_pin(self.pin_with(tree='2' * 40))
        self.refuses_locally('pin-mismatch')

    def test_without_the_bundle_in_the_release_the_pin_is_not_compared(self):
        self.fx.build(bundle=False)
        self.put_pin(self.pin_with(head='1' * 40, tree='2' * 40))
        self.assertEqual(self.fx.check().tag, TAG)

    def test_without_the_bundle_a_pin_of_a_bad_shape_or_signature_is_still_refused(self):
        self.fx.build(bundle=False)
        self.put_pin(b'[1]')
        self.refuses_locally('form')
        self.fx.build(bundle=False)
        sign(self.fx.other, self.fx.dir / 'deploy-pin.json', fp.PIN_NS)
        self.refuses_locally('sig')

    def test_the_created_release_must_read_back_immutable_and_not_a_draft(self):
        self.fx.build()
        for flags in ({'immutable': False, 'draft': False}, {'immutable': True, 'draft': True}, {'draft': False},
                      {'immutable': 'true', 'draft': False}, {'immutable': True}):
            with self.subTest(flags):
                gh = FakeGh()
                gh.release_flags = flags
                self.refuses('immutable-not-set', gh)

    def test_a_confirmed_but_wrong_immutable_variable_does_not_publish_a_mutable_release_unnoticed(self):
        self.fx.build()
        gh = FakeGh(immutable=(1, ''))
        gh.release_flags = {'immutable': False, 'draft': False}
        with contextlib.redirect_stderr(io.StringIO()):
            self.refuses('immutable-not-set', gh, 'yes')

    def test_the_uploaded_bytes_are_the_verified_ones_even_if_the_folder_changes_after_the_check(self):
        self.fx.build()
        plan = self.fx.check()
        self.fx.put('bootstrap.sh', SH + b'echo swapped\n')
        self.fx.put(BUNDLE, b'swapped')
        gh = FakeGh()
        fp.publish(gh, plan, REPO, SHA, TOKEN)  # the read-back digests are those of the signed bytes
        self.assertEqual(gh.created[0].parent, plan.stage)
        by_name = {p.name: p for p in gh.created}
        self.assertEqual(by_name['bootstrap.sh'].read_bytes(), SH)
        self.assertEqual(by_name[BUNDLE].read_bytes(), BUNDLE_BYTES)
        self.assertEqual(sha(SH), next(a.sha256 for a in plan.assets if a.name == 'bootstrap.sh'))

    def test_the_stage_is_removed_after_main_and_on_a_refusal(self):
        self.fx.build()
        before = set(Path(tempfile.gettempdir()).glob('fleet-install-*'))
        self.fx.put('extra.txt', b'x')
        self.refuses_locally('unlisted')
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            fp.main(['x', 'publish', f'release/{TAG}', '--owner-pub', str(self.fx.pub), '--min-serial', '0'],
                    {'GITHUB_REPOSITORY': REPO, 'GITHUB_SHA': SHA, 'GH_TOKEN': TOKEN}, FakeGh(), now=NOW)
        (self.fx.dir / 'extra.txt').unlink()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            fp.main(['x', 'publish', f'release/{TAG}', '--owner-pub', str(self.fx.pub), '--min-serial', '0'],
                    {'GITHUB_REPOSITORY': REPO, 'GITHUB_SHA': SHA, 'GH_TOKEN': TOKEN}, FakeGh(), now=NOW)
        self.assertEqual(set(Path(tempfile.gettempdir()).glob('fleet-install-*')), before)

    def test_a_symlink_named_like_a_listed_file_is_refused(self):
        self.fx.build()
        (self.fx.dir / 'bootstrap.sh').unlink()
        (self.fx.dir / 'bootstrap.sh').symlink_to(self.fx.dir / 'bootstrap.ps1')
        self.refuses_locally('unlisted')

    def test_snapshot_refuses_a_link_even_if_it_was_swapped_in_after_the_scan(self):
        self.fx.build()
        link = self.fx.dir / 'bootstrap.sh'
        link.unlink()
        link.symlink_to(self.fx.dir / 'bootstrap.ps1')
        with tempfile.TemporaryDirectory() as stage, self.assertRaises(fp.Refused) as why:
            fp.snapshot(link, Path(stage), 1 << 20)
        self.assertEqual(why.exception.code, 'unlisted')

    def test_a_bundle_of_the_right_size_and_other_bytes_is_refused_hash(self):
        self.fx.build()
        self.fx.put(BUNDLE, b'X' * len(BUNDLE_BYTES))
        self.refuses_locally('hash')

    def test_a_bundle_whose_signed_size_is_not_its_size_is_refused_hash_though_the_sha_matches(self):
        self.fx.build(bundle=True)
        doc = manifest()
        doc['bundle']['size'] = len(BUNDLE_BYTES) + 1
        doc['kit']['kit_json_sha256'] = sha((self.fx.dir / 'kit.json').read_bytes())
        self.fx.signed_install(doc)
        self.refuses_locally('hash')

    def test_the_folder_must_be_exactly_release_install_serial_in_canonical_form(self):
        self.fx.build()
        pub = self.fx.pub.read_bytes()
        for d in ('../install-5', 'install-5', 'a#b/install-5', 'release/a/install-5', 'x/release/install-5',
                  str(self.fx.dir), 'release/install-05', 'release/install-005', 'release/install-+5',
                  'release/install-x/y'):
            with self.subTest(d), self.assertRaises(fp.Refused) as why:
                fp.check_dir(Path(d), pub, 0, NOW, REPO)
            self.assertEqual(why.exception.code, 'dir')
        self.assertEqual(self.fx.check().tag, TAG)

    def test_leading_zeros_in_the_folder_name_are_refused_so_one_serial_has_one_tag(self):
        self.fx.build(serial=7)
        moved = self.fx.dir.parent / 'install-007'
        self.fx.dir.rename(moved)
        self.fx.dir = moved
        self.refuses_locally('dir')

    def test_a_serial_not_above_the_newest_existing_install_release_is_refused_not_newer(self):
        self.fx.build()
        for tags in (['install-9'], ['install-4', 'install-50'], ['v1', 'install-6']):
            with self.subTest(tags):
                gh = self.refuses('not-newer', FakeGh(releases=[{'tagName': t, 'isDraft': False} for t in tags]))
                self.assertEqual(gh.creates(), [])
        gh = FakeGh(releases=[{'tagName': 'install-4', 'isDraft': False}, {'tagName': 'install-abc'}, {'tagName': 'v9'}])
        fp.publish(gh, self.fx.check(), REPO, SHA, TOKEN)
        self.assertEqual(len(gh.creates()), 1)

    def test_a_kit_json_serial_other_than_the_signed_one_is_refused_kit(self):
        self.fx.build()
        doc = manifest()
        doc['kit']['serial'] = 4
        doc['kit']['kit_json_sha256'] = sha((self.fx.dir / 'kit.json').read_bytes())
        self.fx.signed_install(doc)
        self.refuses_locally('kit')

    def test_gitattributes_must_be_the_committed_constant(self):
        for data in (fp.GITATTRIBUTES + b'*.sh eol=lf\n', b'* text=auto eol=lf\n*.ps1 eol=crlf\n' + b'#' * 5000,
                     'caf\u00e9\n'.encode(), b'', b'* -text\n'):
            with self.subTest(data[:20]):
                self.fx.build()
                self.fx.put('.gitattributes', data)
                self.refuses_locally('size' if len(data) > fp.MAX_ATTR else 'attributes')

    def test_gh_runs_under_exactly_four_variables(self):
        self.fx.build()
        gh = FakeGh()
        fp.publish(gh, self.fx.check(), REPO, SHA, TOKEN)
        self.assertTrue(gh.envs)
        for env in gh.envs:
            self.assertEqual(set(env), {'PATH', 'GH_TOKEN', 'GH_REPO', 'GH_PROMPT_DISABLED'})


    # the exact gh calls (the fake alone proves nothing about what is asked of gh)

    def test_publish_makes_exactly_these_gh_calls_in_this_order_under_the_repo(self):
        self.fx.build()
        gh = FakeGh()
        plan = self.fx.check()
        fp.publish(gh, plan, REPO, SHA, TOKEN)
        notes = (f'Owner-signed install set {TAG}. Verify install.json with ssh-keygen -Y verify'
                 f' -n mirrorstack-fleet-install -I owner.')
        self.assertEqual(gh.calls, [
            ['/usr/bin/gh', 'api', f'repos/{REPO}/git/matching-refs/tags/{TAG}'],
            ['/usr/bin/gh', 'release', 'list', '--limit', '1000', '--json', 'tagName,isDraft'],
            ['/usr/bin/gh', 'api', f'repos/{REPO}/immutable-releases'],
            ['/usr/bin/gh', 'release', 'create', TAG, *(str(plan.stage / a.name) for a in plan.assets),
             '--target', SHA, '--title', TAG, '--notes', notes],
            ['/usr/bin/gh', 'api', f'repos/{REPO}/releases/tags/{TAG}'],
        ])
        want_env = {'PATH': '/usr/bin', 'GH_TOKEN': TOKEN, 'GH_REPO': REPO, 'GH_PROMPT_DISABLED': '1'}
        self.assertEqual(gh.envs, [want_env] * 5)
        self.assertEqual(gh.envs[0]['GH_REPO'], REPO)
        self.assertEqual(gh.timeouts, [fp.TOOL_TIMEOUT] * 3 + [fp.UPLOAD_TIMEOUT, fp.TOOL_TIMEOUT])

    # main(): the one real path, where the job token cannot read the immutable setting

    def run_main(self, verb='publish', gh=None, env=None, key=None, run=fp.run_argv):
        gh = gh or FakeGh()
        environ = {'GITHUB_REPOSITORY': REPO, 'GITHUB_SHA': SHA, 'GH_TOKEN': TOKEN, **(env or {})}
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = fp.main(['x', verb, f'release/{TAG}', '--owner-pub', str(key or self.fx.pub), '--min-serial', '0'],
                           environ, gh, run=run, now=NOW)
        return code, out.getvalue(), err.getvalue(), gh

    def test_main_publishes_an_unreadable_immutable_setting_on_the_owners_confirmation(self):
        self.fx.build()
        gh = FakeGh(immutable=(1, ''))  # the /immutable-releases call fails: the job token cannot read it
        code, out, err, _ = self.run_main(gh=gh, env={'IMMUTABLE_CONFIRMED': 'yes'})
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith(f'OK {TAG}\n'))
        self.assertEqual(len(gh.creates()), 1)
        self.assertIn('unreadable by this token', err)

    def test_main_refuses_immutable_unreadable_without_the_confirmation(self):
        self.fx.build()
        for env in ({}, {'IMMUTABLE_CONFIRMED': ''}, {'IMMUTABLE_CONFIRMED': 'no'}, {'IMMUTABLE_CONFIRMED': 'YES'}):
            with self.subTest(env):
                gh = FakeGh(immutable=(1, ''))
                code, out, _, _ = self.run_main(gh=gh, env=env)
                self.assertEqual((code, out.strip()), (1, 'REFUSED immutable-unreadable'))
                self.assertEqual(gh.creates(), [])

    # the bundle's name

    def resign(self, url: str | None = None, **bundle) -> None:
        """Re-sign install.json with another bundle url (or fields), keeping kit.json's hash right."""
        doc = manifest()
        doc['bundle'].update(bundle)
        if url is not None:
            doc['bundle']['url'] = url
        doc['kit']['kit_json_sha256'] = sha((self.fx.dir / 'kit.json').read_bytes())
        self.fx.signed_install(doc)

    def test_a_bundle_whose_signed_name_is_not_a_plain_file_name_is_refused_bundle_name(self):
        prefix = BUNDLE_URL[:-len(BUNDLE)]
        for name in ('', '.hidden', '..', '-x.tar', '~x.tar', '_x.tar', '.gitattributes'):
            with self.subTest(name):
                self.fx.build()
                self.resign(url=prefix + name)
                self.refuses_locally('bundle-name')

    def test_a_plain_bundle_name_with_dots_dashes_and_underscores_is_fine(self):
        self.fx.build()
        (self.fx.dir / BUNDLE).unlink()
        self.fx.put('A_b-1.2.tar.gz', BUNDLE_BYTES)
        self.resign(url=BUNDLE_URL[:-len(BUNDLE)] + 'A_b-1.2.tar.gz')
        self.assertEqual(self.fx.check().assets[-1].name, 'A_b-1.2.tar.gz')

    def test_a_bundle_named_like_a_fixed_file_or_its_published_name_is_refused_unlisted_not_a_traceback(self):
        for name in ('bootstrap.sh', 'install.json', 'carrier-check.py', 'default.gitattributes'):
            with self.subTest(name):
                self.fx.build()
                self.fx.put(name, BUNDLE_BYTES) if name == 'default.gitattributes' else None
                self.resign(url=BUNDLE_URL[:-len(BUNDLE)] + name)
                self.refuses_locally('unlisted')
        self.fx.build()
        self.resign(url=BUNDLE_URL[:-len(BUNDLE)] + 'bootstrap.sh')
        code, out, err, gh = self.run_main()
        self.assertEqual((code, out.strip(), gh.calls), (1, 'REFUSED unlisted', []))
        self.assertNotIn('Traceback', err)

    def test_the_read_back_name_of_the_bundle_must_equal_the_signed_name_exactly(self):
        self.fx.build()
        for served in (f'default.{BUNDLE}', f'default{BUNDLE}', BUNDLE.upper()):
            with self.subTest(served):
                gh = FakeGh()
                gh.tweak = lambda assets, served=served: [dict(a, name=served) if a['name'] == BUNDLE else a
                                                          for a in assets]
                self.refuses('publish-mismatch', gh)

    def test_only_gitattributes_may_be_read_back_under_the_default_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / '.other'
            path.write_bytes(b'x')
            plan = fp.Plan(TAG, {'serial': SERIAL}, [fp.Asset(path, sha(b'x'), 1)], 'SHA256:x', Path(tmp))
            gh = FakeGh()
            fp.publish(gh, plan, REPO, SHA, TOKEN)  # served as .other, exactly: fine
            gh = FakeGh()
            gh.tweak = lambda assets: [dict(a, name='default.other') for a in assets]
            with self.assertRaises(fp.Refused) as why:
                fp.publish(gh, plan, REPO, SHA, TOKEN)
            self.assertEqual(why.exception.code, 'publish-mismatch')

    def test_a_bundle_url_of_this_release_with_an_empty_repo_is_not_this_release(self):
        self.fx.build()
        self.resign(url=f'https://github.com//releases/download/{TAG}/{BUNDLE}')
        self.refuses_locally('unlisted', repo='')  # the bundle file is then a file nothing signed accounts for

    # every size guard, and the path guards, each with the test that fails without it

    def test_a_small_file_over_max_small_is_refused_size(self):
        for name in ('kit.json.sig', 'deploy-pin.json', 'install.json.sig', 'bootstrap.sh'):
            with self.subTest(name):
                self.fx.build()
                self.fx.put(name, b'x' * (fp.MAX_SMALL + 1))
                self.refuses_locally('size')

    def test_a_kit_file_over_max_kit_is_refused_size(self):
        self.fx.build()
        self.fx.put('verify-archive.py', b'x' * (fp.MAX_KIT + 1))
        self.refuses_locally('size')

    def test_a_bundle_over_the_bundle_limit_is_refused_size_before_its_hash_is_judged(self):
        self.fx.build()
        self.fx.put(BUNDLE, b'x' * 2000)
        with mock.patch.object(fp, 'MAX_BUNDLE', 1500):  # the signed size (1000) still fits the manifest's own bound
            self.refuses_locally('size')

    def test_install_json_over_its_limit_is_refused_size_and_each_file_is_snapshotted_under_its_own_limit(self):
        self.fx.build()
        self.fx.put('install.json', b'x' * (fp.MAX_BYTES + 1))
        self.refuses_locally('size')
        self.fx.build()
        with mock.patch.object(fp, 'snapshot', wraps=fp.snapshot) as spy:
            self.fx.check()
        limits = {call.args[0].name: call.args[2] for call in spy.call_args_list}
        want = {name: fp.MAX_KIT if name in fp.KIT_FILES else fp.MAX_SMALL for name in fp.FIXED + fp.KIT_FILES}
        want.update({'install.json': fp.MAX_BYTES, '.gitattributes': fp.MAX_ATTR, BUNDLE: fp.MAX_BUNDLE})
        self.assertEqual(limits, want)

    def test_snapshot_refuses_a_fifo_or_a_folder_where_a_file_is_expected(self):
        self.fx.build()
        fifo = self.fx.dir / 'fifo'
        os.mkfifo(fifo)
        (self.fx.dir / 'folder').mkdir()
        if hasattr(signal, 'SIGALRM'):  # a snapshot that blocked on the FIFO would hang here, not fail
            signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(AssertionError('snapshot blocked')))
            signal.alarm(20)
            self.addCleanup(signal.alarm, 0)
        for path in (fifo, self.fx.dir / 'folder'):
            with self.subTest(path.name), tempfile.TemporaryDirectory() as stage, self.assertRaises(fp.Refused) as why:
                fp.snapshot(path, Path(stage), 1 << 20)
            self.assertEqual(why.exception.code, 'unlisted')
        self.assertTrue(stat.S_ISFIFO(os.lstat(fifo).st_mode))

    def test_the_pin_serial_has_an_upper_bound(self):
        self.fx.build()
        self.put_pin(self.pin_with(serial=fp.MAX_COUNT))
        self.assertEqual(self.fx.check().tag, TAG)
        self.put_pin(self.pin_with(serial=fp.MAX_COUNT + 1))
        self.refuses_locally('form')

    def test_a_kit_json_path_that_is_not_a_string_is_refused_kit_and_never_a_traceback(self):
        for bad in (['carrier-check.py'], 5, None, {'x': 1}):
            with self.subTest(str(bad)):
                self.fx.build()
                kit = json.loads((self.fx.dir / 'kit.json').read_bytes())
                kit['files'][0]['path'] = bad
                data = json.dumps(kit).encode()
                sign(self.fx.key, self.fx.put('kit.json', data), fp.PIN_NS)
                self.resign()
                self.refuses_locally('kit')

    # the owner's key comes from the release environment, never from this repo

    def test_there_is_no_key_file_in_the_repo(self):
        self.assertEqual([p.name for p in ROOT.rglob('*.pub') if '.git' not in p.parts], [])
        self.assertFalse((ROOT / 'keys').exists())

    def test_a_missing_or_malformed_key_file_is_refused_key_before_anything_else(self):
        self.fx.build()
        line = self.fx.pub.read_bytes()
        blob = line.split()[1]
        bad = {'empty': b'', 'newline only': b'\n', 'two lines': line + line, 'blank then key': b'\n' + line,
               'wrong type': b'ssh-rsa ' + blob + b'\n', 'short blob': b'ssh-ed25519 ' + blob[:-1] + b'\n',
               'long blob': b'ssh-ed25519 ' + blob + b'A\n', 'crlf': line.rstrip(b'\n') + b'\r\n',
               'leading space': b' ' + line, 'two blank at end': line + b'\n', 'comment with a control char':
               b'ssh-ed25519 ' + blob + b' a\x00b\n', 'non-ascii comment': b'ssh-ed25519 ' + blob + ' é\n'.encode(),
               'options': b'no-pty ' + line, 'a private-key header': b'-----BEGIN OPENSSH PRIVATE KEY-----\n',
               'too big': b'ssh-ed25519 ' + blob + b' ' + b'c' * 5000 + b'\n'}
        for what, data in bad.items():
            with self.subTest(what):
                key = self.fx.tmp / 'bad.pub'
                key.write_bytes(data)
                gh = FakeGh()
                code, out, _, _ = self.run_main(gh=gh, key=key)
                self.assertEqual((code, out.strip(), gh.calls), (1, 'REFUSED key', []))
        code, out, _, _ = self.run_main(key=self.fx.tmp / 'no-such-file.pub')
        self.assertEqual((code, out.strip()), (1, 'REFUSED key'))

    def test_a_key_line_with_or_without_a_comment_and_a_final_newline_is_accepted(self):
        self.fx.build()
        blob = self.fx.pub.read_bytes().split()[1]
        for data in (b'ssh-ed25519 ' + blob, b'ssh-ed25519 ' + blob + b'\n', b'ssh-ed25519 ' + blob + b' my key, 2026\n'):
            with self.subTest(data[-12:]):
                key = self.fx.tmp / 'ok.pub'
                key.write_bytes(data)
                self.assertEqual(self.run_main('verify', key=key)[0], 0)

    def test_the_pinned_fingerprint_must_match_the_keys(self):
        self.fx.build()
        mine = fp.key_fingerprint(self.fx.pub.read_bytes())
        other = fp.key_fingerprint(Path(str(self.fx.other) + '.pub').read_bytes())
        code, out, err, _ = self.run_main('verify', env={'OWNER_PIN_SHA256': mine})  # the real ssh-keygen -lf agrees
        self.assertEqual(code, 0)
        self.assertIn(f'owner key {mine}', err)
        for want in (other, 'abc', 'SHA256:' + 'A' * 43, mine.lower(), mine + ' x'):
            with self.subTest(want):
                gh = FakeGh()
                code, out, _, _ = self.run_main(gh=gh, env={'OWNER_PIN_SHA256': want})
                self.assertEqual((code, out.strip(), gh.calls), (1, 'REFUSED key', []))
        # a variable that is not set at all (empty) pins nothing; ssh-keygen failing with one set refuses
        self.assertEqual(self.run_main('verify', env={'OWNER_PIN_SHA256': ''})[0], 0)
        code, out, _, _ = self.run_main('verify', env={'OWNER_PIN_SHA256': mine}, run=lambda argv, stdin: (1, b''))
        self.assertEqual((code, out.strip()), (1, 'REFUSED key'))

    def test_the_fingerprint_is_asked_of_ssh_keygen_for_this_very_file(self):
        self.fx.build()
        mine = fp.key_fingerprint(self.fx.pub.read_bytes())
        calls = []

        def spy(argv, stdin):
            calls.append(tuple(argv))
            return fp.run_argv(argv, stdin)
        self.assertEqual(self.run_main('verify', env={'OWNER_PIN_SHA256': mine}, run=spy)[0], 0)
        self.assertEqual(calls[0], (fp.SSH_KEYGEN, '-l', '-f', str(self.fx.pub)))

    # the public repo carries no internal names

    def test_the_public_files_name_no_private_repo_commit_or_internal_id(self):
        banned = re.compile(r'\bI0\d\b|\bP\+|[0-9a-f]{7,40}\b.*\bmerge\b|manifest\.py|private repo|phone|fleet\.core', re.I)
        for rel in ('bin/fleet-install-publish.py', 'README.md', '.github/workflows/install.yml'):
            for n, line in enumerate((ROOT / rel).read_text(encoding='utf-8').splitlines(), 1):
                self.assertIsNone(banned.search(line), f'{rel}:{n}')
        for n, line in enumerate((ROOT / 'bin/fleet-install-publish.py').read_text(encoding='utf-8').splitlines(), 1):
            self.assertIsNone(re.search(r'\bcommit [0-9a-f]{7,40}\b', line), f'script:{n}')

    # the command line

    def test_main_publishes_and_verify_never_calls_gh(self):
        self.fx.build()
        argv = lambda verb: ['x', verb, f'release/{TAG}', '--owner-pub', str(self.fx.pub), '--min-serial', '5']  # noqa
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


class VendoredVerifier(unittest.TestCase):
    """Section 1 (a copy of the fleet's install manifest rules, schema version 1) against a frozen golden: a change to
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

    def test_the_top_of_the_file_names_the_copied_rules_by_their_schema_version(self):
        self.assertIn("a copy of the fleet's install manifest rules, schema version 1",
                      (ROOT / 'bin/fleet-install-publish.py').read_text(encoding='utf-8')[:2500])

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

    def test_the_publishers_size_limits_are_these_numbers(self):
        self.assertEqual((fp.MAX_SMALL, fp.MAX_KIT, fp.MAX_ATTR), (1 << 20, 16 << 20, 4096))

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

    def test_the_owners_confirmation_reaches_the_script_from_the_release_environments_variable(self):
        step = self.TEXT[self.TEXT.index('          SERIAL:'):]
        self.assertIn('          IMMUTABLE_CONFIRMED: ${{ vars.IMMUTABLE_RELEASES_CONFIRMED }}\n', step)
        self.assertEqual(re.findall(r'IMMUTABLE_\w+: (.*)', self.TEXT), ['${{ vars.IMMUTABLE_RELEASES_CONFIRMED }}'])

    def test_the_owners_key_and_fingerprint_come_from_the_release_environment_not_the_repo(self):
        self.assertIn('          OWNER_PIN_PUB: ${{ vars.OWNER_PIN_PUB }}\n', self.TEXT)
        self.assertIn('          OWNER_PIN_SHA256: ${{ vars.OWNER_PIN_SHA256 }}\n', self.TEXT)
        self.assertEqual(re.findall(r'\$\{\{ (?:vars|secrets)\.\w+ \}\}', self.TEXT).count('${{ vars.OWNER_PIN_PUB }}'), 1)
        self.assertIn('umask 077', self.TEXT)  # the temp file is the job's alone (0600)
        self.assertNotIn('keys/', self.TEXT)
        self.assertNotIn('owner-pin.pub"\n', self.TEXT.split('run: umask')[0])

    def test_the_inputs_reach_the_script_only_through_env(self):
        runs = re.findall(r'(?m)^\s+(?:- )?run: (.*)$', self.TEXT)
        self.assertEqual(runs, ['umask 077 && printf \'%s\\n\' "$OWNER_PIN_PUB" > "$RUNNER_TEMP/owner-pin.pub"',
                                'python3 bin/fleet-install-publish.py publish "release/install-$SERIAL"'
                                ' --owner-pub "$RUNNER_TEMP/owner-pin.pub" --min-serial "$MIN_SERIAL"'])
        self.assertFalse([r for r in runs if '${{' in r])  # nothing in a run: line is an expression
        for want in ('SERIAL: ${{ inputs.serial }}', 'MIN_SERIAL: ${{ inputs.min_serial }}',
                     'GH_TOKEN: ${{ github.token }}'):
            self.assertIn(want, self.TEXT)
        self.assertNotRegex(self.TEXT, r'(?i)secrets\.')
        self.assertIn('timeout-minutes: 60', self.TEXT)


if __name__ == '__main__':
    unittest.main()
