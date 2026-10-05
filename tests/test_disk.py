"""bin/fleet-disk.py over fakes, with no network and no qemu: the signature by the pinned fingerprint, the signed sum,
the qcow2 magic, the serial shape, the existing-tag and size refusals, the two lock entries printed, the real script
refusing before any network call, and the two workflows' shape. Plain unittest, stdlib only."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('fleet_disk', ROOT / 'bin/fleet-disk.py')
fd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fd)

SERIAL = '20260930.1'
BASE = f'https://cloud-images.ubuntu.com/noble/{SERIAL}/'
FPR = 'ABCD' * 10  # the fake key's fingerprint, built here: the real pin is covered by its own test
OTHER = '1234' * 10
PINNED = 'D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81'
IMAGE = fd.QCOW2_MAGIC + b'qcow2 body'
VHDX = b'vhdx body'
REPO, SHA, TOKEN = 'org/repo', 'ab' * 20, 'tok-' + 'x' * 8  # built at runtime, never a secret-shaped literal
sha = lambda data: hashlib.sha256(data).hexdigest()  # noqa: E731


def sums_for(image: bytes = IMAGE) -> bytes:
    return f'{sha(image)} *noble-server-cloudimg-amd64.img\n{sha(b"other")} *other.img\n'.encode()


def validsig(*fprs: str, good: bool = True) -> str:
    """A good signature's status lines: GOODSIG (as gpgv prints it for a key in date) then one VALIDSIG per fpr."""
    return ('[GNUPG:] GOODSIG 0123456789ABCDEF t <t@x.y>\n' if good else '') + ''.join(
        f'[GNUPG:] VALIDSIG {f} 2026-01-01 1 0 4 0 1 10 01 {f}\n' for f in fprs)


class FakeIo:
    """fetch serves bodies by url; run answers gpgv, qemu-img and gh from fields, and logs every argv."""

    def __init__(self, image: bytes = IMAGE, sums: bytes | None = None, gpgv: tuple[int, str] | None = None,
                 qemu: int = 0, gh: int = 0, release_exists: bool = False, tag_exists: bool = False,
                 vhdx: bytes = VHDX):
        self.bodies = {'SHA256SUMS': sums if sums is not None else sums_for(image), 'SHA256SUMS.gpg': b'sig',
                       fd.IMAGE: image}
        self.gpgv, self.qemu, self.gh = gpgv or (0, validsig(FPR)), qemu, gh
        self.release_exists, self.tag_exists, self.vhdx = release_exists, tag_exists, vhdx
        self.fetched: list[str] = []
        self.ran: list[tuple[list[str], dict[str, str]]] = []

    def fetch(self, url: str, dest: Path, limit: int) -> str:
        self.fetched.append(url)
        body = self.bodies[url.rpartition('/')[2]]
        dest.write_bytes(body)
        return sha(body)

    def run(self, argv: list[str], env: dict[str, str]) -> tuple[int, str]:
        self.ran.append((argv, env))
        if argv[0] == fd.GPGV:
            return self.gpgv
        if argv[0] == fd.QEMU_IMG:
            Path(argv[-1]).write_bytes(self.vhdx)
            return self.qemu, ''
        if argv[:3] == [fd.GH, 'release', 'view']:
            return (0 if self.release_exists else 1), ''
        if argv[:2] == [fd.GH, 'api']:
            return (0 if self.tag_exists else 1), ''
        return self.gh, ''

    def tools(self) -> list[str]:
        """The tools run, in order, with gh named by its subcommand."""
        return [Path(argv[0]).name + (' ' + argv[1] if argv[0] == fd.GH else '') for argv, _ in self.ran]


def build(io_: FakeIo, serial: str = SERIAL, **kw) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        return fd.build(io_, serial, Path(tmp), kw.get('repo', REPO), kw.get('sha', SHA), kw.get('token', TOKEN),
                        kw.get('fpr', FPR))


class Build(unittest.TestCase):
    def refused(self, why: str, io_: FakeIo, **kw) -> None:
        with self.assertRaisesRegex(fd.Refused, f'^{why}$'):
            build(io_, **kw)

    def test_the_happy_path_returns_both_lock_entries(self):
        io_ = FakeIo()
        self.assertEqual(build(io_), {
            'disk_input': {'url': BASE + 'noble-server-cloudimg-amd64.img', 'sha256': sha(IMAGE)},
            'disk': {'url': f'https://github.com/{REPO}/releases/download/disk-noble-{SERIAL}/noble-{SERIAL}.vhdx',
                     'sha256': sha(VHDX)}})
        self.assertEqual(io_.tools(), ['gh release', 'gh api', 'gpgv', 'qemu-img', 'gh release'])
        gpgv, qemu, gh = io_.ran[2][0], io_.ran[3][0], io_.ran[4][0]
        self.assertEqual(gpgv[:5], [fd.GPGV, '--keyring', fd.KEYRING, '--status-fd', '1'])
        self.assertEqual(qemu[:6], [fd.QEMU_IMG, 'convert', '-f', 'qcow2', '-O', 'vhdx'])
        self.assertEqual(gh[:4], [fd.GH, 'release', 'create', f'disk-noble-{SERIAL}'])
        self.assertEqual(gh[gh.index('--target') + 1], SHA)
        self.assertEqual(io_.fetched, [BASE + 'SHA256SUMS', BASE + 'SHA256SUMS.gpg', BASE + fd.IMAGE])

    def test_every_tool_is_an_absolute_path_under_a_fixed_path(self):
        io_ = FakeIo()
        build(io_)
        for argv, env in io_.ran:
            self.assertTrue(argv[0].startswith('/usr/bin/'))
            self.assertEqual(env['PATH'], '/usr/bin')

    def test_only_gh_sees_the_token(self):
        io_ = FakeIo()
        build(io_)
        self.assertEqual([TOKEN in env.values() for _, env in io_.ran], [True, True, False, False, True])
        self.assertEqual(io_.ran[4][1]['GH_REPO'], REPO)

    def test_a_bad_signature_stops_before_the_image(self):
        io_ = FakeIo(gpgv=(1, ''))
        self.refused('bad-signature', io_)
        self.assertNotIn(BASE + fd.IMAGE, io_.fetched)

    def test_a_valid_signature_by_another_key_is_refused(self):
        self.refused('wrong-key', FakeIo(gpgv=(0, validsig(OTHER))))
        self.refused('wrong-key', FakeIo(gpgv=(0, '')))  # gpgv exiting 0 with no VALIDSIG vouches for no one

    def test_an_expired_revoked_or_bad_signature_is_refused_though_gpgv_exits_0(self):
        for bad in ('EXPKEYSIG', 'REVKEYSIG', 'EXPSIG', 'ERRSIG', 'BADSIG'):
            with self.subTest(bad=bad):  # gpgv prints EXPKEYSIG in place of GOODSIG for an expired key, VALIDSIG still
                line = f'[GNUPG:] {bad} 0123456789ABCDEF t\n'
                self.refused('bad-signature', FakeIo(gpgv=(0, line + validsig(FPR, good=False))))
                self.refused('bad-signature', FakeIo(gpgv=(0, line + validsig(FPR))))
        self.refused('bad-signature', FakeIo(gpgv=(0, validsig(FPR, good=False))))  # a VALIDSIG alone is not a GOODSIG

    def test_the_pinned_key_may_be_the_primary_of_a_signing_subkey(self):
        sub = validsig() + f'[GNUPG:] VALIDSIG {OTHER} 2026-01-01 1 0 4 0 1 10 01 {FPR}\n'
        self.assertEqual(build(FakeIo(gpgv=(0, sub)))['disk_input']['sha256'], sha(IMAGE))  # fpr is the primary
        self.assertEqual(build(FakeIo(gpgv=(0, sub)), fpr=OTHER)['disk_input']['sha256'], sha(IMAGE))  # the signing key
        self.refused('wrong-key', FakeIo(gpgv=(0, sub)), fpr='9' * 40)

    def test_a_lower_case_fingerprint_in_the_status_still_matches(self):
        self.assertEqual(build(FakeIo(gpgv=(0, validsig(FPR.lower()))))['disk_input']['sha256'], sha(IMAGE))

    def test_a_status_line_not_at_the_start_does_not_count(self):
        for line in (f'junk [GNUPG:] VALIDSIG {FPR} 2026-01-01 1 0 4 0 1 10 01 {FPR}\n',
                     f'[GNUPG:] GOODSIG VALIDSIG {FPR} 2026-01-01 1 0 4 0 1 10 01 {FPR}\n',
                     f'[GNUPG:] NOTE VALIDSIG {FPR} 2026-01-01 1 0 4 0 1 10 01 {FPR}\n'):
            with self.subTest(line=line[:20]):
                self.refused('wrong-key', FakeIo(gpgv=(0, '[GNUPG:] GOODSIG 0123456789ABCDEF t\n' + line)))
        self.refused('bad-signature', FakeIo(gpgv=(0, '[GNUPG:] NOTE GOODSIG\n' + validsig(FPR, good=False))))

    def test_a_crafted_short_validsig_vouches_for_no_one(self):
        short = f'[GNUPG:] VALIDSIG {FPR} 2026-01-01 1 0 4 0 1 10 01\n'  # ten words: no primary fingerprint
        self.refused('wrong-key', FakeIo(gpgv=(0, '[GNUPG:] GOODSIG 0123456789ABCDEF t\n' + short)))

    def test_an_unpinned_key_refuses_before_any_fetch(self):
        for fpr in ('', FPR.lower(), FPR[:-1], FPR + 'A'):
            with self.subTest(fpr=len(fpr)):
                io_ = FakeIo()
                self.refused('unpinned-key', io_, fpr=fpr)
                self.assertEqual((io_.fetched, io_.ran), ([], []))

    def test_the_shipped_pin_is_the_owner_confirmed_fingerprint(self):
        self.assertEqual(fd.CLOUDIMAGE_KEY_FPR, PINNED)
        self.assertTrue(fd.FPR.fullmatch(fd.CLOUDIMAGE_KEY_FPR))

    def test_a_sum_mismatch_stops_before_the_convert(self):
        io_ = FakeIo(sums=sums_for(b'another image'))
        self.refused('sum-mismatch', io_)
        self.assertEqual(io_.tools()[-1], 'gpgv')

    def test_a_non_qcow2_file_is_refused(self):
        io_ = FakeIo(image=b'MZ not a qcow2')  # its sum is signed: the magic is the second line of defense
        self.refused('not-qcow2', io_)
        self.assertEqual(io_.tools()[-1], 'gpgv')

    def test_a_serial_that_is_not_ubuntus_shape_is_refused_before_anything(self):
        for serial in ('', 'current', '2026093', '202609300', '20260930.123', '../20260930', '20260930/x',
                       '20260930\n', '20260930 ', '２０２６０９３０'):
            with self.subTest(serial=serial):
                io_ = FakeIo()
                self.refused('serial', io_, serial=serial)
                self.assertEqual((io_.fetched, io_.ran), ([], []))
        build(FakeIo(), serial='20260930')  # the plain shape passes too

    def test_the_signed_list_must_name_the_image_exactly_once(self):
        line = f'{sha(IMAGE)} *{fd.IMAGE}\n'.encode()
        for sums in (b'', f'{sha(IMAGE)} *x.img\n'.encode(), line * 2, line.upper(),
                     f'{sha(IMAGE)} *prefix-{fd.IMAGE}\n'.encode(), f'{sha(IMAGE)} *{fd.IMAGE}.bak\n'.encode()):
            with self.subTest(sums=sums[:12]):
                self.refused('no-signed-sum', FakeIo(sums=sums))

    def test_the_signed_list_accepts_both_text_and_binary_marks(self):
        for mark in (' ', '*'):
            with self.subTest(mark=mark):
                self.assertEqual(fd.signed_sha(f'{sha(IMAGE)} {mark}{fd.IMAGE}\n'.encode(), fd.IMAGE), sha(IMAGE))

    def test_a_failed_convert_or_publish_is_refused(self):
        self.refused('convert-failed', FakeIo(qemu=1))
        self.refused('publish-failed', FakeIo(gh=1))

    def test_an_existing_release_or_tag_is_refused_before_any_fetch(self):
        for kw in ({'release_exists': True}, {'tag_exists': True}):
            with self.subTest(kw=kw):
                io_ = FakeIo(**kw)
                self.refused('tag-exists', io_)
                self.assertEqual(io_.fetched, [])
                self.assertNotIn('qemu-img', io_.tools())
                self.assertNotIn('gh release', io_.tools()[2:])  # no create

    def test_an_asset_of_2_gib_or_more_is_refused_before_the_upload(self):
        small = fd.MAX_ASSET
        fd.MAX_ASSET = len(VHDX)  # 2 GiB cannot be written in a unit test: shrink the limit to the fake's size
        self.addCleanup(setattr, fd, 'MAX_ASSET', small)
        io_ = FakeIo()
        self.refused('too-big', io_)
        self.assertEqual(io_.tools()[-1], 'qemu-img')
        fd.MAX_ASSET = len(VHDX) + 1
        self.assertEqual(build(FakeIo())['disk']['sha256'], sha(VHDX))

    def test_the_asset_limit_is_2_gib(self):
        self.assertEqual(fd.MAX_ASSET, 2 * 1024 ** 3)

    def test_the_release_environment_is_checked_before_any_fetch(self):
        for kw in ({'repo': ''}, {'repo': 'no-slash'}, {'repo': 'a/b c'}, {'token': ''}, {'sha': ''},
                   {'sha': 'AB' * 20}, {'sha': 'ab' * 19}):
            with self.subTest(kw=kw):
                io_ = FakeIo()
                self.refused('release-env', io_, **kw)
                self.assertEqual((io_.fetched, io_.ran), ([], []))


class Main(unittest.TestCase):
    ENV = {'GITHUB_REPOSITORY': REPO, 'GITHUB_SHA': SHA, 'GH_TOKEN': TOKEN}

    def pin(self, fpr: str) -> None:
        pinned = fd.CLOUDIMAGE_KEY_FPR
        fd.CLOUDIMAGE_KEY_FPR = fpr
        self.addCleanup(setattr, fd, 'CLOUDIMAGE_KEY_FPR', pinned)

    def go(self, argv: list[str], io_: FakeIo, **env: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = fd.main(['fleet-disk.py', *argv], {'RUNNER_TEMP': tmp, **env}, io_)
        return code, out.getvalue(), err.getvalue()

    def test_a_bad_command_line_is_2(self):
        self.assertEqual(self.go([], FakeIo())[0], fd.USAGE)
        self.assertEqual(self.go([SERIAL, 'extra'], FakeIo())[0], fd.USAGE)

    def test_an_unpinned_key_refuses_before_any_fetch(self):
        self.pin('')
        io_ = FakeIo()
        self.assertEqual(self.go([SERIAL], io_, **self.ENV), (fd.REFUSED, '', 'fleet-disk: refused unpinned-key\n'))
        self.assertEqual((io_.fetched, io_.ran), ([], []))

    def test_a_refusal_names_the_rule_and_echoes_nothing(self):
        code, out, err = self.go(['bad serial'], FakeIo(), **self.ENV)
        self.assertEqual((code, out, err), (fd.REFUSED, '', 'fleet-disk: refused serial\n'))

    def test_a_missing_release_environment_is_refused(self):
        self.pin(FPR)
        self.assertEqual(self.go([SERIAL], FakeIo())[2], 'fleet-disk: refused release-env\n')

    def test_the_happy_path_prints_the_entries_to_paste_and_leaves_no_files(self):
        self.pin(FPR)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()) as out:
            code = fd.main(['fleet-disk.py', SERIAL], {'RUNNER_TEMP': tmp, **self.ENV}, FakeIo())
            self.assertEqual(list(Path(tmp).iterdir()), [])
        self.assertEqual(code, 0)
        head, _, body = out.getvalue().partition('\n')
        self.assertIn('carrier.lock.json', head)
        entries = json.loads(body)
        self.assertEqual(sorted(entries), ['disk', 'disk_input'])
        self.assertEqual(sorted(entries['disk']), ['sha256', 'url'])
        self.assertTrue(entries['disk']['url'].startswith(f'https://github.com/{REPO}/releases/download/disk-noble-'))
        self.assertNotIn(TOKEN, out.getvalue())

    def test_the_disk_url_names_this_repo_when_run_there(self):
        self.pin(FPR)
        env = {**self.ENV, 'GITHUB_REPOSITORY': 'mirrorstack-ai/fleet-disk'}
        _, out, _ = self.go([SERIAL], FakeIo(), **env)
        url = json.loads(out.partition('\n')[2])['disk']['url']
        self.assertEqual(url, f'https://github.com/mirrorstack-ai/fleet-disk/releases/download/disk-noble-{SERIAL}/'
                              f'noble-{SERIAL}.vhdx')


class Entry(unittest.TestCase):
    """The real script, run as a child as the workflow runs it, refusing before any network call."""

    def run_script(self, *args: str, **env: str) -> subprocess.CompletedProcess:
        base = {'GITHUB_REPOSITORY': REPO, 'GITHUB_SHA': SHA, 'GH_TOKEN': TOKEN}
        return subprocess.run([sys.executable, '-I', str(ROOT / 'bin/fleet-disk.py'), *args],
                              env={**base, **env}, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              timeout=60, check=False)

    def test_usage_and_a_refused_serial(self):
        self.assertEqual(self.run_script().returncode, fd.USAGE)
        done = self.run_script('current')
        self.assertEqual((done.returncode, done.stdout, done.stderr), (fd.REFUSED, '', 'fleet-disk: refused serial\n'))

    def test_a_missing_release_environment_is_refused(self):
        done = self.run_script(SERIAL, GH_TOKEN='')
        self.assertEqual((done.returncode, done.stdout, done.stderr), (fd.REFUSED, '', 'fleet-disk: refused release-env\n'))

    def test_a_missing_tool_is_refused_not_crashed(self):
        if os.path.exists(fd.GH):
            self.skipTest('gh is installed here; the fake covers the existing-tag path')
        done = self.run_script(SERIAL)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (fd.REFUSED, '', 'fleet-disk: refused tool-missing\n'))


class Real(unittest.TestCase):
    def test_fetch_hashes_what_it_writes_and_refuses_what_is_too_long_or_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dest = Path(tmp, 'src'), Path(tmp, 'dest')
            src.write_bytes(IMAGE)
            self.assertEqual(fd.Real().fetch(src.as_uri(), dest, 1 << 20), sha(IMAGE))
            self.assertEqual(dest.read_bytes(), IMAGE)
            with self.assertRaisesRegex(fd.Refused, '^too-large$'):
                fd.Real().fetch(src.as_uri(), dest, len(IMAGE) - 1)
            with self.assertRaisesRegex(fd.Refused, '^fetch-failed$'):
                fd.Real().fetch(Path(tmp, 'absent').as_uri(), dest, 1 << 20)

    def test_run_returns_status_and_stdout_and_a_missing_tool_is_refused(self):
        code, out = fd.Real().run([sys.executable, '-I', '-c', 'print(7)'], dict(os.environ))
        self.assertEqual((code, out), (0, '7\n'))
        with self.assertRaisesRegex(fd.Refused, '^tool-missing$'):
            fd.Real().run(['/nonexistent/tool'], {})

    def test_valid_fingerprints_reads_both_ends_of_a_validsig(self):
        self.assertEqual(fd.valid_fingerprints(validsig(FPR.lower()) + 'noise\n[GNUPG:] GOODSIG x\n'), {FPR})
        self.assertEqual(fd.valid_fingerprints('[GNUPG:] VALIDSIG short\n'), set())
        sub = f'[GNUPG:] VALIDSIG {OTHER} 2026-01-01 1 0 4 0 1 10 01 {FPR}\n'
        self.assertEqual(fd.valid_fingerprints(sub), {OTHER, FPR})


class Workflows(unittest.TestCase):
    """Text checks of the two workflows (no YAML parser in the stdlib): the safety properties that matter."""

    DISK = (ROOT / '.github/workflows/disk.yml').read_text(encoding='utf-8')
    TEST = (ROOT / '.github/workflows/test.yml').read_text(encoding='utf-8')

    def test_both_run_on_github_hosted_ubuntu_24_04_with_read_only_top_level_permissions(self):
        for text in (self.DISK, self.TEST):
            self.assertRegex(text, r'(?m)^permissions:\n  contents: read\n')
            self.assertEqual(re.findall(r'runs-on: (\S+)', text), ['ubuntu-24.04'])
            self.assertNotIn('self-hosted', text)
            self.assertNotRegex(text, r'(?i)secrets')

    def test_the_disk_workflow_is_a_main_only_dispatch_with_one_input(self):
        self.assertRegex(self.DISK, r'(?m)^on:\n  workflow_dispatch:\n    inputs:\n      serial:\n')
        self.assertEqual(re.findall(r'(?m)^      (\w+):\n        (?:description|required)', self.DISK), ['serial'])
        self.assertNotIn('pull_request', self.DISK)
        self.assertIn("if: github.ref == 'refs/heads/main'", self.DISK)
        self.assertIn('timeout-minutes: 60', self.DISK)

    def test_only_the_disk_job_writes_and_only_contents(self):
        self.assertEqual(re.findall(r'(\w[\w-]*): write', self.DISK), ['contents'])
        self.assertIn('    permissions:\n      contents: write\n', self.DISK)
        self.assertNotIn('write', self.TEST)

    def test_the_input_reaches_the_script_only_through_env(self):
        runs = re.findall(r'(?m)^\s+(?:- )?run: (.*)$', self.DISK)
        self.assertEqual(runs[-1], 'python3 bin/fleet-disk.py "$SERIAL"')
        self.assertIn('SERIAL: ${{ inputs.serial }}', self.DISK)
        self.assertIn('GH_TOKEN: ${{ github.token }}', self.DISK)
        for run in runs:
            self.assertNotIn('${{', run)

    def test_the_disk_workflow_installs_only_qemu_utils_with_apt(self):
        self.assertEqual(re.findall(r'apt-get install (.*)', self.DISK), ['-y --no-install-recommends qemu-utils'])

    def test_the_actions_are_the_sha_pinned_ones_and_match_across_workflows(self):
        for text in (self.DISK, self.TEST):
            for uses in re.findall(r'uses: (\S+)', text):
                self.assertRegex(uses, r'^actions/(checkout|setup-python)@[0-9a-f]{40}$')
        self.assertEqual(re.findall(r'uses: (actions/checkout@\S+)', self.DISK),
                         re.findall(r'uses: (actions/checkout@\S+)', self.TEST))

    def test_the_test_workflow_runs_on_pr_and_push_over_both_pythons_and_the_unittest_command(self):
        self.assertRegex(self.TEST, r'(?m)^on:\n  pull_request:\n  push:\n    branches: \[main\]\n')
        self.assertIn('["3.11", "3.13"]', self.TEST)
        self.assertIn('python3 -m unittest discover -s tests', self.TEST)


if __name__ == '__main__':
    unittest.main()
