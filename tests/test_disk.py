"""bin/fleet-disk.py over fakes, with no network and no qemu: the signature by the pinned fingerprint, the signed sum,
the qcow2 magic, the serial shape, the existing-tag (fail closed) and size refusals, the signature's date, the published digest, timeouts, the two lock entries printed, the real script
refusing before any network call, and the two workflows' shape; the arm64 build over the same fakes: its serial and
sha pins, the vfkit re-check, the raw EFI layout, the zstd round trip, the one asset. Plain unittest, stdlib only."""
from __future__ import annotations

import calendar
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
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
QCOW2 = b'qcow2 out'  # what the fake's second convert writes (the same length as VHDX: one size limit fits both)
REPO, SHA, TOKEN = 'org/repo', 'ab' * 20, 'tok-' + 'x' * 8  # built at runtime, never a secret-shaped literal
SIGNED = calendar.timegm((2026, 9, 30, 12, 0, 0))  # the signature's stamp: the serial's day, midday UTC
NOW = SIGNED + 3600  # the clock the builds run on in tests
sha = lambda data: hashlib.sha256(data).hexdigest()  # noqa: E731


def sums_for(image: bytes = IMAGE, name: str = 'noble-server-cloudimg-amd64.img') -> bytes:
    return f'{sha(image)} *{name}\n{sha(b"other")} *other.img\n'.encode()


def validsig(*fprs: str, good: bool = True, stamp: int = SIGNED) -> str:
    """A good signature's status lines: GOODSIG (as gpgv prints it for a key in date) then one VALIDSIG per fpr."""
    return ('[GNUPG:] GOODSIG 0123456789ABCDEF t <t@x.y>\n' if good else '') + ''.join(
        f'[GNUPG:] VALIDSIG {f} 2026-09-30 {stamp} 0 4 0 1 10 01 {f}\n' for f in fprs)


class FakeIo:
    """fetch serves bodies by url; run answers gpgv, qemu-img and gh from fields, and logs every argv."""

    def __init__(self, image: bytes = IMAGE, sums: bytes | None = None, gpgv: tuple[int, str] | None = None,
                 qemu: int = 0, gh: int = 0, release_exists: bool = False, tag_exists: bool = False,
                 vhdx: bytes = VHDX, qcow2: bytes = QCOW2, check_fails: bool = False, check_out: str | None = None,
                 readback: tuple[int, str] | None = None):
        self.bodies = {'SHA256SUMS': sums if sums is not None else sums_for(image), 'SHA256SUMS.gpg': b'sig',
                       fd.IMAGE: image}
        self.gpgv, self.qemu, self.gh = gpgv or (0, validsig(FPR)), qemu, gh
        self.release_exists, self.tag_exists, self.formats = release_exists, tag_exists, {'vhdx': vhdx, 'qcow2': qcow2}
        self.check_fails, self.check_out, self.readback = check_fails, check_out, readback  # existing-tag check answers
        self.uploaded: list[str] = []
        self.written: dict[str, bytes] = {}  # what the fake tools wrote, by file name: GitHub's digests are read from it
        self.tag = f'disk-noble-{SERIAL}'
        self.fetched: list[str] = []
        self.limits: dict[str, int] = {}
        self.ran: list[tuple[list[str], dict[str, str]]] = []
        self.timeouts: list[int] = []

    def fetch(self, url: str, dest: Path, limit: int) -> str:
        self.fetched.append(url)
        self.limits[url.rpartition('/')[2]] = limit
        body = self.bodies[url.rpartition('/')[2]]
        dest.write_bytes(body)
        return sha(body)

    def run(self, argv: list[str], env: dict[str, str], timeout: int = fd.TOOL_TIMEOUT) -> tuple[int, str]:
        self.timeouts.append(timeout)
        self.ran.append((argv, env))
        if argv[0] == fd.GPGV:
            return self.gpgv
        if argv[0] == fd.QEMU_IMG:
            self.written[Path(argv[-1]).name] = self.formats[argv[argv.index('-O') + 1]]
            Path(argv[-1]).write_bytes(self.written[Path(argv[-1]).name])
            return self.qemu, ''
        tag = self.tag
        if argv[:3] == [fd.GH, 'release', 'list']:  # another tag is always listed: only the exact name counts
            listed = [{'tagName': tag + '0', 'isDraft': False}] + [{'tagName': tag, 'isDraft': True}] * self.release_exists
            return self.answer(json.dumps(listed))
        if argv[:2] == [fd.GH, 'api'] and 'matching-refs' in argv[2]:  # a PREFIX match: it also returns longer tags
            refs = [{'ref': f'refs/tags/{tag}.2'}] + [{'ref': f'refs/tags/{tag}'}] * self.tag_exists
            return self.answer(json.dumps(refs))
        if argv[:2] == [fd.GH, 'api']:  # the read-back of the published release
            if self.readback is not None:
                return self.readback
            return self.gh, json.dumps({'assets': [{'name': n, 'digest': 'sha256:' + sha(self.written[n])}
                                                   for n in self.uploaded]})
        if argv[:3] == [fd.GH, 'release', 'create']:
            self.uploaded = [Path(a).name for a in argv[4:argv.index('--target')]]
        return self.gh, ''

    def answer(self, out: str) -> tuple[int, str]:
        return (1, '') if self.check_fails else (0, self.check_out if self.check_out is not None else out)

    def tools(self) -> list[str]:
        """The tools run, in order, with gh named by its subcommand."""
        return [Path(argv[0]).name + (' ' + argv[1] if argv[0] == fd.GH else '') for argv, _ in self.ran]


def build(io_: FakeIo, serial: str = SERIAL, **kw) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        return fd.build(io_, serial, Path(tmp), kw.get('repo', REPO), kw.get('sha', SHA), kw.get('token', TOKEN),
                        kw.get('fpr', FPR), kw.get('now', NOW))


ARM_SERIAL = fd.ARM64_SERIAL
ARM_BASE = f'https://cloud-images.ubuntu.com/noble/{ARM_SERIAL}/'
ARM_IMAGE = fd.QCOW2_MAGIC + b'arm64 qcow2 body'
ARM_TAG = f'disk-noble-arm64-{ARM_SERIAL}'
ARM_ASSET = f'noble-arm64-{ARM_SERIAL}.raw.zst'
VFKIT = b'vfkit body'
IMAGE_PIN, VFKIT_PIN = sha(ARM_IMAGE), sha(VFKIT)
# the shipped pins are the real image's and the real vfkit's, which no fake can have: the arm64 tests point them at the fakes
ARM_PINS = {'ARM64_IMAGE_SHA256': IMAGE_PIN, 'VFKIT_SHA256': VFKIT_PIN, 'VFKIT_SIZE': len(VFKIT)}
LINUX_FS = uuid.UUID('0FC63DAF-8483-4772-8E79-3D69D8477DE4').bytes_le  # a GPT partition type that is not the ESP's
EMPTY = bytes(16)
ZST = b'zst:'  # the fake zstd's marker: its output is the marker plus its input, so a round trip really compares bytes


def gpt_disk(types: tuple[bytes, ...] = (EMPTY, fd.ESP_TYPE, EMPTY, EMPTY), size: int = 128) -> bytes:
    """A tiny raw disk: a protective MBR, a GPT header at LBA 1 pointing at len(types) entries of `size` bytes at LBA 2,
    each entry starting with its partition type GUID (the default has an EFI System Partition as its second)."""
    disk = bytearray(2 * fd.SECTOR + len(types) * size)
    disk[510:512], disk[512:520] = b'\x55\xaa', b'EFI PART'
    struct.pack_into('<QII', disk, fd.SECTOR + 72, 2, len(types), size)
    for i, kind in enumerate(types):
        disk[2 * fd.SECTOR + i * size:2 * fd.SECTOR + i * size + 16] = kind
    return bytes(disk)


RAW = gpt_disk()


class ArmIo(FakeIo):
    """FakeIo for the arm64 build: the signed list names the arm64 image, vfkit can be fetched, qemu-img writes a raw
    disk and zstd compresses and expands it."""

    def __init__(self, image: bytes = ARM_IMAGE, raw: bytes = RAW, vfkit: bytes = VFKIT, zstd: int = 0,
                 again: bytes | None = None, **kw):
        kw.setdefault('sums', sums_for(image, fd.IMAGE_ARM64))
        super().__init__(image=image, **kw)
        self.bodies[fd.IMAGE_ARM64], self.bodies['vfkit'] = self.bodies.pop(fd.IMAGE), vfkit
        self.tag, self.zstd, self.again = ARM_TAG, zstd, again
        self.formats['raw'] = raw

    def run(self, argv: list[str], env: dict[str, str], timeout: int = fd.TOOL_TIMEOUT) -> tuple[int, str]:
        if argv[0] != fd.ZSTD:
            return super().run(argv, env, timeout)
        self.timeouts.append(timeout)
        self.ran.append((argv, env))
        src, out = Path(argv[-1]), Path(argv[argv.index('-o') + 1])
        out.write_bytes((self.again if self.again is not None else src.read_bytes()[len(ZST):]) if '-d' in argv
                        else ZST + src.read_bytes())
        self.written[out.name] = out.read_bytes()
        return self.zstd, ''


class Build(unittest.TestCase):
    def refused(self, why: str, io_: FakeIo, **kw) -> None:
        with self.assertRaisesRegex(fd.Refused, f'^{why}$'):
            build(io_, **kw)

    def test_the_happy_path_returns_both_lock_entries(self):
        io_ = FakeIo()
        self.assertEqual(build(io_), {
            'disk_input': {'url': BASE + 'noble-server-cloudimg-amd64.img', 'sha256': sha(IMAGE)},
            'disk': {'url': f'https://github.com/{REPO}/releases/download/disk-noble-{SERIAL}/noble-{SERIAL}.vhdx',
                     'sha256': sha(VHDX)},
            'disk_qcow2': {'url': f'https://github.com/{REPO}/releases/download/disk-noble-{SERIAL}/noble-{SERIAL}.qcow2',
                           'sha256': sha(QCOW2), 'size': len(QCOW2)}})
        self.assertEqual(io_.tools(), ['gh api', 'gh release', 'gpgv', 'qemu-img', 'qemu-img', 'gh release', 'gh api'])
        gpgv, qemu, gh = io_.ran[2][0], io_.ran[3][0], io_.ran[5][0]
        self.assertEqual(gpgv[:5], [fd.GPGV, '--keyring', fd.KEYRING, '--status-fd', '1'])
        self.assertEqual(qemu[:8], [fd.QEMU_IMG, 'convert', '-f', 'qcow2', '-O', 'vhdx', '-o',
                                    'subformat=dynamic,block_size=1M'])
        self.assertEqual(gh[:4], [fd.GH, 'release', 'create', f'disk-noble-{SERIAL}'])
        self.assertEqual(gh[gh.index('--target') + 1], SHA)
        self.assertEqual([Path(a).name for a in gh[4:6]], [f'noble-{SERIAL}.vhdx', f'noble-{SERIAL}.qcow2'])  # one release, both
        self.assertEqual(io_.fetched, [BASE + 'SHA256SUMS', BASE + 'SHA256SUMS.gpg', BASE + fd.IMAGE])

    def test_the_qcow2_is_made_from_the_same_verified_input_uncompressed(self):
        io_ = FakeIo()
        build(io_)
        vhdx, qcow2 = io_.ran[3][0], io_.ran[4][0]
        self.assertEqual(qcow2[:8], [fd.QEMU_IMG, 'convert', '-f', 'qcow2', '-O', 'qcow2', '-o', 'compat=1.1'])
        self.assertEqual((qcow2[8], Path(qcow2[9]).name), (vhdx[8], f'noble-{SERIAL}.qcow2'))  # the one image that was checked
        self.assertNotIn('-c', qcow2)  # no compression: the hash does not depend on a compressor's version
        self.assertEqual(io_.fetched.count(BASE + fd.IMAGE), 1)

    def test_a_failed_qcow2_convert_publishes_nothing(self):
        class SecondFails(FakeIo):
            def run(self, argv, env, timeout=fd.TOOL_TIMEOUT):
                if argv[0] == fd.QEMU_IMG and argv[argv.index('-O') + 1] == 'qcow2':
                    return 1, ''
                return super().run(argv, env, timeout)
        io_ = SecondFails()
        self.refused('convert-failed', io_)
        self.assertEqual((io_.tools()[-1], io_.uploaded), ('qemu-img', []))

    def test_every_tool_is_an_absolute_path_under_a_fixed_path(self):
        io_ = FakeIo()
        build(io_)
        for argv, env in io_.ran:
            self.assertTrue(argv[0].startswith('/usr/bin/'))
            self.assertEqual(env['PATH'], '/usr/bin')

    def test_only_gh_sees_the_token(self):
        io_ = FakeIo()
        build(io_)
        self.assertEqual([TOKEN in env.values() for _, env in io_.ran], [True, True, False, False, False, True, True])
        self.assertEqual(io_.ran[5][1]['GH_REPO'], REPO)

    def test_a_bad_signature_stops_before_the_image(self):
        io_ = FakeIo(gpgv=(1, ''))
        self.refused('bad-signature', io_)
        self.assertNotIn(BASE + fd.IMAGE, io_.fetched)

    def test_gpgv_exiting_nonzero_is_refused_whatever_its_status_says(self):
        io_ = FakeIo(gpgv=(1, validsig(FPR)))  # a GOODSIG and a VALIDSIG of the pinned key, yet a failing exit
        self.refused('bad-signature', io_)
        self.assertNotIn(BASE + fd.IMAGE, io_.fetched)

    def test_a_signature_older_than_the_serial_or_from_the_future_is_refused(self):
        day = 86400
        for stamp in (SIGNED - day, SIGNED - 13 * 3600 - 1, 0):  # a replayed older list: before 2026-09-30 00:00 UTC
            with self.subTest(stamp=stamp):
                self.refused('stale-signature', FakeIo(gpgv=(0, validsig(FPR, stamp=stamp))))
        for stamp in (NOW + day + 1, NOW + 400 * day):
            with self.subTest(stamp=stamp):
                self.refused('stale-signature', FakeIo(gpgv=(0, validsig(FPR, stamp=stamp))))
        for stamp in (SIGNED - 12 * 3600, SIGNED, NOW + day):  # the serial's midnight, midday, a day of skew: fine
            with self.subTest(stamp=stamp):
                build(FakeIo(gpgv=(0, validsig(FPR, stamp=stamp))))
        self.refused('stale-signature', FakeIo(gpgv=(0, validsig(FPR, stamp=SIGNED) + validsig(FPR, stamp=1))))
        for word in ('x', '-5', '1e9', '\uff11\uff12\uff13'):
            with self.subTest(word=word):
                bad = (f'[GNUPG:] GOODSIG 0123456789ABCDEF t\n'
                       f'[GNUPG:] VALIDSIG {FPR} 2026-09-30 {word} 0 4 0 1 10 01 {FPR}\n')
                self.refused('stale-signature', FakeIo(gpgv=(0, bad)))

    def test_the_serial_date_is_the_first_eight_digits_of_the_serial(self):
        old = validsig(FPR, stamp=calendar.timegm((2026, 9, 29, 23, 0, 0)))  # the day before 20260930
        self.refused('stale-signature', FakeIo(gpgv=(0, old)), serial='20260930')
        self.assertEqual(build(FakeIo(gpgv=(0, old)), serial='20260929')['disk_input']['sha256'], sha(IMAGE))

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
        sub = validsig() + f'[GNUPG:] VALIDSIG {OTHER} 2026-09-30 {SIGNED} 0 4 0 1 10 01 {FPR}\n'
        self.assertEqual(build(FakeIo(gpgv=(0, sub)))['disk_input']['sha256'], sha(IMAGE))  # fpr is the primary
        self.assertEqual(build(FakeIo(gpgv=(0, sub)), fpr=OTHER)['disk_input']['sha256'], sha(IMAGE))  # the signing key
        self.refused('wrong-key', FakeIo(gpgv=(0, sub)), fpr='9' * 40)

    def test_a_lower_case_fingerprint_in_the_status_still_matches(self):
        self.assertEqual(build(FakeIo(gpgv=(0, validsig(FPR.lower()))))['disk_input']['sha256'], sha(IMAGE))

    def test_a_status_line_not_at_the_start_does_not_count(self):
        for line in (f'junk [GNUPG:] VALIDSIG {FPR} 2026-09-30 {SIGNED} 0 4 0 1 10 01 {FPR}\n',
                     f'[GNUPG:] GOODSIG VALIDSIG {FPR} 2026-09-30 {SIGNED} 0 4 0 1 10 01 {FPR}\n',
                     f'[GNUPG:] NOTE VALIDSIG {FPR} 2026-09-30 {SIGNED} 0 4 0 1 10 01 {FPR}\n'):
            with self.subTest(line=line[:20]):
                self.refused('wrong-key', FakeIo(gpgv=(0, '[GNUPG:] GOODSIG 0123456789ABCDEF t\n' + line)))
        self.refused('bad-signature', FakeIo(gpgv=(0, '[GNUPG:] NOTE GOODSIG\n' + validsig(FPR, good=False))))

    def test_a_crafted_short_validsig_vouches_for_no_one(self):
        short = f'[GNUPG:] VALIDSIG {FPR} 2026-09-30 {SIGNED} 0 4 0 1 10 01\n'  # ten words: no primary fingerprint
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
                self.assertNotIn('create', [argv[1] for argv, _ in io_.ran])  # nothing is created

    def test_a_tag_or_release_check_that_fails_refuses_rather_than_reading_as_not_found(self):
        for kw in ({'check_fails': True}, {'check_out': ''}, {'check_out': 'not json'}, {'check_out': '{}'},
                   {'check_out': 'null'}, {'check_out': '[] []'}):
            with self.subTest(kw=kw):
                io_ = FakeIo(**kw)
                self.refused('tag-check-failed', io_)
                self.assertEqual(io_.fetched, [])
                self.assertEqual(io_.tools(), ['gh api'])  # the first failed check stops the build
        io_ = FakeIo()
        self.assertEqual(build(io_)['disk']['sha256'], sha(VHDX))
        self.assertIn('matching-refs/tags/disk-noble-' + SERIAL, io_.ran[0][0][2])

    def test_a_release_list_that_fails_refuses_too_even_when_the_ref_check_is_clean(self):
        class ListFails(FakeIo):
            def run(self, argv, env, timeout=fd.TOOL_TIMEOUT):
                if argv[:3] == [fd.GH, 'release', 'list']:
                    return super().run(argv, env, timeout)[0] or 1, ''
                return super().run(argv, env, timeout)
        io_ = ListFails()
        self.refused('tag-check-failed', io_)
        self.assertEqual((io_.tools(), io_.fetched), (['gh api', 'gh release'], []))

    def test_only_the_exact_tag_counts_and_a_longer_tag_sharing_the_prefix_does_not(self):
        self.assertEqual(build(FakeIo())['disk']['sha256'], sha(VHDX))  # the fake always lists disk-noble-<serial>.2 and 0
        self.refused('tag-exists', FakeIo(check_out='[{"ref": "refs/tags/x"}, {"ref": "refs/tags/disk-noble-%s"}]' % SERIAL))
        self.refused('tag-exists', FakeIo(check_out=f'[{{"tagName": "disk-noble-{SERIAL}", "isDraft": true}}]'))

    def test_the_published_asset_is_read_back_and_must_match_what_was_hashed(self):
        name, good = f'noble-{SERIAL}.vhdx', 'sha256:' + sha(VHDX)
        qname, qgood = f'noble-{SERIAL}.qcow2', 'sha256:' + sha(QCOW2)
        both = [{'name': name, 'digest': good}, {'name': qname, 'digest': qgood}]
        for readback in ((1, ''), (0, ''), (0, 'not json'), (0, '[]'), (0, '{}'), (0, '{"assets": []}'),
                         (0, json.dumps({'assets': [{'name': name, 'digest': 'sha256:' + sha(b'other')}]})),
                         (0, json.dumps({'assets': [{'name': name, 'digest': None}]})),
                         (0, json.dumps({'assets': [{'name': name, 'digest': sha(VHDX)}]})),
                         (0, json.dumps({'assets': [{'name': 'other.vhdx', 'digest': good}]})),
                         (0, json.dumps({'assets': [{'name': name, 'digest': good}]})),  # the qcow2 is not there
                         (0, json.dumps({'assets': [{'name': name, 'digest': good}, {'name': 'x', 'digest': qgood}]})),
                         (0, json.dumps({'assets': [{'name': name, 'digest': good}, {'name': qname, 'digest': good}]})),
                         (0, json.dumps({'assets': [{'name': name, 'digest': good}] * 2})),
                         (0, json.dumps({'assets': [*both, {'name': 'x', 'digest': good}]}))):
            with self.subTest(readback=readback):
                self.refused('publish-mismatch', FakeIo(readback=readback))
        self.assertEqual(build(FakeIo(readback=(0, json.dumps({'assets': both[::-1]}))))['disk_qcow2']['sha256'], sha(QCOW2))

    def test_slow_tools_get_a_timeout_and_the_convert_a_longer_one(self):
        io_ = FakeIo()
        build(io_)
        self.assertEqual(io_.timeouts, [fd.TOOL_TIMEOUT, fd.TOOL_TIMEOUT, fd.TOOL_TIMEOUT, fd.CONVERT_TIMEOUT,
                                        fd.CONVERT_TIMEOUT, fd.TOOL_TIMEOUT, fd.TOOL_TIMEOUT])
        self.assertLess(fd.CONVERT_TIMEOUT + fd.FETCH_DEADLINE, 60 * 60)

    def test_an_asset_of_2_gib_or_more_is_refused_before_the_upload(self):
        small = fd.MAX_ASSET
        fd.MAX_ASSET = len(VHDX)  # 2 GiB cannot be written in a unit test: shrink the limit to the fake's size
        self.addCleanup(setattr, fd, 'MAX_ASSET', small)
        io_ = FakeIo()
        self.refused('too-big', io_)
        self.assertEqual(io_.tools()[-1], 'qemu-img')
        fd.MAX_ASSET = len(VHDX) + 1
        self.assertEqual(build(FakeIo())['disk']['sha256'], sha(VHDX))
        io_ = FakeIo(qcow2=QCOW2 + b'x')  # the qcow2 alone is over the limit
        self.refused('too-big', io_)
        self.assertEqual((io_.tools()[-2:], io_.uploaded), (['qemu-img', 'qemu-img'], []))

    def test_the_asset_limit_is_2_gib(self):
        self.assertEqual(fd.MAX_ASSET, 2 * 1024 ** 3)

    def test_the_release_environment_is_checked_before_any_fetch(self):
        for kw in ({'repo': ''}, {'repo': 'no-slash'}, {'repo': 'a/b c'}, {'token': ''}, {'sha': ''},
                   {'sha': 'AB' * 20}, {'sha': 'ab' * 19}):
            with self.subTest(kw=kw):
                io_ = FakeIo()
                self.refused('release-env', io_, **kw)
                self.assertEqual((io_.fetched, io_.ran), ([], []))


def arm_build(io_: FakeIo, serial: str = ARM_SERIAL, **kw) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        return fd.build_arm64(io_, serial, Path(tmp), kw.get('repo', REPO), kw.get('sha', SHA), kw.get('token', TOKEN),
                              kw.get('fpr', FPR), kw.get('now', NOW))


class Arm64(unittest.TestCase):
    def setUp(self):
        self.patch(**ARM_PINS)

    def patch(self, **consts) -> None:
        for name, value in consts.items():
            self.addCleanup(setattr, fd, name, getattr(fd, name))
            setattr(fd, name, value)

    def refused(self, why: str, io_: FakeIo | None = None, **kw) -> FakeIo:
        io_ = io_ or ArmIo()
        with self.assertRaisesRegex(fd.Refused, f'^{why}$'):
            arm_build(io_, **kw)
        return io_

    def test_the_happy_path_returns_the_three_lock_entries_and_publishes_one_asset(self):
        io_, zst = ArmIo(), ZST + RAW
        self.assertEqual(arm_build(io_), {
            'disk_arm64_input': {'url': ARM_BASE + fd.IMAGE_ARM64, 'sha256': IMAGE_PIN},
            'disk_arm64': {'url': f'https://github.com/{REPO}/releases/download/{ARM_TAG}/{ARM_ASSET}',
                           'sha256': sha(zst), 'size': len(zst), 'raw_sha256': sha(RAW), 'raw_size': len(RAW)},
            'vfkit': {'version': 'v0.6.4', 'url': fd.VFKIT_URL, 'sha256': VFKIT_PIN, 'size': len(VFKIT)}})
        self.assertEqual(io_.tools(), ['gh api', 'gh release', 'gpgv', 'qemu-img', 'zstd', 'zstd', 'gh release', 'gh api'])
        self.assertEqual(io_.fetched, [ARM_BASE + 'SHA256SUMS', ARM_BASE + 'SHA256SUMS.gpg', fd.VFKIT_URL,
                                       ARM_BASE + fd.IMAGE_ARM64])  # the cheap evidence first, the big image last
        self.assertEqual(io_.limits['vfkit'], len(VFKIT))  # upstream may not serve more than the pinned size
        self.assertEqual(io_.uploaded, [ARM_ASSET])  # never the raw disk: it is far over GitHub's asset limit
        qemu, comp, expand, gh = io_.ran[3][0], io_.ran[4][0], io_.ran[5][0], io_.ran[6][0]
        work = Path(qemu[-2]).parent  # the whole argv, so an option added anywhere is seen: no -o, a plain sparse raw file
        self.assertEqual(qemu, [fd.QEMU_IMG, 'convert', '-f', 'qcow2', '-O', 'raw', str(work / fd.IMAGE_ARM64),
                                str(work / f'noble-arm64-{ARM_SERIAL}.raw')])
        self.assertEqual(comp[:5], [fd.ZSTD, '-19', '-T0', '-q', '-o'])
        self.assertEqual(expand[:3], [fd.ZSTD, '-d', '-q'])
        self.assertEqual((gh[3], gh[gh.index('--target') + 1]), (ARM_TAG, SHA))
        for argv, env in io_.ran:
            self.assertTrue(argv[0].startswith('/usr/bin/'))
            self.assertEqual(env['PATH'], '/usr/bin')
        self.assertEqual([TOKEN in env.values() for _, env in io_.ran], [True, True, False, False, False, False, True, True])

    def test_the_serial_the_key_and_the_environment_are_refused_before_any_network_call(self):
        cases = (('serial', {'serial': 'current'}), ('serial-not-pinned', {'serial': '20260930'}),
                 ('serial-not-pinned', {'serial': ARM_SERIAL + '.1'}), ('unpinned-key', {'fpr': ''}),
                 ('release-env', {'token': ''}))
        for why, kw in cases:
            with self.subTest(kw=kw):
                io_ = self.refused(why, **kw)
                self.assertEqual((io_.fetched, io_.ran), ([], []))

    def test_a_bad_wrong_or_stale_signature_stops_before_vfkit_and_the_image(self):
        old = validsig(FPR, stamp=SIGNED - 5 * 86400)  # four days before the serial's date: a replayed list
        for why, gpgv in (('bad-signature', (1, '')), ('bad-signature', (0, validsig(FPR, good=False))),
                          ('wrong-key', (0, validsig(OTHER))), ('stale-signature', (0, old))):
            with self.subTest(why=why):
                io_ = self.refused(why, ArmIo(gpgv=gpgv))
                self.assertEqual(io_.fetched, [ARM_BASE + 'SHA256SUMS', ARM_BASE + 'SHA256SUMS.gpg'])

    def test_a_signed_sha_that_is_not_the_pinned_one_stops_before_vfkit_and_the_image(self):
        other = fd.QCOW2_MAGIC + b'a rebuilt image'  # validly signed, but not the pinned image
        io_ = self.refused('image-pin-mismatch', ArmIo(image=other))
        self.assertEqual(io_.fetched, [ARM_BASE + 'SHA256SUMS', ARM_BASE + 'SHA256SUMS.gpg'])
        self.refused('no-signed-sum', ArmIo(sums=sums_for(ARM_IMAGE)))  # the list names only the amd64 image

    def test_an_image_that_is_not_the_signed_sha_or_not_a_qcow2_is_refused_before_the_convert(self):
        io_ = ArmIo(sums=sums_for(ARM_IMAGE, fd.IMAGE_ARM64))
        io_.bodies[fd.IMAGE_ARM64] = fd.QCOW2_MAGIC + b'swapped on the way'
        self.refused('sum-mismatch', io_)
        self.assertEqual(io_.tools()[-1], 'gpgv')
        bad = b'MZ not a qcow2'  # its sha is signed and pinned: the magic is the second line of defense
        self.patch(ARM64_IMAGE_SHA256=sha(bad))
        self.refused('not-qcow2', ArmIo(image=bad))

    def test_vfkit_bytes_that_are_not_the_pinned_sha_stop_before_the_image(self):
        replaced = b'vfkit evil'  # the pinned size, other bytes: only the sha can refuse it
        self.assertEqual(len(replaced), len(VFKIT))
        io_ = self.refused('vfkit-mismatch', ArmIo(vfkit=replaced))
        self.assertEqual(io_.fetched[-1], fd.VFKIT_URL)
        self.assertEqual(io_.tools(), ['gh api', 'gh release', 'gpgv'])

    def test_vfkit_of_another_size_than_the_pinned_one_is_refused_even_with_the_pinned_sha(self):
        for size in (len(VFKIT) + 1, len(VFKIT) - 1):  # the lock entry states VFKIT_SIZE: it must be the fetched file's own
            with self.subTest(size=size):
                self.patch(VFKIT_SIZE=size)
                io_ = self.refused('vfkit-mismatch')  # the sha is the pinned one; a short (or long) body is not
                self.assertEqual(io_.tools(), ['gh api', 'gh release', 'gpgv'])

    def test_the_raw_disk_must_be_gpt_with_an_efi_system_partition(self):
        no_esp = gpt_disk((LINUX_FS,) * 4)
        for raw in (no_esp, b'', RAW[:1024], b'\x00' * len(RAW), RAW[:510] + b'\x00\x00' + RAW[512:],
                    RAW[:512] + b'EFI PARX' + RAW[520:]):
            with self.subTest(raw=raw[:8]):
                io_ = self.refused('not-efi-disk', ArmIo(raw=raw))
                self.assertEqual(io_.tools()[-1], 'qemu-img')  # nothing compressed, nothing published

    def test_a_header_that_points_past_any_file_offset_is_not_an_efi_disk_and_does_not_raise(self):
        for lba in (1 << 55, (1 << 55) - 1, (1 << 64) - 1):
            with self.subTest(lba=lba):
                disk = bytearray(RAW)
                struct.pack_into('<Q', disk, fd.SECTOR + 72, lba)
                io_ = self.refused('not-efi-disk', ArmIo(raw=bytes(disk)))
                self.assertEqual((io_.tools()[-1], io_.uploaded), ('qemu-img', []))

    def has_esp(self, raw: bytes) -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'raw').write_bytes(raw)
            return fd.has_esp(Path(tmp, 'raw'))

    def test_has_esp_reads_the_whole_entry_table(self):
        self.assertTrue(self.has_esp(RAW))
        for size, count in ((128, 4), (256, 4), (128, 128), (128, 512)):  # the last of up to 64 KiB of entries counts too
            with self.subTest(size=size, count=count):
                self.assertTrue(self.has_esp(gpt_disk((LINUX_FS,) * (count - 1) + (fd.ESP_TYPE,), size)))
        self.assertFalse(self.has_esp(gpt_disk((LINUX_FS,) * 512 + (fd.ESP_TYPE,))))  # 64 KiB + 128: over the cap
        self.assertFalse(self.has_esp(gpt_disk((LINUX_FS, EMPTY, fd.ESP_TYPE[:-1] + b'\x00', LINUX_FS))))  # no ESP type, one byte off
        self.assertFalse(self.has_esp(b''))  # a file that is not even a header
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(fd.has_esp(Path(tmp, 'absent')))  # unreadable: False, not an exception

    def test_has_esp_refuses_a_table_inside_the_headers_or_with_entries_under_128_bytes(self):
        for lba in (0, 1):  # an ESP GUID planted where that LBA's table would put its second entry: only the LBA stops it
            with self.subTest(lba=lba):
                disk = bytearray(RAW)
                struct.pack_into('<Q', disk, fd.SECTOR + 72, lba)
                disk[lba * fd.SECTOR + 128:lba * fd.SECTOR + 144] = fd.ESP_TYPE
                self.assertFalse(self.has_esp(bytes(disk)))
        for size in (127, 64, 0):  # the same table, with the ESP as its first entry, but entries too small for a GPT's
            with self.subTest(size=size):
                self.assertFalse(self.has_esp(gpt_disk((fd.ESP_TYPE, EMPTY, EMPTY, EMPTY), size)))
        self.assertTrue(self.has_esp(gpt_disk((fd.ESP_TYPE, EMPTY, EMPTY, EMPTY))))  # the control: 128 bytes passes
        for offset, fmt, value in ((72, '<Q', 99999), (84, '<I', 0), (80, '<I', 1 << 20)):  # past the end, size 0, 64 KiB+
            with self.subTest(offset=offset):
                disk = bytearray(RAW)
                struct.pack_into(fmt, disk, fd.SECTOR + offset, value)
                self.assertFalse(self.has_esp(bytes(disk)))

    def test_a_failed_convert_or_compress_publishes_nothing(self):
        self.assertEqual(self.refused('convert-failed', ArmIo(qemu=1)).uploaded, [])
        self.assertEqual(self.refused('compress-failed', ArmIo(zstd=1)).uploaded, [])

    def test_an_asset_that_does_not_expand_to_the_raw_sha_is_refused_before_the_upload(self):
        io_ = self.refused('roundtrip-mismatch', ArmIo(again=RAW + b'\x00'))
        self.assertEqual((io_.tools()[-1], io_.uploaded), ('zstd', []))

    def test_a_raw_disk_over_the_cap_and_an_asset_of_2_gib_or_more_are_refused(self):
        self.assertEqual((fd.MAX_RAW, fd.MAX_ASSET), (8 * 1024 ** 3, 2 * 1024 ** 3))
        for name, limit, why, last in (('MAX_RAW', len(RAW) - 1, 'too-big', 'qemu-img'),
                                       ('MAX_ASSET', len(ZST + RAW), 'too-big', 'zstd')):
            with self.subTest(name=name):
                self.addCleanup(setattr, fd, name, getattr(fd, name))
                setattr(fd, name, limit)  # 2 GiB cannot be written in a unit test: shrink the limit to the fake's size
                io_ = self.refused(why)
                self.assertEqual((io_.tools()[-1], io_.uploaded), (last, []))
                setattr(fd, name, limit + 1)
                arm_build(ArmIo())  # one byte more room and the same build passes

    def test_the_tag_is_its_own_so_the_amd64_release_of_the_same_serial_does_not_block_it(self):
        amd = f'[{{"ref": "refs/tags/disk-noble-{ARM_SERIAL}", "tagName": "disk-noble-{ARM_SERIAL}", "isDraft": false}}]'
        self.assertEqual(arm_build(ArmIo(check_out=amd))['disk_arm64']['url'].split('/')[-2], ARM_TAG)
        self.assertEqual(self.refused('tag-exists', ArmIo(tag_exists=True)).fetched, [])  # tag_is_free is shared with amd64

    def test_the_published_asset_is_read_back_and_must_match_what_was_hashed(self):
        good = {'name': ARM_ASSET, 'digest': 'sha256:' + sha(ZST + RAW)}
        for readback in ((1, ''), (0, json.dumps({'assets': [{**good, 'digest': 'sha256:' + sha(b'other')}]})),
                         (0, json.dumps({'assets': [good, {**good, 'name': 'extra'}]}))):
            with self.subTest(readback=readback):
                self.refused('publish-mismatch', ArmIo(readback=readback))
        arm_build(ArmIo(readback=(0, json.dumps({'assets': [good]}))))


class Arm64Pins(unittest.TestCase):
    """What the script ships, with nothing patched."""

    def test_the_shipped_constants_are_the_reviewed_ones(self):
        self.assertEqual(fd.ARM64_SERIAL, '20260926')
        self.assertEqual((fd.VFKIT_VERSION, fd.VFKIT_SIZE), ('v0.6.4', 66431936))
        self.assertEqual(fd.VFKIT_URL, 'https://github.com/crc-org/vfkit/releases/download/v0.6.4/vfkit')
        # each pin is a full lowercase sha256 that starts and ends as the value checked against Ubuntu's SHA256SUMS for
        # that serial and against the digest of the vfkit release asset
        for pin, head, tail in ((fd.ARM64_IMAGE_SHA256, '1d6bffe6', 'fc55'), (fd.VFKIT_SHA256, '0ed83fc8', '652d')):
            self.assertRegex(pin, r'\A[0-9a-f]{64}\Z')
            self.assertEqual((pin[:8], pin[-4:]), (head, tail))
        self.assertEqual(uuid.UUID(bytes_le=fd.ESP_TYPE), uuid.UUID('C12A7328-F81F-11D2-BA4B-00A0C93EC93B'))


class Main(unittest.TestCase):
    ENV = {'GITHUB_REPOSITORY': REPO, 'GITHUB_SHA': SHA, 'GH_TOKEN': TOKEN}

    def pin(self, fpr: str, **consts: str) -> None:
        for name, value in {'CLOUDIMAGE_KEY_FPR': fpr, **consts}.items():
            self.addCleanup(setattr, fd, name, getattr(fd, name))
            setattr(fd, name, value)

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
        self.assertEqual(sorted(entries), ['disk', 'disk_input', 'disk_qcow2'])
        self.assertEqual(sorted(entries['disk']), ['sha256', 'url'])
        self.assertEqual(sorted(entries['disk_qcow2']), ['sha256', 'size', 'url'])
        self.assertTrue(entries['disk']['url'].startswith(f'https://github.com/{REPO}/releases/download/disk-noble-'))
        self.assertNotIn(TOKEN, out.getvalue())

    def test_arm64_is_a_word_before_the_serial_and_amd64_may_be_named(self):
        for argv in (['arm64', ARM_SERIAL, 'x'], ['sparc', ARM_SERIAL], ['arm64', 'amd64', ARM_SERIAL]):
            self.assertEqual(self.go(argv, FakeIo())[0], fd.USAGE)
        self.pin(FPR)
        code, out, _ = self.go(['amd64', SERIAL], FakeIo(), **self.ENV)
        self.assertEqual((code, sorted(json.loads(out.partition('\n')[2]))), (0, ['disk', 'disk_input', 'disk_qcow2']))

    def test_arm64_refuses_another_serial_before_any_fetch(self):
        self.pin(FPR, **ARM_PINS)
        io_ = ArmIo()
        self.assertEqual(self.go(['arm64', '20260930'], io_, **self.ENV),
                         (fd.REFUSED, '', 'fleet-disk: refused serial-not-pinned\n'))
        self.assertEqual((io_.fetched, io_.ran), ([], []))

    def test_arm64_runs_against_the_shipped_pins_and_stops_at_an_image_that_is_not_the_pinned_one(self):
        self.pin(FPR)  # nothing else patched: the fake image is validly signed but is not the shipped pin
        io_ = ArmIo()
        self.assertEqual(self.go(['arm64', ARM_SERIAL], io_, **self.ENV),
                         (fd.REFUSED, '', 'fleet-disk: refused image-pin-mismatch\n'))
        self.assertEqual(io_.fetched, [ARM_BASE + 'SHA256SUMS', ARM_BASE + 'SHA256SUMS.gpg'])

    def test_arm64_prints_its_three_entries_to_paste_and_leaves_no_files(self):
        self.pin(FPR, **ARM_PINS)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()) as out:
            code = fd.main(['fleet-disk.py', 'arm64', ARM_SERIAL], {'RUNNER_TEMP': tmp, **self.ENV}, ArmIo())
            self.assertEqual(list(Path(tmp).iterdir()), [])
        head, _, body = out.getvalue().partition('\n')
        entries = json.loads(body)
        self.assertEqual((code, sorted(entries)), (0, ['disk_arm64', 'disk_arm64_input', 'vfkit']))
        self.assertIn('carrier.lock.json', head)
        self.assertEqual(sorted(entries['disk_arm64']), ['raw_sha256', 'raw_size', 'sha256', 'size', 'url'])
        self.assertEqual(sorted(entries['vfkit']), ['sha256', 'size', 'url', 'version'])
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

    def run_script_code(self, code: str, *args: str) -> subprocess.CompletedProcess:
        env = {'GITHUB_REPOSITORY': REPO, 'GITHUB_SHA': SHA, 'GH_TOKEN': TOKEN}
        return subprocess.run([sys.executable, '-I', '-c', code, *args], env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=60, check=False)

    def test_usage_and_a_refused_serial(self):
        self.assertEqual(self.run_script().returncode, fd.USAGE)
        done = self.run_script('current')
        self.assertEqual((done.returncode, done.stdout, done.stderr), (fd.REFUSED, '', 'fleet-disk: refused serial\n'))

    def test_arm64_refuses_another_serial_before_any_network_call(self):
        done = self.run_script('arm64', '20260930')
        self.assertEqual((done.returncode, done.stdout, done.stderr), (fd.REFUSED, '', 'fleet-disk: refused serial-not-pinned\n'))
        self.assertEqual(self.run_script('arm64', ARM_SERIAL, 'x').returncode, fd.USAGE)

    def test_a_missing_release_environment_is_refused(self):
        done = self.run_script(SERIAL, GH_TOKEN='')
        self.assertEqual((done.returncode, done.stdout, done.stderr), (fd.REFUSED, '', 'fleet-disk: refused release-env\n'))

    def test_a_missing_tool_is_refused_not_crashed(self):
        # the real subprocess path, with gh pointed at nothing (runs where gh is installed too, as the runners have it)
        code = ('import importlib.util, os, sys\n'
                'spec = importlib.util.spec_from_file_location("fd", sys.argv[1])\n'
                'fd = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(fd)\n'
                'fd.GH = "/nonexistent/gh"\n'
                'sys.exit(fd.main(["fleet-disk.py", sys.argv[2]], dict(os.environ), fd.Real()))\n')
        done = self.run_script_code(code, str(ROOT / 'bin/fleet-disk.py'), SERIAL)
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

    def test_a_tool_that_outlives_its_timeout_is_refused(self):
        with self.assertRaisesRegex(fd.Refused, '^tool-timeout$'):
            fd.Real().run([sys.executable, '-I', '-c', 'import time; time.sleep(30)'], dict(os.environ), 1)

    def test_a_download_past_its_deadline_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp, 'src')
            src.write_bytes(IMAGE)
            old = fd.FETCH_DEADLINE
            fd.FETCH_DEADLINE = -1
            self.addCleanup(setattr, fd, 'FETCH_DEADLINE', old)
            with self.assertRaisesRegex(fd.Refused, '^fetch-timeout$'):
                fd.Real().fetch(src.as_uri(), Path(tmp, 'dest'), 1 << 20)

    def test_valid_fingerprints_reads_both_ends_of_a_validsig(self):
        self.assertEqual(fd.valid_fingerprints(validsig(FPR.lower()) + 'noise\n[GNUPG:] GOODSIG x\n'), {FPR})
        self.assertEqual(fd.valid_fingerprints('[GNUPG:] VALIDSIG short\n'), set())
        sub = f'[GNUPG:] VALIDSIG {OTHER} 2026-09-30 {SIGNED} 0 4 0 1 10 01 {FPR}\n'
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

    def test_the_disk_workflow_is_a_main_only_dispatch_with_a_serial_and_an_arch(self):
        self.assertRegex(self.DISK, r'(?m)^on:\n  workflow_dispatch:\n    inputs:\n      serial:\n')
        self.assertEqual(re.findall(r'(?m)^      (\w+):\n        (?:description|required)', self.DISK),
                         ['serial', 'arch'])
        self.assertIn('        type: choice\n        options: [amd64, arm64]\n        default: amd64\n', self.DISK)
        self.assertNotIn('pull_request', self.DISK)
        self.assertIn("if: github.ref == 'refs/heads/main'", self.DISK)
        self.assertIn('timeout-minutes: 60', self.DISK)

    def test_the_disk_job_runs_in_its_own_environment_never_the_signing_one_and_the_if_is_not_called_a_boundary(self):
        self.assertEqual(re.findall(r'(?m)^    environment: (\S+)$', self.DISK), ['disk'])
        self.assertNotIn('never runs', self.DISK)
        self.assertIn('accidental dispatch', self.DISK)

    def test_no_checkout_leaves_the_token_in_git_config(self):
        for text in (self.DISK, self.TEST):
            self.assertEqual(text.count('persist-credentials: false'), text.count('actions/checkout@'))
            self.assertGreater(text.count('actions/checkout@'), 0)

    def test_only_the_disk_job_writes_and_only_contents(self):
        self.assertEqual(re.findall(r'(\w[\w-]*): write', self.DISK), ['contents'])
        self.assertIn('    permissions:\n      contents: write\n', self.DISK)
        self.assertNotIn('write', self.TEST)

    def test_the_input_reaches_the_script_only_through_env(self):
        runs = re.findall(r'(?m)^\s+(?:- )?run: (.*)$', self.DISK)
        self.assertEqual(runs[-1], 'python3 bin/fleet-disk.py "$ARCH" "$SERIAL"')
        self.assertIn('SERIAL: ${{ inputs.serial }}', self.DISK)
        self.assertIn('ARCH: ${{ inputs.arch }}', self.DISK)
        self.assertIn('GH_TOKEN: ${{ github.token }}', self.DISK)
        for run in runs:
            self.assertNotIn('${{', run)

    def test_the_disk_workflow_installs_only_qemu_utils_and_zstd_with_apt(self):
        self.assertEqual(re.findall(r'apt-get install (.*)', self.DISK), ['-y --no-install-recommends qemu-utils zstd'])

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
