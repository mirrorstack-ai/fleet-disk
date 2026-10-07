"""install.json: the owner-signed release manifest a bootstrap hands over to. `signed_install` counts the
bytes only when `ssh-keygen -Y verify -n mirrorstack-fleet-install -I owner` accepts them (the signature before the
bytes are parsed, as verify-archive.signed_pin does for the pin), then reads them strictly: exactly the keys of
SCHEMA, kind `install`, not expired, no older than the caller's --min-serial, and each bootstrap blob in the source
head's tree; an optional `handoff` names the successor key's first release. Pure: the clock, the tree and the
ssh-keygen runner come from the caller. A refusal is a code, never a value."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from datetime import datetime

from fleet.core import canon, clock

NS, PRINCIPAL = 'mirrorstack-fleet-install', 'owner'  # the pin's namespace is mirrorstack-fleet-pin: one per file kind
SSH_KEYGEN = 'C:\\Windows\\System32\\OpenSSH\\ssh-keygen.exe' if os.name == 'nt' else '/usr/bin/ssh-keygen'
KIND = 'install'
MAX_BYTES = 8192  # a manifest is ~700 bytes; a bigger file is refused before ssh-keygen sees it
MAX_BUNDLE = 1 << 30  # the bundle's byte cap, verify-archive's MAX_BYTES
MAX_COUNT = 1 << 31  # the cap of a serial
CODES = ('size', 'key', 'sig', 'form', 'kind', 'expired', 'rollback', 'tree')  # the word after REFUSED; a test pins it
HEX40, HEX64 = re.compile('[0-9a-f]{40}', re.ASCII), re.compile('[0-9a-f]{64}', re.ASCII)
UTC_TIME = re.compile('[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', re.ASCII)  # no fraction
_KEY = re.compile('[A-Za-z0-9+/]{68}', re.ASCII)  # an ssh-ed25519 blob: 51 bytes, no padding
_LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
URL = re.compile(rf'https://({_LABEL}(?:\.{_LABEL})+)/[A-Za-z0-9._~/-]{{1,200}}', re.ASCII)  # https, a host, a path
Run = Callable[[Sequence[str], bytes], tuple[int, bytes]]  # (absolute argv, stdin) -> (exit code, stdout)
InTree = Callable[[str, str], bool]  # (source_head, blob id) -> is that blob in the head's git tree
SCHEMA = ('kind', 'serial', 'valid_until', 'source_head', 'bootstrap', 'kit', 'lock_sha256', 'bundle')
BOOT_KEYS, KIT_KEYS = ('sha256', 'blob'), ('serial', 'kit_json_sha256')
HANDOFF_KEYS = ('fp', 'first_serial', 'ps1_sha256', 'sh_sha256')  # not `serial`: bootstrap.sh's sed pick would read it
FP = re.compile('SHA256:[A-Za-z0-9+/]{43}', re.ASCII)  # what ssh-keygen -l prints for an ed25519 key
BUNDLE_KEYS = ('head', 'tree', 'url', 'sha256', 'size')
OSES = ('ps1', 'sh')  # the two bootstraps


class Refused(Exception):
    """The word after REFUSED: one of CODES."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def run_argv(argv: Sequence[str], stdin: bytes) -> tuple[int, bytes]:
    """The one process call: argv as given (no shell, no PATH search), a minute at most; (127, b'') if it can't run."""
    try:
        done = subprocess.run(list(argv), input=stdin, capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return 127, b''
    return done.returncode, done.stdout


def verify_signature(text: bytes, sig: bytes, owner_pub: bytes, run: Run = run_argv) -> None:
    """text counts only when sig verifies against the owner's one ssh-ed25519 line under NS and PRINCIPAL; else `key`
    (the key line is off-shape) or `sig`."""
    words = owner_pub.decode('ascii', 'replace').split()
    if len(words) < 2 or words[0] != 'ssh-ed25519' or not _KEY.fullmatch(words[1]):
        raise Refused('key')
    with tempfile.TemporaryDirectory(prefix='fleet-install-') as tmp:
        allowed, armor = os.path.join(tmp, 'allowed_signers'), os.path.join(tmp, 'install.sig')
        with open(allowed, 'wb') as f:  # bytes: text mode would end the line in CRLF on Windows
            f.write(f'{PRINCIPAL} namespaces="{NS}" ssh-ed25519 {words[1]}\n'.encode('ascii'))
        with open(armor, 'wb') as f:
            f.write(sig)
        code, out = run((SSH_KEYGEN, '-Y', 'verify', '-f', allowed, '-I', PRINCIPAL, '-n', NS, '-s', armor), text)
    if code != 0 or not out.startswith(f'Good "{NS}" signature for {PRINCIPAL} with '.encode()):
        raise Refused('sig')


def _obj(v: object, keys: Sequence[str]) -> dict:
    """v when it is an object holding exactly keys; else `form`."""
    if not isinstance(v, dict) or set(v) != set(keys):
        raise Refused('form')
    return v


def _match(v: object, rx: re.Pattern[str]) -> str:
    if type(v) is not str or not rx.fullmatch(v):
        raise Refused('form')
    return v


def _count(v: object, lo: int, hi: int) -> int:
    if type(v) is not int or not lo <= v <= hi:
        raise Refused('form')
    return v


def parse_install(text: bytes) -> dict[str, object]:
    """The exact shape of SCHEMA, plus the optional handoff (a fingerprint, a first_serial above
    serial, two hashes), from strict JSON: hashes lower-case hex, an https URL with a host name, a valid_until like
    2026-12-01T00:00:00Z; kind other than `install` is `kind`, any other misfit `form`."""
    try:
        doc = canon.loads_strict(text)
    except canon.SchemaError:
        raise Refused('form') from None
    if not isinstance(doc, dict) or doc.get('kind') != KIND:
        raise Refused('kind')
    _obj(doc, SCHEMA + ('handoff',) if 'handoff' in doc else SCHEMA)
    _count(doc['serial'], 0, MAX_COUNT)
    try:
        clock.parse_utc(_match(doc['valid_until'], UTC_TIME))
    except ValueError:
        raise Refused('form') from None
    _match(doc['source_head'], HEX40)
    _match(doc['lock_sha256'], HEX64)
    boot = _obj(doc['bootstrap'], OSES)
    for name in OSES:
        entry = _obj(boot[name], BOOT_KEYS)
        _match(entry['sha256'], HEX64)
        _match(entry['blob'], HEX40)
    kit = _obj(doc['kit'], KIT_KEYS)
    _count(kit['serial'], 0, MAX_COUNT)
    _match(kit['kit_json_sha256'], HEX64)
    bundle = _obj(doc['bundle'], BUNDLE_KEYS)
    _match(bundle['head'], HEX40)
    _match(bundle['tree'], HEX40)
    _match(bundle['url'], URL)
    _match(bundle['sha256'], HEX64)
    _count(bundle['size'], 1, MAX_BUNDLE)
    if 'handoff' in doc:
        hand = _obj(doc['handoff'], HANDOFF_KEYS)
        _match(hand['fp'], FP)
        _count(hand['first_serial'], doc['serial'] + 1, MAX_COUNT)  # the successor series starts after this release
        _match(hand['ps1_sha256'], HEX64)
        _match(hand['sh_sha256'], HEX64)
    return doc


def signed_install(text: bytes, sig: bytes, owner_pub: bytes, *, min_serial: int, now: datetime, in_tree: InTree,
                   run: Run = run_argv) -> dict[str, object]:
    """The manifest's value once the signature holds (before any parsing), the schema fits, now is before valid_until,
    serial is at least min_serial (the caller's own floor, never a field of the file) and in_tree(source_head, blob)
    holds for both bootstrap blobs; else Refused with the code."""
    if len(text) > MAX_BYTES:
        raise Refused('size')
    verify_signature(text, sig, owner_pub, run)
    doc = parse_install(text)
    if clock.parse_utc(doc['valid_until']) <= now:
        raise Refused('expired')
    if doc['serial'] < min_serial:
        raise Refused('rollback')
    if not all(in_tree(doc['source_head'], doc['bootstrap'][name]['blob']) for name in OSES):
        raise Refused('tree')
    return doc
