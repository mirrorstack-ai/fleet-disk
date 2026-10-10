#!/usr/bin/env python3
"""Move the sealed secrets that .github/workflows/keygen.yml printed into the Environment `release` of fleet-disk.

TEST-GRADE keys only (never R). This script handles values that are ALREADY sealed (a libsodium sealed box to the
environment's public key); it never sees a private key and cannot make one. It reads the keygen run's log (a file, or
stdin: `gh run view <id> --log | fleet-keygen-put.py`), takes the `KEYGEN-SEALED <NAME> <key_id> <base64>` lines and
refuses the whole batch unless every one is exactly what keygen.yml prints:

  - exactly the three names SIGN_KEY, TAG_KEY and FLEET_READ, each once (a repeated line must be identical), one key_id;
  - strict canonical base64 of exactly 435 bytes (a 387-byte OpenSSH ed25519 private key + the 48-byte sealed-box
    overhead), that is not readable text (a pasted private key, in PEM or base64, is refused here);
  - a key_id that is still the environment's current one (a read of its public key), so a rotated key is caught first.

Then it PUTs each one with `gh api` (the JSON body goes through stdin, never argv) and prints names and key_id, never a
value. `--dry-run` does everything except the PUTs. Exit 0 done, 1 gh failed, 2 refused. Standard library only."""
import argparse
import base64
import json
import re
import shutil
import subprocess
import sys

NAMES = ('SIGN_KEY', 'TAG_KEY', 'FLEET_READ')
MARKER = 'KEYGEN-SEALED'
PLAIN_LEN = 387     # must equal PLAIN_LEN in keygen.yml
SEALED_LEN = PLAIN_LEN + 48     # crypto_box_SEALBYTES: the 32-byte ephemeral public key + the 16-byte MAC
REPO_RE = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
ENV_RE = re.compile(r'[A-Za-z0-9_-]+')
KEY_ID_RE = re.compile(r'[0-9]{1,32}')
PRINTABLE = frozenset(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}


class Refused(Exception):
    pass


def check_sealed(name: str, text: str) -> bytes:
    """The decoded sealed box, or Refused. It cannot prove a value was sealed to the right key (nobody but GitHub can);
    it proves it is not a plaintext key and has the one length keygen.yml produces."""
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        raise Refused('%s: not base64' % name) from None
    if base64.b64encode(raw).decode('ascii') != text:
        raise Refused('%s: base64 is not canonical' % name)
    if len(raw) != SEALED_LEN:
        raise Refused('%s: %d bytes, a sealed box here is exactly %d' % (name, len(raw), SEALED_LEN))
    if b'-----' in raw or b'PRIVATE KEY' in raw or all(b in PRINTABLE for b in raw):
        raise Refused('%s: looks like plaintext, not a sealed box' % name)
    return raw


def parse(log: str) -> tuple:
    """(key_id, {name: base64}) from every KEYGEN-SEALED line of a run log, all or nothing."""
    found: dict = {}
    key_ids = set()
    for line in log.splitlines():
        at = line.find(MARKER)
        if at < 0:
            continue
        fields = line[at:].split()
        if len(fields) != 4:
            raise Refused('a %s line does not have 3 fields' % MARKER)
        _, name, key_id, text = fields
        if name not in NAMES:
            raise Refused('unknown secret name %r' % name[:40])
        if not KEY_ID_RE.fullmatch(key_id):
            raise Refused('%s: key_id is not digits' % name)
        check_sealed(name, text)
        if found.setdefault(name, text) != text:
            raise Refused('%s: two different sealed values' % name)
        key_ids.add(key_id)
    if sorted(found) != sorted(NAMES):
        raise Refused('need exactly %s, found %s' % (', '.join(NAMES), ', '.join(sorted(found)) or 'none'))
    if len(key_ids) != 1:
        raise Refused('the sealed values name different key_ids')
    return key_ids.pop(), found


def gh(args: list, body: str = '') -> str:
    exe = shutil.which('gh')
    if not exe:
        raise SystemExit('gh not found')
    done = subprocess.run([exe, 'api', *args], input=body, capture_output=True, text=True)
    if done.returncode != 0:
        first = (done.stderr.strip().splitlines() or ['no message'])[0]
        raise SystemExit('gh api failed: %s' % first[:200])
    return done.stdout


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('log', nargs='?', default='-', help='the keygen run log (default: stdin)')
    ap.add_argument('--repo', default='mirrorstack-ai/fleet-disk')
    ap.add_argument('--env', default='release')
    ap.add_argument('--dry-run', action='store_true', help='validate and read the current key_id; PUT nothing')
    args = ap.parse_args(argv)
    if not REPO_RE.fullmatch(args.repo) or not ENV_RE.fullmatch(args.env):
        print('refused: --repo must be owner/name and --env a plain name', file=sys.stderr)
        return 2
    try:
        if args.log == '-':
            text = sys.stdin.read()
        else:
            with open(args.log, encoding='utf-8', errors='replace') as handle:
                text = handle.read()
        key_id, values = parse(text)
    except Refused as why:
        print('refused: %s' % why, file=sys.stderr)
        return 2
    base = 'repos/%s/environments/%s/secrets' % (args.repo, args.env)
    current = gh([base + '/public-key', '--jq', '.key_id']).strip()
    if current != key_id:
        print('refused: the sealed values are for key_id %s, the environment now has %s' % (key_id, current),
              file=sys.stderr)
        return 2
    for name in NAMES:
        if args.dry_run:
            print('would PUT %s/%s (key_id %s)' % (args.env, name, key_id))
            continue
        gh(['-X', 'PUT', '%s/%s' % (base, name), '--input', '-'],
           json.dumps({'encrypted_value': values[name], 'key_id': key_id}))
        print('PUT %s/%s (key_id %s)' % (args.env, name, key_id))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
