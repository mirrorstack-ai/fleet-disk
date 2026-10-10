#!/usr/bin/env python3
"""Move the sealed secrets that .github/workflows/keygen.yml printed into the Environment `release` of fleet-disk.

TEST-GRADE keys only (never R). This script handles values that are ALREADY sealed (a libsodium sealed box to the
environment's public key); it never sees a private key and cannot make one. It takes a run id and the reviewed commit,
fetches that run's log itself (`gh run view`; there is no way to hand it a log) and refuses the whole batch unless:

  - the run is what the coordinator dispatched: workflow `.github/workflows/keygen.yml`, event workflow_dispatch, branch
    main, completed with success, and its head commit is exactly `--sha` (the reviewed commit);
  - the run was sealed to THIS environment: the `KEYGEN-RECIPIENT <key_id> <key>` line the workflow prints equals both the
    key_id and the key that the environment's public-key endpoint returns now (the workflow takes the key as a free input,
    so without this a run sealed to someone else's key would pass every other check);
  - exactly the names of the set (`--keys test`, the default: SIGN_KEY, TAG_KEY and FLEET_READ; `--keys kit-upload`: only
    KIT_UPLOAD_KEY, the Ed25519 key that signs uploads to the kit host), each once (a repeated line must be identical), one key_id;
  - each sealed value is strict base64 of exactly 435 bytes (a 387-byte OpenSSH ed25519 private key + the 48-byte
    sealed-box overhead; 167 for the 119-byte Ed25519 PEM of kit-upload), that is not readable text (a pasted private key,
    in PEM or base64, is refused here);
  - each name has exactly one well-formed public line and fingerprint (kit-upload: `ed25519 <64 hex>`, the raw public key the
    kit host is given as KIT_UP_PUB, and the SHA256 fingerprint of exactly those 32 bytes).

Then it prints the verified public lines and fingerprints (the deploy-key settings and the bake step take the public
halves from THIS output, not from a separate look at the log) and PUTs each sealed value with `gh api` (the JSON body goes
through stdin, never argv); it prints names and key_id, never a sealed value. `--dry-run` does everything except the PUTs.
Exit 0 done, 1 gh failed, 2 refused. Standard library only."""
import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys

NAMES = ('SIGN_KEY', 'TAG_KEY', 'FLEET_READ')
UPLOAD_NAMES = ('KIT_UPLOAD_KEY',)
WORKFLOW_PATH = '.github/workflows/keygen.yml'
MARKER_RE = re.compile(r'KEYGEN-(SEALED|PUBLIC|FINGERPRINT|RECIPIENT)(?![\w-])')
RUN_RE = re.compile(r'[0-9]{1,20}')
SHA_RE = re.compile(r'[0-9a-f]{40}')
PUBLIC_RE = re.compile(r'ssh-ed25519 [A-Za-z0-9+/]{68}')    # the 51-byte ed25519 public blob, no padding
UPLOAD_PUBLIC_RE = re.compile(r'ed25519 [0-9a-f]{64}')      # the raw 32-byte public key of the upload key
FINGERPRINT_RE = re.compile(r'SHA256:[A-Za-z0-9+/]{43}')
PLAIN_LEN = 387     # must equal PLAIN_LEN in keygen.yml
PEM_LEN = 119       # must equal PEM_LEN in keygen.yml: an Ed25519 PKCS8 PEM from openssl genpkey
SEALED_LEN = PLAIN_LEN + 48     # crypto_box_SEALBYTES: the 32-byte ephemeral public key + the 16-byte MAC
# per `--keys` set: the names, the length of a private key file, the shape of the public line
SETS = {'test': (NAMES, PLAIN_LEN, PUBLIC_RE), 'kit-upload': (UPLOAD_NAMES, PEM_LEN, UPLOAD_PUBLIC_RE)}
REPO_RE = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
ENV_RE = re.compile(r'[A-Za-z0-9_-]+')
KEY_ID_RE = re.compile(r'[0-9]{1,32}')
PRINTABLE = frozenset(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}


class Refused(Exception):
    pass


def check_sealed(name: str, text: str, plain_len: int = PLAIN_LEN) -> bytes:
    """The decoded sealed box, or Refused. It cannot prove a value was sealed to the right key (nobody but GitHub can);
    it proves it is not a plaintext key and has the one length keygen.yml produces for the set."""
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        raise Refused('%s: not base64' % name) from None
    if base64.b64encode(raw).decode('ascii') != text:  # canonical only: 3.11's validate=True still accepts extra '=' padding
        raise Refused('%s: not canonical base64' % name)
    if len(raw) != plain_len + 48:
        raise Refused('%s: %d bytes, a sealed box here is exactly %d' % (name, len(raw), plain_len + 48))
    if b'-----' in raw or b'PRIVATE KEY' in raw or all(b in PRINTABLE for b in raw):
        raise Refused('%s: looks like plaintext, not a sealed box' % name)
    return raw


def parse(log: str, keys: str = 'test') -> dict:
    """{'key_id', 'recipient', 'sealed', 'public', 'fingerprint'} from every KEYGEN-* line of a run log, all or nothing,
    for the set `keys` (see SETS)."""
    names, plain_len, public_re = SETS[keys]
    sealed: dict = {}
    public: dict = {}
    fingerprint: dict = {}
    key_ids = set()
    recipients = set()
    for line in log.splitlines():
        hit = MARKER_RE.search(line)
        if not hit:
            continue
        kind = hit.group(1)
        fields = line[hit.start():].split()
        if kind == 'RECIPIENT':
            if len(fields) != 3:
                raise Refused('a KEYGEN-RECIPIENT line does not have 2 fields')
            _, key_id, key = fields
            if not KEY_ID_RE.fullmatch(key_id):
                raise Refused('recipient: key_id is not digits')
            check_key(key)
            recipients.add((key_id, key))
            continue
        if kind == 'FINGERPRINT':
            if len(fields) != 3:
                raise Refused('a KEYGEN-FINGERPRINT line does not have 2 fields')
            _, name, value = fields
            ok = FINGERPRINT_RE.fullmatch(value)
            table, what = fingerprint, 'fingerprint'
        else:
            if len(fields) != 4:
                raise Refused('a KEYGEN-%s line does not have 3 fields' % kind)
            _, name, first, second = fields
            if kind == 'PUBLIC':
                value = '%s %s' % (first, second)
                ok = public_re.fullmatch(value)
                table, what = public, 'public line'
            else:
                if not KEY_ID_RE.fullmatch(first):
                    raise Refused('%s: key_id is not digits' % name[:40])
                value, table, what, ok = second, sealed, 'sealed value', True
                key_ids.add(first)
        if name not in names:
            raise Refused('unknown secret name %r' % name[:40])
        if not ok:
            raise Refused('%s: malformed %s' % (name, what))
        if kind == 'SEALED':
            check_sealed(name, value, plain_len)
        if table.setdefault(name, value) != value:
            raise Refused('%s: two different %s values' % (name, what.split()[0]))
    for found in (sealed, public, fingerprint):
        if sorted(found) != sorted(names):
            raise Refused('need exactly %s, found %s' % (', '.join(names), ', '.join(sorted(found)) or 'none'))
    if len(key_ids) != 1:
        raise Refused('the sealed values name different key_ids')
    if len(recipients) != 1:
        raise Refused('need exactly one KEYGEN-RECIPIENT line, found %d' % len(recipients))
    key_id, key = recipients.pop()
    if key_ids != {key_id}:
        raise Refused('the sealed values and the recipient name different key_ids')
    if keys == 'kit-upload':  # the fingerprint is the SHA256 of exactly the 32 bytes the public line carries
        for name in names:
            raw = bytes.fromhex(public[name].split()[1])
            if fingerprint[name] != 'SHA256:' + base64.b64encode(hashlib.sha256(raw).digest()).decode('ascii').rstrip('='):
                raise Refused('%s: the fingerprint is not that of the public key' % name)
    return {'key_id': key_id, 'recipient': key, 'sealed': sealed, 'public': public, 'fingerprint': fingerprint}


def check_key(key: str) -> None:
    """A canonical base64 libsodium public key (32 bytes), or Refused."""
    try:
        raw = base64.b64decode(key, validate=True)
    except ValueError:
        raise Refused('recipient: not base64') from None
    if len(raw) != 32 or base64.b64encode(raw).decode('ascii') != key:
        raise Refused('recipient: not a canonical base64 of 32 bytes')


def check_run(fields: list, sha: str) -> dict:
    """Refuse unless the run is the reviewed keygen.yml, dispatched on main, finished with success, at `sha`."""
    if len(fields) != 6:
        raise Refused('the run record is not path, event, branch, conclusion, sha, actor')
    path, event, branch, conclusion, head, actor = fields
    for want, got, label in ((WORKFLOW_PATH, path.split('@')[0], 'workflow'), ('workflow_dispatch', event, 'event'),
                             ('main', branch, 'branch'), ('success', conclusion, 'conclusion'), (sha, head, 'head commit')):
        if want != got:
            raise Refused('the run is not the reviewed one: %s is %r, expected %r' % (label, got[:60], want))
    return {'actor': actor}


def gh(args: list, body: str = '') -> str:
    exe = shutil.which('gh')
    if not exe:
        raise SystemExit('gh not found')
    done = subprocess.run([exe, *args], input=body, capture_output=True, text=True, errors='replace')
    if done.returncode != 0:
        first = (done.stderr.strip().splitlines() or ['no message'])[0]
        raise SystemExit('gh %s failed: %s' % (args[0], first[:200]))
    return done.stdout


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--run', required=True, help='the id of the keygen run the coordinator just dispatched')
    ap.add_argument('--sha', required=True, help='the full commit sha of keygen.yml that was reviewed (the run must be at it)')
    ap.add_argument('--repo', default='mirrorstack-ai/fleet-disk')
    ap.add_argument('--env', default='release')
    ap.add_argument('--keys', choices=sorted(SETS), default='test',
                    help='the set the run made: test (SIGN_KEY, TAG_KEY, FLEET_READ) or kit-upload (KIT_UPLOAD_KEY)')
    ap.add_argument('--dry-run', action='store_true', help='verify and read the current key; PUT nothing')
    args = ap.parse_args(argv)
    if not REPO_RE.fullmatch(args.repo) or not ENV_RE.fullmatch(args.env):
        print('refused: --repo must be owner/name and --env a plain name', file=sys.stderr)
        return 2
    if not RUN_RE.fullmatch(args.run) or not SHA_RE.fullmatch(args.sha):
        print('refused: --run must be digits and --sha a full lowercase commit sha', file=sys.stderr)
        return 2
    base = 'repos/%s/environments/%s/secrets' % (args.repo, args.env)
    try:
        record = gh(['api', 'repos/%s/actions/runs/%s' % (args.repo, args.run), '--jq',
                     '[.path,.event,.head_branch,.conclusion,.head_sha,.actor.login]|@tsv']).rstrip('\n').split('\t')
        who = check_run(record, args.sha)
        found = parse(gh(['run', 'view', args.run, '--repo', args.repo, '--log']), args.keys)
        current = gh(['api', base + '/public-key', '--jq', '[.key_id,.key]|@tsv']).rstrip('\n').split('\t')
        if len(current) != 2 or not KEY_ID_RE.fullmatch(current[0]):
            raise Refused('the environment public key could not be read')
        if current[0] != found['key_id']:
            raise Refused('the sealed values are for key_id %s, the environment now has %s' % (found['key_id'], current[0]))
        if current[1] != found['recipient']:
            raise Refused('the run was sealed to a key that is not the environment\'s key (same key_id, different key)')
    except Refused as why:
        print('refused: %s' % why, file=sys.stderr)
        return 2
    key_id, values = found['key_id'], found['sealed']
    print('verified run %s of %s at %s (actor %s), sealed to the key_id %s of environment %s' % (
        args.run, WORKFLOW_PATH, args.sha[:12], who['actor'][:40], key_id, args.env))
    names = SETS[args.keys][0]
    for name in names:
        print('KEYGEN-PUBLIC %s %s' % (name, found['public'][name]))
        print('KEYGEN-FINGERPRINT %s %s' % (name, found['fingerprint'][name]))
    for name in names:
        if args.dry_run:
            print('would PUT %s/%s (key_id %s)' % (args.env, name, key_id))
            continue
        gh(['api', '-X', 'PUT', '%s/%s' % (base, name), '--input', '-'],
           json.dumps({'encrypted_value': values[name], 'key_id': key_id}))
        print('PUT %s/%s (key_id %s)' % (args.env, name, key_id))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
