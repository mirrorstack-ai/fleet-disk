"""CS3: .github/workflows/keygen.yml (test-grade keys made and sealed inside GitHub) and bin/fleet-keygen-put.py (moves
the already-sealed values into the Environment as secrets). Offline: the helper over a fake gh, the workflow's text rules
(no YAML parser in the stdlib), and, when a python with PyNaCl exists (this one, or FLEET_KEYGEN_PYTHON), the workflow's
own sealing code run for real over keys that ssh-keygen makes in a temp dir at test time. No key is committed. Plain
unittest, stdlib only."""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('fleet_keygen_put', ROOT / 'bin/fleet-keygen-put.py')
kp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kp)

WF = (ROOT / '.github/workflows/keygen.yml').read_text(encoding='utf-8')
NAMES = ('SIGN_KEY', 'TAG_KEY', 'FLEET_READ')
KEY_ID = '568250167242549743'
ENV_KEY = base64.b64encode(bytes(range(32))).decode()       # the environment's public key (public; any 32 bytes here)
OTHER_KEY = base64.b64encode(bytes(range(1, 33))).decode()  # someone else's
SHA = 'a' * 40
RUN = '\t'.join(['.github/workflows/keygen.yml', 'workflow_dispatch', 'main', 'success', SHA, 'the-coordinator'])
PUB_LINE = 'ssh-ed25519 ' + 'A' * 68
FP = 'SHA256:' + 'a' * 43
GH_PREFIX = 'keygen\tMake the keys, seal them and print only the sealed values\t2026-10-10T10:00:00.1234567Z '


def blob(seed: int, size: int = kp.SEALED_LEN) -> str:
    """A sealed-looking value: pseudo-random bytes of the sealed length (the helper cannot tell it from a real one)."""
    out = b''
    counter = 0
    while len(out) < size:
        out += subprocess.run([sys.executable, '-c', 'import hashlib,sys;sys.stdout.buffer.write(hashlib.sha512(sys.argv[1]'
                               '.encode()).digest())', '%d:%d' % (seed, counter)], capture_output=True).stdout
        counter += 1
    return base64.b64encode(out[:size]).decode('ascii')


def log(values: dict, key_id: str = KEY_ID, prefix: str = '', recipient: str = ENV_KEY) -> str:
    """What keygen.yml prints: the recipient, then per name a sealed value, a public line and a fingerprint."""
    lines = ['some other log line', '%sKEYGEN-RECIPIENT %s %s' % (prefix, key_id, recipient)]
    for n, v in values.items():
        lines += ['%sKEYGEN-SEALED %s %s %s' % (prefix, n, key_id, v), '%sKEYGEN-PUBLIC %s %s' % (prefix, n, PUB_LINE),
                  '%sKEYGEN-FINGERPRINT %s %s' % (prefix, n, FP)]
    return '\n'.join(lines + [''])


GOOD = {name: blob(i) for i, name in enumerate(NAMES)}


class Sealed(unittest.TestCase):
    """What the helper accepts: only a value shaped like a sealed box of the one length keygen.yml makes."""

    def refused(self, text: str, fragment: str = '') -> None:
        with self.assertRaises(kp.Refused) as why:
            kp.parse(text)
        self.assertIn(fragment, str(why.exception))

    def test_the_three_good_values_parse_with_their_key_id_and_recipient(self):
        got = kp.parse(log(GOOD))
        self.assertEqual((got['key_id'], got['recipient'], got['sealed']), (KEY_ID, ENV_KEY, GOOD))
        self.assertEqual(got['public'], {n: PUB_LINE for n in NAMES})
        self.assertEqual(got['fingerprint'], {n: FP for n in NAMES})

    def test_the_actions_log_prefix_and_a_repeated_identical_line_are_fine(self):
        got = kp.parse(log(GOOD, prefix=GH_PREFIX) + log(GOOD, prefix=GH_PREFIX))
        self.assertEqual((got['key_id'], got['sealed']), (KEY_ID, GOOD))

    def test_the_recipient_is_one_canonical_32_byte_key_with_the_same_key_id(self):
        text = log(GOOD)
        self.refused(text.replace('KEYGEN-RECIPIENT', 'x'), 'exactly one KEYGEN-RECIPIENT')
        self.refused(text + 'KEYGEN-RECIPIENT %s %s\n' % (KEY_ID, OTHER_KEY), 'exactly one KEYGEN-RECIPIENT')
        self.refused(text + 'KEYGEN-RECIPIENT %s\n' % KEY_ID, 'does not have 2 fields')
        self.refused(log(GOOD, recipient=base64.b64encode(b'x' * 31).decode()), 'recipient')
        self.refused(log(GOOD, recipient='not*base64'), 'recipient')
        self.refused(log(GOOD, recipient=ENV_KEY[:-2] + 'B='), 'recipient')    # non-canonical trailing bits
        self.refused(text.replace('KEYGEN-RECIPIENT %s' % KEY_ID, 'KEYGEN-RECIPIENT 77'), 'different key_ids')
        self.refused(text.replace('KEYGEN-RECIPIENT %s' % KEY_ID, 'KEYGEN-RECIPIENT 7x'), 'digits')

    def test_every_name_needs_one_well_formed_public_line_and_fingerprint(self):
        text = log(GOOD)
        self.refused(text.replace('KEYGEN-PUBLIC TAG_KEY', 'x'), 'need exactly')
        self.refused(text.replace('KEYGEN-FINGERPRINT FLEET_READ', 'x'), 'need exactly')
        self.refused(text.replace('ssh-ed25519 ' + 'A' * 68, 'ssh-rsa ' + 'A' * 68, 1), 'malformed public line')
        self.refused(text.replace(FP, 'SHA256:abc', 1), 'malformed fingerprint')
        self.refused(text + 'KEYGEN-PUBLIC SIGN_KEY ssh-ed25519 ' + 'B' * 68 + '\n', 'two different public')
        self.refused(text + 'KEYGEN-FINGERPRINT SIGN_KEY SHA256:' + 'b' * 43 + '\n', 'two different fingerprint')
        self.refused(text + 'KEYGEN-PUBLIC SIGN_KEY ssh-ed25519\n', '3 fields')

    def test_the_length_is_exactly_the_key_file_plus_the_sealed_box_overhead(self):
        self.assertEqual(kp.SEALED_LEN, 387 + 48)
        for size in (kp.SEALED_LEN - 1, kp.SEALED_LEN + 1, 32, 48, 1, kp.PLAIN_LEN):
            self.refused(log(dict(GOOD, SIGN_KEY=blob(9, size))), 'SIGN_KEY')

    def test_a_private_key_is_not_a_sealed_box_in_pem_or_base64(self):
        pem = b'-----BEGIN OPENSSH PRIVATE KEY-----\n' + b'A' * (kp.PLAIN_LEN - 71) + b'\n-----END OPENSSH PRIVATE KEY-----\n'
        self.assertEqual(len(pem), kp.PLAIN_LEN)
        self.refused(log(dict(GOOD, TAG_KEY=base64.b64encode(pem).decode())), 'TAG_KEY')
        padded = (pem + b'\n' * 48)  # the sealed length, but readable text
        self.assertEqual(len(padded), kp.SEALED_LEN)
        self.refused(log(dict(GOOD, TAG_KEY=base64.b64encode(padded).decode())), 'plaintext')
        self.refused(log(dict(GOOD, TAG_KEY=base64.b64encode(b'a' * kp.SEALED_LEN).decode())), 'plaintext')

    def test_a_key_hidden_inside_binary_bytes_is_still_refused(self):
        raw = base64.b64decode(GOOD['FLEET_READ'])
        hidden = b'-----BEGIN' + raw[10:]
        self.refused(log(dict(GOOD, FLEET_READ=base64.b64encode(hidden).decode())), 'plaintext')

    def test_bad_base64_is_refused(self):
        value = GOOD['SIGN_KEY']
        for bad in (value[:-1] + '-', value + '=', value[:-4], value[:5] + '*' + value[6:]):
            self.refused(log(dict(GOOD, SIGN_KEY=bad)), 'SIGN_KEY')
        urlsafe = base64.urlsafe_b64encode(base64.b64decode(value)).decode()
        if urlsafe != value:
            self.refused(log(dict(GOOD, SIGN_KEY=urlsafe)), 'SIGN_KEY')

    def test_the_set_must_be_exactly_the_three_names(self):
        self.refused(log({n: GOOD[n] for n in NAMES[:2]}), 'need exactly')
        self.refused(log(dict(GOOD, EXTRA=blob(7))), 'unknown secret name')
        self.refused('no sealed lines at all\n', 'found none')

    def test_one_key_id_and_digits_only(self):
        text = log(GOOD).replace('KEYGEN-SEALED TAG_KEY %s' % KEY_ID, 'KEYGEN-SEALED TAG_KEY 1234')
        self.refused(text, 'different key_ids')
        self.refused(log(GOOD, key_id='12ab'), 'digits')
        self.refused(log(GOOD, key_id='1' * 33), 'digits')

    def test_two_different_values_for_one_name_are_refused(self):
        self.refused(log(GOOD) + log(dict(GOOD, SIGN_KEY=blob(99))), 'two different')

    def test_a_malformed_marker_line_refuses_the_batch(self):
        self.refused(log(GOOD) + 'KEYGEN-SEALED SIGN_KEY ' + KEY_ID + '\n', '3 fields')
        self.refused(log(GOOD) + 'KEYGEN-SEALED SIGN_KEY ' + KEY_ID + ' a b\n', '3 fields')


FAKE_GH = """#!/bin/sh
echo "$@" >> "$FAKE_LOG"
case "$*" in
  *public-key*) printf '%s\\t%s\\n' "$FAKE_KEY_ID" "$FAKE_KEY" ;;
  *"-X PUT"*) cat >> "$FAKE_BODIES"; echo >> "$FAKE_BODIES"; [ -z "$FAKE_PUT_FAILS" ] || { echo "HTTP 422: boom" >&2; exit 1; } ;;
  *actions/runs*) printf '%s\\n' "$FAKE_RUN" ;;
  "run view"*) cat "$FAKE_RUNLOG" ;;
esac
"""
BASE = 'repos/mirrorstack-ai/fleet-disk/environments/release/secrets'
RUN_CALL = 'api repos/mirrorstack-ai/fleet-disk/actions/runs/4242 --jq [.path,.event,.head_branch,.conclusion,.head_sha,.actor.login]|@tsv'
LOG_CALL = 'run view 4242 --repo mirrorstack-ai/fleet-disk --log'
KEY_CALL = 'api %s/public-key --jq [.key_id,.key]|@tsv' % BASE
PUT_CALLS = ['api -X PUT %s/%s --input -' % (BASE, n) for n in NAMES]


class Put(unittest.TestCase):
    """The helper end to end over a fake `gh` on PATH."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='fleet-keygen-put-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        gh = self.tmp / 'gh'
        gh.write_text(FAKE_GH)
        gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
        self.calls, self.bodies = self.tmp / 'calls', self.tmp / 'bodies'
        self.calls.write_text('')
        self.bodies.write_text('')
        self.logfile = self.tmp / 'run.log'
        self.logfile.write_text(log(GOOD, prefix=GH_PREFIX))
        env = {'PATH': str(self.tmp) + os.pathsep + os.environ['PATH'], 'FAKE_LOG': str(self.calls),
               'FAKE_BODIES': str(self.bodies), 'FAKE_KEY_ID': KEY_ID, 'FAKE_KEY': ENV_KEY, 'FAKE_RUN': RUN,
               'FAKE_RUNLOG': str(self.logfile)}
        patch = mock.patch.dict(os.environ, env)
        patch.start()
        self.addCleanup(patch.stop)

    def run_main(self, *argv: str) -> tuple:
        out, err = self.tmp / 'out', self.tmp / 'err'
        argv = argv or ('--run', '4242', '--sha', SHA)
        with open(out, 'w') as o, open(err, 'w') as e, mock.patch.object(sys, 'stdout', o), mock.patch.object(sys, 'stderr', e):
            try:
                code = kp.main(list(argv))
            except SystemExit as stop:
                code = stop.code
        return code, out.read_text(), err.read_text()

    def gh_calls(self) -> list:
        return self.calls.read_text().splitlines()

    def test_it_puts_the_three_secrets_with_the_body_on_stdin_and_prints_no_sealed_value(self):
        code, out, err = self.run_main()
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(self.gh_calls(), [RUN_CALL, LOG_CALL, KEY_CALL] + PUT_CALLS)
        bodies = [json.loads(b) for b in self.bodies.read_text().split('\n') if b]
        self.assertEqual(bodies, [{'encrypted_value': GOOD[n], 'key_id': KEY_ID} for n in NAMES])
        for value in GOOD.values():
            self.assertNotIn(value, out + err + '\n'.join(self.gh_calls()))
        self.assertEqual(out.count('PUT release/'), 3)

    def test_it_prints_the_verified_public_lines_and_fingerprints(self):
        code, out, _ = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn('verified run 4242 of .github/workflows/keygen.yml at %s' % SHA[:12], out)
        for n in NAMES:
            self.assertIn('KEYGEN-PUBLIC %s %s\n' % (n, PUB_LINE), out)
            self.assertIn('KEYGEN-FINGERPRINT %s %s\n' % (n, FP), out)

    def test_dry_run_verifies_and_reads_the_key_and_puts_nothing(self):
        code, out, _ = self.run_main('--run', '4242', '--sha', SHA, '--dry-run')
        self.assertEqual(code, 0)
        self.assertEqual(self.gh_calls(), [RUN_CALL, LOG_CALL, KEY_CALL])
        self.assertEqual(self.bodies.read_text(), '')
        self.assertEqual(out.count('would PUT'), 3)
        self.assertEqual(out.count('KEYGEN-PUBLIC'), 3)

    def test_a_refused_batch_puts_nothing_and_never_reads_the_environment_key(self):
        self.logfile.write_text(log(dict(GOOD, TAG_KEY=blob(5, kp.SEALED_LEN - 1))))
        code, out, err = self.run_main()
        self.assertEqual(code, 2)
        self.assertIn('refused', err)
        self.assertEqual(self.gh_calls(), [RUN_CALL, LOG_CALL])

    def test_a_run_sealed_to_someone_elses_key_is_refused_even_with_the_real_key_id(self):
        # the hostile dispatch: free-input public_key = the attacker's, key_id = the environment's. Every sealed value is
        # well formed, so only the recipient comparison stops it.
        self.logfile.write_text(log(GOOD, recipient=OTHER_KEY))
        code, out, err = self.run_main()
        self.assertEqual(code, 2)
        self.assertIn('not the environment', err)
        self.assertEqual(self.gh_calls(), [RUN_CALL, LOG_CALL, KEY_CALL])
        self.assertEqual((self.bodies.read_text(), out), ('', ''))   # no PUT, and no public line is handed out either

    def test_a_rotated_environment_key_is_refused_before_any_put(self):
        with mock.patch.dict(os.environ, {'FAKE_KEY_ID': '999'}):
            code, _, err = self.run_main()
        self.assertEqual(code, 2)
        self.assertIn('now has 999', err)
        self.assertEqual(len(self.gh_calls()), 3)
        self.assertEqual(self.bodies.read_text(), '')

    def test_an_unreadable_environment_key_is_refused(self):
        with mock.patch.dict(os.environ, {'FAKE_KEY_ID': 'x'}):
            code, _, err = self.run_main()
        self.assertEqual(code, 2)
        self.assertIn('could not be read', err)

    def test_a_run_that_is_not_the_reviewed_keygen_dispatch_is_refused_before_its_log_is_read(self):
        good = RUN.split('\t')
        for index, bad in ((0, '.github/workflows/test.yml'), (1, 'push'), (2, 'feat/x'), (3, 'failure'), (3, ''),
                           (4, 'b' * 40)):
            run = good[:]
            run[index] = bad
            with mock.patch.dict(os.environ, {'FAKE_RUN': '\t'.join(run)}):
                code, _, err = self.run_main()
            self.assertEqual(code, 2, (index, bad))
            self.assertIn('not the reviewed one', err)
        with mock.patch.dict(os.environ, {'FAKE_RUN': '\t'.join(good[:5])}):
            self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(set(self.gh_calls()), {RUN_CALL})

    def test_the_path_may_carry_the_ref_suffix_github_adds_to_some_runs(self):
        run = RUN.replace('keygen.yml', 'keygen.yml@refs/heads/main')
        with mock.patch.dict(os.environ, {'FAKE_RUN': run}):
            self.assertEqual(self.run_main('--run', '4242', '--sha', SHA, '--dry-run')[0], 0)

    def test_run_and_sha_are_required_and_validated_and_there_is_no_way_to_pass_a_log(self):
        for bad in (['--run', 'abc', '--sha', SHA], ['--run', '1 2', '--sha', SHA], ['--run', '4242', '--sha', 'a' * 39],
                    ['--run', '4242', '--sha', 'A' * 40], ['--run', '4242', '--sha', 'main']):
            self.assertEqual(self.run_main(*bad)[0], 2, bad)
        for bad in (['--sha', SHA], ['--run', '4242'], [str(self.logfile), '--run', '4242', '--sha', SHA]):
            self.assertEqual(self.run_main(*bad)[0], 2, bad)    # argparse refuses
        self.assertEqual(self.gh_calls(), [])

    def test_a_failing_put_stops_with_the_first_error_line_only(self):
        with mock.patch.dict(os.environ, {'FAKE_PUT_FAILS': '1'}):
            code, out, err = self.run_main()
        self.assertEqual(code, 'gh api failed: HTTP 422: boom')
        self.assertEqual(len(self.gh_calls()), 4)

    def test_repo_and_env_are_validated(self):
        for bad in (['--repo', 'a b/c'], ['--repo', 'nope'], ['--repo', 'x/y;rm'], ['--env', '../x'], ['--env', 'a b']):
            code, _, err = self.run_main('--run', '4242', '--sha', SHA, *bad)
            self.assertEqual(code, 2, bad)
        self.assertEqual(self.gh_calls(), [])

    def test_it_reads_a_log_that_is_not_utf8_without_crashing(self):
        self.logfile.write_bytes(b'\xff\xfe junk\n' + log(GOOD).encode())
        self.assertEqual(self.run_main()[0], 0)


def runs(text: str) -> list:
    """Every `run:` body of the workflow as one string each (block scalars and one-liners)."""
    out, lines, i = [], text.splitlines(), 0
    while i < len(lines):
        m = re.match(r'^(\s*)(?:- )?run: (.*)$', lines[i])
        if not m:
            i += 1
            continue
        indent, rest = len(m.group(1)), m.group(2)
        if rest in ('|', '>', '|-'):
            body, i = [], i + 1
            while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
                body.append(lines[i])
                i += 1
            width = min((len(b) - len(b.lstrip()) for b in body if b.strip()), default=0)
            out.append('\n'.join(b[width:] for b in body))
        else:
            out.append(rest)
            i += 1
    return out


def python_part(script: str) -> str:
    m = re.search(r"<<'PY'\n(.*?)\nPY$", script, re.S | re.M)
    return m.group(1) if m else ''


class Workflow(unittest.TestCase):
    """Text rules of keygen.yml: the safety properties that matter."""

    RUNS = runs(WF)
    SCRIPT = next(r for r in RUNS if "<<'PY'" in r)
    PY = python_part(SCRIPT)
    SHELL = SCRIPT.replace(PY, '')

    def test_it_is_a_test_grade_dispatch_only_job_with_no_token_environment_or_action(self):
        self.assertIn('TEST-GRADE', WF.split('\nname:')[0])
        self.assertIn('NEVER used for R', WF.split('\nname:')[0])
        self.assertRegex(WF, r'(?m)^on:\n  workflow_dispatch:\n    inputs:\n      public_key:\n(?:.*\n)*?      key_id:\n')
        self.assertEqual(re.findall(r'(?m)^(?:on|  \w+):', WF)[:2], ['on:', '  workflow_dispatch:'])
        self.assertNotRegex(WF, r'(?m)^\s+(pull_request|push|schedule|workflow_run)')
        self.assertRegex(WF, r'(?m)^permissions: \{\}$')
        self.assertEqual(re.findall(r'runs-on: (\S+)', WF), ['ubuntu-24.04'])
        self.assertNotIn('self-hosted', WF)
        self.assertNotRegex(WF, r'(?m)^\s*(- )?uses:')
        self.assertNotRegex(WF, r'(?m)^\s*environment:')
        self.assertNotRegex(WF, r'\$\{\{\s*secrets')
        self.assertNotRegex(WF, r'(?m)^\s+(contents|id-token|actions|packages): ')
        self.assertIn("if: github.ref == 'refs/heads/main'", WF)

    def test_inputs_reach_the_shell_only_through_env(self):
        self.assertTrue(self.RUNS)
        for body in self.RUNS:
            self.assertNotIn('${{', body)
        self.assertEqual(len(re.findall(r'(?m)^\s+(?:PUBLIC_KEY|KEY_ID): \$\{\{ inputs\.\w+ \}\}$', WF)), 2)
        self.assertEqual(sorted(re.findall(r'\$\{\{ ([^}]+) \}\}', WF)), ['inputs.key_id', 'inputs.public_key'])
        self.assertEqual(WF.count('${{'), 2)

    def test_pynacl_comes_from_pinned_hashes_only(self):
        script = self.RUNS[0]
        self.assertIn('--require-hashes', script)
        self.assertIn('--only-binary=:all:', script)
        self.assertIn('--no-deps', script)
        reqs = re.search(r"<<'REQ'\n(.*?)\nREQ$", script, re.S | re.M).group(1)
        names = re.findall(r'(?m)^(\S+)==\S+ \\$', reqs)
        self.assertEqual(names, ['pynacl', 'cffi', 'pycparser'])
        for block in re.split(r'(?m)^(?=\S)', reqs):
            if block.strip():
                self.assertTrue(re.findall(r'--hash=sha256:[0-9a-f]{64}', block), block)
        self.assertEqual(len(re.findall(r'--hash=', reqs)), len(re.findall(r'--hash=sha256:[0-9a-f]{64}', reqs)))
        self.assertNotRegex(script, r'pip install(?!.*--require-hashes)')

    def test_no_step_prints_logs_uploads_or_exports_a_private_key(self):
        for banned in ('set -x', 'bash -x', 'xtrace', 'sh -x', '::add-mask', '::debug', 'GITHUB_ENV', 'GITHUB_OUTPUT',
                       'GITHUB_STEP_SUMMARY', 'upload-artifact', 'ACTIONS_STEP_DEBUG', 'ACTIONS_RUNNER_DEBUG', 'gh ', 'curl',
                       'wget', 'git ', 'ssh-add', 'ssh-agent'):
            self.assertNotIn(banned, WF.split('\nname:')[1], banned)
        for kind in ('SEALED', 'PUBLIC', 'FINGERPRINT', 'RECIPIENT'):
            self.assertNotIn('KEYGEN-' + kind, WF)  # the helper's markers are never in the source the log echoes

    def test_the_shell_never_prints_or_copies_the_key_directory(self):
        printers = re.compile(r'(?<![\w-])(echo|printf|cat|tee|base64|xxd|hexdump|od|strings|xargs|cp|mv|dd|head|tail|sed|awk)\b')
        touch = re.compile(r'KEYDIR|SIGN_KEY|TAG_KEY|FLEET_READ|\$\{?name\b')
        for script in self.RUNS:
            for line in script.replace(self.PY, '').splitlines():
                if printers.search(line):
                    self.assertFalse(touch.search(line), line)
        allowed = [r'KEYDIR=\$\(mktemp -d /dev/shm/keygen\.XXXXXX\)$', r'export KEYDIR$',
                   r"trap 'find \"\$KEYDIR\" -type f -exec shred -u \{\} \+; rm -rf \"\$KEYDIR\"' EXIT$",
                   r'test "\$\(stat -f -c %T "\$KEYDIR"\)" = tmpfs$',
                   r"ssh-keygen -q -t ed25519 -N '' -C '' -f \"\$KEYDIR/\$name\"$"]
        for line in self.SHELL.splitlines():
            if 'KEYDIR' in line:
                self.assertTrue(any(re.fullmatch(a, line.strip()) for a in allowed), line)

    def test_the_keys_are_made_in_tmpfs_with_no_passphrase_or_comment_and_shredded(self):
        self.assertIn('umask 077', self.SHELL)
        self.assertIn('/dev/shm/keygen.XXXXXX', self.SHELL)
        self.assertIn('= tmpfs', self.SHELL)
        self.assertIn('for name in SIGN_KEY TAG_KEY FLEET_READ; do', self.SHELL)
        self.assertEqual(self.SHELL.count("ssh-keygen -q -t ed25519 -N '' -C ''"), 1)
        self.assertIn('shred -u', self.SHELL)
        self.assertRegex(WF, r"(?m)^        if: always\(\)\n        run: find /dev/shm .*shred -u")

    def test_the_python_prints_once_and_only_public_and_sealed_values(self):
        self.assertTrue(self.PY)
        compile(self.PY, 'keygen.yml', 'exec')
        self.assertEqual(re.findall(r'(?m)^\s*print\((.*)\)$', self.PY), ["'\\n'.join(lines)"])
        self.assertNotIn('sys.stdout', self.PY)
        self.assertNotIn('sys.stderr', self.PY)
        self.assertEqual(re.findall(r"(?m)^\s*emit\('RECIPIENT', (.*?)\)(?:  #.*)?$", self.PY),
                         ["key_id, base64.b64encode(public).decode('ascii')"])
        emits = re.findall(r"emit\('(\w+)', name, (.*)\)$", self.PY, re.M)
        self.assertEqual([k for k, _ in emits], ['SEALED', 'PUBLIC', 'FINGERPRINT'])
        self.assertEqual(emits[0][1], "'%s %s' % (key_id, base64.b64encode(sealed).decode('ascii'))")
        for kind, expr in emits:
            self.assertNotIn('secret', expr)
        for line in self.PY.splitlines():
            if re.search(r'\bsecret\b', line):
                self.assertTrue(re.search(r'secret = handle\.read\(\)|len\(secret\)|secret\.startswith|box\.encrypt\(secret\)', line), line)
        exits = re.findall(r'(?m)^.*sys\.exit\(.*$', self.PY)
        self.assertEqual(len(exits), 5)
        for line in exits:  # a refusal says a fixed sentence, at most with the key's NAME, never a value
            self.assertRegex(line, r"^\s*sys\.exit\('(?:[^'%]|%s)*'(?: % name)?\)$")
        self.assertEqual(re.findall(r"sys\.exit\('([^']*)'", self.PY)[0:2], ['refused: public_key is not base64',
                                                                          'refused: public_key is not 32 bytes'])

    def test_the_secrets_are_sealed_to_exactly_the_key_that_was_checked_and_printed(self):
        # SealingRuns checks this by decrypting but needs PyNaCl, which neither required command nor test.yml has; these
        # lines are what a wrong-key seal (a zero key, a reversed key) would have to change.
        self.assertEqual(self.PY.count('PublicKey('), 1)
        self.assertIn("public = base64.b64decode(os.environ['PUBLIC_KEY'], validate=True)", self.PY)
        self.assertEqual(self.PY.count('box = SealedBox(PublicKey(public))\n'), 1)
        self.assertEqual(self.PY.count('SealedBox('), 1)
        self.assertEqual(self.PY.count('sealed = box.encrypt(secret)\n'), 1)
        self.assertEqual(self.PY.count('base64.b64encode(sealed)'), 1)
        self.assertEqual(len(re.findall(r'\bpublic\b *=(?!=)', self.PY)), 1)  # `public` is never reassigned before it seals

    def test_the_plain_length_matches_the_helper_and_what_ssh_keygen_makes(self):
        self.assertEqual(int(re.search(r'PLAIN_LEN = (\d+)', self.PY).group(1)), kp.PLAIN_LEN)
        if not shutil.which('ssh-keygen'):
            self.skipTest('ssh-keygen missing')
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', d + '/k'], check=True)
            self.assertEqual(len((Path(d) / 'k').read_bytes()), kp.PLAIN_LEN)


def nacl_python() -> str:
    """A python that can import PyNaCl: this one, or FLEET_KEYGEN_PYTHON; '' when neither can."""
    for exe in (sys.executable, os.environ.get('FLEET_KEYGEN_PYTHON', '')):
        if exe and subprocess.run([exe, '-c', 'import nacl.public'], capture_output=True).returncode == 0:
            return exe
    return ''


@unittest.skipUnless(nacl_python() and shutil.which('ssh-keygen'), 'needs PyNaCl (or FLEET_KEYGEN_PYTHON) and ssh-keygen')
class SealingRuns(unittest.TestCase):
    """The workflow's own python, extracted and run over keys made in a temp dir, checked by decrypting."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='fleet-keygen-run-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.py = nacl_python()
        for name in NAMES:
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', str(self.tmp / name)], check=True)
        probe = subprocess.run([self.py, '-c', 'import nacl.public as p;k=p.PrivateKey.generate();'
                                'print(k.encode().hex(), bytes(k.public_key).hex())'], capture_output=True, text=True, check=True)
        self.sk, self.pk = [bytes.fromhex(x) for x in probe.stdout.split()]
        (self.tmp / 'seal.py').write_text(Workflow.PY)

    def run_seal(self, public: bytes = b'', key_id: str = KEY_ID):
        env = {'PATH': os.environ['PATH'], 'KEYDIR': str(self.tmp), 'KEY_ID': key_id,
               'PUBLIC_KEY': base64.b64encode(public or self.pk).decode()}
        return subprocess.run([self.py, str(self.tmp / 'seal.py')], env=env, capture_output=True, text=True)

    def test_every_sealed_value_opens_to_the_key_file_and_nothing_else_is_printed(self):
        done = self.run_seal()
        self.assertEqual((done.returncode, done.stderr), (0, ''))
        found = kp.parse(done.stdout)
        key_id, sealed = found['key_id'], found['sealed']
        self.assertEqual((key_id, found['recipient']), (KEY_ID, base64.b64encode(self.pk).decode()))
        opener = subprocess.run([self.py, '-c', 'import sys,base64;from nacl.public import PrivateKey,SealedBox;'
                                 'sk=PrivateKey(bytes.fromhex(sys.argv[1]));print(SealedBox(sk).decrypt(base64.b64decode(sys.argv[2])).hex())',
                                 self.sk.hex(), sealed['SIGN_KEY']], capture_output=True, text=True, check=True)
        self.assertEqual(bytes.fromhex(opener.stdout.strip()), (self.tmp / 'SIGN_KEY').read_bytes())
        for name in NAMES:
            plain = (self.tmp / name).read_bytes()
            body = plain.decode().splitlines()[1:-1]
            self.assertNotIn('PRIVATE KEY', done.stdout)
            for chunk in body:
                self.assertNotIn(chunk[:40], done.stdout)
            self.assertNotIn(base64.b64encode(plain).decode(), done.stdout)
        kinds = [line.split()[0] for line in done.stdout.splitlines()]
        self.assertEqual(kinds, ['KEYGEN-RECIPIENT'] + ['KEYGEN-SEALED', 'KEYGEN-PUBLIC', 'KEYGEN-FINGERPRINT'] * 3)
        for name in NAMES:
            public = (self.tmp / (name + '.pub')).read_text().split()[:2]
            self.assertIn('KEYGEN-PUBLIC %s %s' % (name, ' '.join(public)), done.stdout)
            want = subprocess.run(['ssh-keygen', '-lf', str(self.tmp / (name + '.pub'))], capture_output=True, text=True).stdout.split()[1]
            self.assertIn('KEYGEN-FINGERPRINT %s %s' % (name, want), done.stdout)

    def test_bad_inputs_print_nothing_and_name_no_value(self):
        for public, key_id in ((b'short', KEY_ID), (self.pk, 'abc'), (self.pk, '')):
            done = self.run_seal(public, key_id)
            self.assertNotEqual(done.returncode, 0)
            self.assertEqual(done.stdout, '')
            self.assertNotIn(KEY_ID, done.stderr)
        env = {'PATH': os.environ['PATH'], 'KEYDIR': str(self.tmp), 'KEY_ID': KEY_ID, 'PUBLIC_KEY': 'not*base64'}
        done = subprocess.run([self.py, str(self.tmp / 'seal.py')], env=env, capture_output=True, text=True)
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, '')

    def test_a_key_file_of_the_wrong_shape_prints_nothing(self):
        (self.tmp / 'TAG_KEY').write_bytes(b'x' * kp.PLAIN_LEN)
        done = self.run_seal()
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, '')
        self.assertIn('TAG_KEY', done.stderr)


if __name__ == '__main__':
    unittest.main()
