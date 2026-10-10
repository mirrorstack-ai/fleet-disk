"""K6: .github/workflows/kit-deploy.yml and bin/fleet-kit-check.py. Offline: the script's judges over crafted input, and the
whole staging replay and production probe over HTTP against a stand-in kit Worker written here from the spec (it speaks the
Worker's wire contract: kit/README.md, "The Worker front" and "Admin calls"), with a few deliberately wrong variants that
each must be refused. The workflow's rules are text checks (no YAML parser in the stdlib). No network beyond 127.0.0.1;
the Ed25519 signatures need an `openssl` 3.x binary (the tests that sign skip without one). Plain unittest."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import urllib.error
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('fleet_kit_check', ROOT / 'bin/fleet-kit-check.py')
kc = importlib.util.module_from_spec(_spec)
sys.modules['fleet_kit_check'] = kc
_spec.loader.exec_module(kc)

WF = (ROOT / '.github/workflows/kit-deploy.yml').read_text(encoding='utf-8')
CODE = '\n'.join(l for l in WF.splitlines() if not l.lstrip().startswith('#'))     # the workflow without its comments


def ed25519_openssl() -> bool:
    try:
        with tempfile.TemporaryDirectory() as d:
            pem = Path(d, 'k.pem')
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(pem)], check=True, capture_output=True)
            Path(d, 'm').write_bytes(b'x')
            subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', str(pem), '-rawin', '-in', str(Path(d, 'm')),
                            '-out', str(Path(d, 's'))], check=True, capture_output=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


HAVE_ED25519 = ed25519_openssl()
CODE_RE = re.compile(r'^FleetInvite ([23456789CFGHJMPQRVWX]{10})$')
TARGET_RE = re.compile(r'^/v1/kit/([0-9]{1,9})/(bundle\.tar|gateway\.json|gateway\.json\.sig)$')
ADMIN_RE = re.compile(r'^KitAdmin (upload|gateway) ([1-9][0-9]{12,15}) ([0-9a-f]{128})$')
SPKI_PREFIX = bytes.fromhex('302a300506032b6570032100')


class FakeKit:
    """The kit Worker and its Gate as the spec describes them, in memory. Flags make it wrong in one named way."""

    def __init__(self, pubs: dict[str, str], **flags):
        self.pubs = pubs
        self.flags = flags
        self.lock = threading.Lock()
        self.files: dict[int, bytes] = {}
        self.gateway: dict[int, tuple[bytes, bytes]] = {}
        self.active_gateway: int | None = None
        self.invites: dict[str, dict] = {}
        self.floor = 0
        self.last_ts = {'upload': 0, 'gateway': 0}
        self.fails = 0
        self.per_source = flags.get('per_source', 30)
        self.gate_failures = 0

    def now(self) -> int:
        return int(time.time() * 1000)

    def verify(self, role: str, ts: str, method: str, path: str, digest: str, sig_hex: str) -> bool:
        with tempfile.TemporaryDirectory() as d:
            pub = Path(d, 'p.der')
            pub.write_bytes(SPKI_PREFIX + bytes.fromhex(self.pubs[role]))
            Path(d, 'm').write_bytes(('kit-admin-v1\n%s\n%s\n%s\n%s\n%s' % (role, ts, method, path, digest)).encode())
            Path(d, 's').write_bytes(bytes.fromhex(sig_hex))
            r = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(pub), '-keyform', 'DER', '-rawin',
                                '-in', str(Path(d, 'm')), '-sigfile', str(Path(d, 's'))], capture_output=True)
            return r.returncode == 0


def make_handler(kit: FakeKit):
    class H(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'

        def setup(self):
            super().setup()
            # a small send buffer: a client that hangs up must be noticed mid-send, not after the kernel took the whole file
            self.request.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16384)

        def log_message(self, *a):
            pass

        def send_fixed(self, status, body, ctype='text/plain'):
            self.send_response(status)
            self.send_header('Content-Type', ctype)
            self.send_header('Cache-Control', 'no-store, no-transform')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('CF-RAY', os.urandom(8).hex())
            if kit.flags.get('gzip_404') and status == 404 and 'gzip' in (self.headers.get('Accept-Encoding') or ''):
                self.send_header('Content-Encoding', 'gzip')
            self.end_headers()
            self.wfile.write(body)

        def nf(self):
            self.send_fixed(404, b'not found\n')

        def send_json(self, status, doc):
            self.send_fixed(status, json.dumps(doc).encode(), 'application/json')

        def handle_any(self):
            path = self.path
            if path.startswith('/_k/'):
                return self.admin(path)
            m = TARGET_RE.match(path)
            auths = self.headers.get_all('Authorization') or []
            c = CODE_RE.match(auths[0]) if len(auths) == 1 else None
            if self.command != 'GET' or not m or not c:
                if kit.flags.get('front_spends') and self.command != 'GET':
                    with kit.lock:
                        kit.fails += 1
                return self.nf()
            if self.command == 'GET' and kit.flags.get('range_206') and self.headers.get('Range'):
                self.send_response(206)
                self.end_headers()
                return
            serial, name = int(m.group(1)), m.group(2)
            with kit.lock:
                if kit.fails >= kit.per_source:
                    return self.send_fixed(429, b'try later\n')
                inv = next((i for i in kit.invites.values() if i['code'] == c.group(1)), None)
                data = None
                if name == 'bundle.tar':
                    data = kit.files.get(serial)
                elif kit.active_gateway is not None:
                    g = kit.gateway[kit.active_gateway]
                    data = g[0] if name == 'gateway.json' else g[1]
                ok = (inv is not None and not inv['revoked'] and inv['lo'] <= serial <= inv['hi'] and serial >= kit.floor
                      and inv['exp'] > kit.now() and (name != 'bundle.tar' or inv['used'] < inv['cap']) and data is not None)
                if not ok:
                    kit.fails += 1
                    kit.gate_failures += 1
                    if kit.flags.get('leak_revoked') and inv is not None and inv['revoked']:
                        return self.send_fixed(404, b'revoked\n')
                    return self.nf()
                if name == 'bundle.tar':
                    inv['used'] += 1
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Cache-Control', 'no-store, no-transform')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            try:
                for i in range(0, len(data), 65536):
                    self.wfile.write(data[i:i + 65536])
            except OSError:
                if name == 'bundle.tar' and not kit.flags.get('no_release'):
                    with kit.lock:
                        if inv['refunds'] < 3:
                            inv['used'] -= 1
                            inv['refunds'] += 1

        def admin(self, path):
            a = ADMIN_RE.match(self.headers.get('Authorization') or '')
            routes = [('PUT', r'^/_k/file/([0-9]{1,9})/bundle\.tar$', 'upload', True), ('PUT', r'^/_k/gateway/([0-9]{1,9})$', 'upload', False),
                      ('PUT', r'^/_k/floor$', 'upload', False), ('POST', r'^/_k/invite$', 'gateway', False),
                      ('DELETE', r'^/_k/invite/([A-Za-z0-9_-]{8,64})$', 'gateway', False), ('GET', r'^/_k/state$', 'gateway', False)]
            route = next(((r, m) for r in routes if r[0] == self.command and (m := re.match(r[1], path))), None)
            if not a or not route:
                return self.nf()
            role, ts, sig = a.groups()
            if abs(kit.now() - int(ts)) > 300000 or not kit.pubs.get(role):
                return self.nf()
            length = int(self.headers.get('Content-Length') or 0)
            body = self.rfile.read(length) if length else b''
            digest = self.headers.get('X-Kit-Sha256') if route[0][3] else hashlib.sha256(body).hexdigest()
            if not digest or not kit.verify(role, ts, self.command, path, digest, sig):
                return self.nf()
            if role != route[0][2]:
                return self.send_json(403, {'ok': False, 'error': 'forbidden'})
            ts_i = int(ts)
            with kit.lock:
                if ts_i <= kit.last_ts[role]:
                    return self.send_json(409, {'ok': False, 'error': 'replay'})
                kit.last_ts[role] = ts_i
                return self.admin_op(route[1], path, body, digest)

        def admin_op(self, m, path, body, digest):
            j = lambda: json.loads(body) if body else {}  # noqa: E731
            if path.startswith('/_k/file/'):
                serial = int(m.group(1))
                held = kit.files.get(serial)
                if held is not None and hashlib.sha256(held).hexdigest() != digest:
                    return self.send_json(409, {'ok': False, 'error': 'conflict'})
                if hashlib.sha256(body).hexdigest() != digest:
                    return self.send_json(422, {'ok': False, 'error': 'checksum'})
                kit.files[serial] = body
                return self.send_json(200, {'ok': True, 'sha256': digest, 'size': len(body)})
            if path.startswith('/_k/gateway/'):
                gser, d = int(m.group(1)), j()
                jb, sb = base64.b64decode(d['json']), base64.b64decode(d['sig'])
                if kit.active_gateway is not None and gser < kit.active_gateway:
                    return self.send_json(409, {'ok': False, 'error': 'rollback'})
                kit.gateway[gser] = (jb, sb)
                kit.active_gateway = gser
                h = lambda b: {'sha256': hashlib.sha256(b).hexdigest(), 'size': len(b)}  # noqa: E731
                return self.send_json(200, {'ok': True, 'json': h(jb), 'sig': h(sb)})
            if path == '/_k/floor':
                kit.floor = j()['floor']
                return self.send_json(200, {'ok': True})
            if path == '/_k/state':
                return self.send_json(200, {'ok': True, 'now': kit.now()})
            if self.command == 'POST':
                d = j()
                now = kit.now()
                if d['exp'] - now > 72 * 3600 * 1000 + 300000:
                    return self.send_json(422, {'ok': False, 'error': 'ceiling-life'})
                if d['cap'] > 10:
                    return self.send_json(422, {'ok': False, 'error': 'ceiling-downloads'})
                if sum(1 for i in kit.invites.values() if not i['revoked'] and i['exp'] > now) >= 16:
                    return self.send_json(422, {'ok': False, 'error': 'ceiling-open'})
                kit.invites[d['ref']] = dict(d, used=0, refunds=0, revoked=False)
                return self.send_json(200, {'ok': True, 'created': True})
            kit.invites.get(m.group(1), {}).update(revoked=True)
            return self.send_json(200, {'ok': True})

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = handle_any

    return H


class Served:
    def __init__(self, kit: FakeKit):
        self.kit = kit
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(kit))
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return 'http://127.0.0.1:%d' % self.server.server_address[1]

    def __exit__(self, *a):
        self.server.shutdown()
        self.server.server_close()


def read_pub(gate_dir: str, role: str) -> str:
    der = subprocess.run(['openssl', 'pkey', '-in', str(Path(gate_dir, role + '.pem')), '-pubout', '-outform', 'DER'],
                         check=True, capture_output=True).stdout
    return der[-32:].hex()


class Judges(unittest.TestCase):
    def test_console_scan_flags_calls_and_skips_tests_and_stand_ins(self):
        with tempfile.TemporaryDirectory() as d:
            for name, text in (('worker.js', 'export default {}; // no console calls here\n'),
                               ('gate.js', 'const x = 1;\nconsole.log(x)\n'),
                               ('a.mjs', 'globalThis.console ["warn"]("x")\n'),
                               ('gate.test.js', 'console.log(1)\n'), ('helpers.test-util.js', 'console.log(1)\n'),
                               ('run-tests.js', 'console.log(1)\n'), ('fake-storage.js', 'console.log(1)\n'),
                               ('README.md', 'console.log\n')):
                Path(d, name).write_text(text)
            self.assertEqual(kc.scan_console(d), ['a.mjs:1', 'gate.js:2'])
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'worker.js').write_text('console.error(1)\n')
            Path(d, 'gate.js').write_text('const console = {}\nlogger.console_ok = 1\n')
            self.assertEqual(kc.scan_console(d), ['worker.js:1'])
        with tempfile.TemporaryDirectory() as d:  # a scan over nothing is not a pass
            Path(d, 'only.test.js').write_text('x')
            with self.assertRaises(kc.Refused):
                kc.scan_console(d)

    def test_console_scan_is_recursive_and_catches_aliases_splits_and_other_suffixes(self):
        cases = (('lib/a.js', 'console.log(c)\n'), ('worker.ts', 'console.log(1)\n'), ('x.cjs', 'console.log(1)\n'),
                 ('alias.js', 'const c = console; c.log(1)\n'), ('opt.js', 'console?.log(2)\n'),
                 ('split.js', 'const a = 1\nconsole\n.log(3)\n'), ('destr.js', 'const {error} = console\n'),
                 ('glob.js', 'globalThis.console.log(1)\n'), ('deep/er/m.mts', 'console.warn(1)\n'))
        for name, text in cases:
            with tempfile.TemporaryDirectory() as d:
                Path(d, 'worker.js').write_text('export default {}\n')
                Path(d, name).parent.mkdir(parents=True, exist_ok=True)
                Path(d, name).write_text(text)
                self.assertEqual([h.split(':')[0] for h in kc.scan_console(d)], [name], name)
        with tempfile.TemporaryDirectory() as d:     # node_modules is not Worker source; a nested test file is skipped
            Path(d, 'worker.js').write_text('export default {}\n')
            Path(d, 'node_modules/x').mkdir(parents=True)
            Path(d, 'node_modules/x/i.js').write_text('console.log(1)\n')
            Path(d, 'lib').mkdir()
            Path(d, 'lib/t.test.js').write_text('console.log(1)\n')
            self.assertEqual(kc.scan_console(d), [])

    def test_console_scan_refuses_a_shipped_file_that_imports_a_skipped_one(self):
        for spec in ("import './helpers.test-util.js'", "import {x} from './helpers.test-util'", "await import('./fake-storage.js')",
                     "const f = require('./lib/fake-storage')"):
            with tempfile.TemporaryDirectory() as d:
                Path(d, 'gate.js').write_text(spec + '\n')
                Path(d, 'helpers.test-util.js').write_text('console.log(1)\n')
                Path(d, 'fake-storage.js').write_text('console.log(1)\n')
                with self.assertRaises(kc.Refused, msg=spec):
                    kc.scan_console(d)

    def test_the_real_kit_folder_has_no_console_call(self):
        self.assertEqual(kc.scan_console(str(ROOT / 'kit')), [])

    def test_secret_names(self):
        self.assertEqual(kc.secret_names('[{"name": "INVITE_PEPPER", "type": "secret_text"}]'), {'INVITE_PEPPER'})
        self.assertEqual(kc.secret_names('Update available\n[]\n'), set())
        for bad in ('', 'no json', '[1]', '{"name": "X"}', '[{"x": 1}]', '[{"name": "X"'):
            with self.assertRaises(kc.Refused):
                kc.secret_names(bad)

    GOOD = {'observability': {'enabled': False}, 'logpush': False, 'tail_consumers': []}
    SUB = {'enabled': True, 'previews_enabled': False}

    def test_good_settings_pass(self):
        self.assertEqual(kc.judge_settings([self.GOOD], self.SUB), [])
        self.assertEqual(kc.judge_settings([self.GOOD, {'logpush': False, 'tail_consumers': None}], self.SUB), [])
        # each guarded key is read back by some blob; they need not be the same blob
        self.assertEqual(kc.judge_settings([{'observability': {'enabled': False, 'logs': {'enabled': False}}},
                                            {'logpush': False, 'tail_consumers': []}], self.SUB), [])
        self.assertEqual(kc.judge_settings([{'observability': {'enabled': False}, 'tail_consumers': None},
                                            {'logpush': False}], self.SUB), [])

    def test_a_guarded_key_nobody_reports_is_refused_not_passed(self):
        obs = {'observability': {'enabled': False}}
        self.assertEqual(kc.judge_settings([obs], self.SUB), ['logpush: not reported', 'tail_consumers: not reported'])
        self.assertEqual(kc.judge_settings([dict(obs, logpush=False)], self.SUB), ['tail_consumers: not reported'])
        self.assertEqual(kc.judge_settings([dict(obs, tail_consumers=[])], self.SUB), ['logpush: not reported'])
        # present but not a clean value is a named failure, not a pass
        self.assertEqual(kc.judge_settings([dict(obs, tail_consumers=None, logpush=None)], self.SUB), ['logpush: not reported'])
        self.assertEqual(kc.judge_settings([dict(obs, tail_consumers=None, logpush='yes')], self.SUB), ['logpush is on'])

    def test_each_bad_setting_is_named(self):
        def bad(blob=None, sub=None):
            return kc.judge_settings([dict(self.GOOD, **(blob or {}))], dict(self.SUB, **(sub or {})))
        self.assertIn('observability is not off', bad({'observability': {'enabled': True}}))
        self.assertIn('observability is not off', bad({'observability': {'enabled': False, 'logs': {'enabled': True}}}))
        self.assertIn('observability is not off', bad({'observability': {}}))
        self.assertIn('observability is not off', bad({'observability': None}))
        self.assertIn('tail consumers: 1', bad({'tail_consumers': [{'service': 'x'}]}))
        self.assertIn('logpush is on', bad({'logpush': True}))
        self.assertIn('workers.dev is not on', bad(sub={'enabled': False}))
        self.assertIn('workers.dev is not on', bad(sub={'enabled': None}))
        self.assertIn('preview URLs are not off', bad(sub={'previews_enabled': True}))
        self.assertIn('preview URLs are not off', kc.judge_settings([self.GOOD], {'enabled': True}))  # unknown is not off

    def test_a_missing_observability_answer_is_not_off(self):
        self.assertEqual(kc.judge_settings([{'logpush': False, 'tail_consumers': []}], self.SUB),
                         ['observability: no explicit off in the settings read back'])
        self.assertIn('observability is not off',
                      kc.judge_settings([self.GOOD, {'observability': {'enabled': True}}], self.SUB))  # any source can veto

    def test_a_redirect_is_never_followed_and_so_never_carries_the_token(self):
        req = urllib.request.Request('https://api.cloudflare.com/client/v4/x', headers={'Authorization': 'Bearer SECRETTOKEN'})
        self.assertIsNone(kc.NoRedirect().redirect_request(req, None, 302, 'Found', {}, 'http://attacker.example/steal'))

        class H(BaseHTTPRequestHandler):
            seen: list = []

            def do_GET(self):
                H.seen.append(self.headers.get('Authorization'))
                redirect = self.path == '/start'
                self.send_response(302 if redirect else 200)
                if redirect:
                    self.send_header('Location', '/other')
                self.send_header('Content-Length', '0')
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            r = urllib.request.Request('http://127.0.0.1:%d/start' % srv.server_address[1], headers={'Authorization': 'Bearer T'})
            with self.assertRaises(urllib.error.HTTPError) as why:
                kc._OPENER.open(r, timeout=5)
            self.assertEqual(why.exception.code, 302)
            why.exception.close()
            self.assertEqual(H.seen, ['Bearer T'])          # one request: /other was never asked for
        finally:
            srv.shutdown()
            srv.server_close()

    ACCOUNT = 'a' * 32
    GOOD_ANSWERS = {'/settings': {'observability': {'enabled': False}, 'logpush': False, 'tail_consumers': []},
                    '/script-settings': {'logpush': False},
                    '/subdomain': {'enabled': True, 'previews_enabled': False}}

    def cf(self, answers):
        """Run check_settings with kc._open replaced; answers maps a path tail to a result dict, an int HTTP code,
        'fail' (success: false), or an exception. Returns (outcome, urls asked, authorization headers sent)."""
        asked, auths = [], []

        class Reply:
            def __init__(self, doc):
                self.doc = doc

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps(self.doc).encode()

        def fake_open(req, timeout):
            asked.append(req.full_url)
            auths.append(req.get_header('Authorization'))
            a = answers['/' + req.full_url.rsplit('/', 1)[-1]]
            if isinstance(a, BaseException):
                raise a
            if isinstance(a, int):
                raise urllib.error.HTTPError(req.full_url, a, 'x', {}, io.BytesIO(b''))
            if a == 'fail':
                return Reply({'success': False, 'result': {}})
            return Reply({'success': True, 'result': a})

        old, kc._open = kc._open, fake_open
        try:
            with redirect_stdout(io.StringIO()):
                try:
                    return kc.check_settings('fleet-kit', 'TOKEN', self.ACCOUNT), asked, auths
                except kc.Refused as e:
                    return e, asked, auths
        finally:
            kc._open = old

    def test_the_settings_gate_asks_the_three_exact_endpoints_with_the_token(self):
        out, asked, auths = self.cf(self.GOOD_ANSWERS)
        base = 'https://api.cloudflare.com/client/v4/accounts/%s/workers/scripts/fleet-kit' % self.ACCOUNT
        self.assertEqual(asked, [base + '/settings', base + '/script-settings', base + '/subdomain'])
        self.assertEqual(set(auths), {'Bearer TOKEN'})
        self.assertEqual(out, {'worker': 'fleet-kit', 'sources': 2})

    def test_the_settings_gate_tolerates_one_settings_endpoint_failing_but_not_both_or_the_subdomain(self):
        out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/script-settings': 404}))
        self.assertEqual(out, {'worker': 'fleet-kit', 'sources': 1})
        # the one endpoint left must still prove everything: /script-settings alone says nothing about tail consumers
        out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/settings': 'fail'}))
        self.assertIsInstance(out, kc.Refused)
        self.assertIn('tail_consumers: not reported', str(out))
        out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/settings': 500}))
        self.assertIsInstance(out, kc.Refused)
        self.assertIn('tail_consumers: not reported', str(out))
        out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/settings': 500, '/script-settings': 403}))
        self.assertIsInstance(out, kc.Refused)
        self.assertIn('did not answer', str(out))
        for sub in (404, 'fail'):
            out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/subdomain': sub}))
            self.assertIsInstance(out, kc.Refused, sub)
            self.assertIn('did not answer', str(out))

    def test_the_settings_gate_refuses_a_network_failure_and_names_a_bad_answer(self):
        for exc in (urllib.error.URLError('down'), TimeoutError(), ValueError('bad json')):
            out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/settings': exc}))
            self.assertIsInstance(out, kc.Refused, repr(exc))
        out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/script-settings': {'logpush': True}}))
        self.assertIn('logpush is on', str(out))
        self.assertNotIn('TOKEN', str(out))

    def test_cf_get_only_talks_to_the_cloudflare_api_host(self):
        old = kc.CF_API
        kc.CF_API = 'http://api.cloudflare.com/client/v4'
        try:
            with self.assertRaises(kc.Refused):
                kc.cf_get('/x', 't')
            kc.CF_API = 'https://api.cloudflare.com.evil.example/client/v4'
            with self.assertRaises(kc.Refused):
                kc.cf_get('/x', 't')
        finally:
            kc.CF_API = old

    def test_settings_refuses_a_malformed_worker_or_account(self):
        with self.assertRaises(kc.Refused):
            kc.check_settings('Fleet Kit', 't', 'f' * 32)
        with self.assertRaises(kc.Refused):
            kc.check_settings('fleet-kit', 't', 'short')


@unittest.skipUnless(HAVE_ED25519, 'needs an openssl with Ed25519 -rawin')
class Keys(unittest.TestCase):
    def test_keys_are_made_once_private_and_only_the_public_halves_are_printed(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d, 'gate')
            lines = kc.make_keys(str(out))
            self.assertEqual([l.split('=')[0] for l in lines], ['KIT_UP_PUB', 'KIT_GW_PUB'])
            for line in lines:
                self.assertRegex(line, r'^KIT_(UP|GW)_PUB=[0-9a-f]{64}$')
            self.assertEqual(lines[0].split('=')[1], read_pub(str(out), 'upload'))
            self.assertEqual(lines[1].split('=')[1], read_pub(str(out), 'gateway'))
            self.assertNotEqual(lines[0], lines[1].replace('GW', 'UP'))
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
            for role in ('upload', 'gateway'):
                self.assertEqual(stat.S_IMODE(Path(out, role + '.pem').stat().st_mode), 0o600)
            with self.assertRaises(kc.Refused):
                kc.make_keys(str(out))


@unittest.skipUnless(HAVE_ED25519, 'needs an openssl with Ed25519 -rawin')
class OverHttp(unittest.TestCase):
    """The replay and the probe against the stand-in Worker."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.gate_dir = str(Path(self.tmp, 'gate'))
        kc.make_keys(self.gate_dir)
        self.pubs = {'upload': read_pub(self.gate_dir, 'upload'), 'gateway': read_pub(self.gate_dir, 'gateway')}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def replay(self, **flags):
        kit = FakeKit(self.pubs, **flags)
        with Served(kit) as base:
            client = kc.Client(base, allow_http=True)
            lines = kc.run_replay(client, kc.Admin(client, self.gate_dir), big_mib=12, cut_wait=0.4, short_life_ms=2500,
                                  log=lambda *_: None)
        return kit, lines

    def refused(self, fragment, **flags):
        with self.assertRaises(kc.Refused) as why:
            self.replay(**flags)
        self.assertIn(fragment, str(why.exception))

    def test_the_replay_passes_against_a_worker_that_follows_the_spec_and_cleans_up(self):
        kit, lines = self.replay()
        text = '\n'.join(lines)
        self.assertIn('vectors passed', text)
        self.assertIn('429 after 30 failures', text)
        self.assertIn('(a) client cuts: 2, count restored: 2', text)
        self.assertIn('(c) wrong bytes: 422 (R2 checksum), overwrite: 409 (Worker head guard; the R2 onlyIf wildcard is not separately observable), identical re-upload: 200', text)
        self.assertIn('not CPU time', text)
        self.assertRegex(text, r'404 answers compared: \d+, identical')
        self.assertEqual(kit.fails, 30)
        self.assertEqual(kit.floor, 0)
        self.assertTrue(all(i['revoked'] for i in kit.invites.values()))  # nothing open is left on the Worker
        self.assertNotIn(next(iter(kit.invites.values()))['code'], text)  # no code in what the job prints

    def test_the_replay_refuses_a_worker_that_tells_a_revoked_invite_apart(self):
        self.refused('differs', leak_revoked=True)

    def test_the_replay_refuses_a_worker_that_keeps_the_count_of_a_cut_stream(self):
        self.refused('did not give the download back', no_release=True)

    def test_the_replay_refuses_a_budget_that_is_not_30(self):
        self.refused('429 came after', per_source=29)

    def test_the_replay_refuses_a_front_that_spends_budget_on_a_bad_shape(self):
        self.refused('429 came after', front_spends=True)

    def test_the_replay_refuses_a_gzip_404(self):
        self.refused('differs', gzip_404=True)

    def test_the_replay_refuses_a_range_answer(self):
        self.refused('status 206', range_206=True)

    def test_the_replay_refuses_a_worker_without_the_upload_key(self):
        pubs = dict(self.pubs, upload='')
        kit = FakeKit(pubs)
        with Served(kit) as base:
            client = kc.Client(base, allow_http=True)
            with self.assertRaises(kc.Refused):
                kc.run_replay(client, kc.Admin(client, self.gate_dir), big_mib=1, cut_wait=0, short_life_ms=2500, log=lambda *_: None)

    def test_the_probe_passes_and_spends_at_most_five_gate_failures(self):
        kit = FakeKit(self.pubs)
        with Served(kit) as base:
            lines = kc.run_probe(kc.Client(base, allow_http=True), log=lambda *_: None)
        self.assertIn('byte-identical, 5 reached the gate', lines[0])
        self.assertEqual(kit.gate_failures, 5)
        self.assertLessEqual(kit.gate_failures, kc.PROBE_MAX_FAILURES)

    def test_the_probe_refuses_an_answer_that_differs_or_a_429(self):
        for flags, fragment in (({'gzip_404': True}, 'differs'), ({'per_source': 0}, 'answered 429')):
            kit = FakeKit(self.pubs, **flags)
            with Served(kit) as base, self.assertRaises(kc.Refused) as why:
                kc.run_probe(kc.Client(base, allow_http=True), log=lambda *_: None)
            self.assertIn(fragment, str(why.exception))

    def test_the_cli_prints_a_refusal_as_the_last_line_and_exits_1(self):
        kit = FakeKit(self.pubs, per_source=0)
        buf = io.StringIO()
        with Served(kit) as base, redirect_stdout(buf):
            # https only on the command line: an http base is refused before any request
            rc = kc.main(['probe', base])
        self.assertEqual(rc, 1)
        self.assertTrue(buf.getvalue().strip().splitlines()[-1].startswith('REFUSED'))


class FrontRejects(unittest.TestCase):
    def test_the_lowercase_case_is_always_a_malformed_code_even_for_an_all_digit_code(self):
        class Recorder:
            def __init__(self):
                self.sent = []

            def request(self, method, path, headers=(), body=None, read=True):
                self.sent.append(list(headers))

        for code in ('2345678923', 'CFGHJMPQRV', '9999999999'):
            rec = Recorder()
            kc.front_rejects(rec, code)
            auths = [v for hdrs in rec.sent for k, v in hdrs if k == 'Authorization']
            self.assertIn('FleetInvite c' + code[1:], auths, code)       # the lowercase case is always built from a letter
            self.assertNotRegex('FleetInvite c' + code[1:], r'^FleetInvite [23456789CFGHJMPQRVWX]{10}$')


class Cli(unittest.TestCase):
    def has_secret(self, stdin, name='INVITE_PEPPER'):
        old, sys.stdin = sys.stdin, stdin
        try:
            with redirect_stdout(io.StringIO()):
                return kc.main(['has-secret', name])
        finally:
            sys.stdin = old

    def test_has_secret_exit_codes(self):
        for text, want in (('[{"name": "INVITE_PEPPER", "type": "secret_text"}]', 0), ('[]', kc.ABSENT), ('garbage', 2)):
            self.assertEqual(self.has_secret(io.StringIO(text)), want)
        self.assertEqual(kc.ABSENT, 10)

    def test_a_crash_or_a_bad_input_never_reads_as_absent(self):
        class Bytes:
            def __init__(self, raw):
                self.buffer = io.BytesIO(raw)
        # invalid UTF-8 around a list that lacks the name still parses (decoded with errors=replace): absent, honestly
        self.assertEqual(self.has_secret(Bytes(b'[]\xff')), kc.ABSENT)
        self.assertEqual(self.has_secret(Bytes(b'[{"name": "INVITE_PEPPER"}]\xff')), 0)
        for raw in (b'\xff\xfe', b'', b'\xff[{"name": "X"'):
            self.assertEqual(self.has_secret(Bytes(raw)), 2, raw)
        self.assertEqual(self.has_secret(io.StringIO('[]'), name='bad name'), 2)      # a refused name is not absence

        class Boom:
            def read(self):
                raise RuntimeError('boom')
        self.assertEqual(self.has_secret(Boom()), 2)
        old, kc.secret_names = kc.secret_names, lambda text: (_ for _ in ()).throw(KeyError('x'))
        try:
            self.assertEqual(self.has_secret(io.StringIO('[]')), 2)
        finally:
            kc.secret_names = old

    def test_the_summary_goes_to_the_job_summary_file_and_holds_no_code(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, 'summary.md')
            old = os.environ.get('GITHUB_STEP_SUMMARY')
            os.environ['GITHUB_STEP_SUMMARY'] = str(path)
            try:
                with redirect_stdout(io.StringIO()):
                    kc.summary(['a', 'b'])
            finally:
                if old is None:
                    del os.environ['GITHUB_STEP_SUMMARY']
                else:
                    os.environ['GITHUB_STEP_SUMMARY'] = old
            self.assertEqual(path.read_text(), 'a\nb\n')

    def test_only_https_is_accepted_for_a_real_base(self):
        for bad in ('http://x.workers.dev', 'ftp://x', 'https://x/path', 'x.workers.dev', ''):
            with self.assertRaises(kc.Refused):
                kc.Client(bad)
        kc.Client('https://fleet-kit-staging.mirrorstack-fleet.workers.dev')

    def test_a_script_that_prints_nothing_it_should_not(self):
        text = (ROOT / 'bin/fleet-kit-check.py').read_text(encoding='utf-8')
        self.assertNotRegex(text, r'print\([^)]*(code|token|pepper|\.pem)')


def jobs(text: str) -> dict[str, str]:
    head, _, rest = text.partition('\njobs:\n')
    parts = re.split(r'(?m)^  (\w[\w-]*):\n', rest)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}


class Workflow(unittest.TestCase):
    JOBS = jobs(WF)

    def test_it_parses_as_yaml_when_ruby_is_there(self):
        ruby = shutil.which('ruby')
        if not ruby:
            self.skipTest('no ruby')
        r = subprocess.run([ruby, '-ryaml', '-e', 'd = YAML.load_file(ARGV[0]); abort("no jobs") unless d["jobs"].keys == ["verify", "deploy"]',
                            str(ROOT / '.github/workflows/kit-deploy.yml')], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_two_jobs_only_the_deploy_one_in_the_environment(self):
        self.assertEqual(list(self.JOBS), ['verify', 'deploy'])
        self.assertEqual(re.findall(r'(?m)^    environment: (\S+)$', WF), ['kit-deploy'])
        self.assertIn('environment: kit-deploy', self.JOBS['deploy'])
        self.assertNotIn('environment', self.JOBS['verify'])
        self.assertNotRegex(self.JOBS['verify'], r'(?i)secrets|CLOUDFLARE')
        self.assertIn('needs: verify', self.JOBS['deploy'])

    def test_it_runs_only_on_the_release_branch(self):
        self.assertRegex(WF, r'(?m)^on:\n  push:\n    branches: \[release\]\n')
        self.assertIn('  workflow_dispatch:\n', WF)
        self.assertNotIn('pull_request', WF)
        self.assertEqual(WF.count("if: github.ref == 'refs/heads/release'"), 2)

    def test_hosted_runner_read_only_permissions_and_no_cancel(self):
        self.assertRegex(WF, r'(?m)^permissions:\n  contents: read\n')
        self.assertEqual(re.findall(r'runs-on: (\S+)', WF), ['ubuntu-24.04', 'ubuntu-24.04'])
        self.assertNotIn('self-hosted', WF)
        self.assertNotRegex(WF, r'(?m)^\s+\w[\w-]*: write\b')
        self.assertIn('concurrency:\n  group: kit-deploy\n  cancel-in-progress: false\n', WF)

    def test_actions_are_sha_pinned_checkout_keeps_no_token_and_nothing_is_cached_or_uploaded(self):
        for use in re.findall(r'uses: (\S+)', WF):
            self.assertRegex(use, r'^actions/[\w-]+@[0-9a-f]{40}$')
        self.assertEqual(WF.count('persist-credentials: false'), WF.count('actions/checkout@'))
        for word in ('upload-artifact', 'actions/cache', 'cache:', 'cache-dependency'):
            self.assertNotIn(word, WF)
        # the same pins as the other workflows
        pins = lambda t: set(re.findall(r'(actions/[\w-]+@[0-9a-f]{40})', t))  # noqa: E731
        self.assertEqual(pins(WF) - pins((ROOT / '.github/workflows/kit-test.yml').read_text(encoding='utf-8')), set())

    def test_no_expression_reaches_a_run_line_except_through_env(self):
        bodies, block = [], None
        for line in WF.splitlines():
            if block is not None and (not line.strip() or len(line) - len(line.lstrip()) > block):
                bodies.append(line)
                continue
            block = None
            m = re.match(r'(\s+)(?:- )?run: (.*)$', line)
            if m:
                bodies.append(m.group(2))
                if m.group(2).strip() in ('|', '>', '|-', '>-'):
                    block = len(m.group(1))
        self.assertGreater(len(bodies), 10)
        for body in bodies:
            self.assertNotIn('${{', body)

    def test_the_cloudflare_credentials_exist_only_on_the_steps_that_call_cloudflare(self):
        self.assertNotRegex(CODE.split('\njobs:\n')[0], r'secrets\.|CLOUDFLARE')       # not workflow-level
        deploy = self.JOBS['deploy']
        self.assertNotRegex(deploy.split('\n    steps:\n')[0], r'secrets\.|CLOUDFLARE')  # not job-level
        steps = re.split(r'(?m)^      - ', deploy.split('\n    steps:\n')[1])
        with_token = [s for s in steps if 'CLOUDFLARE_API_TOKEN' in s]
        self.assertEqual(len(with_token), 7)
        self.assertEqual(WF.count('${{ secrets.CLOUDFLARE_API_TOKEN }}'), 7)
        self.assertEqual(WF.count('${{ vars.CLOUDFLARE_ACCOUNT_ID }}'), 7)
        self.assertEqual(re.findall(r'secrets\.(\w+)', WF), ['CLOUDFLARE_API_TOKEN'] * 7)
        for s in steps:
            if 'npm ci' in s or 'replay' in s or 'probe' in s or 'make the' in s.lower():
                self.assertNotIn('CLOUDFLARE_API_TOKEN', s)   # the install, the replay and the probe never hold the token
        self.assertIn('npm ci --ignore-scripts', self.JOBS['deploy'])
        self.assertLess(CODE.index('npm ci --ignore-scripts'), CODE.index('CLOUDFLARE_API_TOKEN'))

    def test_the_order_is_staging_replay_settings_pepper_production_settings_probe(self):
        d = self.JOBS['deploy']
        marks = ['Deploy staging', 'staging INVITE_PEPPER', 'Settings gate, staging', 'Replay', 'INVITE_PEPPER once',
                 'Deploy production', 'Settings gate, production', 'Hostile probe']
        at = [d.index(x) for x in marks]
        self.assertEqual(at, sorted(at), marks)
        self.assertIn('wrangler deploy --env staging', d)
        self.assertEqual(len(re.findall(r'wrangler deploy\b', d)), 2)
        self.assertEqual(len(re.findall(r'wrangler deploy\b(?! --env staging)', d)), 1)
        self.assertIn('--var "KIT_GW_PUB:$KIT_GW_PUB" --var "KIT_UP_PUB:$KIT_UP_PUB"', d)
        self.assertIn('settings fleet-kit-staging', d)
        self.assertIn('settings fleet-kit\n', d)

    def test_the_pepper_is_made_once_piped_and_never_echoed(self):
        d = self.JOBS['deploy']
        self.assertEqual(d.count('openssl rand -hex 32 | npx --no-install wrangler secret put INVITE_PEPPER'), 2)
        self.assertIn('secret list --format json', d)
        self.assertIn('has-secret INVITE_PEPPER', d)
        self.assertNotRegex(d, r'(?i)(echo|printf|cat|tee)\b[^\n]*PEPPER[^\n]*\$')
        self.assertNotRegex(WF, r'(?m)^\s*set -x|\bset -[a-z]*x')
        self.assertNotIn('>> "$GITHUB_ENV"', d.split('INVITE_PEPPER')[1].split('Deploy production')[0])

    def test_wrangler_is_the_pinned_one_telemetry_off_and_never_fetched(self):
        self.assertNotRegex(WF, r'npx (?!--no-install)')
        self.assertNotIn('npm install', WF)
        self.assertNotIn('@latest', WF)
        self.assertIn('WRANGLER_SEND_METRICS: "false"', WF)
        self.assertNotIn('WRANGLER_LOG', WF)

    def test_the_throwaway_keys_are_in_runner_temp_wiped_at_the_end_and_never_secrets(self):
        d = self.JOBS['deploy']
        self.assertIn('KIT_GATE_DIR="$RUNNER_TEMP/kitgate"', d)
        self.assertIn('fleet-kit-check.py keys "$KIT_GATE_DIR"', d)
        self.assertRegex(d, r'(?s)- name: Wipe[^\n]*\n\s+if: always\(\)\n.*shred -u')
        self.assertNotRegex(WF, r'KIT_(UP|GW)_PRIV|\.pem >>')

    def test_the_verify_job_runs_the_kit_tests_the_console_scan_and_this_scripts_tests(self):
        v = self.JOBS['verify']
        for need in ('node --test kit/', 'fleet-kit-check.py console kit', "discover -s tests -p 'test_kit_deploy.py'"):
            self.assertIn(need, v)

    def test_the_summary_is_written_by_the_script_and_a_failed_gate_stops_the_job(self):
        self.assertNotIn('continue-on-error', WF)
        self.assertNotIn('|| true', WF)
        self.assertEqual(WF.count('set -euo pipefail'), WF.count('run: |'))

    def test_the_hosts_are_the_two_workers_dev_names_of_the_fleet_account(self):
        self.assertIn('https://fleet-kit-staging.mirrorstack-fleet.workers.dev', WF)
        self.assertIn('https://fleet-kit.mirrorstack-fleet.workers.dev', WF)
        self.assertNotIn('mirrorstack-kit', WF)

    def test_it_never_touches_the_install_workflow_or_the_floor(self):
        for name in ('KIT_FLOOR', 'KIT_DISABLED', 'KIT_HOST'):
            self.assertNotIn(name, CODE)


def parsed_workflow():
    """The workflow as ruby parses it (the CI runner has ruby); None when there is none."""
    ruby = shutil.which('ruby')
    if not ruby:
        return None
    r = subprocess.run([ruby, '-ryaml', '-rjson', '-e', 'puts JSON.generate(YAML.load_file(ARGV[0]))',
                        str(ROOT / '.github/workflows/kit-deploy.yml')], capture_output=True, text=True)
    return json.loads(r.stdout) if r.returncode == 0 else None


class WorkflowStructure(unittest.TestCase):
    """The properties the security claims rest on, asserted on the parsed steps (a mutation that keeps the old text
    checks green, such as `if: always()` on the production deploy, is caught here)."""
    DOC = parsed_workflow()

    def setUp(self):
        if self.DOC is None:
            self.skipTest('no ruby to parse the workflow')
        self.steps = self.DOC['jobs']['deploy']['steps']

    def named(self, fragment):
        found = [s for s in self.steps if fragment in s.get('name', '')]
        self.assertEqual(len(found), 1, fragment)
        return found[0]

    def test_only_the_wipe_step_has_a_condition_and_nothing_continues_on_error(self):
        self.assertEqual([s['name'] for s in self.steps if 'if' in s], [self.named('Wipe')['name']])
        self.assertEqual(self.named('Wipe')['if'], 'always()')
        for job in self.DOC['jobs'].values():
            for step in job['steps']:
                self.assertNotIn('continue-on-error', step)
            self.assertNotIn('continue-on-error', job)

    def test_the_triggers_are_a_push_to_release_and_a_manual_dispatch_only(self):
        triggers = self.DOC.get('on', self.DOC.get('true'))
        self.assertEqual(sorted(triggers), ['push', 'workflow_dispatch'])
        self.assertEqual(sorted(triggers['push']), ['branches', 'paths'])
        self.assertEqual(triggers['push']['branches'], ['release'])
        self.assertIn(triggers['workflow_dispatch'], (None, {}))

    def test_checkout_takes_no_ref_and_keeps_no_credentials(self):
        for job in self.DOC['jobs'].values():
            for step in job['steps']:
                if str(step.get('uses', '')).startswith('actions/checkout@'):
                    self.assertEqual(step['with'], {'persist-credentials': False})

    def test_staging_gets_the_throwaway_pepper_and_production_neither_that_nor_the_staging_env(self):
        staging = self.named('staging INVITE_PEPPER')['run']
        self.assertRegex(staging, r'wrangler secret put INVITE_PEPPER --env staging\s*$')
        for fragment in ('INVITE_PEPPER once', 'Deploy production'):
            self.assertNotIn('--env', self.named(fragment)['run'], fragment)
            self.assertNotIn('staging', self.named(fragment)['run'], fragment)
        self.assertIn('--env staging', self.named('Deploy staging')['run'])
        self.assertIn('secret put INVITE_PEPPER', self.named('INVITE_PEPPER once')['run'])

    def test_the_pepper_is_made_on_the_absent_code_only(self):
        run = self.named('INVITE_PEPPER once')['run']
        arms = re.findall(r'(?m)^\s+(\d+|\*)\) ', run)
        self.assertEqual(arms, ['0', '10', '*'])
        self.assertNotRegex(run, r'(?m)^\s+1\)')
        put_arm = run.split('10)')[1].split(';;')[0]
        self.assertIn('secret put INVITE_PEPPER', put_arm)
        self.assertNotIn('secret put', run.split('10)')[0])
        self.assertIn('exit 1', run.split('*)')[1])

    def test_no_run_line_can_make_a_failing_step_pass(self):
        allowed = (r'^python3 "\$GITHUB_WORKSPACE/bin/fleet-kit-check\.py" has-secret INVITE_PEPPER < "\$RUNNER_TEMP/secret-names\.json" \|\| rc=\$\?$',
                   r'^test -n "\$CLOUDFLARE_(?:API_TOKEN|ACCOUNT_ID)" \|\| \{ echo "REFUSED [^"]*"; exit 1; \}$')
        for job in self.DOC['jobs'].values():
            for step in job['steps']:
                for line in step.get('run', '').splitlines():
                    line = line.strip()
                    if '||' in line:
                        self.assertTrue(any(re.match(a, line) for a in allowed), line)
                    self.assertNotRegex(line, r'(?:;|&&)\s*(?:true|exit 0|:)\b|\|\s*(?:true|cat)\s*$', line)
                    self.assertNotRegex(line, r'^set [+]e|\bset [+]e\b', line)

    def test_the_token_is_only_ever_tested_never_read_out_by_a_run_line(self):
        test_n = re.compile(r'test -n "\$CLOUDFLARE_API_TOKEN"(?: \|\| \{ echo "[^"]*"; exit 1; \})?')
        for job in self.DOC['jobs'].values():
            for step in job['steps']:
                for line in step.get('run', '').splitlines():
                    self.assertNotIn('CLOUDFLARE_API_TOKEN', test_n.sub('', line), line)

    def test_the_replay_hits_staging_and_the_probe_hits_production_and_neither_the_other(self):
        replay, probe = self.named('Replay')['run'], self.named('Hostile probe')['run']
        self.assertEqual(replay.strip(), 'python3 bin/fleet-kit-check.py replay "$STAGING_URL"')
        self.assertEqual(probe.strip(), 'python3 bin/fleet-kit-check.py probe "$PROD_URL"')
        for step in (self.named('Replay'), self.named('Hostile probe')):
            self.assertNotIn('env', step)                       # no token on either
        self.assertIn('settings fleet-kit-staging', self.named('Settings gate, staging')['run'])
        self.assertRegex(self.named('Settings gate, production')['run'].strip(), r'settings fleet-kit$')


if __name__ == '__main__':
    unittest.main()
