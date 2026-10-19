"""K6: .github/workflows/kit-deploy.yml and bin/fleet-kit-check.py. Offline: the script's judges over crafted input, and the
whole staging replay and production probe over HTTP against a stand-in kit Worker written here from the spec (it speaks the
Worker's wire contract: kit/README.md, "The Worker front" and "Admin calls"), with a few deliberately wrong variants that
each must be refused. The workflow's rules are text checks (no YAML parser in the stdlib). No network beyond 127.0.0.1;
the Ed25519 signatures need an `openssl` 3.x binary (the tests that sign skip without one). Plain unittest."""
from __future__ import annotations

import base64
import hashlib
import http.client
import importlib.util
import inspect
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
from contextlib import contextmanager, nullcontext, redirect_stdout
from unittest import mock
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


class _Redirector(BaseHTTPRequestHandler):
    """Answers every request with `code` and a Location to /other; records (method, path, Authorization)."""
    code = 302
    seen: list = []

    def do_PATCH(self):
        type(self).seen.append((self.command, self.path, self.headers.get('Authorization')))
        self.send_response(type(self).code)
        self.send_header('Location', '/other')
        self.send_header('Content-Length', '0')
        self.end_headers()
    do_GET = do_POST = do_PATCH

    def log_message(self, *a):
        pass


def through_the_real_open(code, call, env):
    """Run call() with the REAL kc._open in the path: only kc._OPENER is wrapped, its open() rewrites the URL to a local
    server answering `code` + Location and delegates to the real NoRedirect opener. Any HTTPS connect is refused (so a
    mutation that bypasses _OPENER fails here instead of reaching the API). Returns (result, requests seen, HTTPS tries)."""
    H = type('H', (_Redirector,), {'code': code, 'seen': []})
    srv = ThreadingHTTPServer(('127.0.0.1', 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    local = 'http://127.0.0.1:%d/start' % srv.server_address[1]
    real, https_tries = kc._OPENER, []

    class Wrapped:
        def open(self, req, timeout=None):
            moved = urllib.request.Request(local, data=req.data, headers=dict(req.header_items()), method=req.get_method())
            return real.open(moved, timeout=5)

    def no_https(conn, *a, **k):
        https_tries.append(conn.host)
        raise ConnectionRefusedError('no network in tests')
    old_connect = http.client.HTTPSConnection.connect
    saved = {k: os.environ.get(k) for k in env}
    kc._OPENER, http.client.HTTPSConnection.connect = Wrapped(), no_https
    try:
        os.environ.update(env)
        return call(), H.seen, https_tries
    finally:
        kc._OPENER, http.client.HTTPSConnection.connect = real, old_connect
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        srv.shutdown()
        srv.server_close()


EDGE_400 = (b'<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n'
            b'<hr><center>cloudflare</center>\r\n</body>\r\n</html>\r\n')
# Cloudflare's managed robots.txt, as run 38107708369's probes saw its head (the measured page is 1248 bytes)
MANAGED_ROBOTS = (b'# As a condition of accessing this website, you agree to abide by the following\n# content signals:\n#\n'
                  b'# search: building a search index and providing search results.\n# ai-input: inputting content into AI models.\n'
                  b'# ai-train: training or fine-tuning AI models.\n\nUser-agent: *\nContent-Signal: search=yes,ai-train=no\n'
                  b'Allow: /\n')

# Cloudflare's NEL headers as run 38164673127's probe saw them on every Worker 404: nel constant, report-to with a token
# that differs per response.
CF_NEL = '{"report_to":"cf-nel","success_fraction":0.0,"max_age":604800}'
CF_REPORT_TO = '{"group":"cf-nel","max_age":604800,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/v4?s=%s"}]}'
# A report-to that is NOT well-formed cf-nel, each wrong in one named way (the token still differs per response).
NOT_CF_NEL = {
    'wrong_group': CF_REPORT_TO.replace('"group":"cf-nel"', '"group":"default"'),
    'foreign_host': CF_REPORT_TO.replace('a.nel.cloudflare.com', 'a.nel.cloudflare.com.example.net'),
    'http': CF_REPORT_TO.replace('https://', 'http://'),
    'extra_key': CF_REPORT_TO.replace('{"group"', '{"include_subdomains":true,"group"'),
    'not_json': 'cf-nel; https://a.nel.cloudflare.com/report/v4?s=%s',
    'big': CF_REPORT_TO.replace('?s=', '?s=' + 'A' * 2048),
    'two_endpoints': CF_REPORT_TO.replace('}]}', '},{"url":"https://a.nel.cloudflare.com/report/v4?s=z"}]}'),
    'dot_dot': CF_REPORT_TO.replace('/report/v4', '/report/../v4'),
    'second_parameter': CF_REPORT_TO.replace('?s=%s', '?s=%s&live=1'),
}
# A report-to that IS well-formed cf-nel and differs from CF_REPORT_TO outside the token: fine on every answer of a run
# (Cloudflare may change it between runs), a difference on one answer among the others.
CF_NEL_OTHER = {
    'max_age_1': CF_REPORT_TO.replace('604800', '1'),
    'path_v5': CF_REPORT_TO.replace('/report/v4', '/report/v5'),
    'spaced': CF_REPORT_TO.replace('"max_age":', '"max_age": '),
    'edge_spelling': '{"endpoints":[{"url":"https:\\/\\/a.nel.cloudflare.com\\/report\\/v4?s=%s"}],"group":"cf-nel",'
                     '"max_age":604800}',
}


def report_to_values(kind: str, token: str) -> list[str]:
    """The Report-To header lines of one answer: 'cf-nel' Cloudflare's own, 'absent' none, 'twice' two of Cloudflare's,
    or one CF_NEL_OTHER or NOT_CF_NEL kind."""
    if kind == 'absent':
        return []
    if kind == 'twice':
        return [CF_REPORT_TO % token, CF_REPORT_TO % (token + '2')]
    return [(CF_REPORT_TO if kind == 'cf-nel' else CF_NEL_OTHER.get(kind) or NOT_CF_NEL[kind]) % token]


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
        self.gate_calls = 0                      # requests that got past the front check into the Gate
        self.requests = 0                        # every request, in order (the 'placeholder' flag asks for this number)
        self.paths: list[str] = []               # every path requested, in order
        self.ready_tries = 0                     # requests to the probe's readiness path so far (the 'ready_fault' flag)
        self.robots_fetches = 0
        self.served_404 = 0                      # the Worker's 404s served so far (edge_nel_nth, nel_nth)
        self.nel_lock = threading.Lock()         # its own lock: a gate 404 is sent while self.lock is held
        self.tokens: list[str] = []              # every report-to token sent (no refusal may print one)
        self.signed_calls = 0                    # well-formed KitAdmin calls seen, in order (version-propagation flags)
        self.per_target: dict[tuple[str, str | None], int] = {}
        self.admin_log: list[tuple[str, str, str, int, int]] = []  # (role, method, path, ts, status) per signed call
        self.skew_ms = 0                         # how far this kit's clock runs ahead of the real one (advance() moves it)
        self.sleeps: list[tuple[float, bool]] = []   # fake_sleep's record: (seconds asked for, True if it moved the clock)

    def now(self) -> int:
        return int(time.time() * 1000 + self.skew_ms)

    def advance(self, ms: float) -> None:
        """Move the kit's clock forward: invites expire and the 300 s signature window shifts, with no real time spent."""
        self.skew_ms += ms

    def fake_sleep(self, real=time.sleep):
        """The `sleep` for run_replay. A wait of 2 s or more is the invite-expiry wait (short_life_ms 2500 + the 2500 ms
        margin, about 5 s): the kit's clock moves instead of the test waiting. Every shorter wait (cut_wait 0.4, the spacings)
        is real-time synchronisation with the fake server and really sleeps through `real`. A wait under 2 s that is the
        expiry wait (a loaded runner already spent more than 3 s) is simply slept for real: correct, only slower."""
        def sleep(s):
            advanced = s >= 2.0
            self.sleeps.append((s, advanced))
            if advanced:
                self.advance(s * 1000)
            else:
                real(s)
        return sleep

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

        def send_fixed(self, status, body, ctype='text/plain', server=None):
            if kit.admin_log and getattr(self, 'signed', False):  # the status of this signed call, for the log
                kit.admin_log[-1] = kit.admin_log[-1][:4] + (status,)
            if server:                                           # as the live host: every answer there says cloudflare
                self.send_response_only(status)
                self.send_header('Server', server)
                self.send_header('Date', self.date_time_string())
            else:
                self.send_response(status)
            self.send_header('Content-Type', ctype)
            self.send_header('Cache-Control', 'no-store, no-transform')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('CF-RAY', os.urandom(8).hex())
            self.edge_nel(status)
            if kit.flags.get('gzip_404') and status == 404 and 'gzip' in (self.headers.get('Accept-Encoding') or ''):
                self.send_header('Content-Encoding', 'gzip')
            self.end_headers()
            self.wfile.write(body)

        def edge_nel(self, status):
            """kit.flags['edge_nel']=KIND: the reporting headers Cloudflare's edge adds to every answer of the Worker (run
            38164673127): a constant NEL and a Report-To of that kind (report_to_values) with a per-response token.
            edge_nel_nth=(N, KIND): the Nth 404 served takes this kind instead. nel_nth=N: the Nth 404's NEL is another."""
            kind = kit.flags.get('edge_nel')
            if not kind:
                return
            n = 0
            if status == 404 and self.path != kc.PROBE_READY_PATH:     # readiness tries are not among the numbered 404s
                with kit.nel_lock:
                    kit.served_404 += 1
                    n = kit.served_404
                nth = kit.flags.get('edge_nel_nth')
                if nth and nth[0] == n:
                    kind = nth[1]
            token = os.urandom(8).hex()
            kit.tokens.append(token)
            for value in report_to_values(kind, token):
                self.send_header('Report-To', value)
            self.send_header('NEL', CF_NEL.replace('0.0', '0.5') if n and n == kit.flags.get('nel_nth') else CF_NEL)

        def nf(self):
            self.send_fixed(404, b'not found\n')

        def send_edge_400(self, *, body=EDGE_400, cache=None, server='cloudflare'):
            # Cloudflare's own page for two Authorization headers, as run 38102844541's probe saw it: no Worker headers
            self.send_response_only(400)
            self.send_header('Server', server)
            self.send_header('Date', self.date_time_string())
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            if cache:
                self.send_header('Cache-Control', cache)
            self.send_header('CF-RAY', os.urandom(8).hex())
            self.end_headers()
            self.wfile.write(body)

        def send_robots(self, body=MANAGED_ROBOTS, status=200, extra=()):
            # Cloudflare's managed robots.txt: an edge page with the Worker's own cache-control, as the probes measured it
            self.send_response_only(status)
            self.send_header('Server', 'cloudflare')
            self.send_header('Date', self.date_time_string())
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store, no-transform')
            self.send_header('CF-RAY', os.urandom(8).hex())
            for k, v in extra:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def robots(self, mode) -> bool:
            """kit.flags['robots']: how the edge answers /robots.txt. True = answered (else the Worker's 404 follows)."""
            with kit.lock:
                kit.robots_fetches += 1
                first = kit.robots_fetches % 2 == 1
            if mode == 'managed':
                self.send_robots()
            elif mode == 'mixed':                                # the managed page once, the Worker's 404 the other time
                if not first:
                    return False
                self.send_robots()
            elif mode == 'hello':                                # a dashboard placeholder, not the managed page
                self.send_robots(b'Hello World!')
            elif mode == 'no_marker':                            # the page without its first line
                self.send_robots(MANAGED_ROBOTS.split(b'\n', 1)[1])
            elif mode == 'no_signals':                           # the first line, but no content signals anywhere
                self.send_robots(MANAGED_ROBOTS.split(b'\n', 1)[0] + b'\nUser-agent: *\nAllow: /\n')
            elif mode == 'big':
                self.send_robots(MANAGED_ROBOTS + b'#' * (64 * 1024))
            elif mode == 'differ':                               # the managed page, one byte other on the second fetch
                self.send_robots(MANAGED_ROBOTS if first else MANAGED_ROBOTS.replace(b'Allow', b'allow'))
            elif mode == 'edge_400':                             # the duplicate-Authorization page on robots
                self.send_edge_400()
            elif mode == 'reporting':                            # run 38140164568 attempt 2: report-to (and nel) per fetch
                self.send_robots(extra=[('Report-To', '{"group":"cf-nel","endpoints":[{"url":"https://a.nel.cloudflare.com'
                                                      '/report/v4?s=%s"}]}' % os.urandom(8).hex()),
                                        ('NEL', '{"success_fraction":0.0%d,"report_to":"cf-nel"}' % (1 if first else 2))])
            elif mode == 'x_foo':                                # another header that differs per fetch: still refused
                self.send_robots(extra=[('X-Foo', os.urandom(4).hex())])
            else:
                return False
            return True

        def dup_auth(self, mode, auths) -> bool:
            """kit.flags['dup_auth']: how the edge (or a wrong Worker) answers two Authorization headers. True = answered."""
            live = any(('FleetInvite ' + i['code']) == auths[0] for i in kit.invites.values())
            if mode == 'edge':
                self.send_edge_400()
            elif mode == 'edge_live_only':                       # mixed: the edge page for a live code, the 404 otherwise
                self.send_edge_400() if live else self.nf()
            elif mode == 'edge_len':                             # the edge page one byte longer for a live code
                self.send_edge_400(body=EDGE_400 + (b' ' if live else b''))
            elif mode == 'edge_body':                            # same length, one byte other for a live code
                self.send_edge_400(body=EDGE_400.replace(b'<hr>', b'<HR>') if live else EDGE_400)
            elif mode == 'edge_worker_cache':                    # the edge page, but with the Worker's cache-control
                self.send_edge_400(cache='no-store, no-transform')
            elif mode == 'edge_not_cloudflare':
                self.send_edge_400(server='nginx')
            elif mode == 'other_404':                            # a 404 for both, but not the Worker's one answer
                self.send_fixed(404, b'not found!\n')
            elif mode == 'json400':                              # Worker-made 400s, with the live host's server header
                self.send_fixed(400, json.dumps({'ok': False, 'error': 'bad-request'}).encode(), 'application/json',
                                server='cloudflare')
            elif mode == 'text400':
                self.send_fixed(400, b'400 Bad Request\n', server='cloudflare')
            else:
                return False
            return True

        def send_json(self, status, doc):
            self.send_fixed(status, json.dumps(doc).encode(), 'application/json')

        def send_placeholder(self):
            # the Cloudflare dashboard's placeholder Worker, run 38180769445: 200 "Hello World!"; no cache-control (measured),
            # nel/report-to were not measured (the refusal prints neither), none are sent here
            body = b'Hello World!'
            self.send_response_only(200)
            self.send_header('Server', 'cloudflare')
            self.send_header('Date', self.date_time_string())
            self.send_header('Content-Type', 'text/plain;charset=UTF-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('CF-RAY', os.urandom(8).hex())
            self.end_headers()
            self.wfile.write(body)

        def send_faulty_404(self, kind):
            """The Worker's fixed 404 (status, text/plain, "not found\\n") with ONE header wrong, as kind names it."""
            body = b'not found\n'
            self.send_response(404)                              # as send_fixed does: Server and Date are the stdlib's
            self.send_header('Content-Type', 'text/plainx-evil' if kind == 'ctype' else 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('CF-RAY', os.urandom(8).hex())
            if kind != 'no-cache-control':
                self.send_header('Cache-Control', 'public, max-age=60' if kind == 'public-cache' else 'no-store, no-transform')
            extra = {'set-cookie': ('Set-Cookie', 'a=b'), 'location': ('Location', '/other'), 'content-encoding':
                     ('Content-Encoding', 'gzip'), 'x-foo': ('X-Foo', '1'), 'report-to': ('Report-To', NOT_CF_NEL['wrong_group'] % 'tok')}
            if kind in extra:
                self.send_header(*extra[kind])
            self.end_headers()
            self.wfile.write(body)

        def handle_any(self):
            path = self.path
            with kit.lock:
                kit.requests += 1
                n = kit.requests
                kit.paths.append(path)
            # kit.flags['placeholder']=f: f(n, path) is True when the edge location asked still serves the previous
            # version (the placeholder); n counts every request of the run from 1
            if kit.flags.get('placeholder') and kit.flags['placeholder'](n, path):
                return self.send_placeholder()
            if path == kc.PROBE_READY_PATH:
                with kit.lock:
                    kit.ready_tries += 1
                    fault = kit.flags.get('ready_fault')
                    faulty = fault and (kit.ready_tries <= fault[0] or kit.ready_tries in fault[2:])
                if faulty:                                       # the Worker's 404 with one header wrong
                    return self.send_faulty_404(fault[1])
                first = kit.flags.get('ready_first')             # (n, status, body): the Worker's own 429/503 for the first n
                if first and kit.ready_tries <= first[0]:
                    return self.send_fixed(first[1], first[2])
            if path == kc.PROBE_READY_PATH and kit.flags.get('ready_answer'):      # a 404 that is not the Worker's fixed one
                return self.send_fixed(*kit.flags['ready_answer'])
            if path == kit.flags.get('edge_400_on'):             # the edge 400 on a label that is not DUP_AUTH
                return self.send_edge_400()
            if path == kit.flags.get('managed_robots_on'):       # the managed robots page on a label that is not robots
                return self.send_robots()
            if path == '/robots.txt' and self.robots(kit.flags.get('robots')):
                return
            dup = self.headers.get_all('Authorization') or []
            if len(dup) == 2 and self.dup_auth(kit.flags.get('dup_auth'), dup):
                return
            if path.startswith('/_k/'):
                return self.admin(path)
            m = TARGET_RE.match(path)
            auths = self.headers.get_all('Authorization') or []
            if kit.flags.get('dup_auth') == 'first_header':      # a wrong front: it takes the first of two headers
                auths = auths[:1]
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
                kit.gate_calls += 1                              # the Gate's decide answers the 429 too: count it first
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

        def propagating(self, a, path) -> bool:
            """Version propagation (run 38140164568): a signed call reaching an isolate with the previous run's keys gets
            the fixed 404. flags: admin_404_first=N (the first N signed calls), admin_404_always, flaky_404=[(method,
            path, skip, times)] (after `skip` such calls, the next `times` of them; path None = any path of that method),
            state_status=S (/_k/state answers S), state_not_json=N (the Nth signed /_k/state call answers a 200 that is
            not JSON), foreign_404=[(method, path, skip, times, kind)] (as flaky_404, but a 404 that is NOT the Worker's
            fixed one: kind 'html' = a text/html page, 'bang' = text/plain "not found!\\n").
            Answered = True."""
            self.signed = True
            with kit.lock:
                kit.signed_calls += 1
                for key in ((self.command, path), (self.command, None)):
                    kit.per_target[key] = kit.per_target.get(key, 0) + 1
                kit.admin_log.append((a.group(1), self.command, path, int(a.group(2)), 0))
                n = kit.signed_calls
            flaky = any(m == self.command and p in (path, None) and skip < kit.per_target[(m, p)] <= skip + times
                        for m, p, skip, times in kit.flags.get('flaky_404', ()))
            foreign = next((kind for m, p, skip, times, kind in kit.flags.get('foreign_404', ())
                            if m == self.command and p in (path, None) and skip < kit.per_target[(m, p)] <= skip + times), None)
            if foreign:
                length = int(self.headers.get('Content-Length') or 0)
                if length:
                    self.rfile.read(length)
                if foreign == 'html':
                    self.send_fixed(404, b'<html><body>404 Not Found</body></html>', 'text/html')
                else:
                    self.send_fixed(404, b'not found!\n')
                return True
            if path == '/_k/state' and kit.per_target[(self.command, path)] == kit.flags.get('state_not_json'):
                self.send_fixed(200, b'ok\n')
                return True
            if n <= kit.flags.get('admin_404_first', 0) or kit.flags.get('admin_404_always') or flaky:
                length = int(self.headers.get('Content-Length') or 0)
                if length:
                    self.rfile.read(length)                      # drain: the client sends the whole body first
                self.nf()
                return True
            if path == '/_k/state' and kit.flags.get('state_status'):
                self.send_json(kit.flags['state_status'], {'ok': False, 'error': 'unavailable'})
                return True
            return False

        def admin(self, path):
            a = ADMIN_RE.match(self.headers.get('Authorization') or '')
            if a and self.propagating(a, path):
                return
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


class ReplayClock:
    """Stands in for the `time` module inside fleet-kit-check.py for one replay. run_replay asks for its late expiry wait as
    (short_life_ms + 2500) / 1000 - (time.monotonic() - t_e): 5 s minus the REAL seconds spent since the invite was made.
    On a slow runner those seconds already exceed 5, so no wait was asked for and the count failed (CI run 39247858912,
    unit 3.13: `0 != 1`, every wait 0.0 to 0.4 s). Here monotonic() is virtual, one millisecond per read, so the wait is
    always almost the full 5 s whatever the runner's speed. time(), sleep() and the rest are the real module's: the kit's
    clock stays real + skew, so the invite still really expires when the fake sleep advances it."""
    TICK = 0.001

    def __init__(self):
        self.t = 0.0

    def monotonic(self) -> float:
        self.t += self.TICK
        return self.t

    def __getattr__(self, name):               # only reached for what is not defined above
        return getattr(time, name)


@contextmanager
def slow_runner(step: float = 10.0):
    """A runner so slow that every read of the process-wide monotonic clock finds `step` more seconds spent. Patched, so
    nothing really sleeps: it is the clock a replay would measure its own elapsed time with, made to show a slow machine."""
    spent = [0.0]
    real = time.monotonic

    def monotonic() -> float:
        spent[0] += step
        return real() + spent[0]
    with mock.patch.object(time, 'monotonic', monotonic):
        yield


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

    OFF = {'enabled': False}
    GOOD = {'settings': {'observability': OFF, 'logpush': False, 'tail_consumers': []},
            'script-settings': {'observability': OFF, 'logpush': False, 'tail_consumers': None},
            'worker': {'observability': OFF, 'logpush': False, 'tail_consumers': [], 'name': 'fleet-kit'}}
    SUB = {'enabled': True, 'previews_enabled': False}
    GONE = object()     # judge(): drop that endpoint (it did not answer) or that key (the endpoint did not report it)

    def judge(self, sub=None, **eps):
        """judge_settings over GOOD with per-endpoint changes: script_settings={'observability': None} merges keys into
        that endpoint's blob (GONE as a value drops the key), script_settings=GONE drops the whole endpoint."""
        blobs = {k: dict(v) for k, v in self.GOOD.items()}
        for name, change in eps.items():
            ep = name.replace('_', '-')
            self.assertIn(ep, blobs)
            if change is self.GONE:
                del blobs[ep]
                continue
            for k, v in change.items():
                if v is self.GONE:
                    blobs[ep].pop(k, None)
                else:
                    blobs[ep][k] = v
        return kc.judge_settings(blobs, dict(self.SUB, **(sub or {})))

    def test_all_three_explicit_off_pass(self):
        self.assertEqual(self.judge(), [])
        full = dict(kc.OBSERVABILITY_OFF)
        self.assertEqual(self.judge(settings={'observability': full}, script_settings={'observability': full},
                                    worker={'observability': full}), [])
        # the GA schema's nullable issues and its other non-`enabled` keys are not "on"
        ga = {'enabled': False, 'head_sampling_rate': 1, 'issues': None, 'redact_query_string': False,
              'logs': {'enabled': False, 'destinations': [], 'invocation_logs': True, 'persist': True}}
        self.assertEqual(self.judge(worker={'observability': ga}), [])

    def test_settings_may_omit_observability_or_not_answer_when_the_other_two_are_off(self):
        self.assertEqual(self.judge(settings={'observability': self.GONE}), [])                         # rule (c)
        self.assertEqual(self.judge(settings=self.GONE), [])

    def test_settings_reporting_observability_is_held_to_off(self):
        for obs in (None, {'enabled': True}, {}, {'enabled': False, 'logs': {'enabled': True}}, 'off'):  # rules (a), (c)
            out = self.judge(settings={'observability': obs})
            self.assertEqual(len(out), 1, (obs, out))
            self.assertTrue(out[0].startswith('settings: observability is not off ('), out)

    def test_script_settings_null_is_the_stored_off_and_passes_only_beside_the_worker_explicit_off(self):  # rules (b), (d)
        # run 38099981335: the off PATCH echoed observability and tail_consumers as null; that is how script-settings
        # stores them, so it is not a refusal there, and not a report either: the GA worker read carries the proof
        stored = {'observability': None, 'tail_consumers': None}
        self.assertEqual(self.judge(script_settings=stored), [])
        self.assertEqual(self.judge(script_settings=stored, worker={'observability': None}),
                         ['worker: observability is not off (observability: null)'])
        self.assertEqual(self.judge(script_settings=stored, worker={'observability': self.GONE}),
                         ['worker: observability not reported'])
        self.assertEqual(self.judge(script_settings=stored, worker={'observability': {'enabled': True}}),
                         ['worker: observability is not off (observability on: enabled)'])
        self.assertEqual(self.judge(script_settings=stored, worker={'observability': {'enabled': False,
                                                                                      'logs': {'enabled': True}}}),
                         ['worker: observability is not off (observability on: logs.enabled)'])
        self.assertEqual(self.judge(script_settings=stored, worker=self.GONE), ['worker: did not answer'])
        self.assertEqual(self.judge(script_settings=stored, worker={'tail_consumers': None}),
                         ['worker: tail_consumers not reported'])
        # script-settings' null tail list is no report of []: with settings silent, only the worker's [] carries it
        self.assertEqual(self.judge(settings=self.GONE, script_settings=stored, worker={'tail_consumers': self.GONE}),
                         ['tail_consumers: not reported (script-settings, worker)', 'worker: tail_consumers not reported'])

    def test_a_null_observability_is_refused_on_every_endpoint_but_script_settings(self):               # rules (a), (c), (d)
        self.assertEqual(self.judge(settings={'observability': None}),
                         ['settings: observability is not off (observability: null)'])
        self.assertEqual(self.judge(script_settings={'observability': None}, settings={'observability': None}),
                         ['settings: observability is not off (observability: null)'])
        self.assertEqual(self.judge(script_settings={'observability': None}, worker={'observability': None}),
                         ['worker: observability is not off (observability: null)'])

    def test_script_settings_with_a_flag_on_under_an_enabled_false_is_refused(self):
        self.assertEqual(self.judge(script_settings={'observability': {'enabled': False, 'logs': {'enabled': True}}}),
                         ['script-settings: observability is not off (observability on: logs.enabled)'])

    def test_script_settings_must_answer_and_say_observability(self):                                  # rule (b)
        self.assertEqual(self.judge(script_settings={'observability': self.GONE}),
                         ['script-settings: observability not reported'])
        self.assertEqual(self.judge(script_settings={'observability': self.GONE, 'tail_consumers': None}),
                         ['script-settings: observability not reported'])     # a missing key is never the stored null
        self.assertEqual(self.judge(script_settings=self.GONE), ['script-settings: did not answer'])

    def test_the_worker_read_must_answer_and_report_an_explicit_off(self):                              # rule (d)
        self.assertEqual(self.judge(worker=self.GONE), ['worker: did not answer'])
        self.assertEqual(self.judge(worker={'observability': self.GONE}), ['worker: observability not reported'])
        self.assertEqual(self.judge(worker={'observability': None}),
                         ['worker: observability is not off (observability: null)'])
        self.assertEqual(self.judge(worker={'observability': {'enabled': True}}),
                         ['worker: observability is not off (observability on: enabled)'])

    def test_the_worker_read_is_held_to_the_logpush_and_tail_rules(self):                               # rule (e)
        self.assertEqual(self.judge(worker={'logpush': True}), ['worker: logpush is on'])
        self.assertEqual(self.judge(worker={'tail_consumers': [{'name': 'x'}]}), ['worker: tail consumers: 1'])
        # the worker read alone can be the one that reports them
        self.assertEqual(self.judge(settings=self.GONE, script_settings={'logpush': self.GONE, 'tail_consumers': self.GONE}), [])

    def test_a_guarded_key_nobody_reports_is_refused_not_passed(self):
        gone = {'logpush': self.GONE, 'tail_consumers': self.GONE}
        self.assertEqual(self.judge(settings=gone, script_settings=gone, worker=gone),
                         ['logpush: not reported (settings, script-settings, worker)',
                          'tail_consumers: not reported (settings, script-settings, worker)',
                          'worker: logpush not reported', 'worker: tail_consumers not reported'])
        # present but not a clean value is a named failure, not a pass; null says nothing, on either key
        nul = {'logpush': None}
        self.assertEqual(self.judge(settings=nul, script_settings=nul, worker=nul),
                         ['logpush: not reported (settings, script-settings, worker)', 'worker: logpush not reported'])
        nul = {'tail_consumers': None}
        self.assertEqual(self.judge(settings=nul, script_settings=nul, worker=nul),
                         ['tail_consumers: not reported (settings, script-settings, worker)',
                          'worker: tail_consumers not reported'])
        self.assertEqual(self.judge(settings={'logpush': 'yes'}), ['settings: logpush is on'])

    def test_the_worker_read_must_report_tail_and_logpush_itself_never_null(self):                       # rule (e)
        for key in ('tail_consumers', 'logpush'):
            self.assertEqual(self.judge(worker={key: self.GONE}), ['worker: %s not reported' % key])
            self.assertEqual(self.judge(worker={key: None}), ['worker: %s not reported' % key])
        # a null in script-settings counts for nothing: settings silent too, so only the worker's [] / false carry it
        self.assertEqual(self.judge(settings=self.GONE, script_settings={'tail_consumers': None, 'logpush': None}), [])
        self.assertEqual(self.judge(settings=self.GONE, script_settings={'tail_consumers': None},
                                    worker={'tail_consumers': self.GONE, 'logpush': self.GONE}),
                         ['tail_consumers: not reported (script-settings, worker)',
                          'worker: logpush not reported', 'worker: tail_consumers not reported'])

    def test_a_truthy_non_boolean_enabled_or_a_wrong_shape_is_never_off(self):                       # rule (a)
        for sub in ('logs', 'traces', 'issues'):
            for v in (1, 'true', 'True', 'yes', {'x': 1}, [1], None, 0, 'false', 2.0, {}):
                out = self.judge(script_settings={'observability': {'enabled': False, sub: {'enabled': v}}})
                self.assertEqual(out, ['script-settings: observability is not off (observability.%s.enabled: not false)'
                                       % sub], (sub, v))
        for sub in ('logs', 'traces'):
            for v in ('on', None, [], 1):
                self.assertEqual(self.judge(worker={'observability': {'enabled': False, sub: v}}),
                                 ['worker: observability is not off (observability.%s: not an object)' % sub], (sub, v))
        self.assertEqual(self.judge(worker={'observability': {'enabled': False, 'issues': 'on'}}),
                         ['worker: observability is not off (observability.issues: not an object)'])
        self.assertEqual(self.judge(worker={'observability': {'enabled': False, 'issues': None}}), [])  # schema: nullable
        self.assertEqual(self.judge(worker={'observability': {'enabled': False, 'logs': {'destinations': [{'enabled': 1}]}}}),
                         ['worker: observability is not off (observability.logs.destinations[0].enabled: not false)'])

    def test_each_bad_setting_is_named_with_its_endpoint(self):
        self.assertIn('settings: tail consumers: 1', self.judge(settings={'tail_consumers': [{'service': 'x'}]}))
        self.assertIn('script-settings: tail consumers: unreadable', self.judge(script_settings={'tail_consumers': 'x'}))
        self.assertIn('script-settings: logpush is on', self.judge(script_settings={'logpush': True}))
        self.assertIn('workers.dev is not on', self.judge(sub={'enabled': False}))
        self.assertIn('workers.dev is not on', self.judge(sub={'enabled': None}))
        self.assertIn('preview URLs are not off', self.judge(sub={'previews_enabled': True}))
        self.assertIn('preview URLs are not off', kc.judge_settings(self.GOOD, {'enabled': True}))  # unknown is not off

    def test_a_refused_observability_names_what_is_on_and_nothing_else(self):
        def why(obs):
            out = self.judge(script_settings={'observability': obs})
            self.assertEqual(len(out), 1, out)                         # exactly one line, naming the endpoint
            head = 'script-settings: observability is not off ('
            self.assertTrue(out[0].startswith(head) and out[0].endswith(')'), out)
            return out[0][len(head):-1]
        self.assertEqual(why({'enabled': True}), 'observability on: enabled')
        self.assertEqual(why({'enabled': False, 'issues': {'enabled': True}, 'logs': {'enabled': True, 'persist': True},
                              'traces': {'enabled': False}}), 'observability on: issues.enabled, logs.enabled')
        self.assertEqual(why({'enabled': True, 'logs': {'enabled': True}}), 'observability on: enabled, logs.enabled')
        self.assertEqual(why({'enabled': False, 'logs': {'destinations': [{'enabled': True}]}}),
                         'observability on: logs.destinations[0].enabled')
        self.assertEqual(why({}), 'observability.enabled: missing')
        self.assertEqual(why({'logs': {'enabled': False}}), 'observability.enabled: missing')
        self.assertEqual(why({'enabled': None}), 'observability.enabled: not false')
        self.assertEqual(why({'enabled': 'false', 'head_sampling_rate': 1}), 'observability.enabled: not false')
        self.assertEqual(self.judge(settings={'observability': None}),     # script-settings' null is its stored off (b)
                         ['settings: observability is not off (observability: null)'])
        self.assertEqual(why([]), 'observability: not an object (list)')
        self.assertEqual(why('on'), 'observability: not an object (str)')

    def test_the_detail_never_carries_a_value_from_the_read_back(self):
        out = self.judge(worker={'observability': {'enabled': False, 'head_sampling_rate': 0.4242,
                                                   'logs': {'enabled': True, 'destinations': ['acct-SECRET']}}})
        self.assertEqual(out, ['worker: observability is not off (observability on: logs.enabled)'])
        self.assertEqual(self.judge(settings={'observability': 'acct-SECRET'}),
                         ['settings: observability is not off (observability: not an object (str))'])

    def test_the_detail_line_is_escaped_and_capped(self):
        out = self.judge(settings={'observability': {'enabled': False, 'a\nb::error::x': {'enabled': True}}})
        self.assertEqual(out, ['settings: observability is not off (observability on: a\\nb::error::x.enabled)'])
        many = {'enabled': False, **{'k%d' % i: {'enabled': True} for i in range(100)}}
        out = self.judge(settings={'observability': many})
        self.assertIn('(+92 more)', out[0])
        self.assertLess(len(out[0]), 340)
        long_key = {'enabled': False, 'x' * 5000: {'enabled': True}}
        self.assertLess(len(self.judge(settings={'observability': long_key})[0]), 340)

    def test_old_verdicts_hold_on_every_endpoint(self):
        for ep in ('settings', 'script_settings', 'worker'):
            for obs, refused in [({'enabled': False}, False), ({'enabled': True}, True), ({}, True), ([], True),
                                 (None, ep != 'script_settings'),          # rule (b): script-settings' stored off
                                 ({'enabled': False, 'logs': {'enabled': True}}, True), ({'enabled': 0}, True),
                                 ({'enabled': False, 'logs': {'enabled': False}}, False)]:
                out = self.judge(**{ep: {'observability': obs}})
                self.assertEqual(any('observability is not off' in b for b in out), refused, (ep, obs))
        self.assertIn('settings: logpush is on', self.judge(settings={'logpush': True}))  # a refusal elsewhere adds nothing else
        self.assertEqual(len(self.judge(settings={'logpush': True})), 1)
        self.assertIn('worker: observability is not off (observability on: enabled)',
                      self.judge(worker={'observability': {'enabled': True}}))  # any source can veto

    def test_the_off_constant_is_the_wrangler_jsonc_block_in_both_envs(self):
        text = (ROOT / 'kit/wrangler.jsonc').read_text(encoding='utf-8')
        cfg = json.loads('\n'.join(l for l in text.splitlines() if not l.strip().startswith('//')))  # as kit/admin.test.js
        self.assertEqual(cfg['observability'], kc.OBSERVABILITY_OFF)
        self.assertEqual(cfg['env']['staging']['observability'], kc.OBSERVABILITY_OFF)
        self.assertEqual(kc.SETTINGS_OFF, {'observability': cfg['observability'], 'logpush': False, 'tail_consumers': []})
        self.assertEqual(kc.SETTINGS_OFF, {'observability': cfg['env']['staging']['observability'],
                                           'logpush': cfg['env']['staging']['logpush'], 'tail_consumers': []})

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

    def test_the_real_get_path_goes_through_the_no_redirect_opener(self):
        """cf_get with the REAL kc._open: a 302/307 is answered as a non-answer, /other is never asked, the token goes
        once. Stock urllib follows a GET redirect and re-sends Authorization, so this fails if _open bypasses _OPENER."""
        for code in (301, 302, 303, 307, 308):
            with redirect_stdout(io.StringIO()) as buf:
                got, seen, https = through_the_real_open(code, lambda: kc.cf_get('/x/settings', 'SECRETTOKEN'), {})
            self.assertIsNone(got, code)
            self.assertEqual((seen, https), ([('GET', '/start', 'Bearer SECRETTOKEN')], []), code)
            self.assertIn('HTTP %d' % code, buf.getvalue())
            self.assertNotIn('SECRETTOKEN', buf.getvalue())


    ACCOUNT = 'a' * 32
    WORKER_READ = {'id': 'x', 'name': 'fleet-kit', 'observability': {'enabled': False, 'logs': {'enabled': False}},
                   'logpush': False, 'tail_consumers': [], 'subdomain': {'enabled': True, 'previews_enabled': False}}
    GOOD_ANSWERS = {'/settings': {'observability': {'enabled': False}, 'logpush': False, 'tail_consumers': []},
                    '/script-settings': {'observability': {'enabled': False}, 'logpush': False},
                    '/worker': WORKER_READ,
                    '/subdomain': {'enabled': True, 'previews_enabled': False}}

    def cf(self, answers):
        """Run check_settings with kc._open replaced; answers maps a path tail ('/worker' = the GA read) to a result dict,
        an int HTTP code, 'fail' (success: false), or an exception. Returns (outcome, urls asked, authorization headers sent)."""
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
            self.assertEqual(req.get_method(), 'GET')
            key = '/worker' if '/workers/workers/' in req.full_url else '/' + req.full_url.rsplit('/', 1)[-1]
            a = answers[key]
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

    def test_the_settings_gate_asks_the_four_exact_endpoints_with_the_token(self):
        out, asked, auths = self.cf(self.GOOD_ANSWERS)
        api = 'https://api.cloudflare.com/client/v4/accounts/%s/workers/' % self.ACCOUNT
        base = api + 'scripts/fleet-kit'
        self.assertEqual(asked, [base + '/settings', base + '/script-settings', api + 'workers/fleet-kit', base + '/subdomain'])
        self.assertEqual(set(auths), {'Bearer TOKEN'})
        self.assertEqual(out, {'worker': 'fleet-kit', 'sources': 3})

    def test_the_settings_gate_tolerates_settings_failing_but_not_script_settings_the_worker_or_the_subdomain(self):
        for bad in (404, 'fail'):
            out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/settings': bad}))
            self.assertEqual(out, {'worker': 'fleet-kit', 'sources': 2}, bad)
            out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/script-settings': bad}))
            self.assertIsInstance(out, kc.Refused, bad)
            self.assertIn('script-settings: did not answer', str(out))
        for bad in (403, 404, 500, 'fail'):                                    # the GA read: non-200 is a refusal
            out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/worker': bad}))
            self.assertIsInstance(out, kc.Refused, bad)
            self.assertIn('worker: did not answer', str(out))
        out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/settings': 500, '/script-settings': 403, '/worker': 403}))
        self.assertIsInstance(out, kc.Refused)
        self.assertIn('did not answer', str(out))
        for sub in (404, 'fail'):
            out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/subdomain': sub}))
            self.assertIsInstance(out, kc.Refused, sub)
            self.assertIn('did not answer', str(out))

    def test_the_settings_gate_refuses_the_worker_read_absent_null_or_on(self):
        for obs, why in (('ABSENT', 'worker: observability not reported'),
                         (None, 'worker: observability is not off (observability: null)'),
                         ({'enabled': True}, 'worker: observability is not off (observability on: enabled)')):
            read = {k: v for k, v in self.WORKER_READ.items() if k != 'observability'}
            if obs != 'ABSENT':
                read['observability'] = obs
            out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/worker': read}))
            self.assertIsInstance(out, kc.Refused, obs)
            self.assertIn(why, str(out))

    def test_the_settings_gate_takes_script_settings_null_only_beside_the_worker_explicit_off(self):
        # run 38099981335: settings-off's PATCH of the all-off record echoed observability and tail_consumers as null,
        # the form script-settings stores them in; the GA worker read is the explicit-off proof
        stored = {'observability': None, 'logpush': False, 'tail_consumers': None}
        out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/script-settings': stored}))
        self.assertEqual(out, {'worker': 'fleet-kit', 'sources': 3})
        worker = lambda **kw: {k: v for k, v in {**self.WORKER_READ, **kw}.items() if v != 'ABSENT'}  # noqa: E731
        for read, why in ((worker(observability=None), 'worker: observability is not off (observability: null)'),
                          (worker(observability='ABSENT'), 'worker: observability not reported'),
                          (worker(observability={'enabled': True}), 'worker: observability is not off (observability on: enabled)'),
                          (worker(tail_consumers=None), 'worker: tail_consumers not reported'),
                          (403, 'worker: did not answer')):
            out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/script-settings': stored, '/worker': read}))
            self.assertIsInstance(out, kc.Refused, why)
            self.assertEqual(str(out), 'settings of fleet-kit: ' + why)
        out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/script-settings': {'logpush': False, 'tail_consumers': None}}))
        self.assertEqual(str(out), 'settings of fleet-kit: script-settings: observability not reported')
        out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/script-settings': stored,
                                                     '/settings': {'observability': None, 'logpush': False}}))
        self.assertEqual(str(out), 'settings of fleet-kit: settings: observability is not off (observability: null)')

    def test_the_settings_gate_refuses_a_network_failure_and_names_a_bad_answer(self):
        for exc in (urllib.error.URLError('down'), TimeoutError(), ValueError('bad json')):
            for ep in ('/settings', '/worker'):
                out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{ep: exc}))
                self.assertIsInstance(out, kc.Refused, repr(exc))
        out, *_ = self.cf(dict(self.GOOD_ANSWERS, **{'/script-settings': {'observability': {'enabled': False}, 'logpush': True}}))
        self.assertIn('script-settings: logpush is on', str(out))
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


class SettingsOff(unittest.TestCase):
    """settings-off: the PATCH of the script-settings record, through the CLI with kc._open replaced."""
    ACCOUNT = 'b' * 32
    TOKEN = 'SECRETTOKEN-0123456789'
    URL = 'https://api.cloudflare.com/client/v4/accounts/%s/workers/scripts/fleet-kit-staging/script-settings' % ACCOUNT
    ECHO = {'observability': dict(kc.OBSERVABILITY_OFF), 'logpush': False, 'tail_consumers': [], 'tags': []}

    def run_cli(self, answer, worker='fleet-kit-staging', env=None):
        """answer: (status, body bytes) | (status, doc) | an int HTTP error code | an exception. Returns (rc, output, requests)."""
        sent = []

        class Reply:
            def __init__(self, status, raw):
                self.status, self.raw = status, raw

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return self.raw

        def fake_open(req, timeout):
            sent.append(req)
            if isinstance(answer, BaseException):
                raise answer
            if isinstance(answer, int):
                raise urllib.error.HTTPError(req.full_url, answer, 'x', {}, io.BytesIO(b'{"errors":["BODYSECRET"]}'))
            status, body = answer
            return Reply(status, body if isinstance(body, bytes) else json.dumps(body).encode())

        buf = io.StringIO()
        old, kc._open = kc._open, fake_open
        environ = {'CLOUDFLARE_API_TOKEN': self.TOKEN, 'CLOUDFLARE_ACCOUNT_ID': self.ACCOUNT} if env is None else env
        saved = {k: os.environ.get(k) for k in ('CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID')}
        try:
            for k in saved:
                os.environ.pop(k, None)
            os.environ.update(environ)
            with redirect_stdout(buf):
                rc = kc.main(['settings-off', worker])
        finally:
            kc._open = old
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        out = buf.getvalue()
        self.assertNotIn(self.TOKEN, out)                  # no token in any output, pass or refusal
        self.assertNotIn('SECRET', out.replace('REFUSED', ''))
        return rc, out, sent

    def refused(self, answer, fragment):
        rc, out, sent = self.run_cli(answer)
        self.assertEqual(rc, 1, out)
        last = out.strip().splitlines()[-1]
        self.assertTrue(last.startswith('REFUSED settings-off: PATCH script-settings'), last)
        self.assertIn(fragment, last)
        return last

    def test_the_request_is_a_patch_of_exactly_the_off_record_as_json(self):
        rc, out, sent = self.run_cli((200, {'success': True, 'result': self.ECHO}))
        self.assertEqual(rc, 0, out)
        # the success line claims only what the echo measures (an accepted PATCH), never "off ... echoed back"
        self.assertIn('settings-off of fleet-kit-staging: PATCH accepted', out)
        self.assertIn("the settings gate's GA read is the proof", out)
        self.assertNotIn('echoed back', out)
        self.assertEqual(len(sent), 1)
        req = sent[0]
        self.assertEqual(req.get_method(), 'PATCH')
        self.assertEqual(req.full_url, self.URL)
        self.assertEqual(req.get_header('Content-type'), 'application/json')
        self.assertEqual(req.get_header('Authorization'), 'Bearer ' + self.TOKEN)
        self.assertEqual(json.loads(req.data), {'observability': kc.OBSERVABILITY_OFF, 'logpush': False, 'tail_consumers': []})
        self.assertEqual(json.loads(req.data), kc.SETTINGS_OFF)

    def test_the_measured_echo_of_null_observability_and_tail_passes_but_a_null_logpush_does_not(self):
        # run 38099981335 (release 1944de0): this PATCH answered 200 success true and echoed observability: null,
        # tail_consumers: null, logpush: false, the stored form of the off record it had just written
        for echo in ({'observability': None, 'logpush': False, 'tail_consumers': None, 'tags': []},
                     dict(self.ECHO, observability=None), dict(self.ECHO, tail_consumers=None)):
            rc, out, _ = self.run_cli((200, {'success': True, 'result': echo}))
            self.assertEqual(rc, 0, (echo, out))
        self.refused((200, {'success': True, 'result': dict(self.ECHO, logpush=None)}), 'logpush echoed null')
        self.refused((200, {'success': True, 'result': dict(self.ECHO, observability=None, tail_consumers=None,
                                                            logpush=None)}), 'the echo is not off: logpush echoed null')
        # the stored null is no licence for a missing key or for an observability that is on
        self.refused((200, {'success': True, 'result': {'logpush': False, 'tail_consumers': None}}), 'observability not echoed')
        self.refused((200, {'success': True, 'result': {'observability': None, 'logpush': False}}), 'tail_consumers not echoed')
        self.refused((200, {'success': True, 'result': dict(self.ECHO, observability={'enabled': True}, tail_consumers=None)}),
                     'the echo is not off: observability on: enabled')
        self.refused((200, {'success': True, 'result': dict(self.ECHO, observability={'enabled': False, 'logs': {'enabled': True}},
                                                            tail_consumers=None)}),
                     'the echo is not off: observability on: logs.enabled')

    def test_an_http_error_or_a_status_other_than_200_is_refused(self):
        for code in (400, 403, 404, 500):
            self.refused(code, 'HTTP %d' % code)
        for status in (201, 202, 204):
            self.refused((status, {'success': True, 'result': self.ECHO}), 'HTTP %d, not 200' % status)

    def test_a_network_failure_or_a_non_json_answer_is_refused(self):
        self.refused(urllib.error.URLError('down'), 'failed (URLError)')
        self.refused(TimeoutError(), 'failed (TimeoutError)')
        self.refused((200, b'<html>SECRET</html>'), 'failed (JSONDecodeError)')
        self.refused((200, b'\xff\xfe'), 'failed')

    def test_success_false_or_no_result_is_refused(self):
        self.refused((200, {'success': False, 'result': self.ECHO}), 'success is not true')
        self.refused((200, {'result': self.ECHO}), 'success is not true')
        self.refused((200, [1]), 'success is not true')
        self.refused((200, {'success': True}), 'no result echoed')
        self.refused((200, {'success': True, 'result': None}), 'no result echoed')

    def test_an_echo_that_is_not_off_is_refused_by_key_never_by_value(self):
        echo = lambda **kw: (200, {'success': True, 'result': {**self.ECHO, **kw}})  # noqa: E731
        self.refused(echo(observability={'enabled': True, 'destinations': ['acct-SECRET']}), 'observability on: enabled')
        self.refused(echo(observability={'enabled': False, 'logs': {'enabled': True}}), 'observability on: logs.enabled')
        self.refused(echo(observability={}), 'observability.enabled: missing')
        self.refused((200, {'success': True, 'result': {'logpush': False, 'tail_consumers': []}}), 'observability not echoed')
        self.refused(echo(logpush=True), 'logpush is not false')
        self.refused(echo(logpush=0), 'logpush is not false')
        self.refused((200, {'success': True, 'result': {'observability': kc.OBSERVABILITY_OFF, 'tail_consumers': []}}),
                     'logpush not echoed')
        self.refused(echo(tail_consumers=[{'name': 'SECRET-tail'}]), 'tail_consumers is not empty')
        self.refused(echo(tail_consumers={}), 'tail_consumers is not empty')
        self.refused((200, {'success': True, 'result': {'observability': kc.OBSERVABILITY_OFF, 'logpush': False}}),
                     'tail_consumers not echoed')
        self.refused(echo(observability={'enabled': False, 'logs': {'enabled': 'true'}}),
                     'observability.logs.enabled: not false')

    def test_a_redirect_is_not_followed(self):
        """The PATCH through the REAL kc._open: a 302/307 is a refusal and the Location is never asked. Stock urllib never
        follows a PATCH redirect either (it raises), so this test alone cannot tell NoRedirect is there; the GET test
        (test_the_real_get_path_goes_through_the_no_redirect_opener) is the one that does."""
        env = {'CLOUDFLARE_API_TOKEN': self.TOKEN, 'CLOUDFLARE_ACCOUNT_ID': self.ACCOUNT}
        for code in (302, 307):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc, seen, https = through_the_real_open(code, lambda: kc.main(['settings-off', 'fleet-kit-staging']), env)
            self.assertEqual(rc, 1, code)
            self.assertIn('HTTP %d' % code, buf.getvalue())
            self.assertNotIn(self.TOKEN, buf.getvalue())
            self.assertEqual((seen, https), ([('PATCH', '/start', 'Bearer ' + self.TOKEN)], []), code)  # /other never asked

    def test_a_dropped_read_or_a_too_deep_answer_is_a_named_refusal_on_both_verbs(self):
        class Reply:
            status = 200

            def __init__(self, what):
                self.what = what

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                if isinstance(self.what, BaseException):
                    raise self.what
                return self.what
        env = {'CLOUDFLARE_API_TOKEN': self.TOKEN, 'CLOUDFLARE_ACCOUNT_ID': self.ACCOUNT}
        saved = {k: os.environ.get(k) for k in env}
        old = kc._open
        try:
            os.environ.update(env)
            for what, name in ((http.client.IncompleteRead(b'x' * 10, 5), 'IncompleteRead'),
                               (ConnectionResetError(), 'ConnectionResetError'),
                               (http.client.RemoteDisconnected('x'), 'RemoteDisconnected'),
                               (b'[' * 200000 + b']' * 200000, 'RecursionError')):
                for cmd in ('settings', 'settings-off'):
                    kc._open = lambda req, timeout, what=what: Reply(what)
                    buf = io.StringIO()
                    with redirect_stdout(buf):
                        rc = kc.main([cmd, 'fleet-kit-staging'])
                    last = buf.getvalue().strip().splitlines()[-1]
                    self.assertEqual(rc, 1, (cmd, name))
                    self.assertTrue(last.startswith('REFUSED %s' % cmd) and last.endswith('(%s)' % name), (cmd, last))
                    self.assertNotIn(self.TOKEN, buf.getvalue())
        finally:
            kc._open = old
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_bad_ids_a_bad_host_or_no_credentials_send_nothing(self):
        for worker in ('Fleet Kit', 'x' * 64, 'a/b'):
            rc, out, sent = self.run_cli((200, {'success': True, 'result': self.ECHO}), worker=worker)
            self.assertEqual((rc, sent), (1, []), worker)
        rc, out, sent = self.run_cli((200, {}), env={'CLOUDFLARE_API_TOKEN': self.TOKEN, 'CLOUDFLARE_ACCOUNT_ID': 'short'})
        self.assertEqual((rc, sent), (1, []))
        rc, out, sent = self.run_cli((200, {}), env={'CLOUDFLARE_ACCOUNT_ID': self.ACCOUNT})
        self.assertEqual((rc, sent), (1, []))
        self.assertIn('settings-off: CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID are needed', out)
        old = kc.CF_API
        for bad in ('http://api.cloudflare.com/client/v4', 'https://api.cloudflare.com.evil.example/client/v4'):
            kc.CF_API = bad
            try:
                rc, out, sent = self.run_cli((200, {'success': True, 'result': self.ECHO}))
            finally:
                kc.CF_API = old
            self.assertEqual((rc, sent), (1, []), bad)
            self.assertIn('not api.cloudflare.com over https', out)


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

    def replay(self, run=None, real_clock=False, **flags):
        """Runs the replay against a fake kit (kept as self.kit, so a refused replay can still be inspected). Its own elapsed
        time is measured on a ReplayClock, not on the runner's clock, unless real_clock (only the slow-runner control)."""
        kit = self.kit = FakeKit(self.pubs, **flags)
        # the readiness streak is the real one (10); only the waits are short here
        kw = dict(big_mib=12, cut_wait=0.4, short_life_ms=2500, ready_spacing=0.0, retry_wait=0.0, log=lambda *_: None)
        kw.update(run or {})
        # the expiry wait moves the kit's clock (no real wait); a `sleep` in `run` is the one every shorter wait really uses
        kw['sleep'] = kit.fake_sleep(kw.get('sleep', time.sleep))
        with Served(kit) as base, (nullcontext() if real_clock else mock.patch.object(kc, 'time', ReplayClock())):
            client = kc.Client(base, allow_http=True)
            lines = kc.run_replay(client, kc.Admin(client, self.gate_dir), **kw)
        return kit, lines

    def refused(self, fragment, run=None, **flags):
        with self.assertRaises(kc.Refused) as why:
            self.replay(run, **flags)
        self.assertIn(fragment, str(why.exception))
        return why.exception

    # -- version propagation (run 38140164568 attempt 1) ---------------------------------------------------------------
    def test_readiness_waits_out_the_fixed_404_and_needs_ten_200s_in_a_row(self):
        kit, lines = self.replay(admin_404_first=4)
        text = '\n'.join(lines)
        self.assertRegex(text, r'readiness: 10 consecutive signed 200s from /_k/state after 14 tries, 4 404s seen, '
                               r'[0-9.]+ s')
        self.assertIn("admin retries on the Worker's fixed 404: 0\n", text + '\n')
        self.assertEqual(kit.fails, 30)
        # a 404 inside the run resets it: 3 good, one 404, then 10 more
        _, lines = self.replay(flaky_404=[('GET', '/_k/state', 3, 1)])
        self.assertIn('after 14 tries, 1 404s seen', '\n'.join(lines))
        _, lines = self.replay()
        self.assertIn('after 10 tries, 0 404s seen', '\n'.join(lines))

    def test_readiness_refuses_a_staging_that_never_serves_this_runs_keys(self):
        why = self.refused(kc.PROPAGATION + ': no 10 consecutive 200s within 0 s (', {'ready_timeout': 0.3,
                                                                                       'ready_spacing': 0.01},
                           admin_404_always=True)
        self.assertRegex(str(why), r'\(\d+ tries, (\d+) 404s seen, longest run 0\)$')
        tries, seen = re.search(r'\((\d+) tries, (\d+) 404s', str(why)).groups()
        self.assertEqual(tries, seen)
        self.assertGreater(int(tries), 1)

    def test_readiness_refuses_any_other_status_at_once(self):
        why = self.refused("readiness: try 1 answered 503, expected 200 or the Worker's fixed 404 (1 tries, 0 404s seen,",
                           state_status=503)
        self.assertNotIn(kc.PROPAGATION, str(why))      # a 503 is a Gate or platform fault, not a key in flight

    def test_readiness_spaces_its_tries_and_checks_each_200_is_json(self):
        rec: list[float] = []

        def sleep(s):
            rec.append(s)
            time.sleep(s)
        # distinct values, so the replay's other sleeps (cut_wait, late, the 503 loop) cannot be mistaken for them
        run = {'ready_spacing': 0.0011, 'retry_wait': 0.0022, 'sleep': sleep}
        self.replay(run)
        self.assertEqual(rec.count(0.0011), 9)          # 10 tries, a wait between each pair, none after the streak
        self.assertEqual(rec.count(0.0022), 0)
        rec.clear()
        self.replay(run, admin_404_first=2)             # 2 404s then 10 200s: a wait after every try but the last
        self.assertEqual(rec.count(0.0011), 11)
        # a 200 that is not JSON mid-streak refuses, even though its status is right
        self.refused('readiness try 5: the reply is not JSON', state_not_json=5)

    def test_readiness_runs_before_the_first_upload(self):
        kit = FakeKit(self.pubs, admin_404_always=True)
        with Served(kit) as base, self.assertRaises(kc.Refused):
            client = kc.Client(base, allow_http=True)
            kc.run_replay(client, kc.Admin(client, self.gate_dir), big_mib=1, ready_timeout=0.2, ready_spacing=0.01,
                          log=lambda *_: None)
        calls = [(m, p) for _, m, p, _, _ in kit.admin_log]
        self.assertEqual(set(calls[:-1]), {('GET', '/_k/state')})
        self.assertEqual(calls[-1], ('PUT', '/_k/floor'))              # only the best-effort cleanup after it
        self.assertEqual(kit.files, {})

    def test_a_2xx_admin_call_that_meets_the_fixed_404_once_is_retried_and_counted(self):
        # run 38140164568 attempt 1's vector: the identical re-upload (the second PUT of s1) answered the fixed 404
        kit, lines = self.replay(flaky_404=[('PUT', '/_k/file/900000001/bundle.tar', 1, 1)])
        text = '\n'.join(lines)
        self.assertIn("admin retries on the Worker's fixed 404: 1 (identical re-upload)", text)
        self.assertIn('identical re-upload: 200', text)
        tss = [ts for _, m, p, ts, _ in kit.admin_log if (m, p) == ('PUT', '/_k/file/900000001/bundle.tar')]
        self.assertEqual(len(tss), 4)                       # small, re-upload (404), re-upload again, overwrite
        self.assertLess(tss[1], tss[2])                     # the retry signed a fresh ts
        # the bound: three retries still pass, the fourth 404 refuses
        _, lines = self.replay(flaky_404=[('PUT', '/_k/file/900000001/bundle.tar', 1, 3)])
        self.assertIn("fixed 404: 3 (identical re-upload, identical re-upload, identical re-upload)", '\n'.join(lines))
        self.refused("identical re-upload: status 404 (the Worker's fixed 404) on 4 tries, expected 200; " + kc.PROPAGATION,
                     flaky_404=[('PUT', '/_k/file/900000001/bundle.tar', 1, 4)])

    def test_each_retry_waits_retry_wait(self):
        rec: list[float] = []

        def sleep(s):
            rec.append(s)
            time.sleep(s)
        run = {'ready_spacing': 0.0011, 'retry_wait': 0.0022, 'sleep': sleep}
        self.replay(run, flaky_404=[('PUT', '/_k/file/900000001/bundle.tar', 1, 2)])
        self.assertEqual(rec.count(0.0022), 2)          # one wait per counted retry
        rec.clear()
        with self.assertRaises(kc.Refused):
            self.replay(run, flaky_404=[('PUT', '/_k/file/900000001/bundle.tar', 1, 4)])
        self.assertEqual(rec.count(0.0022), 3)          # retry_max waits, none after the last refused try

    def test_only_the_workers_exact_404_is_retried(self):
        # a 404 to a signed 2xx call that is not kit/worker.js fixed(404) is not propagation: one try, no retry, refused
        for kind in ('html', 'bang'):
            with self.subTest(kind=kind):
                with self.assertRaises(kc.Refused) as why:
                    self.replay(foreign_404=[('PUT', '/_k/file/900000001/bundle.tar', 1, 1, kind)])
                self.assertIn('identical re-upload: status 404, expected 200', str(why.exception))
                self.assertNotIn(kc.PROPAGATION, str(why.exception))
        kit = FakeKit(self.pubs, foreign_404=[('PUT', '/_k/file/900000001/bundle.tar', 1, 1, 'bang')])
        with Served(kit) as base, self.assertRaises(kc.Refused):
            client = kc.Client(base, allow_http=True)
            kc.run_replay(client, kc.Admin(client, self.gate_dir), big_mib=1, ready_spacing=0.0, retry_wait=0.0,
                          log=lambda *_: None)
        tss = [ts for _, m, p, ts, _ in kit.admin_log if (m, p) == ('PUT', '/_k/file/900000001/bundle.tar')]
        self.assertEqual(len(tss), 2)                   # small, then the re-upload once: never sent again

    def test_every_2xx_admin_call_takes_the_retry_and_the_replay_keeps_its_ts(self):
        targets = [('upload small', 'PUT', '/_k/file/900000001/bundle.tar', 0), ('upload big', 'PUT', '/_k/file/900000002/bundle.tar', 0),
                   ('gateway pair', 'PUT', '/_k/gateway/900000001', 0), ('floor 0', 'PUT', '/_k/floor', 0),
                   ('invite W', 'POST', '/_k/invite', 0), ('floor up', 'PUT', '/_k/floor', 4),
                   ('revoke', 'DELETE', None, 0), ('replay first', 'PUT', '/_k/floor', 2)]
        for label, method, path, skip in targets:
            with self.subTest(label=label):
                kit, lines = self.replay(flaky_404=[(method, path, skip, 1)])
                self.assertIn("fixed 404: 1 (%s)" % label, '\n'.join(lines))
        # (PUT /_k/floor: floor 0, wrong role, replay first, replay second, ...) the replay vector repeats the ts that
        # was served, not the one that met the 404
        floor = [(ts, st) for role, m, p, ts, st in kit.admin_log if (role, m, p) == ('upload', 'PUT', '/_k/floor')]
        self.assertEqual([st for _, st in floor[:4]], [200, 404, 200, 409])
        self.assertLess(floor[1][0], floor[2][0])
        self.assertEqual(floor[2][0], floor[3][0])

    def test_calls_that_expect_a_refusal_get_exactly_one_try(self):
        # each of these fakes answers the fixed 404 once and the expected answer on a second try: no retry, so refused
        for label, method, path, skip, fragment in (
                ('overwrite', 'PUT', '/_k/file/900000001/bundle.tar', 2, 'overwrite: status 404, expected 409'),
                ('wrong bytes', 'PUT', '/_k/file/900000003/bundle.tar', 0, 'wrong bytes: status 404, expected 422'),
                ('rollback', 'PUT', '/_k/gateway/900000000', 0, 'gateway rollback: status 404, expected 409'),
                ('ceiling', 'POST', '/_k/invite', 4, 'ceiling downloads: status 404, expected 422'),
                ('replay second', 'PUT', '/_k/floor', 3, 'replay second: status 404, expected 409')):
            with self.subTest(label=label):
                with self.assertRaises(kc.Refused) as why:
                    self.replay(flaky_404=[(method, path, skip, 1)])
                self.assertIn(fragment, str(why.exception))
        # wrong role (403 or 404 both fine) and stale (404) take what they get: one call each, even on the fixed 404
        kit, lines = self.replay(flaky_404=[('PUT', '/_k/floor', 1, 1)])        # the wrong-role call meets it
        log = kit.admin_log
        self.assertEqual(sum(1 for role, m, p, _, _ in log if (role, m, p) == ('gateway', 'PUT', '/_k/floor')), 1)
        stale = [st for role, m, p, ts, st in log if (m, p) == ('GET', '/_k/state') and ts < kit.now() - 300000]
        self.assertEqual(stale, [404])
        # 10 ready, the stale one, the front reject's zero signature: nothing sent again
        self.assertEqual(sum(1 for _, m, p, _, _ in log if (m, p) == ('GET', '/_k/state')), 12)
        self.assertEqual(sum(1 for *_, st in log if st == 409), 3)     # overwrite, rollback, replay second: once each
        self.assertIn("fixed 404: 0", '\n'.join(lines))

    def test_the_replay_passes_against_a_worker_that_follows_the_spec_and_cleans_up(self):
        kit, lines = self.replay()
        text = '\n'.join(lines)
        self.assertIn('vectors passed', text)
        self.assertIn('429 after 30 failures', text)
        self.assertIn('(a) client cuts: 2, count restored: 2', text)
        self.assertIn('(c) wrong bytes: 422 (R2 checksum), overwrite: 409 (Worker head guard; the R2 onlyIf wildcard is not separately observable), identical re-upload: 200', text)
        self.assertIn('not CPU time', text)
        self.assertRegex(text, r'404 answers compared: \d+, identical')
        self.assertRegex(text, r"Cloudflare's cf-nel report-to on 0 of \d+ \(")   # none here: the summary says so
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

    def test_the_replay_takes_cloudflares_identical_edge_400_for_both_duplicate_authorization_cases(self):
        kit, lines = self.replay(dup_auth='edge')
        text = '\n'.join(lines)
        self.assertIn("Cloudflare's edge 400 for both cases, identical", text)
        self.assertEqual(kit.fails, 30)
        _, lines = self.replay()
        self.assertIn("duplicate Authorization: the Worker's 404 for both cases", '\n'.join(lines))
        self.assertIn("robots: the Worker's 404 for both fetches (robots; robots, second fetch)", '\n'.join(lines))

    def test_the_replay_refuses_any_other_answer_to_the_duplicate_authorization_pair(self):
        for mode, fragment in (('edge_live_only', 'answered 400'),                     # mixed 400 / 404
                               # the refusal names what the answer lacks; server=cloudflare on these, as on the live host
                               ('json400', "edge 400 page (lacks content-type, cache-control, marker; server=cloudflare "
                                           "content-type=application/json"),
                               ('text400', "edge 400 page (lacks content-type, cache-control; server=cloudflare "
                                           "content-type=text/plain"),
                               ('edge_worker_cache', "edge 400 page (lacks cache-control;"),
                               ('edge_not_cloudflare', "edge 400 page (lacks server; server=nginx"),
                               # a front that took the first header: the live code opens gateway.json, the unknown does not
                               ('first_header', '"two authorization headers" answered 200'),
                               ('edge_len', 'headers differ: content-length'),
                               ('edge_body', 'body differs'),
                               ('other_404', 'differs')):                              # a 404 pair is still held to the 404
            with self.subTest(mode=mode), self.assertRaises(kc.Refused) as why:
                self.replay(dup_auth=mode)
            self.assertIn(fragment, str(why.exception))
            self.assertIn('two authorization headers' if mode in ('json400', 'text400', 'edge_worker_cache',
                                                                  'edge_not_cloudflare', 'other_404')
                          else 'duplicate authorization', str(why.exception))
            self.assertNotIn('Bad Request', str(why.exception))                       # a refusal never carries a body

    def test_only_the_duplicate_authorization_cases_may_take_the_edge_400(self):
        self.refused('root: status 400, expected 404', edge_400_on='/')
        self.refused('root: status 400, expected 404', edge_400_on='/', dup_auth='edge')
        self.refused("robots: status 400, neither the Worker's 404 nor Cloudflare's managed robots.txt page (lacks status, "
                     "content-type, marker, content signals;", robots='edge_400')

    def test_the_replay_takes_cloudflares_managed_robots_txt_when_both_fetches_are_identical(self):
        kit, lines = self.replay(robots='managed')
        text = '\n'.join(lines)
        self.assertIn("robots: Cloudflare's managed robots.txt for both fetches, identical (robots; robots, second fetch)",
                      text)
        self.assertIn("duplicate Authorization: the Worker's 404 for both cases", text)
        self.assertEqual(kit.robots_fetches, 2)
        self.assertEqual(kit.fails, 30)
        _, lines = self.replay(robots='managed', dup_auth='edge')        # both rows on their edge pages, one line each
        text = '\n'.join(lines)
        self.assertIn("duplicate Authorization: Cloudflare's edge 400 for both cases, identical", text)
        self.assertIn("robots: Cloudflare's managed robots.txt for both fetches, identical", text)

    def test_the_replay_refuses_any_other_robots_answer_and_names_what_is_missing_never_the_body(self):
        for mode, fragment in (('mixed', 'robots: "robots" answered 200, "robots, second fetch" answered 404'),
                               ('hello', "robots: status 200, neither the Worker's 404 nor Cloudflare's managed robots.txt "
                                         "page (lacks marker, content signals; server=cloudflare"),
                               ('no_marker', 'page (lacks marker; '),
                               ('no_signals', 'page (lacks content signals; '),
                               ('big', 'page (lacks size; '),
                               ('differ', 'robots: "robots, second fetch" differs from "robots": body differs')):
            with self.subTest(mode=mode), self.assertRaises(kc.Refused) as why:
                self.replay(robots=mode)
            self.assertIn(fragment, str(why.exception))
            for body in (b'Hello World!', b'content signals:', b'User-agent', b'condition of accessing'):
                self.assertNotIn(body.decode(), str(why.exception))                    # a refusal never carries a body

    def test_robots_reporting_headers_may_differ_and_nothing_else(self):
        # run 38140164568 attempt 2: '"robots, second fetch" differs from "robots": headers differ: report-to'
        kit, lines = self.replay(robots='reporting')
        self.assertIn("robots: Cloudflare's managed robots.txt for both fetches, identical", '\n'.join(lines))
        self.assertEqual(kit.robots_fetches, 2)
        self.refused('robots: "robots, second fetch" differs from "robots": headers differ: x-foo', robots='x_foo')

    # -- Cloudflare's cf-nel report-to on the Worker's answers (run 38164673127) ---------------------------------------
    def test_the_replay_takes_cloudflares_cf_nel_report_to_whatever_its_token(self):
        # run 38164673127: '404: "below the floor" differs from "admin stale": headers differ: report-to'
        kit, lines = self.replay(edge_nel='cf-nel', robots='reporting', dup_auth='edge')
        text = '\n'.join(lines)
        self.assertIn('vectors passed', text)
        compared = int(re.search(r'404 answers compared: (\d+), identical', text).group(1))
        self.assertGreater(compared, 30)
        self.assertIn("Cloudflare's cf-nel report-to on %d of %d (its token is not compared)" % (compared, compared), text)
        self.assertIn("duplicate Authorization: Cloudflare's edge 400 for both cases, identical", text)
        self.assertIn("robots: Cloudflare's managed robots.txt for both fetches, identical", text)
        self.assertGreater(len(set(kit.tokens)), 30)                     # the tokens did differ, 404 by 404
        self.assertEqual(kit.fails, 30)
        for token in kit.tokens:
            self.assertNotIn(token, text)

    def test_the_replay_refuses_a_404_whose_report_to_is_not_cloudflares_cf_nel(self):
        # one 404 among Cloudflare's own: it is compared raw, differs from every cf-nel row and is named
        e = self.refused('404: "below the floor" differs from "admin stale": headers differ: report-to '
                         "(not Cloudflare's cf-nel)", edge_nel='cf-nel', edge_nel_nth=(2, 'wrong_group'))
        self.assertNotIn('a.nel.cloudflare.com', str(e))                 # never the value
        # every answer: the first fixed answer judged already refuses it (the 429 comes before the 404 set)
        e = self.refused("429: report-to is not Cloudflare's cf-nel", edge_nel='foreign_host')
        self.assertNotIn('example.net', str(e))

    def test_the_replay_refuses_a_404_without_the_report_to_the_others_carry_and_a_differing_nel(self):
        e = self.refused('404: "below the floor" differs from "admin stale": headers differ: report-to',
                         edge_nel='cf-nel', edge_nel_nth=(2, 'absent'))
        self.assertTrue(str(e).endswith('headers differ: report-to'))    # presence alone: nel was there, nothing malformed
        e = self.refused('404: "below the floor" differs from "admin stale": headers differ: nel',
                         edge_nel='cf-nel', nel_nth=2)
        self.assertTrue(str(e).endswith('headers differ: nel'))

    def test_the_replay_refuses_a_404_whose_cf_nel_report_to_differs_in_more_than_its_token(self):
        # well-formed cf-nel on every 404, one of them with another max_age: only the token is left out of the comparison
        e = self.refused('404: "below the floor" differs from "admin stale": headers differ: report-to '
                         '(cf-nel, more than its token)', edge_nel='cf-nel', edge_nel_nth=(2, 'max_age_1'))
        self.assertNotIn('a.nel.cloudflare.com', str(e))                 # never the value

    def test_the_managed_robots_page_on_another_label_is_refused(self):
        self.refused('root: status 200, expected 404', managed_robots_on='/')
        self.refused('root: status 200, expected 404', managed_robots_on='/', robots='managed')

    # -- PW08 (G-KITTEST-1): the expiry wait is the kit's clock moving, not about 5 s of sleep per replay ---------------
    def assert_one_expiry_wait(self, kit):
        asked = [s for s, advanced in kit.sleeps if advanced]
        # (a) the wait is still asked for (the live path is exercised) and it moved the kit's clock for it, once; with the
        # replay's elapsed time on a ReplayClock it is almost the full 5 s, so this holds on any runner
        self.assertEqual(len(asked), 1, kit.sleeps)
        self.assertGreaterEqual(asked[0], 4.0)
        self.assertLessEqual(asked[0], 5.0)
        self.assertGreaterEqual(kit.skew_ms, asked[0] * 1000)
        # (b) every other wait stayed real: the two cut_waits are slept (not advanced); no 3 s 503 retry is ever asked for
        # (the fake cannot answer 503 to the invite POST; if it ever does, the wrapper must exclude that literal 3)
        real = [s for s, advanced in kit.sleeps if not advanced]
        self.assertEqual(real.count(0.4), 2, kit.sleeps)
        self.assertLess(max(real), 2.0)
        self.assertNotIn(3, [s for s, _ in kit.sleeps])

    def test_the_expiry_wait_costs_no_real_time(self):
        kit, _ = self.replay()
        self.assert_one_expiry_wait(kit)
        # no wall-clock bound on purpose: the record above is the evidence the expiry wait was not slept

    def test_a_slow_runner_still_gets_exactly_one_advanced_expiry_wait(self):
        # CI run 39247858912 (unit 3.13, 0 != 1): the runner spent the ~5 s before the late wait, so none was asked for.
        # Every read of the process clock now finds 10 s more spent; the replay must not notice
        with slow_runner():
            kit, _ = self.replay()
        self.assert_one_expiry_wait(kit)

    def test_the_slow_runner_control_without_the_replay_clock_asks_for_no_expiry_wait(self):
        # control for the test above: the same slow runner, the replay measuring on the runner's own clock. It then finds
        # the 5 s already spent and asks for no wait of 2 s or more (the CI failure; there the kit's real clock had also
        # moved on, so the replay passed and only the count failed. Here nothing really waited, so it refuses at 'expired')
        with slow_runner():
            with self.assertRaises(kc.Refused) as why:
                self.replay(real_clock=True)
        self.assertIn('expired', str(why.exception))
        self.assertEqual([s for s, advanced in self.kit.sleeps if advanced], [], self.kit.sleeps)

    def test_a_short_wait_really_sleeps_through_the_replays_own_sleep(self):
        # the passthrough: every wait under 2 s reaches the `sleep` the replay was given (a recorder here), so dropping the
        # real sleep for the cut_waits and spacings would be seen; the expiry wait never reaches it (it moves the clock)
        rec = []
        self.replay(run={'sleep': rec.append})
        self.assertEqual(rec.count(0.4), 2, rec)
        self.assertLess(max(rec), 2.0, rec)

    def test_without_the_clock_moving_the_invite_does_not_expire(self):
        # positive control: the replay needs the clock to move; with the expiry wait skipped and the kit's clock held,
        # the short invite still downloads and the replay refuses at 'expired' (the assertion is not skipped)
        kit = FakeKit(self.pubs)
        frozen = int(time.time() * 1000)
        kit.now = lambda: frozen
        with Served(kit) as base:
            client = kc.Client(base, allow_http=True)
            with self.assertRaises(kc.Refused) as why:
                kc.run_replay(client, kc.Admin(client, self.gate_dir), big_mib=1, cut_wait=0, short_life_ms=2500,
                              ready_spacing=0.0, retry_wait=0.0, sleep=lambda s: None, log=lambda *_: None)
        self.assertIn('expired', str(why.exception))

    def test_the_fake_kit_still_enforces_the_300_s_signature_window_on_its_advanced_clock(self):
        kit = FakeKit(self.pubs)
        with Served(kit) as base:
            client = kc.Client(base, allow_http=True)
            admin = kc.Admin(client, self.gate_dir)
            self.assertEqual(admin.call('gateway', 'GET', '/_k/state').status, 200)
            kit.advance(5000)                           # the replay's expiry wait: far inside the window
            self.assertEqual(admin.call('gateway', 'GET', '/_k/state').status, 200)
            kit.advance(300000)                         # past 300 s in all: a signature made now is refused
            self.assertEqual(admin.call('gateway', 'GET', '/_k/state').status, 404)

    def test_the_replay_refuses_a_worker_without_the_upload_key(self):
        pubs = dict(self.pubs, upload='')
        kit = FakeKit(pubs)
        with Served(kit) as base:
            client = kc.Client(base, allow_http=True)
            with self.assertRaises(kc.Refused):
                kc.run_replay(client, kc.Admin(client, self.gate_dir), big_mib=1, cut_wait=0, short_life_ms=2500,
                              sleep=kit.fake_sleep(), log=lambda *_: None)

    def test_the_probe_passes_and_spends_at_most_five_gate_failures(self):
        kit = FakeKit(self.pubs)
        with Served(kit) as base:
            lines = kc.run_probe(kc.Client(base, allow_http=True), log=lambda *_: None, ready_spacing=0.0)
        self.assertIn('byte-identical, 5 reached the gate', lines[0])
        self.assertIn("Cloudflare's cf-nel report-to on 0 of 25 (its token is not compared)", '\n'.join(lines))
        self.assertEqual(kit.gate_failures, 5)
        self.assertLessEqual(kit.gate_failures, kc.PROBE_MAX_FAILURES)

    # -- production propagation (run 38180769445): the probe waits for the Worker's own 404 before it judges ---------------
    def ready_full(self, kit_flags=None, **kw):
        """wait_worker alone against a fake. A fake clock: sleep() moves it, nothing waits."""
        now = [0.0]
        slept: list[float] = []

        def sleep(s):
            slept.append(s)
            now[0] += s
        kit = FakeKit(self.pubs, **(kit_flags or {}))
        with Served(kit) as base:
            got = kc.wait_worker(kc.Client(base, allow_http=True), sleep=sleep, clock=lambda: now[0], **kw)
        return kit, got, slept

    def ready(self, kit_flags=None, **kw):
        kit, got, slept = self.ready_full(kit_flags, **kw)
        return kit, (got.tries, got.other), slept

    def assertReadyLine(self, lines, tries, other, kinds=''):
        """The summary's readiness line: tries, seconds, how many answers were not the Worker's 404 (and which statuses)."""
        judged = tries - other
        want = (r"  ready after %d tries, \d+\.\d s \(%d answers were not this Worker's 404%s; the %d that were are judged "
                r"with the rest\)$" % (tries, other, re.escape(kinds), judged))
        self.assertTrue([l for l in lines if re.match(want, l)], (want, lines))

    def test_the_readiness_path_is_one_the_worker_front_answers_without_the_gate(self):
        path = kc.PROBE_READY_PATH
        self.assertIsNone(TARGET_RE.match(path))             # not /v1/kit/<serial>/<file>: the front's 404 comes first
        self.assertFalse(path.startswith('/_k/'))            # not the admin route
        self.assertNotIn(path, ('/', '/robots.txt'))         # the fake's (and the edge's) own rows are other labels
        worker = (Path(__file__).resolve().parent.parent / 'kit' / 'worker.js').read_text()
        self.assertIn('if (!m) return fixed(404);', worker)  # publicRoute: no match, 404, before the Authorization check
        # per_source=0 would answer 429 to anything that reached the Gate: the readiness never does
        kit, (tries, other), _ = self.ready({'per_source': 0})
        self.assertEqual((tries, other, kit.gate_calls, kit.fails, kit.gate_failures), (10, 0, 0, 0, 0))
        self.assertEqual(set(kit.paths), {path})

    def test_the_probe_goes_to_the_gate_exactly_five_times_and_readiness_is_not_one_of_them(self):
        kit, lines = self.probe(placeholder=lambda n, path: n <= 3)
        self.assertEqual(kit.gate_calls, 5)
        self.assertEqual(kit.gate_failures, 5)
        self.assertEqual(kit.paths[:13], [kc.PROBE_READY_PATH] * 13)      # 3 placeholders, then the streak of 10

    def test_the_probe_waits_out_k_placeholders_and_names_k(self):
        for k in (1, 7, 40):
            kit, lines = self.probe(placeholder=lambda n, path, k=k: n <= k)
            self.assertReadyLine(lines, 10 + k, k, ': 200 x%d' % k)
            self.assertIn('byte-identical, 5 reached the gate', lines[0])
            self.assertEqual(kit.paths[:10 + k], [kc.PROBE_READY_PATH] * (10 + k))

    def test_an_existing_worker_to_a_new_worker_deploy_passes_with_no_answer_that_was_not_ready(self):
        kit, lines = self.probe()
        self.assertReadyLine(lines, 10, 0)
        # the streak still takes its spaced tries: this is the time propagation gets
        _, (tries, other), slept = self.ready(streak=10, spacing=1.0, timeout=120.0)
        self.assertEqual((tries, other, slept), (10, 0, [1.0] * 9))

    def test_the_run_38180769445_shape_the_previous_versions_page_for_the_first_answers_now_passes(self):
        # every answer of the dashboard placeholder is 200 "Hello World!"; here it holds for the first 30 requests of the
        # probe, so without the wait the gate cases (and the first answer) would have met it
        kit, lines = self.probe(placeholder=lambda n, path: n <= 30)
        self.assertReadyLine(lines, 40, 30, ': 200 x30')
        self.assertIn('byte-identical, 5 reached the gate', lines[0])
        self.assertIn("robots: the Worker's 404 for both fetches", '\n'.join(lines))

    def test_a_streak_broken_at_the_ninth_answer_starts_again(self):
        _, (tries, other), _ = self.ready({'placeholder': lambda n, path: n == 9})
        self.assertEqual((tries, other), (19, 1))             # 8 good, the placeholder, then ten
        _, (tries, other), _ = self.ready({'placeholder': lambda n, path: n in (9, 18)})
        self.assertEqual((tries, other), (28, 2))             # the second run reaches its own ninth and breaks again
        # one short of the streak, again and again: never ready, and the refusal says how many were not the Worker's
        with self.assertRaises(kc.Refused) as why:
            self.ready({'placeholder': lambda n, path: n % 10 == 0}, timeout=40.0)
        self.assertRegex(str(why.exception), r'\(\d+ tries, \d+ were not')

    def test_the_placeholder_forever_is_refused_at_the_timeout_with_its_headers_and_no_body(self):
        with self.assertRaises(kc.Refused) as why:
            self.ready({'placeholder': lambda n, path: True}, streak=10, spacing=1.0, timeout=120.0)
        text = str(why.exception)
        self.assertEqual(text, "probe readiness: no 10 consecutive fixed 404s of the Worker within 120 s (122 tries, 122 were "
                               "not the Worker's 404; the last of them: status 200, content-type text/plain;charset=UTF-8, "
                               "content-length 12)")
        self.assertNotIn('Hello', text)
        self.assertNotIn('World', text)

    def test_a_worker_that_never_makes_ten_in_a_row_is_refused_and_a_probe_with_it_never_reaches_the_gate(self):
        kit = FakeKit(self.pubs, placeholder=lambda n, path: True)
        with Served(kit) as base, self.assertRaises(kc.Refused) as why:
            kc.run_probe(kc.Client(base, allow_http=True), log=lambda *_: None, ready_spacing=0.0, ready_timeout=0.2)
        self.assertIn('probe readiness: no 10 consecutive fixed 404s of the Worker within 0 s (', str(why.exception))
        self.assertEqual((kit.gate_calls, kit.fails), (0, 0))
        self.assertEqual(set(kit.paths), {kc.PROBE_READY_PATH})

    def test_the_readiness_takes_the_workers_404_whatever_the_edge_adds_to_it(self):
        # a per-response report-to token and a nel are not what version it is: ready at once, judged afterwards as before
        for kind in ('cf-nel', *CF_NEL_OTHER):
            _, (tries, other), _ = self.ready({'edge_nel': kind})
            self.assertEqual((tries, other), (10, 0), kind)

    def test_a_404_that_is_not_the_fixed_one_is_not_ready(self):
        for body, ctype in ((b'not found!\n', 'text/plain'), (b'<html>404</html>', 'text/html'), (b'not found\n', 'text/html')):
            with self.subTest(body=body, ctype=ctype), self.assertRaises(kc.Refused) as why:
                self.ready({'ready_answer': (404, body, ctype)}, spacing=1.0, timeout=20.0)
            self.assertIn("were not the Worker's 404; the last of them: status 404", str(why.exception))
            self.assertNotIn(body.decode().strip(), str(why.exception))

    def test_a_404_with_a_wrong_header_during_the_wait_is_judged_not_excused(self):
        # review: worker_404 (status, text/plain, body) ends the wait, but the 404s it kept are judged with the rest, so a
        # header fault confined to the first answers is the same refusal as on any answer, never "0 were not this Worker's 404"
        for kind in ('set-cookie', 'location', 'content-encoding', 'report-to', 'public-cache', 'no-cache-control', 'x-foo', 'ctype'):
            for fault in ((10, kind), (0, kind, 10), (3, kind), (0, kind, 1)):
                with self.subTest(kind=kind, fault=fault), self.assertRaises(kc.Refused) as why:
                    self.probe(ready_fault=fault)
                self.assertRegex(str(why.exception), r'^probe: "readiness try \d+" differs from "bundle, serial 1": ', kind)
                self.assertIn({'public-cache': 'cache-control', 'no-cache-control': 'cache-control', 'ctype': 'content-type'}
                              .get(kind, kind), str(why.exception).split(': ', 2)[2])      # the header that is wrong, by name

    def test_a_faulty_404_before_a_broken_streak_is_judged_too(self):
        with self.assertRaises(kc.Refused) as why:
            self.probe(ready_fault=(0, 'set-cookie', 2), placeholder=lambda n, path: n == 5)
        self.assertIn('headers differ: set-cookie', str(why.exception))

    def test_the_wait_returns_every_answer_that_was_the_workers_404_for_judging(self):
        _, got, _ = self.ready_full({'placeholder': lambda n, path: n in (3, 4)})
        self.assertEqual((got.tries, got.other, got.statuses), (14, 2, {200: 2}))
        self.assertEqual([l for l, _ in got.answers], ['readiness try %d' % i for i in (1, 2, *range(5, 15))])

    def test_the_summary_names_the_statuses_of_the_answers_it_excused(self):
        for status, body in ((503, b'unavailable\n'), (429, b'try later\n')):
            kit, lines = self.probe(ready_first=(3, status, body))
            self.assertReadyLine(lines, 13, 3, ': %d x3' % status)
        kit, lines = self.probe(placeholder=lambda n, path: n == 1, ready_first=(2, 503, b'unavailable\n'))
        self.assertReadyLine(lines, 13, 3, ': 200 x1, 503 x2')

    def test_run_probe_hands_streak_spacing_timeout_sleep_and_clock_to_the_wait(self):
        def run(flags, **kw):
            now, slept = [0.0], []

            def sleep(s):
                slept.append(s)
                now[0] += s
            kit = FakeKit(self.pubs, **flags)
            try:
                with Served(kit) as base:
                    return slept, kc.run_probe(kc.Client(base, allow_http=True), log=lambda *_: None, sleep=sleep,
                                               clock=lambda: now[0], **kw)
            except kc.Refused as e:
                return slept, e
        slept, lines = run({}, ready_streak=3, ready_spacing=1.0, ready_timeout=5.0)
        self.assertEqual(slept, [1.0, 1.0])
        self.assertTrue([l for l in lines if l.startswith("  ready after 3 tries, 2.0 s (0 answers were not")], lines)
        slept, why = run({'placeholder': lambda n, path: True}, ready_streak=3, ready_spacing=1.0, ready_timeout=5.0)
        self.assertEqual(slept, [1.0] * 6)
        self.assertEqual(str(why), "probe readiness: no 3 consecutive fixed 404s of the Worker within 5 s (7 tries, 7 were not the "
                                   "Worker's 404; the last of them: status 200, content-type text/plain;charset=UTF-8, "
                                   "content-length 12)")

    def test_the_production_wait_is_the_staging_wait_and_the_cli_does_not_change_it(self):
        self.assertEqual((kc.PROBE_READY_STREAK, kc.PROBE_READY_SPACING, kc.PROBE_READY_TIMEOUT), (10, 1.0, 120.0))
        self.assertEqual((kc.PROBE_READY_STREAK, kc.PROBE_READY_SPACING, kc.PROBE_READY_TIMEOUT),
                         (kc.READY_STREAK, kc.READY_SPACING, kc.READY_TIMEOUT))
        for fn, names in ((kc.wait_worker, ('streak', 'spacing', 'timeout')),
                          (kc.run_probe, ('ready_streak', 'ready_spacing', 'ready_timeout'))):
            got = tuple(inspect.signature(fn).parameters[n].default for n in names)
            self.assertEqual(got, (10, 1.0, 120.0), fn.__name__)
        with mock.patch.object(kc, 'run_probe', return_value=['x']) as run, redirect_stdout(io.StringIO()):
            self.assertEqual(kc.main(['probe', 'https://x.example']), 0)
        (args, kwargs), = [run.call_args]
        self.assertEqual((len(args), kwargs), (1, {}))           # only the Client: no keyword changes the wait

    def test_the_refusal_names_the_last_answer_that_was_not_the_404_and_a_slow_worker_has_none(self):
        # the placeholder once, then a 404 that is not the fixed one for every later try: the LAST of them is the 404
        with self.assertRaises(kc.Refused) as why:
            self.ready({'placeholder': lambda n, path: n == 1, 'ready_answer': (404, b'not found!\n', 'text/plain')},
                       spacing=1.0, timeout=20.0)
        self.assertIn('the last of them: status 404, content-type text/plain, content-length 11)', str(why.exception))
        # the time runs out with every answer the Worker's 404 (a slow Worker): nothing to name, and no crash
        with self.assertRaises(kc.Refused) as why:
            self.ready(streak=10, spacing=30.0, timeout=120.0)
        self.assertTrue(str(why.exception).endswith("(6 tries, 0 were not the Worker's 404)"), str(why.exception))

    def test_the_probe_takes_the_identical_edge_400_for_the_duplicate_pair_and_nothing_else(self):
        kit = FakeKit(self.pubs, dup_auth='edge')
        with Served(kit) as base:
            lines = kc.run_probe(kc.Client(base, allow_http=True), log=lambda *_: None, ready_spacing=0.0)
        self.assertIn("Cloudflare's edge 400 for both cases, identical", '\n'.join(lines))
        for flags, fragment in (({'dup_auth': 'json400'}, "neither the Worker's 404"), ({'edge_400_on': '/'}, 'differs')):
            kit = FakeKit(self.pubs, **flags)
            with Served(kit) as base, self.assertRaises(kc.Refused) as why:
                kc.run_probe(kc.Client(base, allow_http=True), log=lambda *_: None, ready_spacing=0.0)
            self.assertIn(fragment, str(why.exception))

    def test_the_probe_takes_the_same_robots_rows_as_the_replay(self):
        for robots, line in ((None, "robots: the Worker's 404 for both fetches"),
                             ('managed', "robots: Cloudflare's managed robots.txt for both fetches, identical"),
                             ('reporting', "robots: Cloudflare's managed robots.txt for both fetches, identical")):
            kit = FakeKit(self.pubs, **({'robots': robots} if robots else {}))
            with Served(kit) as base:
                lines = kc.run_probe(kc.Client(base, allow_http=True), log=lambda *_: None, ready_spacing=0.0)
            self.assertIn(line, '\n'.join(lines))
            self.assertIn("duplicate Authorization: the Worker's 404 for both cases", '\n'.join(lines))
            self.assertEqual(kit.gate_failures, 5)
        for flags, fragment in (({'robots': 'hello'}, 'lacks marker, content signals'), ({'robots': 'mixed'}, 'answered 404'),
                                ({'robots': 'differ'}, 'body differs'), ({'managed_robots_on': '/'}, 'differs'),
                                ({'robots': 'x_foo'}, 'headers differ: x-foo')):
            kit = FakeKit(self.pubs, **flags)
            with Served(kit) as base, self.assertRaises(kc.Refused) as why:
                kc.run_probe(kc.Client(base, allow_http=True), log=lambda *_: None, ready_spacing=0.0)
            self.assertIn(fragment, str(why.exception))

    def probe(self, **flags):
        kit = FakeKit(self.pubs, **flags)
        with Served(kit) as base:
            return kit, kc.run_probe(kc.Client(base, allow_http=True), log=lambda *_: None, ready_spacing=0.0)

    def test_the_probe_takes_cloudflares_cf_nel_report_to_by_the_same_rule(self):
        for flags, n in (({'edge_nel': 'cf-nel'}, 25), ({'edge_nel': 'cf-nel', 'robots': 'reporting', 'dup_auth': 'edge'}, 21),
                         # another max_age, path or spelling on EVERY answer is Cloudflare's change between runs: it passes
                         *(({'edge_nel': kind}, 25) for kind in CF_NEL_OTHER)):
            kit, lines = self.probe(**flags)
            self.assertIn('%d answers, byte-identical, 5 reached the gate' % n, lines[0])
            self.assertIn("Cloudflare's cf-nel report-to on %d of %d (its token is not compared)" % (n, n), '\n'.join(lines))
            self.assertGreater(len(set(kit.tokens)), 15)
            self.assertFalse([t for t in kit.tokens if t in '\n'.join(lines)])
        not_cf = "report-to (not Cloudflare's cf-nel)"
        for kind in NOT_CF_NEL:
            for flags, fragment in (
                    # on every answer: the first answer's own check names it
                    ({'edge_nel': kind}, "probe first answer: report-to is not Cloudflare's cf-nel"),
                    # on the first answer only, or on one later answer: the identity check names it
                    ({'edge_nel': 'cf-nel', 'edge_nel_nth': (1, kind)}, "probe first answer: report-to is not Cloudflare's"),
                    ({'edge_nel': 'cf-nel', 'edge_nel_nth': (3, kind)},
                     'probe: "gateway.json, serial 7" differs from "bundle, serial 1": headers differ: ' + not_cf)):
                with self.subTest(kind=kind, flags=flags), self.assertRaises(kc.Refused) as why:
                    self.probe(**flags)
                self.assertIn(fragment, str(why.exception))
                for part in ('a.nel.cloudflare.com', 'example.net', 'AAAA', 'default', 'include_subdomains'):
                    self.assertNotIn(part, str(why.exception))           # a refusal never carries the value
        # ... and on ONE answer among Cloudflare's usual ones it is a difference, named apart from a missing header
        for kind in CF_NEL_OTHER:
            for nth, labels in ((3, '"gateway.json, serial 7" differs from "bundle, serial 1"'),
                                (1, 'differs from "bundle, serial 1"')):
                with self.subTest(kind=kind, nth=nth), self.assertRaises(kc.Refused) as why:
                    self.probe(edge_nel='cf-nel', edge_nel_nth=(nth, kind))
                self.assertIn(labels, str(why.exception))
                self.assertTrue(str(why.exception).endswith('headers differ: report-to (cf-nel, more than its token)'),
                                str(why.exception))
                self.assertNotIn('a.nel.cloudflare.com', str(why.exception))
        for flags, end in (({'edge_nel': 'cf-nel', 'edge_nel_nth': (3, 'absent')}, 'headers differ: report-to'),
                           ({'edge_nel': 'cf-nel', 'edge_nel_nth': (1, 'absent')}, 'headers differ: report-to'),
                           ({'edge_nel': 'absent', 'edge_nel_nth': (3, 'cf-nel')}, 'headers differ: report-to'),
                           ({'edge_nel': 'cf-nel', 'edge_nel_nth': (3, 'twice')}, 'headers differ: report-to'),
                           ({'edge_nel': 'cf-nel', 'nel_nth': 3}, 'headers differ: nel'),
                           ({'edge_nel': 'cf-nel', 'nel_nth': 1}, 'headers differ: nel')):
            with self.subTest(flags=flags), self.assertRaises(kc.Refused) as why:
                self.probe(**flags)
            self.assertTrue(str(why.exception).endswith(end), str(why.exception))

    def test_the_probe_refuses_an_answer_that_differs_or_a_429(self):
        for flags, fragment in (({'gzip_404': True}, 'differs'), ({'per_source': 0}, 'answered 429')):
            kit = FakeKit(self.pubs, **flags)
            with Served(kit) as base, self.assertRaises(kc.Refused) as why:
                kc.run_probe(kc.Client(base, allow_http=True), log=lambda *_: None, ready_spacing=0.0)
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
    class Recorder:
        def __init__(self):
            self.sent = []

        def request(self, method, path, headers=(), body=None, read=True):
            self.sent.append(list(headers))
            return path

    def test_both_duplicate_cases_send_two_identical_headers_one_live_one_unknown(self):
        rec = self.Recorder()
        answers = kc.front_rejects(rec, '2345678923')
        labels = [label for label, _ in answers]
        # gateway.json: the replay's live code still opens it at this point (bundle.tar's cap is spent by then)
        for label in kc.DUP_AUTH:
            self.assertEqual(answers[labels.index(label)][1], '/v1/kit/900000001/gateway.json')
        self.assertEqual(kc.DUP_AUTH, ('two authorization headers', 'two authorization headers, unknown code'))
        live, unknown = (rec.sent[labels.index(label)] for label in kc.DUP_AUTH)
        self.assertEqual(live, [('Authorization', 'FleetInvite 2345678923')] * 2)
        self.assertEqual(len(unknown), 2)
        self.assertEqual(unknown[0], unknown[1])
        self.assertRegex(unknown[0][1], r'^FleetInvite [23456789CFGHJMPQRVWX]{10}$')
        self.assertNotEqual(unknown[0][1], live[0][1])

    def test_edge_400_is_only_cloudflares_page(self):
        page = kc.Resp(400, [('server', 'cloudflare'), ('content-type', 'text/html'), ('content-length', '155')],
                       b'<html><center><h1>400 Bad Request</h1></center></html>', 1)
        self.assertTrue(kc.edge_400(page))
        for change in ({'status': 404}, {'server': 'nginx'}, {'content-type': 'text/plain'},
                       {'cache-control': 'no-store, no-transform'}, {'body': b'bad request'}):
            hdrs = dict(page.headers)
            hdrs.update({k: v for k, v in change.items() if k not in ('status', 'body')})
            r = kc.Resp(change.get('status', 400), list(hdrs.items()), change.get('body', page.body), 1)
            self.assertFalse(kc.edge_400(r), change)
            self.assertEqual(kc.edge_400_misses(r), [{'body': 'marker'}.get(k, k) for k in change], change)

    def test_the_fold_refuses_unless_both_duplicate_cases_are_there_once(self):
        page = kc.Resp(400, [('server', 'cloudflare'), ('content-type', 'text/html')], b'400 Bad Request', 1)
        for labels in ((), kc.DUP_AUTH[:1], kc.DUP_AUTH[1:], kc.DUP_AUTH + kc.DUP_AUTH[:1], kc.DUP_AUTH[:1] * 2):
            with self.subTest(labels=labels), self.assertRaises(kc.Refused) as why:
                kc.fold_edge([('root', page)] + [(label, page) for label in labels + kc.ROBOTS])
            self.assertIn('not exactly', str(why.exception))

    def test_managed_robots_is_only_cloudflares_page(self):
        page = kc.Resp(200, [('server', 'cloudflare'), ('content-type', 'text/plain; charset=utf-8')], MANAGED_ROBOTS, 1)
        self.assertEqual(kc.managed_robots_misses(page), [])
        for change, misses in (({'status': 404}, ['status']), ({'server': 'nginx'}, ['server']),
                               ({'content-type': 'text/html'}, ['content-type']),
                               ({'body': MANAGED_ROBOTS.upper()}, ['marker']),                 # signals case-insensitive
                               ({'body': b'Hello World!'}, ['marker', 'content signals']),
                               ({'body': MANAGED_ROBOTS + b'#' * 65536}, ['size']),
                               # trailing bytes past the cap (the measured page is 1248 bytes, the cap 4 KiB)
                               ({'body': MANAGED_ROBOTS + b'User-agent: *\nDisallow: /x\n' + b'#' * 4096}, ['size']),
                               ({'location': 'https://evil/'}, ['no location']),
                               ({'set-cookie': 'a=1'}, ['no set-cookie']),
                               ({'content-encoding': 'gzip'}, ['no content-encoding'])):
            hdrs = dict(page.headers)
            hdrs.update({k: v for k, v in change.items() if k not in ('status', 'body')})
            r = kc.Resp(change.get('status', 200), list(hdrs.items()), change.get('body', page.body), 1)
            self.assertEqual(kc.managed_robots_misses(r), misses, change)

    def test_the_managed_robots_page_is_refused_on_the_duplicate_authorization_rows(self):
        page = kc.Resp(200, [('server', 'cloudflare'), ('content-type', 'text/plain; charset=utf-8')], MANAGED_ROBOTS, 1)
        nf = kc.Resp(404, [('content-type', 'text/plain')], b'not found\n', 1)
        with self.assertRaises(kc.Refused) as why:
            kc.fold_edge([('root', nf)] + [(label, page) for label in kc.DUP_AUTH] + [(label, nf) for label in kc.ROBOTS])
        self.assertIn("neither the Worker's 404 nor Cloudflare's edge 400 page", str(why.exception))

    def test_the_robots_row_refuses_the_worker_404_then_the_managed_page(self):
        page = kc.Resp(200, [('server', 'cloudflare'), ('content-type', 'text/plain; charset=utf-8')], MANAGED_ROBOTS, 1)
        nf = kc.Resp(404, [('content-type', 'text/plain')], b'not found\n', 1)
        with self.assertRaises(kc.Refused) as why:
            kc.fold_edge([('root', nf)] + [(label, nf) for label in kc.DUP_AUTH] + [(kc.ROBOTS[0], nf), (kc.ROBOTS[1], page)])
        self.assertIn('"robots" answered 404, "robots, second fetch" answered 200', str(why.exception))

    def test_only_the_robots_row_ignores_the_reporting_headers(self):
        def robots(**extra):
            return kc.Resp(200, [('server', 'cloudflare'), ('content-type', 'text/plain; charset=utf-8')] + list(extra.items()),
                           MANAGED_ROBOTS, 1)

        def nf(**extra):
            return kc.Resp(404, [('content-type', 'text/plain')] + list(extra.items()), b'not found\n', 1)

        dup = [(label, nf()) for label in kc.DUP_AUTH]
        left, verdicts = kc.fold_edge(dup + [(kc.ROBOTS[0], robots(**{'report-to': 'a', 'nel': '1'})),
                                             (kc.ROBOTS[1], robots(**{'report-to': 'b', 'nel': '2'}))])
        self.assertEqual([label for label, _ in left], list(kc.DUP_AUTH))
        self.assertIn('identical', verdicts[1])
        for other in ('x-foo', 'content-length', 'cache-control'):
            with self.subTest(header=other), self.assertRaises(kc.Refused) as why:
                kc.fold_edge(dup + [(kc.ROBOTS[0], robots(**{other: 'a'})), (kc.ROBOTS[1], robots(**{other: 'b'}))])
            self.assertIn('headers differ: %s' % other, str(why.exception))
        # a 404 robots pair stays in the list and is held to VARYING alone, as every 404
        left, _ = kc.fold_edge(dup + [(kc.ROBOTS[0], nf(**{'report-to': 'a'})), (kc.ROBOTS[1], nf(**{'report-to': 'b'}))])
        with self.assertRaises(kc.Refused) as why:
            kc.all_identical('404', left)
        self.assertIn('headers differ: report-to', str(why.exception))
        self.assertEqual(kc.VARYING, frozenset({'date', 'cf-ray'}))
        self.assertEqual(kc.EDGE_400_PAGE.varying, kc.VARYING)
        self.assertEqual(kc.MANAGED_ROBOTS.varying, kc.VARYING | {'report-to', 'nel'})

    # -- Cloudflare's cf-nel report-to (run 38164673127) ---------------------------------------------------------------
    RT = CF_REPORT_TO % 'tokenA'

    @staticmethod
    def nf(*headers, status=404, body=b'not found\n'):
        return kc.Resp(status, [('content-type', 'text/plain'), ('cache-control', 'no-store, no-transform')] + list(headers),
                       body, 1)

    def test_cf_nel_report_to_is_only_cloudflares_shape(self):
        good = self.RT
        blank = kc.REPORT_TO_MAX - len(good)                             # whitespace JSON allows, up to the cap
        at_the_cap = good.replace('{"group"', '{' + ' ' * blank + '"group"')
        for value in (good, CF_REPORT_TO % 'x%2By%3D%3D', CF_REPORT_TO % 'x+y/z==', CF_REPORT_TO % 'a',
                      CF_REPORT_TO % 'x\\/y',                             # "/" in the token, spelled as JSON may
                      CF_REPORT_TO % ('A' * 512),                        # exactly the token cap
                      at_the_cap,
                      *(v % 'tokenA' for v in CF_NEL_OTHER.values())):   # other max_age, path, spelling: still the shape
            self.assertTrue(kc.cf_nel_report_to(value), value[:80])
        self.assertEqual(len(at_the_cap), 2048)
        bad = dict(NOT_CF_NEL, **{
            'one over the cap': at_the_cap.replace('{ ', '{  '),
            'token one over its cap': CF_REPORT_TO.replace('%s', 'A' * 513),
            'empty token': CF_REPORT_TO.replace('%s', ''),
            'no query': good.replace('?s=tokenA', ''),
            'another parameter name': good.replace('?s=', '?t='),
            'a second parameter': good.replace('tokenA', 'tokenA&live=1'),
            'a second question mark': good.replace('tokenA', 'token?A'),
            'a fragment': good.replace('tokenA', 'tokenA#live'),
            'a fragment before the query': good.replace('v4?', 'v4#live?'),
            'question mark escaped': good.replace('?s=', '\\u003fs='),
            'token escaped': good.replace('tokenA', 'token\\u0041'),
            'quote in the token': good.replace('tokenA', 'token\\"A'),
            'two endpoints': good.replace('}]}', '},{"url":"https://a.nel.cloudflare.com/report/v4?s=z"}]}'),
            'two endpoints, the same': good.replace('}]}', '},{"url":"https://a.nel.cloudflare.com/report/v4?s=tokenA"}]}'),
            'empty path': good.replace('/report/v4', '/report/'),
            'path ..': good.replace('/report/v4', '/report/../../x'),
            'path ends ..': good.replace('/report/v4', '/report/v4/..'),
            'path %2e%2e': good.replace('/report/v4', '/report/%2e%2e/x'),
            'path %2E': good.replace('/report/v4', '/report/.%2E/x'),
            'path backslash': good.replace('/report/v4', '/report/v4\\\\x'),
            'path too long': good.replace('/report/v4', '/report/' + 'v' * 65),
            'no group': good.replace('"group":"cf-nel",', ''),
            'no max_age': good.replace('"max_age":604800,', ''),
            'no endpoints': '{"group":"cf-nel","max_age":604800}',
            'group twice': good.replace('{"group":"cf-nel"', '{"group":"default","group":"cf-nel"'),
            'group case': good.replace('cf-nel', 'CF-NEL'),
            'group not a string': good.replace('"cf-nel"', '["cf-nel"]'),
            'max_age zero': good.replace('604800', '0'),
            'max_age negative': good.replace('604800', '-1'),
            'max_age float': good.replace('604800', '604800.0'),
            'max_age string': good.replace('604800', '"604800"'),
            'max_age true': good.replace('604800', 'true'),
            'endpoints empty': good.replace('[{"url":"https://a.nel.cloudflare.com/report/v4?s=tokenA"}]', '[]'),
            'endpoints an object': good.replace('[{', '{').replace('}]', '}'),
            'endpoint a string': good.replace('{"url":"https://a.nel.cloudflare.com/report/v4?s=tokenA"}',
                                              '"https://a.nel.cloudflare.com/report/v4"'),
            'endpoint extra key': good.replace('{"url"', '{"priority":1,"url"'),
            'endpoint url twice': good.replace('{"url"', '{"url":"https://example.net/","url"'),
            'endpoint no url': good.replace('"url"', '"uri"'),
            'url not a string': good.replace('"https://a.nel.cloudflare.com/report/v4?s=tokenA"', '7'),
            'second endpoint foreign': good.replace('}]}', '},{"url":"https://example.net/report/v4"}]}'),
            'host with a port': good.replace('cloudflare.com/', 'cloudflare.com:8443/'),
            'host as userinfo': good.replace('https://a.nel.cloudflare.com/', 'https://a.nel.cloudflare.com@example.net/'),
            'host subdomain': good.replace('a.nel.', 'b.a.nel.'),
            'host case': good.replace('a.nel.cloudflare.com', 'A.NEL.CLOUDFLARE.COM'),
            'scheme case': good.replace('https://', 'HTTPS://'),
            'no path': good.replace('/report/v4?s=tokenA', ''),
            'other path': good.replace('/report/', '/reports/'),
            'path is /report': good.replace('/report/v4?s=tokenA', '/report'),
            'backslash host': good.replace('cloudflare.com/report', 'cloudflare.com\\\\@example.net/report'),
            'space in the url': good.replace('tokenA', 'token A'),
            'tab in the url': good.replace('tokenA', 'token\\tA'),
            'non-ascii in the url': good.replace('tokenA', 'token\\u00e9'),
            'leading space in the url': good.replace('"https://', '" https://'),
            'an array': '[%s]' % good,
            'two objects': good + good,
            'a json string': json.dumps(good),
            'empty': '',
            'null': 'null',
            'too deep': '[' * 1500,
        })
        for name, value in bad.items():
            value = value % 'tokenA' if '%s' in value else value
            self.assertFalse(kc.cf_nel_report_to(value), name)
        for value in (None, 7, good.encode()):
            self.assertFalse(kc.cf_nel_report_to(value))
            self.assertIsNone(kc.cf_nel_rest(value))

    def test_cf_nel_rest_is_the_value_with_only_the_token_cut_out(self):
        rest = '{"group":"cf-nel","max_age":604800,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/v4?s="}]}'
        for token in ('tokenA', 'x%2By%3D%3D', 'x+y/z==', 'x\\/y', 'A' * 512, 's=', 'cf-nel', '604800', 'v4'):
            self.assertEqual(kc.cf_nel_rest(CF_REPORT_TO % token), rest, token[:20])
        for kind, value in CF_NEL_OTHER.items():
            with self.subTest(kind=kind):
                self.assertEqual(kc.cf_nel_rest(value % 'tokenA'), value % '')       # every character but the token
                self.assertEqual(kc.cf_nel_rest(value % 'tokenA'), kc.cf_nel_rest(value % 'tokenB'))
                self.assertNotEqual(kc.cf_nel_rest(value % 'tokenA'), rest)
        self.assertIsNone(kc.cf_nel_rest(rest))                          # the rest is not itself a well-formed value

    def test_two_cf_nel_report_tos_are_identical_whatever_their_token_and_nothing_else_is(self):
        nf, differs = self.nf, kc.differs
        a = nf(('report-to', CF_REPORT_TO % 'tokenA'), ('nel', CF_NEL))
        b = nf(('report-to', CF_REPORT_TO % 'tokenB'), ('nel', CF_NEL))
        self.assertEqual(kc.norm(a), kc.norm(b))
        kc.all_identical('404', [('a', a), ('b', b), ('c', nf(('nel', CF_NEL), ('report-to', CF_REPORT_TO % 'c')))])
        self.assertNotIn('token', repr(kc.norm(a)))                      # the row holds nothing of the token
        self.assertIn(('report-to', 'cf-nel', CF_REPORT_TO % ''), kc.headers_of(a))   # ... and all of the rest
        # only the token: another max_age, path, spelling or key order on one answer is a difference, and is named so
        more = 'headers differ: report-to (cf-nel, more than its token)'
        for kind, value in CF_NEL_OTHER.items():
            x, y = nf(('report-to', value % 'tokenA'), ('nel', CF_NEL)), nf(('nel', CF_NEL), ('report-to', value % 'tokenB'))
            with self.subTest(kind=kind):
                self.assertNotEqual(kc.norm(a), kc.norm(x))
                self.assertEqual(differs(a, x), more)
                self.assertEqual(differs(x, a), more)
                self.assertEqual(differs(nf(('report-to', value % 'tokenB'), ('nel', CF_NEL)), b), more)   # the same token
                with self.assertRaises(kc.Refused) as why:
                    kc.all_identical('404', [('first', a), ('second', b), ('third', x)])
                self.assertEqual(str(why.exception), '404: "third" differs from "first": ' + more)
                kc.all_identical('404', [('first', x), ('second', y)])   # on every answer of the run it is no difference
        one, v5 = (nf(('report-to', CF_NEL_OTHER[kind] % 'a')) for kind in ('max_age_1', 'path_v5'))
        self.assertEqual(differs(one, v5), more)
        # two of them against one of another kind: counted, and still named as more than the token
        self.assertEqual(differs(nf(('report-to', self.RT), ('report-to', self.RT)), one), more)
        # presence is compared: with against without, once against twice
        none = nf(('nel', CF_NEL))
        twice = nf(('report-to', CF_REPORT_TO % 'tokenA'), ('report-to', CF_REPORT_TO % 'tokenB'), ('nel', CF_NEL))
        for other in (none, twice):
            self.assertNotEqual(kc.norm(a), kc.norm(other))
            self.assertEqual(differs(a, other), 'headers differ: report-to')
            self.assertEqual(differs(other, a), 'headers differ: report-to')
        # the finding's four: max_age 1 against 604800, two endpoints against one, path v5 against v4, ../ in the path
        two = self.RT.replace('}]}', '},{"url":"https://a.nel.cloudflare.com/report/v4?s=z"}]}')
        for name, value, why_named in (('max_age', self.RT.replace('604800', '1'), 'report-to (cf-nel, more than its token)'),
                                       ('endpoints', two, "report-to (not Cloudflare's cf-nel)"),
                                       ('path', self.RT.replace('/v4', '/v5'), 'report-to (cf-nel, more than its token)'),
                                       ('dot-dot', self.RT.replace('/report/v4', '/report/../v4'),
                                        "report-to (not Cloudflare's cf-nel)")):
            with self.subTest(name=name), self.assertRaises(kc.Refused) as why:
                kc.all_identical('404', [('base', a), ('variant', nf(('report-to', value), ('nel', CF_NEL)))])
            self.assertEqual(str(why.exception), '404: "variant" differs from "base": headers differ: ' + why_named)
        # nel is compared as it is
        nel = nf(('report-to', CF_REPORT_TO % 'tokenB'), ('nel', CF_NEL.replace('0.0', '0.5')))
        self.assertNotEqual(kc.norm(a), kc.norm(nel))
        self.assertEqual(differs(a, nel), 'headers differ: nel')
        self.assertEqual(differs(a, nf(('report-to', CF_REPORT_TO % 'tokenB'))), 'headers differ: nel')
        # a report-to that is not well-formed cf-nel is compared raw: against Cloudflare's, and against another raw one
        named = "headers differ: report-to (not Cloudflare's cf-nel)"
        for kind, value in NOT_CF_NEL.items():
            x, y = nf(('report-to', value % 'tokenA'), ('nel', CF_NEL)), nf(('report-to', value % 'tokenB'), ('nel', CF_NEL))
            with self.subTest(kind=kind):
                self.assertNotEqual(kc.norm(a), kc.norm(x))
                self.assertEqual(differs(a, x), named)
                self.assertEqual(differs(x, a), named)
                self.assertNotEqual(kc.norm(x), kc.norm(y))
                self.assertEqual(differs(x, y), named)
                self.assertEqual(kc.norm(x), kc.norm(nf(('nel', CF_NEL), ('report-to', value % 'tokenA'))))  # raw, equal
                with self.assertRaises(kc.Refused) as why:
                    kc.all_identical('404', [('first', a), ('second', b), ('third', x)])
                self.assertEqual(str(why.exception), '404: "third" differs from "first": ' + named)
        # no raw value can pass for a cf-nel row
        for value in ('', 'cf-nel', "('report-to', 'cf-nel', '')", CF_REPORT_TO % ''):
            self.assertNotEqual(kc.norm(a), kc.norm(nf(('report-to', value), ('nel', CF_NEL))), value[:40])
        # other headers and the body are compared as before
        self.assertEqual(differs(a, nf(('report-to', CF_REPORT_TO % 'tokenB'), ('nel', CF_NEL), ('x-foo', '1'))),
                         'headers differ: x-foo')
        self.assertEqual(differs(a, nf(('report-to', CF_REPORT_TO % 'tokenB'), ('nel', CF_NEL), body=b'not found!\n')),
                         'body differs')
        self.assertEqual(differs(a, nf(('report-to', 'x'), ('nel', CF_NEL), ('x-foo', '1'))),
                         "headers differ: report-to (not Cloudflare's cf-nel), x-foo")
        # date and cf-ray stay the only headers left out; report-to and nel are not among them
        self.assertEqual(kc.norm(nf(('date', 'a'), ('cf-ray', '1'))), kc.norm(nf(('date', 'b'), ('cf-ray', '2'))))
        self.assertEqual(kc.VARYING, frozenset({'date', 'cf-ray'}))

    def test_a_fixed_answer_may_carry_cloudflares_cf_nel_report_to_and_no_other(self):
        for status, body in ((404, kc.NOT_FOUND), (429, kc.TRY_LATER), (503, b'unavailable\n')):
            kc.check_fixed_answer('x', self.nf(status=status, body=body), status, body)
            kc.check_fixed_answer('x', self.nf(('report-to', self.RT), ('nel', CF_NEL), status=status, body=body), status, body)
            kc.check_fixed_answer('x', self.nf(('report-to', self.RT), ('report-to', CF_REPORT_TO % 'b'), status=status,
                                               body=body), status, body)
            for value in CF_NEL_OTHER.values():                          # one answer alone is not held to 604800 or v4
                kc.check_fixed_answer('x', self.nf(('report-to', value % 'tokenA'), status=status, body=body), status, body)
            for kind, value in dict(NOT_CF_NEL, empty='', group_alone='cf-nel').items():
                value = value % 'tokenA' if '%s' in value else value
                # alone, and behind one of Cloudflare's own (every report-to line is judged, not the first)
                for headers in ([('report-to', value)], [('report-to', self.RT), ('report-to', value)]):
                    with self.subTest(status=status, kind=kind, n=len(headers)), self.assertRaises(kc.Refused) as why:
                        kc.check_fixed_answer('the label', self.nf(*headers, status=status, body=body), status, body)
                    self.assertEqual(str(why.exception), "the label: report-to is not Cloudflare's cf-nel")
        # its other rules hold beside a good report-to
        for header, fragment in ((('content-encoding', 'gzip'), 'has a content-encoding header'),
                                 (('location', 'https://example.net/'), 'has a location header'),
                                 (('set-cookie', 'a=1'), 'has a set-cookie header')):
            with self.assertRaises(kc.Refused) as why:
                kc.check_fixed_answer('x', self.nf(('report-to', self.RT), header), 404, kc.NOT_FOUND)
            self.assertIn(fragment, str(why.exception))

    def test_the_edge_rows_take_the_cf_nel_report_to_by_the_same_rule(self):
        def page(*headers):
            return kc.Resp(400, [('server', 'cloudflare'), ('content-type', 'text/html')] + list(headers), b'400 Bad Request', 1)

        def robots(*headers):
            return kc.Resp(200, [('server', 'cloudflare'), ('content-type', 'text/plain; charset=utf-8')] + list(headers),
                           MANAGED_ROBOTS, 1)

        rob = [(label, self.nf()) for label in kc.ROBOTS]
        rt = lambda token: ('report-to', CF_REPORT_TO % token)  # noqa: E731
        left, verdicts = kc.fold_edge([(kc.DUP_AUTH[0], page(rt('a'), ('nel', CF_NEL))),
                                       (kc.DUP_AUTH[1], page(rt('b'), ('nel', CF_NEL)))] + rob)
        self.assertEqual([label for label, _ in left], list(kc.ROBOTS))
        self.assertIn("Cloudflare's edge 400 for both cases, identical", verdicts[0])
        for first, second, fragment in (
                (page(rt('a')), page(), 'headers differ: report-to'),
                (page(rt('a')), page(('report-to', NOT_CF_NEL['http'] % 'b')), "report-to (not Cloudflare's cf-nel)"),
                (page(rt('a')), page(('report-to', CF_NEL_OTHER['max_age_1'] % 'b')), 'report-to (cf-nel, more than its token)'),
                (page(rt('a')), page(('report-to', NOT_CF_NEL['two_endpoints'] % 'b')), "report-to (not Cloudflare's cf-nel)"),
                (page(rt('a'), ('nel', CF_NEL)), page(rt('b'), ('nel', '{}')), 'headers differ: nel')):
            with self.assertRaises(kc.Refused) as why:
                kc.fold_edge([(kc.DUP_AUTH[0], first), (kc.DUP_AUTH[1], second)] + rob)
            self.assertTrue(str(why.exception).startswith('duplicate authorization: "two authorization headers, unknown code" '
                                                          'differs from "two authorization headers": '), str(why.exception))
            self.assertIn(fragment, str(why.exception))
        # the robots row is as it was: report-to and nel are outside its comparison, well-formed or not, there or not
        dup = [(label, self.nf()) for label in kc.DUP_AUTH]
        for first, second in ((robots(rt('a'), ('nel', '1')), robots(rt('b'), ('nel', '2'))),
                              (robots(('report-to', 'x')), robots(rt('b'), ('nel', '2'))),
                              (robots(), robots(rt('b'), ('nel', '2')))):
            left, verdicts = kc.fold_edge(dup + [(kc.ROBOTS[0], first), (kc.ROBOTS[1], second)])
            self.assertEqual([label for label, _ in left], list(kc.DUP_AUTH))
            self.assertIn("Cloudflare's managed robots.txt for both fetches, identical", verdicts[1])
        self.assertEqual(kc.EDGE_REPORTING, frozenset({'report-to', 'nel'}))

    def test_worker_404_is_exactly_the_fixed_answer(self):
        self.assertTrue(kc.worker_404(kc.Resp(404, [('content-type', 'text/plain')], b'not found\n', 1)))
        for r in (kc.Resp(404, [('content-type', 'text/html')], b'not found\n', 1),
                  kc.Resp(404, [('content-type', 'text/plain')], b'not found!\n', 1),
                  kc.Resp(404, [('content-type', 'application/json')], b'{"ok":false}', 1),
                  kc.Resp(403, [('content-type', 'text/plain')], b'not found\n', 1)):
            self.assertFalse(kc.worker_404(r))

    def test_the_edge_table_is_the_two_rows_and_both_robots_fetches_are_sent(self):
        self.assertEqual(kc.EDGE_OWNED, {kc.DUP_AUTH[0]: kc.EDGE_400_PAGE, kc.DUP_AUTH[1]: kc.EDGE_400_PAGE,
                                         'robots': kc.MANAGED_ROBOTS, 'robots, second fetch': kc.MANAGED_ROBOTS})
        rec = self.Recorder()
        answers = kc.front_rejects(rec, '2345678923')
        self.assertEqual([path for label, path in answers if label in kc.ROBOTS], ['/robots.txt', '/robots.txt'])
        self.assertTrue(set(kc.EDGE_OWNED) <= {label for label, _ in answers})

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


# `wrangler secret put` is deliberately not counted: staging's throwaway pepper sits between settings-off and its gate
# (the order test pins it there), and whether it makes a new Worker version is not measured. The gate does not rest on
# this order for safety: its GA worker read must itself be an explicit off object. Do not widen this to `secret put`
# without moving the pepper step.
DEPLOYS = re.compile(r'wrangler (?:deploy|versions (?:deploy|upload)|rollback)\b')


def gate_faults(deploy_job: str) -> list[str]:
    """For each settings gate step in a deploy job's text (comments stripped): what is wrong with its order, [] = fine.
    The settings-off step for the same Worker must come before it with no deploy step between the two."""
    steps = re.split(r'(?m)^(?=      - )', deploy_job)
    faults, gates = [], []
    for i, step in enumerate(steps):
        m = re.search(r'fleet-kit-check\.py settings ([\w-]+)$', step, re.M)
        if not m:
            continue
        gates.append(m.group(1))
        off = re.compile(r'fleet-kit-check\.py settings-off %s$' % re.escape(m.group(1)), re.M)
        before = [j for j in range(i) if off.search(steps[j])]
        if not before:
            faults.append('%s: no settings-off before its gate' % m.group(1))
        elif any(DEPLOYS.search(s) for s in steps[before[-1] + 1:i]):
            faults.append('%s: a deploy between settings-off and its gate' % m.group(1))
    if gates != ['fleet-kit-staging', 'fleet-kit']:
        faults.append('settings gates: %s' % gates)
    return faults


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
        self.assertEqual(len(with_token), 9)
        self.assertEqual(WF.count('${{ secrets.CLOUDFLARE_API_TOKEN }}'), 9)
        self.assertEqual(WF.count('${{ vars.CLOUDFLARE_ACCOUNT_ID }}'), 9)
        self.assertEqual(re.findall(r'secrets\.(\w+)', WF), ['CLOUDFLARE_API_TOKEN'] * 9)
        for s in steps:
            if 'npm ci' in s or 'replay' in s or 'probe' in s or 'make the' in s.lower():
                self.assertNotIn('CLOUDFLARE_API_TOKEN', s)   # the install, the replay and the probe never hold the token
        self.assertIn('npm ci --ignore-scripts', self.JOBS['deploy'])
        self.assertLess(CODE.index('npm ci --ignore-scripts'), CODE.index('CLOUDFLARE_API_TOKEN'))

    def test_the_order_is_staging_replay_settings_pepper_production_settings_probe(self):
        d = self.JOBS['deploy']
        marks = ['Deploy staging', 'Observability off, staging', 'staging INVITE_PEPPER', 'Settings gate, staging', 'Replay',
                 'INVITE_PEPPER once', 'Deploy production', 'Observability off, production', 'Settings gate, production',
                 'Hostile probe']
        at = [d.index(x) for x in marks]
        self.assertEqual(at, sorted(at), marks)
        self.assertIn('wrangler deploy --env staging', d)
        self.assertEqual(len(re.findall(r'wrangler deploy\b', d)), 2)
        self.assertEqual(len(re.findall(r'wrangler deploy\b(?! --env staging)', d)), 1)
        self.assertIn('--var "KIT_GW_PUB:$KIT_GW_PUB" --var "KIT_UP_PUB:$KIT_UP_PUB"', d)
        self.assertIn('settings fleet-kit-staging', d)
        self.assertIn('settings fleet-kit\n', d)
        self.assertIn('settings-off fleet-kit-staging\n', d)
        self.assertIn('settings-off fleet-kit\n', d)

    def test_each_settings_gate_runs_after_its_own_off_write_with_no_deploy_between(self):
        # the stated protocol: settings-off, then its gate, no deploy between. script-settings answers null whether or
        # not the off record was written (run 38095547741 read null before any off write; 38099981335 echoed null right
        # after it), so this order does not make the null proof of anything: the gate's GA worker read carries the proof.
        # On staging the throwaway pepper's `wrangler secret put` is the one tolerated step between the two (DEPLOYS
        # does not count it; the order test above pins the pepper there); assert it is the only one.
        d = jobs(CODE)['deploy']
        self.assertEqual(gate_faults(d), [])
        steps0 = re.split(r'(?m)^(?=      - )', d)
        i_off = next(i for i, s in enumerate(steps0) if '- name: Observability off, staging\n' in s)
        i_gate = next(i for i, s in enumerate(steps0) if '- name: Settings gate, staging\n' in s)
        between = steps0[i_off + 1:i_gate]
        self.assertEqual(len(between), 1, between)
        self.assertIn('wrangler secret put INVITE_PEPPER --env staging', between[0])
        # positive proof the check bites, on crafted orders of the same steps
        steps = re.split(r'(?m)^(?=      - )', d)
        at = lambda name: next(i for i, s in enumerate(steps) if '- name: ' + name + '\n' in s)  # noqa: E731
        swapped = list(steps)
        p, o = at('Deploy production'), at('Observability off, production')
        swapped[p], swapped[o] = swapped[o], swapped[p]
        self.assertEqual(gate_faults(''.join(swapped)), ['fleet-kit: a deploy between settings-off and its gate'])
        dropped = [s for i, s in enumerate(steps) if i != at('Observability off, staging')]
        self.assertEqual(gate_faults(''.join(dropped)), ['fleet-kit-staging: no settings-off before its gate'])
        g = at('Settings gate, staging')
        extra = steps[:g] + ['      - run: npx --no-install wrangler versions deploy --env staging\n'] + steps[g:]
        self.assertEqual(gate_faults(''.join(extra)), ['fleet-kit-staging: a deploy between settings-off and its gate'])

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

    def test_observability_off_runs_right_after_each_deploy_with_the_settings_env_and_before_its_gate(self):
        names = [s.get('name', '') for s in self.steps]
        for env, worker in (('staging', 'fleet-kit-staging'), ('production', 'fleet-kit')):
            off, gate = self.named('Observability off, %s' % env), self.named('Settings gate, %s' % env)
            self.assertEqual(off['run'].strip(), 'python3 bin/fleet-kit-check.py settings-off %s' % worker)
            self.assertEqual(off['env'], gate['env'])                                       # same env, no new secret
            self.assertEqual(sorted(off), ['env', 'name', 'run'])
            at = names.index(off['name'])
            self.assertEqual(names[at - 1], self.named('Deploy %s' % env)['name'], env)   # right after the deploy
            self.assertLess(at, names.index(gate['name']), env)


if __name__ == '__main__':
    unittest.main()
