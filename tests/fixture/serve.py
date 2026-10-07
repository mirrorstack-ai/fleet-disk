"""The boot smoke's two local servers, stdlib only: HTTPS answers GitHub's release layout from one case folder (the
asset URL answers 302 to an object URL on the same origin, as GitHub does) plus /python/<v>/<zip> and /ping; plain HTTP
answers the leaf certificate's CRL and a case's `plain/` folder (what a downgrading redirect would lead to)."""
from __future__ import annotations

import http.server
import os
import re
import ssl
import sys
import threading
from urllib.parse import urlsplit

NAME = r'([A-Za-z0-9][A-Za-z0-9._-]{0,63})'
REL = re.compile(r'/releases/download/(install-(?:0|[1-9][0-9]{0,9}))/' + NAME)
OBJ = re.compile(r'/objects/(install-[0-9]{1,10})/' + NAME)
PY = re.compile(r'/python/([0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2})/' + NAME)  # a version, never `..`
PLAIN = re.compile(r'/(install-[0-9]{1,10})/' + NAME)


def _read(path: str) -> bytes | None:
    try:
        with open(path, 'rb') as f:
            return f.read()
    except OSError:
        return None


class Fixture:
    """Both servers on 127.0.0.1 (port 0 picks one); set_case() points them at <base>/<case> and clears the logs."""

    def __init__(self, base: str, host: str = '127.0.0.1', port: int = 18443, crl_port: int = 18444) -> None:
        self.base, self.case, self.log, self.http_log = base, '-', [], []
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(os.path.join(base, 'tls', 'leaf.crt'), os.path.join(base, 'tls', 'leaf.key'))
        self.https = self._start(host, port, True, ctx)
        self.http = self._start(host, crl_port, False, None)
        self.port, self.crl_port = self.https.server_address[1], self.http.server_address[1]

    def _start(self, host, port, secure, ctx):
        fx = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *args):  # silent
                pass

            def do_GET(self):
                path = urlsplit(self.path).path
                status, body, where = fx.answer(path, secure)
                (fx.log if secure else fx.http_log).append({
                    'path': path, 'status': status, 'ua': self.headers.get('User-Agent', ''),
                    'tls': self.connection.version() if secure else ''})
                self.send_response(status)
                if where:
                    self.send_header('Location', where)
                chunked = status == 200 and secure and fx.is_chunked(path)
                if chunked:  # no Content-Length: only a running count can stop it
                    self.send_header('Transfer-Encoding', 'chunked')
                else:
                    self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                if chunked:
                    for i in range(0, len(body), 4096):
                        self.wfile.write(b'%x\r\n' % len(body[i:i + 4096]) + body[i:i + 4096] + b'\r\n')
                    body = b'0\r\n\r\n'
                self.wfile.write(body)

        srv = http.server.ThreadingHTTPServer((host, port), Handler)
        srv.daemon_threads = True
        srv.handle_error = lambda *args: None  # a client that refuses the certificate is a case, not a traceback
        if ctx:
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def set_case(self, case: str) -> None:
        self.case = case
        self.log.clear()
        self.http_log.clear()

    def is_chunked(self, path: str) -> bool:
        """A case marks an asset to be sent chunked, with no Content-Length, by a `<name>.chunked` file beside it."""
        m = OBJ.fullmatch(path)
        return bool(m) and os.path.isfile(os.path.join(self.base, self.case, 'release', m[1], m[2] + '.chunked'))

    def answer(self, path: str, secure: bool) -> tuple[int, bytes, str | None]:
        d = os.path.join(self.base, self.case)
        if not secure:
            m = PLAIN.fullmatch(path)
            body = _read(os.path.join(self.base, 'tls', 'ca.crl')) if path == '/ca.crl' else (
                _read(os.path.join(d, 'plain', m[1], m[2])) if m else None)
            return (404, b'', None) if body is None else (200, body, None)
        if path == '/ping':
            return 200, b'pong', None
        if m := REL.fullmatch(path):
            f = os.path.join(d, 'release', m[1], m[2])
            moved = _read(f + '.redirect')  # a case that redirects this asset somewhere else
            if moved is not None:
                return 302, b'', moved.decode().strip()
            return (302, b'', f'/objects/{m[1]}/{m[2]}') if os.path.isfile(f) else (404, b'', None)
        if m := OBJ.fullmatch(path):
            body = _read(os.path.join(d, 'release', m[1], m[2]))
        elif m := PY.fullmatch(path):
            body = _read(os.path.join(d, 'python', m[1], m[2]))  # a case's own ZIP first (an oversize one), else the shared one
            if body is None:
                body = _read(os.path.join(self.base, 'python', m[1], m[2]))
        else:
            body = None
        return (404, b'', None) if body is None else (200, body, None)

    def close(self) -> None:
        for srv in (self.https, self.http):
            srv.shutdown()
            srv.server_close()

