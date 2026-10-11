#!/usr/bin/env python3
"""K6: the checks .github/workflows/kit-deploy.yml runs around a deploy of the kit Workers (kit/). Standard library only,
plus the `openssl` binary (3.x: Ed25519 with -rawin) for the throwaway admin keys.

  keys DIR            make the two throwaway Ed25519 admin keys (upload, gateway) in DIR (0700, files 0600) and print
                      KIT_UP_PUB=<64 hex> and KIT_GW_PUB=<64 hex> (public halves only) for $GITHUB_ENV.
  console DIR         refuse if the Worker sources in DIR call console.* (observability is off, but a log line would still be
                      the one thing that writes an invite code somewhere; tests and test stand-ins are not scanned).
  has-secret NAME     stdin = `wrangler secret list --format json`. Exit 0 present, 10 absent (the list parsed and lacks the
                      name; nothing else ever returns 10), 2 anything else (unreadable, a crash, a bad name). Names only.
  settings-off WORKER write the off record explicitly: PATCH .../workers/scripts/WORKER/script-settings with the JSON
                      {observability: OBSERVABILITY_OFF, logpush: false, tail_consumers: []} (OBSERVABILITY_OFF is
                      kit/wrangler.jsonc's block, a test holds them equal), and refuse unless the API answers 200, success
                      true, and echoes each of the three keys back off (null or a missing key is a refusal, named). Why a
                      deploy alone is not trusted: wrangler 4.149's first deploy of a Worker (the kit has a DO migration)
                      takes the PUT path and never PATCHes script-settings, and a later deploy's PATCH of it swallows every
                      error. Staging had been deployed before (run 38076806590); run 38095547741 then read
                      `observability: null` from an endpoint the old unlabelled gate did not name (script-settings, by the
                      schema: only it may answer null). What null means is undocumented, so it is never off. Whether this
                      write changes what the API answers is not yet measured: the next live run is that measurement.
  settings WORKER     read the Worker's settings back from the Cloudflare API (token and account id from the environment)
                      from three endpoints (.../scripts/WORKER/settings, .../scripts/WORKER/script-settings and the GA
                      .../workers/workers/WORKER) and refuse by judge_settings' rules: script-settings and the GA worker
                      read must each answer and report observability explicitly off; settings may stay silent on it but
                      never say anything else; the GA read must report `tail_consumers: []` and `logpush: false`, and any
                      endpoint that reports either otherwise refuses; workers.dev on, preview URLs off. A refusal names
                      the endpoint and key paths, never a value. Null is never a report of "off".
  replay URL          the kit-serve vectors over HTTP against the STAGING Worker (admin keys from $KIT_GATE_DIR): identical
                      404 bytes, 429 after 30, the cap, release on a cut stream, floor, expiry, revoke, bad sha, overwrite,
                      gzip, Range, the admin rules. It makes its own invites and cleans them up.
  probe URL           the hostile probe against PRODUCTION: at most 5 well-formed failures, every answer byte-identical
                      to the first apart from date and cf-ray, one of them with Accept-Encoding: gzip.

Nothing here prints an invite code, a key, a token or a response body; it prints vector names, statuses and numbers.
Exit 0 passed, 1 refused (the reason is the last line), 2 usage.

Not covered, on purpose: the R2 side of the guarded surface (r2.dev public URL off, no custom domain on the bucket, no S3
token) is not readable with the deploy token, which has no R2 permission; the owner's monthly look covers it. The replay's
(b) isolate-restart and (d) 100000-requests-a-day measurements cannot be taken over HTTP and are printed as unmeasured."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import secrets
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ALPHABET = '23456789CFGHJMPQRVWX'      # the invite alphabet (N02): 10 symbols of it
NOT_FOUND = b'not found\n'
TRY_LATER = b'try later\n'
VARYING = frozenset({'date', 'cf-ray'})  # the only headers that may differ between two answers
SECRET_NAME = re.compile(r'[A-Z][A-Z0-9_]{0,63}')
CF_API = 'https://api.cloudflare.com/client/v4'
UA = 'fleet-kit-deploy-check/1'
# kit/wrangler.jsonc's observability block (both envs; a test holds all three equal). settings-off writes exactly this.
OBSERVABILITY_OFF = {'enabled': False, 'issues': {'enabled': False},
                     'logs': {'enabled': False, 'invocation_logs': False, 'persist': False},
                     'traces': {'enabled': False, 'persist': False}}
SETTINGS_OFF = {'observability': OBSERVABILITY_OFF, 'logpush': False, 'tail_consumers': []}
# The settings gate's endpoints, by label. script-settings and the GA worker read MUST report an explicit off; settings'
# schema makes observability optional there, so it may stay silent (but never say anything but off).
MUST_REPORT_OFF = ('script-settings', 'worker')
FAILURE_BUDGET_PER_SOURCE = 30          # kit/gate-core.js LIMITS.perSource
PROBE_MAX_FAILURES = 5                  # the hostile probe may spend at most this much of production's hourly budget
# Worker sources that ship (everything else in kit/ is a test or a test stand-in).
SKIP_NAME = re.compile(r'(\.test\.m?js|\.test-util\.m?js|^run-tests\.m?js|^fake-storage\.m?js)$')
SOURCE_SUFFIXES = frozenset({'.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx'})
# `console.x`, `console?.x`, `console [x]`, `= console` (alias, destructuring), `globalThis.console`: matched on the whole
# text, so `console` and `.log` split over two lines do not get past it.
CONSOLE_RE = re.compile(r'\bconsole\s*(?:\?\.|\.|\[)|=\s*console\b|\.\s*console\b')
# The staging fixtures: fixed serials and fixed bytes, so a re-run is an identical re-upload and R2 does not grow.
S_BASE = 900000000


class Refused(Exception):
    pass


def say(text: str = '') -> None:
    print(text, flush=True)


def summary(lines: list[str]) -> None:
    """Numbers only. Printed, and appended to the job summary when GitHub gave us a file for it."""
    for line in lines:
        say(line)
    path = os.environ.get('GITHUB_STEP_SUMMARY')
    if path:
        with open(path, 'a', encoding='utf-8') as fh:
            fh.write('\n'.join(lines) + '\n')


# ---- keys -----------------------------------------------------------------------------------------------------------

def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)


def make_keys(directory: str) -> list[str]:
    os.umask(0o077)
    base = Path(directory)
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    lines = []
    for role, var in (('upload', 'KIT_UP_PUB'), ('gateway', 'KIT_GW_PUB')):
        pem = base / ('%s.pem' % role)
        if pem.exists():
            raise Refused('%s exists: throwaway keys are made once per job' % pem.name)
        run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(pem)])
        os.chmod(pem, 0o600)
        der = run(['openssl', 'pkey', '-in', str(pem), '-pubout', '-outform', 'DER']).stdout
        if len(der) != 44:
            raise Refused('%s: unexpected public key length %d' % (role, len(der)))
        lines.append('%s=%s' % (var, der[-32:].hex()))
    return lines


# ---- console / secrets / settings -------------------------------------------------------------------------------------

def scan_console(directory: str) -> list[str]:
    """Every console use in a shipped source under `directory` (recursive, node_modules aside), as path:line. Comments count
    (the cheap rule is the safe one). A shipped file that imports a skipped test file is refused: that file ships too."""
    root = Path(directory)
    paths = sorted(p for p in root.rglob('*') if p.is_file() and p.suffix in SOURCE_SUFFIXES
                   and 'node_modules' not in p.relative_to(root).parts)
    shipped = [p for p in paths if not SKIP_NAME.search(p.name)]
    skipped = [p for p in paths if SKIP_NAME.search(p.name)]
    if not shipped:
        raise Refused('no Worker source in %s: the scan would pass over nothing' % directory)
    hits = []
    for path in shipped:
        text = path.read_text(encoding='utf-8')
        rel = path.relative_to(root).as_posix()
        for other in skipped:
            if re.search(r'[\'"`/]' + re.escape(other.stem) + r'(?:\.[cm]?[jt]sx?)?[\'"`]', text):
                raise Refused('%s imports %s, a test file the scan skips' % (rel, other.name))
        lines = {text.count('\n', 0, m.start()) + 1 for m in CONSOLE_RE.finditer(text)}
        hits.extend('%s:%d' % (rel, n) for n in sorted(lines))
    return hits


def secret_names(text: str) -> set[str]:
    """The names in `wrangler secret list --format json`: a JSON array of {name, type}. Tolerates log lines before it."""
    decoder = json.JSONDecoder()
    start = text.find('[')
    if start < 0:
        raise Refused('secret list: no JSON array')
    try:
        data, _ = decoder.raw_decode(text[start:])
    except ValueError:
        raise Refused('secret list: unreadable JSON') from None
    if not isinstance(data, list) or not all(isinstance(x, dict) and isinstance(x.get('name'), str) for x in data):
        raise Refused('secret list: not a list of {name}')
    return {x['name'] for x in data}


def _not_off_paths(node, prefix='') -> list[tuple[str, str]]:
    """(dotted key path, word) for every `enabled` at any depth under node whose value is not exactly false: 'on' for a
    literal true, 'not false' for anything else (1, "true", null, an object, a list). Key names and fixed words only."""
    found = []
    if isinstance(node, dict):
        for k, v in node.items():
            path = prefix + ascii(str(k))[1:-1]       # escaped: a key never injects a newline or a log command
            if k == 'enabled':
                if v is not False:
                    found.append((path, 'on' if v is True else 'not false'))
            else:
                found += _not_off_paths(v, path + '.')
    elif isinstance(node, list):
        for i, v in enumerate(node):
            found += _not_off_paths(v, '%s[%d].' % (prefix[:-1], i))
    return found


def _observability_faults(obs: dict) -> list[tuple[str, str]]:
    """Why an observability object is not off, as (key path, word): `enabled` missing at the top, any `enabled` not exactly
    false at any depth, and a present `logs`/`traces` that is not an object or an `issues` that is neither an object nor
    null (the schema's shapes; a string there cannot be judged off)."""
    faults = [] if 'enabled' in obs else [('enabled', 'missing')]
    for key, nullable in (('logs', False), ('traces', False), ('issues', True)):
        if key in obs and not isinstance(obs[key], dict) and not (nullable and obs[key] is None):
            faults.append((key, 'not an object'))
    return faults + _not_off_paths(obs)


def _why_observability_on(obs) -> str:
    """The one detail line that follows `observability is not off`: key paths and fixed words, never a value."""
    if obs is None:
        return 'observability: null'
    if not isinstance(obs, dict):
        return 'observability: not an object (%s)' % type(obs).__name__
    faults = _observability_faults(obs)
    if not faults:
        return 'observability: not off'               # unreachable while _observability_off uses the same faults
    cut = lambda p: p if len(p) <= 80 else p[:77] + '...'   # noqa: E731
    shown = faults[:8]
    on = [cut(p) for p, w in shown if w == 'on']
    parts = (['observability on: ' + ', '.join(on)] if on else []) + \
            ['observability.%s: %s' % (cut(p), w) for p, w in shown if w != 'on']
    return '; '.join(parts) + (' (+%d more)' % (len(faults) - 8) if len(faults) > 8 else '')


def _observability_off(obs) -> bool:
    """The one explicit-off judge (the gate and settings-off's echo both use it): an object whose `enabled` is exactly
    false, with every `enabled` under it exactly false and logs/traces/issues of the schema's shape. null, a missing
    `enabled`, a truthy non-boolean anywhere, or anything else is not off."""
    return isinstance(obs, dict) and not _observability_faults(obs)


def judge_settings(blobs: dict[str, dict], subdomain: dict) -> list[str]:
    """Why these settings are refused ([] = fine). `blobs` maps an endpoint label ('settings' = GET .../scripts/W/settings,
    'script-settings' = GET .../scripts/W/script-settings, 'worker' = the GA GET .../workers/workers/W) to the `result`
    object it answered; an endpoint that did not answer is not in it. The rules:
      (a) on ANY endpoint, an `observability` that is present but is not an object with every `enabled` in it exactly
          false (and logs/traces/issues of the schema's shape) is a refusal, null included (null is undocumented, so it
          is never off and never "says nothing");
      (b) script-settings MUST answer and report an explicit off (absent = "script-settings: observability not reported");
      (c) settings may omit `observability` (its schema makes it optional), but if present it is held to (a);
      (d) the GA worker read MUST answer and report an explicit off (its schema requires the key);
      (e) `tail_consumers` an empty list and `logpush` an explicit false on every blob that reports them; null on either
          is "not reported" (it never counts as a report, and the next rule needs one). The GA worker read MUST report
          both (its schema requires them, non-null): `tail_consumers: []` and `logpush: false`, else a refusal;
      (f) the subdomain: workers.dev on, preview URLs explicitly off.
    Every detail names the endpoint and key paths, never a value. A missing answer is never a pass."""
    bad = []
    tail_seen = logpush_seen = tail_bad = logpush_bad = False
    for ep, blob in blobs.items():
        if 'observability' in blob:                                            # (a), (c)
            if not _observability_off(blob['observability']):
                bad.append('%s: observability is not off (%s)' % (ep, _why_observability_on(blob['observability'])))
        elif ep in MUST_REPORT_OFF:                                            # (b), (d)
            bad.append('%s: observability not reported' % ep)
        if 'tail_consumers' in blob:                                           # (e)
            tails = blob['tail_consumers']
            if tails == []:
                tail_seen = True
            elif tails is not None:                 # null says nothing, like logpush's: it is never "no consumers"
                tail_bad = True
                bad.append('%s: tail consumers: %s' % (ep, len(tails) if isinstance(tails, list) else 'unreadable'))
        if 'logpush' in blob:
            if blob['logpush'] is False:
                logpush_seen = True
            elif blob['logpush'] is not None:       # null says nothing: it stays "not reported" below
                logpush_bad = True
                bad.append('%s: logpush is on' % ep)
    for ep in MUST_REPORT_OFF:                                                 # (b), (d): an endpoint that did not answer
        if ep not in blobs:
            bad.append('%s: did not answer' % ep)
    worker = blobs.get('worker')
    if worker is not None:                                                     # (e): the GA read reports both, non-null
        if worker.get('tail_consumers') is None:
            bad.append('worker: tail_consumers not reported')
        if worker.get('logpush') is None:
            bad.append('worker: logpush not reported')
    asked = ', '.join(blobs) or 'no endpoint'
    if not tail_seen and not tail_bad:
        bad.append('tail_consumers: not reported (%s)' % asked)
    if not logpush_seen and not logpush_bad:
        bad.append('logpush: not reported (%s)' % asked)
    if subdomain.get('enabled') is not True:
        bad.append('workers.dev is not on')
    if subdomain.get('previews_enabled') is not False:
        bad.append('preview URLs are not off')
    return sorted(set(bad))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Follow nothing: urllib would re-send the Authorization header (the deploy token) to wherever a 3xx points."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(NoRedirect)


def _open(req, timeout):
    return _OPENER.open(req, timeout=timeout)


def _cf_url(path: str, verb: str) -> str:
    """CF_API + path, refused unless it is api.cloudflare.com over https (the token goes nowhere else)."""
    url = urllib.parse.urlsplit(CF_API + path)
    if url.scheme != 'https' or url.hostname != 'api.cloudflare.com':
        raise Refused('%s: the API host is not api.cloudflare.com over https' % verb)
    return CF_API + path


def _check_ids(verb: str, worker: str, account: str) -> None:
    if not re.fullmatch(r'[a-z0-9-]{1,63}', worker) or not re.fullmatch(r'[0-9a-f]{32}', account):
        raise Refused('%s: worker name or account id malformed' % verb)


def cf_get(path: str, token: str, label: str | None = None) -> dict | None:
    label = label or path.rsplit('/', 1)[-1]
    req = urllib.request.Request(_cf_url(path, 'settings'), headers={'Authorization': 'Bearer ' + token, 'User-Agent': UA})
    try:
        with _open(req, 30) as resp:
            doc = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        say('settings: GET %s -> HTTP %d' % (label, e.code))
        e.close()
        return None
    except (urllib.error.URLError, ValueError, TimeoutError) as e:
        raise Refused('settings: GET %s failed (%s)' % (label, type(e).__name__)) from None
    if not isinstance(doc, dict) or doc.get('success') is not True or not isinstance(doc.get('result'), dict):
        say('settings: GET %s -> success is not true' % label)
        return None
    return doc['result']


def check_settings(worker: str, token: str, account: str) -> dict:
    _check_ids('settings', worker, account)
    base = '/accounts/%s/workers/scripts/%s' % (account, worker)
    # Three endpoints carry the script settings, each labelled for judge_settings (which says which must answer).
    asked = (('settings', base + '/settings'), ('script-settings', base + '/script-settings'),
             ('worker', '/accounts/%s/workers/workers/%s' % (account, worker)))     # GA getWorker: worker_id may be the name
    blobs = {label: b for label, path in asked if (b := cf_get(path, token, label)) is not None}
    sub = cf_get(base + '/subdomain', token)
    if not blobs or sub is None:
        raise Refused('settings: the API did not answer (%d settings, subdomain %s)' % (len(blobs), 'yes' if sub else 'no'))
    bad = judge_settings(blobs, sub)
    if bad:
        raise Refused('settings of %s: %s' % (worker, '; '.join(bad)))
    return {'worker': worker, 'sources': len(blobs)}


def _echo_not_off(echo: dict) -> list[str]:
    """What in settings-off's echoed result is not the off record (key names only, never a value)."""
    bad = []
    if 'observability' not in echo:
        bad.append('observability not echoed')
    elif not _observability_off(echo['observability']):
        bad.append(_why_observability_on(echo['observability']))
    for key, off, word in (('logpush', False, 'is not false'), ('tail_consumers', [], 'is not empty')):
        if key not in echo:
            bad.append('%s not echoed' % key)
        elif echo[key] is None:                     # null is never off: the record was written as false / []
            bad.append('%s echoed null' % key)
        elif echo[key] != off or (key == 'logpush' and echo[key] is not False):
            bad.append('%s %s' % (key, word))
    return bad


def settings_off(worker: str, token: str, account: str) -> dict:
    """PATCH SETTINGS_OFF to the script-settings record and hold the echo to the same explicit-off judge. Passes only on
    HTTP 200, `success: true` and an echo that is off; everything else is refused, naming the endpoint, never a body."""
    _check_ids('settings-off', worker, account)
    where = 'settings-off: PATCH script-settings'
    path = '/accounts/%s/workers/scripts/%s/script-settings' % (account, worker)
    req = urllib.request.Request(_cf_url(path, 'settings-off'), data=jbody(SETTINGS_OFF), method='PATCH',
                                 headers={'Authorization': 'Bearer ' + token, 'User-Agent': UA,
                                          'Content-Type': 'application/json'})
    try:
        with _open(req, 30) as resp:
            if resp.status != 200:
                raise Refused('%s -> HTTP %d, not 200' % (where, resp.status))
            doc = json.loads(resp.read())
    except urllib.error.HTTPError as e:              # NoRedirect: a 3xx lands here too, never followed
        code = e.code
        e.close()
        raise Refused('%s -> HTTP %d' % (where, code)) from None
    except (OSError, ValueError, http.client.HTTPException) as e:  # URLError and timeouts are OSErrors; non-JSON a ValueError
        raise Refused('%s failed (%s)' % (where, type(e).__name__)) from None
    if not isinstance(doc, dict) or doc.get('success') is not True:
        raise Refused('%s -> success is not true' % where)
    if not isinstance(doc.get('result'), dict):
        raise Refused('%s -> no result echoed' % where)
    bad = _echo_not_off(doc['result'])
    if bad:
        raise Refused('%s -> the echo is not off: %s' % (where, '; '.join(bad)))
    return {'worker': worker}


# ---- the HTTP client ---------------------------------------------------------------------------------------------------

class Resp:
    def __init__(self, status, headers, body, ms, conn=None, raw=None):
        self.status, self.headers, self.body, self.ms, self.conn, self.raw = status, headers, body, ms, conn, raw

    def header(self, name):
        for k, v in self.headers:
            if k == name:
                return v
        return None

    def read(self, n):
        return self.raw.read(n)

    def close(self):
        if self.conn is not None:
            self.conn.close()


class Client:
    """One connection per request, headers sent exactly as given (a repeated name stays repeated), nothing followed."""

    def __init__(self, base: str, allow_http: bool = False, timeout: float = 120):
        u = urllib.parse.urlsplit(base)
        if u.scheme not in ('https', 'http') or (u.scheme == 'http' and not allow_http) or not u.hostname or u.path not in ('', '/'):
            raise Refused('base url must be https://host')
        self.scheme, self.host, self.port, self.timeout = u.scheme, u.hostname, u.port, timeout

    def request(self, method, path, headers=(), body=None, read=True) -> Resp:
        cls = http.client.HTTPSConnection if self.scheme == 'https' else http.client.HTTPConnection
        conn = cls(self.host, self.port, timeout=self.timeout)
        names = {k.lower() for k, _ in headers}
        t0 = time.monotonic()
        try:
            conn.putrequest(method, path, skip_accept_encoding=True)
            if 'accept-encoding' not in names:
                conn.putheader('Accept-Encoding', 'identity')
            conn.putheader('User-Agent', UA)
            conn.putheader('Connection', 'close')
            for k, v in headers:
                conn.putheader(k, v)
            if body is not None and 'content-length' not in names:
                conn.putheader('Content-Length', str(len(body)))
            conn.endheaders(body)
            raw = conn.getresponse()
            data = raw.read() if read else None
            ms = (time.monotonic() - t0) * 1000
            resp = Resp(raw.status, [(k.lower(), v) for k, v in raw.getheaders()], data, ms, None if read else conn, raw)
        except (OSError, http.client.HTTPException) as e:
            conn.close()
            raise Refused('%s: no answer (%s)' % (method, type(e).__name__)) from None
        if read:
            conn.close()
        return resp


def norm(resp: Resp):
    return (resp.status, tuple(sorted((k, v) for k, v in resp.headers if k not in VARYING)), resp.body)


def differs(a: Resp, b: Resp) -> str:
    if a.status != b.status:
        return 'status %d vs %d' % (a.status, b.status)
    ha = sorted((k, v) for k, v in a.headers if k not in VARYING)
    hb = sorted((k, v) for k, v in b.headers if k not in VARYING)
    if ha != hb:
        names = sorted({k for k, _ in set(ha) ^ set(hb)})
        return 'headers differ: %s' % ', '.join(names)
    return 'body differs'


def expect(label: str, resp: Resp, status: int) -> Resp:
    if resp.status != status:
        raise Refused('%s: status %d, expected %d' % (label, resp.status, status))
    return resp


def check_fixed_answer(label: str, resp: Resp, status: int, body: bytes) -> None:
    expect(label, resp, status)
    if resp.body != body:
        raise Refused('%s: the body is not the fixed answer' % label)
    ctype = resp.header('content-type') or ''
    if not ctype.startswith('text/plain'):
        raise Refused('%s: content-type is not text/plain' % label)
    if resp.header('cache-control') != 'no-store, no-transform':
        raise Refused('%s: cache-control is not no-store, no-transform' % label)
    for h in ('content-encoding', 'location', 'set-cookie'):
        if resp.header(h) is not None:
            raise Refused('%s: has a %s header' % (label, h))


def all_identical(label: str, answers: list[tuple[str, Resp]]) -> None:
    first_label, first = answers[0]
    for name, resp in answers[1:]:
        if norm(resp) != norm(first):
            raise Refused('%s: "%s" differs from "%s": %s' % (label, name, first_label, differs(resp, first)))


# ---- the admin calls ---------------------------------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Admin:
    """kit-admin-v1: Ed25519 over `kit-admin-v1\\n<role>\\n<ts_ms>\\n<METHOD>\\n<path>\\n<sha256hex(body)>`, by openssl."""

    def __init__(self, client: Client, gate_dir: str):
        self.client, self.dir, self.last = client, Path(gate_dir), {}

    def next_ts(self, role: str) -> int:
        ts = max(int(time.time() * 1000), self.last.get(role, 0) + 1)
        self.last[role] = ts
        return ts

    def sign(self, role: str, ts: int, method: str, path: str, digest: str) -> str:
        message = ('kit-admin-v1\n%s\n%d\n%s\n%s\n%s' % (role, ts, method, path, digest)).encode()
        with tempfile.TemporaryDirectory(dir=str(self.dir)) as tmp:
            msg, sig = Path(tmp, 'm'), Path(tmp, 's')
            msg.write_bytes(message)
            run(['openssl', 'pkeyutl', '-sign', '-inkey', str(self.dir / ('%s.pem' % role)), '-rawin', '-in', str(msg), '-out', str(sig)])
            raw = sig.read_bytes()
        if len(raw) != 64:
            raise Refused('signature length %d' % len(raw))
        return raw.hex()

    def call(self, role, method, path, body=b'', *, ts=None, stream_digest=None, sig=None) -> Resp:
        ts = self.next_ts(role) if ts is None else ts
        digest = stream_digest or sha256_hex(body)
        sig = sig or self.sign(role, ts, method, path, digest)
        headers = [('Authorization', 'KitAdmin %s %d %s' % (role, ts, sig))]
        if stream_digest:
            headers.append(('X-Kit-Sha256', stream_digest))
        elif body:
            headers.append(('Content-Type', 'application/json'))
        return self.client.request(method, path, headers, body if (body or method in ('PUT', 'POST')) else None)


def jbody(obj) -> bytes:
    return json.dumps(obj, separators=(',', ':')).encode()


def admin_json(label: str, resp: Resp, status: int = 200, error: str | None = None) -> dict:
    expect(label, resp, status)
    try:
        doc = json.loads(resp.body)
    except ValueError:
        raise Refused('%s: the reply is not JSON' % label) from None
    if not isinstance(doc, dict):
        raise Refused('%s: the reply is not an object' % label)
    if status == 200 and doc.get('ok') is not True:
        raise Refused('%s: ok is not true' % label)
    if error is not None and doc.get('error') != error:
        raise Refused('%s: error is %r, expected %r' % (label, doc.get('error'), error))
    return doc


# ---- the public request shapes -----------------------------------------------------------------------------------------

def random_code() -> str:
    return ''.join(secrets.choice(ALPHABET) for _ in range(10))


def get_kit(client: Client, serial, name: str, code: str, extra=()) -> Resp:
    return client.request('GET', '/v1/kit/%s/%s' % (serial, name), [('Authorization', 'FleetInvite ' + code)] + list(extra))


def front_rejects(client: Client, good_code: str) -> list[tuple[str, Resp]]:
    """Requests the front answers with the one 404 before any database touch (so they spend no budget)."""
    ok_auth = ('Authorization', 'FleetInvite ' + good_code)
    p = '/v1/kit/900000001/bundle.tar'
    cases = [
        ('POST', 'POST', p, [ok_auth], b''),
        ('PUT', 'PUT', p, [ok_auth], b''),
        ('extra segment', 'GET', p + '/x', [ok_auth], None),
        ('query', 'GET', p + '?x=1', [ok_auth], None),
        ('ten digit serial', 'GET', '/v1/kit/9000000010/bundle.tar', [ok_auth], None),
        ('other file name', 'GET', '/v1/kit/900000001/other.tar', [ok_auth], None),
        # a forced lowercase letter: good_code.lower() would equal good_code when the code is all digits
        ('lowercase code', 'GET', p, [('Authorization', 'FleetInvite c' + good_code[1:])], None),
        ('short code', 'GET', p, [('Authorization', 'FleetInvite ' + good_code[:9])], None),
        ('forbidden symbol', 'GET', p, [('Authorization', 'FleetInvite 0' + good_code[1:])], None),
        ('wrong scheme', 'GET', p, [('Authorization', 'Bearer ' + good_code)], None),
        ('no authorization', 'GET', p, [], None),
        ('two authorization headers', 'GET', p, [ok_auth, ok_auth], None),
        ('root', 'GET', '/', [], None),
        ('v1 kit root', 'GET', '/v1/kit/', [ok_auth], None),
        ('robots', 'GET', '/robots.txt', [], None),
        ('admin unsigned state', 'GET', '/_k/state', [], None),
        ('admin unsigned put', 'PUT', '/_k/file/1/bundle.tar', [], b'abc'),
        ('admin zero signature', 'GET', '/_k/state', [('Authorization', 'KitAdmin gateway %d %s' % (int(time.time() * 1000), '0' * 128))], None),
    ]
    return [(label, client.request(m, path, headers, body)) for label, m, path, headers, body in cases]


# ---- the staging replay ------------------------------------------------------------------------------------------------

def det_bytes(label: str, n: int) -> bytes:
    return hashlib.shake_256(('fleet-kit-staging:%s' % label).encode()).digest(n)


def run_replay(client: Client, admin: Admin, *, big_mib: int = 16, cut_wait: float = 5.0, small_bytes: int = 65536,
               short_life_ms: int = 12000, ready_timeout: float = 90, sleep=time.sleep, log=say) -> list[str]:
    s1, s2, s3, s4, s5, gser = (S_BASE + i for i in (1, 2, 3, 4, 5, 1))
    small = det_bytes('s1', small_bytes)
    other = det_bytes('s5', small_bytes)
    big = det_bytes('s2', big_mib * 1024 * 1024)
    wrong = det_bytes('wrong', small_bytes)           # same length as `small`, other bytes
    gjson, gsig = det_bytes('gateway.json', 200), det_bytes('gateway.json.sig', 64)
    refs: list[str] = []
    seen404: list[tuple[str, Resp]] = []
    fails = 0                                          # well-formed failures spent at the gate, as the replay counts them
    vectors = 0
    m: dict = {}

    def vector(label: str) -> None:
        nonlocal vectors
        vectors += 1
        log('vector %s' % label)

    def gate_404(label: str, resp: Resp) -> None:
        nonlocal fails
        expect(label, resp, 404)
        fails += 1
        seen404.append((label, resp))

    def download(label: str, resp: Resp, data: bytes) -> None:
        expect(label, resp, 200)
        if resp.header('content-type') != 'application/octet-stream':
            raise Refused('%s: content-type is not application/octet-stream' % label)
        if resp.header('cache-control') != 'no-store, no-transform':
            raise Refused('%s: cache-control is not no-store, no-transform' % label)
        if resp.header('content-length') != str(len(data)) or resp.header('transfer-encoding') is not None:
            raise Refused('%s: not an exact Content-Length' % label)
        for h in ('content-encoding', 'location', 'set-cookie'):
            if resp.header(h) is not None:
                raise Refused('%s: has a %s header' % (label, h))
        if resp.body != data:
            raise Refused('%s: the bytes are not the uploaded bytes' % label)

    try:
        # A fresh deploy takes a moment to reach every edge: wait until the gateway key answers.
        deadline = time.monotonic() + ready_timeout
        while True:
            r = admin.call('gateway', 'GET', '/_k/state')
            if r.status == 200:
                break
            if time.monotonic() > deadline:
                raise Refused('the staging Worker did not answer an admin call (last status %d)' % r.status)
            sleep(3)
        state = admin_json('state', r, 200)
        offset = state['now'] - int(time.time() * 1000)

        # -- uploads (upload role) ------------------------------------------------------------------------------------
        for label, serial, data in (('upload small', s1, small), ('upload big', s2, big), ('upload other', s5, other)):
            vector(label)
            d = admin_json(label, _put_bundle(admin, serial, data))
            if d.get('sha256') != sha256_hex(data) or d.get('size') != len(data):
                raise Refused('%s: R2 holds other bytes than were sent' % label)
        vector('identical re-upload')
        r = _put_bundle(admin, s1, small)
        admin_json('identical re-upload', r, 200)
        m['c_identical'] = r.status
        vector('overwrite refused')
        r = _put_bundle(admin, s1, wrong)
        admin_json('overwrite', r, 409)
        m['c_overwrite'] = r.status
        vector('wrong bytes refused')
        r = admin.call('upload', 'PUT', '/_k/file/%d/bundle.tar' % s3, wrong, stream_digest=sha256_hex(small))
        admin_json('wrong bytes', r, 422, 'checksum')
        m['c_wrong_bytes'] = r.status
        vector('gateway pair')
        gbody = jbody({'json': base64.b64encode(gjson).decode(), 'sig': base64.b64encode(gsig).decode()})
        d = admin_json('gateway pair', admin.call('upload', 'PUT', '/_k/gateway/%d' % gser, gbody), 200)
        if d.get('json', {}).get('sha256') != sha256_hex(gjson) or d.get('sig', {}).get('sha256') != sha256_hex(gsig):
            raise Refused('gateway pair: R2 holds other bytes than were sent')
        admin_json('gateway pair again', admin.call('upload', 'PUT', '/_k/gateway/%d' % gser, gbody), 200)
        admin_json('gateway rollback', admin.call('upload', 'PUT', '/_k/gateway/%d' % (gser - 1), gbody), 409, 'rollback')
        admin_json('floor 0', admin.call('upload', 'PUT', '/_k/floor', jbody({'floor': 0})), 200)

        # -- invites (gateway role) -----------------------------------------------------------------------------------
        def add_invite(label, *, cap, lo, hi, life_ms, status=200, error=None) -> tuple[str, str]:
            ref = 'r' + secrets.token_hex(8)
            code = random_code()
            body = jbody({'ref': ref, 'code': code, 'tier': 'install', 'lo': lo, 'hi': hi,
                          'exp': int(time.time() * 1000) + offset + life_ms, 'cap': cap})
            r = admin.call('gateway', 'POST', '/_k/invite', body)
            for _ in range(10):          # 503: the new pepper has not reached this edge yet
                if r.status != 503 or status != 200:
                    break
                sleep(3)
                r = admin.call('gateway', 'POST', '/_k/invite', body)
            admin_json(label, r, status, error)
            if status == 200:
                refs.append(ref)
            return code, ref

        half_hour = 30 * 60 * 1000
        code_w, _ = add_invite('invite W', cap=10, lo=s1, hi=s4, life_ms=half_hour)
        code_b, _ = add_invite('invite B', cap=2, lo=s2, hi=s2, life_ms=half_hour)
        code_r, ref_r = add_invite('invite R', cap=1, lo=s1, hi=s1, life_ms=half_hour)
        t_e = time.monotonic()
        code_e, _ = add_invite('invite E', cap=1, lo=s1, hi=s1, life_ms=short_life_ms)
        vector('ceilings')
        add_invite('ceiling downloads', cap=11, lo=s1, hi=s1, life_ms=half_hour, status=422, error='ceiling-downloads')
        add_invite('ceiling life', cap=1, lo=s1, hi=s1, life_ms=73 * 3600 * 1000, status=422, error='ceiling-life')

        vector('expiry, before')
        download('E before expiry', get_kit(client, s1, 'gateway.json', code_e), gjson)

        # -- the admin rules ------------------------------------------------------------------------------------------
        vector('admin: wrong role')
        r = admin.call('gateway', 'PUT', '/_k/floor', jbody({'floor': 0}))
        if r.status not in (403, 404):
            raise Refused('admin wrong role: status %d, expected 403 or 404' % r.status)
        vector('admin: stale')
        r = admin.call('gateway', 'GET', '/_k/state', ts=int(time.time() * 1000) - 10 * 60 * 1000)
        seen404.append(('admin stale', expect('admin stale', r, 404)))
        vector('admin: replay')
        ts = admin.next_ts('upload')
        fbody = jbody({'floor': 0})
        admin_json('replay first', admin.call('upload', 'PUT', '/_k/floor', fbody, ts=ts), 200)
        admin_json('replay second', admin.call('upload', 'PUT', '/_k/floor', fbody, ts=ts), 409, 'replay')

        # -- the public vectors ---------------------------------------------------------------------------------------
        vector('download, headers and bytes')
        download('W small', get_kit(client, s1, 'bundle.tar', code_w), small)                      # W used 1
        vector('download ignores Range')
        download('W Range', get_kit(client, s1, 'bundle.tar', code_w, [('Range', 'bytes=0-9')]), small)   # used 2
        vector('download with Accept-Encoding gzip')
        download('W gzip', get_kit(client, s1, 'bundle.tar', code_w, [('Accept-Encoding', 'gzip')]), small)  # used 3
        vector('gateway pair')
        download('W gateway.json', get_kit(client, s1, 'gateway.json', code_w), gjson)
        download('W gateway.json.sig', get_kit(client, s1, 'gateway.json.sig', code_w), gsig)
        vector('floor')
        admin_json('floor up', admin.call('upload', 'PUT', '/_k/floor', jbody({'floor': s2})), 200)
        gate_404('below the floor', get_kit(client, s1, 'bundle.tar', code_w))
        admin_json('floor down', admin.call('upload', 'PUT', '/_k/floor', jbody({'floor': 0})), 200)
        vector('out of range, absent file, bad-sha upload left nothing')
        gate_404('serial out of range', get_kit(client, s5, 'bundle.tar', code_w))
        gate_404('file absent', get_kit(client, s4, 'bundle.tar', code_w))
        gate_404('bad-sha upload left nothing', get_kit(client, s3, 'bundle.tar', code_w))
        vector('unknown code and gzip 404')
        gate_404('unknown code', get_kit(client, s1, 'bundle.tar', random_code()))
        gate_404('unknown code, gzip', get_kit(client, s1, 'bundle.tar', random_code(), [('Accept-Encoding', 'gzip')]))
        vector('cap of 10')
        for i in range(7):                                                                          # used 4..10
            download('W small #%d' % (i + 4), get_kit(client, s1, 'bundle.tar', code_w), small)
        gate_404('cap exhausted', get_kit(client, s1, 'bundle.tar', code_w))
        download('W gateway.json after the cap', get_kit(client, s1, 'gateway.json', code_w), gjson)  # never counts
        vector('revoke')
        download('R before revoke', get_kit(client, s1, 'gateway.json', code_r), gjson)
        admin_json('revoke', admin.call('gateway', 'DELETE', '/_k/invite/%s' % ref_r), 200)
        gate_404('revoked', get_kit(client, s1, 'gateway.json', code_r))
        vector('front rejects')
        for label, resp in front_rejects(client, code_w):
            expect(label, resp, 404)
            seen404.append((label, resp))

        vector('release on a cut stream')
        for i in (1, 2):
            cut = get_kit_cut(client, s2, code_b)
            if cut != 200:
                raise Refused('cut #%d: status %d, expected 200' % (i, cut))
            sleep(cut_wait)
        vector('after two cuts both downloads still fit')
        m['a_cuts'], m['a_restored'] = 2, 0
        for i in (1, 2):
            r = get_kit(client, s2, 'bundle.tar', code_b)
            if r.status == 200 and r.body == big:
                m['a_restored'] += 1
        if m['a_restored'] != 2:
            raise Refused('a cut stream did not give the download back (%d of 2 restored)' % m['a_restored'])
        gate_404('B third download', get_kit(client, s2, 'bundle.tar', code_b))

        vector('expiry, after')
        late = (short_life_ms + 2500) / 1000 - (time.monotonic() - t_e)
        if late > 0:
            sleep(late)
        gate_404('expired', get_kit(client, s1, 'gateway.json', code_e))

        # -- the budget: the last thing, it blocks this source for the hour --------------------------------------------
        vector('429 after 30')
        left = FAILURE_BUDGET_PER_SOURCE - fails
        if left < 1:
            raise Refused('the replay itself spent %d failures' % fails)
        served = 0
        resp429 = None
        while True:
            r = get_kit(client, s1, 'bundle.tar', random_code())
            if r.status == 429:
                resp429 = r
                break
            expect('budget loop #%d' % (served + 1), r, 404)
            seen404.append(('budget loop', r))
            served += 1
            if served > FAILURE_BUDGET_PER_SOURCE + 10:
                raise Refused('no 429 after %d failures' % (fails + served))
        if served != left:
            raise Refused('429 came after %d failures, expected after %d' % (fails + served, FAILURE_BUDGET_PER_SOURCE))
        m['b429_after'] = fails + served
        check_fixed_answer('429', resp429, 429, TRY_LATER)
        r = get_kit(client, s1, 'gateway.json', code_w)
        check_fixed_answer('valid request while the budget is spent', r, 429, TRY_LATER)
        r = client.request('POST', '/v1/kit/%d/bundle.tar' % s1, [('Authorization', 'FleetInvite ' + code_w)], b'')
        seen404.append(('front reject while the budget is spent', expect('front reject at 429', r, 404)))

        vector('identical 404 bytes')
        check_fixed_answer('404', seen404[0][1], 404, NOT_FOUND)
        all_identical('404', seen404)
    finally:
        _cleanup(admin, refs, log)
    ms = [r.ms for _, r in seen404]
    return [
        'kit-deploy staging replay: %d vectors passed' % vectors,
        '  404 answers compared: %d, identical' % len(seen404),
        '  429 after %d failures' % m['b429_after'],
        '  (a) client cuts: %d, count restored: %d' % (m['a_cuts'], m['a_restored']),
        '  (b) not measurable over HTTP (needs an isolate restart)',
        '  (c) wrong bytes: %d (R2 checksum), overwrite: %d (Worker head guard; the R2 onlyIf wildcard is not separately '
        'observable), identical re-upload: %d' % (m['c_wrong_bytes'], m['c_overwrite'], m['c_identical']),
        '  (d) not measurable here (needs 100000 requests in a day)',
        '  (g) 404 answers, wall clock ms: p50 %d, max %d (not CPU time)' % (statistics.median(ms), max(ms)),
    ]


def _put_bundle(admin: Admin, serial: int, data: bytes) -> Resp:
    return admin.call('upload', 'PUT', '/_k/file/%d/bundle.tar' % serial, data, stream_digest=sha256_hex(data))


def get_kit_cut(client: Client, serial: int, code: str, read_bytes: int = 262144) -> int:
    """Start a bundle download, read a little, hang up. Returns the status line's status."""
    resp = client.request('GET', '/v1/kit/%d/bundle.tar' % serial, [('Authorization', 'FleetInvite ' + code)], read=False)
    try:
        if resp.status == 200 and not resp.read(read_bytes):
            raise Refused('cut: the stream ended at once')
        return resp.status
    finally:
        resp.close()


def _cleanup(admin: Admin, refs: list[str], log) -> None:
    """Best effort, and never a reason to hide the real failure: revoke what was made, floor back to 0."""
    done = 0
    for ref in refs:
        try:
            if admin.call('gateway', 'DELETE', '/_k/invite/%s' % ref).status in (200, 409):
                done += 1
        except Refused:
            pass
    try:
        admin.call('upload', 'PUT', '/_k/floor', jbody({'floor': 0}))
    except Refused:
        pass
    log('cleanup: %d of %d invites revoked, floor 0' % (done, len(refs)))


# ---- the production probe ----------------------------------------------------------------------------------------------

def run_probe(client: Client, *, log=say) -> list[str]:
    """Hostile requests at production: every answer must be the same bytes (date and cf-ray aside). At most
    PROBE_MAX_FAILURES of them reach the gate (each spends one of this source's 30 an hour); the rest are shapes the front
    answers without touching it."""
    code = random_code()
    spent = 0
    answers: list[tuple[str, Resp]] = []
    gate_cases = [
        ('bundle, serial 1', 1, 'bundle.tar', []),
        ('bundle, serial 999999999', 999999999, 'bundle.tar', []),
        ('gateway.json, serial 7', 7, 'gateway.json', []),
        ('gateway.json.sig, serial 123456', 123456, 'gateway.json.sig', []),
        ('bundle with Accept-Encoding gzip', 1, 'bundle.tar', [('Accept-Encoding', 'gzip')]),
    ]
    if len(gate_cases) > PROBE_MAX_FAILURES:
        raise Refused('probe: more gate requests than the budget')
    for label, serial, name, extra in gate_cases:
        spent += 1
        answers.append((label, get_kit(client, serial, name, random_code(), extra)))
    answers.extend(front_rejects(client, code))
    for label, resp in answers:
        if resp.status in (429, 503):
            raise Refused('probe: "%s" answered %d' % (label, resp.status))
        log('probe %s -> %d' % (label, resp.status))
    check_fixed_answer('probe first answer', answers[0][1], 404, NOT_FOUND)
    all_identical('probe', answers)
    ms = [r.ms for _, r in answers]
    return [
        'kit-deploy production probe: %d answers, byte-identical, %d reached the gate' % (len(answers), spent),
        '  wall clock ms: p50 %d, max %d' % (statistics.median(ms), max(ms)),
    ]


ABSENT = 10     # has-secret: the list parsed and does not hold the name. No crash, refusal or usage error ever exits 10.


def read_stdin_text() -> str:
    buf = getattr(sys.stdin, 'buffer', None)
    return buf.read().decode('utf-8', errors='replace') if buf is not None else sys.stdin.read()


def has_secret(name: str) -> int:
    """0 present, ABSENT (10) absent, 2 for every other outcome. The workflow makes the production pepper on 10 only."""
    try:
        if not SECRET_NAME.fullmatch(name):
            raise Refused('bad secret name')
        present = name in secret_names(read_stdin_text())
    except Refused as e:
        say('REFUSED %s' % e)
        return 2
    except Exception as e:  # noqa: BLE001 - a crash must not read as "absent"
        say('REFUSED has-secret failed (%s)' % type(e).__name__)
        return 2
    return 0 if present else ABSENT


# ---- main --------------------------------------------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    for name in ('keys', 'console', 'has-secret', 'settings-off', 'settings', 'replay', 'probe'):
        sub.add_parser(name).add_argument('arg')
    args = ap.parse_args(argv)
    try:
        if args.cmd == 'keys':
            for line in make_keys(args.arg):
                say(line)
        elif args.cmd == 'console':
            hits = scan_console(args.arg)
            if hits:
                raise Refused('console call in a Worker source: %s' % ', '.join(hits))
            say('no console call in the Worker sources')
        elif args.cmd == 'has-secret':
            return has_secret(args.arg)
        elif args.cmd in ('settings', 'settings-off'):
            token, account = os.environ.get('CLOUDFLARE_API_TOKEN', ''), os.environ.get('CLOUDFLARE_ACCOUNT_ID', '')
            if not token or not account:
                raise Refused('%s: CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID are needed' % args.cmd)
            try:
                if args.cmd == 'settings-off':
                    settings_off(args.arg, token, account)
                    say('settings-off of %s: observability off, no Logpush, no tail consumer written and echoed back'
                        % args.arg)
                    return 0
                info = check_settings(args.arg, token, account)
            except Refused:
                raise
            except Exception as e:  # noqa: BLE001 - a dropped read or a too-deep JSON is a named refusal, not a traceback
                raise Refused('%s failed (%s)' % (args.cmd, type(e).__name__)) from None
            say('settings of %s: observability off, no tail consumer, no Logpush, workers.dev on, previews off (%d sources)'
                % (info['worker'], info['sources']))
        elif args.cmd == 'replay':
            gate_dir = os.environ.get('KIT_GATE_DIR', '')
            if not gate_dir:
                raise Refused('replay: KIT_GATE_DIR is needed')
            client = Client(args.arg)
            summary(run_replay(client, Admin(client, gate_dir)))
        elif args.cmd == 'probe':
            summary(run_probe(Client(args.arg)))
    except Refused as e:
        say('REFUSED %s' % e)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
