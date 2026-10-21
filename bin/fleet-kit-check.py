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
                      true, and echoes all three keys: logpush exactly false, observability the off object or null,
                      tail_consumers [] or null (a missing key, a null logpush or anything else is a refusal, named).
                      Measured, run 38099981335 (release 1944de0): this PATCH answered 200 success true and echoed
                      `observability: null` and `tail_consumers: null` (logpush false), so the script-settings record
                      stores the all-off block and the empty list as null; its schema (workers_script-settings-item) makes
                      both nullable on that endpoint only. That null is accepted as the stored form of what was just
                      written, there and nowhere else; the explicit-off proof is the GA read in `settings`. Why a deploy
                      alone is not trusted: wrangler 4.149's first deploy of a Worker (the kit has a DO migration) takes
                      the PUT path and never PATCHes script-settings, and a later deploy's PATCH of it swallows every
                      error (run 38095547741, after a deploy and before this write existed, read an observability null
                      from an endpoint its gate did not name: script-settings by the schema, inferred, not measured;
                      run 38099981335's echo is the first measurement of script-settings answering null).
  settings WORKER     read the Worker's settings back from the Cloudflare API (token and account id from the environment)
                      from three endpoints (.../scripts/WORKER/settings, .../scripts/WORKER/script-settings and the GA
                      .../workers/workers/WORKER) and refuse by judge_settings' rules. The GA worker read is the
                      explicit-off proof: it must answer with observability an explicit off object (its schema requires
                      the key, non-null), `tail_consumers: []` and `logpush: false`. script-settings must answer with
                      observability the off object or null (null is how it stores the off record settings-off just wrote,
                      run 38099981335; a missing key refuses); settings may stay silent on it but never say anything
                      else, null included. Any endpoint that reports tail consumers or logpush otherwise refuses;
                      workers.dev on, preview URLs off. A refusal names the endpoint and key paths, never a value. Null is
                      never a report of "off": on script-settings it is only not a refusal.
  replay URL          the kit-serve vectors over HTTP against the STAGING Worker (admin keys from $KIT_GATE_DIR): identical
                      404 bytes, 429 after 30, the cap, release on a cut stream, floor, expiry, revoke, bad sha, overwrite,
                      gzip, Range, the admin rules. It makes its own invites and cleans them up. It first waits out
                      version propagation (run 38140164568 attempt 1: a correctly signed upload met the fixed 404 of an
                      isolate still on the previous run's keys): 10 consecutive signed 200s from /_k/state, ~1 s apart,
                      within 120 s; then a 2xx-expecting admin call that meets exactly the Worker's fixed 404 is sent
                      again with a fresh signature, at most 3 times, ~2 s apart, and the summary prints the count. A key
                      that never propagates still refuses; calls that expect a refusal, the public requests and the
                      front rejects get one try. Two measurements ride along (PY21): the cut vector (a 1 MiB object read
                      in 64 KiB chunks, cut after the 3rd and after the 4th, each cut must give its download back) and
                      rows read per failed decision (the Gate's rowsRead from /_k/state before and after the budget loop
                      and `--rows-failures N` more rejects, default 200: prints rows_per_failure=<n>, or rows_read=
                      unavailable on a Worker without the counter, or rows_read=reset if the number fell between reads).
  probe URL           the hostile probe against PRODUCTION: at most 5 well-formed failures, every answer byte-identical
                      to the first apart from date, cf-ray and the token in Cloudflare's own cf-nel report-to (below),
                      one of them with Accept-Encoding: gzip. It first waits out version propagation (run 38180769445:
                      the previous version's page, four seconds after the deploy): 10 consecutive fixed 404s of the
                      Worker on an unknown path that never reaches the Gate, ~1 s apart, within 120 s. Only answers that
                      are not the Worker's 404 are excused before that streak, and the summary counts them by status;
                      the Worker's 404s of the wait are judged with the others; a Worker that never gets there refuses.
                      In both, the EDGE_OWNED front rejects are the exception, by one table (fold_edge): each row may be
                      the Worker's 404 or Cloudflare's page for it, the same for every label of the row and identical.
                      (1) The two duplicate-Authorization requests may both be a page shaped like Cloudflare's edge 400.
                      The replay sends them for gateway.json, which its live code still opens, so the pair is live
                      against unknown; the probe has no live code, so its pair is unknown against unknown. A staging
                      probe (the one behind run 38102844541) saw the edge page for two Authorization headers: the same
                      page for a live and an unknown code tells nothing, and the replay's 429 count shows that it spent
                      no budget. (2) Two fetches of /robots.txt may both be Cloudflare's managed robots.txt (run
                      38107708369 and the probes after it: an account-level edge feature in front of the Worker's 404);
                      it carries no code, so two identical fetches say nothing about an invite. The owner may switch it
                      off (AI Crawl Control) to get the Worker's 404 back; both answers pass. The robots row alone also
                      lets report-to and nel differ (Cloudflare's per-response reporting headers, run 38140164568
                      attempt 2). Each summary prints one line per row: which labels, which answer.
                      Cloudflare's cf-nel report-to (run 38164673127, release 5229131: the replay passed every vector,
                      then refused '404: "below the floor" differs from "admin stale": headers differ: report-to'; the
                      coordinator's probe of 6 Worker 404s on staging found the edge now adds a constant `nel` and a
                      `report-to` whose endpoint URL holds a per-response token): in every identity check a report-to
                      that is well-formed Cloudflare NEL (cf_nel_rest: one endpoint, its URL ending ?s=<token>) is
                      compared with its token cut out and nothing else, so two such headers are equal only when they
                      differ in the token alone. The token cannot carry invite state: the Worker never sets the header
                      (kit/worker.test.js pins that its 404, its JSON replies and its 200 carry neither report-to nor
                      nel), so it is the edge's and made without the Worker's verdict. Still compared, byte for byte
                      within the run: the rest of that header (max_age, the endpoint's path, the spelling: key order,
                      whitespace, escapes), whether the header is there at all (one answer with it, one without,
                      refuses), any report-to that is not well-formed cf-nel (raw), `nel` as it is, every other header
                      but date and cf-ray, the status and the body.

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
from collections import Counter
from pathlib import Path
from typing import Callable, NamedTuple

ALPHABET = '23456789CFGHJMPQRVWX'      # the invite alphabet (N02): 10 symbols of it
NOT_FOUND = b'not found\n'
TRY_LATER = b'try later\n'
VARYING = frozenset({'date', 'cf-ray'})  # the only headers left out when two answers are compared (see also cf_nel_rest)
SECRET_NAME = re.compile(r'[A-Z][A-Z0-9_]{0,63}')
CF_API = 'https://api.cloudflare.com/client/v4'
UA = 'fleet-kit-deploy-check/1'
# kit/wrangler.jsonc's observability block (both envs; a test holds all three equal). settings-off writes exactly this.
OBSERVABILITY_OFF = {'enabled': False, 'issues': {'enabled': False},
                     'logs': {'enabled': False, 'invocation_logs': False, 'persist': False},
                     'traces': {'enabled': False, 'persist': False}}
SETTINGS_OFF = {'observability': OBSERVABILITY_OFF, 'logpush': False, 'tail_consumers': []}
# The settings gate's endpoints, by label. Both MUST answer with the observability key; only the GA worker read must
# carry an explicit off object (script-settings may carry null, STORES_OFF_AS_NULL). settings' schema makes
# observability optional there, so it may stay silent (but never say anything but off).
MUST_REPORT_OFF = ('script-settings', 'worker')
# The one endpoint whose observability/tail_consumers null is the stored all-off form (run 38099981335: the off PATCH
# echoed both as null; its schema makes them nullable there only). Not off, not a report: only not a refusal.
STORES_OFF_AS_NULL = 'script-settings'
FAILURE_BUDGET_PER_SOURCE = 30          # kit/gate-core.js LIMITS.perSource
ROWS_FAILURES = 200                     # reject-shaped decisions the rows-read measurement adds (PY21; --rows-failures)
CUT_BYTES = 1024 * 1024                 # the cut vector's object (PY21)
CUT_CHUNK = 64 * 1024                   # ... read by a reader of this chunk size
CUT_AFTER = (3, 4)                      # ... cut after the 3rd chunk, then after the 4th
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
          false (and logs/traces/issues of the schema's shape) is a refusal, null included, with the one exception in (b);
      (b) script-settings MUST answer, and its `observability` must be the explicit off object or null (a missing key =
          "script-settings: observability not reported"). Its null is the stored all-off form, measured: run 38099981335's
          settings-off PATCH of the all-off block answered 200 success true and echoed observability and tail_consumers
          as null, and that endpoint's schema (workers_script-settings-item) alone makes them nullable. script-settings
          answers null whether or not we wrote the off record (run 38095547741 read a null before any off write existed),
          so its null cannot tell "written off" from "never written": it is only not a refusal, never a report of off,
          and (d) carries the proof. The workflow runs settings-off before this gate with no deploy step between (a test
          holds that protocol; on staging the throwaway pepper's `wrangler secret put` does sit between);
      (c) settings may omit `observability` (its schema makes it optional), but if present it is held to (a);
      (d) the GA worker read MUST answer and report an explicit off object (its schema requires the key, non-null): it is
          the explicit-off proof, and the pass needs it whatever script-settings says;
      (e) `tail_consumers` an empty list and `logpush` an explicit false on every blob that reports them; null on either
          is "not reported" (never a report; on script-settings it is the stored form of [], (b)), so it refuses unless
          another endpoint reports the key ("tail_consumers: not reported (...)"). The GA worker read MUST report both
          (its schema requires them, non-null): `tail_consumers: []` and `logpush: false`; null there is a refusal
          ("worker: tail_consumers not reported");
      (f) the subdomain: workers.dev on, preview URLs explicitly off.
    Every detail names the endpoint and key paths, never a value. A missing answer is never a pass."""
    bad = []
    tail_seen = logpush_seen = tail_bad = logpush_bad = False
    for ep, blob in blobs.items():
        if 'observability' in blob:                                            # (a), (b), (c)
            if blob['observability'] is None and ep == STORES_OFF_AS_NULL:
                pass                                # (b): the stored off record; not off by itself, (d) is the proof
            elif not _observability_off(blob['observability']):
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
    """What in settings-off's echoed result is not the off record (key names only, never a value). Every key must be
    echoed. `observability: null` and `tail_consumers: null` are accepted as script-settings' stored form of what this
    PATCH just wrote, measured: run 38099981335 sent the all-off block and [] and got 200 success true with both echoed
    as null (the endpoint's schema, workers_script-settings-item, makes them nullable there only). A present non-null
    observability is held to the same off judge as the gate; logpush must echo exactly false (that run echoed false),
    null included as a refusal. This echo is not the explicit-off proof: the settings gate's GA read is."""
    bad = []
    if 'observability' not in echo:
        bad.append('observability not echoed')
    elif echo['observability'] is not None and not _observability_off(echo['observability']):
        bad.append(_why_observability_on(echo['observability']))
    for key, off, word, stored_null in (('logpush', False, 'is not false', False),
                                        ('tail_consumers', [], 'is not empty', True)):
        if key not in echo:
            bad.append('%s not echoed' % key)
        elif echo[key] is None:
            if not stored_null:                     # logpush was echoed false: its null would be something else
                bad.append('%s echoed null' % key)
        elif echo[key] != off or (key == 'logpush' and echo[key] is not False):
            bad.append('%s %s' % (key, word))
    return bad


def settings_off(worker: str, token: str, account: str) -> dict:
    """PATCH SETTINGS_OFF to the script-settings record and hold the echo to the same explicit-off judge (its stored null
    aside, _echo_not_off). Passes only on HTTP 200, `success: true` and an echo that is off; everything else is refused,
    naming the endpoint, never a body."""
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


# Cloudflare's own Network Error Logging header on the Worker's answers. Measured, kit-deploy run 38164673127 (release
# 5229131): readiness "10 consecutive signed 200s ... 0 404s seen, 12.1 s", every vector passed (the duplicate-Authorization
# pair and robots included), then the last check refused '404: "below the floor" differs from "admin stale": headers
# differ: report-to'. The coordinator's probe after it (6 fetches of the Worker's 404 on staging, and /_k/state): every
# Worker 404 now carries two headers the edge adds,
#   nel: {"report_to":"cf-nel","success_fraction":0.0,"max_age":604800}                       the same on every answer
#   report-to: {"group":"cf-nel","max_age":604800,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/v4?s=<token>"}]}
# and <token> differs on every response. kit/worker.js sets only content-type and cache-control (fixed(), json(), the 200
# download), so neither header is the Worker's: kit/worker.test.js pins that its fixed 404, a JSON admin reply and a 200
# download carry neither. That is why the per-response token cannot carry invite state: the Worker, the only party that
# knows whether a code is live, never writes the header; the edge makes the token per response, the same way for a live
# and a dead code.
# The rule (headers_of, so norm, differs, all_identical: the replay's 404 set, the edge rows, the probe): a report-to
# value that is well-formed Cloudflare NEL (cf_nel_rest) is compared WITHOUT ITS TOKEN and otherwise byte for byte: the
# row holds the header value with the characters between "?s=" and the closing quote cut out. So the one thing excused is
# the part the edge makes per response. What is still compared, within the run (nothing here is held to 604800 or to v4,
# so Cloudflare may change either between runs; a variance inside one run refuses): max_age, the endpoint's path, the
# number of endpoints (exactly one is well-formed), key order, whitespace and escapes; presence (an answer with the header
# against one without, or with another count of them, differs: the row is a row like any other); a report-to that is NOT
# well-formed cf-nel (raw, so it differs from every cf-nel row and from any other value, and differs() names it); `nel`
# as it is (it was constant in the probe; only the robots row's EDGE_REPORTING leaves it out); every other header but
# VARYING.
CF_NEL_GROUP = 'cf-nel'
CF_NEL_ENDPOINT = 'https://a.nel.cloudflare.com/report/'   # https, host exactly a.nel.cloudflare.com, path under /report/
# The endpoint URL: CF_NEL_ENDPOINT, a path of unreserved characters and "/" (no "%", so no %2e; no backslash, "#" or
# second "?"; ".." is refused beside it), then "?s=" and the token: 1 to 512 characters of the base64, base64url and
# percent-encoding alphabets. Nothing may follow the token (no "&name=value" rides in the part that is not compared).
CF_NEL_URL = re.compile(re.escape(CF_NEL_ENDPOINT)
                        + r'(?P<path>[A-Za-z0-9._~/-]{1,64})\?s=(?P<token>[A-Za-z0-9%+/=_.~-]{1,512})')
CF_NEL_QUERY = '?s='
REPORT_TO_MAX = 2048                                       # characters of the whole header value
NOT_CF_NEL = "report-to is not Cloudflare's cf-nel"        # a refusal says this, never the value


def _no_duplicate_keys(pairs):
    doc = dict(pairs)
    if len(doc) != len(pairs):
        raise ValueError('duplicate key')
    return doc


def cf_nel_rest(value) -> str | None:
    """None unless `value` is a report-to header value that is well-formed Cloudflare NEL as run 38164673127's probe
    measured it: at most REPORT_TO_MAX characters; a JSON object with exactly the keys group, max_age, endpoints (none
    twice); group "cf-nel"; max_age a positive integer; endpoints a list of exactly ONE object with exactly one key, url, a
    string that is CF_NEL_URL in full. Then: the value with its token cut out, which is what two answers are compared on
    (headers_of). The token is taken from the header as it is spelled (the one "?s=" up to the closing quote; "\\/" for
    "/" is the only escape taken there), so every character outside it is in the result."""
    if not isinstance(value, str) or len(value) > REPORT_TO_MAX:
        return None
    try:
        doc = json.loads(value, object_pairs_hook=_no_duplicate_keys)
    except (ValueError, RecursionError):
        return None
    if not isinstance(doc, dict) or set(doc) != {'group', 'max_age', 'endpoints'}:
        return None
    if doc['group'] != CF_NEL_GROUP:
        return None
    if type(doc['max_age']) is not int or doc['max_age'] <= 0:        # type(): True is an int and not a max_age
        return None
    endpoints = doc['endpoints']
    if not isinstance(endpoints, list) or len(endpoints) != 1:        # one, as measured: a second one is not excused
        return None
    ep = endpoints[0]
    if not isinstance(ep, dict) or set(ep) != {'url'} or not isinstance(ep['url'], str):
        return None
    url = CF_NEL_URL.fullmatch(ep['url'])
    if not url or '..' in url['path']:
        return None
    if value.count(CF_NEL_QUERY) != 1:                                # the "?" spelled as an escape: not as measured
        return None
    start = value.index(CF_NEL_QUERY) + len(CF_NEL_QUERY)
    end = value.find('"', start)
    if end < 0 or value[start:end].replace('\\/', '/') != url['token']:
        return None
    return value[:start] + value[end:]


def cf_nel_report_to(value) -> bool:
    """A report-to header value that is well-formed Cloudflare NEL (cf_nel_rest says what that is)."""
    return cf_nel_rest(value) is not None


def headers_of(resp: Resp, varying: frozenset = VARYING) -> list[tuple[str, str, str]]:
    """The header rows two answers are compared on, sorted: (name, 'raw', value), or (name, 'cf-nel', the value without
    its token) for a report-to that is well-formed Cloudflare NEL (cf_nel_rest; a raw row can never equal it). Headers in
    `varying` are left out. See the note above CF_NEL_GROUP."""
    rows = []
    for k, v in resp.headers:
        if k in varying:
            continue
        rest = cf_nel_rest(v) if k == 'report-to' else None
        rows.append((k, 'raw', v) if rest is None else (k, CF_NEL_GROUP, rest))
    return sorted(rows)


def norm(resp: Resp, varying: frozenset = VARYING):
    return (resp.status, tuple(headers_of(resp, varying)), resp.body)


def differs(a: Resp, b: Resp, varying: frozenset = VARYING) -> str:
    """Why norm(a) != norm(b): names, never values. A report-to that takes part and is not well-formed cf-nel is said so;
    so are two that are both cf-nel and differ outside the token (a missing or doubled one is plain "report-to")."""
    if a.status != b.status:
        return 'status %d vs %d' % (a.status, b.status)
    ha, hb = Counter(headers_of(a, varying)), Counter(headers_of(b, varying))
    if ha != hb:
        only_a, only_b = ha - hb, hb - ha                             # counted: one header twice against once differs too
        rows = set(only_a + only_b)
        names = sorted({k for k, _, _ in rows})
        if any(k == 'report-to' and kind == 'raw' for k, kind, _ in rows):
            names[names.index('report-to')] = "report-to (not Cloudflare's cf-nel)"
        elif all(any(k == 'report-to' for k, _, _ in side) for side in (only_a, only_b)):
            names[names.index('report-to')] = 'report-to (cf-nel, more than its token)'
        return 'headers differ: %s' % ', '.join(names)
    return 'body differs'


def expect(label: str, resp: Resp, status: int) -> Resp:
    if resp.status != status:
        raise Refused('%s: status %d, expected %d' % (label, resp.status, status))
    return resp


def check_fixed_answer(label: str, resp: Resp, status: int, body: bytes) -> None:
    """One of the Worker's fixed answers (404, 429, 503) as it arrives through the edge. A report-to on it must be
    Cloudflare's cf-nel (run 38164673127: the edge adds one to the Worker's answers); any other is refused by name."""
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
    if any(k == 'report-to' and not cf_nel_report_to(v) for k, v in resp.headers):
        raise Refused('%s: %s' % (label, NOT_CF_NEL))


def cf_nel_line(answers: list[tuple[str, Resp]]) -> str:
    """For a summary, after the answers passed: how many carried a report-to. Each of those is Cloudflare's cf-nel then
    (check_fixed_answer on the first, all_identical on the rest), and its token is the one thing that was not compared:
    the rest of the value was, byte for byte (cf_nel_rest)."""
    n = sum(1 for _, resp in answers if resp.header('report-to') is not None)
    return "Cloudflare's cf-nel report-to on %d of %d (its token is not compared)" % (n, len(answers))


def all_identical(label: str, answers: list[tuple[str, Resp]], varying: frozenset = VARYING) -> None:
    """Every answer equal to the first by norm(). `varying` is VARYING everywhere but one edge row's own comparison
    (EdgePage.varying, fold_edge): every 404 identity check takes the default. In all of them a well-formed cf-nel
    report-to is compared without its token (headers_of), so its per-response token is not a difference; its absence
    and anything else in it are."""
    first_label, first = answers[0]
    for name, resp in answers[1:]:
        if norm(resp, varying) != norm(first, varying):
            raise Refused('%s: "%s" differs from "%s": %s' % (label, name, first_label, differs(resp, first, varying)))


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


# Edge-owned answers: front-reject requests that Cloudflare's edge may answer in front of the Worker, and the page it
# answers with. Every other front reject must be the Worker's 404; these may be the Worker's 404 (held to it exactly as the
# others) or the one edge page their row names, the same for every label of the row and identical by norm() over the row's
# own varying headers (fold_edge; VARYING, plus EDGE_REPORTING for the robots row only, run 38140164568 attempt 2), a
# well-formed cf-nel report-to compared without its token there as everywhere (headers_of, run 38164673127).
# An edge page on any label not in EDGE_OWNED is held to the 404 and refuses.
#
# (1) The two duplicate-Authorization cases: one with a live code, one with a code nobody holds. Measured, kit-deploy run
# 38102844541 (release 4830f2a): the replay refused "two authorization headers: status 400, expected 404", and a probe of
# the staging Worker with a fake code answered ONE Authorization header with the Worker's 404 (text/plain, 10 bytes,
# cache-control no-store, no-transform, body "not found\n") and TWO identical ones with Cloudflare's own edge page (status
# 400, server cloudflare, text/html, 155 bytes, "<html> ... 400 Bad Request ... cloudflare"). kit/worker.js has no 400 on
# /v1/kit (a combined "a, b" value would be its 404), so the page is the edge's. The uniform 404 exists so that no answer
# tells a live invite from a dead one; an answer that is byte-identical for a live and an unknown code tells nothing either.
# That the pair spent no budget is not read off the page: the replay's 429 count (served != left) holds it. The live case
# asks for gateway.json, which the replay's live code still opens after its bundle.tar cap is spent, so a front that took
# the first header would answer 200 there and the pair would differ.
#
# (2) /robots.txt, fetched twice. Measured, kit-deploy run 38107708369 (release af2f722): the replay passed every vector up
# to the front rejects, the duplicate-Authorization pair included, then refused "robots: status 200, expected 404". The
# coordinator's probes of fleet-kit-staging.mirrorstack-fleet.workers.dev then: every other front-reject path (POST, PUT,
# no auth, Bearer, /, /v1/kit/, /_k/state unsigned and zero-signature, PUT /_k/file/1/bundle.tar unsigned, /favicon.ico,
# /.well-known/security.txt) answered the Worker's 404 (text/plain, 10 bytes); GET /robots.txt answered 200, server
# cloudflare, content-type "text/plain; charset=utf-8", content-length 1248, cache-control "no-store, no-transform", a body
# starting with ROBOTS_FIRST_LINE and "# content signals:", byte-identical across two fetches. That is Cloudflare's
# managed robots.txt (the Content Signals Policy), an account-level edge feature that replaces an origin 404 for
# /robots.txt. For /robots.txt the Worker has no answer but its front-check 404 (publicRoute; /_k/ is its only other route
# and /robots.txt is not under it; kit/worker.test.js pins that 404), so the page is the edge's. Its cache-control
# equals the Worker's, so that header proves nothing either way and is not judged. The page carries no code and no serial,
# so it can say nothing about an invite as long as it is the same page every time: the two fetches must be identical. The
# owner may switch the managed robots.txt off (Cloudflare dashboard, AI Crawl Control) to get the Worker's 404 back; both
# answers are accepted. Production (fleet-kit) served only a dashboard "Hello World!" placeholder when this was written;
# once the pipeline deploys it, its probe meets the same page and takes it by the same row.
DUP_AUTH = ('two authorization headers', 'two authorization headers, unknown code')
ROBOTS = ('robots', 'robots, second fetch')
WORKER_CACHE = 'no-store, no-transform'    # the Worker's own cache-control on every answer; the probed edge 400 did not carry it
ROBOTS_FIRST_LINE = b'# As a condition of accessing this website, you agree to abide by the following'
ROBOTS_MAX_BYTES = 4 * 1024                # the measured page is 1248 bytes; room for a policy update, little else


def edge_400_misses(resp: Resp) -> list[str]:
    """The properties of the probed edge 400 page this answer lacks (empty: it has the page's shape). The shape is not proof
    of origin (the Worker's 404 also says server cloudflare); what rules the Worker out is that its response builders
    emit none of it (text/html, no cache-control, a 400 on /v1/kit)."""
    misses = []
    if resp.status != 400:
        misses.append('status')
    if resp.header('server') != 'cloudflare':
        misses.append('server')
    if not (resp.header('content-type') or '').startswith('text/html'):
        misses.append('content-type')
    if resp.header('cache-control') == WORKER_CACHE:
        misses.append('cache-control')
    if b'400 Bad Request' not in (resp.body or b''):
        misses.append('marker')
    return misses


def edge_400(resp: Resp) -> bool:
    """Matches the shape of Cloudflare's edge 400 page as the staging probe saw it; the Worker's builders emit none of it."""
    return not edge_400_misses(resp)


def managed_robots_misses(resp: Resp) -> list[str]:
    """The properties of Cloudflare's managed robots.txt (run 38107708369's probes) this answer lacks (empty: it has the
    page's shape). The shape is not proof of origin: bytes after the first line are not judged beyond the size cap. What
    rules the Worker out is its source: for /robots.txt it answers only its front-check 404 (kit/worker.test.js pins it).
    A content-encoding, location or set-cookie header is refused here as on every fixed answer (check_fixed_answer)."""
    body = resp.body or b''
    misses = []
    if resp.status != 200:
        misses.append('status')
    if resp.header('server') != 'cloudflare':
        misses.append('server')
    if not (resp.header('content-type') or '').startswith('text/plain'):
        misses.append('content-type')
    if not body.startswith(ROBOTS_FIRST_LINE):
        misses.append('marker')
    if b'content signals' not in body.lower():
        misses.append('content signals')
    if len(body) > ROBOTS_MAX_BYTES:
        misses.append('size')
    misses.extend('no %s' % h for h in ('content-encoding', 'location', 'set-cookie') if resp.header(h) is not None)
    return misses


class EdgePage(NamedTuple):
    name: str                               # what a verdict and a refusal call the labels of the row
    each: str                               # what one of those labels is: a case, a fetch
    page: str                               # the edge page they may answer with instead of the Worker's 404
    misses: Callable[[Resp], list[str]]
    marker: bytes                           # describe() says only whether the answer holds this
    varying: frozenset = VARYING            # the headers this row's edge pages may differ in (fold_edge's comparison only)


EDGE_400_PAGE = EdgePage('duplicate Authorization', 'cases', "Cloudflare's edge 400", edge_400_misses, b'400 Bad Request')
# Cloudflare's per-response reporting headers (Reporting API endpoints, Network Error Logging). Measured, kit-deploy run
# 38140164568 attempt 2 (release 721bb8a): every vector passed up to the robots row, which refused '"robots, second fetch"
# differs from "robots": headers differ: report-to'. The managed robots.txt is the edge's page and these headers are the
# edge's per-response metadata about it, not its content; the page itself (status, every other header, the bytes) is still
# held identical across both fetches. Ignored by the robots row's own comparison ONLY: VARYING is unchanged, so every 404
# identity check (the Worker's answers, the front rejects among them) still compares both headers. Since run 38164673127
# (the edge now adds them to the Worker's 404 too) that comparison takes a report-to that is well-formed cf-nel without
# its token (headers_of): the token may differ, while anything else in it, its absence on one answer, a report-to of any
# other shape and a differing nel still refuse there.
EDGE_REPORTING = frozenset({'report-to', 'nel'})
MANAGED_ROBOTS = EdgePage('robots', 'fetches', "Cloudflare's managed robots.txt", managed_robots_misses, ROBOTS_FIRST_LINE,
                          VARYING | EDGE_REPORTING)
EDGE_OWNED = {DUP_AUTH[0]: EDGE_400_PAGE, DUP_AUTH[1]: EDGE_400_PAGE, ROBOTS[0]: MANAGED_ROBOTS, ROBOTS[1]: MANAGED_ROBOTS}


def describe(resp: Resp, marker: bytes) -> str:
    """The non-secret head of an answer, for a refusal: never a body, only whether it holds the edge page's marker."""
    def h(name):
        v = resp.header(name)
        return '-' if v is None else v[:60]
    return 'server=%s content-type=%s content-length=%s cache-control=%s marker=%s' % (
        h('server'), h('content-type'), h('content-length'), h('cache-control'),
        'yes' if marker in (resp.body or b'') else 'no')


def fold_edge(answers: list[tuple[str, Resp]]) -> tuple[list[tuple[str, Resp]], list[str]]:
    """Judge front_rejects' edge-owned answers, row by row of EDGE_OWNED, and return (the answers left to hold to the 404,
    one verdict line per row). Every label of a row the Worker's 404: they stay in the list (the caller holds them to the
    404 and to the others). Every label of a row that row's edge page, identical by norm() over the row's own varying
    headers (page.varying: VARYING, plus EDGE_REPORTING for robots; never wider for a 404; a well-formed cf-nel report-to
    is compared without its token in both rows, headers_of): they leave the list. Anything
    else (a mix, another page, differing answers) is a refusal naming the row and what is missing, never a body. Every
    answer whose label is in no row is passed through untouched."""
    taken: set[str] = set()
    verdicts = []
    for page in dict.fromkeys(EDGE_OWNED.values()):
        want = [label for label, p in EDGE_OWNED.items() if p is page]
        group = [(label, resp) for label, resp in answers if label in want]
        name = page.name.lower()
        if sorted(label for label, _ in group) != sorted(want):
            raise Refused('%s: the cases sent are not exactly %s' % (name, ', '.join(want)))
        if len({resp.status for _, resp in group}) > 1:
            raise Refused('%s: %s' % (name, ', '.join('"%s" answered %d' % (label, resp.status) for label, resp in group)))
        labels = '; '.join(want)
        if group[0][1].status == 404:
            verdicts.append("%s: the Worker's 404 for both %s (%s)" % (page.name, page.each, labels))
            continue
        for label, resp in group:
            misses = page.misses(resp)
            if misses:
                raise Refused("%s: status %d, neither the Worker's 404 nor %s page (lacks %s; %s)"
                              % (label, resp.status, page.page, ', '.join(misses), describe(resp, page.marker)))
        all_identical(name, group, page.varying)
        taken.update(want)
        verdicts.append('%s: %s for both %s, identical (%s)' % (page.name, page.page, page.each, labels))
    return [(label, resp) for label, resp in answers if label not in taken], verdicts


def front_rejects(client: Client, good_code: str) -> list[tuple[str, Resp]]:
    """Requests the front answers with the one 404 before any database touch (so they spend no budget). The EDGE_OWNED
    labels may instead be answered by Cloudflare's edge before the Worker: fold_edge judges them."""
    ok_auth = ('Authorization', 'FleetInvite ' + good_code)
    unknown_auth = ('Authorization', 'FleetInvite ' + random_code())
    p = '/v1/kit/900000001/bundle.tar'
    g = '/v1/kit/900000001/gateway.json'      # the DUP_AUTH path: the replay's live code still opens it (no cap on it)
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
        (DUP_AUTH[0], 'GET', g, [ok_auth, ok_auth], None),
        # the same shape with a code nobody holds: what makes an edge 400 for the pair acceptable is that it is identical
        (DUP_AUTH[1], 'GET', g, [unknown_auth, unknown_auth], None),
        ('root', 'GET', '/', [], None),
        ('v1 kit root', 'GET', '/v1/kit/', [ok_auth], None),
        # Cloudflare's managed robots.txt may answer here (run 38107708369); two fetches, held identical to each other
        (ROBOTS[0], 'GET', '/robots.txt', [], None),
        (ROBOTS[1], 'GET', '/robots.txt', [], None),
        ('admin unsigned state', 'GET', '/_k/state', [], None),
        ('admin unsigned put', 'PUT', '/_k/file/1/bundle.tar', [], b'abc'),
        ('admin zero signature', 'GET', '/_k/state', [('Authorization', 'KitAdmin gateway %d %s' % (int(time.time() * 1000), '0' * 128))], None),
    ]
    return [(label, client.request(m, path, headers, body)) for label, m, path, headers, body in cases]


# ---- the staging replay ------------------------------------------------------------------------------------------------

# Version propagation. Measured, kit-deploy run 38140164568 (release 721bb8a), attempt 1: the settings gate passed; the
# replay's upload small, upload big and upload other each answered 200 (signed admin PUTs with this run's throwaway upload
# key), then "identical re-upload" (the same signed PUT shape, the small bytes to s1 again) answered 404: "REFUSED identical
# re-upload: status 404, expected 200". kit/worker.js answers an AUTHENTICATED admin call only with JSON; its fixed 404
# (text/plain, "not found\n") comes only from the unauthenticated paths (no route, bad or absent auth, ts skew > SKEW_MS,
# key var not set, bad signature, KIT_DISABLED). Attempt 2 (same commit, fresh throwaway keys) passed that vector and every
# one after it up to the robots row (EDGE_REPORTING). The reading: every run deploys staging with NEW throwaway admin keys
# (vars), then `wrangler secret put INVITE_PEPPER` makes another version; for a while after, some requests still reach
# isolates running the previous version, whose KIT_UP_PUB / KIT_GW_PUB are the previous run's keys, so a correctly signed
# call answers the fixed 404. Two answers to it:
#   (1) wait_ready: before the first admin vector, READY_STREAK consecutive signed 200s from /_k/state (the gateway role:
#       the one role ADMIN_ROUTES allows there; both keys arrive in the same deploy's vars), READY_SPACING apart, within
#       READY_TIMEOUT; a 404 resets the streak, any other status refuses at once. A streak shows that this run's keys are
#       being served, not that no old isolate is left: hence (2).
#   (2) run_replay's ok_call: an admin call that EXPECTS 2xx and gets exactly the Worker's fixed 404 is sent again, with a
#       fresh ts and signature, up to RETRY_MAX times, RETRY_WAIT apart, then judged as usual. The count is printed in the
#       summary: a non-zero count is a measurement, never hidden. What the retry cannot hide: a key that never propagates,
#       a wrong signature, a disabled Worker, a stale clock: each answers the fixed 404 every time and still refuses
#       (after RETRY_MAX + 1 tries). What it could hide: a Worker that 404s a well-signed call at most RETRY_MAX times in a
#       row and then serves it; the count says how often that happened. Calls that expect a non-2xx (stale ts -> 404,
#       wrong role -> 403, replay -> 409, overwrite -> 409, wrong bytes -> 422, rollback -> 409, the ceilings -> 422), the
#       public /v1/kit requests and the front rejects get exactly one try.
#   Not covered (possible, never observed): INVITE_PEPPER is its own version after the vars deploy, and each isolate tags
#   invite codes with its own pepper, so an old isolate can pass readiness and still 404 a public GET for an invite another
#   isolate made, or give one of the single-try calls above the fixed 404. A refusal of that shape after this change is
#   that residual, not "the fix did not apply"; its answer would be a pepper-aware readiness (make an invite, read it back).
READY_STREAK = 10
READY_SPACING = 1.0         # seconds between readiness tries
READY_TIMEOUT = 120.0       # seconds for the whole streak
RETRY_MAX = 3               # extra tries of a 2xx-expecting admin call that met the Worker's fixed 404
RETRY_WAIT = 2.0            # seconds between those tries
PROPAGATION = "staging is not serving this run's admin keys (version propagation)"


def worker_404(resp: Resp) -> bool:
    """Exactly kit/worker.js fixed(404): status 404, text/plain, body "not found\n". The only 404 an admin call can meet,
    and it never comes from an authenticated one."""
    return resp.status == 404 and (resp.header('content-type') or '').startswith('text/plain') and resp.body == NOT_FOUND


def wait_ready(admin: Admin, *, streak: int = READY_STREAK, spacing: float = READY_SPACING, timeout: float = READY_TIMEOUT,
               sleep=time.sleep, clock=time.monotonic) -> tuple[Resp, str]:
    """Signed GET /_k/state (gateway role) until `streak` consecutive 200 JSON answers; a 404 resets the run, any other
    status refuses, no streak within `timeout` seconds refuses. Returns (the last answer, the summary line)."""
    t0 = clock()
    tries = seen404 = run = best = 0
    while True:
        r = admin.call('gateway', 'GET', '/_k/state')
        tries += 1
        if r.status == 404:
            seen404 += 1
            run = 0
        elif r.status == 200:
            admin_json('readiness try %d' % tries, r, 200)
            run += 1
            best = max(best, run)
        else:
            # not a propagation symptom (only the fixed 404 is one): name the status, blame nothing
            raise Refused("readiness: try %d answered %d, expected 200 or the Worker's fixed 404 (%d tries, %d 404s seen, "
                          "%.1f s)" % (tries, r.status, tries, seen404, clock() - t0))
        if run >= streak:
            return r, ('readiness: %d consecutive signed 200s from /_k/state after %d tries, %d 404s seen, %.1f s'
                       % (streak, tries, seen404, clock() - t0))
        if clock() - t0 > timeout:
            raise Refused('%s: no %d consecutive 200s within %d s (%d tries, %d 404s seen, longest run %d)'
                          % (PROPAGATION, streak, timeout, tries, seen404, best))
        sleep(spacing)


def det_bytes(label: str, n: int) -> bytes:
    return hashlib.shake_256(('fleet-kit-staging:%s' % label).encode()).digest(n)


def rows_read_of(state: dict) -> int | None:
    """The Gate's rows-read counter from a /_k/state reply, or None when this kit does not report one (a Worker built
    before PY21, or a value that is not a non-negative whole number)."""
    v = state.get('rowsRead')
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def run_replay(client: Client, admin: Admin, *, big_mib: int = 16, cut_wait: float = 5.0, small_bytes: int = 65536,
               rows_failures: int = ROWS_FAILURES,
               short_life_ms: int = 12000, ready_streak: int = READY_STREAK, ready_spacing: float = READY_SPACING,
               ready_timeout: float = READY_TIMEOUT, retry_max: int = RETRY_MAX, retry_wait: float = RETRY_WAIT,
               sleep=time.sleep, log=say) -> list[str]:
    """The staging replay. Waits out version propagation first (wait_ready) and sends a 2xx-expecting admin call again
    on the Worker's fixed 404 (ok_call, at most retry_max times, counted in the summary); see the Version propagation
    note above (run 38140164568 attempts 1 and 2).

    Rows read per failed decision (G-AUD-KIT-WORKER-1b): the Gate counts the rows its decisions read and /_k/state shows the
    number. The replay reads it before the budget loop, makes the loop's own failures plus `rows_failures` more reject-shaped
    requests (the source is past its budget by then, so those are the Gate's flood path: the 429), reads it again and prints
    rows_per_failure. A kit that does not report the number prints rows_read=unavailable (no failure, no extra requests); a
    second read below the first prints rows_read=reset (the Gate was evicted between them)."""
    s1, s2, s3, s4, s5, gser = (S_BASE + i for i in (1, 2, 3, 4, 5, 1))
    s6 = S_BASE + 6                                    # the cut vector's object
    small = det_bytes('s1', small_bytes)
    other = det_bytes('s5', small_bytes)
    big = det_bytes('s2', big_mib * 1024 * 1024)
    wrong = det_bytes('wrong', small_bytes)           # same length as `small`, other bytes
    gjson, gsig = det_bytes('gateway.json', 200), det_bytes('gateway.json.sig', 64)
    cutobj = det_bytes('s6', CUT_BYTES)
    refs: list[str] = []
    seen404: list[tuple[str, Resp]] = []
    fails = 0                                          # well-formed failures spent at the gate, as the replay counts them
    vectors = 0
    m: dict = {}
    retries: list[str] = []                            # one entry per extra try ok_call made, by label

    def ok_call(label: str, send: Callable[[], Resp], status: int = 200) -> tuple[dict, Resp]:
        """send() is one fresh signed call (a new ts and signature each time). Only the Worker's fixed 404 is retried."""
        assert 200 <= status < 300, 'ok_call is for calls that expect success'
        r = send()
        for _ in range(retry_max):
            if not worker_404(r):
                break
            retries.append(label)
            log("retry %s: the Worker's fixed 404 to a signed call (version propagation)" % label)
            sleep(retry_wait)
            r = send()
        if worker_404(r) and retry_max:
            raise Refused("%s: status 404 (the Worker's fixed 404) on %d tries, expected %d; %s"
                          % (label, retry_max + 1, status, PROPAGATION))
        return admin_json(label, r, status), r

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
        # A fresh deploy takes a while to reach every isolate (run 38140164568): wait for a streak of this run's keys.
        r, m['ready'] = wait_ready(admin, streak=ready_streak, spacing=ready_spacing, timeout=ready_timeout, sleep=sleep)
        log(m['ready'])
        state = admin_json('state', r, 200)
        offset = state['now'] - int(time.time() * 1000)

        # -- uploads (upload role) ------------------------------------------------------------------------------------
        for label, serial, data in (('upload small', s1, small), ('upload big', s2, big), ('upload other', s5, other),
                                    ('upload cut', s6, cutobj)):
            vector(label)
            d, _ = ok_call(label, lambda serial=serial, data=data: _put_bundle(admin, serial, data))
            if d.get('sha256') != sha256_hex(data) or d.get('size') != len(data):
                raise Refused('%s: R2 holds other bytes than were sent' % label)
        vector('identical re-upload')
        _, r = ok_call('identical re-upload', lambda: _put_bundle(admin, s1, small))
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
        d, _ = ok_call('gateway pair', lambda: admin.call('upload', 'PUT', '/_k/gateway/%d' % gser, gbody))
        if d.get('json', {}).get('sha256') != sha256_hex(gjson) or d.get('sig', {}).get('sha256') != sha256_hex(gsig):
            raise Refused('gateway pair: R2 holds other bytes than were sent')
        ok_call('gateway pair again', lambda: admin.call('upload', 'PUT', '/_k/gateway/%d' % gser, gbody))
        admin_json('gateway rollback', admin.call('upload', 'PUT', '/_k/gateway/%d' % (gser - 1), gbody), 409, 'rollback')
        ok_call('floor 0', lambda: admin.call('upload', 'PUT', '/_k/floor', jbody({'floor': 0})))

        # -- invites (gateway role) -----------------------------------------------------------------------------------
        def add_invite(label, *, cap, lo, hi, life_ms, status=200, error=None) -> tuple[str, str]:
            ref = 'r' + secrets.token_hex(8)
            code = random_code()
            body = jbody({'ref': ref, 'code': code, 'tier': 'install', 'lo': lo, 'hi': hi,
                          'exp': int(time.time() * 1000) + offset + life_ms, 'cap': cap})
            def post() -> Resp:
                r = admin.call('gateway', 'POST', '/_k/invite', body)
                for _ in range(10):      # 503: the new pepper has not reached this edge yet
                    if r.status != 503 or status != 200:
                        break
                    sleep(3)
                    r = admin.call('gateway', 'POST', '/_k/invite', body)
                return r

            if status == 200:
                ok_call(label, post)
            else:                        # a ceiling: expects a refusal, one try
                admin_json(label, post(), status, error)
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
        fbody = jbody({'floor': 0})
        first_ts = {}

        def replay_first() -> Resp:      # a retry signs a fresh ts; the second send repeats the one that was served
            first_ts['ts'] = admin.next_ts('upload')
            return admin.call('upload', 'PUT', '/_k/floor', fbody, ts=first_ts['ts'])

        ok_call('replay first', replay_first)
        admin_json('replay second', admin.call('upload', 'PUT', '/_k/floor', fbody, ts=first_ts['ts']), 409, 'replay')

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
        ok_call('floor up', lambda: admin.call('upload', 'PUT', '/_k/floor', jbody({'floor': s2})))
        gate_404('below the floor', get_kit(client, s1, 'bundle.tar', code_w))
        ok_call('floor down', lambda: admin.call('upload', 'PUT', '/_k/floor', jbody({'floor': 0})))
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
        ok_call('revoke', lambda: admin.call('gateway', 'DELETE', '/_k/invite/%s' % ref_r))
        gate_404('revoked', get_kit(client, s1, 'gateway.json', code_r))
        vector('front rejects')
        fronts, m['edge'] = fold_edge(front_rejects(client, code_w))
        for label, resp in fronts:
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

        vector('cut vector: 1 MiB in 64 KiB chunks, cut after chunk 3 and after chunk 4')
        code_c, _ = add_invite('invite C', cap=2, lo=s6, hi=s6, life_ms=half_hour)
        for chunks in CUT_AFTER:
            cut = get_kit_cut(client, s6, code_c, chunk=CUT_CHUNK, chunks=chunks)
            if cut != 200:
                raise Refused('cut vector, after chunk %d: status %d, expected 200' % (chunks, cut))
            sleep(cut_wait)
        m['cv_cuts'], m['cv_restored'] = len(CUT_AFTER), 0
        for i in (1, 2):                                                      # cap 2: both fit again only if each cut was released
            r = get_kit(client, s6, 'bundle.tar', code_c)
            if r.status == 200 and r.body == cutobj:
                m['cv_restored'] += 1
        if m['cv_restored'] != len(CUT_AFTER):
            raise Refused('cut vector: a cut stream did not give the download back (%d of %d restored)'
                          % (m['cv_restored'], len(CUT_AFTER)))

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
        # The rows-read counter before the loop: nothing but this loop's decisions (and the flood below) moves it until the
        # second read. A kit built before PY21 has none: no extra requests, and the summary says so.
        rows_before = rows_read_of(ok_call('rows read before', lambda: admin.call('gateway', 'GET', '/_k/state'))[0])
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
        if rows_before is None:
            m['rows'] = 'rows_read=unavailable (this kit does not report rowsRead: a Worker built before PY21)'
        else:
            vector('rows read per failed decision')
            for i in range(rows_failures):                                   # the source is past its budget: the Gate's 429 path
                r = get_kit(client, s1, 'bundle.tar', random_code())
                if r.status != 429:
                    raise Refused('rows read: flood request #%d: status %d, expected 429' % (i + 1, r.status))
            decisions = served + 1 + rows_failures                         # the loop's 404s, its 429, then the flood
            rows_after = rows_read_of(ok_call('rows read after', lambda: admin.call('gateway', 'GET', '/_k/state'))[0])
            if rows_after is None:
                m['rows'] = 'rows_read=unavailable (the second read of /_k/state had no rowsRead)'
            elif rows_after < rows_before:
                m['rows'] = ('rows_read=reset (%d, then %d: the Gate was evicted between the two reads; no figure, '
                             'run the replay again)' % (rows_before, rows_after))
            else:
                m['rows'] = ('rows_per_failure=%.1f (%d rows read over %d failed decisions: the loop\'s %d 404s and its 429, '
                             'then %d more 429s)' % ((rows_after - rows_before) / decisions, rows_after - rows_before,
                                                      decisions, served, rows_failures))
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
        '  ' + m['ready'],
        "  admin retries on the Worker's fixed 404: %d%s" % (len(retries), ' (%s)' % ', '.join(retries) if retries else ''),
        '  404 answers compared: %d, identical' % len(seen404),
        '  ' + cf_nel_line(seen404),
        *('  ' + line for line in m['edge']),
        '  429 after %d failures' % m['b429_after'],
        '  (a) client cuts: %d, count restored: %d' % (m['a_cuts'], m['a_restored']),
        '  (a) cut vector: %d KiB in %d KiB chunks, cut after chunk %s, count restored: %d of %d'
        % (CUT_BYTES // 1024, CUT_CHUNK // 1024, ' and '.join(str(c) for c in CUT_AFTER), m['cv_restored'], m['cv_cuts']),
        '  (b) not measurable over HTTP (needs an isolate restart)',
        '  (c) wrong bytes: %d (R2 checksum), overwrite: %d (Worker head guard; the R2 onlyIf wildcard is not separately '
        'observable), identical re-upload: %d' % (m['c_wrong_bytes'], m['c_overwrite'], m['c_identical']),
        '  (d) not measurable here (needs 100000 requests in a day)',
        '  (g) 404 answers, wall clock ms: p50 %d, max %d (not CPU time)' % (statistics.median(ms), max(ms)),
        '  (h) ' + m['rows'],
    ]


def _put_bundle(admin: Admin, serial: int, data: bytes) -> Resp:
    return admin.call('upload', 'PUT', '/_k/file/%d/bundle.tar' % serial, data, stream_digest=sha256_hex(data))


def get_kit_cut(client: Client, serial: int, code: str, read_bytes: int = 262144, *, chunk: int = 0, chunks: int = 1) -> int:
    """Start a bundle download, read a little, hang up. Returns the status line's status. With `chunk`, the reader takes
    `chunks` reads of `chunk` bytes each (the cut vector: 64 KiB, after the 3rd and after the 4th) and hangs up after the last;
    a stream that ends before that many full chunks is refused (the object is too short for the cut that was asked for)."""
    resp = client.request('GET', '/v1/kit/%d/bundle.tar' % serial, [('Authorization', 'FleetInvite ' + code)], read=False)
    try:
        if chunk:
            for i in range(chunks if resp.status == 200 else 0):
                if len(resp.read(chunk)) < chunk:
                    raise Refused('cut: the stream ended inside chunk %d of %d' % (i + 1, chunks))
        elif resp.status == 200 and not resp.read(read_bytes):
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

# Production propagation. Measured, kit-deploy run 38180769445 (release 98ee712), the first run to deploy production: the
# production deploy, its settings gate and the staging replay all passed; wrangler printed the production "Current Version ID"
# at 22:41:56Z and "Hostile probe on production" refused at 22:42:00Z: "robots: status 200, neither the Worker's 404 nor
# Cloudflare's managed robots.txt page (... server=cloudflare content-type=text/plain;charset=UTF-8 content-length=12 ...)".
# Before that run production served the dashboard placeholder Worker, whose every answer is 200 "Hello World!" (12 bytes,
# text/plain;charset=UTF-8): the probe met an edge location still serving the PREVIOUS version. The same probe by hand passed
# from 22:43:24Z to 22:43:37Z, 88 s after the deploy line (21 answers, byte-identical, cf-nel on 21 of 21; its log is
# kit-prod-probe-manual-2026-10-12.log). The probe holds no key, so it cannot use wait_ready's signed call; its readiness is
# the one thing it can see without one:
#   wait_worker: before the first judged request, GET PROBE_READY_PATH until PROBE_READY_STREAK (= READY_STREAK) consecutive
#   answers are the Worker's own fixed 404, PROBE_READY_SPACING (= READY_SPACING) apart, within PROBE_READY_TIMEOUT
#   (= READY_TIMEOUT). "The Worker's own fixed 404" is worker_404, the definition run_replay's ok_call retries on: status 404,
#   text/plain, the body "not found\n". Headers are not part of it, so a per-response token (date, cf-ray, Cloudflare's cf-nel
#   report-to) never resets a streak and a header fault of a 404 is not waited out for 120 s. Any other answer (the previous
#   version's page, an edge page, the Worker's own 429 or 503) resets the streak and is counted by status in the summary.
#   The path is unknown to the Worker's front (no /_k/ prefix, not /v1/kit/<serial>/<file>), so it is answered fixed(404)
#   before the invite check and never reaches the Gate: it spends none of the 30 an hour.
#   What the wait can hide: only answers that are NOT the Worker's 404, and only BEFORE the streak is complete. Every answer
#   that is the Worker's 404 is kept and judged with the rest of the probe (check_fixed_answer on the first, all_identical on the
#   rest, labelled "readiness try N"), at no extra request: a set-cookie, a location, a content-encoding, a foreign report-to,
#   another cache-control or content-type on one of them is the same refusal as on any other answer. A Worker that never serves
#   the fixed 404 is refused at the timeout, naming the tries, how many were not the fixed 404 and the status, content-type and
#   content-length of the last of them, never a body. Everything after the streak (the 5 gate requests, the front rejects,
#   robots, the duplicate-Authorization pair) is judged exactly as before. The wait does not show that no old location is left;
#   it shows that the locations asked for PROBE_READY_STREAK answers in a row serve this Worker, which is what the judged
#   requests then repeat. When the previous version is an older fleet-kit Worker its fixed 404 is the same, so the streak passes
#   at once; it still takes (PROBE_READY_STREAK - 1) x PROBE_READY_SPACING = 9 s of spacing plus the requests (12.0 s measured
#   for the same streak on staging, run 38180769445), which is the time propagation gets.
PROBE_READY_PATH = '/ready'
PROBE_READY_STREAK = READY_STREAK
PROBE_READY_SPACING = READY_SPACING
PROBE_READY_TIMEOUT = READY_TIMEOUT


def _shown(value, limit: int = 64) -> str:
    """A header value for a refusal: cut short, printable ASCII only (it comes from the network)."""
    return ''.join(c if ' ' <= c <= '~' else '?' for c in str(value)[:limit]) if value is not None else '-'


class Ready(NamedTuple):
    tries: int                                  # requests to PROBE_READY_PATH
    other: int                                  # answers that were not the Worker's fixed 404 (excused, counted)
    statuses: dict                              # status -> how many of those
    answers: list                               # [(label, Resp)] every answer that WAS the Worker's 404, to be judged
    elapsed: float


def wait_worker(client: Client, *, streak: int = PROBE_READY_STREAK, spacing: float = PROBE_READY_SPACING,
                timeout: float = PROBE_READY_TIMEOUT, sleep=time.sleep, clock=time.monotonic) -> Ready:
    """GET PROBE_READY_PATH until `streak` consecutive answers are the Worker's fixed 404; any other answer resets the run
    and is counted by status. No streak within `timeout` seconds refuses. The answers that were the Worker's 404 come back
    for the caller to judge (run_probe does)."""
    t0 = clock()
    tries = other = run = 0
    statuses: dict[int, int] = {}
    kept: list[tuple[str, Resp]] = []
    last = None
    while True:
        r = client.request('GET', PROBE_READY_PATH)
        tries += 1
        if worker_404(r):
            run += 1
            kept.append(('readiness try %d' % tries, r))
        else:
            other += 1
            run = 0
            last = r
            statuses[r.status] = statuses.get(r.status, 0) + 1
        if run >= streak:
            return Ready(tries, other, statuses, kept, clock() - t0)
        if clock() - t0 > timeout:
            raise Refused("probe readiness: no %d consecutive fixed 404s of the Worker within %d s (%d tries, %d were not the "
                          "Worker's 404%s)" % (streak, timeout, tries, other, '' if last is None else
                                               '; the last of them: status %d, content-type %s, content-length %s'
                                               % (last.status, _shown(last.header('content-type')),
                                                  _shown(last.header('content-length')))))
        sleep(spacing)


def run_probe(client: Client, *, log=say, ready_streak: int = PROBE_READY_STREAK, ready_spacing: float = PROBE_READY_SPACING,
              ready_timeout: float = PROBE_READY_TIMEOUT, sleep=time.sleep, clock=time.monotonic) -> list[str]:
    """Hostile requests at production: every answer must be the same bytes (date, cf-ray and the token of Cloudflare's
    own cf-nel report-to aside: headers_of, run 38164673127; a report-to of any other shape, one missing, or a differing
    nel is a difference). At most
    PROBE_MAX_FAILURES of them reach the gate (each spends one of this source's 30 an hour); the rest are shapes the front
    answers without touching it. The EDGE_OWNED answers are judged by fold_edge, by the same table as the replay: the
    duplicate-Authorization pair (run 38102844541; here both of its codes are unknown, so it shows only that two unknown
    codes get the same answer) and the two /robots.txt fetches (run 38107708369: Cloudflare's managed robots.txt, or the
    Worker's 404 once the owner switches that off). Before the first of them it waits for the Worker's own 404 to be what
    production answers (wait_worker, run 38180769445: the previous version was still being served), judges the 404s it
    met with the rest, and says what it excused (statuses only) in the summary."""
    ready = wait_worker(client, streak=ready_streak, spacing=ready_spacing, timeout=ready_timeout, sleep=sleep, clock=clock)
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
    fronts, edge = fold_edge(front_rejects(client, code))
    answers.extend(fronts)
    for label, resp in answers:
        if resp.status in (429, 503):
            raise Refused('probe: "%s" answered %d' % (label, resp.status))
        log('probe %s -> %d' % (label, resp.status))
    check_fixed_answer('probe first answer', answers[0][1], 404, NOT_FOUND)
    all_identical('probe', answers + ready.answers)         # the Worker's 404s of the wait are judged too, after the others
    ms = [r.ms for _, r in answers]
    kinds = ', '.join('%d x%d' % (st, n) for st, n in sorted(ready.statuses.items()))
    return [
        'kit-deploy production probe: %d answers, byte-identical, %d reached the gate' % (len(answers), spent),
        "  ready after %d tries, %.1f s (%d answers were not this Worker's 404%s; the %d that were are judged with the rest)"
        % (ready.tries, ready.elapsed, ready.other, ': ' + kinds if kinds else '', len(ready.answers)),
        '  wall clock ms: p50 %d, max %d' % (statistics.median(ms), max(ms)),
        '  ' + cf_nel_line(answers),
        *('  ' + line for line in edge),
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
    sub.choices['replay'].add_argument('--rows-failures', type=int, default=ROWS_FAILURES, metavar='N',
                                       help='reject-shaped decisions for the rows-read measurement (default %d)' % ROWS_FAILURES)
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
                    say('settings-off of %s: PATCH accepted (script-settings stores the off record as null); '
                        "the settings gate's GA read is the proof" % args.arg)
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
            if not 0 <= args.rows_failures <= 100000:
                raise Refused('replay: --rows-failures must be 0 to 100000')
            summary(run_replay(client, Admin(client, gate_dir), rows_failures=args.rows_failures))
        elif args.cmd == 'probe':
            summary(run_probe(Client(args.arg)))
    except Refused as e:
        say('REFUSED %s' % e)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
