#!/usr/bin/env python3
"""fleet-pins-plan.py (CV05b, D342): judge the control VM's five pin files at the fleet `release` tip before CI signs them.

  fleet-pins-plan.py plan --repo DIR --pub FILE [--release REF] [--main REF] [--tip SHA] [--run-id ID] [--only PATH]
  fleet-pins-plan.py clone URL DIR      (a blob:none clone, else a full one)

Per file the plan prints `path sha256 serial action` on stdout after `tip <sha>` and `run <id>` lines: `keep` when the tip's
.sig verifies under namespace mirrorstack-fleet-ctl (-I owner, key from --pub) for the exact bytes, else `sign`. A sign needs
a serial above every earlier signed body's (read, unverified, at each commit that added or changed the .sig: attack minor 1)
unless the bytes are the previous body's very bytes, and a `keep` needs a serial no lower than any of them (no replay of an
older signed pair). A refusal is `REFUSED <word> <path>` on stderr and exit 1, no manifest:
shape size serial head tree blob tip-moved unread vendor pub fetch. Stdlib and git only: fleet code is never imported, so the
plan cannot judge itself. fleet-disk is PUBLIC, so nothing printed is a value (attack M3): a path, serials, a sha256, key
names, and the hosts' key fingerprints (M5); the review lines go to stderr with a leading `#`. `--only PATH` (one of the five) judges
and prints that file's row alone (CV05d: install.yml's `plan` job runs it on gateway.json before gwsign signs the kit host's copy)."""
from __future__ import annotations

import base64
import ast
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
from pathlib import Path

GIT, SSH_KEYGEN = '/usr/bin/git', '/usr/bin/ssh-keygen'
NS, PRINCIPAL = 'mirrorstack-fleet-ctl', 'owner'
FILES = ('fleet/hosts.json', 'fleet/core/gateway.json', 'fleet/core/work-pin.json', 'fleet/core/deploy-pin.json',
         'fleet/core/proven.json')  # model.PIN_FILES
MAX_PIN, MAX_SIG, MAX_SERIAL, MAX_DEPTH, PIN_DEPTH = 1 << 20, 4 << 10, (1 << 63) - 1, 5, 300  # pins.py; root takes 400
WORK_YML = 'fleet/work/work.yml'  # the fleet tree's own path (CV16); .github/workflows/work.yml is not in it
SHA1, SHA256 = re.compile('[0-9a-f]{40}'), re.compile('[0-9a-f]{64}')
KEY_WORDS = re.compile('ssh-ed25519 ([A-Za-z0-9+/]{68})')
ED_HEAD = b'\0\0\0\x0bssh-ed25519\0\0\0\x20'
PLATFORMS = frozenset(('linux', 'linux-nested-hyperv', 'linux-nested-vmware', 'linux-nested-qemu', 'arm64-nested-vz',
                       'linux-ctl'))  # proven.json's keys: model.PLATFORMS' values and CTL_PLATFORM
ENDPOINT = ('address', 'cert_sha256', 'manifest_key', 'session_key')
TOKENS = re.compile(r'"(?:[^"\\]++|\\.)*+"|[\[\]{}]', re.DOTALL)
GIT_ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
           'GIT_TERMINAL_PROMPT': '0', 'LC_ALL': 'C'}


class Refused(Exception):
    def __init__(self, word: str, path: str = '-') -> None:
        super().__init__(word)
        self.word, self.path = word, path


def git(*args: str, repo: str | None = None, data: bytes | None = None) -> bytes | None:
    """git's stdout, or None on any failure; its stderr is never kept (it can name the private repo)."""
    env = dict(GIT_ENV, **({'GIT_SSH_COMMAND': os.environ['GIT_SSH_COMMAND']} if 'GIT_SSH_COMMAND' in os.environ else {}))
    try:
        done = subprocess.run([GIT, *(['-C', repo] if repo else []), *args], env=env, input=data,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=600)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return done.stdout if done.returncode == 0 else None


def clone(url: str, dest: str, run=git) -> str:
    """A clone with full history and blobs on demand, else a full one (unmeasured here: whether the FLEET_READ deploy key
    accepts --filter=blob:none, so the fallback is the rule). Returns 'filtered' or 'full'."""
    existed = os.path.lexists(dest)
    if existed and (os.path.islink(dest) or not os.path.isdir(dest) or os.listdir(dest)):
        raise Refused('fetch')  # never clean up a folder the caller already had
    for flags, mode in ((('--filter=blob:none',), 'filtered'), ((), 'full')):
        if run('clone', '--no-checkout', '--no-tags', *flags, url, dest) is not None:
            return mode
        if not existed:
            shutil.rmtree(dest, ignore_errors=True)
        else:  # an empty folder the caller made: leave it empty again
            for child in Path(dest).iterdir():
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)
    raise Refused('fetch')


def load(text: bytes, path: str) -> dict:
    """pins.py's strict loader over the exact bytes, plus LF-terminated and no BOM: no duplicate key, float, NaN, integer
    over 19 digits or nesting past MAX_DEPTH."""
    def pairs(items):
        obj = dict(items)
        if len(obj) != len(items):
            raise ValueError
        return obj

    def refuse(_):
        raise ValueError

    def int19(s):
        if len(s) - s.startswith('-') > 19:
            raise ValueError
        return int(s)
    try:
        s = text.decode('utf-8')
        if s.startswith('﻿') or not s.endswith('\n'):
            raise ValueError
        depth = 0
        for m in TOKENS.finditer(s):
            depth += {'[': 1, '{': 1, ']': -1, '}': -1}.get(m[0], 0)
            if depth > MAX_DEPTH:
                raise ValueError
        doc = json.loads(s, object_pairs_hook=pairs, parse_float=refuse, parse_constant=refuse, parse_int=int19)
    except (ValueError, RecursionError):
        raise Refused('shape', path) from None
    if not isinstance(doc, dict) or type(doc.get('serial')) is not int or not 0 <= doc['serial'] <= MAX_SERIAL:
        raise Refused('shape', path)
    return doc


def is_sha(v: object, rx: re.Pattern[str] = SHA1) -> bool:
    return type(v) is str and bool(rx.fullmatch(v))


def is_live(d: dict) -> bool:
    """A gateway's four set: an IP in canonical text, a sha256, two ssh-ed25519 lines (pins._live)."""
    def key(v):
        m = KEY_WORDS.fullmatch(v) if type(v) is str else None
        return bool(m) and base64.b64decode(m[1]).startswith(ED_HEAD)
    try:
        ip = type(d['address']) is str and '%' not in d['address'] and str(ipaddress.ip_address(d['address'])) == d['address']
    except ValueError:
        ip = False
    return ip and is_sha(d['cert_sha256'], SHA256) and key(d['manifest_key']) and key(d['session_key'])


def shape_ok(path: str, d: dict) -> bool:
    """Each file's exact key set and types as fleet/gw/pins.py (§1.7), with deploy-pin's tree required whenever head is set
    (attack M8: root takes {serial, head} alone, the plan signs only the two shapes: a null head, or head and tree)."""
    if path == 'fleet/hosts.json':
        return d.keys() == {'serial', 'hosts'} and isinstance(d['hosts'], list) and all(isinstance(x, dict) for x in d['hosts'])
    if path == 'fleet/core/deploy-pin.json':
        if not {'serial', 'head'} <= d.keys() <= {'serial', 'head', 'tree'}:
            return False
        return d['head'] is None and d.get('tree') is None or is_sha(d['head']) and is_sha(d.get('tree'))
    if path == 'fleet/core/work-pin.json':
        pins, sub = d.get('pins'), d.get('sub')
        return d.keys() == {'serial', 'pins', 'sub'} and isinstance(pins, list) \
            and all(isinstance(p, dict) and p.keys() == {'work_sha', 'blob'} and is_sha(p['work_sha']) and is_sha(p['blob'])
                    for p in pins) and len({p['work_sha'] for p in pins}) == len(pins) \
            and (type(sub) is str and re.fullmatch('[!-~]{1,512}', sub) is not None or sub is None and not pins)
    if path == 'fleet/core/proven.json':
        digests, floor = d.get('digests'), d.get('wire_floor', 1)
        return d.keys() - {'wire_floor'} == {'serial', 'digests'} and type(floor) is int and 1 <= floor <= 255 \
            and isinstance(digests, dict) and digests.keys() <= PLATFORMS and all(is_sha(v, SHA256) for v in digests.values())

    def port_ok(e):  # model.upload_port_ok: 1024-65535, not the control (443) or relay (8443) port
        return 'upload_port' not in e or type(e['upload_port']) is int and 1024 <= e['upload_port'] < 1 << 16 \
            and e['upload_port'] not in (443, 8443)
    nxt = d.get('next')
    if d.keys() - {'upload_port'} != {'serial', *ENDPOINT, 'next', 'r9_closed'} or not port_ok(d) \
            or type(d['r9_closed']) is not bool:
        return False
    if all(d[k] is None for k in ENDPOINT):
        return nxt is None
    return is_live(d) and (nxt is None or isinstance(nxt, dict) and port_ok(nxt)
                           and nxt.keys() - {'upload_port'} == set(ENDPOINT) and is_live(nxt))


def has_ctl_namespace(source: bytes) -> bool:
    """Attack M7: model.py's module-level SIG_NS dict literal (bare, annotated, or inside one call) maps 'ctl' to the
    namespace; a comment or string that only spells it does not count. A source that does not parse has none."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        if any(isinstance(t, ast.Name) and t.id == 'SIG_NS' for t in targets) and node.value is not None:
            value = node.value
            for d in [value] if isinstance(value, ast.Dict) else value.args if isinstance(value, ast.Call) else []:
                if isinstance(d, ast.Dict) and any(isinstance(k, ast.Constant) and k.value == 'ctl' and isinstance(v, ast.Constant)
                                                   and v.value == NS for k, v in zip(d.keys, d.values)):
                    return True
    return False


def vendored_summary() -> types.ModuleType:
    """vendor/pin-summary.py (fleet's bin/pin-summary.py, unchanged: attack M5) run from the bytes whose sha256 is the pin."""
    root = Path(__file__).resolve().parent.parent / 'vendor'
    try:
        data, pin = (root / 'pin-summary.py').read_bytes(), (root / 'pin-summary.sha256').read_text('ascii').strip()
    except OSError:
        raise Refused('vendor') from None
    if hashlib.sha256(data).hexdigest() != pin:
        raise Refused('vendor')
    mod = types.ModuleType('pin_summary')
    exec(compile(data, 'pin-summary.py', 'exec'), mod.__dict__)
    return mod


def verify(signers: str, text: bytes, sig: bytes) -> bool:
    """ssh-keygen -Y verify -n mirrorstack-fleet-ctl -I owner over exactly these bytes (a `pin`-namespace sig fails)."""
    with tempfile.TemporaryDirectory(prefix='pins-plan-') as tmp:
        (Path(tmp) / 'signers').write_text(signers, encoding='ascii')
        (Path(tmp) / 'sig').write_bytes(sig)
        try:
            done = subprocess.run([SSH_KEYGEN, '-Y', 'verify', '-f', f'{tmp}/signers', '-I', PRINCIPAL, '-n', NS, '-s',
                                   f'{tmp}/sig'], input=text, capture_output=True, check=False, timeout=60,
                                  env={'PATH': '/usr/bin:/bin'})
        except (OSError, subprocess.TimeoutExpired):
            raise Refused('unread') from None
    return done.returncode == 0 and done.stdout.startswith(f'Good "{NS}" signature for {PRINCIPAL} with '.encode())


class Plan:
    def __init__(self, repo: str, signers: str, release: str, main: str, tip: str | None) -> None:
        self.repo, self.signers, self.notes = repo, signers, []
        resolved = git('rev-parse', '--verify', '-q', f'{release}^{{commit}}', repo=repo)
        if resolved is None or not git('rev-parse', '--verify', '-q', f'{main}^{{commit}}', repo=repo):
            raise Refused('unread')
        self.tip = resolved.decode().strip()
        if tip is not None and tip != self.tip:
            raise Refused('tip-moved')
        self.main = main
        self.main300: set[str] | None = None
        self.summary = vendored_summary()

    def blob(self, rev: str, path: str) -> bytes | None:
        return git('cat-file', 'blob', f'{rev}:{path}', repo=self.repo)

    def history(self, path: str) -> list[tuple[bytes, dict]]:
        """The bodies at every commit that added or changed `<path>.sig` on the release tip, newest first, read without
        verifying (attack minor 1: the monotonic and ancestor rules survive a key switch). The newest must parse; an older
        one that does not carries no serial and is skipped. Empty when there was never a sig."""
        found = git('log', '--format=%H', '--diff-filter=AM', self.tip, '--', f'{path}.sig', repo=self.repo)
        if found is None:
            raise Refused('unread', path)
        bodies = []
        for i, sha in enumerate(found.decode().split()):
            text = self.blob(sha, path)
            try:
                doc = json.loads(text)
                assert type(doc['serial']) is int
            except (TypeError, ValueError, KeyError, AssertionError):
                if i == 0:
                    raise Refused('serial', path) from None
                continue
            bodies.append((text, doc))
        return bodies

    def judge(self, path: str, text: bytes, doc: dict, prev: dict | None, bodies: list[tuple[bytes, dict]]) -> None:
        """What CI is about to sign, beyond the shape (a `keep` is not judged again)."""
        if path == 'fleet/hosts.json':
            ps = self.summary
            try:
                lines = ps.check_hosts(text)
            except ps.Refused:
                raise Refused('shape', path) from None
            try:
                last = ps.check_hosts(json.dumps(prev).encode()) if prev else {}
            except ps.Refused:
                last = {}
            for line in ps.summarize(lines, last):  # the hosts' key fingerprints: public keys, no id or owner (M3, M5)
                self.notes.append(f'hosts {line.split()[0]} {" ".join(line.split()[8:10])}')
        elif path == 'fleet/core/work-pin.json':
            want = (git('rev-parse', '--verify', '-q', f'{self.tip}:{WORK_YML}', repo=self.repo) or b'').decode().strip()
            if any(p['blob'] != want for p in doc['pins']):  # attack M5: tie each pin to the release tree
                raise Refused('blob', path)
        elif path == 'fleet/core/deploy-pin.json' and doc['head'] is not None:
            self.deploy(path, doc, bodies)

    def deploy(self, path: str, doc: dict, bodies: list[tuple[bytes, dict]]) -> None:
        head, repo = doc['head'], self.repo
        if self.main300 is None:
            out = git('rev-list', '--first-parent', f'-n{PIN_DEPTH}', self.main, repo=repo)
            self.main300 = set((out or b'').decode().split())
        # M2: a head the security-approved release merge never carried must not run as root; the 300 is only a margin
        if head not in self.main300 or git('merge-base', '--is-ancestor', head, self.tip, repo=repo) is None:
            raise Refused('head', path)
        if (git('rev-parse', '--verify', '-q', f'{head}^{{tree}}', repo=repo) or b'').decode().strip() != doc['tree']:
            raise Refused('tree', path)
        if not has_ctl_namespace(self.blob(head, 'fleet/slot/model.py') or b''):  # M7
            raise Refused('head', path)
        old = next((d['head'] for _, d in bodies if d.get('head') is not None), None)  # across a signed null head
        if old is not None and (not is_sha(old) or git('merge-base', '--is-ancestor', old, head, repo=repo) is None):
            raise Refused('head', path)  # no sideways move from the previous signed head

    def file(self, path: str) -> tuple[str, int, str]:
        size = git('cat-file', '-s', f'{self.tip}:{path}', repo=self.repo)
        if size is None:
            raise Refused('shape', path)
        if int(size) > MAX_PIN:
            raise Refused('size', path)
        text = self.blob(self.tip, path)
        doc = load(text, path)
        if not shape_ok(path, doc):
            raise Refused('shape', path)
        sha, sig = hashlib.sha256(text).hexdigest(), self.blob(self.tip, f'{path}.sig')
        serial, bodies = doc['serial'], self.history(path)
        if sig is not None and len(sig) <= MAX_SIG and verify(self.signers, text, sig):
            if any(serial < d['serial'] for _, d in bodies):  # an older signed pair committed back is no `keep`
                raise Refused('serial', path)
            return sha, serial, 'keep'
        prev = bodies[0] if bodies else None
        top = max((d['serial'] for _, d in bodies), default=-1)
        if serial < top or serial == top and prev[0] != text:  # the very same bytes may be signed again at their own serial
            raise Refused('serial', path)
        self.judge(path, text, doc, prev[1] if prev else None, bodies)
        old = prev[1] if prev else {}
        changed = sorted(k for k in doc.keys() | old.keys() if doc.get(k, self) != old.get(k, self))  # key names, never values
        self.notes.append(f'{path} sha256={sha} serial {doc["serial"]} (was {old.get("serial", "none")}) '
                          f'changed: {" ".join(changed) or "-"}')
        return sha, doc['serial'], 'sign'


def signers_line(pub: str) -> str:
    try:
        words = Path(pub).read_text('ascii').split()
    except (OSError, UnicodeDecodeError):
        raise Refused('pub') from None
    if len(words) < 2 or not KEY_WORDS.fullmatch(' '.join(words[:2])):
        raise Refused('pub')
    return f'{PRINCIPAL} namespaces="{NS}" {words[0]} {words[1]}\n'


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 4 and argv[1] == 'clone':
            print(f'clone {clone(argv[2], argv[3])}')
            return 0
        opts = dict(zip(argv[2::2], argv[3::2]))
        want = {'--repo', '--pub', '--release', '--main', '--tip', '--run-id', '--only'}
        run_id = opts.get('--run-id', os.environ.get('GITHUB_RUN_ID', 'local'))
        if argv[1:2] != ['plan'] or len(argv) % 2 or not opts.keys() <= want or not {'--repo', '--pub'} <= opts.keys() \
                or not re.fullmatch('[0-9A-Za-z._-]{1,32}', run_id) or not re.fullmatch('[0-9a-f]{40}', opts.get('--tip', '0' * 40)) \
                or opts.get('--only', FILES[0]) not in FILES:
            print(__doc__.split('\n\n')[1], file=sys.stderr)
            return 2
        plan = Plan(opts['--repo'], signers_line(opts['--pub']), opts.get('--release', 'origin/release'),
                    opts.get('--main', 'origin/main'), opts.get('--tip'))
        rows = [(p, *plan.file(p)) for p in FILES if opts.get('--only', p) == p]
    except Refused as e:
        print(f'REFUSED {e.word} {e.path}', file=sys.stderr)
        return 1
    print(f'tip {plan.tip}\nrun {run_id}')
    for path, sha, serial, action in rows:
        print(f'{path} {sha} {serial} {action}')
    for note in plan.notes:
        print(f'# {note}', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
