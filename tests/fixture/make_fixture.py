#!/usr/bin/env python3
"""Builds the boot smoke's fixture tree, stdlib only (plus the runner's ssh-keygen and openssl), from the two bootstraps a
PR carries. It copies them, bakes a THROWAWAY owner key and expiry into the copies with the publisher's own regexes, points
their base URLs at the local server by pinned regexes (each must match exactly once), and writes one complete release folder
per case, signed with the throwaway key and then damaged the way the case needs. The original files are never changed.

  make_fixture.py --out DIR (--boot-dir release/install-N | --ps1 P --sh P) [--host H] [--port N] [--crl-port N]
                  [--python-version V | --python-zip PATH] [--no-verify]

A failure prints `REFUSED <rewrite|bake|python|tool|out|verify>` and exits 1. The private keys and the CA key never reach
DIR: what is left (public keys, the CA certificate, the leaf TLS key, the CRL) is worthless."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('fleet_install_publish', ROOT / 'bin' / 'fleet-install-publish.py')
PUB = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = PUB
_spec.loader.exec_module(PUB)

NS, PIN_NS = PUB.NS, PUB.PIN_NS
KIT = PUB.KIT_FILES
MAX_SIG, MAX_KIT_JSON, MAX_CARRIER_SH, MAX_KIT, MAX_ZIP = 4096, 65536, 262144, 4 << 20, 32 << 20  # the bootstraps' own caps
CODE = 'ABCDE 23456 FGHJK MNPQR STVWX YZ012 34567 89ABC'  # the one code the dummy carrier-check prints
TIME = '%Y-%m-%dT%H:%M:%SZ'
UNBAKED = 'ssh-ed25519 UNBAKED'
# the base-URL lines, pinned: each must match the bootstrap exactly once or the build refuses (`@` is host:port)
REWRITE = {
    'sh': [(r'^RELEASES=https://github\.com/mirrorstack-ai/fleet-disk/releases/download$',
            'RELEASES=https://@/releases/download')],
    'ps1': [(r"^\$Release = 'https://github\.com/mirrorstack-ai/fleet-disk/releases/download'$",
             "$Release = 'https://@/releases/download'"),
            (r"^\$PythonUrl = 'https://www\.python\.org/ftp/python/\{0\}/python-\{0\}-embed-amd64\.zip'$",
             "$PythonUrl = 'https://@/python/{0}/python-{0}-embed-amd64.zip'")],
}
CNF = """[req]
distinguished_name = dn
prompt = no
[dn]
CN = fleet-smoke
[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
[leaf_ext]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:{host},DNS:localhost
crlDistributionPoints = URI:http://{host}:{crl}/ca.crl
[ca]
default_ca = c
[c]
database = index.txt
serial = serial
new_certs_dir = .
crlnumber = crlnumber
default_md = sha256
policy = pol
unique_subject = no
[pol]
commonName = supplied
"""
BACKDATE = timedelta(hours=1)  # the certificates and the CRL start an hour back: a runner clock a little slow still sees them valid


class Refused(Exception):
    pass


def tool(*argv, cwd=None, data=None):
    try:
        return subprocess.run(argv, check=True, capture_output=True, cwd=cwd, input=data, timeout=120).stdout
    except (OSError, subprocess.SubprocessError):
        raise Refused('tool') from None


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sub_group(rx, text: str, value: str) -> tuple[str, int]:
    """text with group 1 of every match of rx replaced by value, and how many matches there were."""
    def one(m):
        a, b = m.start(1) - m.start(0), m.end(1) - m.start(0)
        return m.group(0)[:a] + value + m.group(0)[b:]
    return rx.subn(one, text)


def rewrite(name: str, data: bytes, host: str, port: int) -> bytes:
    text = data.decode('ascii')
    for rx, new in REWRITE[name]:
        text, n = re.subn(rx, lambda m: new.replace('@', f'{host}:{port}'), text, flags=re.M)
        if n != 1:
            raise Refused('rewrite')
    return text.encode('ascii')


def bake(name: str, data: bytes, key: str, expires: str) -> bytes:
    text = data.decode('ascii')
    for rx, value in zip(PUB.BAKED[name][:2], (key, expires)):
        text, n = sub_group(rx, text, value)
        if n != 1:
            raise Refused('bake')
    return text.encode('ascii')


def check_copy(orig: bytes, copy: bytes, changed: int) -> None:
    """The copy differs from the original in exactly `changed` lines and no live line still names github.com or python.org."""
    a, b = orig.decode('ascii').split('\n'), copy.decode('ascii').split('\n')
    live = [x for x in b if not x.lstrip().startswith('#') and ('github.com' in x or 'python.org' in x)]
    if len(a) != len(b) or sum(x != y for x, y in zip(a, b)) != changed or live:
        raise Refused('rewrite')


def prepare(name: str, raw: bytes, host: str, port: int, key: str, expires: str) -> bytes:
    """One bootstrap copy: base rewritten, throwaway key and expiry baked, and nothing else changed."""
    copy = bake(name, rewrite(name, raw, host, port), key, expires)
    check_copy(raw, copy, len(REWRITE[name]) + 2)
    if PUB.baked_values(name, copy) != (key, expires):  # the publisher reads back what was baked
        raise Refused('bake')
    return copy


class Ctx:
    """What every case shares."""

    def __init__(self, out: Path, now: datetime) -> None:
        self.out, self.now, self.cache = out, now, {}
        self.tmp = Path(tempfile.mkdtemp(prefix='fleet-smoke-keys-'))  # private keys live here and are removed
        self.keys = {}
        for who in ('owner', 'wrong'):
            tool(shutil.which('ssh-keygen') or 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', str(self.tmp / who))
            self.keys[who] = str(self.tmp / who)
        self.key = ' '.join((self.tmp / 'owner.pub').read_text().split()[:2])
        self.fp = PUB.key_fingerprint(self.key.encode())
        self.expires = (now + timedelta(days=120)).strftime(TIME)

    def sign(self, who: str, ns: str, data: bytes) -> bytes:
        k = (who, ns, sha(data))
        if k not in self.cache:
            f = self.tmp / 'to-sign'
            f.write_bytes(data)
            tool('ssh-keygen', '-Y', 'sign', '-q', '-f', self.keys[who], '-n', ns, str(f))
            self.cache[k] = (self.tmp / 'to-sign.sig').read_bytes()
            (self.tmp / 'to-sign.sig').unlink()
        return self.cache[k]


def make_tls(d: Path, host: str, crl: int, now: datetime) -> None:
    """A throwaway CA and a leaf for host (SAN, serverAuth, a CRL point: Windows' curl checks revocation). Everything is valid
    from an hour before `now` to two days after it, the CRL too."""
    d.mkdir()
    (d / 'openssl.cnf').write_text(CNF.format(host=host, crl=crl))
    (d / 'index.txt').write_text('')
    (d / 'crlnumber').write_text('01\n')
    (d / 'serial').write_text('01\n')
    start, end = ((now + delta).strftime('%Y%m%d%H%M%SZ') for delta in (-BACKDATE, timedelta(days=2)))
    c = ['-config', 'openssl.cnf']
    window = ['-startdate', start, '-enddate', end]
    run = lambda *a: tool('openssl', *a, cwd=d)  # noqa: E731
    run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.csr', '-subj', '/CN=fleet-smoke-ca', *c)
    run('ca', '-batch', '-selfsign', *c, '-in', 'ca.csr', '-keyfile', 'ca.key', '-out', 'ca.crt', '-notext', *window,
        '-extensions', 'ca_ext')
    run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', f'/CN={host}', *c)
    run('ca', '-batch', *c, '-in', 'leaf.csr', '-cert', 'ca.crt', '-keyfile', 'ca.key', '-out', 'leaf.crt', '-notext', *window,
        '-extensions', 'leaf_ext')
    run('ca', *c, '-gencrl', '-keyfile', 'ca.key', '-cert', 'ca.crt', '-crl_lastupdate', start, '-crl_nextupdate', end,
        '-out', 'ca.crl.pem')
    run('crl', '-in', 'ca.crl.pem', '-outform', 'DER', '-out', 'ca.crl')
    run('x509', '-in', 'ca.crt', '-outform', 'DER', '-out', 'ca.cer')
    for junk in [*d.glob('*.pem'), *d.glob('index.txt*'), *d.glob('serial*'), *d.glob('crlnumber*'), d / 'ca.key', d / 'ca.csr',
                 d / 'leaf.csr', d / 'openssl.cnf']:
        (d / junk).unlink(missing_ok=True)


def kit_files() -> dict[str, bytes]:
    """Five dummy kit files: both carrier-checks write the one Code line, and the .py proves `-I -X utf8` reached it."""
    return {
        'carrier-check.sh': f"#!/bin/sh\nprintf 'Code  {CODE}\\n' > carrier-check-report.txt\necho carrier-check ok\n".encode(),
        'carrier-check.py': ('import os, sys\nhere = os.path.dirname(os.path.abspath(__file__))\n'
                             'assert sys.flags.isolated == 1 and sys.flags.utf8_mode == 1 and sys.argv[1:] == ["check"]\n'
                             'assert os.path.isfile(os.path.join(here, "check.ps1"))\n'
                             f'open(os.path.join(here, "carrier-check-report.txt"), "w").write("Code  {CODE}\\n")\n').encode(),
        'check.ps1': b'# fixture\n', 'verify-archive.py': b'# fixture\n', 'VERIFY.txt': b'fixture\n',
    }


def C(cid, code=None, info=3, upto='all', only=None, **o):
    """One case: its id, the refusal it must end in (None = the code line), how many info lines precede it, how far the
    fetches get, the OS it is for (None = both) and how it differs from the good set."""
    return {'id': cid, 'code': code, 'info': info, 'upto': upto, 'only': only, 'o': o}


CASES = [
    C('good'), C('good-pretty', pretty=1), C('good-kitorder', kitorder=1),
    C('key', 'key', 1, 'none', baked_key=UNBAKED),
    C('expired-baked', 'expired', 2, 'none', baked_exp='2020-01-01T00:00:00Z'),
    C('expired-install', 'expired', 3, 'sig', days=-1, pub='expired'),
    C('sig-wrong-key', 'sig', 2, 'sig', signer='wrong', pub='sig'),
    C('sig-tampered', 'sig', 2, 'sig', tamper='install', pub='sig'),
    C('sig-namespace', 'sig', 2, 'sig', ns=PIN_NS, pub='sig'),
    C('rollback', 'rollback', 3, 'sig', serial=25, min=10, doc_serial=3, pub='rollback'),
    C('serial', 'serial', 3, 'sig', serial=26, doc_serial=27, pub='serial'),
    C('boot-hash', 'boot-hash', 3, 'sig', run_boot='append'),
    C('boot-hash-crlf', 'boot-hash', 3, 'sig', only='ps1', run_boot='crlf'),
    C('kit-hash', 'kit-hash', 3, 'kit', tamper='kit', pub='hash'),
    C('file-hash', 'file-hash', 3, 'files', tamper='file', pub='hash'),
    C('zip-hash', 'zip-hash', 3, 'all', only='ps1', zip_bad=1),
    C('size-big', 'size', 2, 'install', tamper='big'), C('size-empty', 'size', 2, 'install', tamper='empty'),
    C('redirect-downgrade', 'fetch', 2, 'install', redirect=1),
    C('fetch-missing', 'fetch', 2, 'install', serial=30, no_folder=1),
    C('args', 'args', 0, 'none', args='007'),
    C('args-lt-min', 'args', 0, 'none', args='5', min=10),
    C('args-dup', 'args', 0, 'none', argv=[('serial', '20'), ('min', '5'), ('serial', '20')]),
    C('args-missing', 'args', 0, 'none', argv=[('serial', '20')]),
    C('args-abbrev', 'args', 0, 'none', argv=[('ser', '20'), ('min', '5')]),  # the ps1 has no param(): -Ser must not bind
    C('kind-wrong', 'kind', 3, 'sig', kind='other', pub='kind'),
    C('form-field', 'form', 3, 'sig', drop='valid_until', until='?', pub='form'),
    C('kit-six', 'form', 3, 'kit', kit_extra=1, pub='kit'),
    C('size-sig', 'size', 2, 'sig', tamper='sigbig'),
    C('size-chunked', 'size', 2, 'install', tamper='big', chunked=1),  # no Content-Length: curl stops on the running count
    C('size-kit-json', 'size', 3, 'kit', tamper='kitbig'),
    C('size-kit-file', 'size', 3, 'file1', tamper='filebig'),
    C('size-zip', 'size', 3, 'all', only='ps1', zip_big=1),
]


def want_reqs(upto: str, osn: str) -> list[str]:
    """The logical requests the bootstrap makes, in order, before it stops at `upto`."""
    full = ['install.json', 'install.json.sig', 'kit.json', *(KIT if osn == 'ps1' else ['carrier-check.sh'])]
    if osn == 'ps1':
        full.append('python.zip')
    n = {'none': 0, 'install': 1, 'sig': 2, 'kit': 3, 'file1': 4, 'files': 3 + (KIT.index('carrier-check.sh') + 1 if osn == 'ps1' else 1)}
    return full if upto == 'all' else full[:n[upto]]


def dumps(doc, pretty=False) -> bytes:
    return (json.dumps(doc, indent=2) if pretty else json.dumps(doc, separators=(',', ':'))).encode() + b'\n'


def build_case(x: Ctx, boots: dict[str, bytes], zip_info: dict, c: dict, osn: str) -> dict:
    o, cid = c['o'], f'{c["id"]}-{osn}'
    folder = o.get('serial', 20)
    dserial, minv = o.get('doc_serial', folder), o.get('min', 5)
    run_bytes = boots[osn]
    if 'baked_key' in o or 'baked_exp' in o:
        run_bytes = bake(osn, run_bytes, o.get('baked_key', x.key), o.get('baked_exp', x.expires))
    boots = {**boots, osn: run_bytes}
    files = kit_files()
    entry = (lambda n: {'sha256': sha(files[n]), 'path': n}) if o.get('kitorder') else (lambda n: {'path': n, 'sha256': sha(files[n])})
    zsha = 'f' * 64 if o.get('zip_bad') else zip_info['sha256']
    listed = [entry(n) for n in KIT] + ([{'path': 'extra.txt', 'sha256': sha(b'extra')}] if o.get('kit_extra') else [])
    kit = dumps({'serial': 1, 'files': listed, 'python_zip': {'version': zip_info['version'], 'sha256': zsha}})
    valid = (x.now + timedelta(days=o.get('days', 60))).strftime(TIME)
    doc = {'kind': o.get('kind', 'install'), 'serial': dserial, 'valid_until': valid, 'source_head': 'a' * 40,
           'bootstrap': {n: {'sha256': sha(boots[n]), 'blob': PUB.blob_ids(boots[n]).pop()} for n in ('ps1', 'sh')},
           'kit': {'serial': 1, 'kit_json_sha256': sha(kit)}, 'lock_sha256': '0' * 64,
           'bundle': {'head': 'a' * 40, 'tree': 'b' * 40, 'url': f'https://example.org/v1/kit/{dserial}/bundle.tar', 'sha256': '1' * 64, 'size': 1}}
    doc.pop(o.get('drop'), None)
    install = dumps(doc, bool(o.get('pretty')))
    sig = x.sign(o.get('signer', 'owner'), o.get('ns', NS), install)
    pin = dumps({'serial': 1, 'head': 'a' * 40, 'tree': 'b' * 40})
    out = {'install.json': install, 'install.json.sig': sig, 'kit.json': kit, 'kit.json.sig': x.sign('owner', PIN_NS, kit),
           'deploy-pin.json': pin, 'deploy-pin.json.sig': x.sign('owner', PIN_NS, pin), '.gitattributes': PUB.GITATTRIBUTES,
           'bootstrap.ps1': boots['ps1'], 'bootstrap.sh': boots['sh'], **files}
    t = o.get('tamper')
    if t == 'install':
        out['install.json'] += b'\n'
    elif t == 'kit':
        out['kit.json'] += b'\n'
    elif t == 'file':
        out['carrier-check.sh'] += b'# tampered\n'
    elif t == 'big':
        out['install.json'] = b'x' * 9000
    elif t == 'empty':
        out['install.json'] = b''
    elif t == 'sigbig':
        out['install.json.sig'] = b'x' * (MAX_SIG + 1)
    elif t == 'kitbig':
        out['kit.json'] = b'x' * (MAX_KIT_JSON + 1)
    elif t == 'filebig':  # the first kit file the OS fetches, one byte over that OS's cap
        name, cap = ('carrier-check.sh', MAX_CARRIER_SH) if osn == 'sh' else (KIT[0], MAX_KIT)
        out[name] = b'x' * (cap + 1)
    d = x.out / cid
    if not o.get('no_folder'):
        rel = d / 'release' / f'install-{folder}'
        rel.mkdir(parents=True)
        for n, data in out.items():
            (rel / n).write_bytes(data)
        if o.get('chunked'):
            (rel / 'install.json.chunked').write_bytes(b'')
        if o.get('redirect'):  # the same valid, signed pair, one plain-http hop away: followed, the run would succeed
            plain = d / 'plain' / f'install-{folder}'
            plain.mkdir(parents=True)
            (plain / 'install.json').write_bytes(install)
            (plain / 'install.json.sig').write_bytes(sig)
            (rel / 'install.json.redirect').write_text(f'http://127.0.0.1:{x.crl_port}/install-{folder}/install.json\n')
    if o.get('zip_big'):  # this case's own ZIP, one byte over the cap, served instead of the shared one
        big = d / 'python' / zip_info['version'] / f'python-{zip_info["version"]}-embed-amd64.zip'
        big.parent.mkdir(parents=True)
        big.write_bytes(b'PK' + b'\0' * (MAX_ZIP - 1))
    (d / 'run').mkdir(parents=True, exist_ok=True)
    ran = {'append': lambda b: b + b'# appended\n', 'crlf': lambda b: b.replace(b'\n', b'\r\n')}.get(o.get('run_boot'), lambda b: b)
    (d / 'run' / f'bootstrap.{osn}').write_bytes(ran(run_bytes))
    return {'id': cid, 'os': osn, 'args': [o.get('args', str(folder)), str(minv)], 'code': c['code'], 'info': c['info'],
            'argv': o.get('argv') or [('serial', o.get('args', str(folder))), ('min', str(minv))],
            'serial_line': f'serial {dserial} valid_until {o.get("until", valid)}',
            'reqs': want_reqs(c['upto'], osn),
            'pub': o.get('pub'), 'folder': folder}


def get_zip(ps1: bytes, version: str, dest: Path) -> None:
    """Download the embeddable ZIP from the URL the ps1 itself carries, so a wrong template fails here."""
    m = re.search(r"^\$PythonUrl = '([^']+)'$", ps1.decode('ascii'), re.M)
    try:
        with urllib.request.urlopen(m[1].format(version), timeout=120) as r:
            data = r.read(40 << 20)
    except (OSError, TypeError, ValueError):
        raise Refused('python') from None
    if not data.startswith(b'PK'):
        raise Refused('python')
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)


def publisher(out: Path, c: dict) -> str:
    """What the publisher's own `verify` says of a case's release folder: `OK install-N` or `REFUSED <code>`."""
    done = subprocess.run([sys.executable, str(ROOT / 'bin' / 'fleet-install-publish.py'), 'verify', f'release/install-{c["folder"]}',
                           '--owner-pub', str(out / 'owner.pub'), '--min-serial', c['args'][1]], cwd=out / c['id'], capture_output=True,
                          text=True, env={**os.environ, 'GITHUB_REPOSITORY': 'mirrorstack-ai/fleet-disk'})
    return ' '.join(done.stdout.split()[:2])


def build(out: Path, ps1: Path, sh: Path, host='127.0.0.1', port=18443, crl_port=18444, version='3.12.10', zip_path=None,
          verify=True) -> dict:
    if out.exists():
        raise Refused('out')
    out.mkdir(parents=True)
    x = Ctx(out, datetime.now(timezone.utc))
    x.crl_port = crl_port
    try:
        raw = {'ps1': ps1.read_bytes(), 'sh': sh.read_bytes()}
        boots = {n: prepare(n, b, host, port, x.key, x.expires) for n, b in raw.items()}
        make_tls(out / 'tls', host, crl_port, x.now)
        zdest = out / 'python' / version / f'python-{version}-embed-amd64.zip'
        if zip_path:
            zdest.parent.mkdir(parents=True)
            shutil.copy(zip_path, zdest)
        else:
            get_zip(raw['ps1'], version, zdest)
        zip_info = {'version': version, 'sha256': sha(zdest.read_bytes())}
        (out / 'owner.pub').write_text(x.key + '\n')
        cases = [build_case(x, boots, zip_info, c, osn) for c in CASES for osn in ('ps1', 'sh') if c['only'] in (None, osn)]
        meta = {'host': host, 'port': port, 'crl_port': crl_port, 'fingerprint': x.fp, 'cases': cases}
        (out / 'cases.json').write_text(json.dumps(meta, indent=1))
        if verify and publisher(out, cases[0]) != f'OK install-{cases[0]["folder"]}':  # the good set is one the publisher would publish
            raise Refused('verify')
        return meta
    except BaseException:
        shutil.rmtree(out, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(x.tmp, ignore_errors=True)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog='make_fixture.py', description='build --out DIR from --boot-dir release/install-N or --ps1/--sh')
    for flag, default in (('out', None), ('boot-dir', None), ('ps1', None), ('sh', None), ('host', '127.0.0.1'), ('port', 18443),
                          ('crl-port', 18444), ('python-version', '3.12.10'), ('python-zip', None)):
        p.add_argument('--' + flag, default=default, required=flag == 'out', type=type(default) if isinstance(default, int) else str)
    p.add_argument('--no-verify', action='store_true')
    a = p.parse_args(argv)
    d = Path(a.boot_dir or '')
    ps1, sh = (d / 'bootstrap.ps1', d / 'bootstrap.sh') if a.boot_dir else (Path(a.ps1 or ''), Path(a.sh or ''))
    try:
        meta = build(Path(a.out), ps1, sh, a.host, a.port, a.crl_port, a.python_version, a.python_zip, verify=not a.no_verify)
    except (Refused, OSError, ValueError, TypeError) as why:
        print(f'REFUSED {why if isinstance(why, Refused) else "case"}')
        return 1
    print(f'built {len(meta["cases"])} cases in {a.out}; owner key {meta["fingerprint"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
