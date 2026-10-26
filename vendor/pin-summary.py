"""The owner's hosts.json summary (P+ C01b, §14 #4, X38) and install.json summary (I01): given the file about to be
signed and, optionally, the last signed one, one line per new or changed host, `id tier owner power repos customer_ok
facts hostkey-fp statuskey-fp invite` (N02's invite id, '-' for none), computed from the exact bytes, each fingerprint
as `ssh-keygen -lf` prints it; a file that fails the schema is refused. `--install INSTALL_JSON OWNER_PUB` prints one `name value` line per field the phone's
signer must compare (the bootstraps' sha256s, the key about to be baked, the lock, the bundle, the URL host, the
serial, valid_until). Standalone stdlib, importing nothing of fleet, so it can be copied alone to the owner's phone; its
tables copy fleet's, tests/test_pin_summary.py pins the hosts tables equal and tests/install/test_manifest.py pins the
install tables equal. An error never echoes a value."""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import re
import struct
import sys

FORMS = ('bare', 'carrier-hyperv', 'carrier-vmware', 'carrier-qemu', 'carrier-vz', 'carrier-wsl')  # model.Form
TIERS = ('T0', 'T1', 'T2', 'T3')  # model.Tier: no default, so a line without one is refused, never read as T0
POWERS = (0, 1, 2)  # model.PowerTier
MAX_WORK = 4  # model.MAX_WORK: a line's slot count
FACTS = ('arm64', 'big', 'light', 'seat', 'single-admin')  # the closed set; arm64 = model.ARM64_FACT (D307);
# single-admin only from the machine's admin count (§14 #6); seat = a member's own Claude seat (§16q), its owner label the member
MAX_REPOS = 32
# PA08: types.CUSTOMER_REPOS and github.FLEET_REPO, TRACKER_REPO, lower case: no line below T0 may list them
NEVER_BELOW_T0 = frozenset({'emat-group/kaohsiung-association', 'mirrorstack-ai/mirrorstack-fleet',
                            'mirrorstack-ai/mirrorstack-core-v2'})
MACHINE = re.compile('[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?', re.ASCII)  # shapes.MACHINE
OWNER = re.compile('[a-z0-9-]{1,32}', re.ASCII)
REPO = re.compile(r'(?=[^/]{1,39}/)[A-Za-z0-9](?:-?[A-Za-z0-9])*/[A-Za-z0-9._-]{1,100}', re.ASCII)  # config._REPO
KEY_LINE = re.compile('ssh-ed25519 ([A-Za-z0-9+/]{68})', re.ASCII)  # 51 blob bytes, so no padding and no comment
KEY_HEAD = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32)
HEX40, HEX64 = re.compile('[0-9a-f]{40}', re.ASCII), re.compile('[0-9a-f]{64}', re.ASCII)
UTC_TIME = re.compile('[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', re.ASCII)  # clock.parse_utc
_LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
URL = re.compile(rf'https://({_LABEL}(?:\.{_LABEL})+)/[A-Za-z0-9._~/-]{{1,200}}', re.ASCII)  # manifest.URL
INSTALL_KEYS = ('kind', 'serial', 'valid_until', 'source_head', 'bootstrap', 'kit', 'lock_sha256', 'bundle')
BOOT_KEYS, KIT_KEYS = ('sha256', 'blob'), ('serial', 'kit_json_sha256')
BUNDLE_KEYS = ('head', 'tree', 'url', 'sha256', 'size')  # these four tables: manifest.SCHEMA, BOOT_KEYS, ...
MAX_COUNT, MAX_BUNDLE = 1 << 31, 1 << 30  # manifest's serial cap and bundle byte cap
LINE_KEYS = ('id', 'form', 'slots', 'host_key', 'status_key', 'facts', 'tier', 'owner', 'power', 'repos', 'customer_ok')
INVITE = re.compile('[0-9a-f]{8}', re.ASCII)  # N02: the optional `invite` key, 8 hex, the invite's random ref (K2)


class Refused(ValueError):
    """A file that fails its schema, at a JSON path like $.hosts[0].tier; the value is never echoed."""

    def __init__(self, path: str, msg: str) -> None:
        super().__init__(f'{path}: {msg}')


def _need(ok: object, path: str, msg: str) -> None:
    if not ok:
        raise Refused(path, msg)


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    obj = dict(items)
    _need(len(obj) == len(items), '$', 'a duplicate key')
    return obj


def _constant(name: str) -> object:
    raise Refused('$', f'{name} is not JSON')


def load(data: bytes) -> object:
    """Strict JSON over the exact bytes (X31): UTF-8 with no BOM, no duplicate key, no NaN or Infinity."""
    _need(not data.startswith(b'\xef\xbb\xbf'), '$', 'a byte order mark')
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_constant)
    except Refused:
        raise
    except (ValueError, RecursionError):  # UnicodeDecodeError and JSONDecodeError are ValueErrors
        raise Refused('$', 'not UTF-8 JSON') from None


def keys(obj: object, path: str, want: tuple[str, ...], optional: tuple[str, ...] = ()) -> dict:
    """obj when it is an object holding exactly the keys want, and any of optional; the first missing or unknown key is
    refused."""
    _need(isinstance(obj, dict), path, 'expected an object')
    for key in want:
        _need(key in obj, f'{path}.{key}', 'missing')
    _need(len(obj) == len(want) + sum(k in obj for k in optional), path, 'an unknown key')
    return obj


def key_blob(line: object, path: str) -> bytes:
    """The blob of one `ssh-ed25519 <base64>` public-key line (§14 #4) and nothing else, no comment included."""
    m = KEY_LINE.fullmatch(line) if isinstance(line, str) else None
    blob = base64.b64decode(m[1]) if m else b''
    _need(blob[:19] == KEY_HEAD and len(blob) == 51, path, 'not one ssh-ed25519 public-key line')
    return blob


def fingerprint(blob: bytes) -> str:
    """A key blob's fingerprint as `ssh-keygen -lf` prints it: SHA256: and the unpadded base64 of its sha256."""
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode('ascii').rstrip('=')


def check_line(line: object, path: str) -> dict:
    """One host's line (P+ §1.7 Pins, X24, X38, §14 #4 #6): a machine id (a carrier's is pc- and 8 hex of its host
    key's sha256), a form, 1 to MAX_WORK slots, the host key and the status key (or null) as ssh-ed25519 lines,
    distinct facts of FACTS, a tier, an owner label, a power tier, a T1 line's repos (empty otherwise; never a customer
    repo, the fleet repo or the tracker), customer_ok (true only on T0: customer work is never a lower tier's, PA08)."""
    line = keys(line, path, LINE_KEYS, ('invite',))

    def at(key: str) -> str:
        return f'{path}.{key}'

    _need(isinstance(line['id'], str) and MACHINE.fullmatch(line['id']), at('id'), 'not a machine name')
    _need(isinstance(line['form'], str) and line['form'] in FORMS, at('form'), f'not one of {FORMS}')
    _need(type(line['slots']) is int and 1 <= line['slots'] <= MAX_WORK, at('slots'), f'not 1 to {MAX_WORK}')
    host = key_blob(line['host_key'], at('host_key'))
    if line['status_key'] is not None:
        key_blob(line['status_key'], at('status_key'))
    _need(line['form'] == 'bare' or line['id'] == 'pc-' + hashlib.sha256(host[19:]).hexdigest()[:8], at('id'),
          "not the carrier's name, pc- and 8 hex of its host key's sha256")
    facts = line['facts']
    _need(isinstance(facts, list) and all(isinstance(f, str) and f in FACTS for f in facts)
          and len(set(facts)) == len(facts), at('facts'), f'not distinct facts of {FACTS}')
    _need(isinstance(line['tier'], str) and line['tier'] in TIERS, at('tier'), f'not one of {TIERS}')
    _need(isinstance(line['owner'], str) and OWNER.fullmatch(line['owner']), at('owner'), 'not an owner label')
    _need(type(line['power']) is int and line['power'] in POWERS, at('power'), f'not one of {POWERS}')
    repos = line['repos']
    _need(isinstance(repos, list) and len(repos) <= MAX_REPOS
          and all(isinstance(r, str) and REPO.fullmatch(r) for r in repos)
          and len({r.lower() for r in repos}) == len(repos), at('repos'), f'not {MAX_REPOS} distinct repos or fewer')
    _need(line['tier'] == 'T1' or not repos, at('repos'), 'listed on a line that is not T1')
    _need(not any(r.lower().removesuffix('.git') in NEVER_BELOW_T0 for r in repos), at('repos'),
          'a customer repo, the fleet repo or the tracker, which no line below T0 may list')  # PA08 (D8 A)
    _need(type(line['customer_ok']) is bool, at('customer_ok'), 'not a boolean')
    _need(line['tier'] == 'T0' or not line['customer_ok'], at('customer_ok'), 'true on a line that is not T0')  # PA08
    _need('invite' not in line or isinstance(line['invite'], str) and INVITE.fullmatch(line['invite']), at('invite'),
          'not 8 hex')
    return line


def check_hosts(data: bytes) -> dict[str, dict]:
    """hosts.json from its exact bytes (P+ §1.7 Pins, X31): {serial, hosts}, each id and host key once; its lines
    by id."""
    doc = keys(load(data), '$', ('serial', 'hosts'))
    _need(type(doc['serial']) is int and 0 <= doc['serial'] <= MAX_COUNT, '$.serial', 'not 0 to 2^31')
    _need(isinstance(doc['hosts'], list), '$.hosts', 'not a list')
    lines: dict[str, dict] = {}
    for i, line in enumerate(doc['hosts']):
        line = check_line(line, f'$.hosts[{i}]')
        _need(line['id'] not in lines and all(line['host_key'] != seen['host_key'] for seen in lines.values()),
              f'$.hosts[{i}]', 'a host id or host key already listed')
        lines[line['id']] = line
    return lines


def summary_line(line: dict) -> str:
    """`id tier owner power repos customer_ok facts hostkey-fp statuskey-fp invite` (X38, §14 #4, N02), '-' for none."""
    status = fingerprint(key_blob(line['status_key'], '$')) if line['status_key'] else '-'
    return ' '.join((line['id'], line['tier'], line['owner'], str(line['power']), ','.join(line['repos']) or '-',
                     'true' if line['customer_ok'] else 'false', ','.join(sorted(line['facts'])) or '-',
                     fingerprint(key_blob(line['host_key'], '$')), status, line.get('invite', '-')))


def summarize(new: dict[str, dict], last: dict[str, dict]) -> list[str]:
    """'new' or 'changed' and the summary, for each line of new that last lacks or holds otherwise; an unchanged
    line prints nothing."""
    return [f"{'changed' if id_ in last else 'new'} {summary_line(line)}" for id_, line in new.items()
            if last.get(id_) != line]


def _match(v: object, rx: re.Pattern[str], path: str) -> str:
    _need(isinstance(v, str) and rx.fullmatch(v), path, 'off-shape')
    return v


def check_install(data: bytes) -> dict:
    """install.json from its exact bytes (I01, the same shape as fleet/install/manifest.parse_install): the signer
    sees these values and no others."""
    doc = keys(load(data), '$', INSTALL_KEYS)
    _need(doc['kind'] == 'install', '$.kind', 'not install')
    _need(type(doc['serial']) is int and 0 <= doc['serial'] <= MAX_COUNT, '$.serial', 'not 0 to 2^31')
    when = _match(doc['valid_until'], UTC_TIME, '$.valid_until')
    try:
        datetime.datetime.strptime(when, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        raise Refused('$.valid_until', 'not a real time') from None
    _match(doc['source_head'], HEX40, '$.source_head')
    _match(doc['lock_sha256'], HEX64, '$.lock_sha256')
    for name in ('ps1', 'sh'):
        boot = keys(keys(doc['bootstrap'], '$.bootstrap', ('ps1', 'sh'))[name], f'$.bootstrap.{name}', BOOT_KEYS)
        _match(boot['sha256'], HEX64, f'$.bootstrap.{name}.sha256')
        _match(boot['blob'], HEX40, f'$.bootstrap.{name}.blob')
    kit = keys(doc['kit'], '$.kit', KIT_KEYS)
    _need(type(kit['serial']) is int and 0 <= kit['serial'] <= MAX_COUNT, '$.kit.serial', 'not 0 to 2^31')
    _match(kit['kit_json_sha256'], HEX64, '$.kit.kit_json_sha256')
    bundle = keys(doc['bundle'], '$.bundle', BUNDLE_KEYS)
    for name, rx in (('head', HEX40), ('tree', HEX40), ('url', URL), ('sha256', HEX64)):
        _match(bundle[name], rx, f'$.bundle.{name}')
    _need(type(bundle['size']) is int and 1 <= bundle['size'] <= MAX_BUNDLE, '$.bundle.size', 'not 1 to 2^30')
    return doc


def install_summary(doc: dict, owner_pub: bytes) -> list[str]:
    """One `name value` line per field the signer compares (I01): the bootstraps' sha256s, the fingerprint of the
    key the bootstraps bake, lock_sha256, the bundle's head, tree and sha256, the URL's host, serial, valid_until."""
    words = owner_pub.decode('ascii', 'replace').split()
    key = fingerprint(key_blob(' '.join(words[:2]), '$.owner_pub'))
    bundle = doc['bundle']
    return [f'{name} {value}' for name, value in (
        ('bootstrap-ps1', doc['bootstrap']['ps1']['sha256']), ('bootstrap-sh', doc['bootstrap']['sh']['sha256']),
        ('key', key), ('lock_sha256', doc['lock_sha256']), ('bundle-head', bundle['head']),
        ('bundle-tree', bundle['tree']), ('bundle-sha256', bundle['sha256']),
        ('url-host', URL.fullmatch(bundle['url'])[1]), ('serial', doc['serial']), ('valid_until', doc['valid_until']))]


def main_install(path: str, pub_path: str) -> int:
    """--install INSTALL_JSON OWNER_PUB: the install summary on stdout; exit 1 on a refused or unreadable file."""
    try:
        with open(path, 'rb') as f, open(pub_path, 'rb') as g:
            lines = install_summary(check_install(f.read()), g.read())
    except OSError as e:
        print(f'pin-summary: cannot read a file: {e.strerror}', file=sys.stderr)
        return 1
    except Refused as e:
        print(f'pin-summary: refused {path}: {e}', file=sys.stderr)
        return 1
    print('\n'.join(lines))
    return 0


def main(argv: list[str]) -> int:
    """pin-summary.py HOSTS_JSON [LAST_SIGNED_HOSTS_JSON] or --install INSTALL_JSON OWNER_PUB: the summary on stdout;
    exit 1 on a refused file."""
    if len(argv) == 4 and argv[1] == '--install':
        return main_install(argv[2], argv[3])
    if len(argv) not in (2, 3):
        print('usage: pin-summary.py HOSTS_JSON [LAST_SIGNED_HOSTS_JSON] | --install INSTALL_JSON OWNER_PUB',
              file=sys.stderr)
        return 2
    files = []
    for path in argv[1:]:
        try:
            with open(path, 'rb') as f:
                files.append(check_hosts(f.read()))
        except OSError as e:
            print(f'pin-summary: cannot read {path}: {e.strerror}', file=sys.stderr)
            return 1
        except Refused as e:
            print(f'pin-summary: refused {path}: {e}', file=sys.stderr)
            return 1
    for line in summarize(files[0], files[1] if len(files) > 1 else {}):
        print(line)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
