"""The install bundle and its name audit (P+ I08, §16): a deterministic closure tar at the signed deploy head, in
the shape `verify-archive.py --closure` (ARCH2, I07) proves against the signed pin's tree.

The tar holds `mirrorstack-fleet-<head>/trees/<id>` (the raw body of each git tree on the path to a listed file) and
`files/<path>` (only the listed blobs, as git stored them). Members are sorted, mtime 0, owner 0, no folder entries,
and the format is plain GNU tar (no compression, whose bytes depend on the zlib), so two builds are byte-identical.
Tree bodies name every sibling of a listed path, so the names leak by design (I07): `names` lists them all for the
owner's one-time review, and a denylist the owner supplies flags the customer and contact strings among them."""
from __future__ import annotations

import io
import re
import tarfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from fleet.core.git import Git, GitError
from fleet.install.files import NEVER

_SHA1 = re.compile('[0-9a-f]{40}')
FILE_MODES = ('100644', '100755')
MAX_TAR = 1 << 28  # H3: a PC refuses a bundle.tar over 256 MiB (bootstrap.ps1 $BundleMax), narrower than manifest.MAX_BUNDLE, so no producer signs a bigger one


class BundleError(Exception):
    """A plain sentence on why no bundle was made."""


@dataclass(frozen=True)
class Closure:
    """head's commit and root tree, the tree bodies on the paths by id, and the listed blobs by path."""
    head: str
    tree: str
    trees: dict[str, bytes]
    files: dict[str, bytes]


def rows(body: bytes) -> dict[str, tuple[str, str]]:
    """A git tree body as {name: (mode, id)}; a row cut short is a BundleError."""
    out, i = {}, 0
    while i < len(body):
        nul = body.find(b'\0', i)
        if nul < 0 or nul + 21 > len(body):
            raise BundleError('a tree object is cut short')
        mode, _, name = body[i:nul].decode('utf-8', 'surrogateescape').partition(' ')
        out[name] = (mode, body[nul + 1:nul + 21].hex())
        i = nul + 21
    return out


def cut(repo: Path, head: str, paths: Sequence[str]) -> Closure:
    """The closure of paths at head: each folder's tree body down every path, each file's blob. A path that is
    missing, is not a plain file, is named NEVER or is unsafe, or a head that is not a full commit id, is refused."""
    if not _SHA1.fullmatch(head):
        raise BundleError('the head is a full 40-digit commit id')
    git = Git(repo)
    if not paths:
        raise BundleError('no file is listed')
    try:
        tree = git.run('rev-parse', f'{head}^{{commit}}', f'{head}^{{tree}}').decode().split()[1]
        trees, files = {tree: git.run('cat-file', 'tree', tree)}, {}
        for path in sorted(set(paths)):
            parts = path.split('/')
            if any(p in ('', '.', '..') or set(p) & set('\\:\0') for p in parts):
                raise BundleError(f'{path} is not a safe path')
            if parts[-1] in NEVER:
                raise BundleError(f'{parts[-1]} is never in the bundle')
            node = tree
            for i, part in enumerate(parts):
                last = i == len(parts) - 1
                mode, node = rows(trees[node]).get(part, ('', ''))
                if mode not in (FILE_MODES if last else ('40000',)):
                    raise BundleError(f'{path} is not a plain file in the tree of {head}')
                if not last and node not in trees:
                    trees[node] = git.run('cat-file', 'tree', node)
            files[path] = git.run('cat-file', 'blob', node)
    except GitError as e:
        raise BundleError(str(e)) from None
    return Closure(head, tree, trees, files)


def pack(c: Closure) -> bytes:
    """The closure tar: sorted members, mtime 0, uid and gid 0 with no names, mode 0644 (git, not the tar, says a
    file's mode; the verifier ignores it), no folder entries."""
    out = io.BytesIO()
    members = [(f'trees/{k}', v) for k, v in c.trees.items()] + [(f'files/{k}', v) for k, v in c.files.items()]
    with tarfile.open(fileobj=out, mode='w', format=tarfile.GNU_FORMAT) as tar:
        for name, body in sorted(members):
            info = tarfile.TarInfo(f'mirrorstack-fleet-{c.head}/{name}')
            info.size, info.mode, info.mtime = len(body), 0o644, 0
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            tar.addfile(info, io.BytesIO(body))
    if out.tell() > MAX_TAR:
        raise BundleError(f'the bundle is over {MAX_TAR} bytes, which every PC refuses')
    return out.getvalue()


def names(c: Closure) -> list[tuple[str, str]]:
    """Every name a helper can read in the closure, sorted: ('bundle', path) a listed file, ('dir', path) a folder
    whose tree is in it, ('sibling', path) any other row of those trees (a blob or folder whose name leaks, its
    content does not)."""
    out: list[tuple[str, str]] = []

    def walk(tree: str, prefix: str) -> None:
        for name, (mode, oid) in rows(c.trees[tree]).items():
            path = prefix + name
            if path in c.files:
                out.append(('bundle', path))
            elif mode == '40000' and oid in c.trees:
                out.append(('dir', path))
                walk(oid, path + '/')
            else:
                out.append(('sibling', path))

    walk(c.tree, '')
    return sorted(out, key=lambda row: (row[1], row[0]))


def words(denylist: str) -> list[str]:
    """The denylist's words: one per line, a leading BOM, blank and # lines skipped."""
    return [w.strip() for w in denylist.lstrip('\ufeff').splitlines() if w.strip() and not w.lstrip().startswith('#')]


def shown(text: str) -> str:
    """text for the owner's screen: a character that is not printable (a newline, an escape, a byte that is not
    UTF-8, kept as a lone surrogate) is written out as \\xNN or \\uNNNN, so a tree name cannot forge a line."""
    return ''.join(c if c.isprintable() else f'\\x{ord(c):02x}' if ord(c) < 256 else f'\\u{ord(c):04x}' for c in text)


def denied(listed: Sequence[tuple[str, str]], denylist: str) -> list[tuple[str, str]]:
    """(word, path) for each denylist word (one per line, blank and # lines skipped, case-folded) found in a name.
    The list is the owner's data: nothing here supplies one."""
    found = words(denylist)
    return [(w, path) for _, path in listed for w in found if w.casefold() in path.casefold()]
