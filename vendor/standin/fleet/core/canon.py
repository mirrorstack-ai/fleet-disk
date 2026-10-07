"""Stand-in for the one strict-JSON reader the vendored manifest imports: strict JSON that is UTF-8 with no BOM, no NaN or
Infinity (nor a number like 1e400 that reads as one) and no duplicate key. Any refusal is a SchemaError."""
from __future__ import annotations

import json
import math


class SchemaError(ValueError):
    """A text that is not strict JSON; the text is never echoed."""

    def __init__(self, path: str, msg: str) -> None:
        super().__init__(path, msg)
        self.path, self.msg = path, msg


def loads_strict(text: str | bytes | bytearray) -> object:
    if not isinstance(text, (str, bytes, bytearray)):  # json.loads would take other types by its own rules
        raise SchemaError('$', 'not text')
    if isinstance(text, (bytes, bytearray)):  # json.loads would sniff UTF-16 or UTF-32 in either: only UTF-8 is read
        if text.startswith(b'\xef\xbb\xbf'):
            raise SchemaError('$', 'a byte order mark')
        try:
            text = text.decode('utf-8')
        except UnicodeDecodeError:
            raise SchemaError('$', 'not UTF-8') from None

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        obj: dict[str, object] = {}
        for key, value in items:
            if key in obj:
                raise ValueError('duplicate key')
            obj[key] = value
        return obj

    def constant(name: str) -> object:
        raise ValueError(name)

    def number(s: str) -> float:
        f = float(s)
        if not math.isfinite(f):
            raise ValueError('number too large')
        return f

    try:
        return json.loads(text, parse_constant=constant, parse_float=number, object_pairs_hook=pairs)
    except (ValueError, RecursionError):  # JSONDecodeError is a ValueError
        raise SchemaError('$', 'not strict JSON') from None
