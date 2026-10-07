"""Stand-in for the one time reader the vendored manifest imports: a UTC time like 2026-12-01T00:00:00Z."""
from __future__ import annotations

import re
from datetime import datetime, timezone

_UTC_TIME = re.compile('[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', re.ASCII)  # no fraction, no offset


def parse_utc(s: str) -> datetime:
    """The aware UTC time of s; ValueError if s is not one (an error never echoes the input)."""
    if not _UTC_TIME.fullmatch(s):
        raise ValueError('not a UTC time')
    return datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
