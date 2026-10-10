"""Stand-in for the one constant the vendored packer imports: a file name no closure may hold, at any depth."""
from __future__ import annotations

NEVER = ('gateway.json',)  # the gateway record is served behind an invite, never from a bundle
