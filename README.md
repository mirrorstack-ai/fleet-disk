# fleet-disk

Public, pinned build artifacts for the MirrorStack fleet: the converted Ubuntu noble L1 disk (a VHDX).

## How a build runs

Actions, then `disk`, then Run workflow on `main` with the Ubuntu cloud image `serial` (for example `20260930` or
`20260930.1`). The job runs `bin/fleet-disk.py` on a GitHub-hosted runner with no secrets beyond the job's own token. It
fetches that image with Ubuntu's `SHA256SUMS` and `SHA256SUMS.gpg`, verifies them, converts the image with
`qemu-img`, publishes the VHDX as the release `disk-noble-<serial>` and prints the two lock entries (`disk_input` and
`disk`, each a url and a sha256). A tag that already exists is refused; a VHDX of 2 GiB or more is refused (GitHub's
release asset limit).

## Trust model

- The script trusts only Ubuntu's signature on `SHA256SUMS`, made by the Ubuntu cloud-image signing key pinned in the
  script by its full fingerprint. Expired, revoked or bad signatures, and any other key, are refused.
- The image must match the signed sha256 and be a qcow2 file before it is converted.
- This repo is not trusted by itself. The owner pins both sha256s in the fleet's lock file and signs it; a consumer
  accepts a download only if its sha256 matches that signed pin.
- A release is immutable once pinned. Never edit or replace its asset; build a new serial instead.

## Tests

`python3 -m unittest discover -s tests` (stdlib only, no network, no qemu).
