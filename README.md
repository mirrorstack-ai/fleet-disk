# fleet-disk

Public, pinned build artifacts for the MirrorStack fleet: the converted Ubuntu noble L1 disk (a VHDX).

## How a build runs

Actions, then `disk`, then Run workflow on `main` with the Ubuntu cloud image `serial` (for example `20260930` or
`20260930.1`). The job runs `bin/fleet-disk.py` on a GitHub-hosted runner with no secrets beyond the job's own token. It
fetches that image with Ubuntu's `SHA256SUMS` and `SHA256SUMS.gpg`, verifies them, converts the image with
`qemu-img`, publishes the VHDX as the release `disk-noble-<serial>` and prints the two lock entries (`disk_input` and
`disk`, each a url and a sha256). A release or tag that already exists is refused, and so is any
check that cannot be answered (fail closed); after the upload the published asset's digest is read back and must equal the
printed one. A signature stamped before the serial's date or in the future is refused. A VHDX of 2 GiB or more is refused (GitHub's
release asset limit).

## Trust model

- The script trusts only Ubuntu's signature on `SHA256SUMS`, made by the Ubuntu cloud-image signing key pinned in the
  script by its full fingerprint. Expired, revoked or bad signatures, and any other key, are refused.
- The image must match the signed sha256 and be a qcow2 file before it is converted.
- This repo is not trusted by itself. The owner pins both sha256s in the fleet's lock file and signs it; a consumer
  accepts a download only if its sha256 matches that signed pin.
- A release is meant to be immutable once pinned. Never edit or replace its asset; build a new serial instead. The
  script never overwrites a tag, but only the repo's **Immutable releases** setting stops a writer from replacing an
  asset or moving a tag: it must be on before the first publish and covers only releases created after it is on.

## One-time repo settings

The workflow's `if: github.ref == 'refs/heads/main'` is an accident guard, not a boundary (a dispatched run uses its own
ref's workflow file). The real boundary is set in the repo, not in code:

- Create the Environment `release` first (Settings, Environments), restricted to the `main` branch, with required
  reviewers if wanted. If it does not exist, GitHub creates it on the first run with no restriction.
- A ruleset on `main` that requires pull requests.
- Settings, Releases, **Immutable releases** on.

## Tests

`python3 -m unittest discover -s tests` (stdlib only, no network, no qemu).
