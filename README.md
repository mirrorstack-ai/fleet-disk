# fleet-disk

Public, pinned build artifacts for the MirrorStack fleet: the converted Ubuntu noble L1 disk (a VHDX) and the
owner-signed install set (the `install-<serial>` releases).

## How a build runs

Actions, then `disk`, then Run workflow on `main` with the Ubuntu cloud image `serial` (for example `20260930` or
`20260930.1`). The job runs `bin/fleet-disk.py` on a GitHub-hosted runner with no secrets beyond the job's own token. It
fetches that image with Ubuntu's `SHA256SUMS` and `SHA256SUMS.gpg`, verifies them, converts the image with
`qemu-img`, publishes the VHDX as the release `disk-noble-<serial>` and prints the two lock entries (`disk_input` and
`disk`, each a url and a sha256). A release or tag that already exists is refused, and so is any
check that cannot be answered (fail closed); after the upload the published asset's digest is read back and must equal the
printed one. A signature stamped before the serial's date or in the future is refused. A VHDX of 2 GiB or more is refused (GitHub's
release asset limit).

## How an install set is released and verified

The release inputs are committed here by PR under `release/install-<serial>/`: `install.json` and `.sig`, `kit.json` and
`.sig`, the five kit files (`carrier-check.py`, `check.ps1`, `carrier-check.sh`, `verify-archive.py`, `VERIFY.txt`),
`deploy-pin.json` and `.sig`, `.gitattributes`, `bootstrap.ps1`, `bootstrap.sh` and, when the bundle is public, the bundle
(its name is the last part of the signed `bundle.url`, which must point at this very release). The signatures are made on
the owner's phone; nothing here holds a private key.

Actions, then `install`, then Run workflow on `main` with `serial` and `min_serial` (the lowest serial this publish may
carry, normally the previous release's). The job runs `bin/fleet-install-publish.py publish`, which refuses (exit 1,
`REFUSED <code>`, never a value) unless all of this holds, checked offline before gh is called:

- `install.json.sig` verifies with `ssh-keygen -Y verify -n mirrorstack-fleet-install -I owner` against
  `keys/owner-pin.pub` (the owner's one key line; the log prints its `SHA256:` fingerprint), and `install.json` has exactly
  the signed shape (`bin/fleet-install-publish.py` carries a vendored copy of the private repo's verifier and names the
  commit it copies);
- its `serial` is the folder's and at least `min_serial`, and `valid_until` is at least 30 days away;
- both bootstraps equal the signed sha256 and carry the signed git blob id, `kit.json` equals the signed
  `kit_json_sha256`, and `kit.json` and `deploy-pin.json` carry the owner's signature (namespace
  `mirrorstack-fleet-pin`); the five kit files equal `kit.json`, the bundle equals the signed sha256 and size;
- `deploy-pin.json` is present and no file in the folder is unlisted (a link or a folder is unlisted).

Then it refuses an existing tag or release `install-<serial>` (any check it cannot answer refuses too), requires GitHub's
**Immutable releases** setting (read through the API before the release is created), creates the release with exactly
those assets and reads GitHub's digests back: every asset must be there with the checked sha256, and nothing else.
`python3 bin/fleet-install-publish.py verify <dir> --owner-pub keys/owner-pin.pub --min-serial N` runs the offline half
alone (with `GITHUB_REPOSITORY` set). The owner's own check of a release is `VERIFY.txt`'s `ssh-keygen` line.

Immutable releases: the job's token usually cannot read the setting (it needs admin). Then the run stops with
`immutable-unreadable` until the owner records their confirmation as the Environment variable
`IMMUTABLE_RELEASES_CONFIRMED=yes` on `release`. A setting that reads as off always stops the run.

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

`python3 -m unittest discover -s tests` (stdlib only, no network, no qemu, no real gh; the signature tests use a throwaway
`ssh-keygen` key and are skipped when `ssh-keygen` is missing).
