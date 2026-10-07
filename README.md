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
signed offline by the owner; nothing here holds a private key, and nothing here holds the owner's public key either (see below).

Actions, then `install`, then Run workflow on `main` with `serial` and `min_serial` (the lowest serial this publish may
carry, normally the previous release's). The job runs `bin/fleet-install-publish.py publish`, which refuses (exit 1,
`REFUSED <code>`, never a value) unless all of this holds, checked offline before gh is called:

- `install.json.sig` verifies with `ssh-keygen -Y verify -n mirrorstack-fleet-install -I owner` against
  the owner's public key (one `ssh-ed25519 <base64>[ comment]` line from the `release` environment, see "The owner's
  key" below; the log prints its `SHA256:` fingerprint), and `install.json` has exactly the signed shape
  (`bin/fleet-install-publish.py` carries a copy of the fleet's install manifest rules, schema version 1, and a test
  freezes its constants);
- its `serial` is the folder's and at least `min_serial`, and `valid_until` is at least 30 days away;
- both bootstraps are byte-exact release assets: ASCII, LF only, no CR, no BOM (`boot-bytes`), so the asset is the git
  blob and its blob id is the sha1 of the raw bytes only (no CRLF variant). The LF rule is enforced on the bootstrap
  assets themselves; `.gitattributes` stays an exact published copy of the fleet repo's own file (which sets
  `*.ps1 eol=crlf` for checkouts) and does not change that rule. Each bootstrap must also carry its baked values on one
  assignment line each (`$OwnerKey = '...'` and `$Expires = '...'` in the `.ps1`; `OWNER_KEY='...'` and `EXPIRES=...` in the `.sh`),
  exactly one line each with nothing after the value, and nothing else in the file (outside comment lines) may set either
  variable (a differently cased, scoped, indented or later assignment, `Set-Variable`, `read`, `export` and the like are
  refused; reading the variable is fine): the key must equal (type and base64) the owner key that verified
  `install.json`, and the expiry must have `valid_until`'s shape and be at least `valid_until` and at least 30 days from now
  (`baked`; the placeholders `ssh-ed25519 UNBAKED` and 1970 are refused);
- every asset is held to a size cap no larger than the bootstraps' own downloads: `install.json` 8192 bytes, each
  signature 4096, `kit.json` 65536, each kit file 4 MiB, `carrier-check.sh` 262144 (`size`); `kit.json`'s `python_zip`
  must be a `version` of the form `N.N.N` (one or two digits each) and a lowercase 64-hex `sha256` (`form`);
- both bootstraps equal the signed sha256 and carry the signed git blob id, `kit.json` equals the signed
  `kit_json_sha256`, and `kit.json` and `deploy-pin.json` carry the owner's signature (namespace
  `mirrorstack-fleet-pin`); the five kit files equal `kit.json`, the bundle equals the signed sha256 and size;
- `deploy-pin.json` is present with exactly `serial` (an integer), `head` and `tree` (40 hex) and, when the bundle is in
  the release, its `head` and `tree` equal the signed `bundle.head` and `bundle.tree` (`pin-mismatch`), and no file in the folder
  is unlisted (a link or a folder is unlisted); `.gitattributes` equals the constant committed in the script (it carries
  no signature); the folder is exactly `release/install-<serial>` with a canonical serial (no leading zeros);
- every file is read once into a private temporary copy, and the checks and the upload use that copy only.

Then it refuses an existing tag or release `install-<serial>` or any serial not above the newest existing `install-N`
release (`min_serial` stays an extra floor; any check it cannot answer refuses too), requires GitHub's
**Immutable releases** setting (read through the API before the release is created), creates the release with exactly
those assets and reads GitHub's digests back: every asset must be there with the checked sha256, and nothing else.
`python3 bin/fleet-install-publish.py verify <dir> --owner-pub <key file> --min-serial N` runs the offline half
alone (with `GITHUB_REPOSITORY` set). After the create it also requires the read-back release to say `immutable: true` and
`draft: false` (`immutable-not-set` otherwise), so the owner's variable is only an early stop.
The deploy pin names exactly the commit and tree the bundle was built from: when the release carries the bundle, the pin's
`head` and `tree` must equal `install.json`'s `bundle.head` and `bundle.tree` (`pin-mismatch` otherwise). Without the bundle
in the release the pin is only checked for shape and signature, not compared. The pin's `serial` is not compared here
(the PC's `verify-archive` enforces its own floor). The owner's own check of a release is `VERIFY.txt`'s `ssh-keygen` line.

Immutable releases: the job's token usually cannot read the setting (it needs admin). Then the run stops with
`immutable-unreadable` until the owner records their confirmation as the Environment variable
`IMMUTABLE_RELEASES_CONFIRMED=yes` on `release`. A setting that reads as off always stops the run.

## The owner's key

The key that verifies a release is not in this repo: a copy here would let a merged PR swap it. The owner sets it, once,
as the variable `OWNER_PIN_PUB` of the Environment `release` (Settings, Environments, `release`, Environment variables):
the whole public key line, `ssh-ed25519 <base64>` with an optional comment. The workflow writes it to a temporary file
only the job can read (mode 0600) and passes the path as `--owner-pub`. The script refuses `key` when the variable is
missing, is not exactly one such line, or, when the owner also sets `OWNER_PIN_SHA256` (the `SHA256:...` fingerprint from
`ssh-keygen -lf`), when the key's fingerprint differs. The run log prints the fingerprint of the key it used (`owner key
SHA256:...`): the owner compares it with their own key's. The bootstraps carry their own baked copy of the key; this
variable is only what the publisher checks the release against. `--owner-pub PATH` stays for running `verify` locally.

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
  reviewers if wanted. If it does not exist, GitHub creates it on the first run with no restriction. Put the owner's key
  in it (`OWNER_PIN_PUB`, see "The owner's key").
- A ruleset on `main` that requires pull requests.
- Settings, Releases, **Immutable releases** on.

## Tests

`python3 -m unittest discover -s tests` (stdlib only, no network, no qemu, no real gh; the signature tests use a throwaway
`ssh-keygen` key and are skipped when `ssh-keygen` is missing).

## Boot smoke

`.github/workflows/boot-smoke.yml` runs the two install bootstraps a PR carries (`release/install-<serial>/bootstrap.ps1`
and `bootstrap.sh`) on `windows-2022`, `windows-2025`, `ubuntu-24.04`, `ubuntu-22.04` and `macos-15`, with `contents: read`
and no secret. `tests/fixture/make_fixture.py` copies them, bakes a throwaway owner key into the copies with the
publisher's own regexes, points their base URLs (and the Windows Python ZIP URL) at `127.0.0.1` by pinned regexes, and writes one
signed release folder per case (good, expired, wrong key, tampered, rolled back, a downgrading redirect, and so on).
`tests/fixture/serve.py` serves them over HTTPS with a throwaway CA, and `tests/fixture/smoke_driver.py` runs each case
and checks the exit code, the last two lines, the info lines, the requests made and that no temp folder is left. The OS's
own curl must refuse the certificate before the trust step and accept it after (a control). The PR's files are never
changed; hosted runners are VMs, so this proves the pipeline, not hardware. `python3 tests/fixture/make_fixture.py --out DIR
--boot-dir release/install-<serial>` builds the tree by hand (it needs `ssh-keygen`, `openssl` and, on the Windows side,
network access to python.org for the ZIP, or `--python-zip PATH`).

The cases also cover each size cap (the signature, `install.json` with and without a `Content-Length`, `kit.json`, a kit file, the
ZIP), a wrong `kind`, a missing field, a six-file kit, and bad command lines (below the floor, a repeated or missing flag, an
abbreviated flag). Every runner but `ubuntu-22.04` (which refuses `os` by design) is run with `--must-run`, so a machine
refusal there fails the job instead of passing every case without a request. The throwaway certificates and CRL start an hour
before the build, so a runner clock a little slow still accepts them.

Fork pull requests run this workflow's code (from the PR) on hosted runners, including `sudo` and a trust-store change on the
Windows and macOS ones. It holds no secret and a read-only token, so the worst a hostile fork can do is spend runner minutes.
Keep that true in the repository settings: Actions > General > Fork pull request workflows, set "Require approval for all
outside collaborators", and leave "Send write tokens to workflows from pull requests" off.
