# fleet-disk

Public, pinned build artifacts for the MirrorStack fleet: the converted Ubuntu noble L1 disk (a VHDX for Hyper-V, a qcow2 for Linux,
a zstd-compressed raw arm64 disk for vfkit on macOS) and the CI-signed install set (the `install-<serial>` releases).

## How a build runs

Actions, then `disk`, then Run workflow on `main` with the Ubuntu cloud image `serial` (for example `20260930` or
`20260930.1`). The job runs `bin/fleet-disk.py` on a GitHub-hosted runner with no secrets beyond the job's own token. It
fetches that image with Ubuntu's `SHA256SUMS` and `SHA256SUMS.gpg`, verifies them, converts the image with
`qemu-img` into a VHDX and into an uncompressed `compat=1.1` qcow2 (the Linux disk), publishes both as the release
`disk-noble-<serial>` and prints the three lock entries (`disk_input`, `disk` and `disk_qcow2`: a url and a sha256 each, and
the qcow2's size). A release or tag that already exists is refused, and so is any
check that cannot be answered (fail closed); after the upload the published assets' digests are read back and must equal the
printed ones. A signature stamped before the serial's date or in the future is refused. A VHDX or qcow2 of 2 GiB or more is
refused (GitHub's release asset limit).

## How the arm64 disk (macOS lane) is built

The same workflow with `arch` set to `arm64` runs `bin/fleet-disk.py arm64 <serial>` on the same runner (`qemu-img` only re-encodes the image
and executes none of it), through the amd64 build's shared steps (tag check, signed `SHA256SUMS`, image check, upload read-back). It adds:
the serial must be `ARM64_SERIAL` (20260926); the signed sha of `noble-server-cloudimg-arm64.img` must equal `ARM64_IMAGE_SHA256`; vfkit
v0.6.4 is fetched from upstream and must hash to `VFKIT_SHA256` and be exactly `VFKIT_SIZE` bytes (hashed only, never run or published); the raw
disk must be GPT with an EFI System Partition; `zstd -19` of it must expand to the same raw sha. The one asset of `disk-noble-arm64-<serial>`
is `noble-arm64-<serial>.raw.zst`; the printed entries are `disk_arm64_input`, `disk_arm64` (url, sha256, size, `raw_sha256`, `raw_size`) and
`vfkit` (version, url, sha256, size). Both sha constants are filled in the script; a different serial or vfkit release is a PR that changes them.
A wrong pin fails closed (`image-pin-mismatch` / `vfkit-mismatch`): the evidence is Ubuntu's signature on `SHA256SUMS` (checked with the pinned
key at build time) and the bytes upstream serves, and a pin that does not match them stops the build. The printed `vfkit` lock entry must get `cdhash` and `entitlements` added from a Mac before the owner signs it, because a Linux runner
has no `codesign`.

## How an install set is released and verified

The release inputs are committed in the fleet repository under `release/install-<serial>/` and reach this repo only through
that repository's `release` branch (a main to release pull request the owner merges): `install.json`, `kit.json`, the five kit
files (`carrier-check.py`, `check.ps1`, `carrier-check.sh`, `verify-archive.py`, `VERIFY.txt`), `deploy-pin.json`,
`.gitattributes`, `bootstrap.ps1` and `bootstrap.sh`, and no signature: CI makes those. The bundle is never part of a release
here: the signed `bundle.url` is the invite-gated kit host's download of this serial, and a bundle file in the folder is
refused as unlisted.

Actions, then `install`, then Run workflow on the `release` branch (the only ref the jobs accept) with `serial` and
`min_serial` (the lowest serial this publish may carry, normally the previous release's); `mode` pubkey only prints the
signing key's public line and fingerprint. Four jobs run in order:

- **plan** (Environment `release`, read-only deploy key `FLEET_READ` on the fleet repository, held in `/dev/shm` and wiped
  by a trap on every path) reads the folder from the fleet `release` tip as git blobs, never a checkout. It refuses unless the folder is exactly the files above as plain files, the
  serial fits the series (below), `KIT_HOST` is set, the key baked into both bootstraps has the fingerprint `KEY_SHA256`, and `install.json`'s
  `source_head` and the pin's `head` are on that branch with the pin's `tree` that commit's tree. It runs every check below
  but the signatures. The run summary shows the tree id, each file's blob id and sha256, `install.json` and
  `deploy-pin.json` verbatim, the tag to be created, the hashes of the fleet commits since the previous release's source
  and a `diff --stat` of `.github`, `bin` and `vendor` since the last `install-*` tag (hashes and public files only: these
  logs are public). When the previous release's `source_head` cannot be read or its range cannot be listed the summary says
  `UNKNOWN` and lists the newest 200 fleet commits, never an empty list. The three files to sign leave as base64 outputs with their sha256, the folder as an artifact.
- **sign** (Environment `release`, secret `SIGN_KEY`) runs no repository code and no third-party action. It keeps the key in
  `/dev/shm`, refuses unless `ssh-keygen -lf` of it equals the constant `KEY_SHA256` in `install.yml` (so it refuses while
  that is a placeholder), re-hashes the bytes against the plan's sha256, signs `install.json` (namespace
  `mirrorstack-fleet-install`), `kit.json` and `deploy-pin.json` (`mirrorstack-fleet-pin`), verifies each and wipes the key.
- **tag** (Environment `release`, deploy key `TAG_KEY`) pushes the lightweight tag `install-<serial>` on this run's commit.
- **publish** (no environment, no secret) adds the signatures to the plan's files and runs
  `bin/fleet-install-publish.py publish` with the sign job's public line as `--owner-pub`.

`publish` refuses (exit 1, `REFUSED <code>`, never a value) unless all of this holds, checked offline before gh is called:

- `install.json.sig` verifies with `ssh-keygen -Y verify -n mirrorstack-fleet-install -I owner` against
  the signing key's public line (one `ssh-ed25519 <base64>[ comment]` line from the sign job, held to `KEY_SHA256`, see
  "The signing key" below; the log prints its `SHA256:` fingerprint), and `install.json` has exactly the signed shape
  (the rules are `vendor/manifest.py`, a byte-identical copy of the fleet's install manifest verifier; see "The vendored
  verifier" below);
- the signed `bundle.url` is `https://<kit-host>/v1/kit/<serial>/bundle.tar` for this very serial and the host is not
  GitHub's (`github.com`, `githubusercontent.com` or a name below them), else `form`; and the host is exactly the constant
  `KIT_HOST` of `.github/workflows/install.yml`, else `kit-host` (the bootstrap sends a helper's invite code to that host,
  so which host it is a reviewed change to that file, like `KEY_SHA256`; plan and publish refuse `kit-host` while `KIT_HOST`
  is not a lowercase DNS name, and `verify` by hand holds the host only when `KIT_HOST` is set);
- its `serial` is the folder's and at least `min_serial`, and `valid_until` is at least 30 days away and at most 90 days
  (`SERIES=test`) or 180 days (`release`) away, else `long-validity` (the expiry is the only way a baked key stops being
  trusted, so a merged change cannot set it far out);
- both bootstraps are byte-exact release assets: ASCII, LF only, no CR, no BOM (`boot-bytes`), so the asset is the git
  blob and its blob id is the sha1 of the raw bytes only (no CRLF variant). The LF rule is enforced on the bootstrap
  assets themselves; `.gitattributes` stays an exact published copy of the fleet repo's own file (which sets
  `*.ps1 eol=crlf` for checkouts) and does not change that rule. Each bootstrap must also carry its baked values on one
  assignment line each (`$OwnerKey = '...'` and `$Expires = '...'` in the `.ps1`; `OWNER_KEY='...'` and `EXPIRES=...` in the `.sh`),
  exactly one line each with nothing after the value, and nothing else in the file (outside comment lines) may set either
  variable (a differently cased, scoped, indented or later assignment, `Set-Variable`, `read`, `export` and the like are
  refused; reading the variable is fine): the key must equal (type and base64) the owner key that verified
  `install.json`, and the expiry must have `valid_until`'s shape and be at least `valid_until` and at least 30 days from now
  (`baked`; the placeholders `ssh-ed25519 UNBAKED` and 1970 are refused) and no further out than the same 90 or 180 days
  (`long-validity`);
- every asset is held to a size cap no larger than the bootstraps' own downloads: `install.json` 8192 bytes, each
  signature 4096, `kit.json` 65536, each kit file 4 MiB, `carrier-check.sh` 262144 (`size`); `kit.json`'s `python_zip`
  must be a `version` of the form `N.N.N` (one or two digits each) and a lowercase 64-hex `sha256` (`form`);
- both bootstraps equal the signed sha256 and carry the signed git blob id, `kit.json` equals the signed
  `kit_json_sha256`, and `kit.json` and `deploy-pin.json` carry the owner's signature (namespace
  `mirrorstack-fleet-pin`); the five kit files equal `kit.json`;
- `deploy-pin.json` is present with exactly `serial` (an integer), `head` and `tree` (40 hex), its `head` and `tree`
  always equal the signed `bundle.head` and `bundle.tree` (`pin-mismatch`), and no file in the folder
  is unlisted (a link or a folder is unlisted); `.gitattributes` equals the constant committed in the script (it carries
  no signature); the folder is exactly `release/install-<serial>` with a canonical serial (no leading zeros);
- every file is read once into a private temporary copy, and the checks and the upload use that copy only.

The `SERIES` constant in `install.yml` decides which serials this key may carry: `test` below 1000, `release` 1000 and up
(`series` otherwise). Then it requires the tag `install-<serial>` to exist as a lightweight tag on this run's commit
(`tag-missing`, `tag-moved`; the tag job made it) and refuses a release of it (`tag-exists`) or any serial not above the
newest existing `install-N` release (`min_serial` stays an extra floor; any check it cannot answer refuses too), requires GitHub's
**Immutable releases** setting (read through the API before the release is created), creates the release with exactly
those assets and reads GitHub's digests back: every asset must be there with the checked sha256, and nothing else. The
release body and the run summary carry `key SHA256:<fingerprint>` and, for each OS, the line a helper pastes (the same text
the fleet makes for its `check` mode, pinned to this release's bootstrap sha256); helpers take lines from the release page.
`python3 bin/fleet-install-publish.py verify <dir> --owner-pub <key file> --min-serial N` runs the offline half
alone (no network, no gh, no repository variable). After the create it also requires the read-back release to say `immutable: true` and
`draft: false` (`immutable-not-set` otherwise), so the owner's variable is only an early stop.
The deploy pin names exactly the commit and tree the bundle was built from: its `head` and `tree` must equal
`install.json`'s `bundle.head` and `bundle.tree` (`pin-mismatch` otherwise), though the bundle itself is not in this
release. The pin may also not move back: when an `install-N` release exists, the publisher reads that newest release's
`deploy-pin.json` (`gh release download`, before anything is created) and refuses `pin-mismatch` if this pin's `serial` is
lower, or if that previous pin cannot be read or is not a pin (a floor that cannot be read is no floor). The PC has no pin
floor of its own, so this is one of the bounds on a pin rollback. The previous pin is that release's own asset (immutable,
made by this publisher after it verified the signature), so it is not verified again, which keeps a key change possible.
Not enforced here: that a first release under a new owner key follows a
published handoff from the old key (a new key starts a new series instead: a serial-floor jump). The owner's own check of a
release is `VERIFY.txt`'s `ssh-keygen` line.

Immutable releases: the job's token usually cannot read the setting (it needs admin). Then the run stops with
`immutable-unreadable` until the owner records their confirmation as the Environment variable
`IMMUTABLE_RELEASES_CONFIRMED=yes` on `release` (the plan job passes it on to publish). A setting that reads as off always stops the run.

## The signing key

The key is a secret of the Environment `release` (`SIGN_KEY`, an unencrypted ssh-ed25519 private key), read by the sign job
only. Its fingerprint is the constant `KEY_SHA256` in `.github/workflows/install.yml`, so which key signs is a reviewed
change to a file on the `release` branch, never a setting; the sign job refuses `key-not-set` while it is not an `SHA256:`
fingerprint and `key` when the secret's differs. The public key is not in this repo: the sign job prints it (`mode` pubkey,
or the output `pub`) and the publisher takes it as `--owner-pub PATH`, refusing `key` unless the file is exactly one such
line whose fingerprint equals `OWNER_PIN_SHA256` (the workflow sets it from the constant; `verify` may run without it).
The run log prints the fingerprint of the key it used (`owner key SHA256:...`). The bootstraps carry their own baked copy
of the key, which the plan job holds to the same constant.

## The vendored verifier

`vendor/manifest.py` is the install.json verifier, copied byte for byte from the fleet's own repository; `vendor/manifest.sha256`
holds its sha256 (one lower-case hex line and a newline), and the fleet repository pins the same hash. The publisher loads
that file at start and stops with `REFUSED form` unless the hash matches, so the rules it applies are exactly the copy's, never
a second implementation. The copy imports two helpers (a strict JSON reader and a UTC time reader); `vendor/standin/` answers
those imports without changing a byte of the copy. They decide how strict the copy's rules are, so `vendor/standin.sha256`
pins them too (one hash over the four files, in the order and form `stand_in_digest` in the script says), and the bytes
that were hashed are the ones executed. The UTC reader is deliberately stricter than the fleet's (no fractional seconds).
`.gitattributes` marks the vendored files `-text` so no checkout rewrites their line endings.
A change to the verifier ships as the same two files in both repositories, in the same step: the fleet
repository's `bin/fleet-install.py vendor-sync <this checkout>` says `OK vendor-sync` when the copy and both pins agree.

## The vendored packer and the kit uploader

The install bundle (a deterministic tar of the listed files at the signed head, never part of a release here) is served by the
invite-gated kit host, so something has to put it there. `bin/fleet-kit-upload.py` does, from the kit job of `install.yml`, and
holds no Cloudflare key: the host takes a request only when it carries an Ed25519 signature of the *upload* role, made with
`openssl pkeyutl -rawin` over `kit-admin-v1\n<role>\n<ts_ms>\n<METHOD>\n<path>\n<sha256hex(body)>` (header
`Authorization: KitAdmin upload.<ts_ms>.<base64url signature>`, plus `X-Kit-Sha256` with the body's hash). `KIT_UPLOAD_KEY` lives
in a 0600 file on tmpfs for the length of the run and is overwritten and removed at the end.

- `fleet-kit-upload.py bundle <dir> --owner-pub P` checks `<dir>/install.json` (the vendored verifier, the owner's signature,
  the bundle url is this host's for this serial), shallow-fetches the commit `bundle.head` with the runner's read-only deploy
  key, reads `fleet/install/closure.txt` at that commit (a list of paths: data, so no code of the other repository runs here),
  builds the tar with the vendored packer and refuses unless its size, sha256, head and tree equal install.json
  (`REFUSED bundle-hash <field>`). Only then it does `PUT /_k/file/<serial>/bundle.tar` and requires the host's answer
  (`{"sha256", "size"}`) to equal what it sent. An identical re-run is a 200; different bytes for the same serial are a 409.
- `fleet-kit-upload.py gateway --owner-pub P` reads `fleet/core/gateway.json` and `.sig` from the tip of the fleet `release`
  branch, checks the owner's signature under namespace `mirrorstack-fleet-pin`, and `POST /_k/gateway/<serial>` with both files in
  one request, so the host flips to the pair whole or not at all. These two files never enter the release folder.
- This repository is public, so nothing a build holds is printed: git's stderr and the build's output go to a file in
  `RUNNER_TEMP`, an error names the rule and never a value, and there is no stack dump. The log shows a size and a sha256 only.

`vendor/bundle.py` is the fleet repository's `fleet/install/bundle.py` byte for byte, pinned by `vendor/VENDORED.sha256` (one
lower-case hex line and a newline; the manifest copy keeps its own `vendor/manifest.sha256`). It imports two modules of the fleet,
a git boundary and one constant; `vendor/standin-bundle/` answers those imports, pinned by one hash over its five files
(`vendor/standin-bundle.sha256`, same form as `standin.sha256`). The uploader stops with `REFUSED vendor` unless every hash
matches, and runs the bytes it hashed. The stand-in git module is the fleet's with one difference: an error never carries git's
stderr. `.gitattributes` marks all of it `-text`. A change to the packer ships as the same file and the same pin in both
repositories, in the same step. `tests/test_kit_upload.py` freezes the packer's output against a golden sha256 on every Python
the tests run on.

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

The workflows' `if: github.ref == ...` lines are an accident guard, not a boundary (a dispatched run uses its own
ref's workflow file). The real boundary is set in the repo, not in code:

- Create the Environment `release` first (Settings, Environments), restricted to the `release` branch with admins unable to
  bypass, and put `SIGN_KEY`, `TAG_KEY` and `FLEET_READ` in it. The disk build has its own Environment `disk`
  (restricted to `main`), so nothing about `release` gates or reaches it.
- Rulesets: `release` takes pull requests from `main` only; the tags `install-*` only the `TAG_KEY` deploy key may create.
- A ruleset on `main` that requires pull requests.
- Settings, Releases, **Immutable releases** on.

## Test-phase keys (keygen)

`.github/workflows/keygen.yml` is test-grade and is never used for R, the real release key. One dispatch on `main` makes three
ed25519 keys inside a GitHub-hosted job, in tmpfs: `SIGN_KEY` (T, the test signing key), `TAG_KEY` (the test-phase `install-*`
tag deploy key) and `FLEET_READ` (the read-only deploy key on mirrorstack-fleet). Each private half is sealed to the public key
of the Environment `release` (libsodium sealed box, PyNaCl installed with `--require-hashes`) and the job prints only the sealed
values, the public lines and the fingerprints (`KEYGEN-SEALED`, `KEYGEN-PUBLIC`, `KEYGEN-FINGERPRINT`) and the recipient
key it sealed to (`KEYGEN-RECIPIENT`, public). The plaintext never
leaves the runner, and the job has no token, no environment and no secret.

1. Read the environment's public key: `gh api repos/mirrorstack-ai/fleet-disk/environments/release/secrets/public-key`.
2. Dispatch: `gh workflow run keygen.yml --ref main -f public_key=<key> -f key_id=<key_id>`, and note the run id and the
   commit of `keygen.yml` that was reviewed.
3. `bin/fleet-keygen-put.py --run <id> --sha <commit> --dry-run`, then again without `--dry-run`. The public key is a free
   input of the workflow, so the helper does not trust the run: it fetches the log itself and refuses unless the run is
   `keygen.yml`, a `workflow_dispatch` on `main`, successful, at exactly `<commit>`, and its `KEYGEN-RECIPIENT` line (key_id
   and key) equals what the environment's public-key endpoint returns now. It also refuses anything that is not exactly three
   sealed boxes of the right length. Racing a `gh run list` is therefore safe: a wrong run is refused, not used.
4. The helper prints the verified `KEYGEN-PUBLIC` and `KEYGEN-FINGERPRINT` lines; the deploy-key settings and the bake step
   take the public halves from that output, never from a separate look at the log.

The verified public lines go to the deploy-key settings and the fingerprint into `install.yml` later.

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
