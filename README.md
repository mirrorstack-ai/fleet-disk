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
check that cannot be answered (fail closed). The release is created as a draft: its assets' digests are read back by release id
(up to four reads, five seconds apart) and the draft is made public only when they equal the hashed files, so nothing
irreversible comes before the last check that can refuse. A digest GitHub has not computed yet is retried and then refused as
`publish-unread`; a wrong digest or asset set is `publish-mismatch` at once. Both delete the draft first. A refusal after the
PATCH was sent (the release may be public; the second read must show it published with the same digests) prints `unverified <asset> sha256:<hex>`
lines to stderr: those are the hashed values, not verified entries, so do not pin from them. A signature stamped before the
serial's date or in the future is refused. A VHDX or qcow2 of 2 GiB or more is refused (GitHub's release asset limit).

A draft that an interrupted run left (a cancelled job, the upload's time limit) makes the next dispatch for that serial refuse
`draft-left`, apart from `tag-exists` (a published release or a tag). The workflow's last step always runs
`bin/fleet-disk.py cleanup <arch> <serial>`, which deletes that tag's draft and nothing else (a published release, or a
draft of another tag, is never deleted); if it cannot, delete the draft by hand under the repository's Releases (writers see
drafts there). A draft never made a tag, so deleting it should free the serial (a GitHub behaviour to measure once on a scratch repository
with Immutable releases before the first real dispatch). The cleanup step runs after every build, green ones too, and exits 1
when it cannot read the release list (only the newest 100 releases are read): a red last step after a green build step means
the build result stands, so look for a leftover draft. It also deletes a draft that a PATCH exiting 0 left reading as a draft on every
read of the build step, if its own read still shows a draft then (GitHub reads are normally consistent).

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

## Pinning a disk release

`bin/fleet-disk.py pin [amd64|arm64] <serial>` is the one way to get the lock entries for a PR, in place of copying them from a
run's log. It is read-only (every call is a plain GET through `gh api`, nothing is created, changed or deleted), needs no token
beyond the login `gh` already has (`GH_TOKEN`, `HOME`, `GH_CONFIG_DIR` and `XDG_CONFIG_HOME` are passed on when set; the repository
is `GITHUB_REPOSITORY` or this one), and runs where the build's tools are (`gh`, `gpgv` with the Ubuntu cloud-image keyring, and
`zstd` for arm64, at the same paths). It reads the published release of `disk-noble-<serial>` (or `disk-noble-arm64-<serial>`),
takes the commit the release names (`target_commitish`, which must be a 40-hex sha, the `--target` the build passed), and asks
`compare/main...<sha>`: only `behind` or `identical` (the commit is on `main`) goes on. It then reads the run record of
`disk.yml` (`actions/workflows/disk.yml/runs?head_sha=<sha>&event=workflow_dispatch&status=success`) and goes on only if a
completed, successful `workflow_dispatch` run on branch `main` at exactly that sha exists, the release's author and every asset's
uploader are `github-actions[bot]` (a person's `gh release create` carries their own login), and the release's publication and every
asset's upload fall inside that run's `created_at` to `updated_at` (30 seconds of slack; the release's own `created_at` is its commit's
date, so it is not compared). It then prints the same entries, in the
same form, as the build: the signed upstream sum is re-read through the build's own `gpgv` check, the asset digests and sizes
come from a second read of the release that must equal the first, and for arm64 the asset's bytes are downloaded and must hash
to GitHub's digest, are expanded with `zstd`, and the expanded disk's sha256 and size are measured here (vfkit's upstream bytes are
re-checked too). Nothing is printed that was not read in that run. The words it refuses with, on stderr, with no stdout and exit 1:

- `pin-not-main`: the compare says `ahead` or `diverged`, or any answer that is not `behind` or `identical`; or there is no such
  run (a dispatch of a branch, a push, a failed or other-commit run, or one whose window does not hold the release), or the
  release or an asset was made by someone other than the bot.
- `pin-unread`: any read fails (a nonzero exit, a timeout, not JSON, a tool missing), the release is not exactly one published
  release with the expected assets and a `sha256:` digest and size each, `target_commitish` is not a 40-hex sha (a branch name
  is never compared), the compare answer has no `status`, the run list is not a list, or the release has no author, publication
  time, or an asset with an uploader and creation time.
- `pin-mismatch`: two reads of the release disagree, an asset's bytes are not the digest GitHub lists, or the signed arm64 image is
  not `ARM64_IMAGE_SHA256`.

What it proves is that the release names a commit that is on `main`, that a successful `disk.yml` dispatch on `main` ran at that
commit, and that the bot published the release and uploaded its assets while that run was going. It cannot tell the run's own
release from one that another job of the same bot made at that commit in that window (and a person with a token for the bot is
beyond it), so the owner's signature over the lock and the ruleset on `refs/tags/disk-*` remain the other two walls.

## How an install set is released and verified

The release inputs are committed in the fleet repository under `release/install-<serial>/` and reach this repo only through
that repository's `release` branch (a main to release pull request the owner merges): `install.json`, `kit.json`, the five kit
files (`carrier-check.py`, `check.ps1`, `carrier-check.sh`, `verify-archive.py`, `VERIFY.txt`), `deploy-pin.json`,
`.gitattributes`, `bootstrap.ps1` and `bootstrap.sh`, and no signature: CI makes those. The bundle is never part of a release
here: the signed `bundle.url` is the invite-gated kit host's download of this serial, and a bundle file in the folder is
refused as unlisted.

Actions, then `install`, then Run workflow on the `release` branch (the only ref the jobs accept) with `serial` and
`min_serial` (the lowest serial this publish may carry, normally the previous release's); `mode` pubkey only prints the
signing key's public line and fingerprint, `mode` floor runs only the floor job, `mode` untag only the three untag jobs and `mode` pins only the four pins jobs (all below). Seven jobs run in order:

- **plan** (Environment `release`, read-only deploy key `FLEET_READ` on the fleet repository, held in `/dev/shm` and wiped
  by a trap on every path) reads the folder from the fleet `release` tip as git blobs, never a checkout. It refuses unless the folder is exactly the files above as plain files, the
  serial fits the series (below), `KIT_HOST` is a valid host, the key baked into both bootstraps has the fingerprint `KEY_SHA256`, and `install.json`'s
  `source_head` and the pin's `head` are on that branch with the pin's `tree` that commit's tree. It runs every check below
  but the signatures. The run summary shows the tree id, each file's blob id and sha256, `install.json` and
  `deploy-pin.json` verbatim, the tag to be created, the hashes of the fleet commits since the previous release's source
  and a `diff --stat` of `.github`, `bin` and `vendor` since the last `install-*` tag (hashes and public files only: these
  logs are public). When the previous release's `source_head` cannot be read or its range cannot be listed the summary says
  `UNKNOWN` and lists the newest 200 fleet commits, never an empty list. The three files to sign leave as base64 outputs with their sha256, the folder as an artifact.
- **fixture** (no Environment, no secret, `permissions: {}`, `ubuntu-24.04`) downloads the artifact `loaders` and runs
  `tests/fixture/make_fixture.py` once, on ubuntu, as the fixture job of `boot-smoke.yml` does, then uploads the tree as the
  artifact `fixture`. The plan's `loaders` step reads `bootstrap.sh` and `bootstrap.ps1` from the tip with `git show` (the LF
  blobs; the checked-out ps1 is CRLF) and uploads only those two as the artifact `loaders` (they become public release assets
  anyway; ledger D317). A missing or empty loader fails the plan. Building the fixture on every leg was refused on `macos-15`
  (`REFUSED tool`) and on both Windows legs (`REFUSED verify`), run 38633686710, so no leg builds it.
- **smoke** (needs plan and fixture; no Environment, no secret, `permissions: {}`, hosted runners) downloads the artifact `fixture` and
  runs the boot smoke (below) over the release tip's two loaders on `windows-2022`, `windows-2025`, `ubuntu-24.04`, `ubuntu-22.04`
  and `macos-15`, before anything is signed: `sign` and every job after it need it, so a red smoke (or a failed fixture, which skips
  it) stops the release.
- **sign** (Environment `release`, secret `SIGN_KEY`) runs no repository code and no third-party action. It keeps the key in
  `/dev/shm`, refuses unless `ssh-keygen -lf` of it equals the constant `KEY_SHA256` in `install.yml` (so it refuses while
  that is a placeholder), re-hashes the bytes against the plan's sha256, signs `install.json` (namespace
  `mirrorstack-fleet-install`), `kit.json` and `deploy-pin.json` (`mirrorstack-fleet-pin`), verifies each and wipes the key.
- **kit** (Environment `release`, secrets `FLEET_READ` and `KIT_UPLOAD_KEY` and nothing else) runs `bin/fleet-kit-upload.py`
  three times: `gateway --check` judges the gateway pair at the fleet `release` tip before anything is stored (no upload, so a
  bad pair leaves no bundle behind on the write-once host), `bundle` rebuilds the tar from the fleet commit `install.json`
  names and uploads it, `gateway` reads the gateway record and its signature from the tip again, checks the owner's signature
  and uploads the pair, or, while no gateway is live (the placeholder record: serial 0, address null, and no `.sig` beside it),
  prints `SKIP gateway not-live` and uploads nothing (ledger D309), so a first test release can be published before a gateway
  exists. Any other state without a good signed pair is still `REFUSED gateway` or `REFUSED sig`. The install.json it works
  from is the plan's output re-hashed against the plan's sha256, with the sign job's signature, so nothing here is downloaded.
  The job uploads no artifact, uses no cache and writes no step summary; the log shows a size and a sha256 only. The gateway pair
  is never in the plan's folder, which becomes a public artifact and public release assets.
- **tag** (Environment `release`, deploy key `TAG_KEY`) pushes the lightweight tag `install-<serial>` on this run's commit. It
  needs kit, and so does publish: no tag or release page can exist for a bundle the host cannot serve. A failed upload is a re-run.
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

The plan job makes the same read-only checks before anything is signed, stored on the kit host or tagged (after its offline
ones and before it writes the bytes to sign): a published release of the tag (`tag-exists`), a leftover draft of any install
tag (`draft-left`), the tag on another commit or not a lightweight commit tag (`tag-moved`; an absent tag is fine, the tag job
makes it), a serial not above the newest release (`not-newer`), a pin below that release's (`pin-mismatch`), the Immutable
setting off or unreadable without the owner's confirmation (`immutable-off`, `immutable-unreadable`), and a missing
`GITHUB_REPOSITORY`, `GITHUB_SHA` or `GH_TOKEN` (`release-env`). `publish` makes them again as the final authority. The plan
only reads: it creates and deletes nothing.

What plan guarantees is `tag-exists`, `tag-moved`, `not-newer`, `pin-mismatch` and the Immutable checks. `draft-left` is only
certain in `publish`: GitHub generally shows draft releases only to a token with write access, the plan job's token is
`contents: read` and is not widened for this, so a leftover draft may pass plan and be first named by `publish`, after sign,
kit and tag. That stops before the create, so nothing irreversible has happened, but it is a re-run after the delete. To
measure once at the first real run, on a scratch repository with Immutable releases, before relying on plan to stop a draft
early: whether `gh release list` under a `contents: read` token lists a draft of the repository; whether GitHub reports
`immutable: false` for a moment on a release that later becomes immutable (the publisher deletes on the first read that says
`false`; if it flips late, delete only after a second read).

Because a release cannot be changed once it is immutable, every refusal comes before the first irreversible step, and what a
failed publish leaves is named and, when it is safe, removed. When `gh release create` fails or is killed, or the read-back
says `draft: true` or `immutable: false` (exactly those), the publisher lists the releases and runs
`gh release delete <tag> --yes` for the release of exactly this tag (never with `--cleanup-tag`: the tag job's tag stays), then
gives the first refusal. An immutable published release is never deleted. The read-back of the created release is read up to
three times (5 s, then 15 s apart), only while an answer does not parse; a parsed answer is judged at once. If the delete
fails, or a release is there that cannot be deleted or read, the word is `release-left` and the first refusal is printed on
stderr (`first refusal <word>`).

| word | state | cure |
|---|---|---|
| `draft-left` | a draft of an install tag exists (a run's upload was killed before it was public) | a repo writer runs `gh release delete install-<n> --yes` (the tag stays), then re-runs |
| `release-left` | a release of the tag exists and the publisher could not read, judge or remove it | read the release page; if it is immutable and right, the serial is used: take the next one; a draft or mutable one: `gh release delete install-<n> --yes`, then re-run |
| `tag-exists` | a published release of the tag exists | read the release page; if it is immutable and right, the serial is used |
| `tag-moved` | the tag is on another commit, or not a lightweight commit tag, and has no release | a tag on another commit: `mode` untag with this `serial` removes it (see **Untag**); an annotated or other tag object, which untag refuses, the deploy key deletes by hand |
| `not-newer` | a release of this or a higher serial exists | dispatch the next serial |
| `pin-mismatch` | the pin's serial is below the newest release's, or that pin cannot be read | fix the pin or the serial in the release folder |
| `immutable-off`, `immutable-unreadable` | the Immutable releases setting is off, or the token cannot read it and `IMMUTABLE_RELEASES_CONFIRMED` is not `yes` | turn it on, or record the confirmation |
| `immutable-not-set` | the created release did not read back immutable and not a draft; it was deleted when it was a draft or mutable | turn the setting on, re-run |
| `publish-mismatch` | the read-back release is immutable and its assets are not the checked ones | the serial is used and the release stays: take the next serial |

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
The publisher refuses a signed `bundle.size` over 90 MB (`REFUSED kit-host-size`, from `plan` on): the host takes a bundle in one
request and its Free plan's request body is 100 MB. `KIT_HOST` is `fleet-kit.mirrorstack-fleet.workers.dev` (the production kit
Worker, set 2026-10-11 by D305); `plan`, `kit` and `publish` still refuse `kit-host` for any other host or a non-DNS name.

**Floor.** `mode` floor with `floor` set to a serial makes the host serve no serial below it, the break-glass for a bad
release. It is two jobs. `floor-approve` runs in the Environment `kit-floor` (restricted to `release`, the owner as required
reviewer, admins unable to bypass, no secret), checks the value is digits and prints it; the owner approves that run, whether it
raises the floor, lowers it or sets 0 (which lifts it). `floor` needs it, runs in the Environment `release` with `KIT_UPLOAD_KEY`
(a sealed secret cannot move between Environments, so the key stays) and runs the `floor` verb of the uploader, which needs no fleet
repository and no owner key. The approval exists only once `kit-floor` is made with that reviewer (One-time repo settings): until
then a dispatch on `release` runs unattended, and the `release` Environment itself has no reviewer (the plan, sign, kit and tag jobs
would otherwise each wait for one). A floor run shares no concurrency group with the release runs, so it never waits behind one;
the dashboard variable `KIT_FLOOR` stays the fastest break-glass.

**Untag.** `mode` untag with `serial` set to N removes the tag `install-N` of a run that stopped after the tag job and before the release was made (a
failed publish leaves such a tag; the serial is otherwise usually lost, only a re-run of all jobs with unchanged bundle bytes recovers it), and only a tag that has no release. It is three jobs, in the same concurrency group as a release run. `untag-check` has no
Environment and no secret, only the job token with `contents: read`: it runs the read-only verb `untag-check --serial N` of the publisher, which refuses
`tag-missing` (no such tag), `tag-moved` (the tag is not a lightweight commit tag), `tag-exists` or `draft-left` (any release of the tag, published or draft,
exists: it has a release, so it is not removed; a read-only token may not see a draft, so `draft-left` is only certain once a writer has checked the
releases page) and otherwise prints `tag install-N sha <sha>, no release` and hands the commit id on. `untag-approve` waits in the Environment `kit-floor`
(the owner is its required reviewer, it holds no secret and no token) and prints `approved: delete tag install-N at <sha>`. `untag` needs both, runs in the
Environment `release`, reads only `TAG_KEY` (the deploy key that makes the tag, the one bypass of the `install-*` tag ruleset) and runs no repository code and
holds no token: it deletes with `git push --force-with-lease=refs/tags/install-N:<sha>` of the empty source, so only a tag still on the checked commit goes (a tag that
moved after the check is left). The release check is made once, in `untag-check`: `untag` does not read the releases again after the approval wait, so a release
made by hand between the check and the approval is not seen (the `install` concurrency group stops another install run, not a repository writer). Turn the `kit-floor` required reviewer on first (One-time repo settings): without it nothing stops an untag run. Not yet
measured (the first dispatch shows both): that the ruleset's bypass covers a deletion, and that GitHub refuses to delete a tag an immutable release holds (the
check already refuses such a tag); the first real dispatch should also confirm that GitHub refuses the tag delete when a release holds the tag.

`.gitattributes` marks the vendored files `-text` so no checkout rewrites their line endings.
A change to the verifier ships as the same two files in both repositories, in the same step: the fleet
repository's `bin/fleet-install.py vendor-sync <this checkout>` says `OK vendor-sync` when the copy and both pins agree.

## The vendored packer and the kit uploader

The install bundle (a deterministic tar of the listed files at the signed head, never part of a release here) is served by the
invite-gated kit host, so something has to put it there. `bin/fleet-kit-upload.py` does, from the kit job of `install.yml`, and
holds no Cloudflare key: the host takes a request only when it carries an Ed25519 signature of the *upload* role, made with
`openssl pkeyutl -rawin` over `kit-admin-v1\n<role>\n<ts_ms>\n<METHOD>\n<path>\n<sha256hex(body)>` (header
`Authorization: KitAdmin upload <ts_ms> <128 lower-case hex of the signature>`, plus `X-Kit-Sha256` with the body's hash; the
host's own README, "Admin calls", is the contract). `KIT_UPLOAD_KEY` lives in a 0600 file on tmpfs for the length of the run and
is overwritten and removed at the end; it is taken out of the process environment at the start, so git, ssh-keygen and openssl
never inherit it. `OWNER_PIN_SHA256` is required for both verbs (`REFUSED key` without it). The third verb, `floor N` (`PUT /_k/floor`, read back, `REFUSED readback` unless the host says that floor), needs neither of them.

- `fleet-kit-upload.py bundle <dir> --owner-pub P` checks `<dir>/install.json` (the vendored verifier, the owner's signature,
  the bundle url is this host's for this serial), shallow-fetches the commit `bundle.head` with the runner's read-only deploy
  key, reads `fleet/install/closure.txt` at that commit (a list of paths: data, so no code of the other repository runs here),
  builds the tar with the vendored packer and refuses unless its size, sha256, head and tree equal install.json
  (`REFUSED bundle-hash <field>`). Only then it does `PUT /_k/file/<serial>/bundle.tar` and requires the host's answer
  (`{"sha256", "size"}`, as R2 holds them) to equal what it sent. An identical re-run is a 200; different bytes for the same serial
  are a 409 `conflict`. The other 409s keep their own word (`REFUSED replay`, `rollback`, `revoked`), and another known error
  word of the host follows the status (`REFUSED upload 401 stale`).
- `fleet-kit-upload.py gateway [--check] --owner-pub P` reads `fleet/core/gateway.json` and `.sig` from the tip of the fleet `release`
  branch, checks the owner's signature under namespace `mirrorstack-fleet-pin` and that the record has the gateway record's keys
  (`serial`, `address`, `cert_sha256`, `manifest_key`, `session_key`: the other files signed under the same namespace do not),
  and `PUT /_k/gateway/<serial>` (one to nine digits) with both files in one request, so the host flips to the pair whole or
  not at all. The answer must carry `gserial` and the `{sha256, size}` of both files. These two files never enter the release folder.
  Not live is the one state that is not a refusal: `gateway.json` is a regular file (mode 100644) that is exactly the placeholder
  the fleet repository holds (`serial` the integer 0 written as a plain `0`, `address`, `cert_sha256`, `manifest_key`,
  `session_key` and `next` null, `r9_closed` false, no other key), and the tip has no `gateway.json.sig` at all. Then the verb
  prints `SKIP gateway not-live`, makes no request and exits 0. A half-edited record (any field filled in) is not the placeholder.
  A signature beside a placeholder, a serial 0 with an address, an unsigned record with a null address and a serial of 1 or more,
  a live-looking record without a signature, and every malformed record stay `REFUSED gateway` (or `REFUSED sig` for a bad
  signature). A signed record with a null address and a serial of 1 or more is judged live, as before: the address is not read.
  `--check` is the same read and the same verdict with no upload and no upload key: `OK gateway-check serial=N`, the SKIP line, or
  the refusal. The kit job runs it first, so a refusal comes before the bundle is stored.
- This repository is public, so nothing a build holds is printed: git's stderr and the build's output go to a file in
  `RUNNER_TEMP`, an error names the rule and never a value, and there is no stack dump. The log shows a size and a sha256 only.

`vendor/bundle.py` is the fleet repository's `fleet/install/bundle.py` byte for byte, pinned by `vendor/VENDORED.sha256` (one
lower-case hex line and a newline; the manifest copy keeps its own `vendor/manifest.sha256`). It imports two modules of the fleet,
a git boundary and one constant; `vendor/standin-bundle/` answers those imports, pinned by one hash over its five files
(`vendor/standin-bundle.sha256`, same form as `standin.sha256`). The uploader stops with `REFUSED vendor` unless every hash
matches, and runs the bytes it hashed. The stand-in git module is the fleet's with two differences: an error never carries git's
stderr, and git gets a bare environment (`PATH` and a fixed few, nothing else of the runner's). `.gitattributes` marks all of it `-text`. A change to the packer ships as the same file and the same pin in both
repositories, in the same step; nothing on the fleet side checks `vendor/bundle.py` against its own copy yet (its
`vendor-sync` covers the manifest only), so until that check exists a drift shows first as `REFUSED bundle-hash`. The copy's
comments still carry the fleet's internal plan ids: they go upstream first and the file is re-vendored (comments only, so the
tar bytes do not change) before this repository is merged, or the owner accepts them. `tests/test_kit_upload.py` freezes the packer's output against a golden sha256 on every Python
the tests run on.

## The control VM's pins plan (CV05b, D342)

`bin/fleet-pins-plan.py plan --repo DIR --pub FILE [--release origin/release] [--main origin/main] [--tip SHA] [--run-id ID]`
judges the five root pin files (`fleet/hosts.json`, `fleet/core/{gateway,work-pin,deploy-pin,proven}.json`) at the fleet `release` tip
before CI signs them under namespace `mirrorstack-fleet-ctl`. It reads the fleet tree with git only (never imports fleet code).
stdout is the manifest, one `key value` line each: `tip <sha>`, `run <id>`, then per file `path sha256 serial action`, the keys the
land tool reads (`action` is `keep` when the tip's `.sig` verifies for the exact bytes, else `sign`). Review lines go to stderr
behind `# `: per signed file its sha256, old and new serial and the names of the keys that changed, and per new or changed host its
two key fingerprints; never a value, since this repository is public. A refusal prints `REFUSED <word> <path>` on stderr and exits
1 with no manifest: `shape` (also a hosts line `vendor/pin-summary.py` refuses), `size` (over 1 MiB), `serial` (not above every earlier
signed body's, read unverified at each commit that added or changed the `.sig`, unless the bytes are the previous body's; a `keep`
whose serial is below any of them is refused too), `head` (a deploy
head outside main's first 300 first parents, not an ancestor of the release tip, not a descendant of the last signed non-null head, or
whose `fleet/slot/model.py` has no module-level `SIG_NS` literal mapping `ctl` to the ctl namespace), `tree`, `blob` (a work-pin blob that is not the release tree's
`.github/workflows/work.yml`), `tip-moved`, `unread`, `vendor`, `pub`, `fetch`. `fleet-pins-plan.py clone URL DIR` takes a
`--filter=blob:none` clone and falls back to a full clone when that fails (not measured here: it needs the FLEET_READ key); a DIR that already holds files is
refused (`fetch`) and never touched.
`vendor/pin-summary.py` is the fleet's `bin/pin-summary.py` byte for byte at fleet main 754265e0, pinned by
`vendor/pin-summary.sha256`; `tests/test_pins_plan.py` holds the fleet's own digest as a literal (so a change to the vendored copy needs a visible edit there)
and compares its tables with the fleet's copy when `FLEET_REPO` names a clone.

## The control VM's pin files: mode pins (CV05c, D342)

`mode` pins signs the five files the control VM's root reads from the fleet's `main` (`fleet/hosts.json` and
`fleet/core/{gateway,work-pin,deploy-pin,proven}.json`), taken from the fleet `release` tip, with the key `KEY_SHA256` names, under the
namespace `mirrorstack-fleet-ctl`. It needs no `serial` and no other job runs in it (a test reads `if:` and `needs:` of every job and fails
if one could). A carrier's `deploy-pin.json` is public and signed under `mirrorstack-fleet-pin`; with one namespace for both, a copy of
that pair would pass as root's own pin, so root verifies `ctl` (CV05e) and the carrier files stay on `pin`. Run it on the `release` branch,
after the fleet's main to release merge and before the land PR (fleet repository, CV05f):

- **pins-plan** (Environment `release`, `FLEET_READ` only; the signing key is not in this job): clones the fleet repository, runs
  `bin/fleet-pins-plan.py` (the plan above) over the `release` tip, prints the tip, and hands on the tip, the deploy head, the series and
  the five lines `path sha256 serial action`. `KEY_PUB`, the public line of the signing key, is a constant of the workflow beside
  `KEY_SHA256`: the plan refuses `key-pub` unless its fingerprint is `KEY_SHA256` (it only judges the signatures already at the tip, so
  a change of key changes both in one reviewed edit).
- **pins-approve** (Environment `kit-floor`, no secret): runs only when `SERIES` is `release` (read from the plan, so the test series has no owner step),
  prints the tip, each file's serial, sha256 and action and the deploy head, and waits for the owner. `pins-sign` needs it in the release series
  (attack M4: the main to release PR of some 400 commits shows no per-pin diff). While `kit-floor` has no required reviewer nothing stops
  it: do not rely on it.
- **pins-sign** (Environment `release`; two steps like `gwsign`; no checkout, no action, no repository code, no job token): `fetch` (`FLEET_READ`
  only) refuses `tip-moved` unless the `release` tip is still the planned one, reads each `sign` file as a git blob of that tip (a regular file
  of 1 to 1 MiB) and refuses on a sha256 that differs from the plan's; for `deploy-pin.json` it also refuses unless the head is `null` or an
  ancestor of the tip (attack M2, a second look at what the plan judged). `sign` (`SIGN_KEY` only, no git, ssh or network child) refuses
  `key` unless the key's fingerprint is `KEY_SHA256`, allows the namespace `mirrorstack-fleet-ctl` and no other, signs each file, verifies and
  re-hashes it, and outputs the signatures (base64) and `pub=`. Every output is written after the last file is signed: a refusal hands on nothing.
- **pins-publish** (no secret, `contents: read`): writes `pins-sigs.json` and uploads it as the artifact `pins-sigs`, kept one day:
  `{tip, run, fingerprint, pub, entries[{path, sha256, serial, sig_b64}]}`, one entry per file this run signed (a `keep` file has none; its signature is
  at the tip already). The run id is there for the land PR's body (attack minor 3).

Nothing printed is a value (this repository is public): paths, serials, sha256 sums, the tip and a head. The signatures reach root through
the fleet's `main` only: its ruleset lets CI write nothing, and a write credential into the fleet would be worth more than this key, so an admin
session downloads `pins-sigs` and lands the `.sig` files in a PR (CV05f), which writes only `.sig` files and never a body. The proof of a first
run is the line `signed with key SHA256:16jB0ih9afmAW7rFmgTJVtarDgEv4w/DHA8LKufWhKM` in `pins-sign` and an artifact that
`ssh-keygen -Y verify -n mirrorstack-fleet-ctl` accepts over the file at the tip.

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
  bypass, and put `SIGN_KEY`, `TAG_KEY`, `FLEET_READ` and `KIT_UPLOAD_KEY` in it. The disk build has its own Environment `disk`
  (restricted to `main`), so nothing about `release` gates or reaches it. `disk` holds no secret or variable, so it is not a
  boundary: it only restricts the dispatch to `main`, and the job's write power is the workflow file's `contents: write`.
  No ruleset covers the `disk-*` tags yet, so anyone with push access can take a `disk-noble-<serial>` name. The ruleset
  (creation, update, deletion, with a deploy key stored in `disk` as its only bypass) is the owner's step; until then
  use `pin`, not the log: `bin/fleet-disk.py pin [amd64|arm64] <serial>` (see "Pinning a disk release") prints the entries only for
  a release whose commit is on `main`. A read-only probe, run by hand with an admin token, prints
  FAIL until both exist:

  ```sh
  repo=mirrorstack-ai/fleet-disk
  for id in $(gh api "repos/$repo/rulesets" --jq '.[].id'); do
    gh api "repos/$repo/rulesets/$id" --jq '.conditions.ref_name.include[]?'
  done | grep -q 'refs/tags/disk-' && echo 'ok: a ruleset covers refs/tags/disk-*' || echo 'FAIL: no ruleset covers refs/tags/disk-*'
  gh api "repos/$repo/environments/disk/secrets" --jq '.total_count' | grep -qv '^0$' \
    && echo 'ok: the disk environment holds a secret' || echo 'FAIL: the disk environment holds no secret (no tag key)'
  ```
- Create the Environment `kit-floor`, restricted to the `release` branch, with the owner (or the team `security`) as required
  reviewer and admins unable to bypass, and no secret. It is the only gate on a floor run (`floor-approve`); `release` has no
  reviewer, so a release run is unattended during the test phase. In the release series `pins-approve` waits here too (mode pins, below).
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

**The kit upload key.** The same workflow and helper make `KIT_UPLOAD_KEY`, the Ed25519 key that signs uploads to the kit host:
dispatch with `-f keys=kit-upload` (the default is `test`), then `bin/fleet-keygen-put.py --run <id> --sha <commit> --keys kit-upload`.
Only that one key is made (`openssl genpkey -algorithm ed25519`, a 119-byte PKCS8 PEM, no passphrase), sealed to the same
Environment `release` key and checked the same way; the helper refuses a log of the other set. The job prints one public line,
`KEYGEN-PUBLIC KIT_UPLOAD_KEY ed25519 <64 hex>`, derived from the very bytes that were sealed, and the SHA256 fingerprint of
exactly those 32 bytes (the helper recomputes it). The 64 hex is the host's `KIT_UP_PUB`. The key has no Cloudflare power.

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

The gate that matters is the `smoke` job of `install.yml` (above): the release folder is committed only in the fleet repository,
so the plan fetches the loaders from the fleet `release` tip, the `fixture` job builds one fixture from them on ubuntu with
`make_fixture.py --out fixture --ps1 loaders/bootstrap.ps1 --sh loaders/bootstrap.sh`, and every runner downloads it and runs the same steps and rows as this
workflow, minus the experimental `keychain` and `ubuntu-26.04` rows (the latter is a hosted image that moves weekly, so it only reports here). `boot-smoke.yml` stays as a dispatch and as a PR-path trigger (`release/install-*/bootstrap.*`, which now rarely fires, and edits of the builder and the
driver); a dispatch that finds no complete pair fails. The smoke ends the good run in `kvm` on a hosted runner (no `/dev/kvm`),
and never runs the install itself.

The cases also cover each size cap (the signature, `install.json` with and without a `Content-Length`, `kit.json`, a kit file, the
ZIP), a wrong `kind`, a missing field, a six-file kit, and bad command lines (below the floor, a repeated or missing flag, an
abbreviated flag). Every runner but `ubuntu-22.04` (which refuses `os` by design) is run with `--must-run`, so a machine
refusal there fails the job instead of passing every case without a request. The throwaway certificates and CRL start an hour
before the build, so a runner clock a little slow still accepts them.

Fork pull requests run this workflow's code (from the PR) on hosted runners, including `sudo` and a trust-store change on the
Windows and macOS ones. It holds no secret and a read-only token, so the worst a hostile fork can do is spend runner minutes.
Keep that true in the repository settings: Actions > General > Fork pull request workflows, set "Require approval for all
outside collaborators", and leave "Send write tokens to workflows from pull requests" off.

## Real smoke (a published release)

`.github/workflows/smoke-real.yml` (`workflow_dispatch` only, from `main` only, input `serial` digits only, `contents: read`, no
secret, no Environment) runs the REAL one-liner of a published release `install-<serial>` on the same five runners:
`smoke_driver.py real --serial N` reads the release's notes with `gh release view`, takes the OS's check line (the fence under
`<os> (bootstrap sha256 <hex>):`, the text `release_notes` writes), and runs it with no invite on a throwaway `HOME`/`TEMP`,
stripped of the runner's token. The check must end as a fixture case does (the same `expect`: the machine's own refusal,
`kvm` on a Linux runner without `/dev/kvm`, else exit 0 with the code line), make no file outside the throwaway home (the real
home and temp folder are listed before and after, and so are the places an install would write) and leave nothing in the
throwaway temp folder.

Two values it holds the release against come from `main`, never from the release under test: the owner key's fingerprint is
the `KEY_SHA256` constant of `install.yml`, and the bootstrap digests are `.github/smoke-real-pins.json`
(`{"<serial>": {"ps1": <sha256>, "sh": <sha256>}}`). The release's notes, its downloaded asset and the line must all carry
main's digest (`digest-mismatch` otherwise, even when the notes and the asset agree with each other) and the notes must name
main's key (`key-mismatch`); the run's own `bootstrap sha256` and `key` lines must be main's too. A serial with no pin stops
at `no-main-pin` before anything is read: add the pin (from the signed `install.json` of the fleet release folder) by a reviewed
change first.
Checking a release therefore takes a second, reviewed step per serial: a pin PR that copies the bootstrap sha256 from the signed
`install.json` into `smoke-real-pins.json` (the plan said to stop and report when no main-side digest source exists; this file is
that source, so the plan's rule is waived for it only if the coordinator agrees), then one dispatch from `main`. The line the
release's notes carry must also equal, byte for byte, what `main`'s `bin/fleet-install-publish.py` `check_line` renders for that
serial, OS, repository, digest and min serial, so a line with anything added is never run. A dispatch from any other branch fails
in the `guard` job (red), it never skips green. The leg costs hosted-runner minutes on every dispatch (the macOS leg at the macOS multiplier), so dispatch it
once per published release.

## Descriptor probe (fd-probe)

`.github/workflows/fd-probe.yml` (pull request on its own four files, `workflow_dispatch`, a weekly `schedule`; `contents: read`, only
the scheduled `report` job holds `issues: write` and opens one issue) runs `tests/fixture/fd_probe.py` on `ubuntu-24.04`,
`ubuntu-24.04-arm` (the controls) and `ubuntu-26.04`, `ubuntu-26.04-arm`. It starts `/usr/bin/python3 -I -S`, runs `import ctypes`
and prints every descriptor beyond 0-2 (its `readlink`, `fstat` type, mode, uid, device and inode, `F_GETFL`, `F_GETFD`, the
`/proc/self/maps` lines with the same path and whether their device and inode agree with `fstat`, the filesystem type of its
directory), plus `dpkg-query -W libffi8`, `sys.version`, the interpreter's real path and `dpkg -S` of it and of `/usr/bin/python3`. The child also
opens `/dev/null` after the import and must find it in its own listing (a positive control that the enumeration reads descriptors at
all), and a descriptor it could not read fails the leg instead of vanishing from the count. The verdict is the shape the key
holder's rule needs: no extra descriptor on 24.04; on 26.04 exactly one, a root-owned regular file without setuid, setgid, sticky,
group or other write, `O_RDONLY`, directly in `/usr/lib/<this leg's architecture>-linux-gnu/` as `libffi.so.N...`, with a maps line
for the same path. `F_GETFD` and the device/inode agreement are printed, not judged. Anything else fails, as does an
`/usr/bin/python3` no dpkg package owns or a label that moved to another release. `tests/fixture/fd_golden.json` holds the
vectors, meant to be byte for byte the copy the fleet repository's key holder slice (PZ01) carries once it exists (a row is
`name`, `type`, `uid`, `mode` as octal text, `flags`, `target`, `maps_has_path`, `expect`, and `maps_over_cap` on one row; its sha256 is
the constant in the test); `tests/test_fd_probe.py` runs the verdict over every row of it and checks that sha256. Caveats: the hosted kernel is Azure's and its root filesystem may differ from a production host's, so
the probe prints `stat -f` of the library directory; and the image ships GNU sudo and coreutils, so nothing here speaks for
sudo-rs or uutils. It measures the descriptor; it does not run the private key holder.
