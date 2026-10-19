#!/bin/sh
# bootstrap.sh - the verified check for Ubuntu 24.04 and macOS (P+ I04, I09a1, plan 16; wave I check-line contract, H1-H6).
# Usage: sh bootstrap.sh [--install|--update|--uninstall|--status] --serial N --min-serial N [--gw-serial G]
# No switch is the check; install and update carry --gw-serial G, no other mode may. Each flag once, case-sensitive, any
# order, no abbreviation, no `=` form (GRAMMAR below is the table; fleet/install/line.py parse_args is its oracle). The
# numbers are mandatory, canonical decimal, at most 2147483648, and serial must not be below min-serial. The line
# names the release: https://github.com/mirrorstack-ai/fleet-disk/releases/download/install-<serial>/<name> (never
# releases/latest: that repo also holds disk-noble-* releases).
# It only fetches, hashes and verifies: install.json and its signature (the OS ssh-keygen -Y verify against the key
# baked below), then the kit's carrier-check.sh by hash, which it runs. It installs nothing, needs no root, and keeps
# everything in one mktemp -d directory that it removes. Info lines print as they are earned (bootstrap sha256, key,
# serial); a refusal is always the last two stdout lines, `REFUSED <code>` and one sentence, exit 1 (bad args included).
# Install and update (I09a3, H3/H4 POSIX): after kit-old, ONE sudo call runs LOADER as root; it stages this very file under
# STAGE_ROOT by hash and runs it with --elevated, which repeats the chain, types the invite with no echo, fetches the signed
# gateway record and bundle from kit-serve (the invite only in a 0600 curl -K file), proves the closure, and runs posix.py (INT2: stage.py is Windows').
# The baked values are placeholders in the tree, filled in at release; a placeholder refuses `key`, so an unfilled file
# fails closed. Each is ONE assignment line with nothing after it: the release tools rewrite them by that shape.
# The refusal codes are the wave I shared list (section 5 and H5) plus the two this shell alone speaks (kvm self); a test pins the list:
#   args os arch tools ssh-keygen temp key expired fetch size sig form kind serial rollback boot-hash kit-hash file-hash check-failed elevate invite invite-refused rate-limited gateway-not-live gateway-pin bundle-hash closure pin-mismatch carrier-lock kit-old installed not-installed clock rotated install-failed config-schema learned-schema tampered kvm self
# and the words install.py, run.py, pyinstall.py, stage.py, posix.py, update.py and spike.py write into the result (INT1). This shell does not
# speak them (the root half's output is relayed unfiltered), except managed, python-lock, python-hash, python-install and python-old, which it speaks
# itself on a Mac (M05p fetch_python; M07 check_mac); the block stays the one shared record, kept in step with bootstrap.ps1's table by a test:
#   amd-win10 app-control arm64 bios consent consent-declined consent-managed consent-not-owner firewall folder folder-owner
#   free-space game-conflict gateway-json head home home-win10 hyperv-feature hypervisor-off managed managed-policy not-admin
#   not-x64 owner-pin python python-download python-hash python-install python-lock python-old ram s-mode
#   security-changed store-gb unpinned unverified usage
LC_ALL=C
export LC_ALL
umask 077

# the owner's one public key; this file never fetches a key
OWNER_KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE+5MqONUoRXkjct3UeFr+xffINGAYa4ZytdHK//67CE'
# the last instant this bootstrap runs, UTC, in install.json's valid_until shape; an old line in chat history stops here
EXPIRES=2026-12-24T00:00:00Z
# the per-serial release folder is RELEASES/install-<serial>; BASE is built from it once the line's serial is known
RELEASES=https://github.com/mirrorstack-ai/fleet-disk/releases/download
BASE=
SSH_KEYGEN=/usr/bin/ssh-keygen  # absolute: no PATH search for the program that decides trust
NS=mirrorstack-fleet-install  # install.json's namespace; the pin and the kit sign under their own
SELF=$0
T=
KG_LIMIT=60 CHECK_LIMIT=900  # seconds ssh-keygen and carrier-check.sh may take
GRAMMAR='check:serial,min-serial install:serial,min-serial,gw-serial update:serial,min-serial,gw-serial uninstall:serial,min-serial status:serial,min-serial'
SUDO=/usr/bin/sudo  # absolute, like SSH_KEYGEN; the one program that raises privilege (H4)
PY=/usr/bin/python3  # the root stage runs verify-archive.py and posix.py under this, version 3.12 or newer (H3)
STAGE_ROOT=/var/lib/mirrorstack-fleet-stage  # H4: root-only; the loader makes one 0700 folder under it per run
ROOT_UID=0  # the owner id the stage folder must have, and the id the elevated half must run as
NS_PIN=mirrorstack-fleet-pin  # gateway.json's signing namespace (H3 step 2)
DIE_RC=1  # 10 in the elevated half: the parent maps it to a refusal that is already on stdout (sudo's own failure is 1)
MIN_KIT_SERIAL=5  # the first kit with verify-archive --closure and its hardened _safe (H2): install and update refuse an older one
INSTALL_DIR=/usr/lib/mirrorstack-fleet  # H11: the installed bootstrap copy and the uninstall.json journal; there is no journal when nothing is installed
# M05p: a Mac keeps both under one vendor folder (use_platform swaps them in); its Python is the stage's (fetch_python), never /usr/bin/python3
MAC_DIR='/Library/Application Support/MirrorStack Fleet'
MAC_STAGE_ROOT=$MAC_DIR/stage MAC_INSTALL_DIR=$MAC_DIR/install MAC_STATUS_FILE=$MAC_DIR/public/status.json
MAC_OS_FLOOR=26  # the lowest macOS an install takes: backends.MAC_OS_FLOOR (a test holds both); the install line and the check line agree
# M07, G-M05p-2: a Mac's removal by constants, mac/install.py's FIXED (a test holds both): the role accounts, the carrier's plist, the vendor folder
FIXM_ROLES='_msvm _msrelay' FIXM_PLIST=/Library/LaunchDaemons/ai.mirrorstack.fleet.carrier.plist
MAC_PY_CAP=104857600  # bytes the pinned python-build-standalone archive may be
PBS=https://github.com/astral-sh/python-build-standalone/releases/download  # the one place kit.json's python_mac url may point
TAR=/usr/bin/tar  # absolute, like SSH_KEYGEN
ROOT_CURL=/usr/bin/curl  # AF12: the curl root's loader runs (root has no PATH of ours); install and update on Ubuntu need it before the administrator step
UNFINISHED_SAY='The last install did not finish. Run the uninstall line, then the install line. Nothing was changed.'  # AF12, G-AUD-BOOT-SH-3
FS=  # a prefix of the machine's paths for the fixed removal: empty here, a scratch folder in a test
# INT2, G-LX05-1: the removal by constants, install.py's FIXED (a test holds both): the table, the account, the stop order, every path;
# AF17: and its strays (the loader's stage root, the gate's stamp) beside it, the AppArmor cache files by glob, the download account by the journal
FIX_TABLE=mirrorstack_fleet FIX_USER=mirrorstack-fleet FIX_VAR=/var/lib/mirrorstack-fleet FIX_FETCH=fleet-fetch
FIX_STOP='mirrorstack-fleet-l1.timer mirrorstack-fleet-l1.service mirrorstack-fleet-l1-egress.timer mirrorstack-fleet-l1-egress.service'
FIX_PATHS='/etc/apparmor.d/mirrorstack-fleet-l1 /usr/lib/systemd/system-sleep/mirrorstack-fleet /etc/systemd/system/mirrorstack-fleet-l1.service /etc/systemd/system/mirrorstack-fleet-l1-egress.service /etc/systemd/system/mirrorstack-fleet-l1-egress.timer /etc/systemd/system/mirrorstack-fleet-l1.timer /etc/systemd/system/timers.target.wants/mirrorstack-fleet-l1.timer /etc/systemd/system/mirrorstack-fleet-l1.service.d /var/lib/mirrorstack-fleet-stage /run/mirrorstack-fleet-gate'
STATUS_FILE=/var/lib/mirrorstack-fleet/public/status.json  # H11: the carrier's public status, read for display only
# H8: what a mode does with the two notices a verified release can carry (the clock of its fetch, a key handoff): `clock`
# refuses a local clock a day behind the server's; `rotated` refuses a release that hands over to a new key; `successor`
# only prints that handoff. bootstrap.ps1 holds the same table (its $Rules); a test holds both. Uninstall fetches nothing.
RULES='check:clock,successor install:clock,rotated update:clock,rotated uninstall: status:successor'
CLOCK_SLACK=86400  # seconds this machine's clock may run behind the server's Date before `clock`
STATUS_JSON='^\{("[a-z_]{1,32}":("[^"\\]{0,200}"|-?[0-9]{1,12}|true|false|null)(,"[a-z_]{1,32}":("[^"\\]{0,200}"|-?[0-9]{1,12}|true|false|null))*)?\}$'

# The clock and the machine's facts: the only functions a test replaces, after sourcing this file with FLEET_BOOT_LIB=1
# (which stops before main; no line of this file or of the paste text sets it).
boot_now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
boot_sys() { uname -s; }
boot_arch() { uname -m; }
boot_kernel() { uname -r; }
boot_osrel() { cat /etc/os-release 2>/dev/null; }
boot_kvm() { [ -r /dev/kvm ] && [ -w /dev/kvm ]; }
boot_installed() { [ -f "$INSTALL_DIR/uninstall.json" ] && [ ! -L "$INSTALL_DIR/uninstall.json" ]; }
boot_leftover() { # AF26, Linux only: no journal, yet the account, VAR, a folder at INSTALL_DIR or a FIX_PATHS entry is here (the stage root, whatever it holds, and the gate's stamp are skipped as paths: a killed install's stage folder is no reason for sudo; the fleet-fetch account and the nft table are not looked for: the journal alone names that account, and a machine with only that remnant is told nothing was installed)
  [ "$(boot_sys)" != Darwin ] || return 1
  ! boot_cmd /usr/bin/getent passwd "$FIX_USER" >/dev/null 2>&1 || return 0
  [ ! -L "$INSTALL_DIR" ] && [ -z "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ] || return 0 # an empty folder is nothing the fleet made
  for p in "$FIX_VAR" $FIX_PATHS; do
    [ "$p" != "$STAGE_ROOT" ] && [ "$p" != /run/mirrorstack-fleet-gate ] || continue
    [ ! -e "${FS}${p}" ] && [ ! -L "${FS}${p}" ] || return 0
  done
  return 1
}
boot_unfinished() { # AF12: a journal without a tree is a half install; an unreadable one (root's 0600, seen by a user) is half only on Ubuntu with no status.json
  boot_installed || return 1
  if [ -r "$INSTALL_DIR/uninstall.json" ]; then
    [ -z "$(tr -d ' \t\r\n' < "$INSTALL_DIR/uninstall.json" 2>/dev/null | sed -n '/"tree":{/p')" ] # sed, not grep: the tools this shell may use
  else
    [ "$(boot_sys)" != Darwin ] && [ ! -e "$STATUS_FILE" ] && [ ! -L "$STATUS_FILE" ]
  fi
}
boot_uid() { id -u; }
boot_brand() { /usr/sbin/sysctl -n machdep.cpu.brand_string 2>/dev/null; } # M07: a Mac's chip, `Apple M3 Pro`
boot_macos() { /usr/sbin/sysctl -n kern.osproductversion 2>/dev/null; }
boot_mdm() { /usr/bin/profiles status -type enrollment 2>/dev/null; }

die() { # die CODE SENTENCE: the one way out of a refusal, two lines
  printf 'REFUSED %s\n%s\n' "$1" "$2"
  exit "$DIE_RC"
}

usage() {
  die args 'The line must carry --serial N and --min-serial N (and --gw-serial G for install and update), each once. Paste the whole line again. Nothing was run.'
}

done_ok() { printf 'DONE %s\n%s\n' "$1" "$2"; } # DONE <mode> and one sentence, exit 0 (H6)

clean() {
  if [ -n "$T" ] && [ -d "$T" ] && [ ! -L "$T" ]; then rm -rf "$T"; fi
  T=
}

hash_tool() { # the sha256 command's name: sha256sum on Ubuntu, shasum -a 256 on a Mac
  if command -v sha256sum >/dev/null 2>&1; then printf 'sha256sum'; else printf 'shasum -a 256'; fi
}

sha256_of() { # the file's sha256 in hex
  $(hash_tool) "$1" 2>/dev/null | awk '{ print $1 }'
}

limited() { # limited SECONDS CMD...: CMD under a time limit, 124 when cut; `timeout` where there is one, else a watcher (a Mac has none)
  s=$1
  shift
  if command -v timeout >/dev/null 2>&1; then timeout "$s" "$@"; return $?; fi
  exec 3<&0 # dash gives a background command /dev/null for stdin unless it is named by a descriptor
  "$@" <&3 &
  p=$!
  # trap first, and no output descriptors: a watcher cut before its trap leaves an orphan sleep, which must not hold
  # the caller's $(...) pipe open for the whole limit (dash waits for it)
  (trap 'kill $q 2>/dev/null; exit 0' TERM; sleep "$s" & q=$!; wait $q; kill "$p" 2>/dev/null) >/dev/null 2>&1 &
  w=$!
  wait "$p"
  rc=$?
  exec 3<&-
  kill "$w" 2>/dev/null
  wait "$w" 2>/dev/null
  [ "$rc" -ne 143 ] || rc=124
  return "$rc"
}

size_of() { wc -c < "$1" | tr -d ' '; }

digits() { printf '%s' "$1" | tr -cd '0-9'; } # 2026-10-07T12:00:00Z -> 20261007120000: a time compared as a number

get() { # get NAME MAX [HEADERS]: BASE/NAME into $T/NAME, https only (also after a redirect), at most MAX bytes and not empty
  curl -fsSL --max-redirs 3 --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 20 --max-time 120 \
    --max-filesize "$2" -D "${3:-/dev/null}" -o "$T/$1" "$BASE/$1" 2>/dev/null
  rc=$?
  [ "$rc" -ne 63 ] || die size "$1 is bigger than the $2 bytes it may be. Nothing was run. Tell the owner."
  [ "$rc" -eq 0 ] ||
    die fetch "Could not download $1: no network, a redirect away from https, or the file is missing. Nothing was run. Tell the owner."
  [ -f "$T/$1" ] && [ ! -L "$T/$1" ] || die fetch "Could not download $1. Nothing was run. Tell the owner."
  got=$(size_of "$T/$1")
  [ "$got" -gt 0 ] && [ "$got" -le "$2" ] || die size "$1 is empty or bigger than the $2 bytes it may be. Nothing was run. Tell the owner."
}

hex64() { case $1 in *[!0-9a-f]*) return 1 ;; esac; [ ${#1} -eq 64 ]; }

canon() { # a canonical decimal count: 0 or no leading zero, at most 10 digits, at most 2^31
  case $1 in '' | *[!0-9]*) return 1 ;; 0) ;; 0*) return 1 ;; esac
  [ ${#1} -le 10 ] && [ "$1" -le 2147483648 ]
}

flat() { tr -d ' \t\r\n' < "$1"; } # the JSON on one line with no white space (no value holds any)

old_keygen() { # old_keygen TEXT: an ssh-keygen older than OpenSSH 8.0 has no -Y and says so
  [ -z "$(printf '%s\n' "$1" | sed -En '/(illegal|unknown|invalid) option/p')" ] ||
    die ssh-keygen 'This ssh-keygen cannot verify signatures (it is older than OpenSSH 8.0); update it and paste the line again. Nothing was run.'
}
utc() { case $1 in [0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z) ;; *) return 1 ;; esac; } # a UTC time as the manifest writes it

rule() { # rule WORD: this mode's row of RULES names WORD
  case ",$(printf '%s\n' "$RULES" | tr ' ' '\n' | sed -n "s/^$mode://p")," in *",$1,"*) return 0 ;; esac
  return 1
}

dec() { printf '%s\n' "$1" | sed 's/^0*\(.\)/\1/'; } # 007 -> 7, 00 -> 0: no leading zero for the arithmetic (it reads 08 as octal)

epoch() { # epoch Y M D h m s: seconds since 1970 for a UTC time (days from civil: a year starts in March)
  ck_y=$(dec "$1") ck_m=$(dec "$2") ck_d=$(dec "$3")
  if [ "$ck_m" -gt 2 ]; then ck_m=$((ck_m - 3)); else ck_m=$((ck_m + 9)); ck_y=$((ck_y - 1)); fi
  ck_era=$((ck_y / 400))
  ck_yoe=$((ck_y - ck_era * 400))
  ck_days=$((ck_era * 146097 + ck_yoe * 365 + ck_yoe / 4 - ck_yoe / 100 + (153 * ck_m + 2) / 5 + ck_d - 1 - 719468))
  printf '%s\n' $((ck_days * 86400 + $(dec "$4") * 3600 + $(dec "$5") * 60 + $(dec "$6")))
}

iso_epoch() { # a UTC time in install.json's shape, 2026-10-07T12:00:00Z, as epoch seconds
  utc "$1" || return 1
  set -- $(printf '%s' "$1" | tr -c '0-9' ' ')
  epoch "$@"
}

http_epoch() { # an HTTP date in exactly `Wed, 07 Oct 2026 12:00:00 GMT`'s shape (the weekday is not read), as epoch seconds
  case $1 in
    [A-Z][a-z][a-z],\ [0-3][0-9]\ [A-Z][a-z][a-z]\ [0-9][0-9][0-9][0-9]\ [0-2][0-9]:[0-5][0-9]:[0-5][0-9]\ GMT) ;;
    *) return 1 ;;
  esac
  set -- $(printf '%s' "$1" | tr ':,' '  ')
  case $3 in
    Jan) ck_n=1 ;; Feb) ck_n=2 ;; Mar) ck_n=3 ;; Apr) ck_n=4 ;; May) ck_n=5 ;; Jun) ck_n=6 ;;
    Jul) ck_n=7 ;; Aug) ck_n=8 ;; Sep) ck_n=9 ;; Oct) ck_n=10 ;; Nov) ck_n=11 ;; Dec) ck_n=12 ;;
    *) return 1 ;;
  esac
  [ "$(dec "$2")" -ge 1 ] && [ "$(dec "$5")" -le 23 ] && [ "$4" -ge 1970 ] || return 1
  case $ck_n in 4 | 6 | 9 | 11) ck_dm=30 ;; 2) ck_dm=28; ck_yy=$(dec "$4")
    if [ $((ck_yy % 4)) -eq 0 ] && { [ $((ck_yy % 100)) -ne 0 ] || [ $((ck_yy % 400)) -eq 0 ]; }; then ck_dm=29; fi ;; *) ck_dm=31 ;; esac
  [ "$(dec "$2")" -le "$ck_dm" ] || return 1 # a day the month does not have is a garbled Date, as TryParseExact reads it in the .ps1
  epoch "$4" "$ck_n" "$2" "$5" "$6" "$7"
}

check_clock() { # check_clock HEADERS (H8): this machine's clock more than CLOCK_SLACK behind the Date of the last response in
  rule clock || return 0 # the install.json fetch's header dump is `clock`; a Date absent, ahead, garbled or oversized is ignored
  ck_date=$(tr -d '\r' < "$1" 2>/dev/null | awk '/^HTTP\//{d="";next} tolower(substr($0,1,5))=="date:"{d=substr($0,6)} END{print d}' | sed 's/^[ ]*//') # the Date of the final block only
  ck_server=$(http_epoch "$ck_date") || return 0
  ck_here=$(iso_epoch "$(boot_now)") || return 0
  [ $((ck_server - ck_here)) -le "$CLOCK_SLACK" ] || die clock 'Your clock is wrong. Fix the time and run the line again. Nothing was run.'
}

check_os() { # Ubuntu or a Mac, in every mode (M07, I16; H1)
  case $(boot_sys) in
    Linux)
      hint='sudo apt install curl openssh-client'
      curl_say="curl is missing; install it (for example: $hint) and paste the line again. Nothing was run." ;;
    Darwin) hint='xcode-select --install' curl_say='curl is missing from your PATH, but every Mac has /usr/bin/curl; put /usr/bin on your PATH and paste the line again. Nothing was run.' ;;
    *) die os 'This check is for Ubuntu 24.04 and macOS; Windows has its own line. Nothing was run. Tell the owner.' ;;
  esac
}

check_tools() { # check_tools [nosig]: status needs no ssh-keygen (a failed chain there only says `latest: unknown`)
  check_os
  command -v curl >/dev/null 2>&1 || die tools "$curl_say"
  case $mode in install | update) [ "$(boot_sys)" != Linux ] || [ -x "$ROOT_CURL" ] || die tools "$ROOT_CURL is missing; install it (for example: $hint) and paste the line again. Nothing was run." ;; esac
  if [ "$1" != nosig ]; then
    [ -x "$SSH_KEYGEN" ] || die ssh-keygen "$SSH_KEYGEN is missing; install it (for example: $hint) and paste the line again. Nothing was run."
    out=$(limited "$KG_LIMIT" "$SSH_KEYGEN" -Y verify 2>&1 </dev/null)
    [ $? -ne 124 ] || slow
    old_keygen "$out"
  fi
  command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 ||
    die tools 'Neither sha256sum nor shasum is here; install coreutils (or perl) and paste the line again. Nothing was run.'
}

check_mac() { # M07: only an install or an update reads the Mac; the check line is carrier-check's call, and status and uninstall must always run
  case $mode in install | update) ;; *) return 0 ;; esac
  [ "$(boot_arch)" = arm64 ] || die arch 'This Mac has an Intel processor; the install needs an Apple silicon Mac with an M3 chip or later. Nothing was run. Tell the owner.'
  mac_gen=$(boot_brand | sed -n 's/.*Apple M\([0-9][0-9]*\).*/\1/p')
  [ "${mac_gen:-0}" -ge 3 ] || die arch 'This Mac has an M1 or M2 chip, or its chip could not be read; the install needs an M3 or later. Nothing was run. Tell the owner.'
  mac_os=$(boot_macos | sed -n 's/^\([0-9][0-9]*\).*/\1/p')
  [ "${mac_os:-0}" -ge "$MAC_OS_FLOOR" ] || die os "This Mac needs macOS $MAC_OS_FLOOR or later, or its version could not be read. Nothing was run. Tell the owner."
  [ "$mode" = install ] || die os 'A Mac cannot be updated yet; uninstall it and install again. Nothing was run. Tell the owner.'
  case $(boot_mdm) in
    *'Enrolled via DEP: Yes'* | *'MDM enrollment: Yes'*) die managed 'This Mac is managed by an organization (MDM or DEP). Nothing was run. Tell the owner.' ;;
  esac
}

check_machine() { # Ubuntu 24.04 x86_64 or an installable Mac, read directly, before any network
  [ "$(boot_sys)" = Linux ] || { check_mac; return 0; }
  case $mode in uninstall | status) return 0 ;; esac # as check_mac: a PC that took a release upgrade must still read its status and remove the software (G-AUD-BOOT-SH-2)
  osrel=$(boot_osrel | tr -d '"')
  case $(printf '%s\n' "$osrel" | sed -n 's/^ID=//p') in
    ubuntu) ;;
    *) die os 'This Linux is not Ubuntu 24.04. Nothing was run. Tell the owner.' ;;
  esac
  case $(printf '%s\n' "$osrel" | sed -n 's/^VERSION_ID=//p') in
    24.04) ;;
    *) die os 'This Ubuntu is not 24.04. Nothing was run. Tell the owner.' ;;
  esac
  case $(boot_arch) in
    x86_64|amd64) ;;
    *) die arch 'This machine is not x86_64. Nothing was run. Tell the owner.' ;;
  esac
}

slow() { die ssh-keygen "ssh-keygen did not answer within $KG_LIMIT seconds. Nothing was run. Tell the owner."; }

key_shape() { # the baked key's shape, before the expiry and before any network: an unfilled file says `key`
  set -- $OWNER_KEY
  [ $# -eq 2 ] && [ "$1" = ssh-ed25519 ] && [ ${#2} -eq 68 ] ||
    die key 'The owner key baked into this file is missing or not one ssh-ed25519 key. Nothing was run. Tell the owner.'
  case $2 in *[!A-Za-z0-9+/]*) die key 'The owner key baked into this file is missing or not one ssh-ed25519 key. Nothing was run. Tell the owner.' ;; esac
  key_blob=$2
}

check_key() { # the shape, then the fingerprint ssh-keygen prints for it
  key_shape
  out=$(printf 'ssh-ed25519 %s\n' "$key_blob" | limited "$KG_LIMIT" "$SSH_KEYGEN" -l -f /dev/stdin 2>/dev/null)
  [ $? -ne 124 ] || slow
  set -- $out
  fp=${2:-}
  [ -n "$fp" ] || die key 'The owner key baked into this file is missing or not one ssh-ed25519 key. Nothing was run. Tell the owner.'
  printf 'key %s\n' "$fp"
}

make_tmp() { # a fresh private directory, refused if it is not a plain directory this process just made
  T=$(mktemp -d "${TMPDIR:-/tmp}/fleet-boot.XXXXXX" 2>/dev/null) || die temp 'Could not make a temporary folder. Nothing was run. Tell the owner.'
  if [ -z "$T" ] || [ -L "$T" ] || [ ! -d "$T" ]; then
    T=
    die temp 'The temporary folder is a link or is not a folder; nothing was written and nothing was run. Tell the owner.'
  fi
  chmod 700 "$T" || die temp 'Could not lock the temporary folder. Nothing was run. Tell the owner.'
}

verify_sig() { # verify_sig FILE SIG NS CODE SENTENCE: FILE counts only when SIG holds under the baked key, NS and the principal owner
  printf 'owner namespaces="%s" ssh-ed25519 %s\n' "$3" "$key_blob" > "$T/allowed_signers"
  out=$(limited "$KG_LIMIT" "$SSH_KEYGEN" -Y verify -f "$T/allowed_signers" -I owner -n "$3" -s "$T/$2" \
    < "$T/$1" 2>"$T/verify.err")
  [ $? -ne 124 ] || slow
  old_keygen "$(cat "$T/verify.err")"
  case $out in
    "Good \"$3\" signature for owner with "*) ;;
    *) die "$4" "$5" ;;
  esac
}

verify_install() { verify_sig install.json install.json.sig "$NS" sig 'install.json is not signed by the owner key in this file. Nothing was run. Tell the owner.'; }

pick() { # pick PATTERN: the first capture of a sed pattern over the one-line install.json (the owner signed it)
  printf '%s' "$one" | sed -n "s/$1/\\1/p"
}

read_install() { # the fields this stage needs, from the signed bytes; the full schema is the Python verifier's
  one=$(flat "$T/install.json")
  kit=$(pick '.*"kit":{\([^}]*\)}.*') # the kit object also holds a serial: set it aside
  hand=$(pick '.*"handoff":{\([^}]*\)}.*') # the rotation notice (H8) is set aside too
  case $one in *'"handoff":'*) has_hand=1 ;; *) has_hand= ;; esac # a handoff key that is not a non-empty object is `form`, as in the .ps1
  one=$(printf '%s' "$one" | sed 's/"kit":{[^}]*}//; s/"handoff":{[^}]*}//; s/"proof":{[^}]*}//') # the proof block (I12d) is Windows' re-proof: set aside
  serial=$(pick '.*"serial":\([0-9]\{1,10\}\)[,}].*')
  valid_until=$(pick '.*"valid_until":"\([0-9TZ:-]\{20\}\)".*')
  src_head=$(pick '.*"source_head":"\([0-9a-f]\{40\}\)".*') # status compares it; a check does not need it
  printf 'serial %s valid_until %s\n' "${serial:-?}" "${valid_until:-?}"
  case $one in *'"kind":"install"'*) ;; *) die kind 'This signed file is not an install manifest. Nothing was run. Tell the owner.' ;; esac
  utc "$valid_until" || die form 'install.json has no valid_until in the form this check reads. Nothing was run. Tell the owner.'
  boot_sha=$(pick '.*"sh":{[^}]*"sha256":"\([0-9a-f]\{64\}\)".*')
  kit_serial=$(printf '%s' "$kit" | sed -n 's/.*"serial":\([0-9]\{1,10\}\).*/\1/p')
  kit_sha=$(printf '%s' "$kit" | sed -n 's/.*"kit_json_sha256":"\([0-9a-f]\{64\}\)".*/\1/p')
  [ -n "$serial" ] && [ -n "$valid_until" ] && [ -n "$boot_sha" ] && [ -n "$kit_serial" ] && [ -n "$kit_sha" ] ||
    die form 'install.json is not in the shape this bootstrap reads. Nothing was run. Tell the owner.'
  succ_fp= succ_first=
  if [ -n "$has_hand" ]; then
    succ_fp=$(printf '%s' "$hand" | sed -n 's,.*"fp":"\(SHA256:[A-Za-z0-9+/]\{43\}\)".*,\1,p')
    succ_first=$(printf '%s' "$hand" | sed -n 's/.*"first_serial":\([0-9]\{1,10\}\)[,}]*.*/\1/p')
    [ -n "$hand" ] && [ -n "$succ_fp" ] && [ -n "$succ_first" ] && [ "$(dec "$succ_first")" -gt "$(dec "$serial")" ] ||
      die form 'install.json is not in the shape this bootstrap reads. Nothing was run. Tell the owner.' # first_serial is above this serial, as manifest.py reads it
  fi
}

handoff_notice() { # H8: a verified release that hands over to a new key is refused `rotated` where RULES says, else announced
  [ -n "$succ_fp" ] || return 0
  ! rule rotated || die rotated 'The owner has replaced this line. Ask for the new one.'
  ! rule successor || printf 'successor %s first-serial %s\n' "$succ_fp" "$succ_first"
}

check_install() { # expired, rollback against the line's floor, the line's serial, then this very file against the signed hash
  [ "$(digits "$valid_until")" -gt "$(digits "$(boot_now)")" ] ||
    die expired "install.json ran out on $valid_until; ask for a fresh line. Nothing was run."
  [ "$serial" -ge "$min" ] || die rollback "install.json is serial $serial, older than the $min on your line. Nothing was run. Tell the owner."
  [ "$serial" = "$line_serial" ] ||
    die serial "install.json is serial $serial but your line names serial $line_serial; ask for a fresh line. Nothing was run."
  [ "$self_sha" = "$boot_sha" ] ||
    die boot-hash "This bootstrap is not the one the owner signed for serial $serial; if your line is old, ask for a fresh line, otherwise do not run it. Nothing was run."
}

fetch_kit_json() { # kit.json by the hash install.json carries
  get kit.json 65536
  [ "$(sha256_of "$T/kit.json")" = "$kit_sha" ] || die kit-hash 'kit.json is not the one the owner signed. Nothing was run. Tell the owner.'
}

read_kit() { # the fetched kit.json holds exactly the five kit files and the kit serial install.json names
  kitone=$(flat "$T/kit.json")
  kit_file_serial=$(printf '%s' "$kitone" | sed -n 's/.*"serial":\([0-9]\{1,10\}\)[,}].*/\1/p')
  [ "$kit_file_serial" = "$kit_serial" ] ||
    die form 'kit.json is not the kit serial install.json names. Nothing was run. Tell the owner.'
  names=$(printf '%s' "$kitone" | tr '{' '\n' | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')
  [ "$(printf '%s\n' "$names" | wc -l | tr -d ' ')" -eq 5 ] || die form 'kit.json does not list exactly the five kit files. Nothing was run. Tell the owner.'
  for want in carrier-check.py check.ps1 carrier-check.sh verify-archive.py VERIFY.txt; do
    [ "$(printf '%s\n' "$names" | awk -v n="$want" '$0 == n { c++ } END { print c + 0 }')" -eq 1 ] ||
      die form 'kit.json does not list exactly the five kit files. Nothing was run. Tell the owner.'
  done
}

kit_file() { # kit_file NAME MAX: NAME into $T by the hash kit.json lists for it
  want=$(printf '%s' "$kitone" | tr '{' '\n' | sed -n "/\"path\":\"$1\"/s/.*\"sha256\":\"\([0-9a-f]\{64\}\)\".*/\1/p")
  hex64 "$want" || die form "kit.json does not list $1. Nothing was run. Tell the owner."
  get "$1" "$2"
  [ "$(sha256_of "$T/$1")" = "$want" ] || die file-hash "$1 is not the one kit.json lists. Nothing was run. Tell the owner."
}

run_kit() { # then carrier-check.sh by the hash kit.json carries
  fetch_kit_json
  read_kit
  kit_file carrier-check.sh 262144
  (cd "$T" && limited "$CHECK_LIMIT" sh ./carrier-check.sh) || die check-failed 'carrier-check.sh did not finish. Tell the owner.'
}

show_code() { # the code line of the report, repeated last (carrier-check's own output scrolled it away) and copied on a Mac
  code=$(sed -n 's/^Code  *\(\([0-9A-Z]\{5\} \)\{7\}[0-9A-Z]\{5\}\).*/\1/p' "$T/carrier-check-report.txt" 2>/dev/null | head -1)
  [ -n "$code" ] || die check-failed 'carrier-check.sh printed no code line. Tell the owner.'
  printf 'Your code: %s\n' "$code"
  if [ "$(boot_sys)" = Darwin ] && command -v pbcopy >/dev/null 2>&1; then printf '%s' "$code" | pbcopy 2>/dev/null || :; fi
}

check_kvm() { # after the check, whose code reports kvm: a usable /dev/kvm, and the kernel warning
  [ "$(boot_sys)" = Linux ] || return 0
  printf 'warning: Firecracker supports host kernels 5.10, 6.1 and 6.18; this one is %s and the Ubuntu stock kernel is not on that list\n' "$(boot_kernel)"
}

need_kvm() {
  [ "$(boot_sys)" = Linux ] || return 0
  boot_kvm || die kvm '/dev/kvm is missing or not readable and writable by you; send your code to the owner.'
}

parse_args() { # H1's grammar (line.parse_args is the oracle): sets mode, line_serial, min, gw_serial, elevated, or says args
  mode=check line_serial= min= gw_serial= elevated= have_serial= have_min= have_gw=
  while [ $# -gt 0 ]; do
    case $1 in
      --install | --update | --uninstall | --status) [ "$mode" = check ] || usage; mode=${1#--}; shift; continue ;;
      --elevated) [ -z "$elevated" ] || usage; elevated=1; shift; continue ;;
    esac
    [ $# -ge 2 ] || usage
    case $1 in
      --serial) [ -z "$have_serial" ] || usage; have_serial=1; line_serial=$2 ;;
      --min-serial) [ -z "$have_min" ] || usage; have_min=1; min=$2 ;;
      --gw-serial) [ -z "$have_gw" ] || usage; have_gw=1; gw_serial=$2 ;;
      *) usage ;;
    esac
    shift 2
  done
  wants=$(printf '%s\n' "$GRAMMAR" | tr ' ' '\n' | sed -n "s/^$mode://p")
  for pair in serial:$have_serial min-serial:$have_min gw-serial:$have_gw; do # exactly the numbers the mode carries
    case ",$wants," in
      *",${pair%%:*},"*) [ -n "${pair#*:}" ] || usage ;;
      *) [ -z "${pair#*:}" ] || usage ;;
    esac
  done
  [ -z "$elevated" ] || case $mode in install | update | uninstall) ;; *) usage ;; esac
  canon "$line_serial" && canon "$min" && [ "$line_serial" -ge "$min" ] || usage
  [ -z "$have_gw" ] || canon "$gw_serial" || usage
}

check_installed() { # H2: an install over an installed host and an update over none are refused before any network; AF12: a half install is neither
  ! boot_unfinished || die install-failed "$UNFINISHED_SAY"
  if boot_installed; then
    [ "$mode" != install ] || die installed 'This computer is already installed. Use the update line to update it. Nothing was changed.'
  else
    [ "$mode" != update ] || die not-installed 'Nothing is installed on this computer. Use the install line. Nothing was changed.'
  fi
}

mode_uninstall() { # H2: no network, no signature, no expiry: an expired, revoked or withdrawn line must still remove the software
  printf 'serial %s min-serial %s\n' "$line_serial" "$min"
  if boot_installed; then
    if [ -n "$elevated" ]; then boot_removal; else boot_elevated_run; fi
  elif [ -z "$elevated" ] && boot_leftover; then boot_elevated_run # AF26: no journal but the fleet's own things are here: the loader removes them by the fixed list
  else done_ok uninstall 'Nothing was installed.'; fi
}

latest_head() { # the signed source_head of the release the line names; prints nothing on any failure (never a refusal)
  (
    die() { exit 1; }
    utc "$EXPIRES" && [ "$(digits "$EXPIRES")" -gt "$(digits "$(boot_now)")" ] || exit 1
    get install.json 8192
    get install.json.sig 4096
    verify_install
    read_install >/dev/null
    check_install
    handoff_notice
    printf '%s\n' "$src_head"
  ) 2>/dev/null
}

read_status() { # the public status.json, at most 4096 bytes, strict flat JSON, display only: st_state, st_head
  st_state=not-installed st_head=
  [ -e "$STATUS_FILE" ] || [ -L "$STATUS_FILE" ] || return 0
  st_state=unknown
  [ -f "$STATUS_FILE" ] && [ ! -L "$STATUS_FILE" ] && [ "$(size_of "$STATUS_FILE")" -le 4096 ] || return 0
  one=$(flat "$STATUS_FILE")
  [ -n "$(printf '%s\n' "$one" | sed -En "/$STATUS_JSON/p")" ] || return 0
  st_head=$(printf '%s' "$one" | sed -n 's/.*"installed_head":"\([0-9a-f]\{40\}\)".*/\1/p')
  case $one in
    *'"revoked":true'*) st_state=revoked ;;
    *'"state":"awaiting-login"'*) st_state=awaiting-login ;; # M05s: a FileVault Mac at pre-boot
    *'"paused":true'*) st_state=paused ;;
    *) st_state=installed ;;
  esac
}

mode_status() { # H2: refusals are args tools key temp only (os and arch only on Windows); a failed fetch or chain is `latest: unknown`
  if boot_unfinished; then printf 'STATUS unfinished\n%s\n' "$UNFINISHED_SAY"; return 0; fi # AF12, before status.json (a half install may have none)
  read_status
  latest=
  if [ "$st_state" != not-installed ]; then
    printf 'installed %s\n' "${st_head:-?}"
    make_tmp
    BASE=$RELEASES/install-$line_serial
    got=$(latest_head)
    printf '%s\n' "$got" | sed -n '/^successor /p'
    latest=$(printf '%s\n' "$got" | sed -n '/^[0-9a-f]\{40\}$/p')
    if [ -n "$latest" ]; then printf 'latest %s\n' "$latest"; else echo 'latest: unknown'; fi
  fi
  state=$st_state
  if [ "$state" = installed ]; then
    if [ -z "$latest" ] || [ -z "$st_head" ]; then state=unknown; elif [ "$latest" = "$st_head" ]; then state=installed-current; else state=installed-behind; fi
  fi
  case $state in
    installed-current) say='This computer has the latest release.' ;;
    installed-behind) say='A newer release is out. Ask the owner for the update line.' ;;
    paused) say='The software is installed and paused.' ;;
    revoked) say='Removed by MirrorStack. You can uninstall it with the uninstall line.' ;;
    awaiting-login) say='This Mac restarted and is waiting for someone to log in; the software starts again after you log in.' ;;
    not-installed) say='Nothing is installed on this computer.' ;;
    *) say='The state of this computer could not be read. Tell the owner.' ;;
  esac
  printf 'STATUS %s\n%s\n' "$state" "$say"
}

start_self() { # this very file's hash, printed first: the helper compares it by another route
  [ -f "$SELF" ] && [ ! -L "$SELF" ] || die self 'Run the downloaded file with sh; do not pipe it. Nothing was run.'
  self_sha=$(sha256_of "$SELF")
  printf 'bootstrap sha256 %s\n' "$self_sha"
}

# H4 POSIX step 2, the loader sudo runs as root: LOADER is a constant (no interpolation, no single quote); loader_text puts this
# machine's constants line (stage, install folder, hash tool; a Mac's differ, M05p) in front, and that line is the only thing a test replaces. Install and update: a root-only stage folder under D (links refused), bootstrap.sh of the release
# fetched into it, its sha256 compared with the one the unelevated half verified BEFORE it runs, the stage removed by trap
# (AF12: and the stage root when empty, and V, the vendor folder, when this run made it; a run killed past trapping leaves a
# folder that the next run sweeps after a day).
# Uninstall: the installed copy runs only if its sha256 is the one uninstall.json journals (H11) under the exact key
# "bootstrap_sha256" (a lowercase hex string; I09 and LX05 write it, this loader reads it, and a different key refuses every
# uninstall). It prints its own refusals and exits 10, so the parent knows a refusal is already on stdout. Its first line leaves the folder the
# line was pasted in (G-AUD-BOOT-SH-1): sudo keeps the working folder, and root must run nothing that another user could have put there.
LOADER='cd /
set -eu
umask 077
fail() { printf "REFUSED %s\n%s\n" "$1" "$2"; exit 10; }
die() { fail "$1" "$2"; }
boot_cmd() { "$@"; }
own() { [ -e "$1" ] && [ ! -L "$1" ] && { set -- $(ls -ldn "$1"); [ "$3" = "$Z" ]; }; }
sealed() { own "$1" && { set -- $(ls -ldn "$1"); case $1 in drwx------ | drwx------[.+@]) ;; *) false ;; esac; }; }
[ "$(id -u)" = "$Z" ] || fail elevate "This step must run as root through sudo. Nothing was changed."
h=$1 n=$2
shift 2
case $n in "" | *[!0-9]*) fail args "The serial is not a number. Nothing was changed." ;; esac
if [ "$1" = --uninstall ]; then
  gone="The removal program is missing. Tell the owner."
  if [ -n "${FIX_USER:-}" ] && [ ! -e "$I/uninstall.json" ] && [ ! -L "$I/uninstall.json" ]; then # AF26: no journal and no link in its place: root runs its own fixed list, never a file the person wrote; a Mac has no FIX_USER
    INSTALL_DIR=$I
    fixed_removal
    printf "DONE uninstall\nThe software is removed by the fixed list.\n"
    exit 0
  fi
  own "$I/uninstall.json" && own "$I/boot/bootstrap.sh" && own "$I/boot" || fail install-failed "$gone"
  want=$(tr -d " \t\r\n" < "$I/uninstall.json" | sed -n "s/.*\"bootstrap_sha256\":\"\([0-9a-f]\{64\}\)\".*/\1/p")
  got=$($H "$I/boot/bootstrap.sh" | cut -c1-64)
  [ -n "$want" ] && [ "$got" = "$want" ] || fail install-failed "$gone"
  exec /bin/sh "$I/boot/bootstrap.sh" "$@"
fi
case $h in *[!0-9a-f]*) fail boot-hash "The bootstrap hash is not one. Nothing was changed." ;; esac
[ ${#h} -eq 64 ] || fail boot-hash "The bootstrap hash is not one. Nothing was changed."
mk= s=
if [ -e "$D" ] || [ -L "$D" ]; then sealed "$D"; else { [ -z "${V:-}" ] || [ -d "$V" ] || mk=1; install -d -m 0700 -o "$Z" "$D"; }; fi || fail temp "The stage folder is not a private folder of root. Nothing was changed."
tidy() { [ -z "$s" ] || rm -rf "$s"; rmdir "$D" 2>/dev/null || :; [ -z "${V:-}" ] || [ -z "$mk" ] || rmdir "$V" 2>/dev/null || :; }
trap tidy EXIT
for o in "$D"/*; do
  b=${o##*/}
  case $b in "" | *[!0-9a-f]*) continue ;; esac
  [ ${#b} -eq 18 ] && sealed "$o" && [ -n "$(find "$o" -maxdepth 0 -mmin +1440)" ] && rm -rf "$o" || :
done
u=$(od -An -N9 -tx1 /dev/urandom | tr -d " \n")
{ [ ${#u} -eq 18 ] && [ ! -e "$D/$u" ] && [ ! -L "$D/$u" ] && install -d -m 0700 -o "$Z" "$D/$u" && s=$D/$u && sealed "$s"; } || fail temp "Could not make a private stage folder. Nothing was changed."
trap "exit 1" HUP INT TERM
"$C" -fsSL --max-redirs 3 --proto =https --proto-redir =https --tlsv1.2 --connect-timeout 20 --max-time 120 --max-filesize 262144 \
  -o "$s/bootstrap.sh" "$R/install-$n/bootstrap.sh" || fail fetch "Could not download bootstrap.sh. Nothing was changed. Tell the owner."
[ -f "$s/bootstrap.sh" ] && [ ! -L "$s/bootstrap.sh" ] && [ "$($H "$s/bootstrap.sh" | cut -c1-64)" = "$h" ] ||
  fail boot-hash "This bootstrap is not the one the owner signed. Nothing was changed. Tell the owner."
rc=0
/bin/sh "$s/bootstrap.sh" "$@" || rc=$?
exit $rc'

loader_text() { # M05p: the loader as root runs it: this machine's constants line (ours alone: no input reaches it), `cd /`, FIXED_SH (AF26), then the rest of LOADER
  lv= # V: the vendor folder that holds the stage root on a Mac, which the loader removes after itself when it made it (AF12)
  lt=$FIX_TABLE lu=$FIX_USER lw=$FIX_VAR lf=$FIX_FETCH lo=$FIX_STOP lp=$FIX_PATHS # AF26: the fixed list; a Mac has none, which turns the loader's no-journal branch off
  if [ "$(boot_sys)" = Darwin ]; then lh='/usr/bin/shasum -a 256' lv=$MAC_DIR lt= lu= lw= lf= lo= lp= # root has no Homebrew on its PATH: the Mac's tool is named whole
  else lh=$(hash_tool); fi
  printf 'FS="%s" FIX_TABLE="%s" FIX_USER="%s" FIX_VAR="%s" FIX_FETCH="%s" FIX_STOP="%s" FIX_PATHS="%s" C="%s" D="%s" Z=%s H="%s" I="%s" R=%s V="%s"\ncd /\n%s%s' \
    "$FS" "$lt" "$lu" "$lw" "$lf" "$lo" "$lp" "$ROOT_CURL" "$STAGE_ROOT" "$ROOT_UID" "$lh" "$INSTALL_DIR" "$RELEASES" "$lv" "$FIXED_SH" "${LOADER#cd /}"
}

# Output contract of the root half on POSIX (H5 deviation: its stdout is relayed unfiltered, because it is already inside the verified
# bundle): posix.py prints exactly `DONE <mode>` and one sentence on stdout and exits 0, or its `REFUSED <word>` and one sentence
# and exits 1. This script prints no DONE line for an install or update itself; the uninstall path prints its own (done_ok).
boot_elevated_run() { # the one privilege call (H4 POSIX step 1): a fixed argv with the hash, the serial and the line's own flags, never the invite
  [ -x "$SUDO" ] || die tools 'This computer has no sudo; install it (sudo apt install sudo) and paste the line again. Nothing was changed.'
  [ "$mode" = uninstall ] && arg_sha=- || arg_sha=$self_sha
  set -- "$SUDO" -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /bin/sh -c "$(loader_text)" mirrorstack-stage \
    "$arg_sha" "$line_serial" "--$mode" --serial "$line_serial" --min-serial "$min"
  [ "$mode" = uninstall ] || set -- "$@" --gw-serial "$gw_serial"
  rc=0
  "$@" --elevated || rc=$?
  case $rc in
    0) return 0 ;;
    10) exit 1 ;; # the root half printed REFUSED and its sentence as the last two lines
  esac
  die elevate 'The administrator step was refused or cancelled, so the step may not have run. Tell the owner.'
}

elevated_guard() { # H4: root, and this very file sits in a root-owned folder the loader made under STAGE_ROOT (the installed copy for uninstall)
  DIE_RC=10
  [ "$(boot_uid)" = "$ROOT_UID" ] || die elevate 'This step runs as root through sudo, from the install line. Nothing was changed.'
  here=$(cd "$(dirname "$SELF")" 2>/dev/null && pwd -P) || die elevate 'This file is not where the loader put it. Nothing was changed.'
  case $mode:$here in
    uninstall:"$INSTALL_DIR/boot") ;;
    install:"$STAGE_ROOT"/?* | update:"$STAGE_ROOT"/?*) case ${here#"$STAGE_ROOT"/} in */*) here= ;; esac ;;
    *) here= ;;
  esac
  [ -n "$here" ] && [ ! -L "$SELF" ] || die elevate 'This file is not where the loader put it. Nothing was changed.'
  set -- $(ls -ldn "$here")
  case $1 in d????-??-?*) [ "$3" = "$ROOT_UID" ] ;; *) false ;; esac || die elevate 'The folder of this file is not private to root. Nothing was changed.'
  [ "$mode" = uninstall ] || { TMPDIR=$here; export TMPDIR; } # the temp folder is the stage: every file lands in it
}

boot_cmd() { "$@"; } # the one way the fixed removal runs a program (an absolute path); a test replaces it

tree_ok() { # the installed folder is what uninstall.json journals (install.py's `tampered`): no link, nothing writable by others, every file listed with its sha256, none unlisted; a listed file that is gone is fine
  rows=$(tr -d ' \t\r\n' < "$INSTALL_DIR/uninstall.json" | sed -n 's/.*"tree":{\([^}]*\)}.*/\1/p' | tr ',' '\n')
  [ -n "$rows" ] && [ -z "$(printf '%s\n' "$rows" | sed -n '\|^"[A-Za-z0-9_./-]*":"[0-9a-f]\{64\}"$|!p')" ] || return 1
  [ -z "$(find "$INSTALL_DIR" \( -type l -o ! -uid "$ROOT_UID" -o -perm -020 -o -perm -002 \) -print)" ] || return 1
  files=$(find "$INSTALL_DIR" -type f ! -path "$INSTALL_DIR/uninstall.json" -print | sed "s|^$INSTALL_DIR/||")
  [ -z "$(printf '%s\n' "$files" | sed -n '\|^[A-Za-z0-9_./-]*$|!p')" ] || return 1
  for rel in $files; do
    want=$(printf '%s\n' "$rows" | awk -F'"' -v r="$rel" '$2 == r { print $4 }')
    [ -n "$want" ] && [ "$(sha256_of "$INSTALL_DIR/$rel")" = "$want" ] || return 1
  done
}

# G-LX05-1: install.py's FIXED by constants, no Python of the installed tree; the installed copy and its journal go last, so a failed run can be run again.
# AF17: the download account only when the journal names it; one that was there before (the join's) is not ours; the 26.04 boot-time loader caches the profile.
# AF26: FIXED_SH below is this very function as one constant (no single quote, no interpolation; a test holds the two equal): the LOADER carries it
# (loader_text puts it after `cd /`), so root can remove a machine whose journal is gone with no file the person could write.
# Every rm ends in `|| :`: under set -e a rm that cannot delete (an immutable file, a busy mount) must not end the list silently with exit 1; the scan below says it.
fixed_removal() {
  for u in $FIX_STOP; do boot_cmd /usr/bin/systemctl stop "$u" || :; done
  boot_cmd /usr/sbin/nft delete table inet "$FIX_TABLE" || :
  boot_cmd /usr/sbin/apparmor_parser -R "$FS/etc/apparmor.d/mirrorstack-fleet-l1" || :
  for p in $FIX_PATHS; do rm -rf "${FS}${p}" || :; done
  boot_cmd /usr/sbin/userdel "$FIX_USER" || :
  fetch=
  case $(tr -d " \t\r\n" 2>/dev/null < "$INSTALL_DIR/uninstall.json" || :) in *\[\"user\",\"$FIX_FETCH\"\]*) fetch=1 ;; esac
  [ -z "$fetch" ] || boot_cmd /usr/sbin/userdel "$FIX_FETCH" || :
  for p in "${FS}"/var/cache/apparmor/*/mirrorstack-fleet-l1; do rm -rf "$p" || :; done
  rm -rf "${FS}${FIX_VAR}" || :
  boot_cmd /usr/bin/systemctl daemon-reload || :
  left=
  for p in $FIX_PATHS "$FIX_VAR"; do [ ! -e "${FS}${p}" ] && [ ! -L "${FS}${p}" ] || left=1; done
  for p in "${FS}"/var/cache/apparmor/*/mirrorstack-fleet-l1; do [ ! -e "$p" ] && [ ! -L "$p" ] || left=1; done
  ! boot_cmd /usr/bin/getent passwd "$FIX_USER" >/dev/null 2>&1 || left=1
  [ -z "$fetch" ] || ! boot_cmd /usr/bin/getent passwd "$FIX_FETCH" >/dev/null 2>&1 || left=1
  ! boot_cmd /usr/sbin/nft list table inet "$FIX_TABLE" >/dev/null 2>&1 || left=1
  [ -z "$left" ] || die install-failed "The removal did not finish. Tell the owner."
  rm -rf "$INSTALL_DIR" || :
  [ ! -e "$INSTALL_DIR" ] && [ ! -L "$INSTALL_DIR" ] || die install-failed "The removal did not finish. Tell the owner."
}
FIXED_SH='fixed_removal() {
  for u in $FIX_STOP; do boot_cmd /usr/bin/systemctl stop "$u" || :; done
  boot_cmd /usr/sbin/nft delete table inet "$FIX_TABLE" || :
  boot_cmd /usr/sbin/apparmor_parser -R "$FS/etc/apparmor.d/mirrorstack-fleet-l1" || :
  for p in $FIX_PATHS; do rm -rf "${FS}${p}" || :; done
  boot_cmd /usr/sbin/userdel "$FIX_USER" || :
  fetch=
  case $(tr -d " \t\r\n" 2>/dev/null < "$INSTALL_DIR/uninstall.json" || :) in *\[\"user\",\"$FIX_FETCH\"\]*) fetch=1 ;; esac
  [ -z "$fetch" ] || boot_cmd /usr/sbin/userdel "$FIX_FETCH" || :
  for p in "${FS}"/var/cache/apparmor/*/mirrorstack-fleet-l1; do rm -rf "$p" || :; done
  rm -rf "${FS}${FIX_VAR}" || :
  boot_cmd /usr/bin/systemctl daemon-reload || :
  left=
  for p in $FIX_PATHS "$FIX_VAR"; do [ ! -e "${FS}${p}" ] && [ ! -L "${FS}${p}" ] || left=1; done
  for p in "${FS}"/var/cache/apparmor/*/mirrorstack-fleet-l1; do [ ! -e "$p" ] && [ ! -L "$p" ] || left=1; done
  ! boot_cmd /usr/bin/getent passwd "$FIX_USER" >/dev/null 2>&1 || left=1
  [ -z "$fetch" ] || ! boot_cmd /usr/bin/getent passwd "$FIX_FETCH" >/dev/null 2>&1 || left=1
  ! boot_cmd /usr/sbin/nft list table inet "$FIX_TABLE" >/dev/null 2>&1 || left=1
  [ -z "$left" ] || die install-failed "The removal did not finish. Tell the owner."
  rm -rf "$INSTALL_DIR" || :
  [ ! -e "$INSTALL_DIR" ] && [ ! -L "$INSTALL_DIR" ] || die install-failed "The removal did not finish. Tell the owner."
}'

mac_fixed_removal() { # G-M05p-2: mac/install.py's FIXED by constants (dscl, then the folders), no Python; the install folder (journal and this copy) goes last, so a failed run can be run again
  for n in $FIXM_ROLES; do
    boot_cmd /usr/bin/dscl . -delete "/Users/$n" || :
    boot_cmd /usr/bin/dscl . -delete "/Groups/$n" || :
  done
  rm -rf "${FS}${FIXM_PLIST}"
  find "${FS}${MAC_DIR}" -mindepth 1 ! -path "$INSTALL_DIR" ! -path "$INSTALL_DIR/*" -delete 2>/dev/null || :
  left=
  for n in $FIXM_ROLES; do
    ! boot_cmd /usr/bin/dscl . -read "/Users/$n" >/dev/null 2>&1 || left=1
    ! boot_cmd /usr/bin/dscl . -read "/Groups/$n" >/dev/null 2>&1 || left=1
  done
  [ ! -e "${FS}${FIXM_PLIST}" ] && [ ! -L "${FS}${FIXM_PLIST}" ] || left=1
  [ -z "$(find "${FS}${MAC_DIR}" -mindepth 1 ! -path "$INSTALL_DIR" ! -path "$INSTALL_DIR/*" -print 2>/dev/null)" ] || left=1
  [ -z "$left" ] || die install-failed 'The removal did not finish. Tell the owner.'
  rm -rf "${FS}${MAC_DIR}"
  [ ! -e "${FS}${MAC_DIR}" ] && [ ! -L "${FS}${MAC_DIR}" ] || die install-failed 'The removal did not finish. Tell the owner.'
}

mac_python() { # G-M05p-2: the removal's Python is the pin of the kit.json the install journaled (tree_ok has just checked it), fetched here; any failure leaves PY empty
  kitone=$(flat "$INSTALL_DIR/kit.json" 2>/dev/null) || return 0
  make_tmp
  BASE=
  PY=$( (die() { exit 1; }; fetch_python && printf '%s' "$PY") 2>/dev/null) || PY=
}

mac_removal() { # G-M05p-2, H11: a Mac never takes the Linux list. The installed removal (it tells the gateway first) runs only if the tree is as journaled and the pinned Python is had; any doubt takes the Mac's fixed list
  if [ -f "$INSTALL_DIR/bin/fleet-carrier-mac.py" ] && tree_ok; then
    mac_python
    if python_ok; then
      "$PY" -I -X utf8 "$INSTALL_DIR/bin/fleet-carrier-mac.py" uninstall || die install-failed 'The removal did not finish. Tell the owner.'
      done_ok uninstall 'The software is removed.'
      return 0
    fi
    printf 'The pinned Python could not be had or does not pass; removing by the fixed list\n'
  else
    printf 'tampered: the installed files are not the ones the install made, or cannot be checked; removing by the fixed list\n'
  fi
  mac_fixed_removal
  done_ok uninstall 'The software is removed by the fixed list.'
}

boot_removal() { # H11, G-LX05-1: the installed removal runs the installed Python only if the tree is as journaled; any doubt takes the fixed one
  [ "$(boot_sys)" != Darwin ] || { mac_removal; return; }
  if python_ok && [ -f "$INSTALL_DIR/bin/fleet-carrier.py" ] && tree_ok; then
    if "$PY" -I -X utf8 "$INSTALL_DIR/bin/fleet-carrier.py" uninstall; then
      done_ok uninstall 'The software is removed.'
      return 0
    fi
    printf 'The installed removal did not finish; removing by the fixed list\n' # AF17: it kept the journal and said what is left; the fixed list is the second try
    fixed_removal
    done_ok uninstall 'The software is removed by the fixed list.'
    return 0
  fi
  if boot_unfinished; then printf 'The last install did not finish; removing by the fixed list\n' # AF12: a journal with no tree is not tampering
  else printf 'tampered: the installed files are not the ones the install made, or cannot be checked; removing by the fixed list\n'; fi
  fixed_removal
  done_ok uninstall 'The software is removed by the fixed list.'
}

use_platform() { # M05p: a Mac's folders, and no Python until fetch_python names the stage's (a fresh Mac's /usr/bin/python3 is a Command Line Tools stub)
  [ "$(boot_sys)" = Darwin ] || return 0
  STAGE_ROOT=$MAC_STAGE_ROOT INSTALL_DIR=$MAC_INSTALL_DIR STATUS_FILE=$MAC_STATUS_FILE PY=
}

fetch_python() { # M05p: on a Mac, kit.json's python_mac (the owner signed it) fetched by hash and unpacked in the stage; PY is then that copy and no other
  [ "$(boot_sys)" = Darwin ] || return 0
  pm=$(printf '%s' "$kitone" | sed -n 's/.*"python_mac":{\([^}]*\)}.*/\1/p')
  py_ver=$(printf '%s' "$pm" | sed -n 's/.*"version":"\([0-9]\{1,2\}\.[0-9]\{1,2\}\.[0-9]\{1,3\}\)".*/\1/p')
  py_url=$(printf '%s' "$pm" | sed -n 's/.*"url":"\([^"]\{1,200\}\)".*/\1/p')
  py_sha=$(printf '%s' "$pm" | sed -n 's/.*"sha256":"\([0-9a-f]\{64\}\)".*/\1/p')
  py_rest=${py_url#"$PBS"/} py_tag= py_file=
  [ "$py_rest" != "$py_url" ] && py_tag=${py_rest%%/*} py_file=${py_rest#*/}
  case $py_tag in '' | *[!0-9]*) py_file= ;; esac
  [ -n "$py_ver" ] && [ -n "$py_sha" ] && [ "$py_file" = "cpython-$py_ver+$py_tag-aarch64-apple-darwin-install_only.tar.gz" ] ||
    die python-lock 'kit.json pins no Python for this Mac. Nothing was changed. Tell the owner.'
  py_base=$BASE BASE=$PBS/$py_tag
  get "$py_file" "$MAC_PY_CAP"
  BASE=$py_base
  [ "$(sha256_of "$T/$py_file")" = "$py_sha" ] || die python-hash 'The Python download is not the one the owner signed. Nothing was changed. Tell the owner.'
  mkdir "$T/py" && (cd "$T/py" && "$TAR" -xzf "$T/$py_file" --no-same-owner) 2>/dev/null ||
    die python-install 'The Python download would not unpack. Nothing was changed. Tell the owner.'
  PY=$T/py/python/bin/python3
}

python_ok() { # 3.12 or newer; a Mac's pinned build must also hold zstd, which the arm64 disk is (G-M05p-1: the probe runs through the $PY fetch_python named)
  [ -x "$PY" ] && "$PY" -I -c 'import sys; sys.exit(sys.version_info < (3, 12))' >/dev/null 2>&1 || return 1 # -I: as root, a -c reads no linecache.py of the folder the line was pasted in (G-AUD-BOOT-SH-1)
  [ "$(boot_sys)" != Darwin ] || "$PY" -I -c 'from compression import zstd; zstd.decompress(zstd.compress(b"disk"))' >/dev/null 2>&1
}

boot_secret() { # one line typed with no echo into $secret (the keyboard is the one thing a test replaces)
  old=$(stty -g 2>/dev/null) || old=
  [ -z "$old" ] || { trap 'stty "$old" 2>/dev/null; clean; exit 1' HUP INT TERM; stty -echo; }
  read -r secret || secret=
  [ -z "$old" ] || { stty "$old" 2>/dev/null; trap 'clean; exit 1' HUP INT TERM; }
  printf '\n' >&2
}

ask_invite() { # H1: three tries at the code's shape; it reaches only the 0600 files in the stage, never an argv or a URL
  tries=0 inv=
  while [ "$tries" -lt 3 ]; do
    printf 'Invite code (XXXXX-XXXXX, nothing shows as you type): ' >&2
    boot_secret
    inv=$(printf '%s' "$secret" | tr 'a-z' 'A-Z' | tr -d ' -')
    secret=
    case $inv in '' | *[!23456789CFGHJMPQRVWX]*) ;; *) [ ${#inv} -ne 10 ] || break ;; esac
    inv=
    tries=$((tries + 1))
  done
  [ -n "$inv" ] || die invite 'That is not an invite code (ten letters and digits, XXXXX-XXXXX). Ask the owner for one. Nothing was changed.'
  printf '%s\n' "$inv" > "$T/priv/inv.txt"
  printf 'header = "Authorization: FleetInvite %s"\n' "$inv" > "$T/priv/inv.cfg"
  inv=
}

kget() { # kget NAME MAX SECS: NAME from the kit host with the invite header, Authorization: FleetInvite <code> (curl -K), at most MAX bytes read, never a redirect (H3)
  rm -f "$T/kdump" "$T/krc"
  { curl -sS -K "$T/priv/inv.cfg" --max-redirs 0 --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time "$3" \
      -D "$T/kdump" -o - "$kit_base$1" 2>/dev/null; echo $? > "$T/krc"; } | head -c $(($2 + 1)) > "$T/$1"
  case $(awk '/^HTTP\//{ c = $2 } END { print c }' "$T/kdump" 2>/dev/null) in
    200) ;;
    404) die invite-refused 'The invite is not valid for this release (wrong, used up or expired). Ask the owner for a new one. Nothing was changed.' ;;
    429) die rate-limited 'Too many tries came from this network, or the server is busy. Wait an hour, then try again. Nothing was changed.' ;;
    *) die fetch "Could not download $1 from the install server. Nothing was changed. Tell the owner." ;;
  esac
  [ "$(size_of "$T/$1")" -le "$2" ] || die size "$1 is bigger than the $2 bytes it may be. Nothing was changed. Tell the owner."
  [ "$(cat "$T/krc" 2>/dev/null)" = 0 ] || die fetch "The download of $1 was cut off; run the line again. Nothing was changed."
}

read_bundle() { # the signed bundle object: its url (H3's shape, the kit host), size, sha256, head, tree
  bun=$(flat "$T/install.json" | sed -n 's/.*"bundle":{\([^}]*\)}.*/\1/p')
  bundle_url=$(printf '%s' "$bun" | sed -n 's/.*"url":"\([^"]*\)".*/\1/p')
  bundle_size=$(printf '%s' "$bun" | sed -n 's/.*"size":\([0-9]\{1,10\}\).*/\1/p')
  bundle_sha=$(printf '%s' "$bun" | sed -n 's/.*"sha256":"\([0-9a-f]\{64\}\)".*/\1/p')
  bundle_head=$(printf '%s' "$bun" | sed -n 's/.*"head":"\([0-9a-f]\{40\}\)".*/\1/p')
  bundle_tree=$(printf '%s' "$bun" | sed -n 's/.*"tree":"\([0-9a-f]\{40\}\)".*/\1/p')
  lock_sha=$(flat "$T/install.json" | sed -n 's/.*"lock_sha256":"\([0-9a-f]\{64\}\)".*/\1/p')
  host=${bundle_url#https://}
  host=${host%%/*}
  case $bundle_url in https://*/v1/kit/"$serial"/bundle.tar) ;; *) host= ;; esac
  case $host in # a CA name on port 443: not the gateway edge's port, not GitHub
    '' | .* | *. | *..* | *[!a-z0-9.-]* | github.com | *.github.com | *githubusercontent.com) host= ;;
    *.*) ;;
    *) host= ;;
  esac
  [ -n "$host" ] && [ -n "$bundle_size" ] && hex64 "$bundle_sha" && [ -n "$bundle_head" ] && [ -n "$bundle_tree" ] && hex64 "$lock_sha" &&
    [ "$bundle_size" -ge 1 ] && [ "$bundle_size" -le 268435456 ] ||
    die form 'install.json names no bundle this bootstrap may fetch. Nothing was changed. Tell the owner.'
  kit_base=${bundle_url%bundle.tar}
}

read_gateway() { # H3 step 2: the signed gateway record is live: a serial of at least G (never 0), an address, r9_closed present
  g=$(flat "$T/gateway.json" | sed 's/"next":{[^}]*}//') # a rotation's `next` object holds an address and a serial of its own: set it aside
  gw_s=$(printf '%s' "$g" | sed -n 's/.*"serial":\([0-9]\{1,10\}\)[,}].*/\1/p')
  gw_a=$(printf '%s' "$g" | sed -n 's/.*"address":"\([^"]\{1,200\}\)".*/\1/p')
  case $g in *'"r9_closed":'*) ;; *) gw_s= ;; esac
  [ -n "$gw_s" ] && [ -n "$gw_a" ] && [ "$(dec "$gw_s")" -gt 0 ] && [ "$(dec "$gw_s")" -ge "$gw_serial" ] ||
    die gateway-not-live 'The gateway is not live yet, or is older than your line. Ask the owner. Nothing was changed.'
}

stage_install() { # H3 steps 1-6, the elevated half after the chain: the pin, the invite, the gateway record, the bundle, the closure, posix.py
  read_kit
  fetch_python
  if ! python_ok; then
    [ "$(boot_sys)" != Darwin ] || die python-old 'The Python the owner pinned for this Mac is not 3.12 or newer, or has no zstd. Nothing was changed. Tell the owner.'
    die tools 'This computer has no /usr/bin/python3 of version 3.12 or newer. Install python3 and paste the line again. Nothing was changed.'
  fi
  kit_file verify-archive.py 4194304
  get deploy-pin.json 4096
  get deploy-pin.json.sig 4096
  read_bundle
  mkdir "$T/priv" "$T/x"
  ask_invite
  kget gateway.json 65536 120
  kget gateway.json.sig 4096 120
  verify_sig gateway.json gateway.json.sig "$NS_PIN" gateway-pin 'gateway.json is not signed by the owner key in this file. Nothing was changed. Tell the owner.'
  read_gateway
  kget bundle.tar "$bundle_size" 1800
  rm -f "$T/priv/inv.cfg"
  [ "$(size_of "$T/bundle.tar")" -eq "$bundle_size" ] && [ "$(sha256_of "$T/bundle.tar")" = "$bundle_sha" ] ||
    die bundle-hash 'The download is not the bundle the owner signed. Run the line again; if it repeats, tell the owner. Nothing was changed.'
  printf 'ssh-ed25519 %s\n' "$key_blob" > "$T/x/owner-pin.pub"
  (cd "$T" && limited "$CHECK_LIMIT" "$PY" -I -X utf8 verify-archive.py --closure bundle.tar x/owner-pin.pub deploy-pin.json deploy-pin.json.sig x) \
    > "$T/closure.out" 2>&1 || die closure 'The bundle does not match the owner-signed pin. Nothing was changed. Tell the owner.'
  tree_dir= count=0
  for d in "$T"/x/mirrorstack-fleet-*; do
    [ -d "$d" ] && [ ! -L "$d" ] || continue
    tree_dir=$d count=$((count + 1))
  done
  [ "$count" -eq 1 ] || die closure 'The bundle does not hold exactly one verified release folder. Nothing was changed. Tell the owner.'
  stamp=$(flat "$tree_dir/ARCHIVE-VERIFIED" 2>/dev/null)
  [ "$(printf '%s' "$stamp" | sed -n 's/.*"head":"\([0-9a-f]\{40\}\)".*/\1/p')" = "$bundle_head" ] &&
    [ "$(printf '%s' "$stamp" | sed -n 's/.*"tree":"\([0-9a-f]\{40\}\)".*/\1/p')" = "$bundle_tree" ] ||
    die pin-mismatch 'The signed pin and the release name different bundles. Nothing was changed. Tell the owner.'
  [ "$(sha256_of "$tree_dir/fleet/carrier/carrier.lock.json")" = "$lock_sha" ] ||
    die carrier-lock 'The bundle holds a different carrier lock than the release names. Nothing was changed. Tell the owner.'
  rc=0
  "$PY" -I -X utf8 "$tree_dir/fleet/install/posix.py" --head "$bundle_head" --owner-pin "$T/x/owner-pin.pub" --gw-serial "$gw_serial" \
    --gw-json "$T/gateway.json" --gw-sig "$T/gateway.json.sig" --invite-file "$T/priv/inv.txt" --bootstrap-file "$SELF" --mode "$mode" || rc=$?
  case $rc in
    0) return 0 ;;
    1) exit 10 ;; # posix.py printed its REFUSED line and sentence (a result file is the Windows channel; here stdout is)
  esac
  die install-failed 'The install stopped. Nothing is left running. Tell the owner.'
}


boot_main() {
  parse_args "$@"
  trap clean EXIT
  trap 'clean; exit 1' HUP INT TERM
  use_platform
  [ -z "$elevated" ] || elevated_guard
  case $mode in
    uninstall) check_os; check_machine; start_self; key_shape; mode_uninstall; return ;;
    status) check_tools nosig; check_machine; start_self; key_shape; mode_status; return ;;
  esac
  check_tools
  check_machine
  start_self
  check_key
  case $mode in install | update) check_installed ;; esac # read from this machine only, before the clock and the network
  utc "$EXPIRES" && [ "$(digits "$EXPIRES")" -gt "$(digits "$(boot_now)")" ] ||
    die expired "This bootstrap ran out at $EXPIRES; ask for a fresh line. Nothing was run."
  BASE=$RELEASES/install-$line_serial
  make_tmp
  get install.json 8192 "$T/install.json.hdr"
  check_clock "$T/install.json.hdr"
  get install.json.sig 4096
  verify_install
  read_install
  check_install
  handoff_notice
  case $mode in # H2's unelevated half ends here: kit.json by its hash, a kit of serial 5 or more, then the elevated half
    install | update)
      fetch_kit_json
      [ "$kit_serial" -ge "$MIN_KIT_SERIAL" ] || die kit-old 'This release is older than the kit that installs. Ask the owner for a fresh line. Nothing was changed.'
      if [ -n "$elevated" ]; then stage_install; else boot_elevated_run; fi
      return ;;
  esac
  run_kit
  check_kvm
  show_code
  need_kvm
}

if [ "${FLEET_BOOT_LIB:-}" != 1 ]; then boot_main "$@"; fi
