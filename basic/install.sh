#!/bin/sh
# install.sh - the one-line installer of fleet "basic mode" (the public half; the fleet code itself stays private).
#
#   curl -fsSL https://raw.githubusercontent.com/mirrorstack-ai/fleet-disk/main/basic/install.sh | sh -s -- <invite> [--host NAME]
#
# The invite is '<12 hex id>.<43 char key>.<64 hex sha256>' and is good for under one hour. It names ONE encrypted asset, inv-<id>.enc, of
# its own public release tagged inv-<id> (one release per invite: the repo's releases are immutable, so a shared release cannot take new
# assets, and a tag is never reused): a gzip tar of the private fleet tree that only that key opens. This script holds no secret and
# reaches no private URL: only fleet-disk release assets and python.org. Eight steps, each idempotent (a re-run with the same or a
# new invite resumes where the last one stopped):
#   1 check the invite, this machine, free disk and RAM, sudo      5 start the VM image build in the background
#   2 fetch + verify + decrypt + unpack the fleet code             6 Claude token (the helper's own seat, pasted into fleet-basic)
#   3 Mac: python.org Python 3.11+ (pinned pkg); Linux: python3    7 pair with the owner (send the PAIR line, wait for the answer)
#   4 install fleet-basic, the switch OFF                          8 image, doctor, mint-test, enable, READY line
# Any failure prints ONE line 'STOP <code> <why>' and exits non-zero. The invite is hostile input: it is matched against its exact shape
# BEFORE it is used in any command, goes only to openssl's stdin, and is never printed or eval'd. Everything is inside main(), called
# on the last line, so a download cut short parses as nothing and runs nothing; every child that could read stdin has it redirected, so
# none can eat the rest of the script when it arrives through a pipe.
# Test seams (only with FB_SANDBOX=1, else ignored): FB_ROOT prefixes every system path, FB_ROOT_UID is "root", FB_TTY replaces
# /dev/tty, and PATH is kept (otherwise it is reset to the system's folders).
set -u
LC_ALL=C
export LC_ALL

BASE_PREFIX=https://github.com/mirrorstack-ai/fleet-disk/releases/download/
RUNNER_APP_ID=5208968
PY_MM=3.14
PY_PKG=python-3.14.10-macos11.pkg
PY_URL=https://www.python.org/ftp/python/3.14.10/python-3.14.10-macos11.pkg
PY_SHA=286c7018aa2730f6747ca433dccdc2b31be45f078a9ea0ffa44d5f06368fd2d7
MIN_DISK_MAC_KB=47185920 # 45 GiB: the bake's peak (INSTALL.md)
MIN_DISK_LINUX_KB=10485760 # 10 GiB
MIN_MEM_LINUX_KB=11534336 # 11 GiB MemAvailable
OPENSSL_ENC='-aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -pass stdin'

say() { printf '%s\n' "$*"; }
stop() { printf 'STOP %s\n' "$*"; exit 1; }

# --- small tools -------------------------------------------------------------------------------------------------------------
sha256_file() { # sha256_file FILE: the hex digest on stdout
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else openssl dgst -sha256 "$1" | sed 's/^.* //'; fi
}
sha256_text() { # sha256_text STRING: the hex digest on stdout
  if command -v sha256sum >/dev/null 2>&1; then printf '%s' "$1" | sha256sum | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
  else printf '%s' "$1" | openssl dgst -sha256 | sed 's/^.* //'; fi
}
url_ok() { # url_ok URL KIND: https, no credentials, no port but 443, and a host of that KIND: gh = github.com, a github.com subdomain or a
  # githubusercontent.com subdomain (the release and the signed-objects host it redirects to); py = python.org or a python.org subdomain
  case $1 in https://*) ;; *) return 1 ;; esac
  _ua=${1#https://}
  _ua=${_ua%%/*}
  case $_ua in *:443) _ua=${_ua%:443} ;; esac
  case $_ua in '' | .* | *[!a-z0-9.-]*) return 1 ;; esac
  case $2:$_ua in gh:github.com | gh:*.github.com | gh:*.githubusercontent.com | py:python.org | py:*.python.org) return 0 ;; esac
  return 1
}
fetch() { # fetch URL OUT MAXBYTES [py]: https only, TLS 1.2+, no hang on a stalled link. curl follows NO redirect (--max-redirs 0, no -L):
  # GitHub's one hop to its signed-objects host is followed here, and every URL, the first and each hop, must pass url_ok first
  _fu=$1 _fn=0 _fk=${4:-gh}
  while :; do
    url_ok "$_fu" "$_fk" || return 1
    _fr=$(curl -fsS --proto '=https' --tlsv1.2 --max-redirs 0 --retry 2 --connect-timeout 20 --speed-limit 10000 --speed-time 60 \
      --max-filesize "$3" -o "$2" -w '%{http_code} %{redirect_url}' "$_fu" </dev/null) || return 1
    case ${_fr%% *} in
      200) return 0 ;;
      301 | 302 | 303 | 307 | 308) _fn=$((_fn + 1)); [ "$_fn" -le 5 ] || return 1; _fu=${_fr#* } ;;
      *) return 1 ;;
    esac
  done
}
is_hex() { # is_hex STRING LENGTH
  case $1 in '' | *[!0-9a-f]*) return 1 ;; esac
  [ "${#1}" -eq "$2" ]
}
tree_pids() { # tree_pids PID: the descendants of PID, deepest first, then PID
  for c in $(ps -A -o pid= -o ppid= | awk -v p="$1" '$2 == p { print $1 }'); do tree_pids "$c"; done
  printf '%s\n' "$1"
}
kill_tree() { # kill_tree PID: TERM a process and all its children (the bake VM is a grandchild; on Linux it runs as msvm)
  pids=$(tree_pids "$1")
  # shellcheck disable=SC2086 # numeric pids, split on purpose
  { kill $pids 2>/dev/null; sudo -n kill $pids 2>/dev/null; } </dev/null
  return 0
}
cleanup() {
  rc=$?
  trap - EXIT INT TERM HUP
  # the group redirect also hides bash's "Terminated" notice for the jobs it kills here
  [ -z "${KA_PID:-}" ] || { kill "$KA_PID"; wait "$KA_PID"; } 2>/dev/null
  [ -z "${CAF_PID:-}" ] || { kill "$CAF_PID"; wait "$CAF_PID"; } 2>/dev/null
  if [ -n "${BAKE_PID:-}" ] && kill -0 "$BAKE_PID" 2>/dev/null; then kill_tree "$BAKE_PID" 2>/dev/null; fi
  [ -z "${NEW:-}" ] || [ ! -d "$NEW" ] || sudo -n rm -rf "$NEW" </dev/null >/dev/null 2>&1 # a refused tree is not left behind
  [ -z "${TMP:-}" ] || rm -rf "$TMP"
  exit "$rc"
}

# --- the invite: its exact shape, before it is used in any command -------------------------------------------------------------
parse_invite() { # parse_invite STRING -> ID KEY DIGEST, or 1
  case $1 in '' | *[!0-9a-zA-Z._-]*) return 1 ;; esac
  [ "${#1}" -eq 121 ] || return 1
  ID=${1%%.*}
  rest=${1#*.}
  KEY=${rest%%.*}
  DIGEST=${rest#*.}
  case $DIGEST in *.*) return 1 ;; esac
  [ "${#ID}" -eq 12 ] && [ "${#KEY}" -eq 43 ] && [ "${#DIGEST}" -eq 64 ] || return 1
  case $ID in *[!0-9a-f]*) return 1 ;; esac
  case $KEY in *[!0-9a-zA-Z_-]*) return 1 ;; esac
  case $DIGEST in *[!0-9a-f]*) return 1 ;; esac
  return 0
}
valid_host() { # a-z0-9-, starts with a letter, at most 31, no trailing dash (install-<os>.sh's own rule)
  case $1 in [a-z]*) ;; *) return 1 ;; esac
  case $1 in *[!a-z0-9-]* | *-) return 1 ;; esac
  [ "${#1}" -le 31 ]
}
default_host() { # a name from the machine's own, prefixed mac- or pc-
  if [ "$OS" = mac ]; then
    raw=$(scutil --get LocalHostName 2>/dev/null) || raw=''
    [ -n "$raw" ] || raw=$(hostname -s 2>/dev/null) || raw=''
    pre=mac
  else
    raw=$(hostname -s 2>/dev/null) || raw=''
    pre=pc
  fi
  s=$(printf '%s' "$raw" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9' '-' | sed 's/--*/-/g; s/^-//; s/-$//')
  if [ -n "$s" ]; then h=$pre-$s; else h=$pre; fi
  # 26 characters of name, '-', 4 hex of THIS machine: two Macs that are both "MacBook Air" must not get one identity at the owner
  printf '%s-%s' "$(printf '%s' "$h" | cut -c1-26 | sed 's/-$//')" "$(machine_tag)"
}
machine_tag() { # 4 hex of sha256 over the machine's own id (never the id itself; a random 4 hex when it has none, kept by the host file after)
  if [ "$OS" = mac ]; then
    mid=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | sed -n 's/^.*"IOPlatformUUID" = "\([0-9A-Fa-f-]*\)".*$/\1/p' | head -n 1) || mid=''
  else
    mid=$(head -n 1 "$R/etc/machine-id" 2>/dev/null) || mid=''
  fi
  if [ -n "$mid" ]; then tag=$(sha256_text "fleet-basic:$mid" | cut -c1-4)
  else tag=$(od -An -N2 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n'); fi
  is_hex "$tag" 4 || tag=0000
  printf '%s' "$tag"
}

# --- the archive: only the allowed members, only plain files and folders -----------------------------------------------------
check_archive() { # check_archive TGZ
  names=$(tar -tzf "$1" 2>/dev/null) || return 1
  [ -n "$names" ] || return 1
  printf '%s\n' "$names" | while IFS= read -r n; do
    n=${n%/}
    case $n in
      /* | .. | ../* | */.. | */../*) exit 1 ;;
      COMMIT | fleet | fleet/* | bin | bin/fleet-basic.py | bin/fleet-basic-golden.py) ;;
      *) exit 1 ;;
    esac
  done || return 1
  tar -tvzf "$1" 2>/dev/null | while IFS= read -r l; do
    case $l in -* | d*) ;; *) exit 1 ;; esac # no link, device or fifo
  done || return 1
  return 0
}

# --- Python on a Mac (python.org framework, root-owned, 3.11+) -------------------------------------------------------------------
root_safe() { # root_safe FILE: it and every folder above it is root-owned and not group/other writable (stops at $R in a sandbox)
  p=$(cd "$(dirname "$1")" 2>/dev/null && pwd -P) || return 1
  set -- $(ls -ldLn "$1" 2>/dev/null)
  [ "${3:-x}" = "$ROOT_UID" ] || return 1
  case ${1:-x} in ?????w* | ????????w*) return 1 ;; esac
  while :; do
    set -- $(ls -ldn "$p" 2>/dev/null)
    [ "${3:-x}" = "$ROOT_UID" ] || return 1
    case ${1:-x} in ?????w* | ????????w*) return 1 ;; esac
    [ "$p" = / ] && return 0
    [ -n "$R" ] && [ "$p" = "$R" ] && return 0
    p=$(dirname "$p")
  done
}
py_ok() {
  [ -x "$PYM" ] || return 1
  "$PYM" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' </dev/null >/dev/null 2>&1 || return 1
  root_safe "$PYM"
}
write_choices() { # the framework only: five choices deselected (INSTALL.md)
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0"><array>'
    for c in PythonApplications PythonUnixTools PythonDocumentation PythonProfileChanges PythonInstallPip; do
      echo "<dict><key>attributeSetting</key><integer>0</integer><key>choiceAttribute</key><string>selected</string><key>choiceIdentifier</key><string>org.python.Python.$c-$PY_MM</string></dict>"
    done
    echo '</array></plist>'
  } >"$1"
}

# --- the golden image ------------------------------------------------------------------------------------------------------------
bake_mac_job() { # runs in the background: the public base from fleet-disk, its pin, then the bake VM (no qemu on this Mac)
  fetch "$BASE_URL" "$STAGE/base.raw.gz" 2147483648 || { say 'the public base image could not be downloaded'; return 1; }
  got=$(sha256_file "$STAGE/base.raw.gz")
  [ "$got" = "$BASE_GZ" ] || { say 'the downloaded base image is not the pinned one (sha256 differs)'; return 1; }
  # `pinned` = the lock's base_raw raw_sha256, and no STAGE/base.img (an explicit sha256 would demand the 616 MB .img we never fetch)
  "$PYM" -I -B "$SRC/bin/fleet-basic-golden.py" bake --out "$STAGE" --run --raw-gz pinned </dev/null >"$TMP/golden.out" 2>&1
  r=$?
  cat "$TMP/golden.out"
  [ "$r" -eq 0 ] || return "$r"
  # the finished image's sha256 is written HERE, the moment it exists, so a STOP later (no answer to the pair in an hour) keeps a 20 GB
  # image for the re-run instead of losing it with $TMP; step 8 only reads it. A killed or failed bake leaves none: that stage is rebuilt.
  sealed=$(sed -n 's/^OK sealed \([0-9a-f]\{64\}\)$/\1/p' "$TMP/golden.out" | tail -n 1)
  is_hex "$sealed" 64 && [ -f "$STAGE/noble-arm64.raw" ] || { say 'the build did not report a sealed image'; return 1; }
  printf '%s\n' "$sealed" >"$STAGE/baked.sha256.new" && mv "$STAGE/baked.sha256.new" "$STAGE/baked.sha256"
}
bake_linux_job() { # runs in the background, as msvm (sudo -n: a password prompt here would fight the foreground ones)
  sudo -n -u msvm sh "$STAGE/bake-host.sh" "$STAGE" </dev/null
}
stage_linux() { # a helper-owned stage that golden_linux fills, then msvm's
  sudo rm -rf "$STAGE" </dev/null || return 1
  install -d -m 0755 "$STAGE" || return 1
  [ -d "$STAGE" ] && [ ! -L "$STAGE" ] && [ -O "$STAGE" ] || return 1
  (cd "$SRC" && python3 -B -m fleet.basic.golden_linux bake --out "$STAGE") </dev/null || return 1
  sudo chown -R msvm:msvm "$STAGE" </dev/null
}

# --- the steps that run `fleet-basic` ---------------------------------------------------------------------------------------------
fb_status() { ST=$(sudo "$FB" status </dev/null 2>/dev/null) || ST=''; }
st_has() { printf '%s\n' "$ST" | grep -qxF "$1"; }
fp_of() { # fp_of runner|claude: the 12 hex fingerprint
  sudo "$FB" fingerprint "$1" </dev/null 2>/dev/null | sed -n 's/^OK .* fingerprint \([0-9a-f]\{12\}\)$/\1/p' | tail -n 1
}
run_check() { # run_check WORD LASTLINE CMD...: run it as root, print its lines indented, want exit 0 and that last line
  word=$1 want=$2
  shift 2
  sudo "$@" </dev/null >"$TMP/out.txt" 2>&1
  rc=$?
  sed 's/^/  /' "$TMP/out.txt"
  [ "$rc" -eq 0 ] || stop "$word failed (exit $rc), the lines above say why"
  [ "$(tail -n 1 "$TMP/out.txt")" = "$want" ] || stop "$word did not end with '$want', the lines above say why"
}

usage() { stop 'usage: curl -fsSL https://raw.githubusercontent.com/mirrorstack-ai/fleet-disk/main/basic/install.sh | sh -s -- INVITE [--host NAME]'; }

main() {
  R='' ROOT_UID=0 TTY=/dev/tty
  ORIG_PATH=$PATH
  if [ "${FB_SANDBOX:-}" = 1 ]; then
    ROOT_UID=${FB_ROOT_UID:-0} TTY=${FB_TTY:-/dev/tty}
    [ -z "${FB_ROOT:-}" ] || R=$(cd "$FB_ROOT" && pwd -P) || stop 'sandbox FB_ROOT is not a folder'
  else
    PATH=/usr/bin:/bin:/usr/sbin:/sbin
    export PATH
  fi
  umask 022
  TMP='' NEW='' KA_PID='' CAF_PID='' BAKE_PID=''
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP

  # arguments: the invite is matched against its shape before anything else touches it
  INVITE='' HOST_OVR=''
  while [ $# -gt 0 ]; do
    case $1 in
      --host) [ $# -ge 2 ] || usage; HOST_OVR=$2; shift ;;
      -*) usage ;;
      *) [ -z "$INVITE" ] || usage; INVITE=$1 ;;
    esac
    shift
  done
  [ -n "$INVITE" ] || usage
  parse_invite "$INVITE" || stop 'invite-shape the invite is not the line the owner sent: <12 hex>.<43 characters>.<64 hex>'
  INVITE=''
  [ -z "$HOST_OVR" ] || valid_host "$HOST_OVR" || stop 'host --host is a name of a-z, 0-9 and -, starting with a letter, at most 31, not ending in -'

  say '== fleet basic mode: one machine becomes an agent worker (the code stays private; this line holds no secret) =='

  # ---- 1 ----------------------------------------------------------------------------------------------------------------------
  say '[1/8] check this machine'
  [ "$(id -u)" != 0 ] || stop 'root run this as yourself, not root: it asks for sudo itself'
  case $(uname -s 2>/dev/null) in
    Darwin)
      OS=mac
      [ "$(uname -m)" = arm64 ] || stop 'machine this Mac is not Apple silicon (arm64; a Rosetta terminal reports x86_64)'
      v=$(sw_vers -productVersion 2>/dev/null) || v=''
      case ${v%%.*} in '' | *[!0-9]*) stop 'machine macOS version unreadable' ;; esac
      [ "${v%%.*}" -ge 14 ] || stop "machine macOS 14 or newer is needed, this is $v"
      PYM=$R/Library/Frameworks/Python.framework/Versions/Current/bin/python3
      GOLDEN="$R/Library/Application Support/fleet-basic-vm/golden/noble-arm64.raw"
      SRCP="$R/Library/Application Support/fleet-basic-src"
      STAGE=${HOME:-}/.fleet-basic-stage
      NEED_KB=$MIN_DISK_MAC_KB DISK_DIR=${HOME:-}
      [ -n "${HOME:-}" ] && [ -d "$HOME" ] || stop 'machine HOME is not set'
      ;;
    Linux)
      OS=linux
      [ "$(uname -m)" = x86_64 ] || stop 'machine this PC is not x86_64'
      osid=$(sed -n 's/^ID=//p' "$R/etc/os-release" 2>/dev/null | head -n 1 | tr -d '"')
      osver=$(sed -n 's/^VERSION_ID=//p' "$R/etc/os-release" 2>/dev/null | head -n 1 | tr -d '"')
      [ "$osid" = ubuntu ] || stop "machine Ubuntu 24.04 or 26.04 is needed, this is ${osid:-unknown}"
      case $osver in 24.04 | 26.04) ;; *) stop "machine Ubuntu 24.04 or 26.04 is needed, this is $osver" ;; esac
      [ -e "$R/dev/kvm" ] || stop 'kvm /dev/kvm is missing: turn on VT-x / AMD-V in the BIOS'
      GOLDEN=$R/var/lib/fleet-basic/golden/noble-x86_64.qcow2
      SRCP=$R/usr/local/share/fleet-basic-src
      STAGE=$R/var/tmp/fb-stage
      NEED_KB=$MIN_DISK_LINUX_KB DISK_DIR=$R/var/tmp
      ;;
    *) stop 'machine only Apple-silicon macOS 14+ and Ubuntu 24.04 / 26.04 x86_64 are supported' ;;
  esac
  FB=$R/usr/local/sbin/fleet-basic
  ( : <"$TTY" ) 2>/dev/null || stop 'terminal no terminal: run this line in a Terminal window you are sitting at' # a subshell: dash exits on a failed redirect of a special builtin

  if [ -e "$GOLDEN" ]; then
    say "  ok disk, memory (the VM image is already installed)"
  else
    kb=$(df -Pk "$DISK_DIR" 2>/dev/null | awk 'NR == 2 { print $4 }')
    case $kb in '' | *[!0-9]*) stop 'disk cannot tell how much disk is free' ;; esac
    [ "$kb" -ge "$NEED_KB" ] || stop "disk not enough free disk: $((NEED_KB / 1048576)) GiB are needed, $((kb / 1048576)) GiB are free"
    if [ "$OS" = linux ]; then
      mem=$(awk '/^MemAvailable:/ { print $2 }' "$R/proc/meminfo" 2>/dev/null)
      case $mem in '' | *[!0-9]*) stop 'memory cannot read MemAvailable' ;; esac
      [ "$mem" -ge "$MIN_MEM_LINUX_KB" ] || stop "memory not enough free memory: 11 GiB are needed, $((mem / 1048576)) GiB are free"
    fi
    say "  ok disk and memory"
  fi

  say '  sudo is needed to install (your password; macOS: the login password)'
  sudo -v <"$TTY" || stop 'sudo this account cannot use sudo'
  MYPID=$$
  (while kill -0 "$MYPID" 2>/dev/null; do sudo -n true 2>/dev/null; sleep 50; done) >/dev/null 2>&1 </dev/null &
  KA_PID=$!

  for t in curl tar gzip openssl; do
    if ! command -v "$t" >/dev/null 2>&1; then
      if [ "$OS" = linux ] && { [ "$t" = openssl ] || [ "$t" = curl ]; }; then
        sudo apt-get install -y "$t" </dev/null || stop "tool $t is missing and apt could not install it"
      else stop "tool $t is missing"; fi
    fi
  done
  command -v python3 >/dev/null 2>&1 || [ "$OS" = mac ] || stop 'tool python3 is missing (sudo apt-get install -y python3)'

  PATH_NOW=$PATH PATH=$ORIG_PATH
  CLAUDE_BIN=$(command -v claude 2>/dev/null) || CLAUDE_BIN=''
  PATH=$PATH_NOW
  case $CLAUDE_BIN in /*) ;; *) CLAUDE_BIN='' ;; esac
  ST=''
  [ ! -x "$FB" ] || fb_status
  if ! st_has token=yes && [ -z "$CLAUDE_BIN" ]; then
    stop 'claude Claude Code is not installed here: install it with its official line (curl -fsSL https://claude.ai/install.sh | bash), open a new Terminal window and run this line again'
  fi

  HOST=$HOST_OVR
  if [ -z "$HOST" ]; then
    prev=$(printf '%s\n' "$ST" | sed -n 's/^host=//p' | head -n 1)
    if [ -n "$prev" ] && valid_host "$prev"; then HOST=$prev; else HOST=$(default_host); fi
  fi
  valid_host "$HOST" || stop "host the host name $HOST is not usable: pass --host NAME (a-z, 0-9 and -, starting with a letter)"
  say "  ok $OS, host name $HOST"

  # ---- 2 ----------------------------------------------------------------------------------------------------------------------
  say '[2/8] fetch the fleet code (encrypted, for this machine only, expires within an hour)'
  TMP=$(mktemp -d "${TMPDIR:-/tmp}/fleet-basic-install.XXXXXX") || stop 'tmp cannot make a temp folder'
  chmod 700 "$TMP"
  fetch "${BASE_PREFIX}inv-$ID/inv-$ID.enc" "$TMP/inv.enc" 104857600 || stop 'invite-download the invite was not found: it expires within one hour, ask the owner for a new line'
  got=$(sha256_file "$TMP/inv.enc")
  [ "$got" = "$DIGEST" ] || stop 'invite-sha the downloaded invite is not the one you were given, ask the owner for a new line'
  # shellcheck disable=SC2086 # fixed words
  printf '%s\n' "$KEY" | openssl enc -d $OPENSSL_ENC -in "$TMP/inv.enc" -out "$TMP/inv.tgz" 2>/dev/null ||
    stop 'invite-decrypt the invite does not open, ask the owner for a new line'
  KEY=''
  check_archive "$TMP/inv.tgz" || stop 'archive the invite holds something other than the fleet tree (files only: fleet/, bin/fleet-basic*.py, COMMIT)'

  { sudo mkdir -p "$SRCP" && sudo chmod 755 "$SRCP" && sudo chown 0:0 "$SRCP"; } </dev/null || stop 'source cannot make the source folder'
  NEW=$(sudo mktemp -d "$SRCP/new.XXXXXX" </dev/null) && [ -n "$NEW" ] || stop 'source cannot make a source folder'
  sudo chmod 755 "$NEW" </dev/null
  sudo tar -xzf "$TMP/inv.tgz" -C "$NEW" --no-same-owner </dev/null || stop 'archive the fleet tree could not be unpacked'
  sudo chown -R 0:0 "$NEW" </dev/null
  sudo chmod -R go-w "$NEW" </dev/null
  COMMIT=$(sudo cat "$NEW/COMMIT" 2>/dev/null) || COMMIT=''
  is_hex "$COMMIT" 40 && [ "$(sudo cat "$NEW/COMMIT" </dev/null | wc -c | tr -d ' ')" = 41 ] || stop 'commit COMMIT is not 40 hex and a newline'
  SRC=$SRCP/$COMMIT
  sudo rm -rf "$SRC" </dev/null
  sudo mv "$NEW" "$SRC" </dev/null || stop 'source cannot place the source folder'
  for d in "$SRCP"/*; do [ "$d" = "$SRC" ] || sudo rm -rf "$d" </dev/null; done
  for f in "fleet/basic/install-$OS.sh" bin/fleet-basic.py bin/fleet-basic-golden.py; do
    [ -f "$SRC/$f" ] || stop "archive the fleet tree has no $f"
  done
  say "  ok fleet code $(printf '%s' "$COMMIT" | cut -c1-12) in $SRC"

  if [ "$OS" = mac ]; then # fail now, before any slow step, while the public base image is not pinned
    LOCK=$SRC/fleet/basic/basic-mac.lock.json
    BASE_URL=$(plutil -extract base_raw.url raw -o - "$LOCK" 2>/dev/null) || BASE_URL=TODO
    BASE_GZ=$(plutil -extract base_raw.gz_sha256 raw -o - "$LOCK" 2>/dev/null) || BASE_GZ=TODO
    BASE_RAW=$(plutil -extract base_raw.raw_sha256 raw -o - "$LOCK" 2>/dev/null) || BASE_RAW=TODO
    if [ ! -e "$GOLDEN" ] && { [ "$BASE_URL" = TODO ] || [ "$BASE_GZ" = TODO ] || [ "$BASE_RAW" = TODO ]; }; then
      stop 'base-raw not published yet'
    fi
    if [ ! -e "$GOLDEN" ]; then
      case $BASE_URL in
        "$BASE_PREFIX"*) ;;
        *) stop 'base-raw the lock names a base image outside fleet-disk releases' ;;
      esac
      case ${BASE_URL#"$BASE_PREFIX"} in '' | *[!A-Za-z0-9._/-]* | */../* | ../* | */..) stop 'base-raw the base image url has odd characters' ;; esac
      is_hex "$BASE_GZ" 64 && is_hex "$BASE_RAW" 64 || stop 'base-raw the lock entry has no sha256 pins'
    fi
  fi

  # ---- 3 ----------------------------------------------------------------------------------------------------------------------
  say '[3/8] Python'
  if [ "$OS" = linux ]; then
    say "  ok python3 (Ubuntu's own)"
  elif py_ok; then
    say '  ok python.org Python 3.11+ is in place'
  else
    say "  fetching python.org $PY_PKG (pinned sha256), then installing the framework only"
    fetch "$PY_URL" "$TMP/$PY_PKG" 209715200 py || stop 'python the Python installer could not be downloaded'
    got=$(sha256_file "$TMP/$PY_PKG")
    [ "$got" = "$PY_SHA" ] || stop 'python the downloaded installer is not the pinned one (sha256 differs)'
    sig=$(pkgutil --check-signature "$TMP/$PY_PKG" 2>&1) || stop 'python the installer signature is not valid'
    case $sig in *'Python Software Foundation'*) ;; *) stop 'python the installer is not signed by the Python Software Foundation' ;; esac
    write_choices "$TMP/py-choices.xml"
    sudo installer -pkg "$TMP/$PY_PKG" -target / -applyChoiceChangesXML "$TMP/py-choices.xml" </dev/null >"$TMP/installer.log" 2>&1 ||
      { tail -n 15 "$TMP/installer.log"; stop 'python the Python installer failed'; }
    py_ok || stop 'python python.org Python 3.11+ is not in place after the installer'
    say '  did python.org Python'
  fi

  # ---- 4 ----------------------------------------------------------------------------------------------------------------------
  say "[4/8] install fleet-basic (the switch stays OFF)"
  sudo sh "$SRC/fleet/basic/install-$OS.sh" install --host "$HOST" --runner-app-id "$RUNNER_APP_ID" </dev/null >"$TMP/install.txt" 2>&1
  rc=$?
  sed 's/^/  /' "$TMP/install.txt"
  [ "$rc" -eq 0 ] || stop "install install-$OS.sh failed (exit $rc), the lines above say why"
  [ -x "$FB" ] || stop 'install the fleet-basic command is not in place'
  fb_status

  # ---- 5 ----------------------------------------------------------------------------------------------------------------------
  say '[5/8] build the VM image in the background (5 to 45 minutes)'
  if [ -e "$GOLDEN" ]; then
    say '  ok the image is already installed'
  elif [ "$OS" = mac ] && [ -f "$STAGE/baked.sha256" ] && [ -f "$STAGE/noble-arm64.raw" ] && is_hex "$(cat "$STAGE/baked.sha256")" 64; then
    say '  ok the image from the earlier run is kept'
  elif [ "$OS" = linux ] && [ -f "$STAGE/golden.qcow2" ] && [ -f "$STAGE/golden.qcow2.sha256" ]; then
    say '  ok the image from the earlier run is kept'
  else
    if [ "$OS" = mac ]; then
      rm -rf "$STAGE"
      mkdir -m 700 "$STAGE" || stop 'stage cannot make the build folder'
      (bake_mac_job; r=$?; echo "$r" >"$TMP/bake.rc"; exit "$r") >"$TMP/bake.log" 2>&1 </dev/null &
      BAKE_PID=$!
      caffeinate -i -w "$BAKE_PID" >/dev/null 2>&1 </dev/null &
      CAF_PID=$!
      say '  started; this Mac stays awake while it builds (about 20 GB, keep it plugged in)'
    else
      stage_linux || stop 'stage cannot stage the image build'
      (bake_linux_job; r=$?; echo "$r" >"$TMP/bake.rc"; exit "$r") >"$TMP/bake.log" 2>&1 </dev/null &
      BAKE_PID=$!
      say '  started'
    fi
    BAKE_START=$(date +%s)
  fi

  # ---- 6 ----------------------------------------------------------------------------------------------------------------------
  say '[6/8] Claude token (your own Claude account, one seat per device)'
  if st_has token=yes; then
    say '  ok the token is already set'
  else
    say '  A sign-in opens for `claude setup-token`: sign in as YOURSELF. It prints one long word: select it all and copy it.'
    printf '  Press Return to start it: '
    IFS= read -r _ <"$TTY"
    "$CLAUDE_BIN" setup-token <"$TTY" >>"$TTY" 2>&1 || stop 'claude claude setup-token did not finish: run this line again'
    if [ "$OS" = mac ]; then say '  Now paste the token, press Return, then Ctrl-D (it is not shown again, and never sent anywhere but into fleet-basic):'
    else say '  Now paste the token and press Enter (it never goes anywhere but into fleet-basic):'; fi
    sudo "$FB" claude-token <"$TTY" || stop 'claude fleet-basic refused the token: run this line again and paste the whole word'
    fb_status
    st_has token=yes || stop 'claude the token was not stored: run this line again'
  fi

  # ---- 7 ----------------------------------------------------------------------------------------------------------------------
  say '[7/8] pair with the owner'
  say '  If it prints a line that starts with PAIR, send that line to the owner and leave this window open: it waits up to 60 minutes.'
  say '  The WAIT line after it names ph=<16 characters>: read those OUT LOUD to the owner (a call, not the chat the PAIR line went through). The owner types them to approve.'
  sudo "$FB" pair </dev/null || stop 'pair no answer from the owner within the hour (or it was refused): run this line again with a new invite'
  fb_status
  st_has key=yes && ! st_has shas=0 || stop 'pair the owner answer was not applied: run this line again'
  say '  ok paired'

  # ---- 8 ----------------------------------------------------------------------------------------------------------------------
  say '[8/8] finish: image, doctor, mint-test, enable'
  if [ -n "$BAKE_PID" ]; then
    say '  waiting for the image build to finish'
    last=$BAKE_START
    while [ ! -f "$TMP/bake.rc" ] && kill -0 "$BAKE_PID" 2>/dev/null; do
      sleep 15
      now=$(date +%s)
      if [ $((now - last)) -ge 120 ]; then say "  still building ($(((now - BAKE_START) / 60)) min so far)"; last=$now; fi
    done
    wait "$BAKE_PID"
    rc=$?
    BAKE_PID=''
    [ -z "$CAF_PID" ] || { kill "$CAF_PID"; wait "$CAF_PID"; } 2>/dev/null
    CAF_PID=''
    if [ "$rc" -ne 0 ]; then
      tail -n 20 "$TMP/bake.log"
      stop "bake the image build failed (exit $rc), the lines above say why"
    fi
  fi
  if [ -e "$GOLDEN" ]; then
    say '  ok image'
  elif [ "$OS" = mac ]; then
    sealed=$(cat "$STAGE/baked.sha256" 2>/dev/null) || sealed=''
    is_hex "$sealed" 64 || { [ ! -f "$TMP/bake.log" ] || tail -n 20 "$TMP/bake.log"; stop 'bake the build did not report a sealed image'; }
    say '  installing the image (copies and checks 20 GiB: minutes)'
    sudo "$FB" golden "$STAGE/noble-arm64.raw" "$sealed" </dev/null || stop 'golden the image was refused (see above)'
    rm -rf "$STAGE"
  else
    sealed=$(sudo cut -d' ' -f1 "$STAGE/golden.qcow2.sha256" </dev/null)
    is_hex "$sealed" 64 || stop 'bake the build left no sha256 for the image'
    sudo install -D -o root -g root -m 0444 "$STAGE/golden.qcow2" "$GOLDEN" </dev/null || stop 'golden the image could not be installed'
    (cd "$SRC" && python3 -B -m fleet.basic.golden_linux verify "$GOLDEN" "$sealed") </dev/null || stop 'golden the installed image is not the sealed one'
    sudo rm -rf "$STAGE" </dev/null
    say '  did image'
  fi
  run_check doctor 'DOCTOR ok' "$FB" doctor
  run_check mint-test ok "$FB" mint-test
  sudo "$FB" enable </dev/null || stop 'enable fleet-basic would not switch on (see above)'
  fb_status
  HOST=$(printf '%s\n' "$ST" | sed -n 's/^host=//p' | head -n 1)
  valid_host "$HOST" || stop 'status fleet-basic reports no usable host name'
  RUNNER_FP=$(fp_of runner)
  CLAUDE_FP=$(fp_of claude)
  is_hex "$RUNNER_FP" 12 && is_hex "$CLAUDE_FP" 12 || stop 'fingerprint fleet-basic reports no fingerprints'
  say ''
  say 'Done. Send this one line to the owner:'
  say "FLEET-BASIC READY host=$HOST runner=$RUNNER_FP claude=$CLAUDE_FP"
  say 'Stop it any time: sudo /usr/local/sbin/fleet-basic disable. Remove it: see basic/README.md in fleet-disk.'
}

main "$@"
