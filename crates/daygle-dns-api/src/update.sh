#!/usr/bin/env sh
# Daygle DNS in-place update, driven by the web console.
#
# Usage: sh daygle-dns-update.sh <current-binary> <state-dir>
#
# Preferred path: download the prebuilt release binary for this architecture
# from GitHub Releases and verify its sha256 checksum. Fallback path (only
# when no release asset can be fetched): build from source, the way install.sh
# does. Progress is written to <state-dir>/state.json so the console can
# follow along; all command output accumulates in <state-dir>/update.log.
#
# Privilege model: this helper runs as the (unprivileged) service account and
# NEVER runs sudo or any setuid helper - that design poisoned every update on
# hardened hosts (the service's CapabilityBoundingSet broke sudo's core audit
# write and sudo aborted before doing anything). Instead this script downloads,
# verifies and stages the new binary into <updates>/staging, then drops a
# `request` marker into <updates>. A root-owned systemd path unit
# (daygle-dns-update.path) watches that directory and starts
# daygle-dns-update.service - a short root oneshot that swaps the binary,
# restarts the service, health-checks and rolls back on failure. This script
# only reaches the hand-off; it exits as soon as the apply step takes over so
# the service restart cannot kill it mid-record.
#
# The script runs as a detached helper so it survives the server's restart;
# `state` files and log output live under the OS temp dir (writable by the
# service user without extra privileges).

set -eu

EXE="$1"
DIR="$2"
LOG="$DIR/update.log"
REPO_OWNER="${DAYGLE_UPDATE_REPO_OWNER:-daygle}"
REPO_NAME="${DAYGLE_UPDATE_REPO_NAME:-daygle-dns}"
REPO_URL="${DAYGLE_UPDATE_REPO:-https://github.com/${REPO_OWNER}/${REPO_NAME}.git}"
LATEST_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest"
LATEST_API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"
BASE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download"

# Escape a message for embedding in a JSON string (backslashes, quotes, and
# control characters). Without handling newlines/tabs, a multi-line error
# would produce invalid JSON that the Rust side reads as idle.
json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g' | awk '{
    gsub(/\\n/, "\\\\n");
    gsub(/\\r/, "\\\\r");
    if (NR == 1) printf "%s", $0;
    else printf "\\n%s", $0;
  }'
}

# Write state atomically (temp file + rename) so the server's status polls
# never observe a half-written file.
state() { # phase message
  printf '{"phase":"%s","pid":%s,"started_at":"%s","message":"%s","exit_code":0}\n' \
    "$1" "$$" "$(date -u +%FT%TZ)" "$(json_escape "$2")" > "$DIR/state.json.tmp" \
    && mv -f "$DIR/state.json.tmp" "$DIR/state.json"
}

fail() { # message
  printf '{"phase":"error","pid":%s,"started_at":"%s","message":"%s","exit_code":1}\n' \
    "$$" "$(date -u +%FT%TZ)" "$(json_escape "$1")" > "$DIR/state.json.tmp" \
    && mv -f "$DIR/state.json.tmp" "$DIR/state.json"
}

# Most recent meaningful log line, for embedding in error messages so the
# console says exactly what failed.
last_log_error() {
  tail -n 8 "$LOG" 2>/dev/null | tr '\r' '\n' | grep -v '^[[:space:]]*$' | tail -n 1 | cut -c1-200
}

# The installed binary path can be reported as "... (deleted)" when a previous
# update swapped the on-disk file while this process kept running. It is only
# used in diagnostics; normalise it for readable messages.
if [ ! -f "$EXE" ] && [ -f /usr/local/bin/daygle-dns ]; then
  EXE=/usr/local/bin/daygle-dns
fi

# The updates directory is defined by the installed systemd path unit (so
# custom PREFIX/DATA_DIR installs line up); the default matches install.sh.
UPDATES_DIR="$(sed -n 's/^PathChanged=//p' /etc/systemd/system/daygle-dns-update.path 2>/dev/null | head -n 1)"
[ -n "$UPDATES_DIR" ] || UPDATES_DIR=/var/lib/daygle-dns/updates
STAGING="$UPDATES_DIR/staging"

# Big transient artifacts (a fallback source build's tree and registry cache)
# should not land on /tmp: many distros mount it as tmpfs, so a multi-GB
# release build can exhaust memory on small hosts. /var/tmp is the
# conventional spot.
if [ -z "${TMPDIR:-}" ] && [ -d /var/tmp ]; then
  export TMPDIR=/var/tmp
fi

SRC="$(mktemp -d)"

trap 'rm -rf "$SRC"' EXIT HUP INT TERM

state preparing "Preparing update…"

# The hand-off requires the installer-provisioned update service; fail early
# (before any download) so the operator gets the repair without waiting.
if [ ! -f /etc/systemd/system/daygle-dns-update.path ] || [ ! -d "$STAGING" ] || [ ! -w "$STAGING" ]; then
  fail "the systemd update service is not provisioned on this host (daygle-dns-update.path or the updates staging dir is missing). Re-run the installer from main so it can provision the update service, then retry."
  exit 1
fi

# ---- locate a toolchain (used only by the source-build fallback) --------

find_cargo() {
  if command -v rustup >/dev/null 2>&1; then
    rustup which cargo 2>/dev/null && return 0
  fi
  if command -v cargo >/dev/null 2>&1; then
    command -v cargo && return 0
  fi
  for cand in "$HOME/.cargo/bin/cargo" \
              /root/.cargo/bin/cargo \
              /home/*/.cargo/bin/cargo \
              "${CARGO_HOME:-/.cargo}/bin/cargo" \
              /usr/bin/cargo \
              /usr/local/bin/cargo \
              /snap/bin/cargo; do
    if [ -x "$cand" ]; then
      printf '%s\n' "$cand"
      return 0
    fi
  done
  # Last resort: ask the filesystem. A bare PATH on a service account does
  # not mean the toolchain is missing - rustup under another user's home (or
  # under /opt) is the common case, and the binary is usually world-executable.
  if command -v find >/dev/null 2>&1; then
    find /root /home /opt /usr -maxdepth 4 -type f -name cargo -perm -u+x 2>/dev/null | head -n 1
  fi
}
CARGO_BIN="$(find_cargo || true)"

# ---- download the prebuilt release --------------------------------------

# A downloader (curl or wget) enables the fast prebuilt-release path.
DOWNLOADER=""
if command -v curl >/dev/null 2>&1; then
  DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER="wget"
fi

fetch() { # url dest
  case "$DOWNLOADER" in
    curl) curl -fSL --retry 3 --connect-timeout 15 -o "$2" "$1" ;;
    wget) wget -q --tries=3 -O "$2" "$1" ;;
    *) return 1 ;;
  esac
}

# Match the release asset to this machine's architecture. CI publishes
# daygle-dns-linux-{x86_64,x86_64-musl,aarch64}; the musl asset is the
# universal fallback because it is statically linked and runs on any Linux.
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ASSET="linux-x86_64" ;;
  aarch64|arm64) ASSET="linux-aarch64" ;;
  *) ASSET="linux-x86_64-musl" ;;
esac

DOWNLOAD_OK=0
REL_TAG=""
if [ -n "$DOWNLOADER" ]; then
  state downloading "Downloading the prebuilt release (${ASSET} build)…"
  # Resolve the latest release tag: the GitHub API is authoritative (and
  # cheap); the /releases/latest HTML redirect is the fallback if the API is
  # unreachable or rate-limited. Naming the tag lets errors say exactly
  # which release failed.
  if fetch "$LATEST_API_URL" "$SRC/release.json" 2>>"$LOG"; then
    REL_TAG="$(grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$SRC/release.json" 2>/dev/null | head -n 1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"//; s/"$//')"
  fi
  if [ -z "$REL_TAG" ] && fetch "$LATEST_URL" "$SRC/release.html" 2>>"$LOG"; then
    REL_TAG="$(sed -n 's/.*releases\/tag\/\([^"/?]*\).*/\1/p' "$SRC/release.html" | head -n 1)"
  fi
  # Try the architecture-matched asset first, then the other Linux builds.
  try_assets="$ASSET"
  case "$ASSET" in
    linux-x86_64) try_assets="$try_assets linux-x86_64-musl" ;;
    *) try_assets="$try_assets linux-x86_64" ;;
  esac
  case "$ASSET" in
    linux-aarch64) ;;
    *) try_assets="$try_assets linux-aarch64" ;;
  esac
  for asset in $try_assets; do
    BIN_TMP="$SRC/bin-$asset"
    SUM_TMP="$SRC/sum-$asset"
    if fetch "$BASE_URL/$REL_TAG/daygle-dns-$asset" "$BIN_TMP" 2>>"$LOG" \
       && fetch "$BASE_URL/$REL_TAG/daygle-dns-$asset.sha256" "$SUM_TMP" 2>>"$LOG"; then
      mv -f "$BIN_TMP" "$SRC/daygle-dns"
      mv -f "$SUM_TMP" "$SRC/daygle-dns.sha256"
      DOWNLOAD_OK=1
      break
    fi
    # A failed fetch can leave an empty/partial file behind (wget -O does);
    # remove it so it is never mistaken for a real download.
    rm -f "$BIN_TMP" "$SUM_TMP"
  done
fi

NEW_BIN=""
TARGET_VERSION=""
if [ "$DOWNLOAD_OK" -eq 1 ]; then
  # Verify the checksum BEFORE the file is used; a mismatch is fatal.
  state downloading "Verifying the download checksum…"
  EXPECTED="$(cut -d' ' -f1 "$SRC/daygle-dns.sha256" 2>/dev/null | tr -d '[:space:]')"
  ACTUAL="$( (sha256sum "$SRC/daygle-dns" 2>/dev/null || shasum -a 256 "$SRC/daygle-dns" 2>/dev/null) | cut -d' ' -f1 | tr -d '[:space:]')"
  if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
    fail "checksum verification failed for the downloaded release${REL_TAG:+ ($REL_TAG)} - refusing to install it. If this persists, report the release as broken."
    exit 1
  fi
  chmod 0755 "$SRC/daygle-dns"
  NEW_BIN="$SRC/daygle-dns"
  TARGET_VERSION="$(printf '%s' "$REL_TAG" | sed 's/^v//')"
else
  # No release asset could be fetched: fall back to building from source,
  # which additionally requires git and a working toolchain. Say exactly why
  # the download path failed so the operator knows which fix applies.
  if [ -z "$DOWNLOADER" ]; then
    DL_WHY="no downloader (curl or wget) is installed"
  elif [ -z "$REL_TAG" ]; then
    DL_WHY="no published release exists (publish one by pushing a version tag)"
  else
    DL_WHY="release ${REL_TAG} has no usable binary assets for this platform"
  fi
  if ! command -v git >/dev/null 2>&1; then
    fail "no release binary could be downloaded and git is not installed (needed for the source-build fallback); install git and retry."
    exit 1
  fi
  if [ -z "$CARGO_BIN" ]; then
    fail "no release binary could be downloaded ($DL_WHY) and cargo was not found; install the Rust toolchain (curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal) and retry."
    exit 1
  fi

  state cloning "No prebuilt release matched ($DL_WHY) - building from source (this can take several minutes)…"
  if ! git clone --depth 1 "$REPO_URL" "$SRC" >>"$LOG" 2>&1; then
    fail "git clone failed - check network access to $REPO_URL (see update.log)."
    exit 1
  fi

  cd "$SRC"

  state building "Building the release binary (this can take a few minutes)…"
  # cargo writes its registry to $CARGO_HOME (default $HOME/.cargo). systemd
  # accounts may have no usable home directory; fall back to a writable dir
  # so the build can proceed and cache across runs.
  if [ -z "${CARGO_HOME:-}" ]; then
    if [ -n "${HOME:-}" ] && [ -d "$HOME" ] && [ -w "$HOME" ]; then
      :
    else
      CARGO_HOME="/var/tmp/daygle-dns-cargo-home"
      if ! mkdir -p "$CARGO_HOME" 2>/dev/null || [ ! -w "$CARGO_HOME" ]; then
        CARGO_HOME="$DIR/cargo-home"
        mkdir -p "$CARGO_HOME"
      fi
      export CARGO_HOME
    fi
  fi
  if ! PATH="$(dirname "$CARGO_BIN"):$PATH" cargo build --release -p daygle-dns >>"$LOG" 2>&1; then
    fail "build failed - see update.log for details."
    exit 1
  fi

  NEW_BIN="$SRC/target/release/daygle-dns"
  TARGET_VERSION="$("$NEW_BIN" --version 2>/dev/null | head -n 1 || true)"
fi

# The manifest's version is free text but must be dotted numerics for the
# apply step to accept it; derive it from the tag or the binary.
if [ -z "$TARGET_VERSION" ]; then
  TARGET_VERSION="$("$NEW_BIN" --version 2>/dev/null | head -n 1 || true)"
fi
TARGET_VERSION="$(printf '%s' "$TARGET_VERSION" | sed 's/^v//' | grep -o '[0-9][0-9.]*' | head -n 1 || true)"
[ -n "$TARGET_VERSION" ] || TARGET_VERSION="0.0.0"

# ---- stage and hand off to the root apply service ------------------------

# Stage the verified binary + manifest into the staging subdir (which the
# watcher does NOT monitor), then atomically create the top-level `request`
# marker that triggers daygle-dns-update.service.
stage_and_trigger() { # staged-binary target-version
  src_bin="$1"
  tgt_ver="$2"
  [ -f "$src_bin" ] || return 1
  rm -f "$STAGING/apply.bin" "$STAGING/apply.json" "$UPDATES_DIR/request" "$UPDATES_DIR/request.processing"
  cp -f "$src_bin" "$STAGING/apply.bin" 2>/dev/null || return 1
  sha="$( (sha256sum "$STAGING/apply.bin" 2>/dev/null || shasum -a 256 "$STAGING/apply.bin" 2>/dev/null) | cut -d' ' -f1 | tr -d '[:space:]')"
  [ -n "$sha" ] || return 1
  printf '{"version":"%s","sha256":"%s"}\n' "$tgt_ver" "$sha" > "$STAGING/apply.json" || return 1
  : > "$UPDATES_DIR/request" || return 1
}

state installing "Update ready - handing off to the systemd update service (v${TARGET_VERSION})…"
if ! stage_and_trigger "$NEW_BIN" "$TARGET_VERSION"; then
  WHY="$(last_log_error)"
  fail "the update binary could not be staged into $STAGING${WHY:+: $WHY}. Re-run the installer to repair the update service, then retry."
  exit 1
fi

# Hand over: keep the run visible until the root apply step claims state.json
# with its own pid, then exit (before the service restart, which would kill
# this helper). If the apply step never picks the request up, report it.
i=0
while [ $i -lt 60 ]; do
  if ! grep -q "\"pid\":$$" "$DIR/state.json" 2>/dev/null; then
    exit 0
  fi
  sleep 1
  i=$((i + 1))
done
rm -f "$UPDATES_DIR/request" "$UPDATES_DIR/request.processing"
fail "the update was staged but the update service never applied it (is daygle-dns-update.path running?). Re-run the installer to repair the update service, then retry."
exit 1