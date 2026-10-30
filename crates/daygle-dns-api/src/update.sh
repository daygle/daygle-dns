#!/usr/bin/env sh
# Daygle DNS in-place update, driven by the web console.
#
# Usage: sh daygle-dns-update.sh [--models] <current-binary> <state-dir>
#
# Default path: stage the canonical installer (the same one-line
# `curl -fsSL .../install.sh | sudo sh` an operator would run by hand) and hand it
# to the root apply service, which runs it. The installer resolves the latest
# release, builds daygle-dns from source with that release version stamped,
# installs the binary, re-provisions the systemd units and seeds AI settings
# - while keeping the deployment's own configuration file ([api] listener,
# console accounts, zones, certificates, database) untouched.
#
# `--models` mode: download the daygle-dns-models.tar.gz bundle from the
# latest release and hand it to the same apply service - no architecture
# matching and no installer, since models are platform-independent data.
#
# Progress is written to <state-dir>/state.json so the console can follow
# along; all command output accumulates in <state-dir>/update.log (the apply
# step publishes its own installer log as apply.log).
#
# Privilege model: this helper runs as the (unprivileged) service account and
# NEVER runs sudo or any setuid helper - that design poisoned every update on
# hardened hosts (the service's CapabilityBoundingSet broke sudo's core audit
# write and sudo aborted before doing anything). Instead this script
# downloads, verifies and stages what needs applying into
# <updates>/staging, then drops a
# `request` marker into <updates>. A root-owned systemd path unit
# (daygle-dns-update.path) watches that directory and starts
# daygle-dns-update.service - a short root oneshot that applies the request
# (installer run / binary swap / model install), restarts the service,
# health-checks and rolls back on failure. This script
# only reaches the hand-off; it exits as soon as the apply step takes over so
# the service restart cannot kill it mid-record.
#
# The script runs as a detached helper so it survives the server's restart;
# `state` files and log output live under the OS temp dir (writable by the
# service user without extra privileges).

set -eu

# Modes: default runs the full installer; `--models` updates the AI model
# bundle (daygle-dns-models.tar.gz) instead - no architecture matching,
# since models are platform-independent data.
MODE="install"
AUTOMATIC=0
if [ "$1" = "--models" ]; then
  MODE="models"
  shift
elif [ "$1" = "--automatic" ]; then
  AUTOMATIC=1
  shift
fi

EXE="$1"
DIR="$2"
LOG="$DIR/update.log"
REPO_OWNER="${DAYGLE_DNS_UPDATE_REPO_OWNER:-daygle}"
REPO_NAME="${DAYGLE_DNS_UPDATE_REPO_NAME:-daygle-dns}"
REPO_URL="${DAYGLE_DNS_UPDATE_REPO:-https://github.com/${REPO_OWNER}/${REPO_NAME}.git}"
LATEST_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest"
LATEST_API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"
BASE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download"

# Escape a message for embedding in a JSON string (backslashes, quotes, and
# control characters). Without handling newlines/tabs, a multi-line error
# would produce invalid JSON that the Rust side reads as idle.
json_escape() {
  # Terminal colour codes (install.sh colours its log lines) and any other
  # control or non-ASCII bytes are dropped first: unescaped, they made the
  # JSON invalid (or cut a character in half), and the console then read
  # the running update as idle.
  printf '%s' "$1" | sed "s/$(printf '\033')\[[0-9;?]*[A-Za-z]//g" | tr -cd '\11\12\40-\176' \
    | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g' | awk '{
    gsub(/\\n/, "\\\\n");
    gsub(/\\r/, "\\\\r");
    if (NR == 1) printf "%s", $0;
    else printf "\\n%s", $0;
  }'
}

# Write state atomically (temp file + rename) so the server's status polls
# never observe a half-written file.
state() { # phase message
  printf '{"phase":"%s","pid":%s,"started_at":"%s","message":"%s","exit_code":0,"automatic":%s}\n' \
    "$1" "$$" "$(date -u +%FT%TZ)" "$(json_escape "$2")" "$([ "$AUTOMATIC" -eq 1 ] && printf true || printf false)" > "$DIR/state.json.tmp" \
    && mv -f "$DIR/state.json.tmp" "$DIR/state.json"
}

fail() { # message
  printf '{"phase":"error","pid":%s,"started_at":"%s","message":"%s","exit_code":1,"automatic":%s}\n' \
    "$$" "$(date -u +%FT%TZ)" "$(json_escape "$1")" "$([ "$AUTOMATIC" -eq 1 ] && printf true || printf false)" > "$DIR/state.json.tmp" \
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

# Big transient artifacts (a fresh source checkout for the installer) should
# not land on /tmp: many distros mount it as tmpfs, so a multi-GB checkout
# plus release build can exhaust memory on small hosts. /var/tmp is the
# conventional spot.
if [ -z "${TMPDIR:-}" ] && [ -d /var/tmp ]; then
  export TMPDIR=/var/tmp
fi

SRC="$(mktemp -d)"

trap 'rm -rf "$SRC"' EXIT HUP INT TERM

state preparing "Preparing update..."

# The hand-off requires the installer-provisioned update service; fail early
# (before any download) so the operator gets the repair without waiting.
if [ ! -f /etc/systemd/system/daygle-dns-update.path ] || [ ! -d "$STAGING" ] || [ ! -w "$STAGING" ]; then
  fail "the systemd update service is not provisioned on this host (daygle-dns-update.path or the updates staging dir is missing). Re-run the installer so it can provision the update service, then retry."
  exit 1
fi

# A downloader (curl or wget) fetches the installer script and the models
# bundle; a git client clones the repository the installer lives in.
DOWNLOADER=""
if command -v curl >/dev/null 2>&1; then
  DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER="wget"
fi

fetch() { # url dest
  case "$DOWNLOADER" in
    curl) curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$1" ;;
    wget) wget -q --tries=3 -O "$2" "$1" ;;
    *) return 1 ;;
  esac
}

# At least one fetch mechanism is required: a downloader fetches the installer
# script (and the models bundle); git clones the repository the installer
# lives in.
if [ -z "$DOWNLOADER" ] && ! command -v git >/dev/null 2>&1; then
  fail "no downloader (curl or wget) and no git is installed; at least one is needed to fetch the installer."
  exit 1
fi

STAGE_SRC=""
TARGET_VERSION=""

# ---- models-only branch --------------------------------------------------
if [ "$MODE" = "models" ]; then
  if [ -z "$DOWNLOADER" ]; then
    fail "no downloader (curl or wget) is installed; it is needed to fetch the AI models bundle."
    exit 1
  fi
  # Resolve the latest release tag with the same API-first logic as the
  # installer path.
  REL_TAG=""
  if fetch "$LATEST_API_URL" "$SRC/release.json" 2>>"$LOG"; then
    REL_TAG="$(grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$SRC/release.json" 2>/dev/null | head -n 1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"//; s/"$//')"
  fi
  if [ -z "$REL_TAG" ] && fetch "$LATEST_URL" "$SRC/release.html" 2>>"$LOG"; then
    REL_TAG="$(sed -n 's/.*releases\/tag\/\([^"/?]*\).*/\1/p' "$SRC/release.html" | head -n 1)"
  fi
  if [ -z "$REL_TAG" ]; then
    fail "could not resolve the latest release (GitHub unreachable or rate-limited) - see update.log."
    exit 1
  fi
  state downloading "Downloading the AI models bundle (${REL_TAG})..."
  BUNDLE_TMP="$SRC/models.tar.gz"
  BUNDLE_SUM="$SRC/models.sha256"
  if fetch "$BASE_URL/$REL_TAG/daygle-dns-models.tar.gz" "$BUNDLE_TMP" 2>>"$LOG" \
     && fetch "$BASE_URL/$REL_TAG/daygle-dns-models.tar.gz.sha256" "$BUNDLE_SUM" 2>>"$LOG"; then
    :
  else
    rm -f "$BUNDLE_TMP" "$BUNDLE_SUM"
    fail "release ${REL_TAG} has no AI models bundle (daygle-dns-models.tar.gz) or it failed to download - see update.log."
    exit 1
  fi

  # Verify the bundle checksum BEFORE staging; a mismatch is fatal.
  state downloading "Verifying the models bundle checksum..."
  EXPECTED="$(cut -d' ' -f1 "$BUNDLE_SUM" 2>/dev/null | tr -d '[:space:]')"
  ACTUAL="$( (sha256sum "$BUNDLE_TMP" 2>/dev/null || shasum -a 256 "$BUNDLE_TMP" 2>/dev/null) | cut -d' ' -f1 | tr -d '[:space:]')"
  if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
    fail "checksum verification failed for the AI models bundle${REL_TAG:+ ($REL_TAG)} - refusing to install it."
    exit 1
  fi
  STAGE_SRC="$BUNDLE_TMP"
  TARGET_VERSION="$(printf '%s' "$REL_TAG" | sed 's/^v//')"

# ---- default: stage the canonical installer -------------------------------
else
  # Fetch the installer from the repository's main branch - the exact script
  # (and URL semantics) the manual one-line command pipes into sh. Without a
  # downloader, a shallow git clone provides the same file.
  state downloading "Fetching the canonical installer (install.sh)..."
  INSTALLER="$SRC/install.sh"
  GOT=0
  if [ -n "$DOWNLOADER" ]; then
    if fetch "https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/main/install.sh" "$INSTALLER" 2>>"$LOG" \
       && [ -s "$INSTALLER" ]; then
      GOT=1
    else
      rm -f "$INSTALLER"
    fi
  fi
  if [ "$GOT" -eq 0 ] && command -v git >/dev/null 2>&1; then
    if git clone --depth 1 "$REPO_URL" "$SRC/repo" >>"$LOG" 2>&1 \
       && cp -f "$SRC/repo/install.sh" "$INSTALLER"; then
      GOT=1
    else
      rm -f "$INSTALLER"
    fi
  fi
  if [ "$GOT" -eq 0 ]; then
    fail "the canonical installer could not be fetched - check network access to $REPO_URL (see update.log)."
    exit 1
  fi

  # Resolve the latest release tag: the GitHub API is authoritative (and
  # cheap); the /releases/latest HTML redirect is the fallback if the API is
  # unreachable or rate-limited. The installer stamps the built binary with
  # this version and refuses to build without one, so resolve it here too -
  # naming the tag lets errors say exactly which release this run targets.
  state downloading "Resolving the latest release..."
  REL_TAG=""
  if fetch "$LATEST_API_URL" "$SRC/release.json" 2>>"$LOG"; then
    REL_TAG="$(grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$SRC/release.json" 2>/dev/null | head -n 1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"//; s/"$//')"
  fi
  if [ -z "$REL_TAG" ] && fetch "$LATEST_URL" "$SRC/release.html" 2>>"$LOG"; then
    REL_TAG="$(sed -n 's/.*releases\/tag\/\([^"/?#]*\).*/\1/p' "$SRC/release.html" | head -n 1)"
  fi
  if [ -z "$REL_TAG" ]; then
    fail "could not resolve the latest release (GitHub unreachable or rate-limited); the installer would refuse to build a stale version - see update.log."
    exit 1
  fi
  TARGET_VERSION="$(printf '%s' "$REL_TAG" | sed 's/^v//')"
  STAGE_SRC="$INSTALLER"
fi

# The manifest's version is free text but must be dotted numerics for the
# apply step to accept it.
TARGET_VERSION="$(printf '%s' "$TARGET_VERSION" | sed 's/^v//' | grep -o '[0-9][0-9.]*' | head -n 1 || true)"
[ -n "$TARGET_VERSION" ] || TARGET_VERSION="0.0.0"

# ---- stage and hand off to the root apply service ------------------------

# Stage the verified artifact + manifest into the staging subdir (which the
# watcher does NOT monitor), then atomically create the top-level `request`
# marker that triggers daygle-dns-update.service.
stage_and_trigger() { # staged-file target-version kind
  stage_file="$1"
  tgt_ver="$2"
  stage_kind="$3"
  [ -f "$stage_file" ] || return 1
  rm -f "$STAGING/apply.bin" "$STAGING/apply.json" "$UPDATES_DIR/request" "$UPDATES_DIR/request.processing"
  cp -f "$stage_file" "$STAGING/apply.bin" 2>/dev/null || return 1
  sha="$( (sha256sum "$STAGING/apply.bin" 2>/dev/null || shasum -a 256 "$STAGING/apply.bin" 2>/dev/null) | cut -d' ' -f1 | tr -d '[:space:]')"
  [ -n "$sha" ] || return 1
  printf '{"kind":"%s","version":"%s","sha256":"%s","automatic":%s}\n' "$stage_kind" "$tgt_ver" "$sha" "$([ "$AUTOMATIC" -eq 1 ] && printf true || printf false)" > "$STAGING/apply.json" || return 1
  : > "$UPDATES_DIR/request" || return 1
}

state installing "Update ready - handing off to the systemd update service (v${TARGET_VERSION})..."
if ! stage_and_trigger "$STAGE_SRC" "$TARGET_VERSION" "$MODE"; then
  WHY="$(last_log_error)"
  fail "the update could not be staged into $STAGING${WHY:+: $WHY}. Re-run the installer to repair the update service, then retry."
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