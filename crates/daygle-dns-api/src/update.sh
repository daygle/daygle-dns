#!/usr/bin/env sh
# Daygle DNS in-place update, driven by the web console.
#
# Usage: sh daygle-dns-update.sh <current-binary> <state-dir>
#
# Preferred path: download the prebuilt release binary for this architecture
# from GitHub Releases, verify its sha256 checksum, swap it in place, and
# restart the systemd service - no Rust toolchain, no git, no compilation on
# the host. Fallback path (only when no release asset can be fetched): build
# from source, the way install.sh does. Progress is written to
# <state-dir>/state.json so the console can follow along; all command output
# accumulates in <state-dir>/update.log.
#
# Privilege model: the helper runs as the service account and only invokes
# root for two narrow steps (swap the binary, restart the service) through
# the root-owned update-priv.sh installed by install.sh under a sudo rule
# that permits exactly that script - the service account never gets broad
# root access. On older installs with a passwordless ALL grant, the generic
# sudo fallback still works.
#
# The script runs as a detached helper so it survives the server's restart.
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
# control characters). Without handling newlines/tabs, a multi-line sudo error
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

# Most recent meaningful log line, for embedding in error messages: without
# this, a failed sudo invocation (whose stderr only goes to the log) leaves
# the console saying "install failed" with no hint as to why.
last_log_error() {
  tail -n 8 "$LOG" 2>/dev/null | tr '\r' '\n' | grep -v '^[[:space:]]*$' | tail -n 1 | cut -c1-200
}

# Detect a host whose sudo policy itself is broken: one unparsable sudoers
# file makes EVERY sudo command die with the audit-plugin error, which no
# updater-side retry can fix. Name the likely cause and the exact repair.
sudo_broken_hint() {
  local log_snippet
  log_snippet="$(tail -n 40 "$LOG" 2>/dev/null)"
  # Actual sudoers syntax errors: every sudo command is refused.
  if printf '%s' "$log_snippet" | grep -q "no valid sudoers sources\|parse error in /etc/sudoers"; then
    printf '%s' "the sudo policy on this host is broken (a sudoers file fails to parse, so every sudo command fails). Repair it before retrying: as root, run 'visudo -cf /etc/sudoers /etc/sudoers.d/*' to find the offending file. The most common cause is an '@includedir /etc/sudoers.d' line appended by older installer versions on sudo < 1.9.3 - change '@includedir' to '#includedir' in /etc/sudoers."
    return
  fi
  # The audit plugin warning alone is non-fatal on hosts where auditd is not
  # installed; only flag it when the actual sudoers errors are absent.
  if printf '%s' "$log_snippet" | grep -q "audit plugin sudoers_audit"; then
    printf '%s' "sudo reports an audit-plugin initialisation warning (auditd may not be installed). This is usually harmless but can be silenced: as root, edit /etc/sudo.conf and uncomment only the policy and I/O plugin lines (leave sudoers_audit commented out)."
  fi
}

# ---- Rollback support ----------------------------------------------------
# Before installing a new binary, we create a timestamped backup. If the new
# binary fails health checks after restart, we can automatically revert.

BACKUP_DIR="$DIR/backups"
ROLLBACK_INFO="$DIR/rollback.json"

# Create a backup of the current binary before updating.
create_backup() {
  local backup_name="daygle-dns.$(date -u +%Y%m%dT%H%M%SZ)"
  local backup_path="$BACKUP_DIR/$backup_name"
  mkdir -p "$BACKUP_DIR"
  
  # Copy the current binary
  if [ -f "$EXE" ]; then
    cp -f "$EXE" "$backup_path" 2>/dev/null || true
    chmod 0755 "$backup_path" 2>/dev/null || true
    
    # Record rollback information
    printf '{"backup":"%s","original":"%s","timestamp":"%s","version":"%s"}\n' \
      "$backup_path" "$EXE" "$(date -u +%FT%TZ)" "$(${EXE} --version 2>/dev/null | head -n1 || echo unknown)" \
      > "$ROLLBACK_INFO"
    
    # Keep only the last 3 backups
    ls -1t "$BACKUP_DIR"/daygle-dns.* 2>/dev/null | tail -n +4 | xargs rm -f 2>/dev/null || true
    
    return 0
  fi
  return 1
}

# Attempt to rollback to the previous binary if the update failed.
# Returns 0 if rollback succeeded, 1 if no backup exists or rollback failed.
attempt_rollback() {
  if [ ! -f "$ROLLBACK_INFO" ]; then
    return 1
  fi
  
  local backup_path
  backup_path=$(grep -o '"backup":"[^"]*"' "$ROLLBACK_INFO" | cut -d'"' -f4)
  
  if [ -z "$backup_path" ] || [ ! -f "$backup_path" ]; then
    return 1
  fi
  
  state rolling_back "Update failed - rolling back to previous version…"
  
  # Try to restore the backup
  if priv_install "$backup_path"; then
    state done "Update failed - successfully rolled back to previous version. Please fix the issue and try again."
    return 0
  else
    state error "Update failed and rollback also failed. Manual intervention required. Previous binary backup: $backup_path"
    return 1
  fi
}

# Verify the new binary is functional before declaring success.
# Returns 0 if healthy, 1 if unhealthy.
health_check() {
  local check_exe="$1"
  
  # Wait a moment for the binary to be ready
  sleep 2
  
  # Check if the binary can at least show its version
  if ! "$check_exe" --version >/dev/null 2>&1; then
    return 1
  fi
  
  # Check if the service is responding (if systemd is available)
  if [ -f /etc/systemd/system/daygle-dns.service ] && command -v systemctl >/dev/null 2>&1; then
    # Give the service up to 10 seconds to start
    local i=0
    while [ $i -lt 10 ]; do
      if systemctl is-active --quiet daygle-dns 2>/dev/null; then
        # Service is active, try to reach the API
        if curl -fsSL --max-time 2 http://localhost:5380/api/health >/dev/null 2>&1; then
          return 0
        fi
      fi
      sleep 1
      i=$((i + 1))
    done
    return 1
  fi
  
  # No systemd: just check that the binary is executable
  return 0
}

# Root-owned privilege helper installed by install.sh; permits exactly the
# binary swap and service restart - nothing else. May also sit beside a
# custom-PREFIX install: derive candidates from the binary's own location.
PRIV_HELPER=""
EXE_DIR="$(dirname "$EXE")"
for cand in /usr/local/lib/daygle-dns/update-priv.sh \
            /usr/local/libexec/daygle-dns/update-priv.sh \
            /usr/lib/daygle-dns/update-priv.sh \
            "$EXE_DIR/../lib/daygle-dns/update-priv.sh" \
            "$EXE_DIR/../libexec/daygle-dns/update-priv.sh"; do
  # Canonicalize each candidate (resolve "/.." segments): sudo matches the
  # command literally, and "sudo /usr/local/bin/../lib/x" does NOT match a
  # sudoers rule written for "/usr/local/lib/x" - so a perfectly installed
  # helper would be refused and silently fall back to generic sudo.
  cand="$(cd "$(dirname "$cand")" 2>/dev/null && pwd)/$(basename "$cand")"
  if [ -x "$cand" ]; then
    PRIV_HELPER="$cand"
    break
  fi
done

SUDO_HINT=""
if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
  SUDO_HINT="sudo is not installed"
elif [ "$(id -u)" -ne 0 ] && [ -z "$PRIV_HELPER" ] && command -v sudo >/dev/null 2>&1 \
     && ! sudo -n true >/dev/null 2>&1; then
  # Deliberately not probed when a privilege helper exists: the narrowed
  # sudoers rule permits only that helper, so a generic `sudo -n true`
  # failure would be meaningless there.
  SUDO_HINT="passwordless sudo is not configured for this account (re-running install.sh provisions the privilege helper)"
fi

# Swap the current binary for a new one. Prefers the narrowed helper; on
# failure falls back to the account's own sudo rights (covers hosts upgraded
# from the old broad-grant installer where the helper exists but its rule
# does not, and vice versa). All privileged output goes to the log.
priv_install() { # src
  if [ -z "${1:-}" ] || [ ! -f "$1" ]; then
    echo "priv_install: refusing to install - source binary missing or unreadable: ${1:-<none>}" >>"$LOG"
    return 1
  fi
  if [ "$(id -u)" -eq 0 ]; then
    cp -f "$EXE" "$EXE.bak" 2>/dev/null || true
    # Install beside the target and rename: writing over a running
    # executable in place can fail with "Text file busy" (ETXTBSY), while
    # rename(2) swaps the directory entry without touching the live inode.
    rm -f "$EXE.new"
    install -m 0755 "$1" "$EXE.new" && mv -f "$EXE.new" "$EXE"
    return
  fi
  if [ -n "$PRIV_HELPER" ] && command -v sudo >/dev/null 2>&1; then
    if sudo -n "$PRIV_HELPER" install "$1" >>"$LOG" 2>&1; then
      return 0
    fi
    # The helper was refused (rule mismatch, mixed install state, ...) - try
    # the generic sudo path before giving up.
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo -n cp -f "$EXE" "$EXE.bak" 2>>"$LOG" || true
    sudo -n rm -f "$EXE.new" 2>>"$LOG" || true
    if sudo -n install -m 0755 "$1" "$EXE.new" >>"$LOG" 2>&1 \
       && sudo -n mv -f "$EXE.new" "$EXE" >>"$LOG" 2>&1; then
      return 0
    fi
  fi
  return 1
}

priv_restart() {
  if [ "$(id -u)" -eq 0 ]; then
    systemctl restart daygle-dns
    return 0
  fi
  if [ -n "$PRIV_HELPER" ] && command -v sudo >/dev/null 2>&1; then
    if sudo -n "$PRIV_HELPER" restart >>"$LOG" 2>&1; then
      return 0
    fi
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo -n systemctl restart daygle-dns >>"$LOG" 2>&1
    return
  fi
  return 1
}

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

  # Create backup before installing new binary
  state preparing "Creating backup of current binary…"
  if ! create_backup; then
    echo "Warning: could not create backup, continuing anyway" >>"$LOG"
  fi

  state installing "Installing the release binary…"
  # priv_install keeps a .bak copy of the current binary as a manual rollback
  # point (best effort; a release that installs can still fail at runtime).
  if ! priv_install "$SRC/daygle-dns"; then
    WHY="$(last_log_error)"
    BROKEN="$(sudo_broken_hint)"
    fail "installing the release binary to $EXE failed${WHY:+: $WHY}.${BROKEN:+ $BROKEN}${SUDO_HINT:+ (${SUDO_HINT})}"
    exit 1
  fi
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
    fail "no release binary could be downloaded ($DL_WHY) and cargo was not found${SUDO_HINT:+; privilege checks also failed ($SUDO_HINT)}; install the Rust toolchain (curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal) and retry."
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

  # Create backup before installing new binary
  state preparing "Creating backup of current binary…"
  if ! create_backup; then
    echo "Warning: could not create backup, continuing anyway" >>"$LOG"
  fi

  state installing "Installing the new binary…"
  if ! priv_install target/release/daygle-dns; then
    WHY="$(last_log_error)"
    BROKEN="$(sudo_broken_hint)"
    fail "installing the new binary to $EXE failed${WHY:+: $WHY}.${BROKEN:+ $BROKEN}${SUDO_HINT:+ (${SUDO_HINT})}"
    exit 1
  fi
fi

if [ -f /etc/systemd/system/daygle-dns.service ] && command -v systemctl >/dev/null 2>&1; then
  # The restart is issued strictly after "done" is written: systemd kills the
  # old unit's cgroup (which includes this helper) once the service stops.
  state done "Update installed - restarting the service…"
  if ! priv_restart >>"$LOG" 2>&1; then
    WHY="$(last_log_error)"
    state done "Update installed - restart daygle-dns manually (auto-restart failed${WHY:+: $WHY})."
    exit 0
  fi
  
  # Health check after restart - wait for service to come up
  state checking "Verifying the new binary is working…"
  if ! health_check "$EXE"; then
    echo "Health check failed after update, attempting rollback" >>"$LOG"
    if attempt_rollback; then
      priv_restart >>"$LOG" 2>&1 || true
      exit 0
    else
      state error "Update installed but health check failed and rollback was not possible. Manual intervention required."
      exit 1
    fi
  fi
  
  state done "Update installed and verified successfully."
  exit 0
fi

# No systemd: the new binary is in place; the operator restarts manually.
state done "Update installed - restart daygle-dns to use the new binary."
exit 0
