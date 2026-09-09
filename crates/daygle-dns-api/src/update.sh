#!/usr/bin/env sh
# Daygle DNS in-place update, driven by the web console.
#
# Usage: sh daygle-dns-update.sh <current-binary> <state-dir>
#
# Mirrors what install.sh does for an existing installation: clone the latest
# source, build a release binary, swap it in place, and restart the systemd
# service. Progress is written to <state-dir>/state.json so the console can
# follow along; all command output accumulates in <state-dir>/update.log.
#
# The script runs as a detached helper so it survives the server's restart.
# `state` files and log output live under the OS temp dir (writable by the
# service user without extra privileges).

set -u

EXE="$1"
DIR="$2"
LOG="$DIR/update.log"
REPO="${DAYGLE_UPDATE_REPO:-https://github.com/daygle/daygle-dns.git}"

# systemd service accounts usually have no sudo and a bare PATH, so cargo (as
# installed by rustup for the operator/root) is unreachable. When passwordless
# sudo is available, re-exec the whole updater as root: the same pid is kept
# (exec), state and log stay where they are, and the build/install/restart
# steps all write to their normal locations. Otherwise the script continues
# as the service user with whatever tooling it can reach.
SUDO_HINT=""
if [ "$(id -u)" -ne 0 ]; then
  if ! command -v sudo >/dev/null 2>&1; then
    SUDO_HINT="sudo is not installed"
  elif ! sudo -n true >/dev/null 2>&1; then
    SUDO_HINT="passwordless sudo is not configured for this account (re-running install.sh provisions it)"
  else
    exec sudo -n sh "$0" "$EXE" "$DIR"
  fi
fi

# Big transient artifacts (the build tree, the cargo registry cache) should
# not land on /tmp: many distros mount it as tmpfs, so a multi-GB release
# build can exhaust memory on small hosts. /var/tmp is the conventional spot.
# (Placed after the sudo re-exec because sudo strips env: this way both the
# service-account and root paths get it.)
if [ -z "${TMPDIR:-}" ] && [ -d /var/tmp ]; then
  export TMPDIR=/var/tmp
fi

SRC="$(mktemp -d)"

trap 'rm -rf "$SRC"' EXIT HUP INT TERM

# Escape a message for embedding in a JSON string (backslashes and quotes).
json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
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

run_as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -n "$@"
  else
    return 1
  fi
}

state preparing "Preparing update…"

if ! command -v git >/dev/null 2>&1; then
  fail "git is required to update; install git and try again."
  exit 1
fi

# Cargo may live almost anywhere: on this account's PATH, rustup's layout for
# any plausible user, or a distro package (/usr/bin). Prefer `rustup which`
# when rustup is reachable, then crawl the standard spots.
CARGO_BIN=""
if command -v rustup >/dev/null 2>&1; then
  CARGO_BIN="$(rustup which cargo 2>/dev/null || true)"
fi
if [ -z "$CARGO_BIN" ]; then
  if command -v cargo >/dev/null 2>&1; then
    CARGO_BIN="$(command -v cargo)"
  else
    for cand in "$HOME/.cargo/bin/cargo" \
                /root/.cargo/bin/cargo \
                /home/*/.cargo/bin/cargo \
                "${CARGO_HOME:-/.cargo}/bin/cargo" \
                /usr/bin/cargo \
                /usr/local/bin/cargo \
                /snap/bin/cargo; do
      if [ -x "$cand" ]; then
        CARGO_BIN="$cand"
        break
      fi
    done
  fi
fi
# Last resort: ask the filesystem. A bare PATH on a service account does not
# mean the toolchain is missing - rustup under another user's home (or under
# /opt) is the common case, and the binary there is usually world-executable.
if [ -z "$CARGO_BIN" ] && command -v find >/dev/null 2>&1; then
  CARGO_BIN="$(find /root /home /opt /usr -maxdepth 4 -type f -name cargo -perm -u+x 2>/dev/null | head -n 1)"
fi
if [ -z "$CARGO_BIN" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    fail "cargo was not found; install the Rust toolchain (curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal), then retry."
  else
    fail "cargo was not found and ${SUDO_HINT:-passwordless sudo is unavailable}; install the Rust toolchain for this account, or re-run install.sh as root to provision passwordless sudo, then retry."
  fi
  exit 1
fi
export PATH="$(dirname "$CARGO_BIN"):$PATH"

# cargo writes its registry to $CARGO_HOME (default $HOME/.cargo). systemd
# accounts may have no usable home directory; fall back to a writable dir
# inside the state directory so the build can proceed and cache across runs.
if [ -z "${CARGO_HOME:-}" ]; then
  if [ -n "${HOME:-}" ] && [ -d "$HOME" ] && [ -w "$HOME" ]; then
    :
  else
    # Prefer /var/tmp so the registry cache survives reboots and stays off a
    # tmpfs-backed /tmp; fall back to the state dir when it is not writable.
    CARGO_HOME="/var/tmp/daygle-dns-cargo-home"
    if ! mkdir -p "$CARGO_HOME" 2>/dev/null || [ ! -w "$CARGO_HOME" ]; then
      CARGO_HOME="$DIR/cargo-home"
      mkdir -p "$CARGO_HOME"
    fi
    export CARGO_HOME
  fi
fi

state cloning "Fetching the latest source…"
if ! git clone --depth 1 "$REPO" "$SRC" >>"$LOG" 2>&1; then
  fail "git clone failed - check network access to $REPO (see update.log)."
  exit 1
fi

cd "$SRC"

state building "Building the release binary (this can take a few minutes)…"
if ! cargo build --release -p daygle-dns >>"$LOG" 2>&1; then
  fail "build failed - see update.log for details."
  exit 1
fi

state installing "Installing the new binary…"
if ! command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
  fail "cannot install the new binary: sudo is not installed. Re-run install.sh as root to provision passwordless sudo, then retry."
  exit 1
fi
# Keep a copy of the current binary as a manual rollback point (best effort;
# a release that builds can still fail at runtime).
run_as_root cp -f "$EXE" "$EXE.bak" >>"$LOG" 2>&1 || true
if ! run_as_root install -m 0755 target/release/daygle-dns "$EXE"; then
  fail "installing the new binary to $EXE failed (needs root or passwordless sudo)."
  exit 1
fi

if [ -f /etc/systemd/system/daygle-dns.service ] && command -v systemctl >/dev/null 2>&1; then
  # The restart is issued strictly after "done" is written: systemd kills the
  # old unit's cgroup (which includes this helper) once the service stops.
  state done "Update installed - restarting the service…"
  if ! run_as_root systemctl restart daygle-dns >>"$LOG" 2>&1; then
    state done "Update installed - restart daygle-dns manually (auto-restart failed)."
  fi
  exit 0
fi

# No systemd: the new binary is in place; the operator restarts manually.
state done "Update installed - restart daygle-dns to use the new binary."
exit 0