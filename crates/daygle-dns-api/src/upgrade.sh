#!/usr/bin/env sh
# Daygle DNS in-place update, driven by the web console.
#
# Usage: sh daygle-dns-upgrade.sh <current-binary> <state-dir>
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
SRC="$(mktemp -d)"
LOG="$DIR/update.log"
REPO="${DAYGLE_UPGRADE_REPO:-https://github.com/daygle/daygle-dns.git}"

trap 'rm -rf "$SRC"' EXIT HUP INT TERM

state() { # phase message
  printf '{"phase":"%s","pid":%s,"started_at":"%s","message":"%s","exit_code":0}\n' \
    "$1" "$$" "$(date -u +%FT%TZ)" "$2" > "$DIR/state.json"
}

fail() { # phase message
  printf '{"phase":"error","pid":%s,"started_at":"%s","message":"%s","exit_code":1}\n' \
    "$$" "$(date -u +%FT%TZ)" "$1" > "$DIR/state.json"
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
if ! command -v cargo >/dev/null 2>&1; then
  fail "cargo is required to update; install Rust and try again."
  exit 1
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