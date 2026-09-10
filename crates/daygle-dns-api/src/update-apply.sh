#!/usr/bin/env sh
# Daygle DNS - root-side apply step for in-place updates.
#
# Started by systemd: the daygle-dns-update.path watcher fires whenever the
# unprivileged service account drops a `request` marker into the updates dir,
# and daygle-dns-update.service runs this script as root (a short oneshot).
#
# It performs the ONLY privileged work an update needs - swap the binary,
# restart the unit, health-check, roll back on failure - and writes its
# progress to the same <temp>/daygle-dns-update/state.json the console polls.
# No sudo, no setuid, no capability gymnastics: the privileged step is a
# normal root systemd unit, so the service account itself never gains any
# rights beyond the staging dir it already owns.
#
# Contract (paths baked by install.sh via __DAYGLE_EXE__/__DAYGLE_UPDATES_DIR__):
#   <updates>/request               - empty trigger marker (created atomically
#                                     by the updater after staging completes)
#   <updates>/staging/apply.json   - {"version":"x.y.z","sha256":"<64hex>"}
#   <updates>/staging/apply.bin    - the staged, checksum-verified binary
#
# Only the fixed staging paths are ever touched (the manifest cannot select a
# path), and the staged binary is validated against the manifest's sha256, so
# a hostile request cannot cause an arbitrary file to be installed.

set -eu

EXE="__DAYGLE_EXE__"
UPDATES_DIR="__DAYGLE_UPDATES_DIR__"
STAGING="$UPDATES_DIR/staging"
REQ="$UPDATES_DIR/request"
DIR="${DAYGLE_UPDATE_DIR:-/tmp/daygle-dns-update}"
LOG="$DIR/update.log"

log() { printf '[daygle-dns-update] %s\n' "$*" >>"$LOG"; }

# Escape a message for embedding in a JSON string (see update.sh).
json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g' | awk '{
    gsub(/\\n/, "\\\\n");
    gsub(/\\r/, "\\\\r");
    if (NR == 1) printf "%s", $0;
    else printf "\\n%s", $0;
  }'
}

# Write state atomically (temp file + rename) so status polls never observe a
# half-written file.
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

mkdir -p "$DIR"

# Nothing pending: the marker's own rename/removal events can re-trigger this
# unit; a run without a request is a clean no-op.
if [ ! -f "$REQ" ]; then
  exit 0
fi

# Consume the marker before doing anything so a crash mid-apply cannot make
# the watcher re-fire it endlessly.
mv -f "$REQ" "$REQ.processing"

MANIFEST="$STAGING/apply.json"
BIN="$STAGING/apply.bin"

if [ ! -f "$MANIFEST" ] || [ ! -f "$BIN" ]; then
  log "request present but staged manifest/binary missing"
  rm -f "$REQ.processing"
  fail "the update was requested but its staged manifest or binary is missing. Re-run the update from the console; if it persists, re-run the installer."
  exit 1
fi

VERSION="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MANIFEST" | head -n 1)"
SHA256="$(sed -n 's/.*"sha256"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MANIFEST" | head -n 1)"
BAD=""

# Strict validation of the manifest: version is dotted numerics only; sha256
# is exactly 64 hex chars. Nothing in the manifest ever selects a path.
case "$VERSION" in
  ''|*[!0-9.]*|*..*|.*|*.) BAD="invalid version '$VERSION' in the update manifest" ;;
esac
case "$SHA256" in
  ''|*[!0-9a-fA-F]*) BAD="invalid sha256 in the update manifest" ;;
esac
if [ -z "$BAD" ] && [ "${#SHA256}" -ne 64 ]; then
  BAD="invalid sha256 length in the update manifest"
fi
if [ -n "$BAD" ]; then
  log "rejecting update: $BAD"
  rm -f "$REQ.processing"
  fail "the staged update was rejected (${BAD}). Re-run the update from the console."
  exit 1
fi

ACTUAL="$( (sha256sum "$BIN" 2>/dev/null || shasum -a 256 "$BIN" 2>/dev/null) | cut -d' ' -f1 | tr -d '[:space:]')"
if [ -z "$ACTUAL" ] || [ "$ACTUAL" != "$SHA256" ]; then
  log "rejecting update: sha256 mismatch (expected $SHA256, got ${ACTUAL:-none})"
  rm -f "$REQ.processing"
  fail "the staged binary failed checksum verification - refusing to install it. Re-run the update from the console."
  exit 1
fi

state applying "Applying release v${VERSION}…"
log "applying v${VERSION} from $BIN"

# Back up the current binary for rollback (best effort). Prefer the image of
# the RUNNING process: a previous update can have swapped the on-disk file
# while this server keeps running from the old inode, leaving the path
# reported as "... (deleted)" - copying /proc/<MainPID>/exe captures the true
# running version in that case. Then swap via a temp name + rename: writing
# over a running executable fails with "Text file busy" (ETXTBSY), while
# rename(2) swaps the directory entry atomically.
MAINPID="$(systemctl show daygle-dns -p MainPID --value 2>/dev/null || true)"
BACKUP_SRC="$EXE"
case "$MAINPID" in
  ''|0) ;;
  *) if [ -r "/proc/$MAINPID/exe" ]; then BACKUP_SRC="/proc/$MAINPID/exe"; fi ;;
esac
cp -f "$BACKUP_SRC" "$EXE.bak" 2>/dev/null || true
rm -f "$EXE.new"
if ! install -m 0755 "$BIN" "$EXE.new"; then
  rm -f "$EXE.new" "$REQ.processing"
  fail "installing the new binary to $EXE failed (install step). Please check the disk and retry."
  exit 1
fi
if ! mv -f "$EXE.new" "$EXE"; then
  rm -f "$EXE.new" "$REQ.processing"
  fail "installing the new binary to $EXE failed (swap step). Please check the disk and retry."
  exit 1
fi

state restarting "Restarting the service…"
if ! systemctl restart daygle-dns; then
  log "systemctl restart daygle-dns failed after install"
  rm -f "$REQ.processing"
  if [ -f "$EXE.bak" ]; then
    mv -f "$EXE.bak" "$EXE"
    systemctl restart daygle-dns 2>>"$LOG" || true
    fail "the new binary was installed but the service restart failed; the previous version was restored."
  else
    fail "the new binary was installed but the service restart failed and no backup was available for rollback."
  fi
  exit 1
fi

# Health check: the service must come back and the API answer. Phase stays
# "restarting" (a running phase) so the console keeps polling.
i=0
HEALTHY=0
while [ $i -lt 15 ]; do
  sleep 1
  if systemctl is-active --quiet daygle-dns 2>/dev/null \
     && curl -fsSL --max-time 2 http://localhost:5380/api/health >/dev/null 2>&1; then
    HEALTHY=1
    break
  fi
  i=$((i + 1))
done

rm -f "$REQ.processing" "$MANIFEST" "$BIN"

if [ "$HEALTHY" -eq 1 ]; then
  log "applied v${VERSION} and health check passed"
  state done "Update installed and verified successfully (v${VERSION})."
  exit 0
fi

log "health check failed after update - rolling back"
if [ -f "$EXE.bak" ]; then
  state rolling_back "Update failed - rolling back to the previous version…"
  mv -f "$EXE.bak" "$EXE"
  systemctl restart daygle-dns 2>>"$LOG" || true
  fail "Update failed - successfully rolled back to the previous version. Release v${VERSION} did not pass its health check."
  exit 1
fi
fail "Update installed but the health check failed and no backup was available for rollback. Manual intervention required."
exit 1