#!/usr/bin/env sh
# Daygle DNS - root-side apply step for in-place updates.
#
# Started by systemd: the daygle-dns-update.path watcher fires whenever the
# unprivileged service account drops a `request` marker into the updates dir,
# and daygle-dns-update.service runs this script as root (a short oneshot).
#
# It performs the ONLY privileged work an update needs - swap the binary,
# restart the unit, health-check, roll back on failure - and writes its
# progress to the same <temp>/daygle-dns-update/state.json the console polls
# (plus its own log as apply.log next to it).
# No sudo, no setuid, no capability gymnastics: the privileged step is a
# normal root systemd unit, so the service account itself never gains any
# rights beyond the staging dir it already owns.
#
# Contract (paths baked by install.sh via __DAYGLE_DNS_EXE__/
# __DAYGLE_DNS_UPDATES_DIR__/__DAYGLE_DNS_MODELS_DIR__/__DAYGLE_DNS_USER__):
#   <updates>/request               - empty trigger marker (created atomically
#                                     by the updater after staging completes)
#   <updates>/staging/apply.json   - {"kind":"release|models","version":"x.y.z","sha256":"<64hex>"}
#   <updates>/staging/apply.bin    - the staged, checksum-verified binary (or
#                                     models bundle tar.gz for kind=models)
#
# Only the fixed staging paths are ever touched (the manifest cannot select a
# path), and the staged binary is validated against the manifest's sha256, so
# a hostile request cannot cause an arbitrary file to be installed.

set -eu

EXE="__DAYGLE_DNS_EXE__"
UPDATES_DIR="__DAYGLE_DNS_UPDATES_DIR__"
MODELS_DIR="__DAYGLE_DNS_MODELS_DIR__"
SERVICE_USER="__DAYGLE_DNS_USER__"
STAGING="$UPDATES_DIR/staging"
REQ="$UPDATES_DIR/request"
DIR="${DAYGLE_DNS_UPDATE_DIR:-/tmp/daygle-dns-update}"

# The manifest may only install AI model files with these exact flat names
# (mirrors update.rs MODEL_FILES). Nothing in a manifest or a bundle ever
# selects another path.
MODEL_WHITELIST="daygle-starter.bin all-MiniLM-L6-v2-int8.onnx minilm-tokenizer.json minilm-centroids.json"

# This step runs as root, but $DIR (and everything under $UPDATES_DIR) is
# writable by the unprivileged service account. Root therefore never opens
# (reads, writes or appends to) a path in those directories: progress and
# log output are written to a root-private scratch dir and only *renamed*
# into $DIR, and the staged binary is copied out before it is verified, so a
# symlink or a file swapped in mid-run cannot redirect a root write or slip
# an unverified binary past the checksum.
PRIV="$(mktemp -d)"
trap 'rm -rf "$PRIV"' EXIT HUP INT TERM
LOG="$PRIV/apply.log"
: >"$LOG"

# Only publish into the workspace when it is a real directory (the service
# creates it before requesting an update); never create it as root, which
# would leave a root-owned workspace the service cannot use.
PUBLISH=1
if [ -L "$DIR" ] || [ ! -d "$DIR" ]; then
  PUBLISH=0
fi

# Rename a finished root-private file into the workspace.
publish() { # private-file name
  [ "$PUBLISH" -eq 1 ] || return 0
  chmod 0644 "$1" 2>/dev/null || true
  mv -f "$1" "$DIR/$2" 2>/dev/null || true
}

log() {
  printf '[daygle-dns-update] %s\n' "$*" >>"$LOG"
  { cp -f "$LOG" "$PRIV/apply.log.pub" && publish "$PRIV/apply.log.pub" apply.log; } || true
}

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
    "$1" "$$" "$(date -u +%FT%TZ)" "$(json_escape "$2")" > "$PRIV/state.json" \
    && publish "$PRIV/state.json" state.json
}

fail() { # message
  printf '{"phase":"error","pid":%s,"started_at":"%s","message":"%s","exit_code":1}\n' \
    "$$" "$(date -u +%FT%TZ)" "$(json_escape "$1")" > "$PRIV/state.json" \
    && publish "$PRIV/state.json" state.json
}

# Most recent meaningful line of an arbitrary log file (see the installer
# branch, which streams the installer's last line as state).
last_log_error_from_file() {
  tail -n 8 "$1" 2>/dev/null | tr '\r' '\n' | grep -v '^[[:space:]]*$' | tail -n 1 | cut -c1-200
}

# The API endpoint the health check probes, read from the [api] section of
# the config file next to the models dir (defaults: 127.0.0.1:5380). A
# hard-coded port/host would fail the check - and roll back every update - on
# hosts whose console listens elsewhere. Only digits / address characters are
# accepted from the (service-writable) file.
CONFIG_FILE="${MODELS_DIR%/*}/daygle-dns.toml"
api_setting() { # key
  awk -v key="$1" '
    /^\[api\][[:space:]]*$/ { in_api = 1; next }
    /^\[/ { in_api = 0 }
    in_api {
      line = $0
      sub(/#.*/, "", line)
      if (line ~ "^[[:space:]]*" key "[[:space:]]*=") {
        sub(/^[^=]*=[[:space:]]*/, "", line)
        gsub(/["[:space:]]/, "", line)
        print line
        exit
      }
    }
  ' "$CONFIG_FILE" 2>/dev/null || true
}
API_PORT="$(api_setting port)"
case "$API_PORT" in ''|*[!0-9]*) API_PORT=5380 ;; esac
API_HOST="$(api_setting listen)"
case "$API_HOST" in
  ''|0.0.0.0|*[!0-9A-Fa-f.:]*) API_HOST=127.0.0.1 ;;
  ::) API_HOST='[::1]' ;;
  *:*) API_HOST="[$API_HOST]" ;;
esac
HEALTH_URL="http://$API_HOST:$API_PORT/api/health"

# Wait up to 15s for the unit to be active and the API to answer.
health_check() {
  i=0
  while [ $i -lt 15 ]; do
    sleep 1
    if systemctl is-active --quiet daygle-dns 2>/dev/null \
       && curl -fsS --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
  done
  return 1
}

# Nothing pending: the marker's own rename/removal events can re-trigger this
# unit; a run without a request is a clean no-op.
if [ ! -f "$REQ" ]; then
  exit 0
fi

# Consume the marker before doing anything so a crash mid-apply cannot make
# the watcher re-fire it endlessly.
mv -f "$REQ" "$REQ.processing"

MANIFEST="$STAGING/apply.json"
STAGED_BIN="$STAGING/apply.bin"
# Verify and install a root-private copy, never the service-writable file.
BIN="$PRIV/apply.bin"

if [ ! -f "$MANIFEST" ] || [ ! -f "$STAGED_BIN" ] || [ -L "$STAGED_BIN" ] \
   || ! cp "$STAGED_BIN" "$BIN"; then
  log "request present but staged manifest/binary missing"
  rm -f "$REQ.processing"
  fail "the update was requested but its staged manifest or binary is missing. Re-run the update from the console; if it persists, re-run the installer."
  exit 1
fi

VERSION="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MANIFEST" | head -n 1)"
SHA256="$(sed -n 's/.*"sha256"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MANIFEST" | head -n 1)"
KIND="$(sed -n 's/.*"kind"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$MANIFEST" | head -n 1)"
KIND="${KIND:-release}"
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
  log "rejecting update: sha256 mismatch (expected $SHA256)"
  rm -f "$REQ.processing"
  fail "the staged binary failed checksum verification - refusing to install it. Re-run the update from the console."
  exit 1
fi

# ---- installer-run update ---------------------------------------------
# The staged file is the canonical installer script (install.sh), fetched by
# the unprivileged updater from the repository's main branch - the same
# one-line install an operator would run by hand, run here as root through
# this dedicated oneshot. Configuration-affecting rewrites ([api] listen,
# console accounts) are disabled for this run via DAYGLE_DNS_GUI_UPDATE=1;
# the deployment's own config file is never touched.
#
# $BIN is the already sha-verified root-private copy, so the script is run
# from there, never from the service-writable staged file. Real deployment
# paths are handed in via the environment the installer already accepts
# (PREFIX/CONFIG_DIR/DATA_DIR/SERVICE_USER/PRIV_LIB_DIR), derived from the
# paths the installer baked into this helper - so a customised install is
# updated in place, not reset to the defaults.
if [ "$KIND" = "install" ]; then
  state applying "Running the full installer (this can take several minutes)..."
  log "running the canonical installer for v${VERSION}"

  cp -f "$BIN" "$PRIV/install.sh"
  chmod 0700 "$PRIV/install.sh"

  # Deployment layout from the baked-in helper paths (mirroring how
  # install.sh configures the placeholder substitutions).
  PREFIX="$(dirname "$(dirname "$EXE")")"
  CONFIG_DIR="$(dirname "$MODELS_DIR")"
  DATA_DIR="$(dirname "$UPDATES_DIR")"
  PRIV_LIB_DIR="$(dirname -- "$0")"
  export PREFIX CONFIG_DIR DATA_DIR SERVICE_USER PRIV_LIB_DIR
  # The installer's LAN-GUI section rebinds [api] listen to 0.0.0.0 and may
  # write console accounts - explicitly not wanted here ("update the app,
  # keep the operator's settings").
  export DAYGLE_DNS_GUI_UPDATE=1
  unset DAYGLE_DNS_ADMIN_USER DAYGLE_DNS_ADMIN_PASSWORD DAYGLE_DNS_LAN_GUI DAYGLE_DNS_NO_DEPS || true

  # Run in the background so progress can be streamed: the installer's last
  # log line becomes the state message the console shows while it clones,
  # builds and installs (several minutes on a small host).
  : > "$PRIV/installer-exit"
  (
    sh "$PRIV/install.sh" >>"$LOG" 2>&1
    printf '%s' "$?" > "$PRIV/installer-exit"
  ) &
  WORKER="$!"

  LAST="installer: hand-off accepted"
  state applying "$LAST"
  while kill -0 "$WORKER" 2>/dev/null; do
    sleep 3
    STEP="$(tail -n 20 "$LOG" 2>/dev/null | tr '\r' '\n' | grep -v '^[[:space:]]*$' | tail -n 1 | cut -c1-160)"
    NEW="installer: ${STEP:-working...}"
    if [ "$NEW" != "$LAST" ]; then
      LAST="$NEW"
      state applying "$LAST"
    fi
  done

  RC="$(cat "$PRIV/installer-exit" 2>/dev/null || true)"
  case "$RC" in ''|*[!0-9]*) RC=1 ;; esac

  if [ "$RC" -eq 0 ]; then
    # The installer restarts the service itself; require that it is back
    # and healthy, as with every other apply kind.
    state restarting "Installer finished - checking the restarted service..."
    if health_check; then
      rm -f "$REQ.processing" "$MANIFEST" "$STAGED_BIN"
      log "installer completed v${VERSION} and health check passed"
      state done "Full update installed by the canonical installer and verified successfully (v${VERSION})."
      exit 0
    fi
    rm -f "$REQ.processing" "$MANIFEST" "$STAGED_BIN"
    fail "the installer completed but the service health check failed. The installer rebuilt and installed v${VERSION}; check the service with 'systemctl status daygle-dns' (details in apply.log)."
    exit 1
  fi

  # Best effort: if the installer stopped/failed mid-apply, make sure the
  # previously installed binary is still the one systemd runs.
  systemctl start daygle-dns 2>>"$LOG" || true
  STOP="$(last_log_error_from_file "$LOG")"
  rm -f "$REQ.processing" "$MANIFEST" "$STAGED_BIN"
  fail "the full installer failed (exit ${RC})${STOP:+ — last installer message: $STOP}. Nothing was replaced if it failed before the install step; details in apply.log."
  exit 1
fi

# ---- models-only update ------------------------------------------------
# The staged file is a tar.gz bundle containing manifest.json + whitelisted
# model files. Install them INTO $MODELS_DIR, chmod/chown for the service
# account, restart, health-check and roll the files back on failure. The
# binary path below never runs for this kind.
if [ "$KIND" = "models" ]; then
  state applying "Applying AI model files (v${VERSION})..."
  log "applying models bundle v${VERSION} into $MODELS_DIR"

  WORK="$PRIV/models"
  mkdir -p "$WORK"
  # --no-same-owner: root must not recreate archive-chosen ownership.
  if ! tar --no-same-owner -xzf "$BIN" -C "$WORK"; then
    log "tar extraction failed for the models bundle"
    rm -f "$REQ.processing"
    fail "the staged AI models bundle could not be extracted. Re-run the model update from the console."
    exit 1
  fi

  INNER="$WORK/manifest.json"
  if [ ! -f "$INNER" ] || [ -L "$INNER" ]; then
    log "models bundle is missing its manifest.json"
    rm -f "$REQ.processing"
    fail "the staged AI models bundle is missing its internal manifest. Re-run the model update from the console."
    exit 1
  fi

  VALID=""
  for f in $MODEL_WHITELIST; do
    if grep -q "\"name\"[[:space:]]*:[[:space:]]*\"$f\"" "$INNER"; then
      VALID="$VALID $f"
    fi
  done
  if [ -z "$VALID" ]; then
    log "models manifest lists no whitelisted files"
    rm -f "$REQ.processing"
    fail "the models bundle manifest lists no installed model files. Re-run the model update from the console."
    exit 1
  fi

  # Verify each file against the manifest's sha256 before installing.
  mkdir -p "$PRIV/model-backup"
  FAILED=""
  for f in $VALID; do
    SRCF="$WORK/$f"
    WANT="$(sed -n "s/.*\"name\"[[:space:]]*:[[:space:]]*\"$f\"[^}]*\"sha256\"[[:space:]]*:[[:space:]]*\"\([0-9a-fA-F]*\)\".*/\1/p" "$INNER" | head -n 1)"
    case "$WANT" in ''|*[!0-9a-fA-F]*) WANT="" ;; esac
    if [ -z "$WANT" ] || [ "${#WANT}" -ne 64 ] || [ -L "$SRCF" ] || [ ! -f "$SRCF" ]; then
      FAILED="$FAILED $f"
      continue
    fi
    ACT="$( (sha256sum "$SRCF" 2>/dev/null || shasum -a 256 "$SRCF" 2>/dev/null) | cut -d' ' -f1 | tr -d '[:space:]')"
    [ "$ACT" = "$WANT" ] || FAILED="$FAILED $f"
  done
  if [ -n "$FAILED" ]; then
    log "rejecting models bundle; failed:${FAILED}"
    rm -f "$REQ.processing"
    fail "the staged AI models bundle failed file validation:${FAILED}. Re-run the model update from the console."
    exit 1
  fi

  # Back up whatever is currently installed (best effort), install the
  # verified files atomically (temp name + rename), hand them to the
  # service account.
  for f in $VALID; do
    if [ -f "$MODELS_DIR/$f" ]; then cp -f "$MODELS_DIR/$f" "$PRIV/model-backup/$f" 2>/dev/null || true; fi
    install -m 0644 "$WORK/$f" "$MODELS_DIR/.new-$f" 2>>"$LOG" || { FAILED="$FAILED $f"; continue; }
    mv -f "$MODELS_DIR/.new-$f" "$MODELS_DIR/$f"
  done
  if [ -n "$FAILED" ]; then
    log "install failed for:${FAILED}"
    rm -f "$REQ.processing"
    fail "installing the AI model files failed (${FAILED}). Please check the disk and retry."
    exit 1
  fi
  for f in $VALID; do
    chown "$SERVICE_USER":"$SERVICE_USER" "$MODELS_DIR/$f" 2>/dev/null || true
  done

  state restarting "Restarting the service to load the new AI models..."
  if ! systemctl restart daygle-dns; then
    log "systemctl restart daygle-dns failed after model install"
    for f in $VALID; do
      if [ -f "$PRIV/model-backup/$f" ]; then cp -f "$PRIV/model-backup/$f" "$MODELS_DIR/$f" 2>/dev/null || true; fi
    done
    systemctl restart daygle-dns 2>>"$LOG" || true
    rm -f "$REQ.processing"
    fail "the new AI models were installed but the service restart failed; the previous model files were restored."
    exit 1
  fi

  # Health check: the service must come back and the API answer.
  HEALTHY=0
  if health_check; then HEALTHY=1; fi

  rm -f "$REQ.processing" "$MANIFEST" "$STAGED_BIN"
  if [ "$HEALTHY" -eq 1 ]; then
    log "applied models bundle v${VERSION} and health check passed"
    state done "AI model files updated and verified successfully (v${VERSION})."
    exit 0
  fi

  log "health check failed after model update - rolling back"
  state rolling_back "Model update failed - rolling back the AI model files..."
  for f in $VALID; do
    if [ -f "$PRIV/model-backup/$f" ]; then cp -f "$PRIV/model-backup/$f" "$MODELS_DIR/$f" 2>/dev/null || true; fi
  done
  systemctl restart daygle-dns 2>>"$LOG" || true
  rm -f "$REQ.processing"
  fail "Model update failed - successfully rolled back the AI model files. Release v${VERSION} did not pass its health check."
  exit 1
fi

state applying "Applying release v${VERSION}..."
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

state restarting "Restarting the service..."
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
HEALTHY=0
if health_check; then HEALTHY=1; fi

rm -f "$REQ.processing" "$MANIFEST" "$STAGED_BIN"

if [ "$HEALTHY" -eq 1 ]; then
  log "applied v${VERSION} and health check passed"
  state done "Update installed and verified successfully (v${VERSION})."
  exit 0
fi

log "health check failed after update - rolling back"
if [ -f "$EXE.bak" ]; then
  state rolling_back "Update failed - rolling back to the previous version..."
  mv -f "$EXE.bak" "$EXE"
  systemctl restart daygle-dns 2>>"$LOG" || true
  fail "Update failed - successfully rolled back to the previous version. Release v${VERSION} did not pass its health check."
  exit 1
fi
fail "Update installed but the health check failed and no backup was available for rollback. Manual intervention required."
exit 1