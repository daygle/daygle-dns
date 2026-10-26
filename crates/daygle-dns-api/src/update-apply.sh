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
#   <updates>/staging/apply.json   - {"kind":"install|models","version":"x.y.z","sha256":"<64hex>"}
#   <updates>/staging/apply.bin    - the staged installer script (kind=install)
#                                     or models bundle tar.gz (kind=models)
#
# Only the fixed staging paths are ever touched (the manifest cannot select a
# path). The manifest's sha256 is written by the same unprivileged account
# that writes apply.bin, so it only proves the copy is intact - never that
# the content is genuine. Root therefore trusts nothing it did not fetch
# itself: kind=install runs an installer root downloads from the canonical
# repository, and kind=models installs a bundle only when its checksum
# matches the one published with that release (fetched by root). Any other
# kind - including the retired binary-swap "release" kind - is refused.

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

# Canonical sources, fixed here (the same ones install.sh itself uses): root
# never takes a URL, or content it runs, from the service-writable dirs.
REPO_SLUG="daygle/daygle-dns"
INSTALLER_URL="https://raw.githubusercontent.com/$REPO_SLUG/main/install.sh"
REPO_URL="https://github.com/$REPO_SLUG.git"
RELEASE_BASE_URL="https://github.com/$REPO_SLUG/releases/download"

# Download over HTTPS only (redirects included) as root.
root_fetch() { # url dest
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 --connect-timeout 15 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --tries=3 -O "$2" "$1"
  else
    return 1
  fi
}

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

# Wait up to 90 s for the service to come up. The console answering
# /api/health proves it. The console may not be where the config file says
# (moved to another port or HTTPS-only in Settings, which the database holds),
# so the unit staying active under one process for 20 s proves it too: a
# start that fails exits and is restarted under a new process.
health_check() {
  i=0
  pid=""
  steady=0
  while [ $i -lt 90 ]; do
    sleep 1
    i=$((i + 1))
    if ! systemctl is-active --quiet daygle-dns 2>/dev/null; then
      pid=""
      steady=0
      continue
    fi
    if curl -fsS --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then
      return 0
    fi
    now="$(systemctl show daygle-dns -p MainPID --value 2>/dev/null || true)"
    if [ -n "$now" ] && [ "$now" != 0 ] && [ "$now" = "$pid" ]; then
      steady=$((steady + 1))
      if [ $steady -ge 20 ]; then
        log "service up (pid $now) without the console answering at $HEALTH_URL"
        return 0
      fi
    else
      pid="$now"
      steady=0
    fi
  done
  return 1
}

# Checksum of a file (empty when unreadable).
file_sha() {
  (sha256sum "$1" 2>/dev/null || shasum -a 256 "$1" 2>/dev/null) | cut -d' ' -f1 | tr -d '[:space:]'
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
BAD=""
case "$KIND" in
  install|models) ;;
  *) BAD="unsupported update kind '$KIND' in the update manifest" ;;
esac

# Strict validation of the manifest: version is dotted numerics only; sha256
# is exactly 64 hex chars. Nothing in the manifest ever selects a path.
if [ -z "$BAD" ]; then
  case "$VERSION" in
    ''|*[!0-9.]*|*..*|.*|*.) BAD="invalid version '$VERSION' in the update manifest" ;;
  esac
fi
if [ -z "$BAD" ]; then
  case "$SHA256" in
    ''|*[!0-9a-fA-F]*) BAD="invalid sha256 in the update manifest" ;;
  esac
fi
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
# The canonical installer script (install.sh) from the repository's main
# branch - the same one-line install an operator would run by hand - run
# here as root through this dedicated oneshot. Configuration-affecting
# rewrites ([api] listen, console accounts) are disabled for this run via
# DAYGLE_DNS_GUI_UPDATE=1; the deployment's own config file is never touched.
#
# The service account staged its own copy, but root never runs that: a
# compromised service account could stage any script with a matching
# manifest checksum and so run code as root. Root downloads the installer
# itself from the canonical URL (or, without a downloader, takes it from a
# fresh clone of the canonical repository) into its private dir. Real deployment
# paths are handed in via the environment the installer already accepts
# (PREFIX/CONFIG_DIR/DATA_DIR/SERVICE_USER/PRIV_LIB_DIR), derived from the
# paths the installer baked into this helper - so a customised install is
# updated in place, not reset to the defaults.
if [ "$KIND" = "install" ]; then
  state applying "Running the full installer (this can take several minutes)..."
  log "running the canonical installer for v${VERSION}"

  if root_fetch "$INSTALLER_URL" "$PRIV/install.sh" 2>>"$LOG" && [ -s "$PRIV/install.sh" ]; then
    :
  elif command -v git >/dev/null 2>&1 \
       && git clone --depth 1 "$REPO_URL" "$PRIV/repo" >>"$LOG" 2>&1 \
       && cp -f "$PRIV/repo/install.sh" "$PRIV/install.sh"; then
    :
  else
    log "cannot fetch the canonical installer from $INSTALLER_URL"
    rm -f "$REQ.processing"
    fail "the update service could not download the canonical installer ($INSTALLER_URL). Check this host's network access to GitHub and retry."
    exit 1
  fi
  chmod 0700 "$PRIV/install.sh"

  # Deployment layout from the baked-in helper paths (mirroring how
  # install.sh configures the placeholder substitutions).
  PREFIX="$(dirname "$(dirname "$EXE")")"
  CONFIG_DIR="$(dirname "$MODELS_DIR")"
  DATA_DIR="$(dirname "$UPDATES_DIR")"
  PRIV_LIB_DIR="$(dirname -- "$0")"
  export PREFIX CONFIG_DIR DATA_DIR SERVICE_USER PRIV_LIB_DIR
  # systemd starts this oneshot without HOME; rustup/cargo (and the
  # installer's `set -u`) need it, so give the installer root's home.
  HOME="${HOME:-/root}"
  export HOME
  # The installer's LAN-GUI section rebinds [api] listen to 0.0.0.0 and may
  # write console accounts - explicitly not wanted here ("update the app,
  # keep the operator's settings").
  export DAYGLE_DNS_GUI_UPDATE=1
  unset DAYGLE_DNS_ADMIN_USER DAYGLE_DNS_ADMIN_PASSWORD DAYGLE_DNS_LAN_GUI DAYGLE_DNS_NO_DEPS || true

  # The checkout and release build take gigabytes: keep them off /tmp,
  # which many distributions mount as a small tmpfs (RAM).
  if [ -z "${TMPDIR:-}" ] && [ -d /var/tmp ]; then
    BUILD_TMP=/var/tmp
  else
    BUILD_TMP="${TMPDIR:-/tmp}"
  fi

  # Keep the binary the service runs now, to put back if the new one does
  # not come up. Prefer the running image: a previous update can have
  # replaced the file while this server kept running from the old inode.
  ROLLBACK="$PRIV/rollback.bin"
  BACKUP_SRC="$EXE"
  MAINPID="$(systemctl show daygle-dns -p MainPID --value 2>/dev/null || true)"
  case "$MAINPID" in
    ''|0) ;;
    *) if [ -r "/proc/$MAINPID/exe" ]; then BACKUP_SRC="/proc/$MAINPID/exe"; fi ;;
  esac
  if ! cp -f "$BACKUP_SRC" "$ROLLBACK" 2>>"$LOG"; then
    ROLLBACK=""
    log "could not keep a copy of the current binary; a failed update cannot be rolled back"
  fi

  # Put the kept binary back and restart; false when there is nothing to
  # roll back (no copy, or the installer never replaced the binary).
  rollback_binary() {
    [ -n "$ROLLBACK" ] && [ -s "$ROLLBACK" ] || return 1
    [ "$(file_sha "$ROLLBACK")" != "$(file_sha "$EXE")" ] || return 1
    state rolling_back "The update did not come up - restoring the previous version..."
    log "rolling back $EXE to the previous binary"
    install -m 0755 "$ROLLBACK" "$EXE.rollback" 2>>"$LOG" && mv -f "$EXE.rollback" "$EXE" || return 1
    systemctl restart daygle-dns 2>>"$LOG" || true
    return 0
  }

  # Run in the background so progress can be streamed: the installer's last
  # log line becomes the state message the console shows while it clones,
  # builds and installs (several minutes on a small host).
  : > "$PRIV/installer-exit"
  # (`|| rc=$?`: under `set -e` a failing installer would otherwise end the
  # subshell before its exit code is recorded, and every failure read as 1.)
  (
    rc=0
    TMPDIR="$BUILD_TMP" sh "$PRIV/install.sh" >>"$LOG" 2>&1 || rc=$?
    printf '%s' "$rc" > "$PRIV/installer-exit"
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
    log "health check failed after installing v${VERSION}"
    if rollback_binary; then
      if health_check; then
        fail "v${VERSION} was installed but did not come up, so the previous version was restored and is running again. Details in apply.log."
      else
        fail "v${VERSION} did not come up, and neither did the restored previous version. Check 'systemctl status daygle-dns' (details in apply.log)."
      fi
    else
      fail "the installer completed but the service health check failed, and no previous binary could be restored. Check 'systemctl status daygle-dns' (details in apply.log)."
    fi
    exit 1
  fi

  # The installer failed. If it got as far as replacing the binary, put the
  # previous one back; either way make sure the service is running.
  STOP="$(last_log_error_from_file "$LOG")"
  rm -f "$REQ.processing" "$MANIFEST" "$STAGED_BIN"
  if rollback_binary; then
    WHAT="the previous version was restored"
  else
    systemctl start daygle-dns 2>>"$LOG" || true
    WHAT="nothing was replaced"
  fi
  fail "the full installer failed (exit ${RC})${STOP:+ - last installer message: $STOP}; ${WHAT}. Details in apply.log."
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

  # The manifest checksum only proves the staged copy is intact; the bundle
  # is genuine only if it matches the checksum published with the release,
  # fetched here by root (before root extracts anything from it).
  PUBLISHED="$PRIV/models.sha256"
  WANT_BUNDLE=""
  if root_fetch "$RELEASE_BASE_URL/v${VERSION}/daygle-dns-models.tar.gz.sha256" "$PUBLISHED" 2>>"$LOG"; then
    WANT_BUNDLE="$(cut -d' ' -f1 "$PUBLISHED" 2>/dev/null | tr -d '[:space:]' | tr 'A-F' 'a-f')"
  fi
  if [ -z "$WANT_BUNDLE" ] || [ "$WANT_BUNDLE" != "$(printf '%s' "$ACTUAL" | tr 'A-F' 'a-f')" ]; then
    log "rejecting models bundle: it does not match the checksum published for v${VERSION}"
    rm -f "$REQ.processing"
    fail "the staged AI models bundle does not match the checksum published with release v${VERSION} (or it could not be fetched) - refusing to install it."
    exit 1
  fi

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

# Unreachable: the kind was validated above (install or models only).
fail "unsupported update kind '$KIND'."
exit 1
