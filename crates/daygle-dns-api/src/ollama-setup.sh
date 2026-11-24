#!/usr/bin/env sh
# DAYGLE_DNS_OLLAMA_SETUP_V1
# Daygle DNS - install, update or remove a local Ollama server for the AI's
# language-model reader.
#
# Run as root, either by install.sh (DAYGLE_DNS_OLLAMA=1 or =0) or by the
# root update service (daygle-dns-update.service) when an admin asks for it
# in the console. The console's request only names the action; this script,
# installed root-owned beside update-apply.sh, decides everything else:
#
#   install  - check there is memory for a model, run Ollama's official
#              installer, keep the server on loopback at low priority, and
#              download DAYGLE_DNS_OLLAMA_MODEL (default qwen2.5:1.5b).
#   update   - run Ollama's official installer again (it upgrades in place)
#              and re-apply the settings above. Models are kept.
#   remove   - stop and remove the server, its unit, its account and the
#              models it downloaded.
#
# Ollama's API has no authentication, so the server is kept on 127.0.0.1;
# do not change OLLAMA_HOST to a network address on a shared network.

set -eu

ACTION="${1:-}"
OLLAMA_INSTALLER_URL="https://ollama.com/install.sh"
OLLAMA_HOST_ADDR="127.0.0.1:11434"
MODEL="${DAYGLE_DNS_OLLAMA_MODEL:-qwen2.5:1.5b}"
# Total memory below this is refused for an install (about 3.5 GB): the
# smallest useful model and the DNS server have to share it.
MIN_MEM_KB=3500000
UNIT=/etc/systemd/system/ollama.service
DROP_DIR=/etc/systemd/system/ollama.service.d

log() { printf '[ollama-setup] %s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"
[ "$(uname -s)" = "Linux" ] || die "Ollama can only be managed on Linux"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

case "$MODEL" in
  ''|*[!A-Za-z0-9._:/-]*|/*|.*|-*) die "invalid model name '$MODEL'" ;;
esac

fetch() { # url dest
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 --connect-timeout 15 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --tries=3 -O "$2" "$1"
  else
    return 1
  fi
}

api_up() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 3 "http://$OLLAMA_HOST_ADDR/api/version" >/dev/null 2>&1
  else
    wget -q -T 3 -O /dev/null "http://$OLLAMA_HOST_ADDR/api/version" 2>/dev/null
  fi
}

wait_api() {
  i=0
  while [ $i -lt 60 ]; do
    api_up && return 0
    sleep 1
    i=$((i + 1))
  done
  return 1
}

ollama_bin() {
  for b in /usr/local/bin/ollama /usr/bin/ollama; do
    [ -x "$b" ] && { printf '%s' "$b"; return 0; }
  done
  command -v ollama 2>/dev/null || return 1
}

# Loopback only, one model and one request at a time, and below the DNS
# server for CPU and disk: a page read must never slow DNS answers.
configure() {
  install -d -m 0755 "$DROP_DIR"
  cat > "$DROP_DIR/daygle-dns.conf" <<EOF
# Written by Daygle DNS (ollama-setup.sh). Re-running the setup rewrites it.
[Service]
Environment="OLLAMA_HOST=$OLLAMA_HOST_ADDR"
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_KEEP_ALIVE=10m"
Nice=10
CPUWeight=20
IOSchedulingClass=idle
EOF
  systemctl daemon-reload
  systemctl enable --quiet ollama 2>/dev/null || true
  systemctl restart ollama
  wait_api || die "Ollama did not start (see: journalctl -u ollama -n 30)"
}

run_official_installer() {
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT HUP INT TERM
  log "Downloading Ollama's installer from $OLLAMA_INSTALLER_URL..."
  fetch "$OLLAMA_INSTALLER_URL" "$tmp/install.sh" || die "could not download $OLLAMA_INSTALLER_URL"
  [ -s "$tmp/install.sh" ] || die "the Ollama installer was empty"
  log "Running Ollama's installer (it downloads several hundred MB; this can take a few minutes)..."
  if ! sh "$tmp/install.sh" >"$tmp/out" 2>&1; then
    tr '\r' '\n' <"$tmp/out" | grep -v '^[[:space:]]*$' | tail -n 15 | while IFS= read -r line; do log "$line"; done
    die "Ollama's installer failed"
  fi
  tr '\r' '\n' <"$tmp/out" | grep -v '^[[:space:]]*$' | grep -v '#' | tail -n 5 | while IFS= read -r line; do log "$line"; done
  ollama_bin >/dev/null || die "the Ollama installer did not install ollama"
}

case "$ACTION" in
  install)
    mem_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
    if [ "${DAYGLE_DNS_OLLAMA_FORCE:-}" != "1" ] && [ "${mem_kb:-0}" -lt "$MIN_MEM_KB" ]; then
      die "this machine has $((mem_kb / 1024)) MB of memory; a language model needs about 3.5 GB in total. Run Ollama on another machine and point Daygle at it, or set DAYGLE_DNS_OLLAMA_FORCE=1."
    fi
    run_official_installer
    configure
    log "Downloading the model $MODEL (about 1 GB)..."
    "$(ollama_bin)" pull "$MODEL" 2>&1 | tr '\r' '\n' | grep -v '^[[:space:]]*$' | tail -n 3 \
      | while IFS= read -r line; do log "$line"; done
    "$(ollama_bin)" list 2>/dev/null | awk -v m="$MODEL" '$1 == m { found = 1 } END { exit !found }' \
      || log "WARNING: the model $MODEL did not download; download it from the console (AI > Language Model)."
    log "Ollama $("$(ollama_bin)" --version 2>/dev/null | awk '{print $NF}') is ready at http://$OLLAMA_HOST_ADDR"
    ;;
  update)
    ollama_bin >/dev/null || die "Ollama is not installed here; install it first"
    before="$("$(ollama_bin)" --version 2>/dev/null | awk '{print $NF}')"
    run_official_installer
    configure
    after="$("$(ollama_bin)" --version 2>/dev/null | awk '{print $NF}')"
    if [ "$before" = "$after" ]; then
      log "Ollama is already the newest version ($after)"
    else
      log "Ollama updated from $before to $after"
    fi
    ;;
  remove)
    log "Stopping and removing Ollama..."
    systemctl disable --now ollama 2>/dev/null || true
    rm -f "$UNIT"
    rm -rf "$DROP_DIR"
    systemctl daemon-reload
    for b in /usr/local/bin/ollama /usr/bin/ollama; do rm -f "$b"; done
    rm -rf /usr/local/lib/ollama /usr/lib/ollama /usr/share/ollama
    if id ollama >/dev/null 2>&1; then userdel ollama 2>/dev/null || true; fi
    if getent group ollama >/dev/null 2>&1; then groupdel ollama 2>/dev/null || true; fi
    log "Ollama and its models were removed"
    ;;
  *)
    die "usage: ollama-setup.sh install|update|remove"
    ;;
esac
