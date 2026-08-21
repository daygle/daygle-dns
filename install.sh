#!/usr/bin/env sh
# Daygle DNS - one-line installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh | sh
#
# The script installs the `daygle` binary to /usr/local/bin, a configuration
# file and a systemd unit (systemd-based Linux only). It requires Rust and
# Cargo; install them first with https://rustup.rs.

set -eu

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/daygle}"
DATA_DIR="${DATA_DIR:-/var/lib/daygle}"
SERVICE_USER="${SERVICE_USER:-daygle}"

log() { printf '\033[1;32m[daygle-install]\033[0m %s\n' "$1"; }

command -v cargo >/dev/null 2>&1 || {
    printf 'error: cargo was not found. Install Rust first: https://rustup.rs\n' >&2
    exit 1
}

SRC_DIR="$(mktemp -d)"
trap 'rm -rf "$SRC_DIR"' EXIT

log "Downloading Daygle DNS source…"
if command -v git >/dev/null 2>&1; then
    git clone --depth 1 https://github.com/daygle/daygle-dns.git "$SRC_DIR"
else
    printf 'error: git is required to download the source\n' >&2
    exit 1
fi
cd "$SRC_DIR"

log "Building release binary (this may take a few minutes)…"
cargo build --release -p daygle

log "Installing binary to $PREFIX/bin/daygle…"
install -d "$PREFIX/bin"
install -m 0755 target/release/daygle "$PREFIX/bin/daygle"

log "Installing configuration to $CONFIG_DIR…"
install -d "$CONFIG_DIR" "$CONFIG_DIR/zones" "$CONFIG_DIR/certs" "$DATA_DIR"
if [ ! -f "$CONFIG_DIR/daygle.toml" ]; then
    install -m 0644 daygle.toml.example "$CONFIG_DIR/daygle.toml"
fi

# ---- systemd unit (Linux with systemd only) -----------------------------
if [ -d /etc/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    log "Installing systemd unit…"
    cat > /etc/systemd/system/daygle.service <<EOF
[Unit]
Description=Daygle DNS server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
ExecStart=${PREFIX}/bin/daygle --config ${CONFIG_DIR}/daygle.toml
Restart=on-failure
RestartSec=3
# DNS on port 53 needs privileges; drop to a dedicated user after binding.
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF
    id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --no-create-home "$SERVICE_USER"
    chown -R "$SERVICE_USER":"$SERVICE_USER" "$CONFIG_DIR" "$DATA_DIR"
    systemctl daemon-reload
    systemctl enable --now daygle
    log "Daygle DNS started via systemd."
else
    log "No systemd detected. Start the server manually:"
    log "  $PREFIX/bin/daygle --config $CONFIG_DIR/daygle.toml"
fi

log "Done! Web GUI: http://127.0.0.1:5380"
log "Configuration: $CONFIG_DIR/daygle.toml"
