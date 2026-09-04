#!/usr/bin/env sh
# Daygle DNS - one-line installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh | sh
#
# The script installs the `daygle-dns` binary to /usr/local/bin, a configuration
# file and a systemd unit (systemd-based Linux only). It requires Rust and
# Cargo; install them first with https://rustup.rs.

set -eu

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/daygle-dns}"
DATA_DIR="${DATA_DIR:-/var/lib/daygle-dns}"
SERVICE_USER="${SERVICE_USER:-daygle-dns}"

log() { printf '\033[1;32m[daygle-dns-install]\033[0m %s\n' "$1"; }

command -v cargo >/dev/null 2>&1 || {
    printf '%s\n' \
        'error: cargo was not found. Daygle is built from source and requires Rust.' \
        'Install the minimal Rust toolchain non-interactively:' \
        '' \
        '    curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal' \
        '' \
        'Then open a new shell (or run: source "$HOME/.cargo/env") and re-run the installer.' \
        'See https://rustup.rs for other installation options.' >&2
    exit 1
}

command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1 || {
    printf '%s\n' \
        'error: no C compiler (cc/gcc/clang) was found. Daygle also needs a system' \
        'C toolchain: bundled SQLite and ring are compiled from C source.' \
        '' \
        'Install a C toolchain for your system:' \
        '    Debian/Ubuntu:  apt-get update && apt-get install -y build-essential' \
        '    RHEL/Fedora:    dnf groupinstall "Development Tools"' \
        '    Alpine:         apk add build-base' \
        '    Arch:           pacman -S --needed base-devel' \
        '    macOS:          xcode-select --install' \
        '' \
        'Then re-run this installer.' >&2
    exit 1
}

SRC_DIR="$(mktemp -d)"
trap 'rm -rf "$SRC_DIR"' EXIT

log "Downloading Daygle DNS source…"
if command -v git >/dev/null 2>&1; then
    git clone --depth 1 https://github.com/daygle/daygle-dns.git "$SRC_DIR"
else
    printf '%s\n' \
        'error: git is required to download the Daygle source.' \
        'Install git for your system:' \
        '' \
        '    Debian/Ubuntu:  apt-get update && apt-get install -y git' \
        '    RHEL/Fedora:    dnf install -y git' \
        '    Alpine:         apk add git' \
        '    Arch:           pacman -S --needed git' \
        '    macOS:          xcode-select --install' \
        '' \
        'Then re-run this installer.' >&2
    exit 1
fi
cd "$SRC_DIR"

log "Building release binary (this may take a few minutes)…"
cargo build --release -p daygle-dns

log "Installing binary to $PREFIX/bin/daygle-dns…"
install -d "$PREFIX/bin"
install -m 0755 target/release/daygle-dns "$PREFIX/bin/daygle-dns"

log "Installing configuration to $CONFIG_DIR…"
install -d "$CONFIG_DIR" "$CONFIG_DIR/zones" "$CONFIG_DIR/certs" "$DATA_DIR"
if [ ! -f "$CONFIG_DIR/daygle-dns.toml" ]; then
    install -m 0644 daygle-dns.toml.example "$CONFIG_DIR/daygle-dns.toml"
fi

# ---- systemd unit (Linux with systemd only) -----------------------------
if [ -d /etc/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    log "Installing systemd unit…"
    cat > /etc/systemd/system/daygle-dns.service <<EOF
[Unit]
Description=Daygle DNS server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
ExecStart=${PREFIX}/bin/daygle-dns --config ${CONFIG_DIR}/daygle-dns.toml
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
    systemctl enable --now daygle-dns
    log "Daygle DNS started via systemd."
else
    log "No systemd detected. Start the server manually:"
    log "  $PREFIX/bin/daygle-dns --config $CONFIG_DIR/daygle-dns.toml"
fi

log "Done! Web GUI: http://127.0.0.1:5380"
log "Configuration: $CONFIG_DIR/daygle-dns.toml"
