#!/usr/bin/env sh
# Daygle DNS - one-line installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh | sh
#
# The script installs the `daygle-dns` binary to /usr/local/bin, a
# configuration file and a systemd unit (systemd-based Linux only). Missing
# prerequisites (Rust, a C compiler, git, a downloader such as curl) are
# installed automatically when possible via rustup and the detected package
# manager; DNS test tools (dig) are installed as a convenience. Set
# DAYGLE_NO_DEPS=1 to skip the automatic installs and get manual
# instructions instead.

set -eu

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/daygle-dns}"
DATA_DIR="${DATA_DIR:-/var/lib/daygle-dns}"
SERVICE_USER="${SERVICE_USER:-daygle-dns}"

log() { printf '\033[1;32m[daygle-dns-install]\033[0m %s\n' "$1"; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

need_cargo() { ! have_cmd cargo; }
need_git() { ! have_cmd git; }
need_downloader() { ! { have_cmd curl || have_cmd wget; }; }
need_dig() { ! have_cmd dig; }
need_cc() {
    ! { have_cmd cc || have_cmd gcc || have_cmd clang; }
}

run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@" || return 1
    elif have_cmd sudo; then
        sudo "$@" || return 1
    else
        return 1
    fi
}

install_system_toolchain() {
    # C compiler, git, and curl via the platform package manager.
    if have_cmd apt-get; then
        run_as_root apt-get update || return 1
        run_as_root apt-get install -y --no-install-recommends build-essential git curl || return 1
    elif have_cmd dnf; then
        run_as_root dnf -y group install "Development Tools" || return 1
        run_as_root dnf -y install git curl || return 1
    elif have_cmd yum; then
        run_as_root yum -y groupinstall "Development Tools" || return 1
        run_as_root yum -y install git curl || return 1
    elif have_cmd apk; then
        run_as_root apk add --no-cache build-base git curl || return 1
    elif have_cmd pacman; then
        run_as_root pacman -S --needed --noconfirm base-devel git curl || return 1
    elif have_cmd zypper; then
        run_as_root zypper -n install -t pattern devel_basis || return 1
        run_as_root zypper -n install git curl || return 1
    elif [ "$(uname -s)" = "Darwin" ]; then
        # Xcode Command Line Tools provide a C compiler (and git); curl ships with macOS.
        xcode-select --install >/dev/null 2>&1 || true
    else
        return 1
    fi
}

install_dns_tools() {
    # Optional: dig for query testing. Best-effort - never fatal.
    if have_cmd dig; then
        return 0
    fi
    log "Installing DNS test tools (dig)…"
    if have_cmd apt-get; then
        run_as_root apt-get install -y --no-install-recommends dnsutils || true
    elif have_cmd dnf || have_cmd yum; then
        run_as_root dnf -y install bind-utils || run_as_root yum -y install bind-utils || true
    elif have_cmd apk; then
        run_as_root apk add --no-cache bind-tools || true
    elif have_cmd pacman; then
        run_as_root pacman -S --needed --noconfirm bind || true
    elif have_cmd zypper; then
        run_as_root zypper -n install bind-utils || true
    fi
    if have_cmd dig; then
        log "Installed dig - try: dig @127.0.0.1 example.com A"
    else
        log "dig not installed; DNS test tools are optional (dnsutils/bind-utils)."
    fi
}

install_rust() {
    log "Installing Rust via rustup (minimal profile)…"
    if have_cmd curl; then
        curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal || return 1
    elif have_cmd wget; then
        wget -qO- https://sh.rustup.rs | sh -s -- -y --profile minimal || return 1
    else
        return 1
    fi
    export PATH="$HOME/.cargo/bin:$PATH"
}

open_lan_firewall() {
    # Best-effort: open LAN-scoped rules where possible, warn otherwise.
    # Prints a warning when a firewall is active that we cannot configure.
    if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | grep -qi '^Status: active'; then
            log "Opening ports 53, 853, and 5380 for private LAN ranges in ufw..."
            for net in 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8; do
                ufw allow from "$net" to any port 5380 proto tcp >/dev/null 2>&1 || true
                ufw allow from "$net" to any port 53 >/dev/null 2>&1 || true
                ufw allow from "$net" to any port 853 proto tcp >/dev/null 2>&1 || true
            done
            return 0
        fi
        log "ufw is installed but inactive - no local firewall rules to open."
        return 0
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        log "Opening ports 53, 853, and 5380 for private LAN ranges in firewalld..."
        for net in 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8; do
            firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$net port port=5380 protocol=tcp accept" >/dev/null 2>&1 || true
            firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$net port port=53 protocol=udp accept" >/dev/null 2>&1 || true
            firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$net port port=53 protocol=tcp accept" >/dev/null 2>&1 || true
            firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$net port port=853 protocol=tcp accept" >/dev/null 2>&1 || true
        done
        firewall-cmd --reload >/dev/null 2>&1 || true
        return 0
    fi
    if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1 && [ -n "$(nft list ruleset 2>/dev/null)" ]; then
        log "WARNING: nftables ruleset detected - open ports 53, 853, and 5380 for your LAN manually."
        return 1
    fi
    if command -v iptables >/dev/null 2>&1 && iptables -S >/dev/null 2>&1 && [ -n "$(iptables -S 2>/dev/null)" ]; then
        log "WARNING: iptables rules detected - open ports 53, 853, and 5380 for your LAN manually."
        return 1
    fi
    return 0
}

# ---- prerequisites -----------------------------------------------------
# System packages first so curl is available for the rustup fetch below.
if need_cc || need_git || need_downloader; then
    if [ "${DAYGLE_NO_DEPS:-0}" != "1" ]; then
        install_system_toolchain || true
    fi
fi
if need_cc; then
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
fi

if need_dig; then
    if [ "${DAYGLE_NO_DEPS:-0}" != "1" ]; then
        install_dns_tools || true
    fi
fi

if need_cargo; then
    if [ "${DAYGLE_NO_DEPS:-0}" != "1" ]; then
        install_rust || true
    fi
    if need_cargo; then
        printf '%s\n' \
            'error: cargo was not found. Daygle is built from source and requires Rust.' \
            'Install the minimal Rust toolchain non-interactively:' \
            '' \
            '    curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal' \
            '' \
            'Then open a new shell (or run: source "$HOME/.cargo/env") and re-run the installer.' \
            'See https://rustup.rs for other installation options.' >&2
        exit 1
    fi
fi

SRC_DIR="$(mktemp -d)"
trap 'rm -rf "$SRC_DIR"' EXIT

log "Downloading Daygle DNS source…"
if need_git; then
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
git clone --depth 1 https://github.com/daygle/daygle-dns.git "$SRC_DIR"
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
# Older example configs referenced an optional blocklist file that was
# never created; keep a placeholder so those configs can start.
if [ ! -f "$CONFIG_DIR/blocklist.txt" ]; then
    : > "$CONFIG_DIR/blocklist.txt"
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

# ---- optional LAN access for the web GUI ------------------------------
# The API/GUI binds to 127.0.0.1 by default so an unauthenticated admin
# console is never exposed. When run interactively the installer can bind
# it to 0.0.0.0 and create an admin login; non-interactive runs opt in
# with DAYGLE_LAN_GUI=1 (plus DAYGLE_ADMIN_USER / DAYGLE_ADMIN_PASSWORD)
# and opt out with DAYGLE_LAN_GUI=0.
CONFIG_FILE="$CONFIG_DIR/daygle-dns.toml"
LAN_SETUP=0
LAN_IP=""
if [ "${DAYGLE_LAN_GUI:-}" = "1" ]; then
    LAN_SETUP=1
elif [ "${DAYGLE_LAN_GUI:-}" != "0" ] && : < /dev/tty 2>/dev/null; then
    printf '%s' "[daygle-dns-install] Expose the web GUI to your LAN (adds an admin login, binds 0.0.0.0:5380)? [y/N] "
    ANSWER=
    read -r ANSWER < /dev/tty || true
    case "$ANSWER" in
        y|Y|yes|Yes|YES) LAN_SETUP=1 ;;
    esac
fi

if [ "$LAN_SETUP" = "1" ]; then
    ADMIN_USER="${DAYGLE_ADMIN_USER:-admin}"
    if [ -n "${DAYGLE_ADMIN_PASSWORD:-}" ]; then
        ADMIN_PASSWORD="$DAYGLE_ADMIN_PASSWORD"
    elif : < /dev/tty 2>/dev/null; then
        printf '%s' "[daygle-dns-install] Password for user '$ADMIN_USER': "
        ADMIN_PASSWORD=
        read -r ADMIN_PASSWORD < /dev/tty || true
        printf '\n'
    else
        if command -v openssl >/dev/null 2>&1; then
            ADMIN_PASSWORD="$(openssl rand -hex 12)"
        else
            ADMIN_PASSWORD="daygle-$(date +%s)$$"
        fi
        log "Generated a random admin password (shown at the end of this run)."
    fi
    if [ -z "${ADMIN_PASSWORD:-}" ]; then
        log "No password given - leaving the GUI on the loopback interface."
        LAN_SETUP=0
    else
        ADMIN_HASH="$("$PREFIX/bin/daygle-dns" hash-password "$ADMIN_PASSWORD")"
        # Rebind the API/GUI to all interfaces (portable sed: no -i).
        sed 's/^listen = "127.0.0.1"/listen = "0.0.0.0"/' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
        if ! grep -q '\[\[api.users\]\]' "$CONFIG_FILE"; then
            cat >> "$CONFIG_FILE" <<EOF

# Added by the installer: LAN web GUI login.
[[api.users]]
username = "$ADMIN_USER"
password_hash = "$ADMIN_HASH"
role = "admin"
EOF
        fi
        open_lan_firewall || true
        LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
        log "Web GUI user '$ADMIN_USER' added and API bound to 0.0.0.0:5380."
        if command -v systemctl >/dev/null 2>&1; then
            systemctl restart daygle-dns 2>/dev/null || true
            log "Restarted daygle-dns to apply the GUI bind."
        fi
        if [ -n "$LAN_IP" ]; then
            log "Web GUI (LAN): http://$LAN_IP:5380  user: $ADMIN_USER  password: $ADMIN_PASSWORD"
        fi
    fi
fi

GUI_HOST="$LAN_IP"
[ -n "$GUI_HOST" ] || GUI_HOST="127.0.0.1"
log "Done! Web GUI: http://$GUI_HOST:5380"
log "Configuration: $CONFIG_DIR/daygle-dns.toml"
