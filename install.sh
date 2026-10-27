#!/usr/bin/env sh
# Daygle DNS - one-line installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh | sudo sh
#
# The script installs the `daygle-dns` binary to /usr/local/bin, a
# configuration file and a systemd unit (systemd-based Linux only). Missing
# prerequisites (Rust, a C compiler, git, a downloader such as curl) are
# installed automatically when possible via rustup and the detected package
# manager; DNS test tools (dig) are installed as a convenience. Set
# DAYGLE_DNS_NO_DEPS=1 to skip the automatic installs and get manual
# instructions instead.
#
# DAYGLE_DNS_GUI_UPDATE=1 marks an update run driven by the installed
# console (its updater stages this script and the root apply service
# executes it): everything still runs, but configuration-affecting rewrites
# - the [api] listen rebind, generated console accounts, firewall rule
# changes and freeing port 53 from systemd-resolved - are skipped, because
# the deployment's own config is authoritative on a host that is merely
# being updated.
#
# DAYGLE_DNS_KEEP_RESOLVED=1 leaves the systemd-resolved stub listener on
# (by default it is turned off so the server can bind port 53).

set -eu

# A GUI-driven update runs this script from a systemd oneshot, whose
# environment has no HOME (and a PATH without ~/.cargo/bin). Fall back to the
# invoking user's passwd home so rustup/cargo resolve the same toolchain a
# hand-run install would, instead of tripping `set -u` or reinstalling Rust.
if [ -z "${HOME:-}" ]; then
    HOME="$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6 || true)"
    [ -n "$HOME" ] || HOME="/root"
    export HOME
fi
if [ -d "$HOME/.cargo/bin" ]; then
    case ":$PATH:" in
        *":$HOME/.cargo/bin:"*) ;;
        *) PATH="$HOME/.cargo/bin:$PATH"; export PATH ;;
    esac
fi

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/daygle-dns}"
DATA_DIR="${DATA_DIR:-/var/lib/daygle-dns}"
SERVICE_USER="${SERVICE_USER:-daygle-dns}"
CONFIG_FILE="$CONFIG_DIR/daygle-dns.toml"
SERVICE_FILE="/etc/systemd/system/daygle-dns.service"
PRIV_LIB_DIR="${PRIV_LIB_DIR:-$PREFIX/lib/daygle-dns}"
APPLY_HELPER="$PRIV_LIB_DIR/update-apply.sh"
# DAYGLE_DNS_AI=0 keeps the AI scanner off (the bundled starter model is
# still copied to the config dir; the [ai] section is simply not enabled).

# Detect the installation mode before changing anything. A config file is the
# strongest signal, while the binary/unit checks also catch interrupted or
# partially completed installations that should be repaired as upgrades.
INSTALL_MODE="install"
if [ -f "$CONFIG_FILE" ] || [ -x "$PREFIX/bin/daygle-dns" ] || [ -f "$SERVICE_FILE" ]; then
    INSTALL_MODE="upgrade"
fi

log() { printf '\033[1;32m[daygle-dns-install]\033[0m %s\n' "$1"; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# The binary, unit files and /etc paths all need root: check now rather than
# failing with "Permission denied" after a several-minute build.
if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' \
        'error: the installer must run as root. Re-run it with sudo:' \
        '' \
        '    curl -fsSL https://raw.githubusercontent.com/daygle/daygle-dns/main/install.sh | sudo sh' >&2
    exit 1
fi

download_url() {
    if have_cmd curl; then
        curl -fsSL --retry 3 --connect-timeout 15 "$1"
    elif have_cmd wget; then
        wget -qO- "$1"
    else
        return 1
    fi
}

need_cargo() { ! have_cmd cargo; }
need_git() { ! have_cmd git; }
need_downloader() { ! { have_cmd curl || have_cmd wget; }; }
need_dig() { ! have_cmd dig; }
need_cc() {
    ! { have_cmd cc || have_cmd gcc || have_cmd clang; }
}

has_configured_api_users() {
    [ -f "$CONFIG_FILE" ] && grep -q '^[[:space:]]*\[\[api\.users\]\]' "$CONFIG_FILE"
}

api_listen_address() {
    awk '
        /^\[api\][[:space:]]*$/ { in_api = 1; next }
        /^\[/ { in_api = 0 }
        in_api && $1 == "listen" {
            gsub(/["\r]/, "", $3)
            print $3
            exit
        }
    ' "$CONFIG_FILE" 2>/dev/null || true
}

first_api_username() {
    awk '
        /^\[\[api\.users\]\][[:space:]]*$/ { in_user = 1; next }
        /^\[/ { in_user = 0 }
        in_user && $1 == "username" {
            gsub(/["\r]/, "", $3)
            print $3
            exit
        }
    ' "$CONFIG_FILE" 2>/dev/null || true
}

has_ai_section() {
    [ -f "$CONFIG_FILE" ] && grep -q '^[[:space:]]*\[ai\][[:space:]]*$' "$CONFIG_FILE"
}

# Run a short-lived maintenance command as the service user (its SQLite
# database files are owned by it). The installer itself normally runs as
# root; being already the service user also works.
run_as_service() {
    if [ "$(id -u)" -eq 0 ]; then
        if have_cmd sudo; then
            sudo -H -u "$SERVICE_USER" -- "$@" || return 1
        elif have_cmd runuser; then
            runuser -u "$SERVICE_USER" -- "$@" || return 1
        else
            return 1
        fi
    elif [ "$(id -un)" = "$SERVICE_USER" ]; then
        "$@" || return 1
    else
        return 1
    fi
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
        run_as_root apt-get install -y --no-install-recommends build-essential git curl sudo || return 1
    elif have_cmd dnf; then
        run_as_root dnf -y group install "Development Tools" || return 1
        run_as_root dnf -y install git curl sudo || return 1
    elif have_cmd yum; then
        run_as_root yum -y groupinstall "Development Tools" || return 1
        run_as_root yum -y install git curl sudo || return 1
    elif have_cmd apk; then
        run_as_root apk add --no-cache build-base git curl sudo || return 1
    elif have_cmd pacman; then
        run_as_root pacman -S --needed --noconfirm base-devel git curl sudo || return 1
    elif have_cmd zypper; then
        run_as_root zypper -n install -t pattern devel_basis || return 1
        run_as_root zypper -n install git curl sudo || return 1
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
    log "Installing DNS test tools (dig)..."
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
        log "Installed dig (DNS test tool)."
    else
        log "dig not installed; DNS test tools are optional (dnsutils/bind-utils)."
    fi
}

install_rust() {
    log "Installing Rust via rustup (minimal profile)..."
    if have_cmd curl; then
        curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal || return 1
    elif have_cmd wget; then
        wget -qO- https://sh.rustup.rs | sh -s -- -y --profile minimal || return 1
    else
        return 1
    fi
    export PATH="$HOME/.cargo/bin:$PATH"
}

# Provision the root-owned apply step and the systemd units that perform the
# privileged half of an in-place update. The web console's updater (running as
# the unprivileged service account) only downloads, verifies and stages a
# release into $DATA_DIR/updates/staging, then drops a `request` marker into
# $DATA_DIR/updates. The daygle-dns-update.path watcher notices the marker and
# starts daygle-dns-update.service - a short root oneshot that swaps the
# binary, restarts the unit, health-checks and rolls back on failure. No sudo,
# no setuid, no CapabilityBoundingSet gymnastics: the privileged step is its
# own root systemd unit, so the service account never gains any other rights.
install_update_service() {
    run_as_root install -d "$PRIV_LIB_DIR" || return 1
    run_as_root install -d "$DATA_DIR/updates" "$DATA_DIR/updates/staging" || return 1
    run_as_root chown "$SERVICE_USER":"$SERVICE_USER" "$DATA_DIR/updates" "$DATA_DIR/updates/staging" || return 1
    run_as_root chmod 0770 "$DATA_DIR/updates" "$DATA_DIR/updates/staging" || return 1
    # Install the apply step from the checkout (single source of truth) and
    # bake in the concrete binary/updates paths.
    run_as_root install -m 0700 "$SRC_DIR/crates/daygle-dns-api/src/update-apply.sh" "$APPLY_HELPER" || return 1
    run_as_root chown root:root "$APPLY_HELPER" || return 1
    run_as_root sed -i "s|__DAYGLE_DNS_EXE__|$PREFIX/bin/daygle-dns|; s|__DAYGLE_DNS_UPDATES_DIR__|$DATA_DIR/updates|; s|__DAYGLE_DNS_MODELS_DIR__|$CONFIG_DIR/models|; s|__DAYGLE_DNS_USER__|$SERVICE_USER|" "$APPLY_HELPER" || return 1
    run_as_root tee /etc/systemd/system/daygle-dns-update.service > /dev/null <<EOF
[Unit]
Description=Daygle DNS update apply step (root oneshot)

[Service]
Type=oneshot
# A GUI-driven update rebuilds from source inside this oneshot and can
# legitimately run for several minutes on a small host; never time it out.
TimeoutStartSec=0
ExecStart=$APPLY_HELPER
EOF
    run_as_root tee /etc/systemd/system/daygle-dns-update.path > /dev/null <<EOF
[Unit]
Description=Daygle DNS update request watcher

[Path]
PathChanged=$DATA_DIR/updates
Unit=daygle-dns-update.service

[Install]
WantedBy=multi-user.target
EOF
    run_as_root systemctl daemon-reload || return 1
    run_as_root systemctl enable --quiet --now daygle-dns-update.path || return 1
    # Remove the sudo-based privilege plumbing provisioned by older installer
    # runs (it is obsolete and can no longer be exercised by the updater).
    run_as_root rm -f /etc/sudoers.d/"$SERVICE_USER" "$PRIV_LIB_DIR/update-priv.sh"
}

# Networks the installer opens the firewall to: the same private ranges the
# server's "Private Networks Only" recursion access trusts (PRIVATE_NETWORKS
# in config.rs, loopback aside): RFC 1918, CGNAT 100.64.0.0/10 (also used by
# Tailscale), link-local, and IPv6 unique local and link-local addresses.
LAN_NETS_V4="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16"
LAN_NETS_V6="fc00::/7 fe80::/10"

open_lan_firewall() {
    # Best-effort: open LAN-scoped rules where possible, warn otherwise.
    # Prints a warning when a firewall is active that we cannot configure.
    # Port 853 is DNS over TLS (TCP) and DNS over QUIC (UDP).
    if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | grep -qi '^Status: active'; then
            log "Opening ports 53, 853, and 5380 for private LAN ranges (IPv4 and IPv6) in ufw..."
            for net in $LAN_NETS_V4 $LAN_NETS_V6; do
                ufw allow from "$net" to any port 5380 proto tcp >/dev/null 2>&1 || true
                ufw allow from "$net" to any port 53 >/dev/null 2>&1 || true
                ufw allow from "$net" to any port 853 >/dev/null 2>&1 || true
            done
            return 0
        fi
        return 0
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        log "Opening ports 53, 853, and 5380 for private LAN ranges (IPv4 and IPv6) in firewalld..."
        for net in $LAN_NETS_V4 $LAN_NETS_V6; do
            case "$net" in
                *:*) family=ipv6 ;;
                *) family=ipv4 ;;
            esac
            for rule in 5380/tcp 53/udp 53/tcp 853/tcp 853/udp; do
                firewall-cmd --permanent --add-rich-rule="rule family=$family source address=$net port port=${rule%/*} protocol=${rule#*/} accept" >/dev/null 2>&1 || true
            done
        done
        firewall-cmd --reload >/dev/null 2>&1 || true
        return 0
    fi
    if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1 && [ -n "$(nft list ruleset 2>/dev/null)" ]; then
        log "NOTE: nftables rules were detected. If the web GUI is not reachable from your LAN,"
        log "      open ports 53, 853, and 5380 for your LAN in nftables (or your cloud/router firewall)."
        return 0
    fi
    if command -v iptables >/dev/null 2>&1 && iptables -S >/dev/null 2>&1 && [ -n "$(iptables -S 2>/dev/null)" ]; then
        log "NOTE: iptables rules were detected. If the web GUI is not reachable from your LAN,"
        log "      open ports 53, 853, and 5380 for your LAN in iptables (or your cloud/router firewall)."
        return 0
    fi
    return 0
}

# The value of `key` in config file section `[$1]` (empty when unset).
config_setting() {
    awk -v section="[$1]" -v key="$2" '
        /^\[/ { in_section = ($1 == section) ; next }
        in_section && $1 == key {
            sub(/^[^=]*=[[:space:]]*/, "")
            sub(/[[:space:]]*#.*$/, "")
            gsub(/["\r]/, "")
            print
            exit
        }
    ' "$CONFIG_FILE" 2>/dev/null || true
}

# Programs other than Daygle DNS listening on TCP or UDP port 53, as
# `address (program)` lines. Empty when `ss` is missing.
port_53_holders() {
    have_cmd ss || return 0
    ss -Hlntup 'sport = :53' 2>/dev/null | awk '
        $0 !~ /"daygle-dns"/ {
            prog = "unknown program"
            if (match($0, /users:\(\("[^"]+"/)) prog = substr($0, RSTART + 9, RLENGTH - 10)
            print $5 " (" prog ")"
        }
    ' | sort -u
}

# Free port 53 for the DNS server. systemd-resolved (Ubuntu, Fedora and
# other systemd distributions) runs a stub resolver on 127.0.0.53:53 and
# 127.0.0.54:53, and Linux will not let a wildcard listener share the port
# with it, so the service would exit with "Address already in use". Turn the
# stub off with a drop-in and point /etc/resolv.conf at the upstream servers
# systemd-resolved knows (not at this server, so the host keeps resolving
# while Daygle DNS is stopped). DAYGLE_DNS_KEEP_RESOLVED=1 leaves it alone.
free_dns_port() {
    port="$(config_setting server port)"
    [ -z "$port" ] || [ "$port" = "53" ] || return 0
    listen="$(config_setting server listen)"
    case ",${listen:-0.0.0.0}," in
        *0.0.0.0*|*,::,*|*'[::]'*|*127.0.0.53*|*127.0.0.54*) ;;
        *) return 0 ;; # only specific addresses: they do not collide
    esac

    if have_cmd systemctl && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        stub_on=1
        if have_cmd ss && ! ss -Hlntu 'sport = :53' 2>/dev/null | grep -qE '127\.0\.0\.5[34](%[^:]*)?:53'; then
            stub_on=0
        fi
        if [ "$stub_on" = "1" ]; then
            if [ "${DAYGLE_DNS_KEEP_RESOLVED:-}" = "1" ]; then
                log "WARNING: systemd-resolved is listening on port 53 and DAYGLE_DNS_KEEP_RESOLVED=1 is set,"
                log "         so Daygle DNS cannot bind port 53 until its stub listener is turned off."
                return 0
            fi
            log "Turning off the systemd-resolved stub listener so Daygle DNS can use port 53..."
            run_as_root mkdir -p /etc/systemd/resolved.conf.d
            run_as_root tee /etc/systemd/resolved.conf.d/daygle-dns.conf >/dev/null <<'EOF'
# Written by the Daygle DNS installer. Daygle DNS answers on port 53, so the
# systemd-resolved stub listener (127.0.0.53 and 127.0.0.54) is turned off.
# To undo: delete this file, link /etc/resolv.conf back to
# /run/systemd/resolve/stub-resolv.conf and restart systemd-resolved.
[Resolve]
DNSStubListener=no
EOF
            # The stub resolv.conf names 127.0.0.53, which stops answering:
            # use the list of real upstream servers instead.
            if [ -L /etc/resolv.conf ] && readlink /etc/resolv.conf | grep -q 'stub-resolv\.conf$'; then
                run_as_root ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
                log "Linked /etc/resolv.conf to /run/systemd/resolve/resolv.conf (the upstream DNS servers)."
            elif grep -qE '^[[:space:]]*nameserver[[:space:]]+127\.0\.0\.5[34]' /etc/resolv.conf 2>/dev/null; then
                log "WARNING: /etc/resolv.conf names 127.0.0.53 but is not the systemd-resolved stub link;"
                log "         point it at your DNS servers (or at this server) so this host keeps resolving."
            fi
            run_as_root systemctl restart systemd-resolved || log "WARNING: could not restart systemd-resolved."
        fi
    fi

    holders="$(port_53_holders)"
    if [ -n "$holders" ]; then
        log "WARNING: port 53 is still in use, so Daygle DNS may fail to start:"
        printf '%s\n' "$holders" | while IFS= read -r line; do log "           $line"; done
        log "         Stop or reconfigure that program (dnsmasq, bind9, unbound, another DNS server)."
    fi
}

# ---- prerequisites -----------------------------------------------------
# System packages first so curl is available for the rustup fetch below.
if need_cc || need_git || need_downloader; then
    if [ "${DAYGLE_DNS_NO_DEPS:-0}" != "1" ]; then
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
    if [ "${DAYGLE_DNS_NO_DEPS:-0}" != "1" ]; then
        install_dns_tools || true
    fi
fi

if need_cargo; then
    if [ "${DAYGLE_DNS_NO_DEPS:-0}" != "1" ]; then
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

if [ "$INSTALL_MODE" = "upgrade" ]; then
    log "Existing Daygle DNS installation detected - upgrading in place."
    if [ -x "$PREFIX/bin/daygle-dns" ]; then
        INSTALLED_VERSION="$($PREFIX/bin/daygle-dns --version 2>/dev/null || true)"
        [ -n "$INSTALLED_VERSION" ] && log "Installed version: $INSTALLED_VERSION"
    fi
    log "Existing configuration, zones, certificates, and database will be preserved."
else
    log "No existing Daygle DNS installation detected - performing a fresh install."
fi

SRC_DIR="$(mktemp -d)"
trap 'rm -rf "$SRC_DIR"' EXIT

log "Downloading Daygle DNS source..."
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
# Build the latest stable release, not the tip of main: "update to the
# latest release" must install exactly that release's code, and the version
# the binary reports must name the code it runs.
RELEASE_TAG="$(download_url "https://api.github.com/repos/daygle/daygle-dns/releases/latest" 2>/dev/null \
    | sed -n 's/^[[:space:]]*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1 || true)"
if [ -z "$RELEASE_TAG" ]; then
    RELEASE_TAG="$(download_url "https://github.com/daygle/daygle-dns/releases/latest" 2>/dev/null \
        | sed -n 's#.*releases/tag/\([^"/?#]*\).*#\1#p' \
        | head -n 1 || true)"
fi
RELEASE_VERSION="${RELEASE_TAG#v}"
if ! printf '%s\n' "$RELEASE_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$'; then
    log "ERROR: Could not resolve a valid latest GitHub release version; refusing to build with a stale version."
    exit 1
fi
git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$RELEASE_TAG" \
    https://github.com/daygle/daygle-dns.git "$SRC_DIR"
cd "$SRC_DIR"

# Cargo embeds the workspace package version into the binary, and a tag's
# manifest can lag its tag (historically v1.0.0): set it from the tag.
if ! awk -v version="$RELEASE_VERSION" '
    /^\[workspace\.package\][[:space:]]*$/ { in_workspace_package = 1; print; next }
    /^\[/ { if (in_workspace_package) in_workspace_package = 0 }
    in_workspace_package && /^[[:space:]]*version[[:space:]]*=/ {
        print "version = \"" version "\""
        updated = 1
        next
    }
    { print }
    END { if (!updated) exit 1 }
' Cargo.toml > Cargo.toml.tmp; then
    rm -f Cargo.toml.tmp
    log "ERROR: Could not set the Cargo workspace version from release $RELEASE_TAG."
    exit 1
fi
mv Cargo.toml.tmp Cargo.toml
log "Building Daygle DNS release $RELEASE_TAG (this may take a few minutes)..."
cargo build --release -p daygle-dns
BUILT_VERSION="$(target/release/daygle-dns --version 2>/dev/null | awk '{print $2}')"
if [ "$BUILT_VERSION" != "$RELEASE_VERSION" ]; then
    log "ERROR: Built binary reports version '$BUILT_VERSION', expected '$RELEASE_VERSION'."
    exit 1
fi

log "Installing binary to $PREFIX/bin/daygle-dns..."
install -d "$PREFIX/bin"
# Install beside the target and rename: writing over the running executable
# fails with "Text file busy" (ETXTBSY); rename(2) swaps the directory entry
# atomically without touching the live inode.
rm -f "$PREFIX/bin/daygle-dns.new"
install -m 0755 target/release/daygle-dns "$PREFIX/bin/daygle-dns.new"
mv -f "$PREFIX/bin/daygle-dns.new" "$PREFIX/bin/daygle-dns"

log "Installing configuration to $CONFIG_DIR..."
install -d "$CONFIG_DIR" "$CONFIG_DIR/zones" "$CONFIG_DIR/certs" "$DATA_DIR"
if [ ! -f "$CONFIG_DIR/daygle-dns.toml" ]; then
    install -m 0644 daygle-dns.toml.example "$CONFIG_DIR/daygle-dns.toml"
fi
# Older example configs referenced an optional blocklist file that was
# never created; keep a placeholder so those configs can start.
if [ ! -f "$CONFIG_DIR/blocklist.txt" ]; then
    : > "$CONFIG_DIR/blocklist.txt"
fi

# ---- bundled AI starter model --------------------------------------------
# The AI scanner (daygle-dns-ml) is enabled in safe "train" mode out of the
# box: a small fastText classifier ships in the source tree and is recorded
# verdicts only until mode = "enforce". DAYGLE_DNS_AI=0 keeps the scanner
# disabled without touching the rest of the install.
if [ "${DAYGLE_DNS_AI:-}" != "0" ]; then
    if [ -f "$SRC_DIR/models/daygle-starter.bin" ]; then
        install -d "$CONFIG_DIR/models"
        if [ ! -f "$CONFIG_DIR/models/daygle-starter.bin" ]; then
            install -m 0644 "$SRC_DIR/models/daygle-starter.bin" \
                "$CONFIG_DIR/models/daygle-starter.bin"
            chown "$SERVICE_USER":"$SERVICE_USER" \
                "$CONFIG_DIR/models/daygle-starter.bin" 2>/dev/null || true
            log "Installed bundled AI starter model to $CONFIG_DIR/models/daygle-starter.bin"
        fi
        # MiniLM/ONNX verifier artifacts: model, tokenizer, centroid refs.
        for f in all-MiniLM-L6-v2-int8.onnx minilm-tokenizer.json minilm-centroids.json; do
            if [ -f "$SRC_DIR/models/$f" ] && [ ! -f "$CONFIG_DIR/models/$f" ]; then
                install -m 0644 "$SRC_DIR/models/$f" "$CONFIG_DIR/models/$f"
                chown "$SERVICE_USER":"$SERVICE_USER" "$CONFIG_DIR/models/$f" 2>/dev/null || true
            fi
        done
        # Upgrades keep their existing configuration untouched, but an older
        # installer predates the AI section: seed it once, in train mode, so
        # the model the operator already has on disk is actually used.
        if ! has_ai_section && [ -f "$CONFIG_FILE" ]; then
            cat >> "$CONFIG_FILE" <<EOF

# AI scanner (added by the installer): train mode records verdicts only;
# nothing is blocked until you set mode = "enforce" below or in the GUI.
[ai]
enabled = true
mode = "train"
database = ""
model_path = "$CONFIG_DIR/models/daygle-starter.bin"
EOF
            chown "$SERVICE_USER":"$SERVICE_USER" "$CONFIG_FILE" 2>/dev/null || true
            log "Added safe [ai] section (train mode) to $CONFIG_FILE."
        fi
    else
        log "WARNING: bundled AI model missing from the source tree; the AI scanner will fall back to its heuristic backend."
    fi
else
    log "DAYGLE_DNS_AI=0 - leaving the AI scanner disabled."
    if [ "$INSTALL_MODE" = "install" ] && has_ai_section; then
        sed -i '/^\[ai\][[:space:]]*$/,/^\[/s/^enabled = true/enabled = false/' "$CONFIG_FILE"
        log "Fresh install with DAYGLE_DNS_AI=0: [ai] section disabled in $CONFIG_FILE."
    fi
fi

# ---- systemd unit (Linux with systemd only) -----------------------------
if [ -d /etc/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    log "Installing systemd unit..."
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
# DNS on port 53 needs privileges. The service drops to a dedicated user;
# the ambient cap covers the port bind. The privileged half of updates is
# performed by the separate root daygle-dns-update.service (see
# install_update_service), so this unit carries no setuid/sudo machinery and
# nothing it runs may gain privileges (ambient capabilities are unaffected).
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
# Files the server creates (the database with its private keys, TOTP
# secrets and password hashes, backups, TLS material) are not readable by
# other local accounts.
UMask=0027

[Install]
WantedBy=multi-user.target
EOF
    id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --no-create-home "$SERVICE_USER"
    # In-place updates from the web console hand the privileged binary swap,
    # restart and health-check to a root systemd oneshot triggered by a path
    # unit (no sudo, no setuid on the service account).
    install_update_service || log "WARNING: could not provision the systemd update service; in-place updates from the web console will be unavailable until a re-run succeeds."
    # Older installer runs (and some debugging drop-ins) pinned the service's
    # CapabilityBoundingSet with setuid/sudo machinery that is no longer used.
    # Reconcile a stale drop-in so a reinstall heals the host without manual
    # edits; drop-ins with other, deliberate settings are left untouched.
    DROP_DIR=/etc/systemd/system/daygle-dns.service.d
    if [ -f "$DROP_DIR/capabilities.conf" ]; then
        if [ -z "$(grep -vE '^[[:space:]]*(#.*)?$' "$DROP_DIR/capabilities.conf" 2>/dev/null | grep -v '^CapabilityBoundingSet=')" ]; then
            run_as_root rm -f "$DROP_DIR/capabilities.conf"
            if [ -z "$(ls -A "$DROP_DIR" 2>/dev/null)" ]; then
                run_as_root rmdir "$DROP_DIR" 2>/dev/null || true
            fi
            log "Removed the stale capabilities drop-in (the service unit now grants only CAP_NET_BIND_SERVICE)."
        fi
    fi
    chown -R "$SERVICE_USER":"$SERVICE_USER" "$CONFIG_DIR" "$DATA_DIR"
    # The config can hold the API token and TSIG secrets, and the data dir
    # the database with every private key: keep other local accounts out of
    # both (existing installs included, whose files were created 0644).
    chmod 0750 "$CONFIG_DIR" "$DATA_DIR"
    # A GUI-driven update leaves the host's resolver setup alone.
    if [ "${DAYGLE_DNS_GUI_UPDATE:-}" != "1" ]; then
        free_dns_port || true
    fi
    systemctl daemon-reload
    if [ "$INSTALL_MODE" = "upgrade" ]; then
        WAS_ACTIVE=0
        if systemctl is-active --quiet daygle-dns 2>/dev/null; then
            WAS_ACTIVE=1
        fi
        # The runtime settings overlay lives in the database and wins over
        # the config file: synchronize the [ai] section (bundled starter
        # model, train mode) for installs that predate the AI feature. This
        # writes SQLite, so the service must be down while it runs.
        systemctl stop daygle-dns 2>/dev/null || true
        if [ "${DAYGLE_DNS_AI:-}" != "0" ] && id "$SERVICE_USER" >/dev/null 2>&1; then
            # (global --config must precede the subcommand)
            # Its stdout says which branch it took; report that through log
            # rather than letting the bare line interleave with ours.
            if SEED_OUT=$(run_as_service "$PREFIX/bin/daygle-dns" --config "$CONFIG_FILE" seed-ai-settings); then
                case "$SEED_OUT" in
                    *"left untouched"*)
                        log "AI runtime settings were changed in the web console; keeping them (config file [ai] section not applied)." ;;
                    *)
                        log "AI runtime settings synchronized from the config file (bundled starter model, train mode)." ;;
                esac
            else
                log "WARNING: could not synchronize AI runtime settings; enable the AI scanner from the console's AI page if you want it."
            fi
        fi
        if [ "$WAS_ACTIVE" = "1" ]; then
            systemctl restart daygle-dns
        else
            # Also repairs an interrupted or previously disabled installation.
            systemctl enable --quiet --now daygle-dns
        fi
    else
        systemctl enable --quiet --now daygle-dns
    fi
fi

# ---- web GUI on the LAN -----------------------------------------
# The API/GUI binds to 127.0.0.1 by default so an unauthenticated admin
# console is never exposed. The installer always rebinds it to 0.0.0.0 so
# the first-run setup page (or a supplied admin account) is reachable from
# the LAN; opt out with DAYGLE_DNS_LAN_GUI=0.
#
# A GUI-driven update run (DAYGLE_DNS_GUI_UPDATE=1) skips this whole
# section: the operator's listen address, console accounts and firewall
# rules were explicit choices and an in-place update must not change them.
if [ "${DAYGLE_DNS_GUI_UPDATE:-}" = "1" ]; then
    log "Update run: configuration, [api] listener, accounts and firewall rules left untouched."
elif [ "${DAYGLE_DNS_LAN_GUI:-}" = "0" ]; then
    :
else
    ADMIN_USER="${DAYGLE_DNS_ADMIN_USER:-}"
    PRESERVE_USERS=0
    if [ "$INSTALL_MODE" = "upgrade" ] && has_configured_api_users; then
        PRESERVE_USERS=1
        EXISTING_USER="$(first_api_username)"
        [ -n "$EXISTING_USER" ] && ADMIN_USER="$EXISTING_USER"
        log "Preserving existing console account '$ADMIN_USER'; the installer will not replace its password."
    fi
    if [ "$PRESERVE_USERS" = "1" ]; then
        ADMIN_PASSWORD=""
        ADMIN_HASH=""
    elif [ -n "${DAYGLE_DNS_ADMIN_USER:-}" ]; then
        ADMIN_PASSWORD="${DAYGLE_DNS_ADMIN_PASSWORD:-}"
        if [ -z "$ADMIN_PASSWORD" ]; then
            if command -v openssl >/dev/null 2>&1; then
                ADMIN_PASSWORD="$(openssl rand -hex 12)"
            else
                # Never derive it from the clock/pid: those are guessable.
                ADMIN_PASSWORD="$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
            fi
            GENERATED_PASSWORD=1
        fi
    else
        # No explicit credentials: leave ADMIN_USER / ADMIN_PASSWORD empty so
        # no [[api.users]] is written and the first GUI visit shows the setup page.
        :
    fi

    # Rebind the API listener from 127.0.0.1 to 0.0.0.0. Only the [api] section
    # is touched (the DNS and DoT/DoH/DoQ listeners keep their own binds).
    awk '
        /^\[api\][[:space:]]*$/ { in_api = 1 }
        /^\[/ && $0 !~ /^\[api\][[:space:]]*$/ { in_api = 0 }
        in_api && $1 == "listen" { $0 = "listen = \"0.0.0.0\"" }
        { print }
    ' "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
    chown "$SERVICE_USER":"$SERVICE_USER" "$CONFIG_FILE" 2>/dev/null || true

    # Best-effort verification: if the awk pattern did not match the actual
    # listen line (unusual formatting, different quoting, a comment, etc.)
    # force the bind with a second, more explicit pass so the LAN GUI is
    # reachable without requiring the user to hand-edit the config.
    if [ "$(api_listen_address)" != "0.0.0.0" ]; then
        # Scoped to the [api] section: an unscoped substitution would also
        # rebind the DNS and DoT/DoH/DoQ listeners.
        sed -i '/^\[api\][[:space:]]*$/,/^\[/ s/^\([[:space:]]*listen[[:space:]]*=[[:space:]]*\)"[^"]*"/\1"0.0.0.0"/' "$CONFIG_FILE"
        chown "$SERVICE_USER":"$SERVICE_USER" "$CONFIG_FILE" 2>/dev/null || true
    fi

    if [ "$PRESERVE_USERS" != "1" ] && [ -n "${ADMIN_USER:-}" ] && [ -n "${ADMIN_PASSWORD:-}" ]; then
        # Explicit credentials: also write the admin account to the config so the
        # GUI is reachable immediately without the setup page.
        ADMIN_HASH="$("$PREFIX/bin/daygle-dns" hash-password "$ADMIN_PASSWORD")"
        cat >> "$CONFIG_FILE" <<EOF

# Added by the installer: LAN web GUI login.
[[api.users]]
username = "$ADMIN_USER"
password_hash = "$ADMIN_HASH"
role = "admin"
EOF
    fi

    open_lan_firewall || true
fi

# ---- summary -------------------------------------------------------------
# Restart so the console listens where the config now says, wait until the
# service is up and the console answers, then report what is true: the
# addresses to use, the next step, and where to look if it is not running.

# Whether something answers HTTP(S) at $1 (any status counts: the console
# may redirect or ask for a login).
answers() {
    if have_cmd curl; then
        code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 2 "$1" 2>/dev/null || true)"
        [ -n "$code" ] && [ "$code" != "000" ]
    elif have_cmd wget; then
        # 8: the server answered with an error status, which still counts.
        rc=0
        wget -q -O /dev/null --no-check-certificate -T 2 -t 1 "$1" 2>/dev/null || rc=$?
        [ "$rc" -eq 0 ] || [ "$rc" -eq 8 ]
    else
        return 1
    fi
}

# The console URL on `$1` (an address), or empty when it does not answer.
# Settings → General may have moved it to HTTPS, so both ports are tried.
console_url() {
    for url in "http://$1:$API_PORT" "https://$1:$HTTPS_PORT"; do
        if answers "$url"; then
            printf '%s\n' "$url"
            return 0
        fi
    done
}

# Run only when the installer is run by hand: a GUI-driven update has its
# own health check and rollback, and its output goes to the journal.
if [ "${DAYGLE_DNS_GUI_UPDATE:-}" != "1" ]; then
    API_PORT="$(config_setting api port)"; API_PORT="${API_PORT:-5380}"
    HTTPS_PORT="$(config_setting web https_port)"; HTTPS_PORT="${HTTPS_PORT:-5443}"
    DNS_PORT="$(config_setting server port)"; DNS_PORT="${DNS_PORT:-53}"
    LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    VERSION="$("$PREFIX/bin/daygle-dns" --version 2>/dev/null | awk '{print $2}' || true)"
    if [ "$INSTALL_MODE" = "upgrade" ]; then DONE="upgraded"; else DONE="installed"; fi

    RUNNING=""
    LOCAL_URL=""
    if have_cmd systemctl && [ -f "$SERVICE_FILE" ]; then
        systemctl restart daygle-dns 2>/dev/null || true
        tries=0
        while [ "$tries" -lt 30 ]; do
            if systemctl is-active --quiet daygle-dns; then
                RUNNING=1
                LOCAL_URL="$(console_url 127.0.0.1)"
                [ -n "$LOCAL_URL" ] && break
            else
                RUNNING=""
            fi
            tries=$((tries + 1))
            sleep 1
        done
    fi

    log ""
    if [ -z "$RUNNING" ] && ! { have_cmd systemctl && [ -f "$SERVICE_FILE" ]; }; then
        log "Daygle DNS ${VERSION:+v$VERSION }is $DONE. No systemd was found, so start it yourself:"
        log "    $PREFIX/bin/daygle-dns --config $CONFIG_FILE"
    elif [ -z "$RUNNING" ]; then
        log "Daygle DNS ${VERSION:+v$VERSION }is $DONE, but the service is NOT running."
        log "See why with:  journalctl -u daygle-dns -n 30"
        log "Configuration: $CONFIG_FILE"
        exit 1
    else
        log "Daygle DNS ${VERSION:+v$VERSION }is $DONE and running."
    fi
    log ""

    # The console as other devices reach it, else as this machine does.
    SHOWN_URL=""
    if [ -n "$LOCAL_URL" ] && [ -n "$LAN_IP" ] && [ "$(api_listen_address)" != "127.0.0.1" ]; then
        SHOWN_URL="$(console_url "$LAN_IP")"
    fi
    if [ -n "$SHOWN_URL" ]; then
        log "  Web console:  $SHOWN_URL"
    elif [ -n "$LOCAL_URL" ]; then
        log "  Web console:  $LOCAL_URL (this machine only)"
    elif [ -n "$RUNNING" ]; then
        log "  Web console:  not answering yet on port $API_PORT; see journalctl -u daygle-dns"
    elif [ -n "$LAN_IP" ]; then
        log "  Web console:  http://$LAN_IP:$API_PORT once started"
    else
        log "  Web console:  http://<this server's address>:$API_PORT once started"
    fi
    if [ -n "${GENERATED_PASSWORD:-}" ]; then
        log "  Admin login:  $ADMIN_USER / $ADMIN_PASSWORD"
        log "                Shown only now: sign in and change it on the Account page."
    elif [ -n "${ADMIN_USER:-}" ]; then
        log "  Admin login:  $ADMIN_USER"
    elif [ "$INSTALL_MODE" = "install" ] && [ -n "$RUNNING" ]; then
        log "                Open it now to create the admin account."
    elif [ "$INSTALL_MODE" = "install" ]; then
        log "                Open it to create the admin account."
    fi

    DNS_HOST="${LAN_IP:-<this server's address>}"
    if [ "$DNS_PORT" = "53" ]; then
        log "  DNS server:   $DNS_HOST (set it as the DNS server on your router or devices)"
    else
        log "  DNS server:   $DNS_HOST port $DNS_PORT"
    fi
    log "  Config file:  $CONFIG_FILE"
    if have_cmd dig && [ -n "$RUNNING" ]; then
        if [ "$DNS_PORT" = "53" ]; then
            log "  Test:         dig @${LAN_IP:-127.0.0.1} example.com"
        else
            log "  Test:         dig @${LAN_IP:-127.0.0.1} -p $DNS_PORT example.com"
        fi
    fi
fi
