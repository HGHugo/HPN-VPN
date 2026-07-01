#!/bin/bash
#
# HPN VPN Server/Relay Deployment Script
#
# Usage:
#   ./install.sh [server|relay]
#
# This script:
#   1. Installs system dependencies
#   2. Creates hpn user and directories
#   3. Installs binaries
#   4. Configures systemd services
#   5. Tunes kernel parameters for VPN performance
#   6. Sets up firewall rules
#   7. Generates server keys (if server mode)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
HPN_USER="hpn"
HPN_GROUP="hpn"
HPN_DIR="/opt/hpn"
HPN_CONFIG_DIR="/etc/hpn"
HPN_LOG_DIR="/var/log/hpn"
HPN_DATA_DIR="/var/lib/hpn"
ADMIN_TOKEN_FILE="$HPN_CONFIG_DIR/admin-api-token"

# Default ports
SERVER_PORT=51820
RELAY_PORT=51821
METRICS_PORT=9100
ADMIN_PORT=9101

# Detect script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# NOTE: All performance tuning is now automatic at runtime.
# The server auto-detects: CPU cores, NIC queues, AF_XDP, io_uring, memory.
# No configuration or detection needed in install script.

#------------------------------------------------------------------------------
# Helper functions
#------------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    else
        DISTRO="unknown"
    fi
    log_info "Detected distribution: $DISTRO $DISTRO_VERSION"
}

#------------------------------------------------------------------------------
# Installation functions
#------------------------------------------------------------------------------

install_dependencies() {
    log_info "Installing system dependencies..."

    case $DISTRO in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq \
                iptables \
                iproute2 \
                procps \
                net-tools \
                curl \
                ca-certificates \
                gnupg
            ;;
        centos|rhel|fedora|rocky|alma)
            if command -v dnf &> /dev/null; then
                dnf install -y -q \
                    iptables \
                    iproute \
                    procps-ng \
                    net-tools \
                    curl \
                    ca-certificates
            else
                yum install -y -q \
                    iptables \
                    iproute \
                    procps-ng \
                    net-tools \
                    curl \
                    ca-certificates
            fi
            ;;
        *)
            log_warn "Unknown distribution, skipping dependency installation"
            ;;
    esac

    log_success "Dependencies installed"
}

create_user() {
    log_info "Creating HPN user and group..."

    if ! getent group "$HPN_GROUP" > /dev/null 2>&1; then
        groupadd --system "$HPN_GROUP"
    fi

    if ! id "$HPN_USER" > /dev/null 2>&1; then
        useradd --system --gid "$HPN_GROUP" --shell /sbin/nologin \
            --home-dir "$HPN_DATA_DIR" --no-create-home "$HPN_USER"
    fi

    log_success "User $HPN_USER created"
}

create_directories() {
    log_info "Creating directories..."

    mkdir -p "$HPN_DIR/bin"
    mkdir -p "$HPN_CONFIG_DIR"
    mkdir -p "$HPN_DATA_DIR"

    chown -R "$HPN_USER:$HPN_GROUP" "$HPN_DIR"
    chown -R "$HPN_USER:$HPN_GROUP" "$HPN_CONFIG_DIR"
    chown -R "$HPN_USER:$HPN_GROUP" "$HPN_DATA_DIR"

    chmod 750 "$HPN_CONFIG_DIR"
    chmod 755 "$HPN_DIR"

    log_success "Directories created"
}

install_binaries() {
    log_info "Installing binaries..."

    local mode=$1

    if [ -f "$SCRIPT_DIR/hpn-server" ]; then
        install -m 755 "$SCRIPT_DIR/hpn-server" "$HPN_DIR/bin/"
        log_success "Installed hpn-server"
    fi

    if [ -f "$SCRIPT_DIR/hpn-relay" ]; then
        install -m 755 "$SCRIPT_DIR/hpn-relay" "$HPN_DIR/bin/"
        log_success "Installed hpn-relay"
    fi

    # Create symlinks in /usr/local/bin
    ln -sf "$HPN_DIR/bin/hpn-server" /usr/local/bin/hpn-server 2>/dev/null || true
    ln -sf "$HPN_DIR/bin/hpn-relay" /usr/local/bin/hpn-relay 2>/dev/null || true

    log_success "Binaries installed to $HPN_DIR/bin"
}

#------------------------------------------------------------------------------
# Configuration functions
#------------------------------------------------------------------------------

configure_server() {
    log_info "Configuring HPN server..."

    local config_file="$HPN_CONFIG_DIR/server.toml"
    local admin_token

    if [ -f "$config_file" ]; then
        log_warn "Config file already exists, backing up to ${config_file}.bak"
        cp "$config_file" "${config_file}.bak"
    fi

    # Detect primary network interface for NAT
    local default_iface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$default_iface" ]; then
        default_iface="eth0"
    fi

    # Generate (or reuse) a strong Admin API token.
    # The token is stored in a dedicated file for operational use and also written
    # into server.toml so the server can enforce bearer auth automatically.
    if [ -s "$ADMIN_TOKEN_FILE" ]; then
        admin_token=$(tr -d '\r\n' < "$ADMIN_TOKEN_FILE")
        log_info "Reusing existing Admin API token from $ADMIN_TOKEN_FILE"
    else
        if command -v openssl > /dev/null 2>&1; then
            admin_token=$(openssl rand -hex 32)
        else
            admin_token=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
        fi

        if [ -z "$admin_token" ]; then
            log_error "Failed to generate Admin API token"
            exit 1
        fi

        umask 077
        printf "%s\n" "$admin_token" > "$ADMIN_TOKEN_FILE"
        chown root:root "$ADMIN_TOKEN_FILE"
        chmod 600 "$ADMIN_TOKEN_FILE"
        log_success "Generated Admin API token at $ADMIN_TOKEN_FILE"
    fi

    cat > "$config_file" << EOF
# HPN VPN Server Configuration
# Generated by install.sh on $(date)
#
# Documentation: https://hpn.hmsx.io/docs
#
# PERFORMANCE IS FULLY AUTOMATIC
# The server auto-detects CPU, memory, NIC, and kernel features.

[server]
# Listen address for UDP connections
listen_addr = "0.0.0.0:${SERVER_PORT}"

# IPv4 address pool for clients (CIDR notation)
ipv4_pool = "10.99.0.0/24"

# Server's tunnel IP address
server_tunnel_ip = "10.99.0.1"

# IPv6 dual-stack
# ipv6_pool = "fd00:99::/64"
# server_tunnel_ipv6 = "fd00:99::1"

# DNS servers to provide to clients
dns_servers = ["10.99.0.1", "1.1.1.1"]

# TUN device name
tun_name = "hpn0"

# MTU for the tunnel
mtu = 1420

# No-log mode (default: true)
# When enabled, no session data is logged. Only uptime is sent in heartbeat.
no_log = true

# Session management
session_timeout_secs = 180
keepalive_interval_secs = 25

# NAT configuration
enable_nat = true
nat_interface = "${default_iface}"

# Metrics (Prometheus format, optional)
enable_metrics = false
metrics_addr = "127.0.0.1:${METRICS_PORT}"

# Admin API
enable_admin_api = true
admin_addr = "127.0.0.1:${ADMIN_PORT}"
admin_api_token = "${admin_token}"

# User authentication
users_db_path = "${HPN_DATA_DIR}/users.db"
require_auth = true

# Privilege drop (defense-in-depth)
run_as_user = "${HPN_USER}"
run_as_group = "${HPN_GROUP}"

EOF

    chown root:"$HPN_GROUP" "$config_file"
    chmod 640 "$config_file"

    # Migrate legacy auth DB path if present.
    # Older installs used /etc/hpn/users.db, but systemd ProtectSystem=strict makes
    # /etc read-only at runtime unless explicitly whitelisted.
    if [ -f "${HPN_CONFIG_DIR}/users.db" ] && [ ! -f "${HPN_DATA_DIR}/users.db" ]; then
        mv "${HPN_CONFIG_DIR}/users.db" "${HPN_DATA_DIR}/users.db"
        chown "$HPN_USER:$HPN_GROUP" "${HPN_DATA_DIR}/users.db"
        chmod 600 "${HPN_DATA_DIR}/users.db"
        log_info "Migrated legacy user DB to ${HPN_DATA_DIR}/users.db"
    fi

    log_success "Server configuration created at $config_file"
}

configure_relay() {
    log_info "Configuring HPN relay..."

    local config_file="$HPN_CONFIG_DIR/relay.toml"

    if [ -f "$config_file" ]; then
        log_warn "Config file already exists, backing up to ${config_file}.bak"
        cp "$config_file" "${config_file}.bak"
    fi

    # Get hostname for relay ID
    local hostname=$(hostname -s)

    cat > "$config_file" << EOF
# HPN VPN Relay Configuration
# Generated by install.sh on $(date)
#
# Documentation: https://hpn.hmsx.io/docs

[relay]
# Listen address for client connections
listen_addr = "0.0.0.0:${RELAY_PORT}"

# Upstream VPN server (CHANGE THIS!)
upstream_addr = "YOUR_VPN_SERVER_IP:${SERVER_PORT}"

# Relay identifier
relay_id = "${hostname}"

# No-log mode (default: true)
no_log = true

# Session management
max_sessions = 10000
session_timeout_secs = 180
EOF

    chown "$HPN_USER:$HPN_GROUP" "$config_file"
    chmod 640 "$config_file"

    log_success "Relay configuration created at $config_file"
    log_warn "IMPORTANT: Edit $config_file and set the correct upstream_addr!"
}

generate_server_keys() {
    log_info "Generating server keys..."

    local config_file="$HPN_CONFIG_DIR/server.toml"
    local keys_file="$HPN_CONFIG_DIR/server-keys.toml"

    if [ ! -f "$HPN_DIR/bin/hpn-server" ]; then
        log_warn "hpn-server binary not found, skipping key generation"
        return
    fi

    # Generate keys using the server binary
    # genkey outputs 4 TOML sections:
    #   [keypair_level3]     - ML-DSA-65 signing (Level 3)
    #   [kem_keypair_level3] - ML-KEM-768 identity hiding (Level 3)
    #   [keypair_level5]     - ML-DSA-87 signing (Level 5)
    #   [kem_keypair_level5] - ML-KEM-1024 identity hiding (Level 5)
    cd "$HPN_CONFIG_DIR"
    "$HPN_DIR/bin/hpn-server" genkey --output "$keys_file" 2>/dev/null || {
        log_warn "Could not generate keys automatically. Please generate manually:"
        log_warn "  hpn-server genkey --output $keys_file"
        return
    }

    if [ ! -f "$keys_file" ]; then
        log_warn "Key generation failed - no keys file created"
        return
    fi

    # Append all keypair sections from genkey output directly to server config.
    # The genkey output is valid TOML with all 4 key sections — we strip
    # comment lines and blank-line-only headers, then append the sections.
    {
        echo ""
        echo "# ============================================================================"
        echo "# Server Keypairs (auto-generated by install.sh)"
        echo "# KEEP THE SECRET KEYS SECURE!"
        echo "# ============================================================================"
        echo ""
        # Extract only TOML sections and key=value lines (skip genkey comment header)
        grep -E '^\[|^secret_key|^public_key' "$keys_file"
    } >> "$config_file"

    # Verify all 4 sections were written
    local section_count
    section_count=$(grep -c '^\[' "$keys_file" 2>/dev/null || echo "0")
    if [ "$section_count" -ge 4 ]; then
        log_success "All $section_count keypair sections injected into config"
        log_success "  - Signing keypairs: Level 3 (ML-DSA-65) + Level 5 (ML-DSA-87)"
        log_success "  - KEM keypairs: Level 3 (ML-KEM-768) + Level 5 (ML-KEM-1024)"
        log_info "Identity hiding is ENABLED for both security levels"
    else
        log_warn "Expected 4 keypair sections, found $section_count. Check $keys_file"
    fi

    # Keep the keys file as backup
    chown root:"$HPN_GROUP" "$keys_file"
    chmod 600 "$keys_file"
}

verify_server_hardening() {
    log_info "Running post-install security checks..."

    local config_file="$HPN_CONFIG_DIR/server.toml"
    local checks_failed=0

    if [ ! -f "$config_file" ]; then
        log_error "Missing server config: $config_file"
        return 1
    fi

    if grep -Eq '^admin_addr\s*=\s*"127\.0\.0\.1:' "$config_file"; then
        log_success "Admin API bound to loopback"
    else
        log_error "Admin API is not bound to 127.0.0.1"
        checks_failed=$((checks_failed + 1))
    fi

    if grep -Eq '^admin_api_token\s*=\s*"[^"]+"' "$config_file"; then
        log_success "Admin API token is configured in server.toml"
    else
        log_error "Admin API token missing or empty in server.toml"
        checks_failed=$((checks_failed + 1))
    fi

    if grep -Eq '^run_as_user\s*=\s*"[^"]+"' "$config_file" && \
       grep -Eq '^run_as_group\s*=\s*"[^"]+"' "$config_file"; then
        log_success "Privilege drop account configured (run_as_user/run_as_group)"
    else
        log_error "run_as_user/run_as_group missing in server.toml"
        checks_failed=$((checks_failed + 1))
    fi

    if [ -s "$ADMIN_TOKEN_FILE" ]; then
        local perm
        perm=$(stat -c '%a %U:%G' "$ADMIN_TOKEN_FILE" 2>/dev/null || true)
        if [ "$perm" = "600 root:root" ]; then
            log_success "Admin token file permissions are strict ($perm)"
        else
            log_warn "Admin token file permissions are not ideal: ${perm:-unknown}"
            log_warn "Expected: -rw------- root:root"
        fi
    else
        log_error "Admin token file missing or empty: $ADMIN_TOKEN_FILE"
        checks_failed=$((checks_failed + 1))
    fi

    if systemctl is-active --quiet hpn-server; then
        local main_pid
        main_pid=$(systemctl show -p MainPID --value hpn-server)
        if [ -n "$main_pid" ] && [ "$main_pid" -gt 0 ] 2>/dev/null; then
            local proc_user
            proc_user=$(ps -o user= -p "$main_pid" 2>/dev/null | xargs)
            if [ -n "$proc_user" ] && [ "$proc_user" != "root" ]; then
                log_success "hpn-server process runs as non-root user: $proc_user"
            else
                log_error "hpn-server process is running as root"
                checks_failed=$((checks_failed + 1))
            fi
        else
            log_warn "Unable to determine hpn-server MainPID"
        fi
    else
        log_warn "hpn-server is not running yet; start it to verify runtime user"
    fi

    if [ "$checks_failed" -eq 0 ]; then
        log_success "Post-install security checks passed"
        return 0
    fi

    log_error "Post-install security checks failed: $checks_failed"
    return 1
}

#------------------------------------------------------------------------------
# Systemd service setup
#------------------------------------------------------------------------------

install_systemd_server() {
    log_info "Installing systemd service for HPN server..."

    cat > /etc/systemd/system/hpn-server.service << EOF
[Unit]
Description=HPN Post-Quantum VPN Server
After=network-online.target hpn-firewall.service
Wants=network-online.target
Requires=hpn-firewall.service
Documentation=https://hpn.hmsx.io/docs

[Service]
Type=simple
User=${HPN_USER}
Group=${HPN_GROUP}
ExecStart=${HPN_DIR}/bin/hpn-server --config ${HPN_CONFIG_DIR}/server.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
TimeoutStopSec=30

# Security hardening
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${HPN_LOG_DIR} ${HPN_DATA_DIR} /dev/net/tun

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hpn-server

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload

    # Configure journald limits for HPN (prevent disk fill from log storms)
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/hpn.conf << JEOF
[Journal]
SystemMaxUse=500M
RateLimitIntervalSec=30s
RateLimitBurst=10000
JEOF
    systemctl restart systemd-journald 2>/dev/null || true

    log_success "Systemd service installed: hpn-server.service"
}

install_systemd_relay() {
    log_info "Installing systemd service for HPN relay..."

    cat > /etc/systemd/system/hpn-relay.service << EOF
[Unit]
Description=HPN Post-Quantum VPN Relay
After=network-online.target
Wants=network-online.target
Documentation=https://hpn.hmsx.io/docs

[Service]
Type=simple
User=${HPN_USER}
Group=${HPN_GROUP}
ExecStart=${HPN_DIR}/bin/hpn-relay run --config ${HPN_CONFIG_DIR}/relay.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
TimeoutStopSec=30

# Security hardening (relay doesn't need TUN)
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${HPN_LOG_DIR} ${HPN_DATA_DIR}

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hpn-relay

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service installed: hpn-relay.service"
}

#------------------------------------------------------------------------------
# Kernel tuning
#------------------------------------------------------------------------------

tune_kernel() {
    log_info "Tuning kernel parameters for VPN performance..."

    local sysctl_file="/etc/sysctl.d/99-hpn-vpn.conf"

    cat > "$sysctl_file" << EOF
# HPN VPN Kernel Tuning
# Generated by install.sh on $(date)

# Enable IP forwarding (required for VPN server)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Increase UDP buffer sizes for high throughput (256MB for 10Gbps+)
net.core.rmem_default = 33554432
net.core.rmem_max = 268435456
net.core.wmem_default = 33554432
net.core.wmem_max = 268435456
net.core.netdev_max_backlog = 262144
net.core.netdev_budget = 3000
net.core.netdev_budget_usecs = 20000
net.core.optmem_max = 25165824

# UDP memory tuning (high throughput)
net.ipv4.udp_mem = 16777216 33554432 67108864
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# Busy polling (reduce latency)
net.core.busy_poll = 50
net.core.busy_read = 50

# GRO batch size (Generic Receive Offload)
net.core.gro_normal_batch = 8

# Conntrack tuning (high session count - 2M connections)
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# TCP optimizations (for admin API/metrics)
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# Increase ARP cache size
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384
EOF

    # Apply sysctl settings
    sysctl -p "$sysctl_file" > /dev/null 2>&1 || {
        log_warn "Some sysctl parameters could not be applied (this is normal if conntrack module is not loaded)"
    }

    # Load conntrack module
    modprobe nf_conntrack 2>/dev/null || true

    log_success "Kernel parameters tuned"
}

#------------------------------------------------------------------------------
# Firewall configuration
#------------------------------------------------------------------------------

configure_firewall_server() {
    log_info "Configuring firewall for HPN server..."

    local default_iface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$default_iface" ]; then
        default_iface="eth0"
    fi

    # Disable UFW if enabled (it conflicts with direct iptables rules)
    if command -v ufw &> /dev/null; then
        if ufw status | grep -q "Status: active"; then
            log_warn "UFW is active - disabling to use iptables directly"
            ufw disable
        fi
    fi

    # Stop firewalld if running (it also conflicts)
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        log_warn "firewalld is active - stopping and disabling"
        systemctl stop firewalld
        systemctl disable firewalld
    fi

    # Create comprehensive firewall script
    cat > "$HPN_DIR/bin/hpn-firewall.sh" << 'FIREWALL_EOF'
#!/bin/bash
# HPN VPN Firewall Rules
# Generated by install.sh
# This script manages iptables rules for HPN VPN server

set -e

# Configuration - these are set during install
IFACE="__DEFAULT_IFACE__"
VPN_PORT="__VPN_PORT__"
VPN_SUBNET="10.99.0.0/24"
VPN_SUBNET_V6="fd00:99::/64"
TUN_IFACE="hpn0"

# Check if rule already exists
rule_exists() {
    iptables -C "$@" 2>/dev/null
}

rule_exists_nat() {
    iptables -t nat -C "$@" 2>/dev/null
}

rule_exists_v6() {
    ip6tables -C "$@" 2>/dev/null
}

rule_exists_nat_v6() {
    ip6tables -t nat -C "$@" 2>/dev/null
}

start_firewall() {
    echo "Applying HPN VPN firewall rules..."

    # ========================================
    # IPv4 Rules
    # ========================================

    # 1. Enable IP forwarding (redundant with sysctl but ensures it's on)
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # 2. Allow VPN UDP port (if not already allowed)
    if ! rule_exists INPUT -p udp --dport $VPN_PORT -j ACCEPT; then
        iptables -A INPUT -p udp --dport $VPN_PORT -j ACCEPT
        echo "  Added: INPUT allow UDP $VPN_PORT"
    fi

    # 3. Allow all traffic on TUN interface
    if ! rule_exists INPUT -i $TUN_IFACE -j ACCEPT; then
        iptables -A INPUT -i $TUN_IFACE -j ACCEPT
        echo "  Added: INPUT allow from $TUN_IFACE"
    fi

    # 4. FORWARD rules - critical for routing VPN traffic to internet
    # Allow forwarding FROM VPN subnet (outgoing traffic)
    if ! rule_exists FORWARD -s $VPN_SUBNET -i $TUN_IFACE -j ACCEPT; then
        iptables -A FORWARD -s $VPN_SUBNET -i $TUN_IFACE -j ACCEPT
        echo "  Added: FORWARD allow from $VPN_SUBNET via $TUN_IFACE"
    fi

    # Allow forwarding TO VPN subnet (return traffic)
    if ! rule_exists FORWARD -d $VPN_SUBNET -o $TUN_IFACE -j ACCEPT; then
        iptables -A FORWARD -d $VPN_SUBNET -o $TUN_IFACE -j ACCEPT
        echo "  Added: FORWARD allow to $VPN_SUBNET via $TUN_IFACE"
    fi

    # Allow established/related connections (for return traffic)
    if ! rule_exists FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT; then
        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        echo "  Added: FORWARD allow ESTABLISHED,RELATED"
    fi

    # 5. NAT/Masquerade - translate VPN client IPs to server's public IP
    # Use a single rule that masquerades traffic going out any interface except the VPN tunnel
    # This handles single-NIC and multi-NIC servers correctly
    if ! rule_exists_nat POSTROUTING -s $VPN_SUBNET ! -o $TUN_IFACE -j MASQUERADE; then
        iptables -t nat -A POSTROUTING -s $VPN_SUBNET ! -o $TUN_IFACE -j MASQUERADE
        echo "  Added: NAT MASQUERADE for $VPN_SUBNET (any outgoing except $TUN_IFACE)"
    fi

    # ========================================
    # IPv6 Rules (if kernel supports it)
    # ========================================
    if [ -f /proc/sys/net/ipv6/conf/all/forwarding ]; then
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

        # Allow VPN UDP port IPv6
        if ! rule_exists_v6 INPUT -p udp --dport $VPN_PORT -j ACCEPT; then
            ip6tables -A INPUT -p udp --dport $VPN_PORT -j ACCEPT 2>/dev/null || true
        fi

        # FORWARD rules for IPv6 VPN subnet
        if ! rule_exists_v6 FORWARD -s $VPN_SUBNET_V6 -i $TUN_IFACE -j ACCEPT; then
            ip6tables -A FORWARD -s $VPN_SUBNET_V6 -i $TUN_IFACE -j ACCEPT 2>/dev/null || true
        fi

        if ! rule_exists_v6 FORWARD -d $VPN_SUBNET_V6 -o $TUN_IFACE -j ACCEPT; then
            ip6tables -A FORWARD -d $VPN_SUBNET_V6 -o $TUN_IFACE -j ACCEPT 2>/dev/null || true
        fi

        # NAT66 for IPv6
        if ! rule_exists_nat_v6 POSTROUTING -s $VPN_SUBNET_V6 ! -o $TUN_IFACE -j MASQUERADE; then
            ip6tables -t nat -A POSTROUTING -s $VPN_SUBNET_V6 ! -o $TUN_IFACE -j MASQUERADE 2>/dev/null || true
        fi
    fi

    echo "HPN firewall rules applied successfully"
}

stop_firewall() {
    echo "Removing HPN VPN firewall rules..."

    # Remove IPv4 rules (best effort, ignore errors)
    iptables -D INPUT -p udp --dport $VPN_PORT -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -i $TUN_IFACE -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -s $VPN_SUBNET -i $TUN_IFACE -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -d $VPN_SUBNET -o $TUN_IFACE -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s $VPN_SUBNET ! -o $TUN_IFACE -j MASQUERADE 2>/dev/null || true

    # Remove IPv6 rules
    ip6tables -D INPUT -p udp --dport $VPN_PORT -j ACCEPT 2>/dev/null || true
    ip6tables -D FORWARD -s $VPN_SUBNET_V6 -i $TUN_IFACE -j ACCEPT 2>/dev/null || true
    ip6tables -D FORWARD -d $VPN_SUBNET_V6 -o $TUN_IFACE -j ACCEPT 2>/dev/null || true
    ip6tables -t nat -D POSTROUTING -s $VPN_SUBNET_V6 ! -o $TUN_IFACE -j MASQUERADE 2>/dev/null || true

    echo "HPN firewall rules removed"
}

status_firewall() {
    echo "=== IPv4 INPUT rules ==="
    iptables -L INPUT -n -v | grep -E "(udp dpt:$VPN_PORT|$TUN_IFACE)" || echo "  (no HPN rules)"
    echo ""
    echo "=== IPv4 FORWARD rules ==="
    iptables -L FORWARD -n -v | grep -E "($VPN_SUBNET|$TUN_IFACE)" || echo "  (no HPN rules)"
    echo ""
    echo "=== IPv4 NAT POSTROUTING ==="
    iptables -t nat -L POSTROUTING -n -v | grep -E "$VPN_SUBNET" || echo "  (no HPN rules)"
    echo ""
    echo "=== IP Forwarding ==="
    echo "  IPv4: $(cat /proc/sys/net/ipv4/ip_forward)"
    [ -f /proc/sys/net/ipv6/conf/all/forwarding ] && echo "  IPv6: $(cat /proc/sys/net/ipv6/conf/all/forwarding)"
}

case "${1:-start}" in
    start)
        start_firewall
        ;;
    stop)
        stop_firewall
        ;;
    restart)
        stop_firewall
        sleep 1
        start_firewall
        ;;
    status)
        status_firewall
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
FIREWALL_EOF

    # Replace placeholders with actual values
    sed -i "s|__DEFAULT_IFACE__|${default_iface}|g" "$HPN_DIR/bin/hpn-firewall.sh"
    sed -i "s|__VPN_PORT__|${SERVER_PORT}|g" "$HPN_DIR/bin/hpn-firewall.sh"

    chmod +x "$HPN_DIR/bin/hpn-firewall.sh"

    # Create systemd service for firewall rules (runs before hpn-server)
    cat > /etc/systemd/system/hpn-firewall.service << EOF
[Unit]
Description=HPN VPN Firewall Rules
Before=hpn-server.service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${HPN_DIR}/bin/hpn-firewall.sh start
ExecStop=${HPN_DIR}/bin/hpn-firewall.sh stop
ExecReload=${HPN_DIR}/bin/hpn-firewall.sh restart

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable hpn-firewall.service

    # Apply firewall rules now
    "$HPN_DIR/bin/hpn-firewall.sh" start || log_warn "Could not apply firewall rules"

    log_success "Firewall configured (systemd service: hpn-firewall.service)"
}

configure_firewall_relay() {
    log_info "Configuring firewall for HPN relay..."

    # Simple rule: just allow the relay port
    iptables -A INPUT -p udp --dport "$RELAY_PORT" -j ACCEPT 2>/dev/null || {
        log_warn "Could not add firewall rule for relay port"
    }

    log_success "Firewall configured for relay"
}

#------------------------------------------------------------------------------
# Persistence for firewall rules
#------------------------------------------------------------------------------

persist_firewall() {
    log_info "Persisting firewall rules..."

    case $DISTRO in
        ubuntu|debian)
            if command -v netfilter-persistent &> /dev/null; then
                netfilter-persistent save
            elif [ -d /etc/iptables ]; then
                iptables-save > /etc/iptables/rules.v4
                ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
            fi
            ;;
        centos|rhel|fedora|rocky|alma)
            if command -v firewall-cmd &> /dev/null; then
                firewall-cmd --permanent --add-port=${SERVER_PORT}/udp 2>/dev/null || true
                firewall-cmd --permanent --add-port=${RELAY_PORT}/udp 2>/dev/null || true
                firewall-cmd --reload 2>/dev/null || true
            else
                iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            fi
            ;;
    esac

    log_success "Firewall rules persisted"
}

#------------------------------------------------------------------------------
# TUN device setup
#------------------------------------------------------------------------------

setup_tun() {
    log_info "Setting up TUN device..."

    # Ensure TUN module is loaded
    modprobe tun 2>/dev/null || true

    # Create /dev/net/tun if it doesn't exist
    if [ ! -c /dev/net/tun ]; then
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200
        chown root:"$HPN_GROUP" /dev/net/tun
        chmod 0660 /dev/net/tun
    fi

    # Ensure TUN is loaded on boot
    if [ ! -f /etc/modules-load.d/tun.conf ]; then
        echo "tun" > /etc/modules-load.d/tun.conf
    fi

    log_success "TUN device configured"
}

#------------------------------------------------------------------------------
# Main installation flow
#------------------------------------------------------------------------------

print_banner() {
    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}        ${GREEN}HPN Post-Quantum VPN - Deployment Script${NC}          ${BLUE}║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_usage() {
    echo "Usage: $0 [server|relay|both]"
    echo ""
    echo "Options:"
    echo "  server  - Install HPN VPN server"
    echo "  relay   - Install HPN VPN relay"
    echo "  both    - Install both server and relay"
    echo ""
    echo "Examples:"
    echo "  $0 server   # Install VPN server"
    echo "  $0 relay    # Install relay node"
    echo ""
}

install_server() {
    log_info "Installing HPN VPN Server..."
    echo ""

    install_dependencies
    create_user
    create_directories
    install_binaries server
    configure_server
    generate_server_keys
    install_systemd_server
    tune_kernel
    setup_tun
    configure_firewall_server
    persist_firewall
    verify_server_hardening || true

    echo ""
    log_success "HPN VPN Server installation complete!"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo -e "  1. Edit configuration: ${BLUE}nano $HPN_CONFIG_DIR/server.toml${NC}"
    echo -e "  2. Start the service: ${BLUE}systemctl start hpn-server${NC}"
    echo -e "  3. Enable on boot: ${BLUE}systemctl enable hpn-server${NC}"
    echo -e "  4. Check status: ${BLUE}systemctl status hpn-server${NC}"
    echo -e "  5. View logs: ${BLUE}journalctl -u hpn-server -f${NC}"
    echo -e "  6. Documentation: ${BLUE}https://hpn.hmsx.io/docs${NC}"
    echo ""
    echo -e "${YELLOW}Firewall:${NC}"
    echo -e "  UDP port ${SERVER_PORT} has been opened"
    echo -e "  NAT/Masquerade is configured for VPN clients"
    echo ""
}

install_relay() {
    log_info "Installing HPN VPN Relay..."
    echo ""

    install_dependencies
    create_user
    create_directories
    install_binaries relay
    configure_relay
    install_systemd_relay
    tune_kernel
    configure_firewall_relay
    persist_firewall

    echo ""
    log_success "HPN VPN Relay installation complete!"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo -e "  1. Edit configuration: ${BLUE}nano $HPN_CONFIG_DIR/relay.toml${NC}"
    echo -e "  2. Set upstream_addr to your VPN server IP"
    echo -e "  3. Start the service: ${BLUE}systemctl start hpn-relay${NC}"
    echo -e "  4. Enable on boot: ${BLUE}systemctl enable hpn-relay${NC}"
    echo -e "  5. Check status: ${BLUE}systemctl status hpn-relay${NC}"
    echo -e "  6. View logs: ${BLUE}journalctl -u hpn-relay -f${NC}"
    echo -e "  7. Documentation: ${BLUE}https://hpn.hmsx.io/docs${NC}"
    echo ""
}

main() {
    print_banner
    check_root
    detect_distro

    local mode="${1:-}"

    case "$mode" in
        server)
            install_server
            ;;
        relay)
            install_relay
            ;;
        both)
            install_server
            echo ""
            echo "---"
            echo ""
            install_relay
            ;;
        -h|--help|help)
            print_usage
            exit 0
            ;;
        *)
            print_usage
            exit 1
            ;;
    esac
}

# Run main
main "$@"
