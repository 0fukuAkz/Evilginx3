#!/bin/bash

#############################################################################
# Evilginx - Private Dev Edition - One-Click Installer
#############################################################################
# This script automates the complete installation and configuration process
# Based on: DEPLOYMENT.md
#
# Supports: Ubuntu 20.04/22.04/24.04, Debian 11/12
# Architectures: amd64, arm64
#
# What this script does:
#
#   System Preparation
#   - Validates OS (Ubuntu 20.04/22.04/24.04, Debian 11/12) with version check
#   - Repairs interrupted dpkg and waits for apt/dpkg locks (VPS-safe)
#   - Updates apt package lists
#   - Installs system dependencies: curl, wget, git, vim, ufw, fail2ban, htop,
#     net-tools, build-essential, ca-certificates, gnupg, lsb-release, tar,
#     gzip, openssl, screen, tmux, dnsutils, libsqlite3-dev, iptables
#
#   Go Runtime
#   - Downloads and installs Go 1.25.1 (amd64/arm64) from go.dev
#   - Verifies download integrity (size check + SHA256 against go.dev)
#   - Adds Go to system PATH via /etc/profile.d/golang.sh
#
#   Users & Directories
#   - Creates dedicated least-privilege service user: evilginx (no login shell)
#   - Creates /opt/evilginx, /etc/evilginx, /var/log/evilginx
#   - Optionally creates an admin user with SSH key and sudo access
#
#   Conflicting Services
#   - Stops and disables: apache2, nginx, bind9, named, systemd-resolved
#   - Frees port 53 by masking systemd-resolved
#   - Writes static /etc/resolv.conf (Google + Cloudflare DNS)
#   - Ensures hostname is resolvable in /etc/hosts
#
#   Build & Install
#   - Builds Evilginx from source using CGO_ENABLED=1 (required for go-sqlite3)
#   - Installs binary to /opt/evilginx/evilginx.bin
#   - Installs phishlets    → /opt/evilginx/phishlets/
#   - Installs redirectors  → /opt/evilginx/redirectors/
#   - Installs post-redirectors → /opt/evilginx/post_redirectors/
#   - Installs web UI       → /opt/evilginx/web/
#   - Installs GoPhish static files + GeoIP DB → /opt/evilginx/static/
#   - Creates system-wide wrapper at /usr/local/bin/evilginx (auto-loads paths)
#   - Copies documentation: README, DEPLOYMENT, DOMAIN-ROTATION-GUIDE, LICENSE,
#     cloudflare-workers-deployment.md
#   - Sets CAP_NET_BIND_SERVICE capability (bind ports 53/80/443 without root)
#
#   Firewall (UFW)
#   - Preserves existing rules (safe for cloud instances)
#   - Opens: 22/tcp (SSH), 53/tcp+udp (DNS), 80/tcp (HTTP),
#            443/tcp (HTTPS), 2030/tcp (Admin API), 3333/tcp (GoPhish Admin)
#
#   Fail2Ban
#   - Configures SSH brute-force protection (jail.d/sshd.conf)
#   - Supports systemd backend for Debian 12+ / Ubuntu 24+ (no auth.log)
#
#   Systemd Service
#   - Creates /etc/systemd/system/evilginx.service
#   - Runs as dedicated service user with hardened sandbox
#     (PrivateTmp, ProtectSystem=strict, NoNewPrivileges)
#   - Enables auto-start on boot
#
#   Helper Scripts (installed to /usr/local/bin/)
#   - evilginx-start    : start the systemd service
#   - evilginx-stop     : stop the systemd service
#   - evilginx-restart  : restart the systemd service
#   - evilginx-status   : show service status
#   - evilginx-logs     : tail live journal logs
#   - evilginx-console  : stop service and run Evilginx interactively
#
#   Cloudflare Tunnel (optional — prompted at end of install)
#   - Installs cloudflared via .deb package
#   - Authenticates with Cloudflare (browser login flow)
#   - Creates named tunnel: evilginx-panels
#   - Exposes admin.DOMAIN  → localhost:2030 (Web Admin API)
#   - Exposes gophish.DOMAIN → localhost:3333 (GoPhish Admin)
#   - Creates DNS CNAME records automatically
#   - Installs cloudflared as a systemd service (auto-starts on boot)
#   - Domain configurable via TUNNEL_DOMAIN env var or interactive prompt
#
# Usage:
#   sudo ./install.sh                                    # Full installation
#   sudo ./install.sh --upgrade                          # Rebuild + reinstall only
#   sudo ./install.sh --uninstall                        # Remove Evilginx
#   sudo ./install.sh --tunnel                           # Cloudflare Tunnel setup only
#   sudo ./install.sh --dry-run                          # Show what would be done
#   ./install.sh --help                                  # Show usage
#
#   TUNNEL_DOMAIN=example.com sudo ./install.sh          # Pre-set tunnel domain
#   TUNNEL_DOMAIN=example.com sudo ./install.sh --tunnel # Tunnel only, no prompt
#
# Author: AKaZA (Akz0fuku)
# Version: 3.5.4
#############################################################################

set -euo pipefail  # Exit on error, undefined vars, pipe failures
trap 'log_error "Installation failed at line $LINENO (exit code $?)"; exit 1' ERR

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

#############################################################################
# Helper Functions (defined early so they are available during setup)
#############################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_step() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}▶ $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}\n"
}

#############################################################################
# Script Directory & Configuration
#############################################################################

# Get script directory - handle both direct execution and sudo execution
if [[ -n "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_PATH="${BASH_SOURCE[0]}"
else
    SCRIPT_PATH="$0"
fi

# Resolve to absolute path
if [[ "$SCRIPT_PATH" = /* ]]; then
    # Already absolute
    SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
else
    # Relative path - resolve it
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
fi

# Final fallback: if still empty or doesn't exist, use current directory
if [[ -z "$SCRIPT_DIR" ]] || [[ ! -d "$SCRIPT_DIR" ]]; then
    SCRIPT_DIR="$(pwd)"
fi

# Configuration
EVILGINX_VERSION="3.5.4"
GO_VERSION="1.25.1"
INSTALL_DIR="/usr/local/bin"
INSTALL_BASE="/opt/evilginx"
SERVICE_USER="evilginx"  # Dedicated service user (least-privilege)
CONFIG_DIR="/etc/evilginx"
LOG_DIR="/var/log/evilginx"
PHISHLETS_DIR="$INSTALL_BASE/phishlets"
REDIRECTORS_DIR="$INSTALL_BASE/redirectors"
POST_REDIRECTORS_DIR="$INSTALL_BASE/post_redirectors"
INSTALL_LOG=""

# Cloudflare Tunnel configuration (optional) — edit or pass as env vars
# Set CF_TUNNEL_DOMAIN before running, or you will be prompted interactively.
CF_TUNNEL_DOMAIN="${TUNNEL_DOMAIN:-YOUR_DOMAIN_HERE}"  # e.g. example.com
CF_TUNNEL_NAME="${CF_TUNNEL_NAME:-evilginx-panels}"
CF_TUNNEL_ADMIN_SUB="${CF_TUNNEL_ADMIN_SUB:-admin}"     # admin.<domain> → port 2030
CF_TUNNEL_GOPHISH_SUB="${CF_TUNNEL_GOPHISH_SUB:-gophish}" # gophish.<domain> → port 3333

# Tunnel state — populated by setup_cloudflare_tunnel(), read by display_completion()
TUNNEL_CONFIGURED=false
TUNNEL_ADMIN_URL=""
TUNNEL_GOPHISH_URL=""

# Detect architecture early (log_warning is now defined above)
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
case "$ARCH" in
    amd64|x86_64) GO_ARCH="amd64" ;;
    arm64|aarch64) GO_ARCH="arm64" ;;
    armhf|armv7l)  GO_ARCH="armv6l" ;;
    *)             GO_ARCH="amd64"; log_warning "Unknown arch '$ARCH', defaulting to amd64" ;;
esac

# Prevent ALL interactive prompts from apt/dpkg/needrestart globally
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1
# Keep existing config files without prompting (e.g. sshd_config on Ubuntu 22.04)
APT_OPTS=(-o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef")

# Distro-specific variables (set by detect_os)
DISTRO_ID=""
DISTRO_VER=""

#############################################################################
# Utility Functions
#############################################################################

# Repair interrupted dpkg and wait for apt/dpkg locks (common on fresh VPS)
wait_for_apt_lock() {
    # Fix interrupted dpkg first — this is the #1 cause of apt failures on VPS
    # (unattended-upgrades crashes or gets killed mid-run on first boot)
    if dpkg --audit 2>&1 | grep -q .; then
        log_warning "dpkg was interrupted — running automatic repair..."
        dpkg --configure -a --force-confold --force-confdef
        log_success "dpkg repaired"
    fi

    local max_wait=120  # seconds
    local waited=0

    # Check for apt/dpkg locks (fuser may not exist on minimal systems)
    while { command -v fuser &>/dev/null && fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock &>/dev/null; } || \
          { [[ -f /var/lib/dpkg/lock-frontend ]] && ! apt-get check &>/dev/null; }; do
        if [[ $waited -eq 0 ]]; then
            log_warning "Waiting for apt/dpkg lock (another process is using apt)..."
            log_info "This is normal on fresh VPS — unattended-upgrades runs on first boot"
        fi
        sleep 5
        waited=$((waited + 5))
        if [[ $waited -ge $max_wait ]]; then
            log_error "apt lock not released after ${max_wait}s"
            log_info "Try: sudo kill \$(sudo lsof -t /var/lib/dpkg/lock-frontend) && sudo dpkg --configure -a"
            exit 1
        fi
    done

    if [[ $waited -gt 0 ]]; then
        log_success "apt lock released after ${waited}s"
    fi
}

# Consolidated function to find the Evilginx root directory
# Replaces duplicate search logic that was in both main() and build_evilginx()
find_evilginx_root() {
    local search_dirs=("$SCRIPT_DIR" "$(pwd)" "${HOME:-/root}/Evilginx3" "/root/Evilginx3")
    for dir in "${search_dirs[@]}"; do
        if [[ -n "$dir" ]] && [[ -d "$dir" ]] && [[ -f "$dir/main.go" ]]; then
            echo "$dir"
            return 0
        fi
    done
    return 1
}

print_banner() {
    echo -e "${PURPLE}"
    cat << EOF
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     ███████╗██╗   ██╗██╗██╗      ██████╗ ██╗███╗   ██╗██╗  ██╗  ║
║     ██╔════╝██║   ██║██║██║     ██╔════╝ ██║████╗  ██║╚██╗██╔╝  ║
║     █████╗  ██║   ██║██║██║     ██║  ███╗██║██╔██╗ ██║ ╚███╔╝   ║
║     ██╔══╝  ╚██╗ ██╔╝██║██║     ██║   ██║██║██║╚██╗██║ ██╔██╗   ║
║     ███████╗ ╚████╔╝ ██║███████╗╚██████╔╝██║██║ ╚████║██╔╝ ██╗  ║
║     ╚══════╝  ╚═══╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝  ║
║                                                                   ║
║              One-Click Installer - Private Dev Edition           ║
║                         Version ${EVILGINX_VERSION}                             ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root!"
        log_info "Please run: sudo $0"
        exit 1
    fi
    log_success "Running as root"
}

ensure_git() {
    if ! command -v git &>/dev/null; then
        log_info "Installing git (required)..."
        wait_for_apt_lock
        apt-get update -qq && apt-get install -y -qq "${APT_OPTS[@]}" git
        log_success "git installed"
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        DISTRO_ID="$ID"
        DISTRO_VER="$VER"
        log_info "Detected OS: $OS $VER ($ARCH)"

        # Supported: Ubuntu 20.04 / 22.04 / 24.04  and  Debian 11 / 12
        case "$ID" in
            ubuntu)
                case "$VERSION_ID" in
                    20.04|22.04|24.04)
                        log_success "Supported Ubuntu version: $VERSION_ID"
                        ;;
                    *)
                        log_warning "Ubuntu $VERSION_ID is not officially supported (tested: 20.04, 22.04, 24.04)"
                        read -p "Continue anyway? (y/N): " -n 1 -r < /dev/tty
                        echo
                        [[ $REPLY =~ ^[Yy]$ ]] || exit 1
                        ;;
                esac
                # Suppress needrestart interactive prompts (22.04+)
                export NEEDRESTART_MODE=a
                export NEEDRESTART_SUSPEND=1
                ;;
            debian)
                case "$VERSION_ID" in
                    11|12)
                        log_success "Supported Debian version: $VERSION_ID"
                        ;;
                    *)
                        log_warning "Debian $VERSION_ID is not officially supported (tested: 11, 12)"
                        read -p "Continue anyway? (y/N): " -n 1 -r < /dev/tty
                        echo
                        [[ $REPLY =~ ^[Yy]$ ]] || exit 1
                        ;;
                esac
                ;;
            *)
                log_error "Unsupported OS: $ID"
                log_error "This installer requires Ubuntu (20.04/22.04/24.04) or Debian (11/12)"
                log_warning "Detected: $NAME $VERSION_ID"
                read -p "Attempt installation anyway? Expect failures. (y/N): " -n 1 -r < /dev/tty
                echo
                [[ $REPLY =~ ^[Yy]$ ]] || exit 1
                ;;
        esac
    else
        log_error "Cannot detect OS: /etc/os-release not found"
        log_error "This installer requires Ubuntu (20.04/22.04/24.04) or Debian (11/12)"
        exit 1
    fi
}

confirm_installation() {
    echo -e "${YELLOW}"
    cat << EOF

WARNING: This installer will make significant system changes:

   1. Install Go $GO_VERSION ($GO_ARCH) and dependencies
   2. Stop and disable Apache2/Nginx (if installed)
   3. Configure UFW firewall (ports 22, 53, 80, 443)
   4. Create directories with admin privileges
   5. Install Evilginx to: $INSTALL_DIR
   6. Create systemd service: evilginx.service
   7. Enable automatic startup
   8. (Optional) Set up Cloudflare Tunnel for admin panels

LEGAL NOTICE:
   This tool is for AUTHORIZED SECURITY TESTING ONLY.
   Unauthorized use is ILLEGAL and UNETHICAL.
   You are responsible for compliance with all applicable laws.

EOF
    echo -e "${NC}"
    
    read -p "Do you have WRITTEN AUTHORIZATION to deploy this tool? (yes/NO): " -r < /dev/tty
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_error "Installation cancelled. Authorization required."
        exit 1
    fi

    read -p "Proceed with installation? (yes/NO): " -r < /dev/tty
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_error "Installation cancelled by user"
        exit 1
    fi
}

# Pre-flight connectivity and resource checks
preflight_check() {
    log_step "Pre-flight Checks"

    # Test internet connectivity (use wget or curl — one of them should exist)
    local connectivity_ok=false
    if command -v curl &>/dev/null; then
        curl -s --max-time 10 https://go.dev > /dev/null 2>&1 && connectivity_ok=true
    elif command -v wget &>/dev/null; then
        wget -q --timeout=10 --spider https://go.dev 2>/dev/null && connectivity_ok=true
    else
        # Neither curl nor wget — try a basic TCP connection via bash
        if (echo > /dev/tcp/go.dev/443) 2>/dev/null; then
            connectivity_ok=true
        fi
    fi

    if [[ "$connectivity_ok" == true ]]; then
        log_success "Internet connectivity OK (go.dev reachable)"
    else
        log_error "Cannot reach go.dev — check internet connectivity"
        log_error "Go download will fail without internet access"
        exit 1
    fi

    # Test DNS resolution
    if command -v host &>/dev/null; then
        if ! host go.dev > /dev/null 2>&1; then
            log_warning "DNS resolution may be impaired — installation may have issues"
        else
            log_success "DNS resolution OK"
        fi
    elif command -v nslookup &>/dev/null; then
        if ! nslookup go.dev > /dev/null 2>&1; then
            log_warning "DNS resolution may be impaired — installation may have issues"
        else
            log_success "DNS resolution OK"
        fi
    fi

    # Check disk space (need at least 2GB free)
    local free_space_mb
    free_space_mb=$(df / --output=avail -BM 2>/dev/null | tail -1 | tr -d 'M ' || echo "0")
    if [[ "$free_space_mb" -lt 2048 ]]; then
        log_warning "Low disk space: ${free_space_mb}MB free (recommended: 2048MB+)"
    else
        log_success "Disk space OK (${free_space_mb}MB free)"
    fi
}

#############################################################################
# Uninstall Function
#############################################################################

uninstall_evilginx() {
    log_step "Uninstalling Evilginx"
    
    # Stop and disable service
    if systemctl is-active --quiet evilginx 2>/dev/null; then
        log_info "Stopping Evilginx service..."
        systemctl stop evilginx
        log_success "Service stopped"
    fi
    
    if systemctl is-enabled --quiet evilginx 2>/dev/null; then
        log_info "Disabling Evilginx service..."
        systemctl disable evilginx
        log_success "Service disabled"
    fi
    
    # Kill any running processes (graceful first, then force)
    if pgrep -x evilginx >/dev/null 2>&1; then
        log_info "Sending SIGTERM to Evilginx processes..."
        pkill -x evilginx 2>/dev/null || true
        sleep 3
        if pgrep -x evilginx >/dev/null 2>&1; then
            log_warning "Processes still running, sending SIGKILL..."
            pkill -9 -x evilginx 2>/dev/null || true
            sleep 1
        fi
        log_success "Processes terminated"
    fi
    
    # Remove service file
    if [ -f /etc/systemd/system/evilginx.service ]; then
        log_info "Removing systemd service file..."
        rm -f /etc/systemd/system/evilginx.service
        systemctl daemon-reload
        log_success "Service file removed"
    fi
    
    # Remove installation directory
    if [ -d "$INSTALL_BASE" ]; then
        log_info "Removing $INSTALL_BASE..."
        rm -rf "$INSTALL_BASE"
        log_success "Installation directory removed"
    fi
    
    # Remove wrapper and helper scripts
    log_info "Removing scripts from /usr/local/bin/..."
    rm -f /usr/local/bin/evilginx
    rm -f /usr/local/bin/evilginx-start
    rm -f /usr/local/bin/evilginx-stop
    rm -f /usr/local/bin/evilginx-restart
    rm -f /usr/local/bin/evilginx-status
    rm -f /usr/local/bin/evilginx-logs
    rm -f /usr/local/bin/evilginx-console
    log_success "Scripts removed"
    
    # Remove config directory (prompt user)
    if [ -d "$CONFIG_DIR" ]; then
        read -p "Remove configuration directory $CONFIG_DIR? This includes certs and DB. (y/N): " -n 1 -r < /dev/tty
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$CONFIG_DIR"
            log_success "Configuration directory removed"
        else
            log_info "Configuration directory preserved"
        fi
    fi
    
    # Remove log directory
    if [ -d "$LOG_DIR" ]; then
        rm -rf "$LOG_DIR"
        log_success "Log directory removed"
    fi
    
    # Remove Go PATH drop-in (if created by us)
    if [ -f /etc/profile.d/golang.sh ]; then
        read -p "Remove Go PATH configuration (/etc/profile.d/golang.sh)? (y/N): " -n 1 -r < /dev/tty
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -f /etc/profile.d/golang.sh
            log_success "Go PATH drop-in removed"
        else
            log_info "Go PATH drop-in preserved"
        fi
    fi

    # Optionally remove Cloudflare Tunnel
    if command -v cloudflared &>/dev/null || [ -d /etc/cloudflared ]; then
        read -p "Remove Cloudflare Tunnel (cloudflared service + config)? (y/N): " -n 1 -r < /dev/tty
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            systemctl stop cloudflared 2>/dev/null || true
            systemctl disable cloudflared 2>/dev/null || true
            cloudflared service uninstall 2>/dev/null || true
            rm -rf /etc/cloudflared
            log_success "Cloudflare Tunnel removed"
        else
            log_info "Cloudflare Tunnel preserved"
        fi
    fi

    echo ""
    log_success "Evilginx uninstalled successfully"
    echo ""
    log_info "Note: Go runtime, UFW rules, and Fail2Ban config were NOT removed"
    log_info "Note: systemd-resolved was NOT re-enabled (run 'systemctl unmask systemd-resolved' if needed)"
}

#############################################################################
# Installation Steps
#############################################################################

update_system() {
    log_step "Step 1: Updating System Packages"

    # Wait for any existing apt operations to finish (common on fresh VPS)
    wait_for_apt_lock

    # Kill needrestart if it's running (causes hangs on Ubuntu 22.04+)
    if pgrep -x needrestart &>/dev/null; then
        log_info "Stopping needrestart daemon to prevent interactive prompts..."
        killall needrestart 2>/dev/null || true
    fi

    # Disable needrestart prompts for this session if the config exists
    if [[ -d /etc/needrestart/conf.d ]]; then
        echo '$nrconf{restart} = "a";' > /etc/needrestart/conf.d/99-installer-tmp.conf
    fi

    apt-get update -qq
    log_success "Package lists updated"

    # Only update, don't upgrade — avoids kernel surprises and needrestart hangs
    log_info "Skipping full system upgrade (run 'apt upgrade' manually if desired)"
}

install_dependencies() {
    log_step "Step 2: Installing Dependencies"

    wait_for_apt_lock

    log_info "Installing essential packages..."
    apt-get install -y -qq "${APT_OPTS[@]}" \
        curl \
        wget \
        git \
        vim \
        ufw \
        fail2ban \
        htop \
        net-tools \
        build-essential \
        ca-certificates \
        gnupg \
        lsb-release \
        tar \
        gzip \
        openssl \
        screen \
        tmux \
        dnsutils \
        libsqlite3-dev

    # iptables may already be provided by nftables — install separately so failure is non-fatal
    apt-get install -y -qq "${APT_OPTS[@]}" iptables 2>/dev/null || true
    
    # iptables-persistent can conflict with nftables on newer systems
    if [[ "$DISTRO_ID" == "debian" ]] && [[ "${DISTRO_VER%%.*}" -ge 12 ]]; then
        log_info "Skipping iptables-persistent on Debian 12+ (nftables is default)"
    elif [[ "$DISTRO_ID" == "ubuntu" ]] && [[ "${DISTRO_VER%%.*}" -ge 24 ]]; then
        log_info "Skipping iptables-persistent on Ubuntu 24+ (nftables is default)"
    else
        apt-get install -y -qq "${APT_OPTS[@]}" iptables-persistent 2>/dev/null || true
    fi
    
    log_success "Essential packages installed"
}

install_go() {
    log_step "Step 3: Installing Go $GO_VERSION ($GO_ARCH)"
    
    # Remove apt-installed Go if present (Ubuntu ships old versions)
    if [[ "$DISTRO_ID" == "ubuntu" ]]; then
        if dpkg -l golang-go 2>/dev/null | grep -q '^ii'; then
            log_info "Removing apt-installed Go to avoid conflicts..."
            apt-get remove -y "${APT_OPTS[@]}" golang-go golang 2>/dev/null || true
        fi
    fi
    
    # Check if correct Go is already installed
    # Note: also check /usr/local/go/bin/go directly since sudo doesn't source /etc/profile.d/
    local GO_BIN=""
    if command -v go &> /dev/null; then
        GO_BIN="go"
    elif [[ -x /usr/local/go/bin/go ]]; then
        GO_BIN="/usr/local/go/bin/go"
    fi

    if [[ -n "$GO_BIN" ]]; then
        INSTALLED_VERSION=$($GO_BIN version | awk '{print $3}' | sed 's/go//')
        if [[ "$INSTALLED_VERSION" == "$GO_VERSION" ]]; then
            log_success "Go $GO_VERSION already installed"
            # Ensure PATH is set for current session
            export PATH=$PATH:/usr/local/go/bin
            return 0
        else
            log_info "Removing old Go version: $INSTALLED_VERSION"
        fi
    fi

    # Always clean existing Go installation before extracting to prevent overlay corruption
    if [[ -d /usr/local/go ]]; then
        log_info "Cleaning existing Go installation..."
        rm -rf /usr/local/go
    fi
    
    local GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"

    # Download and verify in a subshell to avoid changing the working directory
    (
        cd /tmp

        log_info "Downloading Go $GO_VERSION for $GO_ARCH..."
        wget -q --show-progress "https://go.dev/dl/${GO_TARBALL}"

        # Verify download integrity
        log_info "Verifying download integrity..."

        if [[ ! -f "$GO_TARBALL" ]]; then
            log_error "Go download failed — file not found!"
            exit 1
        fi

        local actual_size
        actual_size=$(stat -c%s "$GO_TARBALL" 2>/dev/null || stat -f%z "$GO_TARBALL" 2>/dev/null || echo "0")
        if [[ "$actual_size" -lt 50000000 ]]; then
            log_error "Downloaded Go tarball is too small (${actual_size} bytes, expected 50MB+)"
            log_error "Download may be corrupted or intercepted"
            rm -f "$GO_TARBALL"
            exit 1
        fi

        if ! gzip -t "$GO_TARBALL" 2>/dev/null; then
            log_error "Downloaded file is not a valid gzip archive — possibly corrupted"
            rm -f "$GO_TARBALL"
            exit 1
        fi

        log_success "Download verified (${actual_size} bytes, valid gzip)"

        # SHA256 checksum verification against go.dev
        log_info "Verifying SHA256 checksum against go.dev..."
        local expected_sha256
        expected_sha256=$(curl -sL "https://go.dev/dl/?mode=json&include=all" \
            | grep -A 5 "\"filename\": \"${GO_TARBALL}\"" \
            | grep '"sha256"' \
            | head -1 \
            | sed 's/.*"sha256": "\([a-f0-9]*\)".*/\1/')

        if [[ -n "$expected_sha256" ]]; then
            local actual_sha256
            actual_sha256=$(sha256sum "$GO_TARBALL" | awk '{print $1}')
            if [[ "$actual_sha256" != "$expected_sha256" ]]; then
                log_error "SHA256 checksum mismatch!"
                log_error "  Expected: $expected_sha256"
                log_error "  Got:      $actual_sha256"
                rm -f "$GO_TARBALL"
                exit 1
            fi
            log_success "SHA256 checksum verified"
        else
            log_warning "Could not fetch expected SHA256 from go.dev — skipping checksum verification"
            log_warning "Proceeding with size + gzip validation only"
        fi

        log_info "Extracting Go..."
        tar -C /usr/local -xzf "$GO_TARBALL"

        # Cleanup
        rm -f "$GO_TARBALL"
    )

    # Add to PATH using /etc/profile.d/ drop-in (clean, single-location approach)
    # This replaces the old method of writing to /etc/profile, /etc/environment,
    # /root/.bashrc, and $HOME/.bashrc — all of which is unnecessary
    log_info "Adding Go to system PATH via /etc/profile.d/..."

    cat > /etc/profile.d/golang.sh << 'GOEOF'
# Go language PATH configuration (managed by Evilginx installer)
export PATH=$PATH:/usr/local/go/bin
GOEOF
    chmod 644 /etc/profile.d/golang.sh

    # Export for current session
    export PATH=$PATH:/usr/local/go/bin

    log_success "Go $GO_VERSION ($GO_ARCH) installed successfully"
    log_success "Go added to PATH via /etc/profile.d/golang.sh (all users, all login shells)"
    /usr/local/go/bin/go version
}

create_service_user() {
    log_step "Creating Dedicated Service User"
    
    if id "$SERVICE_USER" &>/dev/null; then
        log_success "Service user '$SERVICE_USER' already exists"
        return 0
    fi
    
    useradd --system \
        --shell /usr/sbin/nologin \
        --home-dir "$INSTALL_BASE" \
        --no-create-home \
        --comment "Evilginx service account" \
        "$SERVICE_USER"
    
    log_success "Created service user '$SERVICE_USER' (no login shell)"
}

create_admin_user() {
    log_step "Admin User Setup (Optional)"
    
    echo ""
    log_info "You are currently logged in as root."
    log_info "It is recommended to create a separate admin user for VPS management."
    echo ""
    read -r -p "$(echo -e "${CYAN}Create an admin user for SSH/management? [y/N]: ${NC}")" CREATE_ADMIN < /dev/tty
    
    if [[ ! "$CREATE_ADMIN" =~ ^[Yy]$ ]]; then
        log_info "Skipping admin user creation (you can do this later)"
        return 0
    fi
    
    # Get username
    read -r -p "$(echo -e "${CYAN}Enter admin username [evilginx-admin]: ${NC}")" ADMIN_USER < /dev/tty
    ADMIN_USER="${ADMIN_USER:-evilginx-admin}"
    
    # Check if user already exists
    if id "$ADMIN_USER" &>/dev/null; then
        log_warning "User '$ADMIN_USER' already exists"
        # Ensure sudo group membership
        usermod -aG sudo "$ADMIN_USER" 2>/dev/null || true
        log_success "Ensured '$ADMIN_USER' is in sudo group"
        return 0
    fi
    
    # Create user with home directory and bash shell
    useradd --create-home \
        --shell /bin/bash \
        --groups sudo \
        --comment "Evilginx admin operator" \
        "$ADMIN_USER"
    
    log_success "Created admin user '$ADMIN_USER'"
    
    # SSH key setup
    echo ""
    read -r -p "$(echo -e "${CYAN}Set up SSH key authentication? [Y/n]: ${NC}")" SETUP_SSH_KEY < /dev/tty
    
    if [[ ! "$SETUP_SSH_KEY" =~ ^[Nn]$ ]]; then
        ADMIN_SSH_DIR="/home/$ADMIN_USER/.ssh"
        mkdir -p "$ADMIN_SSH_DIR"
        chmod 700 "$ADMIN_SSH_DIR"
        
        # Check if root has authorized_keys to copy
        if [[ -f /root/.ssh/authorized_keys ]] && [[ -s /root/.ssh/authorized_keys ]]; then
            cp /root/.ssh/authorized_keys "$ADMIN_SSH_DIR/authorized_keys"
            log_success "Copied root's SSH keys to $ADMIN_USER"
        else
            echo ""
            log_info "Paste your SSH public key (or press Enter to skip):"
            read -r SSH_PUB_KEY < /dev/tty
            if [[ -n "$SSH_PUB_KEY" ]]; then
                echo "$SSH_PUB_KEY" > "$ADMIN_SSH_DIR/authorized_keys"
                log_success "SSH key added"
            else
                log_warning "No SSH key added — you'll need to set a password"
            fi
        fi
        
        chmod 600 "$ADMIN_SSH_DIR/authorized_keys" 2>/dev/null || true
        chown -R "$ADMIN_USER:$ADMIN_USER" "$ADMIN_SSH_DIR"
    fi
    
    # Set password (as fallback or primary auth)
    echo ""
    read -r -p "$(echo -e "${CYAN}Set a password for '$ADMIN_USER'? [y/N]: ${NC}")" SET_PASSWD < /dev/tty
    if [[ "$SET_PASSWD" =~ ^[Yy]$ ]]; then
        passwd "$ADMIN_USER"
    fi
    
    # Offer to disable root SSH login
    echo ""
    read -r -p "$(echo -e "${CYAN}Disable root SSH login for security? [y/N]: ${NC}")" DISABLE_ROOT < /dev/tty
    if [[ "$DISABLE_ROOT" =~ ^[Yy]$ ]]; then
        sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
        log_success "Root SSH login disabled"
        log_warning "From now on, SSH in as: ssh $ADMIN_USER@$(hostname -I | awk '{print $1}')"
    fi
    
    echo ""
    log_success "Admin user '$ADMIN_USER' is ready"
    log_info "Login: ssh $ADMIN_USER@$(hostname -I | awk '{print $1}')"
    log_info "Use 'sudo' for privileged operations"
}

setup_directories() {
    log_step "Step 4: Creating Directories"
    
    # Create necessary directories
    mkdir -p "$INSTALL_BASE"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    
    # Set ownership to dedicated service user
    chown -R "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_BASE"
    
    log_success "Directories created and owned by $SERVICE_USER"
}

stop_conflicting_services() {
    log_step "Step 5: Stopping Conflicting Services"
    
    # Stop Evilginx if it's running
    log_info "Checking for running Evilginx instances..."
    if systemctl is-active --quiet evilginx 2>/dev/null; then
        log_info "Stopping Evilginx service..."
        systemctl stop evilginx
        sleep 2
        log_success "Evilginx service stopped"
    fi
    
    # Kill any running evilginx processes (graceful first, then force)
    if pgrep -x evilginx >/dev/null; then
        log_info "Sending SIGTERM to Evilginx processes..."
        pkill -x evilginx 2>/dev/null || true
        sleep 3
        if pgrep -x evilginx >/dev/null; then
            log_warning "Processes still running, sending SIGKILL..."
            pkill -9 -x evilginx 2>/dev/null || true
            sleep 1
        fi
        log_success "Evilginx processes terminated"
    fi
    
    # Stop other conflicting services
    SERVICES=("apache2" "nginx" "bind9" "named" "systemd-resolved")
    
    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_info "Stopping $service..."
            systemctl stop "$service"
            systemctl disable "$service"
            log_success "Stopped and disabled: $service"
        else
            log_info "$service not running (OK)"
        fi
    done
}

disable_systemd_resolved() {
    log_step "Step 5.1: Disabling systemd-resolved (Port 53 Conflict)"
    
    # Check if systemd-resolved is installed
    if ! systemctl list-unit-files | grep -q systemd-resolved.service 2>/dev/null; then
        log_success "systemd-resolved is not installed - no action needed"
        log_info "Port 53 is available for Evilginx DNS server"
        return 0
    fi
    
    log_warning "systemd-resolved detected - will disable to free port 53"
    
    # Stop systemd-resolved
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        log_info "Stopping systemd-resolved service..."
        systemctl stop systemd-resolved || log_warning "Failed to stop systemd-resolved"
        log_success "systemd-resolved stopped"
    fi
    
    # Disable from auto-start
    if systemctl is-enabled --quiet systemd-resolved 2>/dev/null; then
        log_info "Disabling systemd-resolved from auto-start..."
        systemctl disable systemd-resolved || log_warning "Failed to disable systemd-resolved"
        log_success "systemd-resolved disabled"
    fi
    
    # Mask to prevent activation
    log_info "Masking systemd-resolved to prevent activation..."
    systemctl mask systemd-resolved 2>/dev/null || log_warning "Failed to mask systemd-resolved"
    
    # Ubuntu-specific: Disable DNS stub listener to prevent port 53 conflicts after reboot
    if [[ "$DISTRO_ID" == "ubuntu" ]] && [ -f /etc/systemd/resolved.conf ]; then
        log_info "Disabling DNS stub listener (Ubuntu-specific)..."
        sed -i 's/^#\?DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
        # Also add if not present at all
        if ! grep -q "^DNSStubListener" /etc/systemd/resolved.conf; then
            echo "DNSStubListener=no" >> /etc/systemd/resolved.conf
        fi
        log_success "DNS stub listener disabled in resolved.conf"
    fi
    
    # Handle /etc/resolv.conf
    log_info "Configuring /etc/resolv.conf..."
    
    # Capture existing search domains before deleting anything
    SEARCH_DOMAINS=$(grep "^search" /etc/resolv.conf 2>/dev/null || true)
    if [[ -n "$SEARCH_DOMAINS" ]]; then
        log_info "Preserving search domains: $SEARCH_DOMAINS"
    fi

    # Remove immutable attribute if set
    chattr -i /etc/resolv.conf 2>/dev/null || true
    
    # Backup existing resolv.conf
    if [ -f /etc/resolv.conf ]; then
        cp /etc/resolv.conf /etc/resolv.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    fi
    
    # Remove symlink if it exists
    if [ -L /etc/resolv.conf ]; then
        log_info "Removing /etc/resolv.conf symlink..."
        rm -f /etc/resolv.conf 2>/dev/null || true
    fi
    
    # Create static resolv.conf — use proper error handling (not dead $? check)
    if ! cat > /etc/resolv.conf 2>/dev/null << RESOLVEOF
# Static DNS configuration for Evilginx
# systemd-resolved disabled to free port 53

${SEARCH_DOMAINS}

# Google Public DNS
nameserver 8.8.8.8
nameserver 8.8.4.4

# Cloudflare DNS (backup)
nameserver 1.1.1.1

# Options
options timeout:2
options attempts:3
RESOLVEOF
    then
        log_warning "Failed to create /etc/resolv.conf - file may be protected"
        log_info "DNS resolution should still work via existing configuration"
        log_info "If DNS issues occur, manually configure /etc/resolv.conf after installation"
    else
        log_success "Static /etc/resolv.conf created with public DNS servers"
    fi
    
    log_success "systemd-resolved disabled - Port 53 available for Evilginx"

    # Fix: Ensure hostname is resolvable in /etc/hosts
    log_info "Verifying hostname resolution..."
    CURRENT_HOSTNAME=$(hostname)
    
    if [ -n "$CURRENT_HOSTNAME" ]; then
        if ! grep -q "127.0.0.1.*$CURRENT_HOSTNAME" /etc/hosts && ! grep -q "127.0.1.1.*$CURRENT_HOSTNAME" /etc/hosts; then
            log_info "Adding hostname '$CURRENT_HOSTNAME' to /etc/hosts..."
            
            # Backup hosts file
            cp /etc/hosts /etc/hosts.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
            
            # Append to hosts
            echo "127.0.1.1 $CURRENT_HOSTNAME" >> /etc/hosts
            log_success "Hostname added to /etc/hosts"
        else
            log_success "Hostname '$CURRENT_HOSTNAME' already resolvable in /etc/hosts"
        fi
    fi
}

build_evilginx() {
    log_step "Step 6: Building and Installing Evilginx"

    # Verify build toolchain is available
    if ! command -v gcc &>/dev/null; then
        log_error "gcc not found! Install build-essential: apt-get install -y build-essential libsqlite3-dev"
        exit 1
    fi

    if [[ ! -x /usr/local/go/bin/go ]]; then
        log_error "Go not found at /usr/local/go/bin/go"
        log_error "Run full install (sudo ./install.sh) or install Go manually"
        exit 1
    fi

    # Use consolidated find_evilginx_root() instead of duplicated search logic
    local BUILD_DIR
    BUILD_DIR=$(find_evilginx_root) || {
        log_error "Cannot find main.go!"
        log_error "Searched directories:"
        log_error "  - $SCRIPT_DIR"
        log_error "  - $(pwd)"
        log_error "  - ${HOME:-/root}/Evilginx3"
        log_error "  - /root/Evilginx3"
        log_error ""
        log_error "Please run: cd ~/Evilginx3 && sudo ./install.sh"
        exit 1
    }

    # Build in a subshell to avoid changing the working directory
    (
        cd "$BUILD_DIR"
        log_info "Building from: $(pwd)"

        log_info "Compiling Evilginx..."
        # CGO_ENABLED=1 is required for go-sqlite3 (CGo-based SQLite driver)
        # go build does not create the output directory — must exist first
        mkdir -p build
        CGO_ENABLED=1 /usr/local/go/bin/go build -mod=vendor -o build/evilginx main.go

        if [[ ! -f "$BUILD_DIR/build/evilginx" ]]; then
            log_error "Build failed - binary not created"
            exit 1
        fi

        log_success "Evilginx compiled successfully"
    )

    # Install artifacts (ensure base directory exists for --upgrade path)
    mkdir -p "$INSTALL_BASE"
    log_info "Installing to system directories..."

    # Remove old binaries if they exist (after stopping services)
    if [ -f "$INSTALL_BASE/evilginx.bin" ]; then
        log_info "Removing old binary..."
        rm -f "$INSTALL_BASE/evilginx.bin"
    fi
    if [ -f "/usr/local/bin/evilginx" ]; then
        log_info "Removing old wrapper script..."
        rm -f "/usr/local/bin/evilginx"
    fi

    # Copy binary to /opt/evilginx (actual binary location)
    log_info "Installing binary to $INSTALL_BASE..."
    cp "$BUILD_DIR/build/evilginx" "$INSTALL_BASE/evilginx.bin"
    chmod +x "$INSTALL_BASE/evilginx.bin"
    
    # Install phishlets, redirectors, post_redirectors, and web UI (using update mode to preserve custom files)
    log_info "Installing phishlets, redirectors, post_redirectors, and web UI..."
    mkdir -p "$INSTALL_BASE/phishlets" "$INSTALL_BASE/redirectors" "$INSTALL_BASE/post_redirectors" "$INSTALL_BASE/web"
    cp -ru "$BUILD_DIR/phishlets/." "$INSTALL_BASE/phishlets/"
    cp -ru "$BUILD_DIR/redirectors/." "$INSTALL_BASE/redirectors/"
    if [ -d "$BUILD_DIR/post_redirectors" ]; then
        cp -ru "$BUILD_DIR/post_redirectors/." "$INSTALL_BASE/post_redirectors/"
    fi
    if [ -d "$BUILD_DIR/web" ]; then
        cp -ru "$BUILD_DIR/web/." "$INSTALL_BASE/web/"
    fi
    if [ -d "$BUILD_DIR/gophish/static" ]; then
        log_info "Installing Gophish static files and GeoIP database..."
        mkdir -p "$INSTALL_BASE/static"
        cp -ru "$BUILD_DIR/gophish/static/." "$INSTALL_BASE/static/"
    fi
    
    # Create wrapper script with default paths at /usr/local/bin/evilginx
    log_info "Creating system-wide wrapper script..."
    cat > /usr/local/bin/evilginx << 'WRAPPEREOF'
#!/bin/bash
# Evilginx wrapper script with default paths
# Automatically loads phishlets and redirectors from system directories

# Default paths
PHISHLETS_PATH="/opt/evilginx/phishlets"
REDIRECTORS_PATH="/opt/evilginx/redirectors"
POST_REDIRECTORS_PATH="/opt/evilginx/post_redirectors"
CONFIG_PATH="/etc/evilginx"

# Check if user provided paths, otherwise use defaults
ARGS=()
HAS_P_FLAG=false
HAS_T_FLAG=false
HAS_U_FLAG=false
HAS_C_FLAG=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -p)
            HAS_P_FLAG=true
            ARGS+=("$1" "$2")
            shift 2
            ;;
        -t)
            HAS_T_FLAG=true
            ARGS+=("$1" "$2")
            shift 2
            ;;
        -u)
            HAS_U_FLAG=true
            ARGS+=("$1" "$2")
            shift 2
            ;;
        -c)
            HAS_C_FLAG=true
            ARGS+=("$1" "$2")
            shift 2
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

# Add default paths if not provided
if [ "$HAS_P_FLAG" = false ]; then
    ARGS=("-p" "$PHISHLETS_PATH" "${ARGS[@]}")
fi
if [ "$HAS_T_FLAG" = false ]; then
    ARGS=("-t" "$REDIRECTORS_PATH" "${ARGS[@]}")
fi
if [ "$HAS_U_FLAG" = false ]; then
    ARGS=("-u" "$POST_REDIRECTORS_PATH" "${ARGS[@]}")
fi
if [ "$HAS_C_FLAG" = false ]; then
    ARGS=("-c" "$CONFIG_PATH" "${ARGS[@]}")
fi

# Run evilginx binary with constructed arguments
exec /opt/evilginx/evilginx.bin "${ARGS[@]}"
WRAPPEREOF
    chmod +x /usr/local/bin/evilginx
    
    # Copy all documentation
    log_info "Copying documentation to $INSTALL_BASE..."
    cp "$BUILD_DIR/README.md" "$INSTALL_BASE/" 2>/dev/null || true
    cp "$BUILD_DIR/DEPLOYMENT.md" "$INSTALL_BASE/" 2>/dev/null || true
    cp "$BUILD_DIR/DOMAIN-ROTATION-GUIDE.md" "$INSTALL_BASE/" 2>/dev/null || true
    cp "$BUILD_DIR/LICENSE" "$INSTALL_BASE/" 2>/dev/null || true
    cp "$BUILD_DIR/cloudflare-workers-deployment.md" "$INSTALL_BASE/" 2>/dev/null || true
    
    chmod -R 755 "$PHISHLETS_DIR"
    chmod -R 755 "$REDIRECTORS_DIR"
    chmod -R 755 "$POST_REDIRECTORS_DIR"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_BASE"
    
    log_success "Files installed to $INSTALL_DIR"
    log_success "System-wide command 'evilginx' is now available"
}

configure_firewall() {
    log_step "Step 7: Configuring Firewall (UFW)"
    
    # Don't reset — preserve existing rules (critical for cloud instances)
    log_info "Adding firewall rules (preserving existing rules)..."
    
    # Set default policies (only if not already set)
    ufw default deny incoming 2>/dev/null || true
    ufw default allow outgoing 2>/dev/null || true
    
    # Allow SSH (port 22) — always add first to prevent lockouts
    log_info "Allowing SSH (port 22/tcp)..."
    ufw allow 22/tcp comment 'SSH access' 2>/dev/null || true
    
    # Allow HTTP (port 80)
    log_info "Allowing HTTP (port 80/tcp)..."
    ufw allow 80/tcp comment 'HTTP - ACME challenges' 2>/dev/null || true
    
    # Allow HTTPS (port 443)
    log_info "Allowing HTTPS (port 443/tcp)..."
    ufw allow 443/tcp comment 'HTTPS - Evilginx proxy' 2>/dev/null || true
    
    # Allow DNS (port 53)
    log_info "Allowing DNS (port 53/tcp and 53/udp)..."
    ufw allow 53/tcp comment 'DNS TCP - Evilginx nameserver' 2>/dev/null || true
    ufw allow 53/udp comment 'DNS UDP - Evilginx nameserver' 2>/dev/null || true
    
    # Allow Admin Panel (port 2030)
    log_info "Allowing Admin Panel (port 2030/tcp)..."
    ufw allow 2030/tcp comment 'Admin Panel' 2>/dev/null || true
    
    # Allow Gophish Admin UI (port 3333)
    log_info "Allowing Gophish Admin UI (port 3333/tcp)..."
    ufw allow 3333/tcp comment 'Gophish Admin UI' 2>/dev/null || true
    
    # Enable UFW (if not already enabled)
    if ! ufw status | grep -q "Status: active"; then
        log_info "Enabling firewall..."
        echo "y" | ufw enable
    else
        log_info "Firewall already active, rules added"
    fi
    
    log_success "Firewall configured"
    
    # Show status
    echo ""
    ufw status numbered
    echo ""
}

configure_fail2ban() {
    log_step "Step 8: Configuring Fail2Ban"

    # Verify fail2ban is actually installed
    if ! command -v fail2ban-client &>/dev/null; then
        log_warning "fail2ban is not installed — skipping configuration"
        return 0
    fi

    # Create jail.local from jail.conf if it doesn't exist yet
    if [[ ! -f /etc/fail2ban/jail.local ]]; then
        if [[ -f /etc/fail2ban/jail.conf ]]; then
            cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
            log_success "Created /etc/fail2ban/jail.local"
        else
            log_warning "/etc/fail2ban/jail.conf not found — skipping jail.local creation"
        fi
    fi

    # Determine backend based on distro
    # Debian 12+ and Ubuntu 24+ may not have /var/log/auth.log without rsyslog
    F2B_BACKEND=""
    F2B_LOGPATH="logpath = /var/log/auth.log"

    USE_SYSTEMD_BACKEND=false
    if [[ "$DISTRO_ID" == "debian" ]] && [[ "${DISTRO_VER%%.*}" -ge 12 ]]; then
        USE_SYSTEMD_BACKEND=true
    elif [[ "$DISTRO_ID" == "ubuntu" ]] && [[ "${DISTRO_VER%%.*}" -ge 24 ]]; then
        USE_SYSTEMD_BACKEND=true
    fi

    if [[ "$USE_SYSTEMD_BACKEND" == true ]] && [[ ! -f /var/log/auth.log ]]; then
        F2B_BACKEND="backend = systemd"
        F2B_LOGPATH="logpath = %(sshd_log)s"
        log_info "Using systemd backend for Fail2Ban (no /var/log/auth.log detected)"
    fi

    # Ensure jail.d directory exists
    mkdir -p /etc/fail2ban/jail.d

    # Build config — avoid blank lines from empty variables
    {
        echo "[sshd]"
        echo "enabled = true"
        echo "port = 22"
        echo "filter = sshd"
        echo "$F2B_LOGPATH"
        [[ -n "$F2B_BACKEND" ]] && echo "$F2B_BACKEND"
        echo "maxretry = 3"
        echo "bantime = 3600"
        echo "findtime = 600"
    } > /etc/fail2ban/jail.d/sshd.conf

    log_success "Fail2Ban configured for SSH protection"

    systemctl enable fail2ban
    if systemctl restart fail2ban; then
        log_success "Fail2Ban enabled and started"
    else
        log_warning "Fail2Ban failed to start — check: systemctl status fail2ban / journalctl -u fail2ban"
        log_warning "Continuing installation (fail2ban is non-critical)"
    fi
}

create_systemd_service() {
    log_step "Step 9: Creating Systemd Service"
    
    cat > /etc/systemd/system/evilginx.service << EOF
[Unit]
Description=Evilginx $EVILGINX_VERSION - Private Dev Edition
Documentation=https://github.com/kgretzky/evilginx2
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_BASE
ExecStart=/usr/local/bin/evilginx -c $CONFIG_DIR
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=evilginx

# Security hardening (non-root service user)
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$CONFIG_DIR $LOG_DIR $INSTALL_BASE
NoNewPrivileges=true

# Capabilities needed for binding to ports 53, 80, 443
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF
    
    log_success "Systemd service file created"
    
    # Reload systemd
    systemctl daemon-reload
    log_success "Systemd daemon reloaded"
    
    # Enable service
    systemctl enable evilginx.service
    log_success "Evilginx service enabled for automatic startup"
}

configure_capabilities() {
    log_step "Step 10: Setting Binary Capabilities"
    
    # Allow binding to privileged ports
    log_info "Setting CAP_NET_BIND_SERVICE capability on binary..."
    setcap 'cap_net_bind_service=+ep' "$INSTALL_BASE/evilginx.bin"
    
    log_success "Binary can now bind to ports 53, 80, 443"
}

create_helper_scripts() {
    log_step "Step 11: Creating Helper Scripts"
    
    # Create start script (root check instead of redundant sudo)
    cat > /usr/local/bin/evilginx-start << 'EOF'
#!/bin/bash
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0"; exit 1; fi
systemctl start evilginx
systemctl status evilginx --no-pager
EOF
    chmod +x /usr/local/bin/evilginx-start
    
    # Create stop script
    cat > /usr/local/bin/evilginx-stop << 'EOF'
#!/bin/bash
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0"; exit 1; fi
systemctl stop evilginx
echo "Evilginx stopped"
EOF
    chmod +x /usr/local/bin/evilginx-stop
    
    # Create restart script
    cat > /usr/local/bin/evilginx-restart << 'EOF'
#!/bin/bash
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0"; exit 1; fi
systemctl restart evilginx
systemctl status evilginx --no-pager
EOF
    chmod +x /usr/local/bin/evilginx-restart
    
    # Create status script
    cat > /usr/local/bin/evilginx-status << 'EOF'
#!/bin/bash
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0"; exit 1; fi
systemctl status evilginx --no-pager -l
EOF
    chmod +x /usr/local/bin/evilginx-status
    
    # Create logs script
    cat > /usr/local/bin/evilginx-logs << 'EOF'
#!/bin/bash
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0"; exit 1; fi
journalctl -u evilginx -f
EOF
    chmod +x /usr/local/bin/evilginx-logs
    
    # Create console script
    cat > /usr/local/bin/evilginx-console << 'EOF'
#!/bin/bash
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0"; exit 1; fi
echo "Stopping systemd service to run interactively..."
systemctl stop evilginx 2>/dev/null || true
echo ""
echo "Starting Evilginx in interactive mode..."
echo "Press Ctrl+C to stop, then run 'evilginx-start' to resume service mode"
echo ""
evilginx -c /etc/evilginx

# Ensure permissions are restored to service user if root modified anything
echo "Restoring configuration ownership to evilginx..."
chown -R evilginx:evilginx /etc/evilginx 2>/dev/null || true
EOF
    chmod +x /usr/local/bin/evilginx-console
    
    log_success "Helper scripts created in /usr/local/bin/"
}

setup_cloudflare_tunnel() {
    log_step "Step 12: Cloudflare Tunnel Setup (Optional)"

    echo ""
    log_info "Cloudflare Tunnel exposes your admin panels publicly via HTTPS:"
    log_info "  • https://${CF_TUNNEL_ADMIN_SUB}.<domain>   → Web Admin API (port 2030)"
    log_info "  • https://${CF_TUNNEL_GOPHISH_SUB}.<domain> → GoPhish Admin  (port 3333)"
    echo ""

    read -r -p "$(echo -e "${CYAN}Set up Cloudflare Tunnel for admin panels? [y/N]: ${NC}")" SETUP_TUNNEL < /dev/tty
    if [[ ! "$SETUP_TUNNEL" =~ ^[Yy]$ ]]; then
        log_info "Skipping Cloudflare Tunnel setup"
        log_info "You can run setup-tunnel.sh manually at any time"
        return 0
    fi

    # Resolve domain — prompt if still a placeholder
    local TDOMAIN="$CF_TUNNEL_DOMAIN"
    if [[ "$TDOMAIN" == "YOUR_DOMAIN_HERE" ]]; then
        read -r -p "$(echo -e "${CYAN}Enter your domain for the tunnel (e.g. example.com): ${NC}")" TDOMAIN < /dev/tty
        if [[ -z "$TDOMAIN" ]]; then
            log_warning "No domain entered — skipping tunnel setup"
            return 0
        fi
    fi

    local TNAME="$CF_TUNNEL_NAME"
    local ADMIN_SUB="$CF_TUNNEL_ADMIN_SUB"
    local GOPHISH_SUB="$CF_TUNNEL_GOPHISH_SUB"

    # Helper: look up tunnel ID by name (reusable inside this function)
    _get_tunnel_id() {
        cloudflared tunnel list -o json 2>/dev/null | python3 -c "
import sys, json
tunnels = json.load(sys.stdin)
for t in tunnels:
    if t['name'] == '$1':
        print(t['id'])
        break
" 2>/dev/null || true
    }

    # ── Install cloudflared ──────────────────────────────────
    log_step "Step 12.1: Installing cloudflared"
    if command -v cloudflared &>/dev/null; then
        log_success "cloudflared already installed: $(cloudflared --version)"
    else
        # Re-use the ARCH already detected at script start
        local CF_ARCH
        CF_ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
        log_info "Downloading cloudflared for ${CF_ARCH}..."
        curl -sL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}.deb" \
            -o /tmp/cloudflared.deb
        dpkg -i /tmp/cloudflared.deb
        rm -f /tmp/cloudflared.deb
        log_success "cloudflared installed: $(cloudflared --version)"
    fi

    # ── Authenticate ─────────────────────────────────────────
    log_step "Step 12.2: Authenticate with Cloudflare"
    # Always re-authenticate to ensure credentials match the target zone
    rm -f "$HOME/.cloudflared/cert.pem"
    echo ""
    log_info "[ACTION REQUIRED] A browser URL will appear below."
    log_info "  1. Copy the URL and open it in your browser"
    log_info "  2. Log in to Cloudflare"
    log_info "  3. Select the zone: ${TDOMAIN}"
    log_info "  4. Return here — it will continue automatically"
    echo ""
    cloudflared tunnel login
    log_success "Authentication complete"

    # ── Remove old tunnels ────────────────────────────────────
    log_step "Step 12.3: Cleaning up old tunnels"
    local OLD_TUNNEL_ID
    OLD_TUNNEL_ID=$(_get_tunnel_id "${TNAME}")

    if [[ -n "$OLD_TUNNEL_ID" ]]; then
        log_info "Removing existing tunnel '${TNAME}' (ID: ${OLD_TUNNEL_ID})..."
        # Stop any running cloudflared service first
        systemctl stop cloudflared 2>/dev/null || true
        # Clean up old connections before deleting
        cloudflared tunnel cleanup "${TNAME}" 2>/dev/null || true
        cloudflared tunnel delete "${TNAME}" 2>/dev/null || true
        # Remove stale credentials file
        rm -f "$HOME/.cloudflared/${OLD_TUNNEL_ID}.json" "/root/.cloudflared/${OLD_TUNNEL_ID}.json" 2>/dev/null
        log_success "Old tunnel removed"
    else
        log_info "No existing tunnel '${TNAME}' found"
    fi

    # ── Create tunnel ─────────────────────────────────────────
    log_step "Step 12.4: Creating tunnel '${TNAME}'"
    log_info "Creating tunnel..."
    cloudflared tunnel create "${TNAME}"
    local TUNNEL_ID
    TUNNEL_ID=$(_get_tunnel_id "${TNAME}")
    if [[ -z "$TUNNEL_ID" ]]; then
        log_error "Failed to retrieve tunnel ID after creation"
        return 1
    fi
    log_info "Tunnel ID: ${TUNNEL_ID}"

    # ── Write config ──────────────────────────────────────────
    log_step "Step 12.5: Writing tunnel config"
    local CRED_FILE=""
    if [[ -f "$HOME/.cloudflared/${TUNNEL_ID}.json" ]]; then
        CRED_FILE="$HOME/.cloudflared/${TUNNEL_ID}.json"
    elif [[ -f "/root/.cloudflared/${TUNNEL_ID}.json" ]]; then
        CRED_FILE="/root/.cloudflared/${TUNNEL_ID}.json"
    else
        log_error "Credentials file not found for tunnel ID: ${TUNNEL_ID}"
        return 1
    fi

    cat > "$HOME/.cloudflared/config.yml" <<CFEOF
tunnel: ${TUNNEL_ID}
credentials-file: ${CRED_FILE}

ingress:
  - hostname: ${ADMIN_SUB}.${TDOMAIN}
    service: http://localhost:2030
  - hostname: ${GOPHISH_SUB}.${TDOMAIN}
    service: http://localhost:3333
  # Catch-all (required by cloudflared)
  - service: http_status:404
CFEOF
    log_success "Config written to $HOME/.cloudflared/config.yml"

    # ── DNS routes ────────────────────────────────────────────
    log_step "Step 12.6: Creating DNS routes"

    # Helper: delete existing DNS records for a hostname using Cloudflare API
    # The cert.pem from `cloudflared tunnel login` contains zone/account/token info
    _delete_cf_dns_record() {
        local hostname="$1"
        local cert_json
        cert_json=$(awk '/BEGIN ARGO TUNNEL TOKEN/{found=1;next} /END ARGO TUNNEL TOKEN/{found=0} found' \
            "$HOME/.cloudflared/cert.pem" | base64 -d 2>/dev/null) || return 0

        local zone_id account_id api_token
        zone_id=$(echo "$cert_json" | python3 -c "import sys,json;print(json.load(sys.stdin)['zoneID'])" 2>/dev/null) || return 0
        api_token=$(echo "$cert_json" | python3 -c "import sys,json;print(json.load(sys.stdin)['apiToken'])" 2>/dev/null) || return 0

        if [[ -z "$zone_id" || -z "$api_token" ]]; then
            return 0
        fi

        # Find existing records for this hostname
        local records
        records=$(curl -s -X GET \
            "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records?name=${hostname}" \
            -H "Authorization: Bearer ${api_token}" \
            -H "Content-Type: application/json" 2>/dev/null)

        # Extract record IDs and delete them
        echo "$records" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('result', []):
    print(r['id'])
" 2>/dev/null | while read -r record_id; do
            if [[ -n "$record_id" ]]; then
                log_info "Deleting old DNS record ${record_id} for ${hostname}..."
                curl -s -X DELETE \
                    "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}" \
                    -H "Authorization: Bearer ${api_token}" \
                    -H "Content-Type: application/json" >/dev/null 2>&1
            fi
        done
    }

    # Remove stale DNS records before creating new routes
    _delete_cf_dns_record "${ADMIN_SUB}.${TDOMAIN}"
    _delete_cf_dns_record "${GOPHISH_SUB}.${TDOMAIN}"

    log_info "Routing ${ADMIN_SUB}.${TDOMAIN} → tunnel..."
    cloudflared tunnel route dns "${TNAME}" "${ADMIN_SUB}.${TDOMAIN}" 2>/dev/null || \
        log_warning "DNS route may already exist for ${ADMIN_SUB}.${TDOMAIN}"

    log_info "Routing ${GOPHISH_SUB}.${TDOMAIN} → tunnel..."
    cloudflared tunnel route dns "${TNAME}" "${GOPHISH_SUB}.${TDOMAIN}" 2>/dev/null || \
        log_warning "DNS route may already exist for ${GOPHISH_SUB}.${TDOMAIN}"
    log_success "DNS routes created"

    # ── System service ────────────────────────────────────────
    log_step "Step 12.7: Installing cloudflared as system service"
    systemctl stop cloudflared 2>/dev/null || true
    cloudflared service uninstall 2>/dev/null || true

    mkdir -p /etc/cloudflared
    cp "$HOME/.cloudflared/config.yml" /etc/cloudflared/config.yml
    cp "${CRED_FILE}" "/etc/cloudflared/${TUNNEL_ID}.json"
    sed -i "s|credentials-file:.*|credentials-file: /etc/cloudflared/${TUNNEL_ID}.json|" /etc/cloudflared/config.yml

    # Create systemd unit directly (cloudflared service install can silently fail)
    cat > /etc/systemd/system/cloudflared.service <<SVCEOF
[Unit]
Description=cloudflared tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
TimeoutStartSec=0
ExecStart=$(command -v cloudflared) --no-autoupdate tunnel run
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable cloudflared
    systemctl restart cloudflared
    log_success "cloudflared service started and enabled on boot"

    # Expose tunnel URLs for display_completion()
    TUNNEL_CONFIGURED=true
    TUNNEL_ADMIN_URL="https://${ADMIN_SUB}.${TDOMAIN}"
    TUNNEL_GOPHISH_URL="https://${GOPHISH_SUB}.${TDOMAIN}"
}

display_completion() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                   ║${NC}"
    echo -e "${GREEN}║          ✓ INSTALLATION COMPLETED SUCCESSFULLY!                  ║${NC}"
    echo -e "${GREEN}║                                                                   ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log_step "Installation Summary"
    
    echo -e "${CYAN}Installation Details:${NC}"
    echo "  • OS:                   $OS $VER ($GO_ARCH)"
    echo "  • Evilginx Binary:      /usr/local/bin/evilginx (wrapper)"
    echo "  • Actual Binary:        $INSTALL_BASE/evilginx.bin"
    echo "  • Phishlets Directory:  $PHISHLETS_DIR"
    echo "  • Redirectors Directory: $REDIRECTORS_DIR"
    echo "  • Configuration:        $CONFIG_DIR"
    echo "  • Logs:                 $LOG_DIR"
    echo "  • Running as:           Admin (root)"
    echo "  • Systemd Service:      evilginx.service"
    if [[ -n "$INSTALL_LOG" ]]; then
        echo "  • Install Log:          $INSTALL_LOG"
    fi
    echo ""
    
    echo -e "${CYAN}Firewall Rules (UFW):${NC}"
    echo "  • Port 22/tcp  - SSH (allow)"
    echo "  • Port 53/tcp  - DNS (allow)"
    echo "  • Port 53/udp  - DNS (allow)"
    echo "  • Port 80/tcp  - HTTP (allow)"
    echo "  • Port 443/tcp - HTTPS (allow)"
    echo "  • Port 2030/tcp - Admin Panel (allow)"
    echo "  • Port 3333/tcp - Gophish Admin UI (allow)"
    echo ""
    
    echo -e "${CYAN}Quick Usage:${NC}"
    echo "  • sudo evilginx         - Run with default paths (phishlets & redirectors included)"
    echo "  • sudo evilginx -debug  - Run in debug mode"
    echo "  • sudo evilginx -developer - Run in developer mode"
    echo ""
    echo -e "${CYAN}Integrated Gophish:${NC}"
    echo "  • Admin UI (local):     http://127.0.0.1:3333"
    echo "  • Gophish Database:     $CONFIG_DIR/gophish.db"
    echo "  • Access Remotely:      ssh -L 3333:127.0.0.1:3333 your-vps-ip"

    if [[ "$TUNNEL_CONFIGURED" == true ]]; then
        echo ""
        echo -e "${CYAN}Cloudflare Tunnel (active):${NC}"
        echo "  • Web Admin:            $TUNNEL_ADMIN_URL"
        echo "  • GoPhish:              $TUNNEL_GOPHISH_URL"
        echo "  • Service:              systemctl status cloudflared"
        echo "  • Logs:                 journalctl -u cloudflared -f"
        echo ""
        echo -e "  ${YELLOW}[!] Recommended: add Cloudflare Access policies to restrict access${NC}"
        echo -e "      Dashboard → Zero Trust → Access → Applications"
    else
        echo ""
        echo -e "${CYAN}Cloudflare Tunnel (not configured):${NC}"
        echo "  • Run setup-tunnel.sh at any time to expose admin panels via HTTPS"
        echo "  • Or re-run: TUNNEL_DOMAIN=example.com sudo ./install.sh --tunnel"
    fi
    echo ""
    echo -e "  ${GREEN}No need to specify -p or -t flags anymore!${NC}"
    echo ""
    
    echo -e "${CYAN}Available Commands:${NC}"
    echo "  • evilginx-start        - Start Evilginx service"
    echo "  • evilginx-stop         - Stop Evilginx service"
    echo "  • evilginx-restart      - Restart Evilginx service"
    echo "  • evilginx-status       - Check service status"
    echo "  • evilginx-logs         - View live logs"
    echo "  • evilginx-console      - Run interactive console"
    echo ""
    
    echo -e "${CYAN}Systemd Commands:${NC}"
    echo "  • systemctl start evilginx    - Start service"
    echo "  • systemctl stop evilginx     - Stop service"
    echo "  • systemctl restart evilginx  - Restart service"
    echo "  • systemctl status evilginx   - Check status"
    echo "  • journalctl -u evilginx -f   - View logs"
    echo ""
    
    echo -e "${YELLOW}[!] IMPORTANT: Next Steps${NC}"
    echo ""
    echo "1. Configure Evilginx before starting:"
    echo "   Run: evilginx-console"
    echo ""
    echo "2. In the Evilginx console, configure:"
    echo "   domains set yourdomain.com"
    echo "   config ipv4 external <YOUR_SERVER_IP>"
    echo "   config autocert on"
    echo ""
    echo "3. Enable a phishlet:"
    echo "   phishlets hostname o365 login.yourdomain.com"
    echo "   phishlets enable o365"
    echo ""
    echo "4. Create a lure:"
    echo "   lures create o365"
    echo "   lures get-url 0"
    echo ""
    echo "5. (Optional) Set up domain rotation:"
    echo "   domains add yourdomain2.com"
    echo "   domains rotation enable on"
    echo "   See: /opt/evilginx/DOMAIN-ROTATION-GUIDE.md"
    echo ""
    echo "6. Exit console (Ctrl+C) and start service:"
    echo "   evilginx-start"
    echo ""
    
    echo -e "${YELLOW}[!] SECURITY REMINDERS${NC}"
    echo ""
    echo "  • Ensure you have WRITTEN AUTHORIZATION"
    echo "  • Configure Cloudflare DNS for your domain"
    echo "  • Enable advanced features (ML, JA3, Sandbox detection)"
    echo "  • Set up Telegram notifications for monitoring"
    echo "  • Review DEPLOYMENT.md for complete setup"
    echo "  • Check logs regularly: journalctl -u evilginx -f"
    echo ""
    
    echo -e "${GREEN}Documentation:${NC}"
    echo "  • Deployment Guide:     /opt/evilginx/DEPLOYMENT.md"
    echo "  • Domain Rotation:      /opt/evilginx/DOMAIN-ROTATION-GUIDE.md"
    echo "  • README:               /opt/evilginx/README.md"
    echo ""
    
    echo -e "${CYAN}Quick Start:${NC}"
    echo "  1. sudo evilginx        # Run with auto-loaded paths"
    echo "  2. <configure settings> # Set domain, IP, phishlets"
    echo "  3. exit or Ctrl+C       # Exit console"
    echo "  4. evilginx-start       # Start service"
    echo "  5. evilginx-status      # Verify running"
    echo ""
    
    echo -e "${CYAN}Environment:${NC}"
    echo "  • Go installed at:      /usr/local/go"
    echo "  • Go PATH via:          /etc/profile.d/golang.sh"
    echo "  • Verify with:          go version"
    echo ""
    
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Remind about PATH
    echo -e "${YELLOW}Note:${NC} Go has been added to PATH. You may need to reload your shell or run:"
    echo "  source /etc/profile.d/golang.sh"
    echo ""
}

#############################################################################
# Usage / Help
#############################################################################

show_usage() {
    echo "Evilginx $EVILGINX_VERSION - One-Click Installer"
    echo ""
    echo "Usage: sudo $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  (none)       Full installation (default)"
    echo "  --upgrade    Rebuild and reinstall binary only (skip deps/firewall/service)"
    echo "  --uninstall  Remove Evilginx (binary, service, scripts, optionally config)"
    echo "  --tunnel     Set up (or re-run) Cloudflare Tunnel only"
    echo "  --dry-run    Show what would be done without making changes"
    echo "  --help, -h   Show this help message"
    echo ""
    echo "Environment variables (tunnel):"
    echo "  TUNNEL_DOMAIN=example.com   Domain for tunnel subdomains"
    echo "  CF_TUNNEL_NAME=my-tunnel    Override tunnel name (default: evilginx-panels)"
    echo "  CF_TUNNEL_ADMIN_SUB=admin   Override admin subdomain prefix (default: admin)"
    echo "  CF_TUNNEL_GOPHISH_SUB=gp    Override gophish subdomain prefix (default: gophish)"
    echo ""
    echo "Examples:"
    echo "  sudo ./install.sh                                    # Full install"
    echo "  sudo ./install.sh --upgrade                          # Quick rebuild"
    echo "  sudo ./install.sh --uninstall                        # Clean removal"
    echo "  TUNNEL_DOMAIN=example.com sudo ./install.sh --tunnel # Tunnel only"
    echo "  ./install.sh --dry-run                               # Preview (no root needed)"
    echo ""
}

#############################################################################
# Main Installation Flow
#############################################################################

main() {
    # Set up install logging — tee all output to a log file
    INSTALL_LOG="/tmp/evilginx-install-$(date +%Y%m%d_%H%M%S).log"
    exec > >(tee -a "$INSTALL_LOG") 2>&1
    log_info "Installation log: $INSTALL_LOG"
    
    print_banner
    
    # Pre-flight: ensure git is available
    ensure_git
    
    # Find Evilginx root directory using consolidated search
    EVILGINX_ROOT=$(find_evilginx_root) || true
    if [[ -n "$EVILGINX_ROOT" ]]; then
        cd "$EVILGINX_ROOT"
        log_info "Working directory: $(pwd)"
    else
        log_error "Cannot find Evilginx root directory with main.go"
        log_error "Searched: $SCRIPT_DIR, $(pwd), ${HOME:-/root}/Evilginx3, /root/Evilginx3"
        exit 1
    fi
    
    # Pre-installation checks
    check_root
    detect_os
    confirm_installation
    
    # Pre-flight connectivity and resource checks
    preflight_check
    
    # Installation steps
    update_system
    install_dependencies
    install_go
    create_service_user
    setup_directories
    stop_conflicting_services
    disable_systemd_resolved
    build_evilginx
    configure_firewall
    configure_fail2ban
    create_systemd_service
    configure_capabilities
    create_helper_scripts
    create_admin_user
    setup_cloudflare_tunnel

    # Cleanup temporary needrestart override
    rm -f /etc/needrestart/conf.d/99-installer-tmp.conf 2>/dev/null

    # Completion
    display_completion

    log_success "Installation complete! Review the information above."
    log_success "Full log saved to: $INSTALL_LOG"
}

#############################################################################
# Argument Parsing & Entry Point
#############################################################################

case "${1:-}" in
    --help|-h)
        show_usage
        exit 0
        ;;
    --uninstall)
        check_root
        print_banner
        uninstall_evilginx
        exit 0
        ;;
    --tunnel)
        check_root
        print_banner
        setup_cloudflare_tunnel
        if [[ "$TUNNEL_CONFIGURED" == true ]]; then
            echo ""
            log_success "Tunnel active:"
            log_success "  Web Admin:  $TUNNEL_ADMIN_URL"
            log_success "  GoPhish:    $TUNNEL_GOPHISH_URL"
            log_info "Recommended: add Cloudflare Access policies to restrict access"
            log_info "  Dashboard → Zero Trust → Access → Applications"
        fi
        exit 0
        ;;
    --upgrade)
        check_root

        # Set up logging first so all output is captured
        INSTALL_LOG="/tmp/evilginx-upgrade-$(date +%Y%m%d_%H%M%S).log"
        exec > >(tee -a "$INSTALL_LOG") 2>&1
        log_info "Upgrade log: $INSTALL_LOG"

        print_banner
        detect_os

        log_step "Upgrade Mode — Updating all components"

        EVILGINX_ROOT=$(find_evilginx_root) || true
        if [[ -z "$EVILGINX_ROOT" ]]; then
            log_error "Cannot find Evilginx root directory with main.go"
            log_error "Searched: $SCRIPT_DIR, $(pwd), ${HOME:-/root}/Evilginx3, /root/Evilginx3"
            exit 1
        fi
        log_info "Working directory: $EVILGINX_ROOT"

        # Ensure build dependencies exist (gcc required for CGo/go-sqlite3)
        if ! command -v gcc &>/dev/null; then
            log_warning "gcc not found — installing build dependencies..."
            wait_for_apt_lock
            apt-get update -qq
            apt-get install -y -qq "${APT_OPTS[@]}" build-essential libsqlite3-dev
            log_success "Build dependencies installed"
        fi

        # Update Go if version has changed
        install_go

        # Ensure service user and directories exist with correct permissions
        create_service_user
        setup_directories

        # Stop services, rebuild, reinstall
        stop_conflicting_services
        build_evilginx
        configure_capabilities

        # Refresh systemd service file (picks up any new flags/settings)
        create_systemd_service

        # Refresh all helper scripts (evilginx-start, stop, console, etc.)
        create_helper_scripts

        # Reload and restart
        systemctl daemon-reload
        log_info "Restarting Evilginx service..."
        systemctl restart evilginx 2>/dev/null || log_warning "Service not started (run 'evilginx-console' to configure first)"

        # Cleanup
        rm -f /etc/needrestart/conf.d/99-installer-tmp.conf 2>/dev/null

        log_success "Upgrade complete!"
        log_success "Full log saved to: $INSTALL_LOG"
        exit 0
        ;;
    --dry-run)
        print_banner

        # Detect OS for display (doesn't require root)
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS=$NAME
            VER=$VERSION_ID
        fi

        echo ""
        log_info "DRY RUN — The following steps would be executed:"
        echo ""
        echo "   1.  Update system packages (apt-get update)"
        echo "   2.  Install dependencies (~20 packages: curl, wget, ufw, fail2ban, etc.)"
        echo "   3.  Install Go $GO_VERSION ($GO_ARCH) from go.dev"
        echo "   4.  Create directories: $CONFIG_DIR, $LOG_DIR"
        echo "   5.  Stop conflicting services (apache2, nginx, bind9, systemd-resolved)"
        echo "   6.  Disable systemd-resolved (free port 53)"
        echo "   7.  Build Evilginx from source"
        echo "   8.  Install binary + phishlets to: $INSTALL_BASE"
        echo "   9.  Configure UFW firewall (ports 22, 53, 80, 443)"
        echo "  10.  Configure Fail2Ban (SSH protection)"
        echo "  11.  Create systemd service: evilginx.service"
        echo "  12.  Set binary capabilities (CAP_NET_BIND_SERVICE)"
        echo "  13.  Create helper scripts (evilginx-{start,stop,restart,status,logs,console})"
        echo "  14.  [Optional] Set up Cloudflare Tunnel (admin + gophish panels via HTTPS)"
        echo "       Pass TUNNEL_DOMAIN=example.com or answer the interactive prompt"
        echo ""
        log_info "No changes were made."
        echo ""
        echo "To perform actual installation, run:"
        echo "  sudo ./install.sh"
        echo ""
        exit 0
        ;;
    "")
        # Default: full installation
        main
        ;;
    *)
        log_error "Unknown option: $1"
        show_usage
        exit 1
        ;;
esac

exit 0
