#!/bin/bash

#############################################################################
# Evilginx 3.3.1 - Private Dev Edition - One-Click Installer
#############################################################################
# This script automates the complete installation and configuration process
# Based on: DEPLOYMENT_GUIDE.md
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
#   sudo ./install.sh
#
# Author: AKaZA (Akz0fuku)
# Version: 1.0.0
#############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
GO_VERSION="1.22.0"
INSTALL_DIR="/usr/local/evilginx"
SERVICE_USER="root"  # Run as admin
CONFIG_DIR="/etc/evilginx"
LOG_DIR="/var/log/evilginx"
PHISHLETS_DIR="/usr/local/evilginx/phishlets"
REDIRECTORS_DIR="/usr/local/evilginx/redirectors"

#############################################################################
# Helper Functions
#############################################################################

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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root!"
        log_info "Please run: sudo $0"
        exit 1
    fi
    log_success "Running as root"
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        log_info "Detected OS: $OS $VER"
        
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
    else
        log_error "Cannot detect OS. /etc/os-release not found"
        exit 1
    fi
}

confirm_installation() {
    echo -e "${YELLOW}"
    cat << EOF

⚠️  WARNING: This installer will make significant system changes:

   1. Install Go $GO_VERSION and dependencies
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

#############################################################################
# Installation Steps
#############################################################################

update_system() {
    log_step "Step 1: Updating System Packages"
    
    apt-get update -qq
    log_success "Package lists updated"
    
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
    log_success "System packages upgraded"
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
        iptables \
        iptables-persistent 2>/dev/null || true
    
    log_success "Essential packages installed"
}

install_go() {
    log_step "Step 3: Installing Go $GO_VERSION"
    
    # Check if Go is already installed
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
    
    log_info "Downloading Go $GO_VERSION..."
    cd /tmp
    wget -q --show-progress "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    
    log_info "Extracting Go..."
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    
    # Add to PATH
    if ! grep -q "/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    
    export PATH=$PATH:/usr/local/go/bin
    
    # Cleanup
    rm -f "go${GO_VERSION}.linux-amd64.tar.gz"
    
    log_success "Go $GO_VERSION installed successfully"
    /usr/local/go/bin/go version
    
    # Return to original directory
    cd - > /dev/null
}

setup_directories() {
    log_step "Step 4: Creating Directories (Admin Mode)"
    
    # Running as admin, no need to create a separate user
    log_info "Running installation with admin privileges"
    
    # Create necessary directories
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    
    # No need to change ownership when running as admin/root
    
    log_success "Directories created with admin privileges"
}

stop_conflicting_services() {
    log_step "Step 5: Stopping Conflicting Services"
    
    SERVICES=("apache2" "nginx" "bind9" "named")
    
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
    
    # Handle /etc/resolv.conf
    log_info "Configuring /etc/resolv.conf..."
    
    # Backup existing resolv.conf
    if [ -f /etc/resolv.conf ]; then
        cp /etc/resolv.conf /etc/resolv.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    fi
    
    # Remove symlink if it exists
    if [ -L /etc/resolv.conf ]; then
        log_info "Removing /etc/resolv.conf symlink..."
        rm -f /etc/resolv.conf
    fi
    
    # Create static resolv.conf with public DNS servers
    cat > /etc/resolv.conf << 'RESOLVEOF'
# Static DNS configuration for Evilginx
# systemd-resolved disabled to free port 53

# Google Public DNS
nameserver 8.8.8.8
nameserver 8.8.4.4

# Cloudflare DNS (backup)
nameserver 1.1.1.1

# Options
options timeout:2
options attempts:3
RESOLVEOF
    
    log_success "Static /etc/resolv.conf created with public DNS servers"
    
    # Make resolv.conf immutable (optional)
    chattr +i /etc/resolv.conf 2>/dev/null || true
    
    log_success "systemd-resolved disabled - Port 53 available for Evilginx"
}

build_evilginx() {
    log_step "Step 6: Building Evilginx"
    
    # Get current directory (where install.sh is located)
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    
    log_info "Building from: $SCRIPT_DIR"
    
    # Check if we're in the Evilginx directory
    if [[ ! -f "$SCRIPT_DIR/main.go" ]]; then
        log_error "main.go not found in $SCRIPT_DIR"
        log_error "Please run this script from the Evilginx root directory"
        exit 1
    fi
    
    # Build
    log_info "Downloading Go dependencies..."
    cd "$SCRIPT_DIR"
    /usr/local/go/bin/go mod download
    
    log_info "Compiling Evilginx..."
    /usr/local/go/bin/go build -o build/evilginx main.go
    
    if [[ ! -f "$SCRIPT_DIR/build/evilginx" ]]; then
        log_error "Build failed - binary not created"
        exit 1
    fi
    
    log_success "Evilginx compiled successfully"
    
    # Create system-wide installation directory
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$PHISHLETS_DIR"
    
    # Copy files
    log_info "Installing files to $INSTALL_DIR..."
    cp "$SCRIPT_DIR/build/evilginx" "$INSTALL_DIR/evilginx.bin"
    cp -r "$SCRIPT_DIR/redirectors" "$INSTALL_DIR/"
    
    # Create wrapper script with default paths
    log_info "Creating system-wide wrapper script..."
    cat > /usr/local/bin/evilginx << 'EOF'
#!/bin/bash
# Evilginx wrapper with default paths
exec /usr/local/evilginx/evilginx.bin -p /usr/local/evilginx/phishlets -t /usr/local/evilginx/redirectors "$@"
EOF
    chmod +x /usr/local/bin/evilginx
    
    # Copy documentation
    cp "$SCRIPT_DIR/README.md" "$INSTALL_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR/DEPLOYMENT_GUIDE.md" "$INSTALL_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR/LURE_RANDOMIZATION_GUIDE.md" "$INSTALL_DIR/" 2>/dev/null || true
    
    # Set permissions
    chmod +x "$INSTALL_DIR/evilginx.bin"
    chmod 755 "$INSTALL_DIR"
    chmod -R 755 "$PHISHLETS_DIR"
    chmod -R 755 "$REDIRECTORS_DIR"
    # No need to change ownership when running as admin
    
    log_success "Files installed to $INSTALL_DIR (admin mode)"
    log_success "System-wide command 'evilginx' is now available"
}

configure_firewall() {
    log_step "Step 7: Configuring Firewall (UFW)"
    
    # Reset UFW to default
    log_info "Resetting UFW to default configuration..."
    ufw --force reset
    
    # Set default policies
    log_info "Setting default policies..."
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (port 22)
    log_info "Allowing SSH (port 22/tcp)..."
    ufw allow 22/tcp comment 'SSH access'
    
    # Allow HTTP (port 80)
    log_info "Allowing HTTP (port 80/tcp)..."
    ufw allow 80/tcp comment 'HTTP - ACME challenges'
    
    # Allow HTTPS (port 443)
    log_info "Allowing HTTPS (port 443/tcp)..."
    ufw allow 443/tcp comment 'HTTPS - Evilginx proxy'
    
    # Allow DNS (port 53)
    log_info "Allowing DNS (port 53/tcp and 53/udp)..."
    ufw allow 53/tcp comment 'DNS TCP - Evilginx nameserver'
    ufw allow 53/udp comment 'DNS UDP - Evilginx nameserver'
    
    # Enable UFW
    log_info "Enabling firewall..."
    echo "y" | ufw enable
    
    log_success "Firewall configured and enabled"
    
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
    
    # Configure SSH protection
    cat > /etc/fail2ban/jail.d/sshd.conf << EOF
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
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
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/local/bin/evilginx -c $CONFIG_DIR
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=evilginx

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CONFIG_DIR $LOG_DIR

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
    
    # Allow binding to privileged ports without root
    log_info "Setting CAP_NET_BIND_SERVICE capability..."
    setcap 'cap_net_bind_service=+ep' "$INSTALL_DIR/evilginx"
    
    log_success "Binary can now bind to ports 53, 80, 443 without root"
}

create_helper_scripts() {
    log_step "Step 11: Creating Helper Scripts"
    
    # Create start script
    cat > /usr/local/bin/evilginx-start << 'EOF'
#!/bin/bash
sudo systemctl start evilginx
sudo systemctl status evilginx --no-pager
EOF
    chmod +x /usr/local/bin/evilginx-start
    
    # Create stop script
    cat > /usr/local/bin/evilginx-stop << 'EOF'
#!/bin/bash
sudo systemctl stop evilginx
echo "Evilginx stopped"
EOF
    chmod +x /usr/local/bin/evilginx-stop
    
    # Create restart script
    cat > /usr/local/bin/evilginx-restart << 'EOF'
#!/bin/bash
sudo systemctl restart evilginx
sudo systemctl status evilginx --no-pager
EOF
    chmod +x /usr/local/bin/evilginx-restart
    
    # Create status script
    cat > /usr/local/bin/evilginx-status << 'EOF'
#!/bin/bash
sudo systemctl status evilginx --no-pager -l
EOF
    chmod +x /usr/local/bin/evilginx-status
    
    # Create logs script
    cat > /usr/local/bin/evilginx-logs << 'EOF'
#!/bin/bash
sudo journalctl -u evilginx -f
EOF
    chmod +x /usr/local/bin/evilginx-logs
    
    # Create console script
    cat > /usr/local/bin/evilginx-console << EOF
#!/bin/bash
echo "Stopping systemd service to run interactively..."
sudo systemctl stop evilginx
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
    echo "  • Evilginx Binary:      /usr/local/bin/evilginx (wrapper)"
    echo "  • Actual Binary:        $INSTALL_DIR/evilginx.bin"
    echo "  • Phishlets Directory:  $PHISHLETS_DIR"
    echo "  • Redirectors Directory: $REDIRECTORS_DIR"
    echo "  • Configuration:        $CONFIG_DIR"
    echo "  • Logs:                 $LOG_DIR"
    echo "  • Running as:           Admin (root)"
    echo "  • Systemd Service:      evilginx.service"
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
    echo "   config ipv4 external $(curl -s ifconfig.me)"
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
    echo "  • Main Guide:           $INSTALL_DIR/DEPLOYMENT_GUIDE.md"
    echo "  • Lure Randomization:   $INSTALL_DIR/LURE_RANDOMIZATION_GUIDE.md"
    echo "  • README:               $INSTALL_DIR/README.md"
    echo ""
    
    echo -e "${CYAN}Quick Start:${NC}"
    echo "  1. evilginx-console     # Configure interactively"
    echo "  2. <configure settings> # Set domain, IP, phishlets"
    echo "  3. exit or Ctrl+C       # Exit console"
    echo "  4. evilginx-start       # Start service"
    echo "  5. evilginx-status      # Verify running"
    echo ""
    
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

#############################################################################
# Main Installation Flow
#############################################################################

main() {
    print_banner
    
    # Pre-installation checks
    check_root
    detect_os
    confirm_installation
    
    # Installation steps
    update_system
    install_dependencies
    install_go
    setup_directories
    stop_conflicting_services
    disable_systemd_resolved
    build_evilginx
    configure_firewall
    configure_fail2ban
    create_systemd_service
    configure_capabilities
    create_helper_scripts
    
    # Completion
    display_completion
    
    log_success "Installation complete! Review the information above."
}

# Run main installation
main

exit 0

