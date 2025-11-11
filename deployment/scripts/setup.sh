#!/bin/bash
#
# Evilginx2 Setup Script
# This script sets up Evilginx2 on a fresh server
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_PATH="${INSTALL_PATH:-/opt/evilginx}"
SERVICE_NAME="${SERVICE_NAME:-evilginx2}"
DOMAIN="${DOMAIN:-}"
EXTERNAL_IP="${EXTERNAL_IP:-}"
HTTPS_PORT="${HTTPS_PORT:-443}"
DNS_PORT="${DNS_PORT:-53}"

# Functions
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        print_error "Cannot detect OS"
        exit 1
    fi
    
    print_info "Detected OS: $OS $VER"
}

# Install dependencies based on OS
install_dependencies() {
    print_info "Installing dependencies..."
    
    if [[ "$OS" == "Ubuntu" ]] || [[ "$OS" == "Debian"* ]]; then
        apt-get update -y
        apt-get install -y \
            wget \
            curl \
            git \
            build-essential \
            net-tools \
            dnsutils \
            jq \
            certbot
    elif [[ "$OS" == "CentOS"* ]] || [[ "$OS" == "Red Hat"* ]]; then
        yum update -y
        yum install -y \
            wget \
            curl \
            git \
            gcc \
            make \
            net-tools \
            bind-utils \
            jq \
            certbot
    else
        print_error "Unsupported OS: $OS"
        exit 1
    fi
}

# Install Go
install_go() {
    GO_VERSION="1.21.5"
    
    if command -v go &> /dev/null; then
        print_info "Go is already installed"
        go version
        return
    fi
    
    print_info "Installing Go $GO_VERSION..."
    
    cd /tmp
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    rm "go${GO_VERSION}.linux-amd64.tar.gz"
    
    # Add Go to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    
    go version
}

# Create directory structure
create_directories() {
    print_info "Creating directory structure..."
    
    mkdir -p "$INSTALL_PATH"/{phishlets,redirectors,data}
    mkdir -p /etc/evilginx
    mkdir -p /var/log/evilginx
}

# Download or build Evilginx
install_evilginx() {
    print_info "Installing Evilginx..."
    
    cd "$INSTALL_PATH"
    
    # Try to download pre-built binary
    if wget -q -O evilginx "https://github.com/kgretzky/evilginx2/releases/latest/download/evilginx-linux-amd64" 2>/dev/null; then
        chmod +x evilginx
        print_info "Downloaded pre-built binary"
    else
        # Build from source
        print_info "Building from source..."
        
        cd /tmp
        rm -rf evilginx2
        git clone https://github.com/kgretzky/evilginx2
        cd evilginx2
        
        export PATH=$PATH:/usr/local/go/bin
        go build -o "$INSTALL_PATH/evilginx" .
        
        # Copy phishlets and redirectors
        cp -r phishlets/* "$INSTALL_PATH/phishlets/" 2>/dev/null || true
        cp -r redirectors/* "$INSTALL_PATH/redirectors/" 2>/dev/null || true
        
        cd /tmp
        rm -rf evilginx2
    fi
    
    # Make executable
    chmod +x "$INSTALL_PATH/evilginx"
}

# Configure Evilginx
configure_evilginx() {
    print_info "Configuring Evilginx..."
    
    # Detect external IP if not provided
    if [[ -z "$EXTERNAL_IP" ]]; then
        EXTERNAL_IP=$(curl -s https://api.ipify.org)
        print_info "Detected external IP: $EXTERNAL_IP"
    fi
    
    # Create config
    cat > /etc/evilginx/config.json <<EOF
{
  "general": {
    "domain": "${DOMAIN}",
    "external_ipv4": "${EXTERNAL_IP}",
    "bind_ipv4": "0.0.0.0",
    "https_port": ${HTTPS_PORT},
    "dns_port": ${DNS_PORT},
    "autocert": true
  },
  "blacklist": {
    "mode": "unauth"
  }
}
EOF
    
    print_info "Configuration written to /etc/evilginx/config.json"
}

# Setup systemd service
setup_service() {
    print_info "Setting up systemd service..."
    
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Evilginx2 Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_PATH}
ExecStart=${INSTALL_PATH}/evilginx -p /etc/evilginx
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/evilginx ${INSTALL_PATH} /var/log/evilginx

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    print_info "Service ${SERVICE_NAME} created and enabled"
}

# Configure firewall
configure_firewall() {
    print_info "Configuring firewall..."
    
    if [[ "$OS" == "Ubuntu" ]] || [[ "$OS" == "Debian"* ]]; then
        # Check if ufw is installed
        if command -v ufw &> /dev/null; then
            ufw --force enable
            ufw allow 22/tcp
            ufw allow "${HTTPS_PORT}/tcp"
            ufw allow "${DNS_PORT}/tcp"
            ufw allow "${DNS_PORT}/udp"
            ufw reload
            print_info "UFW firewall configured"
        else
            print_warn "UFW not found, skipping firewall configuration"
        fi
    elif [[ "$OS" == "CentOS"* ]] || [[ "$OS" == "Red Hat"* ]]; then
        # Check if firewalld is running
        if systemctl is-active firewalld &> /dev/null; then
            firewall-cmd --permanent --add-port="${HTTPS_PORT}/tcp"
            firewall-cmd --permanent --add-port="${DNS_PORT}/tcp"
            firewall-cmd --permanent --add-port="${DNS_PORT}/udp"
            firewall-cmd --reload
            print_info "Firewalld configured"
        else
            print_warn "Firewalld not active, skipping firewall configuration"
        fi
    fi
}

# Configure system settings
configure_system() {
    print_info "Configuring system settings..."
    
    # Increase file limits
    cat >> /etc/security/limits.conf <<EOF
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
EOF
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    sysctl -p
    
    # Disable systemd-resolved if it's using port 53
    if systemctl is-active systemd-resolved &> /dev/null; then
        print_warn "Disabling systemd-resolved to free up port 53..."
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved
        
        # Update resolv.conf
        rm -f /etc/resolv.conf
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
        echo "nameserver 8.8.4.4" >> /etc/resolv.conf
    fi
}

# Start service
start_service() {
    print_info "Starting Evilginx service..."
    
    systemctl start "$SERVICE_NAME"
    sleep 5
    
    if systemctl is-active "$SERVICE_NAME" &> /dev/null; then
        print_info "Service started successfully"
        systemctl status "$SERVICE_NAME" --no-pager
    else
        print_error "Service failed to start"
        journalctl -u "$SERVICE_NAME" -n 50 --no-pager
        exit 1
    fi
}

# Verify installation
verify_installation() {
    print_info "Verifying installation..."
    
    # Check if binary exists
    if [[ ! -f "$INSTALL_PATH/evilginx" ]]; then
        print_error "Evilginx binary not found"
        return 1
    fi
    
    # Check if service is running
    if ! systemctl is-active "$SERVICE_NAME" &> /dev/null; then
        print_error "Service is not running"
        return 1
    fi
    
    # Check if ports are listening
    if command -v ss &> /dev/null; then
        if ! ss -tlnp | grep -q ":${HTTPS_PORT} "; then
            print_error "HTTPS port ${HTTPS_PORT} is not listening"
            return 1
        fi
        
        if ! ss -tlnp | grep -q ":${DNS_PORT} "; then
            print_error "DNS port ${DNS_PORT} is not listening"
            return 1
        fi
    fi
    
    print_info "Installation verified successfully"
    return 0
}

# Show post-installation info
show_info() {
    echo
    echo "=========================================="
    echo "Evilginx2 Installation Complete!"
    echo "=========================================="
    echo
    echo "Installation path: $INSTALL_PATH"
    echo "Service name: $SERVICE_NAME"
    echo "Configuration: /etc/evilginx/config.json"
    echo
    echo "Domain: ${DOMAIN:-Not set}"
    echo "External IP: $EXTERNAL_IP"
    echo "HTTPS Port: $HTTPS_PORT"
    echo "DNS Port: $DNS_PORT"
    echo
    echo "Commands:"
    echo "  systemctl status $SERVICE_NAME    # Check status"
    echo "  systemctl restart $SERVICE_NAME   # Restart service"
    echo "  journalctl -u $SERVICE_NAME -f    # View logs"
    echo "  $INSTALL_PATH/evilginx            # Run manually"
    echo
    echo "=========================================="
    echo
    
    if [[ -n "$DOMAIN" ]]; then
        echo "Next steps:"
        echo "1. Point your domain's nameservers to this server"
        echo "2. Configure phishlets for your domain"
        echo "3. Test the setup"
    else
        print_warn "No domain configured. You'll need to set this up manually."
    fi
}

# Main installation flow
main() {
    print_info "Starting Evilginx2 installation..."
    
    check_root
    detect_os
    install_dependencies
    install_go
    create_directories
    install_evilginx
    configure_evilginx
    configure_system
    setup_service
    configure_firewall
    start_service
    
    if verify_installation; then
        show_info
    else
        print_error "Installation verification failed!"
        exit 1
    fi
}

# Run main function
main "$@"
