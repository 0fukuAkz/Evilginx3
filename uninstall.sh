#!/bin/bash

#############################################################################
# Evilginx 3.3.1 - Private Dev Edition - Uninstaller
#############################################################################
# This script completely removes Evilginx and cleans up all traces
#
# What this script does:
# - Stops and disables the systemd service
# - Removes the Evilginx binary and files
# - Removes the service user
# - Removes firewall rules (optional)
# - Cleans up configuration and logs
# - Removes helper scripts
#
# Usage:
#   sudo ./uninstall.sh
#
# Author: AKaZA (Akz0fuku)
# Version: 1.0.0
#############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration (must match install.sh)
INSTALL_DIR="/opt/evilginx"
SERVICE_USER="evilginx"
CONFIG_DIR="/etc/evilginx"
LOG_DIR="/var/log/evilginx"

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
║                        UNINSTALLER                                ║
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

confirm_uninstall() {
    echo -e "${YELLOW}"
    cat << EOF

⚠️  WARNING: This will completely remove Evilginx from your system!

The following will be deleted:
   • Systemd service: evilginx.service
   • Installation directory: $INSTALL_DIR
   • Configuration directory: $CONFIG_DIR
   • Log directory: $LOG_DIR
   • Service user: $SERVICE_USER
   • Helper scripts in /usr/local/bin/evilginx-*
   • All captured sessions and data

⚠️  This action CANNOT be undone!

EOF
    echo -e "${NC}"
    
    read -p "Are you sure you want to uninstall Evilginx? (yes/NO): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_error "Uninstall cancelled by user"
        exit 0
    fi
}

stop_service() {
    log_step "Step 1: Stopping Evilginx Service"
    
    if systemctl is-active --quiet evilginx 2>/dev/null; then
        systemctl stop evilginx
        log_success "Service stopped"
    else
        log_info "Service not running"
    fi
    
    if systemctl is-enabled --quiet evilginx 2>/dev/null; then
        systemctl disable evilginx
        log_success "Service disabled"
    fi
}

remove_service_file() {
    log_step "Step 2: Removing Systemd Service"
    
    if [[ -f /etc/systemd/system/evilginx.service ]]; then
        rm -f /etc/systemd/system/evilginx.service
        systemctl daemon-reload
        log_success "Systemd service file removed"
    else
        log_info "Service file not found"
    fi
}

remove_files() {
    log_step "Step 3: Removing Installation Files"
    
    if [[ -d "$INSTALL_DIR" ]]; then
        log_warning "Removing $INSTALL_DIR..."
        rm -rf "$INSTALL_DIR"
        log_success "Installation directory removed"
    else
        log_info "Installation directory not found"
    fi
    
    if [[ -d "$CONFIG_DIR" ]]; then
        log_warning "Removing configuration: $CONFIG_DIR"
        # Backup before deletion (optional)
        if [[ -f "$CONFIG_DIR/config.json" ]]; then
            BACKUP="/tmp/evilginx_config_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
            tar -czf "$BACKUP" -C "$CONFIG_DIR" . 2>/dev/null || true
            log_info "Configuration backed up to: $BACKUP"
        fi
        rm -rf "$CONFIG_DIR"
        log_success "Configuration directory removed"
    fi
    
    if [[ -d "$LOG_DIR" ]]; then
        log_warning "Removing logs: $LOG_DIR"
        rm -rf "$LOG_DIR"
        log_success "Log directory removed"
    fi
}

remove_user() {
    log_step "Step 4: Removing Service User"
    
    if id "$SERVICE_USER" &>/dev/null; then
        # Kill any processes owned by the user
        pkill -u "$SERVICE_USER" 2>/dev/null || true
        sleep 1
        
        # Remove user
        userdel -r "$SERVICE_USER" 2>/dev/null || userdel "$SERVICE_USER" 2>/dev/null || true
        log_success "User $SERVICE_USER removed"
    else
        log_info "User $SERVICE_USER not found"
    fi
}

remove_helper_scripts() {
    log_step "Step 5: Removing Helper Scripts"
    
    SCRIPTS=(
        "/usr/local/bin/evilginx-start"
        "/usr/local/bin/evilginx-stop"
        "/usr/local/bin/evilginx-restart"
        "/usr/local/bin/evilginx-status"
        "/usr/local/bin/evilginx-logs"
        "/usr/local/bin/evilginx-console"
    )
    
    for script in "${SCRIPTS[@]}"; do
        if [[ -f "$script" ]]; then
            rm -f "$script"
            log_success "Removed: $script"
        fi
    done
}

cleanup_firewall() {
    log_step "Step 6: Firewall Cleanup (Optional)"
    
    echo -e "${YELLOW}"
    read -p "Remove firewall rules for ports 53, 80, 443? (y/N): " -n 1 -r
    echo -e "${NC}"
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Removing firewall rules..."
        
        # Remove specific rules
        ufw delete allow 53/tcp 2>/dev/null || true
        ufw delete allow 53/udp 2>/dev/null || true
        ufw delete allow 80/tcp 2>/dev/null || true
        ufw delete allow 443/tcp 2>/dev/null || true
        
        log_success "Firewall rules removed"
        log_warning "SSH (port 22) rule kept for safety"
    else
        log_info "Firewall rules kept (skipped)"
    fi
}

secure_delete_data() {
    log_step "Step 7: Secure Data Deletion"
    
    echo -e "${YELLOW}"
    read -p "Securely wipe all Evilginx data? (recommended for post-engagement) (y/N): " -n 1 -r
    echo -e "${NC}"
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_warning "Performing secure deletion (this may take time)..."
        
        # Find and securely delete database files
        find /tmp -name "*.db" -path "*/evilginx/*" -exec shred -vfz -n 10 {} \; 2>/dev/null || true
        find /var -name "*.db" -path "*/evilginx/*" -exec shred -vfz -n 10 {} \; 2>/dev/null || true
        
        # Clear bash history
        history -c 2>/dev/null || true
        
        # Clear system logs related to evilginx
        journalctl --rotate 2>/dev/null || true
        journalctl --vacuum-time=1s 2>/dev/null || true
        
        log_success "Secure deletion completed"
    else
        log_info "Secure deletion skipped"
    fi
}

remove_go() {
    log_step "Step 8: Remove Go (Optional)"
    
    echo -e "${YELLOW}"
    read -p "Remove Go programming language? (y/N): " -n 1 -r
    echo -e "${NC}"
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [[ -d "/usr/local/go" ]]; then
            rm -rf /usr/local/go
            
            # Remove from PATH in /etc/profile
            sed -i '/\/usr\/local\/go\/bin/d' /etc/profile 2>/dev/null || true
            
            log_success "Go removed"
        else
            log_info "Go not found"
        fi
    else
        log_info "Go kept (skipped)"
    fi
}

display_completion() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                   ║${NC}"
    echo -e "${GREEN}║          ✓ UNINSTALLATION COMPLETED SUCCESSFULLY!                ║${NC}"
    echo -e "${GREEN}║                                                                   ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log_step "Uninstallation Summary"
    
    echo -e "${CYAN}Removed:${NC}"
    echo "  ✓ Evilginx service"
    echo "  ✓ Installation files ($INSTALL_DIR)"
    echo "  ✓ Configuration files ($CONFIG_DIR)"
    echo "  ✓ Log files ($LOG_DIR)"
    echo "  ✓ Service user ($SERVICE_USER)"
    echo "  ✓ Helper scripts"
    echo ""
    
    if [[ -f "/tmp/evilginx_config_backup_"*.tar.gz ]]; then
        echo -e "${YELLOW}Backup created:${NC}"
        ls -lh /tmp/evilginx_config_backup_*.tar.gz 2>/dev/null || true
        echo ""
    fi
    
    echo -e "${YELLOW}Post-Uninstall Recommendations:${NC}"
    echo ""
    echo "  • Review firewall rules: sudo ufw status"
    echo "  • Check for remaining files: find / -name '*evilginx*' 2>/dev/null"
    echo "  • Remove DNS records from Cloudflare"
    echo "  • Delete domain or let it expire"
    echo "  • Review system logs: journalctl -b"
    echo ""
    
    log_success "Evilginx has been completely removed from your system"
}

main() {
    print_banner
    
    check_root
    confirm_uninstall
    
    stop_service
    remove_service_file
    remove_files
    remove_user
    remove_helper_scripts
    cleanup_firewall
    secure_delete_data
    remove_go
    
    display_completion
}

main

exit 0

