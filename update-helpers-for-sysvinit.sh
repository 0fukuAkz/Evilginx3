#!/bin/bash

#############################################################################
# Update Evilginx Helper Scripts for sysvinit
# 
# This script updates the evilginx helper scripts to use sysvinit
# instead of systemd commands.
#
# Usage:
#   sudo ./update-helpers-for-sysvinit.sh
#
#############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

log_info "Updating Evilginx helper scripts for sysvinit..."

# Update evilginx-start
if [[ -f /usr/local/bin/evilginx-start ]]; then
    cat > /usr/local/bin/evilginx-start << 'EOF'
#!/bin/bash
sudo /etc/init.d/evilginx start
sudo /etc/init.d/evilginx status
EOF
    chmod +x /usr/local/bin/evilginx-start
    log_success "Updated evilginx-start"
fi

# Update evilginx-stop
if [[ -f /usr/local/bin/evilginx-stop ]]; then
    cat > /usr/local/bin/evilginx-stop << 'EOF'
#!/bin/bash
sudo /etc/init.d/evilginx stop
echo "Evilginx stopped"
EOF
    chmod +x /usr/local/bin/evilginx-stop
    log_success "Updated evilginx-stop"
fi

# Update evilginx-restart
if [[ -f /usr/local/bin/evilginx-restart ]]; then
    cat > /usr/local/bin/evilginx-restart << 'EOF'
#!/bin/bash
sudo /etc/init.d/evilginx restart
sudo /etc/init.d/evilginx status
EOF
    chmod +x /usr/local/bin/evilginx-restart
    log_success "Updated evilginx-restart"
fi

# Update evilginx-status
if [[ -f /usr/local/bin/evilginx-status ]]; then
    cat > /usr/local/bin/evilginx-status << 'EOF'
#!/bin/bash
sudo /etc/init.d/evilginx status
EOF
    chmod +x /usr/local/bin/evilginx-status
    log_success "Updated evilginx-status"
fi

# Update evilginx-logs (no journalctl, use file logs)
if [[ -f /usr/local/bin/evilginx-logs ]]; then
    cat > /usr/local/bin/evilginx-logs << 'EOF'
#!/bin/bash
if [[ -f /var/log/evilginx/evilginx.log ]]; then
    sudo tail -f /var/log/evilginx/evilginx.log
elif [[ -f /opt/evilginx/evilginx.log ]]; then
    sudo tail -f /opt/evilginx/evilginx.log
else
    echo "Evilginx log file not found. Check /var/log/evilginx/ or /opt/evilginx/"
fi
EOF
    chmod +x /usr/local/bin/evilginx-logs
    log_success "Updated evilginx-logs"
fi

log_success "All helper scripts updated for sysvinit!"
log_info "You can now use: evilginx-start, evilginx-stop, evilginx-restart, evilginx-status, evilginx-logs"

