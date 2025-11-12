#!/bin/bash

#############################################################################
# Remove systemd from Debian Permanently
# 
# WARNING: This script will:
# - Replace systemd with sysvinit (traditional Debian init system)
# - Remove all systemd packages
# - Convert systemd services to sysvinit scripts
# - This is IRREVERSIBLE without a backup
#
# REQUIREMENTS:
# - Full system backup recommended
# - Root access
# - Debian-based system
# - Physical or console access (SSH may break during transition)
#
# Usage:
#   sudo ./remove-systemd.sh
#
#############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Logging functions
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

log_step() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}▶${NC} $1"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        echo "Usage: sudo $0"
        exit 1
    fi
}

# Check if running on Debian
check_debian() {
    if [[ ! -f /etc/debian_version ]]; then
        log_error "This script is designed for Debian-based systems only"
        exit 1
    fi
    
    DEBIAN_VERSION=$(cat /etc/debian_version)
    log_info "Detected Debian version: $DEBIAN_VERSION"
}

# Display warning and get confirmation
confirm_removal() {
    echo ""
    echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}${BOLD}           CRITICAL WARNING - READ CAREFULLY              ${NC}"
    echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}This script will PERMANENTLY remove systemd from your system.${NC}"
    echo ""
    echo -e "${RED}RISKS:${NC}"
    echo "  • System may become unbootable if something goes wrong"
    echo "  • SSH connections may be lost during transition"
    echo "  • Some services may not work correctly"
    echo "  • Some applications depend on systemd features"
    echo "  • Requires physical/console access"
    echo ""
    echo -e "${YELLOW}REQUIREMENTS:${NC}"
    echo "  • Full system backup (HIGHLY RECOMMENDED)"
    echo "  • Physical or console access to the machine"
    echo "  • Debian-based system"
    echo "  • Root access"
    echo ""
    echo -e "${YELLOW}WHAT WILL HAPPEN:${NC}"
    echo "  1. Install sysvinit-core (alternative init system)"
    echo "  2. Configure sysvinit as default init system"
    echo "  3. Convert systemd services to sysvinit scripts"
    echo "  4. Remove systemd packages"
    echo "  5. System will use sysvinit on next reboot"
    echo ""
    echo -e "${RED}THIS OPERATION CANNOT BE EASILY UNDONE!${NC}"
    echo ""
    read -p "Type 'YES REMOVE SYSTEMD' to confirm: " confirmation
    
    if [[ "$confirmation" != "YES REMOVE SYSTEMD" ]]; then
        log_error "Confirmation failed. Exiting."
        exit 1
    fi
    
    echo ""
    read -p "Have you created a full system backup? (yes/no): " backup_confirm
    
    if [[ "$backup_confirm" != "yes" ]]; then
        log_warning "No backup confirmed. This is risky!"
        read -p "Continue anyway? (yes/no): " continue_anyway
        if [[ "$continue_anyway" != "yes" ]]; then
            log_error "Aborted by user"
            exit 1
        fi
    fi
}

# Create backup of critical files
create_backup() {
    log_step "Creating Backup of Critical Files"
    
    BACKUP_DIR="/root/systemd-removal-backup-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    log_info "Backing up to: $BACKUP_DIR"
    
    # Backup systemd service files
    if [[ -d /etc/systemd ]]; then
        cp -r /etc/systemd "$BACKUP_DIR/"
        log_success "Backed up /etc/systemd"
    fi
    
    # Backup init system configuration
    if [[ -f /etc/inittab ]]; then
        cp /etc/inittab "$BACKUP_DIR/"
        log_success "Backed up /etc/inittab"
    fi
    
    # Backup grub configuration
    if [[ -f /etc/default/grub ]]; then
        cp /etc/default/grub "$BACKUP_DIR/"
        log_success "Backed up /etc/default/grub"
    fi
    
    # Backup current init system info
    ls -la /sbin/init > "$BACKUP_DIR/init_symlink.txt" 2>/dev/null || true
    readlink -f /sbin/init > "$BACKUP_DIR/init_target.txt" 2>/dev/null || true
    
    # List installed systemd packages
    dpkg -l | grep systemd > "$BACKUP_DIR/systemd_packages.txt" 2>/dev/null || true
    
    log_success "Backup created at: $BACKUP_DIR"
    echo "$BACKUP_DIR" > /root/.systemd-removal-backup-path
}

# Install sysvinit-core
install_sysvinit() {
    log_step "Installing sysvinit-core"
    
    log_info "Updating package lists..."
    apt-get update -qq
    
    log_info "Installing sysvinit-core..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y sysvinit-core sysvinit-utils
    
    log_success "sysvinit-core installed"
}

# Convert evilginx systemd service to sysvinit script
convert_evilginx_service() {
    log_step "Converting Evilginx Service to sysvinit"
    
    if [[ ! -f /etc/systemd/system/evilginx.service ]]; then
        log_warning "Evilginx systemd service not found - skipping conversion"
        return
    fi
    
    # Extract service information from systemd service file
    SERVICE_USER=$(grep "^User=" /etc/systemd/system/evilginx.service | cut -d= -f2 || echo "root")
    WORKING_DIR=$(grep "^WorkingDirectory=" /etc/systemd/system/evilginx.service | cut -d= -f2 || echo "/opt/evilginx")
    EXEC_START=$(grep "^ExecStart=" /etc/systemd/system/evilginx.service | cut -d= -f2 || echo "/usr/local/bin/evilginx")
    CONFIG_DIR=$(echo "$EXEC_START" | grep -oP '(?<=-c\s)\S+' || echo "/etc/evilginx")
    
    # Create sysvinit script
    cat > /etc/init.d/evilginx << 'EOFSCRIPT'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          evilginx
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Evilginx 3.3.1 Service
# Description:       Evilginx phishing framework service
### END INIT INFO

# Service configuration
SERVICE_NAME="evilginx"
SERVICE_USER="root"
WORKING_DIR="/opt/evilginx"
EXEC_BIN="/usr/local/bin/evilginx"
CONFIG_DIR="/etc/evilginx"
PIDFILE="/var/run/evilginx.pid"

# Source function library
. /lib/lsb/init-functions

start() {
    log_daemon_msg "Starting $SERVICE_NAME"
    
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        log_end_msg 1 "$SERVICE_NAME is already running"
        return 1
    fi
    
    cd "$WORKING_DIR" || exit 1
    
    start-stop-daemon --start --quiet --background \
        --make-pidfile --pidfile "$PIDFILE" \
        --chuid "$SERVICE_USER" \
        --chdir "$WORKING_DIR" \
        --exec "$EXEC_BIN" -- -c "$CONFIG_DIR"
    
    sleep 2
    
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        log_end_msg 0
        return 0
    else
        log_end_msg 1 "Failed to start $SERVICE_NAME"
        return 1
    fi
}

stop() {
    log_daemon_msg "Stopping $SERVICE_NAME"
    
    if [ ! -f "$PIDFILE" ]; then
        log_end_msg 1 "$SERVICE_NAME is not running"
        return 1
    fi
    
    PID=$(cat "$PIDFILE")
    
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID"
        sleep 2
        
        if kill -0 "$PID" 2>/dev/null; then
            kill -9 "$PID"
            sleep 1
        fi
        
        rm -f "$PIDFILE"
        log_end_msg 0
        return 0
    else
        rm -f "$PIDFILE"
        log_end_msg 1 "$SERVICE_NAME was not running"
        return 1
    fi
}

restart() {
    stop
    sleep 1
    start
}

status() {
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        PID=$(cat "$PIDFILE")
        echo "$SERVICE_NAME is running (PID: $PID)"
        return 0
    else
        echo "$SERVICE_NAME is not running"
        return 1
    fi
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    status)
        status
        ;;
    reload)
        restart
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|reload}"
        exit 1
        ;;
esac

exit $?
EOFSCRIPT
    
    # Update service configuration in script
    sed -i "s|SERVICE_USER=\".*\"|SERVICE_USER=\"$SERVICE_USER\"|" /etc/init.d/evilginx
    sed -i "s|WORKING_DIR=\".*\"|WORKING_DIR=\"$WORKING_DIR\"|" /etc/init.d/evilginx
    sed -i "s|EXEC_BIN=\".*\"|EXEC_BIN=\"$EXEC_START\"|" /etc/init.d/evilginx
    sed -i "s|CONFIG_DIR=\".*\"|CONFIG_DIR=\"$CONFIG_DIR\"|" /etc/init.d/evilginx
    
    chmod +x /etc/init.d/evilginx
    
    # Enable service
    update-rc.d evilginx defaults
    
    log_success "Evilginx sysvinit script created and enabled"
}

# Convert other critical services
convert_critical_services() {
    log_step "Converting Critical Services"
    
    # Convert networking service
    if systemctl list-unit-files | grep -q "networking.service"; then
        log_info "Networking service will be handled by sysvinit automatically"
    fi
    
    # Convert SSH service
    if systemctl list-unit-files | grep -q "ssh.service"; then
        log_info "SSH service will be handled by sysvinit automatically"
    fi
    
    log_success "Critical services will use sysvinit"
}

# Configure sysvinit as default
configure_sysvinit() {
    log_step "Configuring sysvinit as Default Init System"
    
    # Update GRUB to use sysvinit
    if [[ -f /etc/default/grub ]]; then
        log_info "Updating GRUB configuration..."
        
        # Backup grub
        cp /etc/default/grub /etc/default/grub.backup.$(date +%Y%m%d_%H%M%S)
        
        # Remove systemd from kernel parameters if present
        sed -i 's/ systemd[^ ]*//g' /etc/default/grub
        
        # Add init=/sbin/init.sysvinit if not present
        if ! grep -q "init=" /etc/default/grub; then
            sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="init=\/sbin\/init.sysvinit /' /etc/default/grub
        fi
        
        # Update GRUB
        if command -v update-grub &> /dev/null; then
            update-grub
            log_success "GRUB updated"
        fi
    fi
    
    # Create /etc/inittab if it doesn't exist
    if [[ ! -f /etc/inittab ]]; then
        log_info "Creating /etc/inittab..."
        cat > /etc/inittab << 'EOF'
# /etc/inittab: init(8) configuration.
# $Id: inittab,v 1.91 2002/01/25 13:35:21 miquels Exp $

# The default runlevel.
id:2:initdefault:

# Boot-time system configuration/initialization script.
# This is run first except when booting in emergency (-b) mode.
si::sysinit:/etc/init.d/rcS

# What to do in single-user mode.
~~:S:wait:/sbin/sulogin

# /etc/init.d executes the S and K scripts upon change
# of runlevel.
#
# Runlevel 0 is halt.
# Runlevel 1 is single-user.
# Runlevels 2-5 are multi-user.
# Runlevel 6 is reboot.

l0:0:wait:/etc/init.d/rc 0
l1:1:wait:/etc/init.d/rc 1
l2:2:wait:/etc/init.d/rc 2
l3:3:wait:/etc/init.d/rc 3
l4:4:wait:/etc/init.d/rc 4
l5:5:wait:/etc/init.d/rc 5
l6:6:wait:/etc/init.d/rc 6

# Normally not reached, but fallthrough in case of emergency.
z6:6:respawn:/sbin/sulogin

# What to do when CTRL-ALT-DEL is pressed.
ca:12345:ctrlaltdel:/sbin/shutdown -t1 -a -r now

# Action on special keypress (ALT-UpArrow).
#kb::kbrequest:/bin/echo "Keyboard Request--edit /etc/inittab to let this work."

# What to do when the power fails/returns.
pf::powerwait:/etc/init.d/powerfail start
pn::powerfailnow:/etc/init.d/powerfail now
po::powerokwait:/etc/init.d/powerfail stop

# /sbin/getty invocations for the runlevels.
#
# The "id" field MUST be the same as the last
# characters of the device (after "tty").
#
# Format:
#  <id>:<runlevels>:<action>:<process>
#
# Note that on most Debian systems tty7 is used by the X Window System,
# so if you want to add more getty's go ahead but skip tty7 if you run X.
#
1:2345:respawn:/sbin/getty 38400 tty1
2:23:respawn:/sbin/getty 38400 tty2
3:23:respawn:/sbin/getty 38400 tty3
4:23:respawn:/sbin/getty 38400 tty4
5:23:respawn:/sbin/getty 38400 tty5
6:23:respawn:/sbin/getty 38400 tty6

# Example how to put a getty on a serial line (for a terminal)
#
#T0:23:respawn:/sbin/getty -L ttyS0 9600 vt100
#T1:23:respawn:/sbin/getty -L ttyS1 9600 vt100

# Example how to put a getty on a modem line.
#
#T3:23:respawn:/sbin/mgetty -x0 -s 57600 ttyS3
EOF
        log_success "/etc/inittab created"
    fi
    
    # Update /sbin/init symlink
    log_info "Updating /sbin/init symlink..."
    if [[ -L /sbin/init ]]; then
        rm /sbin/init
    fi
    ln -sf /lib/sysvinit/init /sbin/init
    
    log_success "sysvinit configured as default init system"
}

# Remove systemd packages
remove_systemd() {
    log_step "Removing systemd Packages"
    
    log_warning "This will remove all systemd packages..."
    
    # List systemd packages first
    log_info "Systemd packages to be removed:"
    dpkg -l | grep -E "^ii.*systemd" | awk '{print "  " $2}'
    
    # Remove systemd packages
    log_info "Removing systemd packages..."
    
    # Remove in stages to avoid dependency issues
    DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y \
        systemd \
        systemd-sysv \
        libsystemd0 \
        2>&1 | grep -v "^WARNING" || true
    
    # Remove remaining systemd packages
    DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y 2>&1 | grep -v "^WARNING" || true
    
    log_success "Systemd packages removed"
}

# Final verification
verify_installation() {
    log_step "Verification"
    
    # Check init system
    INIT_TARGET=$(readlink -f /sbin/init 2>/dev/null || echo "unknown")
    log_info "Current init system: $INIT_TARGET"
    
    if echo "$INIT_TARGET" | grep -q "sysvinit"; then
        log_success "sysvinit is configured as init system"
    else
        log_warning "Init system may not be correctly configured"
    fi
    
    # Check if evilginx script exists
    if [[ -f /etc/init.d/evilginx ]]; then
        log_success "Evilginx sysvinit script exists"
    else
        log_warning "Evilginx sysvinit script not found"
    fi
    
    # Check backup
    if [[ -f /root/.systemd-removal-backup-path ]]; then
        BACKUP_PATH=$(cat /root/.systemd-removal-backup-path)
        log_success "Backup available at: $BACKUP_PATH"
    fi
}

# Display completion message
display_completion() {
    log_step "Removal Complete"
    
    echo ""
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}           systemd Removal Complete                        ${NC}"
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${YELLOW}IMPORTANT:${NC}"
    echo "  1. System will use sysvinit on next reboot"
    echo "  2. Reboot is REQUIRED for changes to take effect"
    echo "  3. Have physical/console access ready"
    echo "  4. SSH may be interrupted during reboot"
    echo ""
    
    echo -e "${YELLOW}After reboot, use these commands:${NC}"
    echo "  # Start Evilginx"
    echo "  sudo /etc/init.d/evilginx start"
    echo ""
    echo "  # Stop Evilginx"
    echo "  sudo /etc/init.d/evilginx stop"
    echo ""
    echo "  # Check status"
    echo "  sudo /etc/init.d/evilginx status"
    echo ""
    echo "  # Or use service command"
    echo "  sudo service evilginx start"
    echo ""
    
    if [[ -f /root/.systemd-removal-backup-path ]]; then
        BACKUP_PATH=$(cat /root/.systemd-removal-backup-path)
        echo -e "${YELLOW}Backup location:${NC} $BACKUP_PATH"
        echo ""
    fi
    
    echo -e "${RED}WARNING:${NC} Do not reboot yet if you need to make any adjustments!"
    echo ""
}

#############################################################################
# Main Function
#############################################################################

main() {
    echo -e "${CYAN}${BOLD}"
    echo "═══════════════════════════════════════════════════════════"
    echo "     systemd Removal Script for Debian"
    echo "     WARNING: This is a MAJOR system change"
    echo "═══════════════════════════════════════════════════════════"
    echo -e "${NC}"
    
    check_root
    check_debian
    confirm_removal
    
    create_backup
    install_sysvinit
    convert_evilginx_service
    convert_critical_services
    configure_sysvinit
    remove_systemd
    verify_installation
    display_completion
    
    log_success "Script completed successfully"
    log_warning "REBOOT REQUIRED - Use: sudo reboot"
}

# Run main function
main "$@"

exit 0

