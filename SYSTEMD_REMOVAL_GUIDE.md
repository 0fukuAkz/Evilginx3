# systemd Removal Guide for Debian

## ⚠️ CRITICAL WARNING

**Removing systemd is a MAJOR system change that can make your system unbootable if not done correctly.**

### Risks:
- System may become unbootable
- SSH connections may be lost during transition
- Some services may not work correctly
- Some applications depend on systemd features
- Requires physical/console access

### Requirements:
- ✅ Full system backup (HIGHLY RECOMMENDED)
- ✅ Physical or console access to the machine
- ✅ Debian-based system
- ✅ Root access
- ✅ Time to troubleshoot if issues arise

---

## Overview

This guide explains how to permanently remove systemd from Debian and replace it with sysvinit (the traditional Debian init system).

### What is systemd?

systemd is the default init system and service manager for most modern Linux distributions, including Debian. It handles:
- System initialization
- Service management
- Process tracking
- Logging (journald)
- Device management
- Network management

### Why Remove systemd?

Some reasons you might want to remove systemd:
- Prefer traditional Unix init systems
- Reduce system complexity
- Avoid systemd-resolved DNS conflicts (though this can be disabled without removing systemd)
- System resource constraints
- Compatibility with older software

**Note:** For Evilginx, you typically only need to disable `systemd-resolved`, not remove systemd entirely. See `disable-systemd-resolved.sh` for that simpler approach.

---

## Prerequisites

### 1. Create a Full System Backup

**This is CRITICAL!** Before proceeding, create a full system backup:

```bash
# Using tar (example)
sudo tar -czf /backup/system-backup-$(date +%Y%m%d).tar.gz \
    --exclude=/backup \
    --exclude=/proc \
    --exclude=/sys \
    --exclude=/dev \
    --exclude=/run \
    --exclude=/tmp \
    /

# Or use your preferred backup tool (rsync, dd, etc.)
```

### 2. Ensure Physical/Console Access

You **MUST** have physical or console access to the machine. SSH connections may be lost during the transition.

### 3. Verify Debian System

```bash
cat /etc/debian_version
cat /etc/os-release
```

---

## Automated Removal Script

The `remove-systemd.sh` script automates the entire process:

```bash
# Make executable
chmod +x remove-systemd.sh

# Run with root privileges
sudo ./remove-systemd.sh
```

### What the Script Does:

1. **Creates Backup** - Backs up critical system files
2. **Installs sysvinit-core** - Installs the alternative init system
3. **Converts Services** - Converts systemd services to sysvinit scripts
4. **Configures sysvinit** - Sets sysvinit as the default init system
5. **Removes systemd** - Removes systemd packages
6. **Verifies Installation** - Checks that everything is configured correctly

### Script Safety Features:

- ✅ Extensive warnings and confirmations
- ✅ Automatic backup creation
- ✅ Service conversion for Evilginx
- ✅ Verification steps
- ✅ Rollback information

---

## Manual Removal Process

If you prefer to do it manually or the script doesn't work:

### Step 1: Install sysvinit-core

```bash
sudo apt-get update
sudo apt-get install -y sysvinit-core sysvinit-utils
```

### Step 2: Create /etc/inittab

```bash
sudo cat > /etc/inittab << 'EOF'
id:2:initdefault:
si::sysinit:/etc/init.d/rcS
l0:0:wait:/etc/init.d/rc 0
l1:1:wait:/etc/init.d/rc 1
l2:2:wait:/etc/init.d/rc 2
l3:3:wait:/etc/init.d/rc 3
l4:4:wait:/etc/init.d/rc 4
l5:5:wait:/etc/init.d/rc 5
l6:6:wait:/etc/init.d/rc 6
ca:12345:ctrlaltdel:/sbin/shutdown -t1 -a -r now
1:2345:respawn:/sbin/getty 38400 tty1
2:23:respawn:/sbin/getty 38400 tty2
3:23:respawn:/sbin/getty 38400 tty3
4:23:respawn:/sbin/getty 38400 tty4
5:23:respawn:/sbin/getty 38400 tty5
6:23:respawn:/sbin/getty 38400 tty6
EOF
```

### Step 3: Update GRUB Configuration

```bash
# Backup GRUB config
sudo cp /etc/default/grub /etc/default/grub.backup

# Edit GRUB config
sudo nano /etc/default/grub

# Remove systemd from kernel parameters and add init parameter:
# GRUB_CMDLINE_LINUX_DEFAULT="quiet init=/sbin/init.sysvinit"

# Update GRUB
sudo update-grub
```

### Step 4: Update /sbin/init Symlink

```bash
sudo rm /sbin/init
sudo ln -sf /lib/sysvinit/init /sbin/init
```

### Step 5: Convert Evilginx Service

Create `/etc/init.d/evilginx`:

```bash
sudo nano /etc/init.d/evilginx
```

See the script for the complete init script template.

Enable the service:

```bash
sudo chmod +x /etc/init.d/evilginx
sudo update-rc.d evilginx defaults
```

### Step 6: Remove systemd Packages

```bash
# Remove systemd
sudo apt-get remove --purge -y systemd systemd-sysv libsystemd0

# Clean up dependencies
sudo apt-get autoremove --purge -y
```

### Step 7: Reboot

```bash
sudo reboot
```

**⚠️ IMPORTANT:** Have console access ready!

---

## After Removal - Using sysvinit

### Service Management

With sysvinit, services are managed differently:

```bash
# Start a service
sudo /etc/init.d/evilginx start
# OR
sudo service evilginx start

# Stop a service
sudo /etc/init.d/evilginx stop
# OR
sudo service evilginx stop

# Restart a service
sudo /etc/init.d/evilginx restart
# OR
sudo service evilginx restart

# Check status
sudo /etc/init.d/evilginx status
# OR
sudo service evilginx status

# Enable service on boot
sudo update-rc.d evilginx defaults

# Disable service on boot
sudo update-rc.d evilginx remove
```

### Runlevels

sysvinit uses runlevels:

- **0** - Halt
- **1** - Single-user mode
- **2** - Multi-user (default on Debian)
- **3** - Multi-user with networking
- **4** - Unused
- **5** - Multi-user with networking and X11
- **6** - Reboot

Check current runlevel:

```bash
runlevel
```

Change runlevel:

```bash
sudo init 3  # Switch to runlevel 3
```

### Logging

Without systemd, you won't have `journalctl`. Use traditional logging:

```bash
# View Evilginx logs (if configured)
sudo tail -f /var/log/evilginx/evilginx.log

# View system logs
sudo tail -f /var/log/syslog
sudo tail -f /var/log/messages

# View service-specific logs
sudo tail -f /var/log/evilginx/evilginx.log
```

---

## Troubleshooting

### System Won't Boot

If the system won't boot after removal:

1. Boot from a live CD/USB
2. Mount your root filesystem
3. Restore the backup or fix the configuration
4. Check `/etc/inittab` and `/sbin/init` symlink

### Services Not Starting

Check service scripts:

```bash
# Check if script exists and is executable
ls -la /etc/init.d/evilginx

# Test script manually
sudo /etc/init.d/evilginx start

# Check for errors
sudo /etc/init.d/evilginx status
```

### Network Not Working

Check networking service:

```bash
sudo /etc/init.d/networking restart
sudo ifconfig
sudo route -n
```

### SSH Not Working

If SSH doesn't start automatically:

```bash
# Start SSH manually
sudo /etc/init.d/ssh start

# Enable on boot
sudo update-rc.d ssh defaults
```

---

## Rollback (If Needed)

If you need to restore systemd:

### From Backup

1. Boot from live CD/USB
2. Mount root filesystem
3. Restore backup files from `/root/systemd-removal-backup-*`
4. Reinstall systemd packages
5. Restore GRUB configuration
6. Reboot

### Reinstall systemd

```bash
# Install systemd back
sudo apt-get update
sudo apt-get install --reinstall systemd systemd-sysv

# Restore /sbin/init
sudo rm /sbin/init
sudo ln -sf /lib/systemd/systemd /sbin/init

# Restore GRUB (remove init= parameter)
sudo nano /etc/default/grub
sudo update-grub

# Reboot
sudo reboot
```

---

## Alternative: Just Disable systemd-resolved

**For most Evilginx users, you don't need to remove systemd entirely!**

If you only need to free port 53 for Evilginx's DNS server, just disable `systemd-resolved`:

```bash
# Use the provided script
sudo ./disable-systemd-resolved.sh

# Or manually:
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo systemctl mask systemd-resolved
```

This is much safer and easier to reverse.

---

## Comparison: systemd vs sysvinit

| Feature | systemd | sysvinit |
|---------|---------|----------|
| **Service Management** | `systemctl start/stop` | `/etc/init.d/service start/stop` |
| **Service Status** | `systemctl status` | `/etc/init.d/service status` |
| **Logging** | `journalctl` | `/var/log/syslog` |
| **Boot Time** | Faster (parallel) | Slower (sequential) |
| **Dependencies** | Automatic | Manual |
| **Process Tracking** | Advanced | Basic |
| **Resource Limits** | Built-in | Requires ulimit |
| **Complexity** | High | Low |

---

## Related Files

- `remove-systemd.sh` - Automated removal script
- `disable-systemd-resolved.sh` - Simpler script to just disable DNS resolver
- `SYSTEMD_RESOLVED_DISABLED.md` - Documentation for disabling systemd-resolved

---

## Summary

**Removing systemd is a major undertaking that should only be done if:**
- ✅ You have a full system backup
- ✅ You have physical/console access
- ✅ You understand the risks
- ✅ You're prepared to troubleshoot

**For Evilginx users:** Consider just disabling `systemd-resolved` instead of removing systemd entirely. This is safer and easier to manage.

---

**Last Updated:** $(date +%Y-%m-%d)  
**Status:** ⚠️ Use with extreme caution

