# Quick Start: Disable systemd Permanently

## ⚠️ CRITICAL WARNING

**This will permanently remove systemd and replace it with sysvinit.**
- System may become unbootable if something goes wrong
- **REQUIRES full system backup**
- **REQUIRES physical/console access** (SSH may break)
- This is **IRREVERSIBLE** without a backup

---

## Quick Start

### 1. Create System Backup

```bash
# Create a full backup (CRITICAL!)
sudo tar -czf /backup/system-backup-$(date +%Y%m%d).tar.gz \
    --exclude=/backup \
    --exclude=/proc \
    --exclude=/sys \
    --exclude=/dev \
    --exclude=/run \
    --exclude=/tmp \
    /
```

### 2. Run Removal Script

```bash
# Make executable (on Linux)
chmod +x remove-systemd.sh

# Run the script
sudo ./remove-systemd.sh
```

The script will:
- ✅ Create automatic backups
- ✅ Install sysvinit-core
- ✅ Convert Evilginx service to sysvinit
- ✅ Configure sysvinit as default
- ✅ Remove systemd packages
- ✅ Verify installation

### 3. Reboot

```bash
sudo reboot
```

**⚠️ Have console access ready!**

---

## After Reboot

### Start Evilginx

```bash
# Using init script
sudo /etc/init.d/evilginx start

# Or using service command
sudo service evilginx start

# Or use helper script (if updated)
sudo evilginx-start
```

### Check Status

```bash
sudo /etc/init.d/evilginx status
# OR
sudo service evilginx status
```

### Update Helper Scripts (Optional)

If you want the `evilginx-start`, `evilginx-stop` commands to work:

```bash
sudo ./update-helpers-for-sysvinit.sh
```

---

## Alternative: Just Disable systemd-resolved

**If you only need port 53 for Evilginx DNS, you don't need to remove systemd!**

Just disable the DNS resolver:

```bash
sudo ./disable-systemd-resolved.sh
```

This is much safer and easier to reverse.

---

## Troubleshooting

### System Won't Boot

1. Boot from live CD/USB
2. Mount root filesystem
3. Restore backup from `/root/systemd-removal-backup-*`
4. Or reinstall systemd packages

### Services Not Starting

```bash
# Check if init script exists
ls -la /etc/init.d/evilginx

# Test manually
sudo /etc/init.d/evilginx start

# Check for errors
sudo /etc/init.d/evilginx status
```

### Need to Rollback

See `SYSTEMD_REMOVAL_GUIDE.md` for detailed rollback instructions.

---

## Files Created

- `remove-systemd.sh` - Main removal script
- `update-helpers-for-sysvinit.sh` - Updates helper scripts
- `SYSTEMD_REMOVAL_GUIDE.md` - Complete documentation
- `QUICK_START_SYSTEMD_REMOVAL.md` - This file

---

## Summary

**To permanently disable systemd:**

1. ✅ Backup system
2. ✅ Run `sudo ./remove-systemd.sh`
3. ✅ Reboot
4. ✅ Use sysvinit commands

**For most users:** Consider `disable-systemd-resolved.sh` instead - it's safer!

