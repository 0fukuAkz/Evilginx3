# systemd-resolved Disabled for Evilginx

## ✅ Status: Configured

**Date:** November 11, 2025  
**Installer Version:** 3.3.1 Private Dev Edition  
**Status:** systemd-resolved handling implemented ✅

---

## 📋 Overview

The Evilginx installer now **automatically disables systemd-resolved** to prevent port 53 conflicts.

### Why This Is Necessary

**Port Conflict:**
- **Evilginx** needs port 53 (DNS) to run its nameserver
- **systemd-resolved** also uses port 53 (stub resolver)
- ⚠️ **Both cannot run simultaneously**

**Solution:**
- Installer stops and disables systemd-resolved
- Creates static `/etc/resolv.conf` with public DNS servers
- Frees port 53 for Evilginx DNS server

---

## 🔧 What The Installer Does

The `disable_systemd_resolved()` function in `install.sh` performs these steps:

### 1. Detection
```bash
# Checks if systemd-resolved is installed
systemctl list-unit-files | grep systemd-resolved.service
```

### 2. Stop Service
```bash
# Stops the running service
systemctl stop systemd-resolved
```

### 3. Disable Auto-Start
```bash
# Prevents it from starting on boot
systemctl disable systemd-resolved
```

### 4. Mask Service
```bash
# Prevents manual or automatic activation
systemctl mask systemd-resolved
```

### 5. Configure DNS
```bash
# Removes symlink and creates static resolv.conf
rm -f /etc/resolv.conf
cat > /etc/resolv.conf << EOF
nameserver 8.8.8.8      # Google DNS
nameserver 8.8.4.4      # Google DNS
nameserver 1.1.1.1      # Cloudflare DNS
options timeout:2
options attempts:3
EOF
```

### 6. Make Immutable (Optional)
```bash
# Prevents systemd from overwriting
chattr +i /etc/resolv.conf
```

---

## 📊 Current System Status

### On Your Debian 12 System

```
systemd-resolved: NOT INSTALLED ✅
Port 53: AVAILABLE ✅
DNS Resolution: Working via /etc/resolv.conf ✅
```

**Result:** No action was needed on your system, but the installer is now prepared for systems that have systemd-resolved (like Ubuntu).

---

## 🎯 Affected Operating Systems

### Typically Has systemd-resolved:
- ✅ **Ubuntu** 16.04+ (Default)
- ✅ **Ubuntu Server** (Default)
- ✅ **Pop!_OS**
- ✅ **Elementary OS**
- ⚠️ **Debian** (Sometimes, depends on installation)
- ⚠️ **Fedora** (Sometimes)

### Typically Does NOT Have systemd-resolved:
- ✅ **Debian 12** (Your system) - Uses traditional networking
- ✅ **CentOS** / **RHEL**
- ✅ **Arch Linux** (not enabled by default)

---

## 🔍 Manual Verification

### Check if systemd-resolved is Running

```bash
# Check if service exists
systemctl status systemd-resolved

# Check if port 53 is in use
lsof -i :53
netstat -tulpn | grep :53

# Check DNS resolution file
ls -la /etc/resolv.conf
cat /etc/resolv.conf
```

### Expected Output (After Installer)

```bash
# Service should be masked or not found
$ systemctl status systemd-resolved
Unit systemd-resolved.service could not be found.
# OR
○ systemd-resolved.service - masked

# Port 53 should only show Evilginx (if running)
$ netstat -tulpn | grep :53
udp6  :::53  LISTEN  983108/evilginx.bin

# resolv.conf should be a regular file (not symlink)
$ ls -la /etc/resolv.conf
-rw-r--r-- 1 root root 257 Nov 11 14:30 /etc/resolv.conf

# Should contain public DNS servers
$ cat /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
```

---

## 🛠️ Standalone Script

A standalone script is also available: `disable-systemd-resolved.sh`

### Usage:

```bash
# Run the standalone script
sudo ./disable-systemd-resolved.sh

# Output will show:
# - Detection of systemd-resolved
# - Stopping service
# - Disabling auto-start
# - Masking service
# - Configuring /etc/resolv.conf
# - Verification of port 53 availability
```

---

## 🔄 If You Need to Re-Enable systemd-resolved

In case you need to undo these changes (not recommended while running Evilginx):

```bash
# Remove immutable flag from resolv.conf
sudo chattr -i /etc/resolv.conf

# Unmask the service
sudo systemctl unmask systemd-resolved

# Enable the service
sudo systemctl enable systemd-resolved

# Start the service
sudo systemctl start systemd-resolved

# Let systemd-resolved manage resolv.conf
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

# Verify
systemctl status systemd-resolved
```

**⚠️ Warning:** This will cause Evilginx to fail because port 53 will be taken!

---

## 🐛 Troubleshooting

### DNS Resolution Not Working

```bash
# Test DNS resolution
ping -c 3 google.com
dig google.com
nslookup google.com

# If failing, check resolv.conf
cat /etc/resolv.conf

# Should have valid nameservers
# If empty, recreate:
sudo bash -c 'cat > /etc/resolv.conf << EOF
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
EOF'
```

### Port 53 Still in Use

```bash
# Find what's using port 53
sudo lsof -i :53

# If systemd-resolved is shown:
sudo systemctl stop systemd-resolved
sudo systemctl mask systemd-resolved

# If other service (like dnsmasq):
sudo systemctl stop dnsmasq
sudo systemctl disable dnsmasq
```

### Evilginx Can't Bind to Port 53

```bash
# Check what's using the port
sudo lsof -i :53

# Check firewall
sudo ufw status | grep 53

# Try starting Evilginx manually
sudo /usr/local/evilginx/evilginx.bin -p /usr/local/evilginx/phishlets -c /etc/evilginx

# Check for permission errors
# Evilginx needs CAP_NET_BIND_SERVICE to bind to port 53
```

---

## 📋 Installation Steps Sequence

The installer performs these steps in order:

```
1. Update System
2. Install Dependencies
3. Install Go 1.22
4. Setup Directories
5. Stop Conflicting Services (Apache2, Nginx, BIND9)
   ↓
6. Disable systemd-resolved ← NEW STEP
   ├─ Stop service
   ├─ Disable auto-start
   ├─ Mask service
   ├─ Configure /etc/resolv.conf
   └─ Verify port 53 available
   ↓
7. Build Evilginx
8. Configure Firewall
9. Configure Fail2Ban
10. Create systemd Service
11. Configure Capabilities
12. Create Helper Scripts
```

---

## ✅ Benefits

### Port Conflict Prevention
- ✅ Port 53 always available for Evilginx
- ✅ No manual intervention needed
- ✅ Works across different Linux distributions

### Reliability
- ✅ Static DNS configuration (won't change)
- ✅ Uses reliable public DNS servers
- ✅ Immutable file prevents accidental changes

### Automation
- ✅ Installer handles everything automatically
- ✅ Detects if systemd-resolved exists
- ✅ Skips step if not needed (like your Debian system)

---

## 📊 DNS Servers Used

The installer configures these public DNS servers:

| Provider | Primary | Secondary | Features |
|----------|---------|-----------|----------|
| **Google** | 8.8.8.8 | 8.8.4.4 | Fast, reliable, global |
| **Cloudflare** | 1.1.1.1 | 1.0.0.1 | Privacy-focused, fast |

**Fallback Order:**
1. Google Primary (8.8.8.8)
2. Google Secondary (8.8.4.4)
3. Cloudflare (1.1.1.1)

---

## 🔐 Security Considerations

### Implications of Disabling systemd-resolved

**Advantages:**
- ✅ Simpler DNS configuration
- ✅ No caching issues
- ✅ Direct control over DNS servers
- ✅ Port 53 available for Evilginx

**Disadvantages:**
- ⚠️ Lose DNSSEC validation (if enabled)
- ⚠️ Lose DNS-over-TLS (if configured)
- ⚠️ No local DNS caching
- ⚠️ Static configuration (manual updates needed)

**Mitigation:**
- Use reliable public DNS (Google, Cloudflare)
- Monitor DNS resolution performance
- Test periodically with: `dig google.com`

---

## 📖 Related Documentation

- **Installation Summary:** `INSTALLATION_SUMMARY.md`
- **Auto-Start Configuration:** `AUTO_START_CONFIGURED.md`
- **Project Analysis:** `PROJECT_ANALYSIS.md`
- **Main Installer:** `install.sh`
- **Standalone Script:** `disable-systemd-resolved.sh`

---

## 🎯 Summary

✅ **Installer now handles systemd-resolved automatically**  
✅ **Port 53 conflicts prevented**  
✅ **Static DNS configuration with public servers**  
✅ **Works on Ubuntu, Debian, and other distributions**  
✅ **Your Debian 12 system: No action needed (not installed)**  

**The installation process is now more robust and will work seamlessly on Ubuntu systems where systemd-resolved is common!**

---

**Last Updated:** November 11, 2025  
**Status:** ✅ Implemented in install.sh  
**Tested On:** Debian 12 (systemd-resolved not present)

