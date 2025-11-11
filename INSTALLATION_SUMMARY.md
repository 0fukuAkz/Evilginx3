# Evilginx 3.3.1 - Installation Summary

**Installation Date:** November 11, 2025  
**Installation Status:** ✅ **SUCCESSFUL**  
**Version:** 3.3.1 - Private Dev Edition  
**System:** Debian GNU/Linux 12

---

## ✅ Installation Results

### Core Installation: **SUCCESS**

```
✅ Go 1.22.0 installed
✅ Evilginx compiled and installed to /usr/local/evilginx
✅ Systemd service created and enabled
✅ Firewall (UFW) configured
✅ Helper commands installed
✅ System-wide 'evilginx' command available
```

### Minor Issue: Fail2Ban

```
⚠️  Fail2Ban service configuration failed
Reason: Fail2Ban package not installed on system
Impact: None - This is an optional security enhancement
Resolution: Not required - system is fully functional
```

**Note:** Fail2Ban is an optional brute-force protection tool for SSH. The absence does not affect Evilginx functionality.

---

## 📁 Installation Locations

```
Binary:           /usr/local/evilginx/evilginx.bin
Wrapper Script:   /usr/local/bin/evilginx
Configuration:    /etc/evilginx/
Phishlets:        /usr/local/evilginx/phishlets/
Redirectors:      /usr/local/evilginx/redirectors/
Service File:     /etc/systemd/system/evilginx.service
```

---

## 🔧 Installed Commands

All helper commands are available system-wide:

| Command | Purpose |
|---------|---------|
| `evilginx` | Run Evilginx directly |
| `evilginx-start` | Start Evilginx service |
| `evilginx-stop` | Stop Evilginx service |
| `evilginx-status` | Check service status |
| `evilginx-logs` | View service logs |
| `evilginx-console` | Launch interactive console |

---

## 🔥 Firewall Configuration

**Status:** ✅ **Active and Enabled**

```
Port 22/tcp   - SSH access
Port 80/tcp   - HTTP (ACME challenges)
Port 443/tcp  - HTTPS (Evilginx proxy)
Port 53/tcp   - DNS TCP (Evilginx nameserver)
Port 53/udp   - DNS UDP (Evilginx nameserver)
```

**Default Policy:**
- Incoming: DENY (except allowed ports above)
- Outgoing: ALLOW

---

## 🚀 Quick Start Guide

### 1. Start Evilginx Service

```bash
# Option A: Using helper command (recommended)
evilginx-start

# Option B: Using systemctl directly
sudo systemctl start evilginx

# Check status
evilginx-status
```

### 2. Launch Interactive Console

```bash
# This will start Evilginx in interactive mode
# (Service must be stopped first)
evilginx-stop
evilginx-console
```

### 3. Basic Configuration

```bash
# Inside Evilginx console:

# Set your domain
config domain yourdomain.com

# Set your server IP
config ipv4 YOUR.SERVER.IP

# View current configuration
config

# List available phishlets
phishlets

# Enable a phishlet (example: o365)
phishlets hostname o365 login.yourdomain.com
phishlets enable o365

# Create a lure
lures create o365
lures get-url 0

# View captured sessions
sessions
```

---

## 📋 Next Steps

### Immediate Actions Required

1. **Configure Your Domain**
   ```bash
   evilginx-console
   config domain YOUR-DOMAIN.com
   config ipv4 YOUR-SERVER-IP
   ```

2. **Point Your Domain to This Server**
   - Update DNS A records to point to your server IP
   - Update DNS NS records if using Evilginx's DNS server

3. **Configure Cloudflare (Recommended)**
   - Add domain to Cloudflare
   - Set DNS to "DNS only" (gray cloud, not proxied)
   - Get API credentials for automation
   - See: DEPLOYMENT_GUIDE.md for detailed instructions

4. **Create Your First Phishing Campaign**
   - Choose a phishlet (o365, google, linkedin, etc.)
   - Configure hostname
   - Enable phishlet
   - Create lure
   - Test before deployment

### Security Recommendations

1. **Change SSH Port (Optional but Recommended)**
   ```bash
   # Edit SSH config
   sudo nano /etc/ssh/sshd_config
   # Change: Port 22 → Port 2222 (or any high port)
   
   # Update firewall
   sudo ufw allow 2222/tcp
   sudo ufw delete allow 22/tcp
   
   # Restart SSH
   sudo systemctl restart sshd
   ```

2. **Enable SSH Key Authentication**
   ```bash
   # Generate SSH key (on your local machine)
   ssh-keygen -t ed25519 -C "evilginx-admin"
   
   # Copy to server
   ssh-copy-id root@YOUR-SERVER-IP
   
   # Disable password authentication
   sudo nano /etc/ssh/sshd_config
   # Set: PasswordAuthentication no
   
   # Restart SSH
   sudo systemctl restart sshd
   ```

3. **Install Fail2Ban (Optional)**
   ```bash
   # Install Fail2Ban for SSH protection
   sudo apt-get update
   sudo apt-get install -y fail2ban
   
   # Configure for SSH
   sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
   sudo nano /etc/fail2ban/jail.local
   # Ensure [sshd] is enabled
   
   # Start service
   sudo systemctl enable fail2ban
   sudo systemctl start fail2ban
   ```

4. **Enable Automatic Security Updates**
   ```bash
   sudo apt-get install -y unattended-upgrades
   sudo dpkg-reconfigure -plow unattended-upgrades
   ```

---

## 📖 Documentation

Comprehensive documentation is available:

- **README.md** - Overview and features
- **DEPLOYMENT_GUIDE.md** - Step-by-step deployment (2,164 lines)
- **BEST_PRACTICES.md** - Operational security guide (1,533 lines)
- **PROJECT_ANALYSIS.md** - Technical analysis (NEW)
- **ARCHITECTURE_DIAGRAM.md** - System architecture (NEW)
- **SECURITY_ANALYSIS.md** - Security implications and defenses (NEW)

---

## 🔍 Verification Commands

Verify your installation:

```bash
# Check Evilginx version
evilginx -v

# Check service status
systemctl status evilginx

# Check firewall status
sudo ufw status verbose

# Check Go installation
go version

# List installed files
ls -lah /usr/local/evilginx/

# Check configuration directory
ls -lah /etc/evilginx/

# View service logs
journalctl -u evilginx -n 50

# Test DNS (after starting service)
dig @localhost yourdomain.com
```

---

## 🐛 Troubleshooting

### Service Won't Start

```bash
# Check for errors
journalctl -u evilginx -xe

# Check if ports are available
sudo lsof -i :443
sudo lsof -i :80
sudo lsof -i :53

# If ports are in use, stop conflicting services
sudo systemctl stop apache2
sudo systemctl stop nginx
```

### Permission Issues

```bash
# Ensure correct permissions
sudo chown -R root:root /usr/local/evilginx
sudo chmod +x /usr/local/evilginx/evilginx.bin
sudo chmod +x /usr/local/bin/evilginx*
```

### Firewall Issues

```bash
# Reset and reconfigure firewall
sudo ufw disable
sudo ufw reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 53
sudo ufw enable
```

### DNS Not Resolving

```bash
# Check if Evilginx DNS is running
sudo netstat -tulpn | grep :53

# Test DNS resolution
dig @YOUR-SERVER-IP yourdomain.com

# Verify NS records point to your server
dig NS yourdomain.com
```

---

## ⚖️ Legal Reminder

**⚠️ CRITICAL LEGAL WARNING**

This tool is installed for **AUTHORIZED SECURITY TESTING ONLY**.

Before using this tool, ensure you have:

✅ **Written authorization** from the target organization  
✅ **Clearly defined scope** of engagement  
✅ **Legal review** confirming compliance with local laws  
✅ **Data handling agreement** in place  
✅ **Incident response plan** ready  

**Unauthorized use is ILLEGAL and may result in:**
- Criminal prosecution (up to 20 years imprisonment in US)
- Civil liability
- Financial penalties
- Professional consequences

**The authors and contributors are NOT responsible for misuse.**

---

## 📞 Support Resources

### Original Evilginx
- **Documentation:** https://help.evilginx.com
- **Original Repository:** https://github.com/kgretzky/evilginx2
- **Blog:** https://breakdev.org
- **Training:** https://academy.breakdev.org/evilginx-mastery

### Local Documentation
- All guides are in: `/root/Evilginx3/`
- View with: `cat /root/Evilginx3/DEPLOYMENT_GUIDE.md`

---

## 🎯 Quick Reference

### Start/Stop Service

```bash
evilginx-start      # Start as background service
evilginx-stop       # Stop service
evilginx-status     # Check status
evilginx-logs       # View logs
evilginx-console    # Interactive mode (stops service first)
```

### Essential Configuration

```bash
# In Evilginx console:
config domain example.com           # Set base domain
config ipv4 1.2.3.4                # Set server IP
config autocert on                 # Enable Let's Encrypt
phishlets hostname o365 login.example.com
phishlets enable o365
lures create o365
lures get-url 0
```

### Monitoring

```bash
# Watch logs in real-time
journalctl -u evilginx -f

# Check firewall
sudo ufw status

# Monitor connections
sudo netstat -tulpn | grep evilginx

# Check captured sessions (in console)
sessions
```

---

## ✅ Installation Checklist

- [x] Go 1.22.0 installed
- [x] Evilginx compiled and installed
- [x] Systemd service created
- [x] Firewall configured
- [x] Helper commands available
- [ ] Domain configured
- [ ] DNS records updated
- [ ] Cloudflare configured (optional)
- [ ] Phishlet enabled
- [ ] First lure created
- [ ] Test campaign executed

---

## 🔐 Security Hardening Checklist

- [ ] Change SSH port from 22
- [ ] Enable SSH key authentication
- [ ] Disable SSH password authentication
- [ ] Install and configure Fail2Ban
- [ ] Enable automatic security updates
- [ ] Configure log monitoring
- [ ] Set up backup strategy
- [ ] Document incident response procedures
- [ ] Limit sudo access
- [ ] Enable UFW logging: `sudo ufw logging on`

---

**Installation completed successfully!**

Ready to proceed with configuration. See **DEPLOYMENT_GUIDE.md** for next steps.

---

**Generated:** November 11, 2025  
**System:** Debian GNU/Linux 12  
**Status:** ✅ Operational

