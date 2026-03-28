# 🔄 Domain Rotation Guide

> Multi-domain rotation with simultaneous lures across different hostnames for the same phishlet.

---

## Overview

Domain rotation lets you run **multiple domains simultaneously** for the same phishlet. Each domain gets its own lure URL, and the system can automatically rotate between them. This provides:

- **Resilience** — if one domain gets flagged, others keep working
- **Distributed traffic** — spread requests across domains to avoid detection
- **Operational flexibility** — different lures for different target segments

---

## Quick Start

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

---

## Step-by-Step Setup

### Step 1: Configure Domains

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
```
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

### Step 2: Set External IP

```bash
config ipv4 <YOUR_VPS_IP>
```

### Step 3: Configure the Phishlet

```bash
# Set hostname using the primary domain
phishlets hostname o365 login.yourdomain1.com
phishlets enable o365
```

Evilginx will automatically obtain TLS certificates for the phishlet hostname.

### Step 4: Create Multi-Domain Lures

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

### Step 5: Generate Phishing URLs

```bash
lures get-url 0
lures get-url 1
lures get-url 2
```

Each URL is served on a different domain. **All are active at the same time.**

### Step 6: Enable Domain Rotation

```bash
# Enable rotation (auto-populates pool from configured domains)
domains rotation enable on

# Set rotation strategy
domains rotation strategy round-robin

# Set rotation interval (minutes)
domains rotation interval 30
```

---

## Rotation Strategies

| Strategy | Description | Best For |
|----------|-------------|----------|
| `round-robin` | Cycles through domains sequentially | Even traffic distribution |
| `weighted` | Distributes based on domain health/weight | Performance optimization |
| `health-based` | Prefers domains with best health scores | Maximum uptime |
| `random` | Random domain selection | Unpredictable pattern |

```bash
# Examples
domains rotation strategy round-robin
domains rotation strategy health-based
domains rotation strategy random
```

---

## Monitoring

### Check Rotation Status

```bash
domains rotation
```

**Output:**
```
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

### View Detailed Stats

```bash
domains rotation stats
```

### List Domains in Pool

```bash
domains rotation list
```

### Mark a Compromised Domain

If a domain gets flagged or taken down:

```bash
domains rotation mark-compromised yourdomain2.com "reported by target"
```

This removes it from active rotation while keeping the other domains running.

---

## DNS Configuration

For each domain in your pool, set up DNS records:

### Cloudflare (Recommended)

For **each domain**, add these records:

| Type | Name | Content | Proxy Status |
|------|------|---------|--------------|
| A | @ | YOUR_VPS_IP | DNS only (Gray) |
| A | login | YOUR_VPS_IP | DNS only (Gray) |
| A | * | YOUR_VPS_IP | DNS only (Gray) |

> **Critical:** Proxy status must be "DNS only" (gray cloud). Orange cloud will break certificate generation.

---

## Advanced: Segment by Campaign

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

---

## Command Reference

| Command | Description |
|---------|-------------|
| `domains set <domain>` | Set primary (base) domain |
| `domains add <domain> [desc]` | Add domain to pool |
| `domains remove <domain>` | Remove domain from pool |
| `domains list` | List all configured domains |
| `domains rotation enable on` | Enable rotation (auto-populates pool) |
| `domains rotation off` | Disable rotation |
| `domains rotation strategy <type>` | Set rotation strategy |
| `domains rotation interval <min>` | Set rotation interval |
| `domains rotation max-domains <n>` | Set max domains in pool |
| `domains rotation list` | List rotation pool domains |
| `domains rotation stats` | Show rotation statistics |
| `domains rotation mark-compromised <domain> <reason>` | Flag a domain |
| `lures edit <id> hostname <host>` | Set lure hostname (any configured domain) |
| `lures get-url <id>` | Generate phishing URL for a lure |

---

## Tips

1. **Stagger lure deployment** — don't send all domain URLs at once. Use domain 1 first, then switch to domain 2 if it gets flagged.
2. **Different OG metadata per lure** — customize the link preview (title, image, description) for each domain to match the campaign context.
3. **Monitor health** — use `domains rotation stats` regularly to check which domains are still healthy.
4. **Auto-populate** — when you enable rotation, all configured domains are automatically added to the rotation pool. No need to add them separately.
5. **Certificates** — Evilginx auto-obtains TLS certs for each lure hostname. Ensure ports 80/443 are open and DNS is configured before creating lures.
