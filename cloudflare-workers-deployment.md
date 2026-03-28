# Cloudflare Workers Module — Deployment Guide

## Module Overview

The Cloudflare Workers module provides **worker script generation, API-based deployment, and lifecycle management** directly from the Evilginx3 CLI. Workers run on Cloudflare's edge network and redirect visitors to the phishing infrastructure while applying filtering, anti-bot checks, and fingerprinting.

### Source Files

| File | Purpose |
|------|---------|
| [cloudflare_worker.go](file:///c:/Users/user/Desktop/Projects/git/Evilginx3/core/cloudflare_worker.go) | Worker script generator — 3 Go templates + lure integration |
| [cloudflare_worker_api.go](file:///c:/Users/user/Desktop/Projects/git/Evilginx3/core/cloudflare_worker_api.go) | Cloudflare API client — deploy/update/delete/list/routes/status |
| [cloudflare.go](file:///c:/Users/user/Desktop/Projects/git/Evilginx3/core/dns_providers/cloudflare.go) | DNS record management via Cloudflare API (A/CNAME/TXT records) |
| [config.go](file:///c:/Users/user/Desktop/Projects/git/Evilginx3/core/config.go) | `CloudflareConfig` struct — persistent credential/state storage |
| [domain_manager.go](file:///c:/Users/user/Desktop/Projects/git/Evilginx3/core/domain_manager.go) | Unified `DomainManager` — multi-domain pool, rotation, health checks |
| [terminal.go](file:///c:/Users/user/Desktop/Projects/git/Evilginx3/core/terminal.go) | CLI handler — `cloudflare` command (lines 2713–3243) |

---

## Worker Types

### 1. Simple Redirect (`simple`)
- **302 redirect** to the target URL
- Optional: User-Agent filter, geo-filter, request logging, configurable delay
- Minimal footprint, fastest execution

### 2. HTML Redirector (`html`)
- Serves an **HTML page with a loading spinner** and meta-refresh redirect
- Default 2-second delay (configurable)
- Supports custom HTML content via `CustomHtml` field
- Custom response headers support

### 3. Advanced (`advanced`)
- All features of HTML + **anti-bot detection**:
  - Known bot User-Agent blocking (Google, Bing, Baidu, curl, wget, Python, etc.)
  - Required header validation (`Accept-Language`, `Accept-Encoding`)
  - **Data center ASN blocking** — blocks IPs from hosting/cloud providers
  - Geo-filtering by country code
- **Visitor fingerprinting** — appends `cf_ip`, `cf_country`, `cf_ts` query params to redirect URL
- Full request logging (IP, UA, referer, country, city, ASN, organization, all headers)
- Default: logging enabled, 2-second delay

---

## Deployment Methods

### Method 1: CLI Auto-Deploy (Recommended)

Deploy workers directly from the Evilginx3 shell using the Cloudflare API.

#### Step 1 — Configure Credentials

```
config cloudflare_worker account_id <your_account_id>
config cloudflare_worker api_token <your_api_token>
config cloudflare_worker zone_id <your_zone_id>        # Optional, needed for custom routes
config cloudflare_worker subdomain <your_subdomain>     # Optional, for workers.dev URL display
config cloudflare_worker enabled true
```

#### Step 2 — Test Credentials

```
config cloudflare_worker test
# or:
cloudflare config test
```

#### Step 3 — Deploy

```
# Basic deploy
cloudflare deploy my-redirector simple https://phish.example.com/login

# Advanced deploy with options
cloudflare deploy my-redirector advanced https://phish.example.com/login --ua-filter "Mozilla|Chrome|Firefox" --geo US,CA,GB --delay 3 --log --subdomain --route "*.example.com/*"
```

The worker will be available at: `https://<worker-name>.<subdomain>.workers.dev`

#### Step 4 — Manage Workers

```
cloudflare list                              # List all deployed workers
cloudflare status <worker_name>              # Check deployment status + URL
cloudflare update <worker_name> <new_url>    # Update redirect URL
cloudflare delete <worker_name>              # Remove a worker
```

---

### Method 2: Generate & Manual Deploy

Generate a worker script file, then deploy it manually via the Cloudflare dashboard or `wrangler` CLI.

#### Step 1 — Generate Script

```
# Generate simple redirect
cloudflare worker simple https://phish.example.com/login

# Generate from a lure
cloudflare worker advanced --lure 0

# Generate with options
cloudflare worker html https://phish.example.com/login --ua-filter "Mozilla" --geo US,GB --delay 5 --log
```

This creates a file like `cloudflare-worker-advanced-20260304-021625.js`.

#### Step 2 — Deploy via Cloudflare Dashboard

1. Go to **Cloudflare Dashboard → Workers & Pages → Create Application → Create Worker**
2. Paste the generated JavaScript into the editor
3. Deploy and note the `*.workers.dev` URL

#### Step 3 — Deploy via Wrangler CLI (Alternative)

```bash
npm install -g wrangler
wrangler login
wrangler deploy cloudflare-worker-advanced-20260304-021625.js --name my-redirector
```

---

### Method 3: Lure-Based Generation

Generate workers tied directly to an existing lure configuration.

```
# Generate worker from lure ID 0
cloudflare worker advanced --lure 0

# Deploy worker from lure
cloudflare deploy lure-worker advanced --lure 0 --subdomain
```

This automatically:
- Extracts the redirect URL from the lure's `hostname` + `path`
- Inherits the lure's `ua_filter`
- Falls back to `redirect_url` if configured on the lure

---

## Configuration Reference

### `CloudflareConfig` Struct (persisted in `config.json`)

| Field | Config Key | Required | Description |
|-------|-----------|----------|-------------|
| `AccountID` | `cloudflare_worker.account_id` | ✅ | Cloudflare account ID |
| `APIToken` | `cloudflare_worker.api_token` | ✅ | API token with Workers permissions |
| `ZoneID` | `cloudflare_worker.zone_id` | ❌ | Required only for custom route patterns |
| `WorkerSubdomain` | `cloudflare_worker.worker_subdomain` | ❌ | Your `*.workers.dev` subdomain |
| `Enabled` | `cloudflare_worker.enabled` | ✅ | Must be `true` for API deployments |

### `CloudflareWorkerConfig` (per-worker generation)

| Field | CLI Flag | Description |
|-------|----------|-------------|
| `Type` | positional | `simple`, `html`, or `advanced` |
| `RedirectUrl` | positional | Target URL for redirection |
| `UserAgentFilter` | `--ua-filter` | Regex to whitelist User-Agents |
| `GeoFilter` | `--geo` | Comma-separated country codes |
| `DelaySeconds` | `--delay` | Seconds to wait before redirect |
| `LogRequests` | `--log` | Enable console logging of requests |
| `CustomHtml` | (code only) | Custom HTML for the html worker type |
| `Headers` | (code only) | Custom response headers |

---

## CLI Command Reference

| Command | Syntax | Description |
|---------|--------|-------------|
| **Generate** | `cloudflare worker <type> <redirect_url> [options]` | Generate a `.js` worker script file |
| **Deploy** | `cloudflare deploy <name> <type> <url> [options]` | Deploy worker to Cloudflare via API |
| **List** | `cloudflare list` | List all deployed workers with URLs |
| **Delete** | `cloudflare delete <worker_name>` | Delete a deployed worker |
| **Update** | `cloudflare update <worker_name> <url>` | Update a worker's redirect URL |
| **Status** | `cloudflare status <worker_name>` | Check if worker is deployed + get URL |
| **Config** | `cloudflare config` | Show current Cloudflare configuration |
| **Config Set** | `cloudflare config <key> <value>` | Set a config value |
| **Config Test** | `cloudflare config test` | Validate API credentials |

### Deploy-Only Options

| Flag | Description |
|------|-------------|
| `--route <pattern>` | Create a custom route pattern (requires `zone_id`) |
| `--subdomain` | Enable `workers.dev` subdomain access |

---

## API Internals

The `CloudflareWorkerAPI` struct wraps the Cloudflare REST API (`https://api.cloudflare.com/client/v4`):

| Method | API Endpoint | Purpose |
|--------|-------------|---------|
| `DeployWorker` | `PUT /accounts/{id}/workers/scripts/{name}` | Upload worker script |
| `UpdateWorker` | `PUT /accounts/{id}/workers/scripts/{name}` | Replace worker script |
| `DeleteWorker` | `DELETE /accounts/{id}/workers/scripts/{name}` | Remove worker |
| `ListWorkers` | `GET /accounts/{id}/workers/scripts` | List all workers |
| `CreateWorkerRoute` | `POST /zones/{id}/workers/routes` | Bind worker to URL pattern |
| `ListWorkerRoutes` | `GET /zones/{id}/workers/routes` | List route bindings |
| `DeleteWorkerRoute` | `DELETE /zones/{id}/workers/routes/{route_id}` | Remove route |
| `ValidateCredentials` | `GET /accounts/{id}` | Test API token validity |
| `GetWorkerSubdomain` | `GET /accounts/{id}/workers/subdomain` | Retrieve workers.dev subdomain |
| `GetWorkerStatus` | (via `ListWorkers`) | Check if named worker exists |

---

## Cloudflare Turnstile Redirectors

The `redirectors/` directory contains **pre-built HTML pages** that integrate with Cloudflare Turnstile for bot protection. These are separate from Workers but complement them:

| Redirector | Target |
|------------|--------|
| `o365_turnstile/` | Microsoft 365 login pages |
| `linkedin_turnstile/` | LinkedIn login pages |
| `apple_turnstile/` | Apple ID login pages |
| `paypal_turnstile/` | PayPal login pages |
| `amazon_turnstile/` | Amazon login pages |

These require a **Cloudflare Turnstile Site Key** (configured in the HTML). Deploy these via **Cloudflare Pages** or **GitHub Pages** as static sites.

---

## Domain Management Integration

Workers redirect traffic to domains managed by the unified `DomainManager`. All domain operations are now handled through the `domains` command:

### Managing Domains for Worker Targets

```
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

### Domain Rotation for Workers

When domain rotation is enabled, the `DomainManager` cycles through active domains using the configured strategy. Workers should point to the current active domain:

```
# Enable rotation
domains rotation on
domains rotation strategy health-based
domains rotation interval 30

# Add DNS providers for auto-generation
domains rotation add-provider cf cloudflare <api_key> <api_secret> <zone>

# Enable automatic replacement of compromised domains
domains rotation auto-generate on
```

**Rotation Strategies**: `round-robin`, `weighted`, `health-based`, `random`

### Domain Status Values

| Status | Meaning |
|--------|---------|
| `active` | Domain is healthy and serving traffic |
| `inactive` | Domain is disabled (manual or health check failure) |
| `compromised` | Domain is burned — removed from rotation, triggers auto-generation |

---

## DNS Provider Integration

The `dns_providers/cloudflare.go` module manages DNS records through the Cloudflare API:

- **CRUD for DNS records**: A, CNAME, TXT (for ACME challenges)
- **Zone lookup by domain** with caching
- Authentication via API Token or API Key + Email
- Used by the certificate system for automated DNS-01 challenges
- DNS providers can be registered with `DomainManager` for automatic domain generation and rotation via `domains rotation add-provider`

---

## Obtaining Cloudflare Credentials

### Account ID
1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Click on any domain → **Overview** tab
3. Scroll down to **API** section on the right sidebar → copy **Account ID**

### API Token
1. Go to **My Profile → API Tokens → Create Token**
2. Use the **"Edit Cloudflare Workers"** template, or create custom with:
   - `Account.Workers Scripts`: Edit
   - `Zone.Workers Routes`: Edit (if using custom routes)
   - `Account.Account Settings`: Read (for credential validation)

### Zone ID (Optional)
1. Same location as Account ID — copy the **Zone ID** from the domain overview page
2. Only needed if you plan to create custom route patterns

### Workers Subdomain
1. Go to **Workers & Pages** in the dashboard
2. Your subdomain appears as `<subdomain>.workers.dev`
