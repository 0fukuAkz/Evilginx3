<p align="center">
  <img alt="Evilginx2 Logo" src="media/img/evilginx2-logo-512.png" height="160" />
  <p align="center">
    <img alt="Evilginx2 Title" src="media/img/evilginx2-title-black-512.png" height="60" />
  </p>
</p>

# Evilginx 3.6.4 - Private Dev Edition

**Evilginx** is a man-in-the-middle attack framework used for phishing login credentials along with session cookies, which in turn allows to bypass 2-factor authentication protection.

This **Private Development Edition** includes advanced evasion, detection, and operational features not available in the standard release.

**Modified by:** AKaZA (Akz0fuku)  
**Original Author:** Kuba Gretzky ([@mrgretzky](https://twitter.com/mrgretzky))  
**Version:** 3.6.4 - Private Dev Edition

## Disclaimer

This tool is designed for **AUTHORIZED PENETRATION TESTING AND RED TEAM ENGAGEMENTS ONLY**. Unauthorized use of this tool is illegal and unethical. The authors and contributors are not responsible for misuse or damage caused by this tool.

**Legal Requirements:**
- Written authorization from target organization
- Defined scope of engagement
- Compliance with local laws and regulations
- Proper data handling and destruction protocols

Evilginx should be used only in legitimate penetration testing assignments with written permission from to-be-phished parties.

---

## Quick Start

### Requirements

- **Go 1.25.13+** — [Download Go](https://golang.org/dl/)
- Linux or macOS (recommended for production deployments)
- Ports 80, 443 (HTTPS proxy) and 53 (DNS) available

### Build from Source

```bash
git clone https://github.com/0fukuAkz/Evilginx3.git
cd Evilginx3
make build
```

The binary is output to `./build/evilginx`.

### First Run (Developer Mode)

Developer mode uses self-signed certificates — no domain or DNS setup required. Use this for local testing:

```bash
./build/evilginx -p ./phishlets -developer
```

### Production Run

```bash
./build/evilginx -p ./phishlets -c ~/.evilginx
```

On first launch, set your domain and external IP inside the REPL:

```
: config domain yourdomain.com
: config ipv4 external YOUR.SERVER.IP
```

Then enable a phishlet and create a lure:

```
: phishlets enable o365
: lures create o365
: lures get-url 0
```

### Common Flags

| Flag | Description |
|------|-------------|
| `-p <path>` | Path to the phishlets directory |
| `-t <path>` | Path to the redirectors directory |
| `-c <path>` | Config directory (default: `~/.evilginx`) |
| `-debug` | Enable verbose debug logging |
| `-developer` | Generate self-signed certs for local testing |

### Other Make Targets

```bash
make test    # Run test suite
make vet     # Run go vet
make fmt     # Format source with gofmt
make lint    # Run golangci-lint
make vuln    # Run govulncheck
make clean   # Remove build artifact
```

---

## What's New

### v3.6.4
- Bumped Go toolchain to 1.25.13 to resolve 20 call-graph-reachable stdlib CVEs (`net/url`, `net/http`, `crypto/tls`, `html/template`, `encoding/asn1`, `net/mail`, `net/textproto`, `mime`, `crypto/x509`, `net`)

### v3.6.3
- Upgraded `golang.org/x/text` to v0.39.0 to fix GO-2026-5970 (infinite loop in `norm.Form`)
- Bumped Go toolchain to 1.25.8 to fix 23 stdlib CVEs

### v3.6.2
- Fixed crash on lure click: GeoIP lookup now reads the embedded `geolite2-city.mmdb` via `embed.FS` instead of the OS filesystem

### v3.6.1
- Hardened CI: `govulncheck` now gates merges (was `continue-on-error`)
- Dependency updates: `golang.org/x/crypto`, `x/net`, `x/sys` bumped to latest

### v3.6.0
- **Web Admin UI** — Full single-page admin dashboard with campaigns, lures, sessions, and phishlets management
- **Campaign automation** — Creating a lure automatically provisions a GoPhish campaign
- **Campaigns table fixes** — URL column, stats, and live updates now work correctly
- **Embedded GoPhish** — Full GoPhish email campaign engine with RBAC and SMTP
- **Encryption-key URL params** — Phish URLs can carry AES-encrypted recipient params
- Dependency security upgrades (`golang.org/x/net` v0.55.0, eliminates 6 idna vulns)

### Earlier Highlights
- JA3/JA3S TLS fingerprinting and blocking
- Sandbox, VM, and headless-browser detection
- Polymorphic JavaScript engine (dynamic code mutation)
- Cloudflare Worker integration for traffic fronting
- Turnstile / reCAPTCHA v3 / hCaptcha CAPTCHA protection
- Domain rotation and automated provisioning
- Enhanced Telegram session exfil notifications
- Antibot engine with IP reputation and rate limiting

---

## Architecture Overview

```
evilginx3
├── core/               # Proxy, DNS, config, terminal REPL, Web API, Telegram, Cloudflare
│   └── antibot/        # Multi-signal bot detection (IP, JA3, rate, telemetry, polymorphic JS)
├── database/           # BuntDB session persistence
├── gophish/            # Embedded GoPhish fork (email campaigns, SMTP, phishing pages)
│   └── evilginx/       # Bridge interface coupling GoPhish ↔ evilginx proxy
├── phishlets/          # YAML phishlet templates
├── redirectors/        # Cloudflare Turnstile landing pages
├── post_redirectors/   # Post-capture redirect pages
└── web/                # Admin dashboard SPA (index.html, login.html)
```

The application runs as a single interactive CLI (REPL) wrapping long-lived services: HTTPS reverse proxy, built-in DNS server, ACME certificate manager, antibot engine, and Web API.

---

## Official Resources

- **Original Documentation**: https://help.evilginx.com
- **Blog**: https://breakdev.org
- **Training**: [Evilginx Mastery Course](https://academy.breakdev.org/evilginx-mastery)
- **Original Repository**: https://github.com/kgretzky/evilginx2

---

## License & Legal

**BSD-3 Clause License** — Copyright (c) 2018-2023 Kuba Gretzky. All rights reserved.  
Private modifications by AKaZA (Akz0fuku).

**This tool is provided for educational and authorized testing purposes only.**  
By using this software, you agree to:
- Only use it with explicit written authorization
- Comply with all applicable laws and regulations
- Accept full responsibility for your actions

**Unauthorized access to computer systems is illegal.** Use responsibly.

---

## Donations

If this project has been useful to you, feel free to donate to support continued development:

- **USDT (TRC20)**: `TFZ7ivnja4NYbSxxYG2bySEi3Q8VQ7ShMQ`
- **LTC**: `LMktBKBigh1MiJTrshaf4htKfJ7fpQD41S`
- **TRX**: `TFZ7ivnja4NYbSxxYG2bySEi3Q8VQ7ShMQ`

Every contribution is greatly appreciated.

---

## Support

**For this private edition:**
- Contact **AKaZA (Akz0fuku) on Telegram (@Akaza0fuku)** for support.
- Enable debug mode (`-debug`) for detailed logs.
