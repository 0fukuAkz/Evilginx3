<p align="center">
  <img alt="Evilginx2 Logo" src="media/img/evilginx2-logo-512.png" height="160" />
  <p align="center">
    <img alt="Evilginx2 Title" src="media/img/evilginx2-title-black-512.png" height="60" />
  </p>
</p>

# Evilginx 3.7.2 - Private Dev Edition

**Evilginx** is a man-in-the-middle attack framework used for phishing login credentials along with session cookies, which in turn allows to bypass 2-factor authentication protection.

This **Private Development Edition** includes advanced evasion, detection, and operational features not available in the standard release.

**Modified by:** AKaZA (Akz0fuku)  
**Original Author:** Kuba Gretzky ([@mrgretzky](https://twitter.com/mrgretzky))  
**Version:** 3.7.2 - Private Dev Edition

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

- **Go 1.26.10+** — [Download Go](https://golang.org/dl/)
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

### Hot-reloading phishlets

Edit a phishlet YAML file on disk and reload it without restarting the process:

```
: phishlets reload o365       # reload a single phishlet
: phishlets reload            # reload all phishlets (picks up new files too)
```

Enabled state, hostname, and all other per-phishlet settings are preserved across reloads. Child phishlets are automatically rebuilt from their updated parent.

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

## Licensing

This edition requires a license key issued by the admin.

### Installing the license

Place the token in the config directory before first launch:

```bash
cat > ~/.evilginx/license.key <<'EOF'
<paste token here>
EOF
```

Or just launch evilginx — if the file is missing, it will prompt you to paste the key interactively:

```
No license key found. Contact your admin to obtain one.
Paste license key:
```

### What the license checks

On every startup evilginx:

1. Reads `<cfgDir>/license.key` and verifies the Ed25519 signature.
2. Checks the expiry date.
3. If the license is bound to an IP, verifies the machine has that IP on a live network interface.

If any check fails, the process exits with a clear error message.

### Heartbeat (phone-home)

After startup, evilginx phones home every **5 minutes** to the admin's heartbeat server and checks the revocation list every **1 minute**. If either signals the license is revoked, the process exits immediately.

- Network errors (server unreachable, timeout) are non-fatal — evilginx keeps running.
- HTTP 403 from the heartbeat server or a match in `revoked.json` → immediate shutdown.
- The heartbeat includes an HMAC proof so the server can verify the client holds the actual token.

### Admin VPS bypass

If evilginx is running on the same machine as the heartbeat server, all license checks are automatically skipped — no `license.key` needed on the admin machine.

---

## What's New

### v3.7.1
- **Phishlet hot-reload** — `phishlets reload [name]` re-reads YAML files from disk without restarting the process; picks up new phishlet files too; preserves enabled state and hostname across reloads
- Bumped Go toolchain to 1.26.10 and `golang.org/x/net` to v0.60.0, resolving 13 call-graph-reachable CVEs (`crypto/x509`, `net/http`, `x/net`, and related stdlib packages)
- Fixed CI build: `make build` no longer auto-runs keygen when `admin.key` is absent
- Updated Docker builder base image to `golang:1.26.10-alpine`

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

Contact Admin @Akaza0fuku on Telegram for License

---

## Donations

If this project has been useful to you, feel free to donate to support continued development:

- **USDT (TRC20)**: `TFZ7ivnja4NYbSxxYG2bySEi3Q8VQ7ShMQ`
- **LTC**: `LMktBKBigh1MiJTrshaf4htKfJ7fpQD41S`
- **TRX**: `TFZ7ivnja4NYbSxxYG2bySEi3Q8VQ7ShMQ`
  
---

## Support

**For this private edition:**
- Contact **AKaZA (Akz0fuku) on Telegram (@Akaza0fuku)** for support and License.
- Enable debug mode (`-debug`) for detailed logs.
