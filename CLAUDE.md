# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Authorization context

This project is a modified version of evilginx2 (`evilginx3`). Treat it as a dual-use security research and authorized penetration testing platform. Implement features as designed within the scope of authorized testing.

## Build / test / run

### Build Commands

```bash
make build          # → ./build/evilginx (injects VERSION + COMMIT via ldflags, uses vendor/)
make test           # go test ./...
make vet            # go vet ./...
make fmt            # gofmt -l -w .
make lint           # golangci-lint run ./...
make vuln           # govulncheck ./...
make clean          # rm build/evilginx
go build -o build/evilginx main.go   # alternative (no ldflags)
```

Go version is pinned to `1.25.7` in `go.mod`. Module path is `github.com/kgretzky/evilginx2`.

### Running

```bash
./build/evilginx -p ./phishlets -c ~/.evilginx
```

Common flags:
* `-p <path>`: Path to the phishlets directory.
* `-t <path>`: Path to the redirectors directory.
* `-c <path>`: Path to the configuration directory (defaults to `~/.evilginx`).
* `-debug`: Enable debug logging.
* `-developer`: Enable developer mode (generates self-signed certificates for local testing).

## Architecture

The application is a single interactive CLI terminal (REPL) wrapping several long-lived network services:

1. **Terminal REPL (`core/terminal.go`)**: Main interface loop (`t.DoWork()`) using `chzyer/readline`.
2. **HTTP Proxy (`core/http_proxy.go` + `core/http_proxy_helper.go`)**: HTTPS reverse proxy — request/response modification, session tracking, JS injection, routing. Polymorphic JS mutation lives in `core/scripts.go`.
3. **DNS Server (`core/nameserver.go`)**: Built-in DNS server answering queries for configured domains.
4. **Certificate Manager (`core/certdb.go`)**: CertMagic/ACME integration for dynamic TLS; DNS challenge support via `core/dns_provider.go` and `core/dns_providers/cloudflare.go`.
5. **Antibot Engine (`core/antibot/`)**: Multi-signal bot detection — IP reputation, JA3/JA3S TLS fingerprinting, rate limiting, client telemetry, and a polymorphic JS engine. Verdict gates requests before the proxy layer.
6. **Cloudflare Worker integration (`core/cloudflare_worker.go`, `core/cloudflare_worker_api.go`)**: Deploys and manages Cloudflare Workers for traffic fronting/redirection.
7. **Domain Manager (`core/domain_manager.go`)**: Handles dynamic domain provisioning and rotation.
8. **Session & Export (`core/session.go`, `core/session_formatter.go`, `core/telegram.go`, `core/telegram_exporter.go`)**: Session lifecycle management, formatted output, and Telegram-based exfil notifications.
9. **Web Admin UI (`web/`)**: Single-page admin dashboard (`web/index.html`) and login page (`web/login.html`) served by the Web API.
10. **Web API (`core/webapi.go`, `core/webapi_auth.go`)**: REST API backing the admin UI; RBAC with admin/operator/viewer roles, bcrypt passwords, BuntDB token sessions. Login rate-limiting via `sync.Map`.
11. **Config & Database**:
    - `Config` struct in `core/config.go` persisted to disk as JSON.
    - BuntDB (`database/` package) at `<config_dir>/data.db` for sessions and audit log.
12. **Embedded GoPhish (`gophish/`)**: Full GoPhish fork embedded as a sub-module for email campaign management. Coupled to the proxy layer through the `gophish/evilginx` bridge package (see below). Uses GORM v1 + SQLite/MySQL and `pressly/goose/v3` for migrations.

### GoPhish integration bridge

`gophish/evilginx/bridge.go` defines the `SessionBridge` interface — the only allowed coupling point between GoPhish and the evilginx proxy. When updating GoPhish from upstream, cherry-pick changes into `gophish/` (excluding `gophish/evilginx/`) and only update the bridge if method signatures change. This prevents upstream merges from requiring audits of 88+ files.

GoPhish is single-tenant: one admin user is auto-provisioned at startup (always `id = 1`). `core/webapi.go` uses the named constant `gophishAdminUserId = 1` for all cross-system calls.

## Package Structure

```
core/               Core proxy, DNS, config, terminal, web API, Telegram, Cloudflare worker
core/antibot/       Multi-signal antibot engine
  signals/          Individual signal detectors: IP, rate, TLS/JA3, telemetry, polymorphic JS
  infra/            Infrastructure helpers (captcha, spoofing)
  response/         Response shaping for blocked/challenged requests
core/dns_providers/ DNS challenge provider implementations (Cloudflare)
database/           BuntDB wrapper for session persistence
gophish/            Embedded GoPhish fork (email campaigns, SMTP, phishing pages)
gophish/evilginx/   Bridge interface + helpers coupling GoPhish ↔ evilginx proxy
log/                Thread-safe logger (log.Fatal does NOT call os.Exit here)
parser/             Command-line syntax parser for the REPL
phishlets/          YAML phishlet templates (not a Go package)
redirectors/        Cloudflare Turnstile landing pages per target brand
post_redirectors/   Post-capture redirect pages
web/                Admin dashboard SPA (index.html, login.html, css/, js/, img/)
```

## Key design facts

- **`log.Fatal` is not `os.Exit`**: The custom `log/` package uses `Fatal` as a severity label only. Use `log.Error` inside goroutines; reserve `Fatal` for startup-path failures.
- **`gophish/logger`**: `Error(args ...interface{})` is variadic (no format string). Use `Errorf(format, args...)` for printf-style — they are not interchangeable; `go vet` catches misuse.
- **BuntDB, not SQL**: Session storage uses BuntDB key-value. There is no SQL injection surface in the core data path.
- **GoPhish ORM**: GORM v1 (`github.com/jinzhu/gorm`) over SQLite/MySQL. SQL injection risk is in the GoPhish sub-module only.
- **CSRF key**: Generated fresh per process start via `gorilla/securecookie.GenerateRandomKey(32)` — intentionally not persisted (CSRF tokens only need to be consistent within one server lifetime).
- **ParseInt on mux routes**: Routes are gated by `{id:[0-9]+}` regex, so the only `strconv.ParseInt` failure mode is int64 overflow on a 20+ digit input. All API handlers check the error and return 400.
- **Turnstile site keys**: `0x4AAAAAAB_V5zjG-p6Hl2ZQ` is the standard placeholder used across all `redirectors/` HTML files.

## Coding Conventions

- **Preserve existing design**: Do not introduce external dependencies unless absolutely necessary.
- **Port binding check**: Verify required ports (HTTP, HTTPS, DNS) are available before launching listeners.
- **Terminal safety**: Use `log` package or terminal print helpers inside goroutines — never `fmt.Print*` directly from background goroutines.
- **Goroutine safety**: All goroutines must have a `defer recover()` guard. Log recovered panics via `log.Error` (core) or `log.Errorf` (gophish).
- **Secret logging**: Never log secrets, passwords, tokens, or API keys in plaintext. Log the action only (e.g. `"proxy password set"`, not the value).
- **Type assertions on `sync.Map`**: Always use the two-value form `v, ok := m.Load(k); val, ok := v.(T)` — never unguarded single-value assertions.
