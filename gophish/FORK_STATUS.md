# GoPhish Fork Status

This directory contains a fork of [gophish/gophish](https://github.com/gophish/gophish)
embedded directly into the evilginx3 codebase. This document tracks its divergence
from upstream so that security patches can be applied systematically.

## Upstream Reference

| Field | Value |
|-------|-------|
| Upstream repo | https://github.com/gophish/gophish |
| Fork base | Approximately v0.12.1 (see note below) |
| Last sync check | 2026-06-14 |
| Local modifications | See "Modified Files" below |

> **Note:** The exact upstream commit this fork was cut from was not recorded.
> Run `git log --follow gophish/models/models.go` to find the earliest commit
> touching these files, then match against upstream tags.

## Coupling Seam

All integration between GoPhish and evilginx flows through:

```
gophish/evilginx/bridge.go   — SessionBridge interface (formal contract)
gophish/evilginx/helpers.go  — URL param encoding / encryption utilities
```

**Do not add direct imports of core/ packages into gophish/ code.**
Any new coupling must go through the SessionBridge interface.

## Modified Files (vs upstream GoPhish)

Files confirmed to diverge from upstream gophish/gophish:

| File | Nature of change |
|------|-----------------|
| `gophish/models/models.go` | DB migration replaced with pressly/goose v3; WAL pragma added |
| `gophish/models/imap.go` | PostIMAP wrapped in transaction; error propagation improved |
| `gophish/imap/imap.go` | Fetch goroutine error propagated via errCh |
| `gophish/imap/monitor.go` | Login error backoff added; checkForNewEmails returns error |
| `gophish/controllers/route.go` | renderTemplate helper; password reset flash message |
| `gophish/middleware/ratelimit/ratelimit.go` | TODO comment removed |
| `gophish/util/util.go` | ParseMail takes []byte instead of *http.Request |
| `gophish/evilginx/` | Entire sub-package is evilginx-specific (not in upstream) |
| `gophish/db/` | Migration SQL files include evilginx-specific schema additions |
| `gophish/config/` | Config extended with evilginx paths |

## How to Apply Upstream Security Patches

1. Check the upstream [releases page](https://github.com/gophish/gophish/releases)
   for security advisories.

2. For each changed upstream file, check the "Modified Files" table above:
   - **Not listed** → safe to copy upstream version directly.
   - **Listed** → manually diff upstream change against local version and merge.

3. Never overwrite `gophish/evilginx/` — it has no upstream equivalent.

4. After merging, run:
   ```bash
   go build -mod=vendor ./...
   go test -mod=vendor ./gophish/...
   ```

5. Update the "Last sync check" date in this file.

## Checking for Upstream Drift

The CI workflow `.github/workflows/upstream-drift.yml` runs weekly and compares
the upstream GoPhish release tag against this fork, posting a summary of files
that have changed upstream.

To run manually:
```bash
# Fetch upstream
git remote add gophish-upstream https://github.com/gophish/gophish || true
git fetch gophish-upstream --tags

# Diff a specific file vs upstream tag
git diff gophish-upstream/master -- gophish/controllers/route.go
```
