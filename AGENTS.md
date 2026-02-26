# AGENTS.md

## Cursor Cloud specific instructions

This is a Go 1.24 monolithic application (Evilginx). Dependencies are vendored in the `vendor/` directory.

### Relevant services

| Service | Description |
|---------|-------------|
| Evilginx binary | Single Go binary: DNS server, HTTP/HTTPS reverse proxy, interactive CLI |

### Build, lint, test, run

Standard commands are documented in the `Makefile` and `README.md`:

- **Build**: `make build` (output: `./build/evilginx`)
- **Lint**: `go vet -mod=vendor ./...`
- **Test**: `go test -mod=vendor ./...` (no test files exist in this codebase currently)
- **Run (dev)**: `./build/evilginx -developer -p ./phishlets -t ./redirectors`

### Non-obvious caveats

- Go 1.24 is required (`go.mod` specifies `go 1.24`). The system default Go (1.22) is insufficient; Go 1.24 is installed at `/usr/local/go/bin/go` and added to `PATH` via `~/.bashrc`.
- The binary needs `cap_net_bind_service` capability to bind ports 53/80/443 without root: `sudo setcap 'cap_net_bind_service=+ep' ./build/evilginx`. Re-run this after every rebuild.
- Use `-developer` flag for local development (self-signed certs, no Let's Encrypt/DNS required).
- The `-mod=vendor` flag is required for all `go` commands since dependencies are vendored.
- No external databases are needed; the app uses embedded BuntDB (file-based).
- The app is an interactive CLI. For non-interactive testing, pipe commands via stdin: `printf 'config domain test.local\nphishlets\nexit\n' | ./build/evilginx -developer ...`
