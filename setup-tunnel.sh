#!/bin/bash
# ============================================================
# Cloudflare Tunnel Setup for Evilginx Admin Panels
# Exposes localhost panels via public subdomains
#
# USAGE: Edit the variables below before running.
# ============================================================

set -eu

# ── Configuration ── EDIT THESE BEFORE RUNNING ──────────────
DOMAIN="${TUNNEL_DOMAIN:-YOUR_DOMAIN_HERE}"          # e.g. example.com
TUNNEL_NAME="${TUNNEL_NAME:-evilginx-panels}"
ADMIN_SUB="${TUNNEL_ADMIN_SUB:-admin}"               # admin.<DOMAIN> → localhost:2030
GOPHISH_SUB="${TUNNEL_GOPHISH_SUB:-gophish}"         # gophish.<DOMAIN> → localhost:3333
# ────────────────────────────────────────────────────────────

# Validate placeholders
if [ "$DOMAIN" = "YOUR_DOMAIN_HERE" ]; then
    echo "[ERROR] Set DOMAIN before running, e.g.:"
    echo "  TUNNEL_DOMAIN=example.com bash setup-tunnel.sh"
    exit 1
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     Cloudflare Tunnel Setup — Evilginx Admin Panels      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "This will create:"
echo "  • https://${ADMIN_SUB}.${DOMAIN}  → Web Admin API (port 2030)"
echo "  • https://${GOPHISH_SUB}.${DOMAIN} → GoPhish Admin  (port 3333)"
echo ""

# ── Helper: get tunnel ID by name ───────────────────────────
get_tunnel_id() {
    cloudflared tunnel list -o json 2>/dev/null | python3 -c "
import sys, json
tunnels = json.load(sys.stdin)
for t in tunnels:
    if t['name'] == '$1':
        print(t['id'])
        break
" 2>/dev/null || true
}

# ── Step 1: Install cloudflared ──────────────────────────────
echo "═══════════════════════════════════════════════════════════"
echo "▶ Step 1: Installing cloudflared"
echo "═══════════════════════════════════════════════════════════"

if command -v cloudflared &> /dev/null; then
    echo "[✓] cloudflared already installed: $(cloudflared --version)"
else
    ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    echo "[INFO] Downloading cloudflared for ${ARCH}..."
    curl -sL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.deb" \
        -o /tmp/cloudflared.deb
    dpkg -i /tmp/cloudflared.deb
    rm -f /tmp/cloudflared.deb
    echo "[✓] cloudflared installed: $(cloudflared --version)"
fi

# ── Step 2: Authenticate with Cloudflare ─────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "▶ Step 2: Authenticate with Cloudflare"
echo "═══════════════════════════════════════════════════════════"

if [ -f "$HOME/.cloudflared/cert.pem" ]; then
    echo "[✓] Already authenticated (cert.pem exists)"
else
    echo ""
    echo "[ACTION REQUIRED] A URL will appear below."
    echo "  1. Copy the URL and open it in your browser"
    echo "  2. Log in to Cloudflare"
    echo "  3. Select the zone: ${DOMAIN}"
    echo "  4. Return here — it will continue automatically"
    echo ""
    cloudflared tunnel login
    echo "[✓] Authentication complete"
fi

# ── Step 3: Create tunnel ────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "▶ Step 3: Creating tunnel '${TUNNEL_NAME}'"
echo "═══════════════════════════════════════════════════════════"

TUNNEL_ID=$(get_tunnel_id "${TUNNEL_NAME}")

if [ -n "$TUNNEL_ID" ]; then
    echo "[✓] Tunnel '${TUNNEL_NAME}' already exists (ID: ${TUNNEL_ID})"
else
    echo "[INFO] Creating tunnel..."
    cloudflared tunnel create "${TUNNEL_NAME}"
    TUNNEL_ID=$(get_tunnel_id "${TUNNEL_NAME}")
    if [ -z "$TUNNEL_ID" ]; then
        echo "[ERROR] Failed to retrieve tunnel ID after creation."
        exit 1
    fi
fi

echo "[INFO] Tunnel ID: ${TUNNEL_ID}"

# ── Step 4: Create config ────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "▶ Step 4: Writing tunnel config"
echo "═══════════════════════════════════════════════════════════"

CRED_FILE=""
if [ -f "$HOME/.cloudflared/${TUNNEL_ID}.json" ]; then
    CRED_FILE="$HOME/.cloudflared/${TUNNEL_ID}.json"
elif [ -f "/root/.cloudflared/${TUNNEL_ID}.json" ]; then
    CRED_FILE="/root/.cloudflared/${TUNNEL_ID}.json"
else
    echo "[ERROR] Credentials file not found for tunnel ID: ${TUNNEL_ID}"
    exit 1
fi

cat > "$HOME/.cloudflared/config.yml" <<EOF
tunnel: ${TUNNEL_ID}
credentials-file: ${CRED_FILE}

ingress:
  - hostname: ${ADMIN_SUB}.${DOMAIN}
    service: http://localhost:2030
  - hostname: ${GOPHISH_SUB}.${DOMAIN}
    service: http://localhost:3333
  # Catch-all (required by cloudflared)
  - service: http_status:404
EOF

echo "[✓] Config written to $HOME/.cloudflared/config.yml"
cat "$HOME/.cloudflared/config.yml"

# ── Step 5: Create DNS routes ────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "▶ Step 5: Creating DNS routes"
echo "═══════════════════════════════════════════════════════════"

echo "[INFO] Routing ${ADMIN_SUB}.${DOMAIN} → tunnel..."
cloudflared tunnel route dns "${TUNNEL_NAME}" "${ADMIN_SUB}.${DOMAIN}" 2>/dev/null || \
    echo "[WARN] DNS route may already exist for ${ADMIN_SUB}.${DOMAIN}"

echo "[INFO] Routing ${GOPHISH_SUB}.${DOMAIN} → tunnel..."
cloudflared tunnel route dns "${TUNNEL_NAME}" "${GOPHISH_SUB}.${DOMAIN}" 2>/dev/null || \
    echo "[WARN] DNS route may already exist for ${GOPHISH_SUB}.${DOMAIN}"

echo "[✓] DNS routes created"

# ── Step 6: Install as system service ────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "▶ Step 6: Installing as system service"
echo "═══════════════════════════════════════════════════════════"

# Stop existing service if running
systemctl stop cloudflared 2>/dev/null || true

# Install service
cloudflared service install 2>/dev/null || echo "[INFO] Service may already be installed"

# Copy config to system path
mkdir -p /etc/cloudflared
cp "$HOME/.cloudflared/config.yml" /etc/cloudflared/config.yml
cp "${CRED_FILE}" "/etc/cloudflared/${TUNNEL_ID}.json"

# Update credentials path in service config
sed -i "s|credentials-file:.*|credentials-file: /etc/cloudflared/${TUNNEL_ID}.json|" /etc/cloudflared/config.yml

# Start service
systemctl enable cloudflared
systemctl restart cloudflared

echo "[✓] cloudflared service started"

# ── Done ─────────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    ✓ Setup Complete!                      ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║                                                           ║"
echo "║  Web Admin:  https://${ADMIN_SUB}.${DOMAIN}               ║"
echo "║  GoPhish:    https://${GOPHISH_SUB}.${DOMAIN}             ║"
echo "║                                                           ║"
echo "║  Tunnel runs as a systemd service (auto-starts on boot)   ║"
echo "║                                                           ║"
echo "║  Useful commands:                                         ║"
echo "║    systemctl status cloudflared   # check status          ║"
echo "║    journalctl -u cloudflared -f   # view logs             ║"
echo "║    cloudflared tunnel list        # list tunnels          ║"
echo "║                                                           ║"
echo "║  ⚠ RECOMMENDED: Add Cloudflare Access policies for       ║"
echo "║    these subdomains to restrict who can access them.      ║"
echo "║    Dashboard → Zero Trust → Access → Applications        ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
