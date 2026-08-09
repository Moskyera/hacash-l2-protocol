#!/usr/bin/env bash
set -euo pipefail

PROVIDER_ID="${PROVIDER_ID:-MyHub}"
PUBLIC_URL="${PUBLIC_URL:-}"
FULLNODE="${FULLNODE:-127.0.0.1:8080}"
BOOTSTRAP="${BOOTSTRAP:-}"
SEEDS_URL="${SEEDS_URL:-}"
REGION="${REGION:-}"
FEE_PPM="${FEE_PPM:-0}"
FEE_BASE_MEI="${FEE_BASE_MEI:-0}"
BIND="${BIND:-127.0.0.1:9090}"
DATA_DIR="${DATA_DIR:-/var/lib/hacash-l2}"
USER_NAME="${USER_NAME:-hacash-l2}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo -E bash $0"
  exit 1
fi
if [[ -z "$PUBLIC_URL" ]]; then
  echo "Set PUBLIC_URL=https://your.domain before install."
  exit 1
fi
if [[ "$PUBLIC_URL" != https://* && "${ALLOW_INSECURE_HTTP:-false}" != "true" ]]; then
  echo "PUBLIC_URL must use HTTPS for a public hub."
  echo "For an isolated test only, set ALLOW_INSECURE_HTTP=true."
  exit 1
fi
if [[ ! -x ./hacash-l2-hub ]]; then
  echo "Run this installer from the extracted Linux release directory."
  exit 1
fi
if [[ "$FULLNODE" != "127.0.0.1:8080" && "$FULLNODE" != "localhost:8080" ]]; then
  echo "Warning: use a trusted private full-node endpoint. Never expose port 8080 publicly."
fi

API_TOKEN="${API_TOKEN:-$(openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | xxd -p)}"
IDENTITY_PASSWORD="${IDENTITY_PASSWORD:-$(openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | xxd -p)}"

id "$USER_NAME" &>/dev/null || useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin "$USER_NAME"
mkdir -p "$DATA_DIR"
chown -R "$USER_NAME:$USER_NAME" "$DATA_DIR"
install -m 0755 ./hacash-l2-hub /usr/local/bin/hacash-l2-hub

ENV_FILE="/etc/hacash-l2-hub.env"
cat > "$ENV_FILE" <<EOF
HACASH_L2_BIND=${BIND}
HACASH_L2_PUBLIC_URL=${PUBLIC_URL}
HACASH_L2_PROVIDER_ID=${PROVIDER_ID}
HACASH_L2_NAME=${PROVIDER_ID}
HACASH_L2_FULLNODE=${FULLNODE}
HACASH_L2_BOOTSTRAP=${BOOTSTRAP}
HACASH_L2_SEEDS_URL=${SEEDS_URL}
HACASH_L2_STATE_PATH=${DATA_DIR}/hub-state.json
HACASH_L2_API_TOKEN=${API_TOKEN}
HACASH_L2_IDENTITY_PASSWORD=${IDENTITY_PASSWORD}
HACASH_L2_ALLOW_PRIVATE_PEERS=false
HACASH_L2_REQUIRE_VALID_HELLO_SIG=true
HACASH_L2_PUBLIC=true
HACASH_L2_REGION=${REGION}
HACASH_L2_FEE_PPM=${FEE_PPM}
HACASH_L2_FEE_BASE_MEI=${FEE_BASE_MEI}
HACASH_L2_GOSSIP_SECS=30
HACASH_L2_WATCH_SECS=60
HACASH_L2_ANNOUNCE_ON_START=true
HACASH_L2_SIG_VERIFY=true
RUST_LOG=hacash_l2_hub=info
EOF
chmod 600 "$ENV_FILE"
chown root:root "$ENV_FILE"

UNIT="/etc/systemd/system/hacash-l2-hub.service"
cat > "$UNIT" <<EOF
[Unit]
Description=HPAY Fast Pay Hub
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${USER_NAME}
Group=${USER_NAME}
EnvironmentFile=/etc/hacash-l2-hub.env
ExecStart=/usr/local/bin/hacash-l2-hub
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now hacash-l2-hub

echo "HPAY Fast Pay Hub installed."
echo "Service: systemctl status hacash-l2-hub"
echo "Health:  curl -fsS ${PUBLIC_URL}/health"
echo "Secrets: ${ENV_FILE} (root-only; back up the identity securely)"
