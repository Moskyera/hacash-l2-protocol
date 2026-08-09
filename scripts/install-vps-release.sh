#!/usr/bin/env bash
set -euo pipefail
umask 077

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
ENV_FILE="/etc/hacash-l2-hub.env"

die() { echo "$*" >&2; exit 1; }
existing_value() {
  local key="$1"
  [[ -f "$ENV_FILE" ]] || return 0
  sed -n "s/^${key}=//p" "$ENV_FILE" | head -n1
}
no_control_characters() {
  [[ "$1" != *$'\n'* && "$1" != *$'\r'* ]]
}

[[ "$(id -u)" -eq 0 ]] || die "Run as root: sudo -E bash $0"
[[ -n "$PUBLIC_URL" ]] || die "Set PUBLIC_URL=https://your.domain before install."
if [[ "$PUBLIC_URL" != https://* && "${ALLOW_INSECURE_HTTP:-false}" != true ]]; then
  die "PUBLIC_URL must use HTTPS. ALLOW_INSECURE_HTTP is for isolated tests only."
fi
[[ -x ./hacash-l2-hub ]] || die "Run this installer from the extracted Linux release directory."
[[ "$BIND" == 127.0.0.1:* || "$BIND" == "[::1]:"* ]] \
  || die "The Hub backend must bind to loopback; publish it through an HTTPS reverse proxy."
[[ "$PROVIDER_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] \
  || die "PROVIDER_ID must contain only letters, numbers, dot, dash or underscore."
for value in "$PUBLIC_URL" "$FULLNODE" "$BOOTSTRAP" "$SEEDS_URL" "$REGION" "$DATA_DIR" "$USER_NAME"; do
  no_control_characters "$value" || die "Configuration values cannot contain line breaks."
done
if [[ "$FULLNODE" != 127.0.0.1:8080 && "$FULLNODE" != localhost:8080 ]]; then
  echo "Warning: use a trusted private full-node endpoint. Never expose port 8080 publicly."
fi

API_TOKEN="${API_TOKEN:-$(existing_value HACASH_L2_API_TOKEN)}"
IDENTITY_PASSWORD="${IDENTITY_PASSWORD:-$(existing_value HACASH_L2_IDENTITY_PASSWORD)}"
API_TOKEN="${API_TOKEN:-$(openssl rand -hex 24)}"
IDENTITY_PASSWORD="${IDENTITY_PASSWORD:-$(openssl rand -hex 16)}"
[[ "$API_TOKEN" =~ ^[A-Za-z0-9._~+-]{32,256}$ ]] || die "API_TOKEN is too short or contains unsafe characters."
[[ "$IDENTITY_PASSWORD" =~ ^[A-Za-z0-9._~+-]{32,256}$ ]] \
  || die "IDENTITY_PASSWORD is too short or contains unsafe characters."

id "$USER_NAME" >/dev/null 2>&1 \
  || useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin "$USER_NAME"
mkdir -p "$DATA_DIR"
chown -R "$USER_NAME:$USER_NAME" "$DATA_DIR"
install -m 0755 ./hacash-l2-hub /usr/local/bin/hacash-l2-hub

env_tmp="$(mktemp /etc/hacash-l2-hub.env.XXXXXX)"
unit_tmp="$(mktemp /etc/systemd/system/hacash-l2-hub.service.XXXXXX)"
cleanup() { rm -f -- "$env_tmp" "$unit_tmp"; }
trap cleanup EXIT

cat > "$env_tmp" <<EOF
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
install -m 0600 -o root -g root "$env_tmp" "$ENV_FILE"

cat > "$unit_tmp" <<EOF
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
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
[Install]
WantedBy=multi-user.target
EOF
install -m 0644 -o root -g root "$unit_tmp" /etc/systemd/system/hacash-l2-hub.service

systemctl daemon-reload
systemctl enable --now hacash-l2-hub

echo "HPAY Fast Pay Hub installed."
echo "Service: systemctl status hacash-l2-hub"
echo "Health:  curl -fsS ${PUBLIC_URL}/health"
echo "Secrets: ${ENV_FILE} (root-only; back up the identity securely)"
