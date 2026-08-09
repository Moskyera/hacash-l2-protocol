#!/usr/bin/env bash
set -Eeuo pipefail

readonly NODE_TAG="node-v1.0.10-hpay.1"
readonly NODE_ARCHIVE="hpay-compatible-hacash-fullnode-linux-x86_64-node-v1.0.10-hpay.1.tar.gz"
readonly NODE_SHA256="9501a0c9e7d37d4db634873184388515fb02042b8051ecb89376c3d271e50fa5"
readonly NODE_URL="https://github.com/Moskyera/fullnodedev/releases/download/${NODE_TAG}/${NODE_ARCHIVE}"
readonly NODE_ROOT="/opt/hpay/fullnode"
readonly NODE_DATA="/var/lib/hpay-fullnode/hacash_mainnet_data"
readonly NODE_CONFIG="/etc/hpay/hacash.config.ini"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

TEMP_DIR=""
say() { printf '\n[HPAY] %s\n' "$*"; }
warn() { printf '\n[HPAY warning] %s\n' "$*" >&2; }
die() { printf '\n[HPAY error] %s\n' "$*" >&2; exit 1; }
cleanup() { [[ -z "$TEMP_DIR" || ! -d "$TEMP_DIR" ]] || rm -rf -- "$TEMP_DIR"; }
trap cleanup EXIT
trap 'printf "\n[HPAY error] Installation stopped near line %s. Wallet and Miner files were not touched.\n" "$LINENO" >&2' ERR

usage() {
  cat <<'EOF'
HPAY one-click VPS installer

Recommended:
  sudo bash ./ONE-CLICK-VPS.sh

Unattended:
  sudo HPAY_NONINTERACTIVE=1 HPAY_DOMAIN=hub.example.com \
    HPAY_PROVIDER_ID=MyHub HPAY_FULLNODE_MODE=install \
    bash ./ONE-CLICK-VPS.sh

HPAY_FULLNODE_MODE is "install" or "existing".
Use --check to validate the release without changing the computer.
EOF
}

validate_domain() {
  local value="${1:-}" label
  [[ ${#value} -le 253 ]] || return 1
  [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || return 1
  [[ "$value" == *.* && "$value" != *..* && ! "$value" =~ ^[0-9.]+$ ]] || return 1
  IFS='.' read -ra labels <<< "$value"
  for label in "${labels[@]}"; do
    [[ ${#label} -le 63 && "$label" != -* && "$label" != *- ]] || return 1
  done
}
validate_provider() { [[ "${1:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; }
validate_mode() { [[ "${1:-}" == install || "${1:-}" == existing ]]; }

self_check() {
  validate_domain hub.example.com
  if validate_domain https://hub.example.com; then die "URL passed as domain."; fi
  if validate_domain 127.0.0.1; then die "IP passed as domain."; fi
  if validate_domain bad..example.com; then die "Broken domain passed validation."; fi
  validate_provider HPAYHub_1
  if validate_provider "HPAY Hub"; then die "Unsafe provider passed validation."; fi
  validate_mode install
  validate_mode existing
  [[ "$NODE_SHA256" =~ ^[0-9a-f]{64}$ ]]
  [[ -x "$SCRIPT_DIR/INSTALL-VPS.sh" || -x "$SCRIPT_DIR/install-vps-release.sh" ]]
  [[ -x "$SCRIPT_DIR/hpay-status.sh" ]]
  say "Release check passed. No files or services were changed."
}

supported_host() {
  [[ "$(id -u)" -eq 0 ]] || die "Run: sudo bash ./ONE-CLICK-VPS.sh"
  [[ "$(uname -m)" == x86_64 || "$(uname -m)" == amd64 ]] || die "Only x86_64 is supported."
  [[ -f /etc/os-release ]] || die "Cannot identify Linux."
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == ubuntu || "${ID:-}" == debian ]] || die "Use Ubuntu or Debian."
  command -v systemctl >/dev/null || die "systemd is required."
  command -v apt-get >/dev/null || die "apt is required."
}

ask() {
  DOMAIN="${HPAY_DOMAIN:-}"
  PROVIDER="${HPAY_PROVIDER_ID:-HPAYHub}"
  MODE="${HPAY_FULLNODE_MODE:-}"
  if [[ "${HPAY_NONINTERACTIVE:-0}" != 1 ]]; then
    say "Install HPAY Fast Pay Hub with automatic HTTPS"
    printf '%s\n' "Point a domain to this VPS first." "Open ports 80 and 443 in the VPS firewall."
    while ! validate_domain "$DOMAIN"; do
      read -r -p "Domain without https://: " DOMAIN
    done
    read -r -p "Hub name [HPAYHub]: " answer
    PROVIDER="${answer:-$PROVIDER}"
    if [[ -z "$MODE" ]]; then
      read -r -p "Install full node too? [Y/n]: " answer
      if [[ -z "$answer" || "$answer" =~ ^[Yy] ]]; then MODE=install; else MODE=existing; fi
    fi
    printf 'Domain: https://%s\nHub: %s\nNode: %s\n' "$DOMAIN" "$PROVIDER" "$MODE"
    read -r -p "Continue? [Y/n]: " answer
    [[ -z "$answer" || "$answer" =~ ^[Yy] ]] || die "Cancelled."
  fi
  validate_domain "$DOMAIN" || die "HPAY_DOMAIN must be a valid domain without https://."
  validate_provider "$PROVIDER" || die "Hub name contains unsafe characters."
  validate_mode "$MODE" || die "HPAY_FULLNODE_MODE must be install or existing."
}

packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl tar openssl debian-keyring debian-archive-keyring apt-transport-https gnupg
}

install_node() {
  say "Downloading the pinned HPAY-compatible full node"
  TEMP_DIR="$(mktemp -d)"
  local archive="$TEMP_DIR/$NODE_ARCHIVE" entry source
  curl --fail --show-error --location --proto '=https' --tlsv1.2 --retry 4 --retry-all-errors "$NODE_URL" -o "$archive"
  printf '%s  %s\n' "$NODE_SHA256" "$archive" | sha256sum --check --status || die "Full-node SHA-256 mismatch."
  while IFS= read -r entry; do
    [[ "$entry" != /* && "/$entry/" != *"/../"* ]] || die "Unsafe archive path."
  done < <(tar -tzf "$archive")
  tar -xzf "$archive" -C "$TEMP_DIR"
  source="$TEMP_DIR/hpay-compatible-hacash-fullnode-linux-x86_64"
  [[ -x "$source/hacash" && -f "$source/hacash.config.ini.example" ]] || die "Unexpected node package."

  id hpay-node >/dev/null 2>&1 || useradd --system --home /var/lib/hpay-fullnode --shell /usr/sbin/nologin hpay-node
  install -d -m 0755 "$NODE_ROOT" /etc/hpay
  install -d -m 0750 -o hpay-node -g hpay-node /var/lib/hpay-fullnode "$NODE_DATA"
  install -m 0755 "$source/hacash" "$NODE_ROOT/hacash"
  local config_tmp
  config_tmp="$(mktemp /etc/hpay/hacash.config.ini.XXXXXX)"
  { printf 'data_dir = %s\n\n' "$NODE_DATA"; cat "$source/hacash.config.ini.example"; } > "$config_tmp"
  grep -q '^bind = 127\.0\.0\.1$' "$config_tmp" || die "Node API is not private."
  grep -A3 '^\[miner\]' "$config_tmp" | grep -q '^enable = false$' || die "HAC mining is enabled."
  grep -A3 '^\[diamondminer\]' "$config_tmp" | grep -q '^enable = false$' || die "HACD mining is enabled."
  install -m 0640 -o root -g hpay-node "$config_tmp" "$NODE_CONFIG"
  rm -f -- "$config_tmp"

  cat > /etc/systemd/system/hpay-fullnode.service <<EOF
[Unit]
Description=HPAY-compatible Hacash Full Node (mining disabled)
After=network-online.target
Wants=network-online.target
[Service]
User=hpay-node
Group=hpay-node
ExecStart=${NODE_ROOT}/hacash ${NODE_CONFIG}
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/hpay-fullnode
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now hpay-fullnode
}

check_existing_node() {
  curl --fail --silent --max-time 5 http://127.0.0.1:8080/query/capabilities >/dev/null \
    || die "No HPAY-compatible full node answered at 127.0.0.1:8080."
}

install_hub() {
  local installer="$SCRIPT_DIR/INSTALL-VPS.sh"
  [[ -x "$installer" ]] || installer="$SCRIPT_DIR/install-vps-release.sh"
  [[ -x "$installer" ]] || die "Hub installer is missing."
  (cd "$SCRIPT_DIR"; PUBLIC_URL="https://${DOMAIN}" PROVIDER_ID="$PROVIDER" \
    FULLNODE=127.0.0.1:8080 BIND=127.0.0.1:9090 bash "$installer")
  if [[ "$MODE" == install ]]; then
    install -d /etc/systemd/system/hacash-l2-hub.service.d
    printf '[Unit]\nAfter=hpay-fullnode.service\nWants=hpay-fullnode.service\n' \
      > /etc/systemd/system/hacash-l2-hub.service.d/fullnode.conf
    systemctl daemon-reload
    systemctl restart hacash-l2-hub
  fi
}

install_caddy() {
  command -v caddy >/dev/null 2>&1 || apt-get install -y caddy || {
    TEMP_DIR="${TEMP_DIR:-$(mktemp -d)}"
    curl -fsSL --proto '=https' --tlsv1.2 https://dl.cloudsmith.io/public/caddy/stable/gpg.key -o "$TEMP_DIR/caddy.key"
    gpg --batch --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg "$TEMP_DIR/caddy.key"
    curl -fsSL --proto '=https' --tlsv1.2 https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
      -o /etc/apt/sources.list.d/caddy-stable.list
    chmod 0644 /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
    apt-get update
    apt-get install -y caddy
  }
  install -d /etc/caddy/hpay.d
  local base=/etc/caddy/Caddyfile fragment=/etc/caddy/hpay.d/fast-pay-hub.caddy backup
  backup="$(mktemp -d /etc/caddy/hpay-backup.XXXXXX)"
  [[ ! -f "$base" ]] || cp -a "$base" "$backup/Caddyfile"
  [[ ! -f "$fragment" ]] || cp -a "$fragment" "$backup/fragment"
  touch "$base"
  grep -Fqx 'import /etc/caddy/hpay.d/*.caddy' "$base" || printf '\nimport /etc/caddy/hpay.d/*.caddy\n' >> "$base"
  printf '%s {\n encode zstd gzip\n reverse_proxy 127.0.0.1:9090\n header {\n  Strict-Transport-Security "max-age=31536000"\n  X-Content-Type-Options "nosniff"\n }\n}\n' "$DOMAIN" > "$fragment"
  if ! caddy validate --config "$base" --adapter caddyfile; then
    [[ ! -f "$backup/Caddyfile" ]] || cp -a "$backup/Caddyfile" "$base"
    [[ -f "$backup/Caddyfile" ]] || rm -f -- "$base"
    [[ ! -f "$backup/fragment" ]] || cp -a "$backup/fragment" "$fragment"
    [[ -f "$backup/fragment" ]] || rm -f -- "$fragment"
    die "HTTPS config was rejected; the previous Caddy config was restored."
  fi
  if ! systemctl enable --now caddy || ! systemctl reload caddy; then
    [[ ! -f "$backup/Caddyfile" ]] || cp -a "$backup/Caddyfile" "$base"
    [[ -f "$backup/Caddyfile" ]] || rm -f -- "$base"
    [[ ! -f "$backup/fragment" ]] || cp -a "$backup/fragment" "$fragment"
    [[ -f "$backup/fragment" ]] || rm -f -- "$fragment"
    systemctl reload caddy >/dev/null 2>&1 || true
    die "HTTPS service failed; the previous Caddy config was restored."
  fi
  rm -rf -- "$backup"
}

finish() {
  install -m 0755 "$SCRIPT_DIR/hpay-status.sh" /usr/local/bin/hpay-status
  if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
    ufw allow 80/tcp
    ufw allow 443/tcp
    [[ "$MODE" != install ]] || ufw allow 3337/tcp
  fi
  say "Installed. Run: sudo hpay-status"
  printf 'Public Hub: https://%s\nSecrets: /etc/hacash-l2-hub.env (root-only)\n' "$DOMAIN"
  [[ "$MODE" != install ]] || warn "Wait for full-node mainnet synchronization before using Fast Pay."
  getent ahosts "$DOMAIN" >/dev/null 2>&1 || warn "DNS is not ready yet."
  curl -fsS --max-time 8 "https://${DOMAIN}/health" >/dev/null || warn "HTTPS is not ready; check DNS/firewall."
}

main() {
  case "${1:-}" in
    --help|-h) usage; return ;;
    --check) self_check; return ;;
    "") ;;
    *) usage; die "Unknown option: $1" ;;
  esac
  supported_host
  ask
  packages
  if [[ "$MODE" == install ]]; then install_node; else check_existing_node; fi
  install_hub
  install_caddy
  finish
}
[[ "${BASH_SOURCE[0]}" != "$0" ]] || main "$@"
