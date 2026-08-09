#!/usr/bin/env bash
set -u

green='\033[0;32m'; yellow='\033[0;33m'; red='\033[0;31m'; reset='\033[0m'
service_status() {
  local unit="$1" label="$2"
  if ! systemctl list-unit-files "$unit" >/dev/null 2>&1; then
    printf '%-18s %bnot installed%b\n' "$label" "$yellow" "$reset"
  elif systemctl is-active --quiet "$unit"; then
    printf '%-18s %brunning%b\n' "$label" "$green" "$reset"
  else
    printf '%-18s %bstopped/failed%b\n' "$label" "$red" "$reset"
  fi
}
endpoint_status() {
  if curl --fail --silent --max-time 5 "$1" >/dev/null 2>&1; then
    printf '%-18s %bready%b\n' "$2" "$green" "$reset"
  else
    printf '%-18s %bnot ready%b\n' "$2" "$yellow" "$reset"
  fi
}

printf 'HPAY Fast Pay status\n\n'
service_status hpay-fullnode.service "Full node service"
service_status hacash-l2-hub.service "Hub service"
service_status caddy.service "HTTPS service"
printf '\n'
endpoint_status http://127.0.0.1:8080/query/capabilities "Full node API"
endpoint_status http://127.0.0.1:9090/health "Local Hub"
if [[ -r /etc/hacash-l2-hub.env ]]; then
  public_url="$(sed -n 's/^HACASH_L2_PUBLIC_URL=//p' /etc/hacash-l2-hub.env | head -n1)"
  [[ "$public_url" != https://* ]] || endpoint_status "${public_url}/health" "Public HTTPS"
fi
printf '\nLogs if something is not ready:\n'
printf '  sudo journalctl -u hpay-fullnode -u hacash-l2-hub -u caddy -n 100 --no-pager\n'
