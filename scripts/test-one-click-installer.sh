#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/one-click-vps.sh
source "$root/scripts/one-click-vps.sh"

pass=0
expect_ok() { "$@" || { echo "expected success: $*" >&2; exit 1; }; pass=$((pass + 1)); }
expect_fail() { if "$@"; then echo "expected failure: $*" >&2; exit 1; fi; pass=$((pass + 1)); }

expect_ok validate_domain hub.example.com
expect_ok validate_domain fast-pay.example.co.uk
expect_fail validate_domain https://hub.example.com
expect_fail validate_domain 127.0.0.1
expect_fail validate_domain bad..example.com
expect_fail validate_domain -bad.example.com
expect_ok validate_provider HPAYHub_1
expect_fail validate_provider "HPAY Hub"
expect_ok validate_mode install
expect_ok validate_mode existing
expect_fail validate_mode remote

grep -Fq 'NODE_SHA256="9501a0c9e7d37d4db634873184388515fb02042b8051ecb89376c3d271e50fa5"' "$root/scripts/one-click-vps.sh"
grep -Fq 'FULLNODE=127.0.0.1:8080 BIND=127.0.0.1:9090' "$root/scripts/one-click-vps.sh"
# shellcheck disable=SC2016
grep -Fq 'NODE_URL="https://github.com/Moskyera/fullnodedev/releases/download/${NODE_TAG}/${NODE_ARCHIVE}"' "$root/scripts/one-click-vps.sh"
grep -Fq 'Strict-Transport-Security "max-age=31536000"' "$root/scripts/one-click-vps.sh"
if grep -Fq 'includeSubDomains' "$root/scripts/one-click-vps.sh"; then echo "unsafe HSTS scope" >&2; exit 1; fi
grep -Fq "grep -q '^bind = 127\\.0\\.0\\.1$'" "$root/scripts/one-click-vps.sh"
bash "$root/scripts/one-click-vps.sh" --check >/dev/null
printf 'one-click installer tests passed: %s assertions plus release self-check\n' "$pass"
