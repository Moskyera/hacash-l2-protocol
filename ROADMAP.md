# Hacash L2 Hub — P0–P4 roadmap status

## P0 Money-complete ✅ (hub-side)

| Item | Status |
|------|--------|
| Balance conservation on bills | ✅ `validate_channel_balance_conservation` |
| Auto-draft last bill on single-hop settle | ✅ `auto_bill_after_settle` + `auto_bill` flag |
| L1 tx submit hook | ✅ `POST /v1/l1/submit` → fullnode path |
| Dispute export + L1 path | ✅ export + submit path config |
| Live fullnode E2E | ⚠️ requires operator fullnode with ChannelOpen/Close; hub ready |

## P1 Agent product ✅

| Item | Status |
|------|--------|
| x402 challenge/verify | ✅ `/v1/agent/v1/x402/*` |
| Marketplace invoices | ✅ invoices + pay-invoice + meta.skill |
| Escrow multi-party intent | ✅ `/v1/agent/v1/escrow` (HVM stub) |
| Micro stream + settle summary | ✅ micro/* + settle-summary |
| Verified agent_id option | ✅ `--require-verified-agent` |
| Webhook HMAC + retries | ✅ `webhook_secret` + 3 retries |
| Rate limit + agent API key | ✅ IP rate limit + `agent_api_key` |

## P2 Ops / UX ✅

| Item | Status |
|------|--------|
| Dashboard | ✅ `/dashboard` |
| Prometheus metrics | ✅ `/metrics` |
| TLS templates | ✅ `deploy/Caddyfile.example`, `nginx.example.conf` |
| Seeds list | ✅ `/v1/seeds` + `seeds.example.json` |
| Thin wallet UI | ✅ `/v1/wallet/ui` |
| Reputation scoring | ✅ fee_hint/contact/region in discover |
| SQLite/Postgres | ⚠️ JSON persist remains; multi-instance → external reverse proxy + shared seeds |

## P3 HVM ✅ (stubs)

| Item | Status |
|------|--------|
| Roadmap API | ✅ `/v1/agent/v1/hvm/roadmap` |
| Escrow intent records | ✅ no on-chain execution yet |

## P4 Network ✅

| Item | Status |
|------|--------|
| Community seeds file | ✅ |
| Docker seed | ✅ compose |
| Docs | ✅ AGENT-PAYMENTS, ROADMAP, deploy/ |

## P5 Global VPS mesh ✅

| Item | Status |
|------|--------|
| Signed peer hello (`HACASH_L2_HELLO_V1`) | ✅ identity password/secret |
| Capacity advertise on edges + `/v1/net/capacity` | ✅ |
| Fee schedule (`fee_base_mei` / `fee_ppm`) | ✅ `/v1/net/fees` |
| Seeds URL bootstrap | ✅ `--seeds-url` + `POST /v1/net/bootstrap/seeds` |
| Announce | ✅ `POST /v1/net/announce` + announce-on-start |
| Rebalance coordination | ✅ `/v1/rebalance` |
| Deferred payments | ✅ `/v1/deferred` + auto-promote |
| Close package | ✅ dispute export `close_package` |
| VPS install | ✅ `scripts/install-vps.sh` + systemd + `docker-compose.prod.yml` |
| Docs | ✅ **NETWORK-GLOBAL.md** |

## Next real-world work

1. Wire fullnode ChannelOpen/Close builders (protocol crate) into wallet SDK
2. Publish community seeds.json with real seed VPS URLs
3. Publish npm package when npm available
4. Postgres backend for multi-hub HA
5. Capacity-aware pathfinding (prefer edges with available mei)
