# Global L2 mesh — κάθε χρήστης VPS → παγκόσμιο δίκτυο

Στόχος: **ο καθένας τρέχει `hacash-l2-hub` σε VPS**, χωρίς κεντρικό master, με **όλες τις ιδιότητες** του Channel Chain / CSP μοντέλου.

```
  Wallet / AI Agent
         │
    GET /v1/discover  (1 seed URL)
         │
    ┌────┴────┬────────────┐
    ▼         ▼            ▼
  VPS-A     VPS-B        VPS-N
 AliceHub  BobHub       …
    │         │            │
    └──── signed hello / gossip / capacity / fees ────┘
                      │
                 L1 fullnode(s)
```

## Ιδιότητες (whitepaper → hub)

| Ιδιότητα | Endpoint / flag | Σημείωση |
|----------|-----------------|----------|
| CSP χωρίς custody | design | Κλειδιά μόνο σε wallet/agent |
| Channel register + L1 query | `/v1/channels`, `/v1/l1/channel/:id` | Hub δεν ανοίγει κανάλι· wallet/L1 |
| Instant multi-hop pay | `POST /v1/payments` | BFS path, ordered multi-sig |
| Ordered sigs payee→payer | `POST /v1/payments/:id/sign` | secp256k1 + SHA3-256 |
| Last bill only | `/v1/channels/:id/bill` | Ιστορικό απορρίπτεται |
| Dispute / close package | `GET /v1/channels/:id/dispute` | `close_package` για L1 close |
| Rebalancing | `/v1/rebalance` | Συντονισμός· bills υπογράφουν τα parties |
| Deferred payments | `/v1/deferred` | Schedule → promote → live session |
| Fee market (CSP) | `GET /v1/net/fees` | `fee_base_mei` + `fee_ppm` hints |
| Capacity advertise | `GET /v1/net/capacity` | mei ανά κανάλι στο hello |
| Signed peer hello | `POST /v1/net/hello` | `HACASH_L2_IDENTITY_*` |
| Gossip / bootstrap | `--bootstrap`, gossip loop | Mesh χωρίς central DB |
| Community seeds | `--seeds-url`, `/v1/seeds`, `POST /v1/net/bootstrap/seeds` | 2–5 stable seeds |
| Announce | `POST /v1/net/announce` | Proactive join |
| Discover directory | `GET /v1/discover` | Wallet «Find hubs» |
| Agent protocol | `/v1/agent/v1/*` | HAP + tools + invoices |

## VPS setup (5 λεπτά)

### 1. Binary

```bash
# από source
cargo build --release
sudo install -m 755 target/release/hacash-l2-hub /usr/local/bin/

# ή Docker — βλ. docker-compose.yml + scripts/install-vps.sh
```

### 2. Ταυτότητα hub (υποχρεωτικό για production mesh)

```bash
export HACASH_L2_IDENTITY_PASSWORD='long-random-passphrase-only-you-know'
# ή
export HACASH_L2_IDENTITY_SECRET_HEX='<64 hex chars = 32 bytes>'
```

Χωρίς identity → hellos **unsigned** (OK για lab, αδύναμο για global trust).

### 3. Run

```bash
hacash-l2-hub \
  --bind 0.0.0.0:9090 \
  --public-url https://hub.example.com \
  --provider-id YourUniqueName \
  --name "my-vps-hub" \
  --fullnode 127.0.0.1:8080 \
  --bootstrap https://seed1.example,https://seed2.example \
  --seeds-url https://community.example/seeds.json \
  --state-path /var/lib/hacash-l2/hub-state.json \
  --api-token "$(openssl rand -hex 24)" \
  --fee-base-mei 0 \
  --fee-ppm 1000 \
  --region eu \
  --public true \
  --identity-password "$HACASH_L2_IDENTITY_PASSWORD"
```

Ή systemd: `scripts/hacash-l2-hub.service` + `scripts/install-vps.sh`.

### 4. Firewall / reverse proxy

- Άνοιξε **TCP 9090** (ή μόνο 443 πίσω από Caddy/nginx — `deploy/`).
- `HACASH_L2_PUBLIC_URL` = το **δημόσιο** HTTPS URL (όχι private IP).
- Production: `HACASH_L2_ALLOW_PRIVATE_PEERS=false`.

## Πώς σχηματίζεται το παγκόσμιο δίκτυο

1. **Seeds**: κοινότητα δημοσιεύει `seeds.json` (βλ. `seeds.example.json`).
2. Νέο VPS: `--bootstrap` ή `--seeds-url` → hello σε seeds.
3. Seeds μαθαίνουν τον νέο hub· **gossip** (`--gossip-secs 30`) διαδίδει peers + channels.
4. Wallet χρειάζεται **1 seed URL** → `GET /v1/discover` → ranked list.
5. Agent: `GET /v1/agent/connect` στο seed → `attach_to` best hub.

Δεν χρειάζεται full mesh 50×50 από την αρχή. Gossip γεμίζει τον γράφο.

## Fee schedule (CSP market)

```http
GET /v1/net/fees
```

- `fee_base_mei` — flat hint
- `fee_ppm` — parts per million στο amount
- **Δεν** είναι on-chain enforced· multi-hop wallets μπορούν να επιλέξουν φθηνότερο path από `meta`.

## Capacity + directional liquidity

```http
GET /v1/net/capacity
```

Advertised channels στο hello διατηρούν τα legacy πεδία ολόκληρων HAC
`capacity_mei`, `left_available_mei`, `right_available_mei`. Από protocol 2.0
τα ακριβή πεδία `capacity_zhu`, `left_available_zhu`, `right_available_zhu`
χρησιμοποιούνται κατά προτεραιότητα για routing και μικροπληρωμές.

**Routing (σημαντικό):** όταν το amount είναι γνωστό και το edge έχει `liquidity_known` (local channels πάντα):
- κάθε hop απαιτεί **διαθέσιμο mei στην πλευρά του sender** (`can_send_from`)
- explicit routes ελέγχονται hop-by-hop
- unknown liquidity (peer ads χωρίς balances) → δεν μπλοκάρει (best-effort)

Local balances από registration = authoritative· peer ads με μόνο total capacity = soft bound και στις δύο πλευρές.

### Μετά settle (hub balances)

Όταν payment γίνει `settled` (hub multi-sig complete):

1. **Shift** balances σε κάθε **local** hop της route (`balance_source=payment_settle`) — για σωστό routing/liquidity στο επόμενο pay.
2. **Auto-bill draft** ανά hop (parties πρέπει ακόμα να υπογράψουν το last bill).
3. Όταν bill γίνει **Active** → balances mirror από bill (`balance_source=active_bill`) — authoritative για L1 close package.

Idempotent ανά `payment_id` (δεν διπλο-αφαιρεί). Remote hops χωρίς local channel: skip shift, walker μέσω ads.

## Rebalance

```http
POST /v1/rebalance
{ "channel_a": "<hex>", "channel_b": "<hex>", "amount_mei": 100, "note": "..." }
```

1. Hub καταγράφει proposal (shared address required).
2. Parties προτείνουν **νέα last bills** και στα δύο κανάλια.
3. `POST /v1/rebalance/:id/complete` όταν και τα δύο bills είναι `active`.

## Deferred pay

```http
POST /v1/deferred
{ "payer":"...", "payee":"...", "amount_hac":"1:247", "execute_after_unix": 1893456000 }
```

TTL loop προωθεί due intents → live `PaymentSession` (ακόμα χρειάζονται υπογραφές).

## Close / dispute package + agent close-plan

```http
GET /v1/channels/:id/dispute
GET /v1/agent/v1/close-plan/:channel_id
```

Επιστρέφει `close_package` (`hacash-l2-close-package/1`) και agent `close_plan` (`hacash-l2-close-intent/1`) με distribution + bill signatures για wallet/fullnode ChannelClose.

SDK (Python/TS):
```python
intent = client.close_intent(channel_id)
if intent["ready_for_l1_close"]:
    # wallet builds ChannelClose wire from intent["distribution"] + bill_signatures
    client.submit_signed_l1_tx(signed_tx_hex)  # optional relay; needs api token
```

Το hub **δεν** encode-άρει L1 ChannelClose και **δεν** κρατά keys. Μόνο evidence + optional submit relay.

## Cross-hub payment mirrors (non-authoritative)

When a payment route uses channels advertised by **other** hubs (`remote_hops`):

1. **Origin hub** remains the only place that accepts user signatures and decides commit.
2. Origin **best-effort** `POST {peer}/v1/net/payment-notify` to each remote hub URL.
3. Remote hubs store a **foreign mirror** only if the notify involves their `via_provider` or a local channel.
4. Agent `GET /v1/agent/v1/inbox` on a remote hub may return items with `kind: sign_on_origin_hub` — sign at `action.sign_endpoint` (origin), not locally.
5. Origin re-notifies after each signature / settle so remotes update `next_signer` and status.

```http
POST /v1/net/payment-notify   # hub-to-hub
GET  /v1/net/foreign-payments # ops: list mirrors
```

These notifications are discovery/UI mirrors only; durable settlement uses the 2PC endpoints documented below.

## Signed hello

Domain: `HACASH_L2_HELLO_V1`
Υπογράφεται: provider_id, public_url, name, timestamp, protocol_version,
identity, channel_ids, fees και capacity. Στο protocol 2.x η υπογραφή περιέχει
επιπλέον canonical hash όλων των channel advertisement fields, οπότε μεταβολή
σε address, provider, fee ή liquidity ακυρώνει το hello.

```http
GET /v1/net/self   # δες το δικό σου signed hello
POST /v1/net/hello # inbound από peers
```

`HACASH_L2_REQUIRE_VALID_HELLO_SIG=true` απορρίπτει bad signatures.
`HACASH_L2_HELLO_MAX_AGE_SECS=600` replay window.

## Checklist production

- [ ] Unique `provider_id` (χωρίς spaces/underscores)
- [ ] HTTPS `public_url`
- [ ] Identity password/secret
- [ ] `api_token` + optional `agent_api_key`
- [ ] `HACASH_L2_REQUIRE_VERIFIED_AGENT=true` (policy binds to `v:address`)
- [ ] `state_path` + disk backups
- [ ] 1–3 bootstrap seeds
- [ ] Fullnode reachable για L1 query/watch
- [ ] `allow_private_peers=false`
- [ ] Firewall + fail2ban / rate limits

## Όρια (honest)

| Έτοιμο στο hub | Ακόμα wallet/L1 |
|----------------|-----------------|
| CSP coordination, bills, mesh | ChannelOpen/Close builders |
| Fee **hints** | On-chain fee market |
| Rebalance **coord** | Automatic multi-party atomic rebalance |
| Close **package** | Full L1 arbitration tx encode |
| Privacy of amounts | Off-chain only between parties; hub sees sessions it coordinates |

Για HVM/scriptable evolution: `HVM-EVOLUTION.md`.
## Multi-hop cross-hub settlement (durable 2PC)

A route that contains channels owned by other hubs uses authenticated,
blocking two-phase commit:

1. The origin creates one content-bound, idempotent payment session and fsyncs
   `coordinator_preparing` to `<state_path>.txlog`.
2. Every participant verifies the signed descriptor, proves exact coverage of
   its channels in the user-signed route, reserves directional liquidity, and
   fsyncs `participant_prepared` before acknowledging.
3. Users or agents sign the same canonical hash in payee-to-payer order.
4. After all signatures verify, the coordinator fsyncs the irreversible
   `coordinator_commit_decided` record before any balance change or commit
   message.
5. Every participant verifies the complete Hacash signature set, records its
   decision, applies local hops exactly once, and acknowledges.
6. Missing commit or abort acknowledgements remain in the journal and are
   retried after restart. The origin stays `committing` until commit delivery
   completes.

A prepared participant never guesses, expires, or aborts on its own. This is
the blocking trade-off of 2PC: during coordinator failure its reserved
liquidity remains locked until a signed decision arrives.

```http
POST /v1/net/tx/prepare
POST /v1/net/tx/commit
POST /v1/net/tx/abort
GET  /v1/net/transactions     # operator only
```

Cross-hub execution is fail-closed unless every involved hub has a persistent
`state_path`, a local identity key, strict signed-hello verification, and
pinned verified peers advertising `distributed-2pc`.

Human clients must send `Idempotency-Key` to `POST /v1/payments` or
`/v1/wallet/pay` whenever the selected route crosses hubs; wallet JSON may use
`idempotency_key`. AI agents use `/v1/agent/v1/pay`, where the key is always
required. Retry an ambiguous response with the same key and identical fields.
