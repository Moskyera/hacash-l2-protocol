# Hacash L2 Hub — Security and Protocol Audit

Date: 2026-07-26
Scope: Rust hub, peer mesh, payment/bill state machines, persistence, HTTP APIs,
Docker/VPS deployment, Python SDK, TypeScript SDK.

## Executive verdict

**Do not deploy this version with real funds or advertise it as a working global
payment network yet.**

The implementation is a useful prototype, but five stop-ship areas remain:

1. HAC amount arithmetic is not protocol-correct.
2. Settlement is acknowledged before an atomic, durable balance commit.
3. Cross-hub hops are not committed on the remote hubs.
4. The persistence layer is not transactional or crash-safe.
5. Spending and administrative actions are not consistently bound to a signed
   request from the claimed address/agent.

The official Hacash amount documentation states that `1:248 = 1 HAC` and
`1:247 = 0.1 HAC`; the current parser treats both as integer `1`:
<https://hacash.org/HAC-unit?amount=8%3A246>.

The official CSP documentation shows a 16-byte/32-hex channel ID:
<https://hacash.org/layer-2-node?lang=en>. That compatibility issue has been
fixed in this audit.

## Fixes applied

### 1. Multi-hop signature order

`src/route.rs` now walks the payer-to-payee path in reverse while constructing
the payee-to-payer signer order. Previously, routes longer than two hops omitted
intermediaries. A four-hop regression test now requires:

`payee -> intermediary 3 -> intermediary 2 -> intermediary 1 -> payer`

### 2. Hacash L1 channel ID width

`src/state.rs::normalize_channel_id` now accepts exactly 16 bytes/32 hex
characters instead of 32 bytes/64 hex characters. Test fixtures and a
real-width regression test were updated.

### 3. Active reconciliation bill preservation

`src/state.rs` now stores:

- the last fully signed active bill; and
- the unsigned/partially signed replacement draft

in separate maps. A new draft can no longer erase the last usable arbitration
proof. The draft is promoted atomically in memory only after both signatures
are accepted. Persistence includes both records because `list_bills()` returns
both.

This fixes the direct overwrite bug, but durable bill safety still depends on
replacing JSON snapshots with a transactional store.

### 4. Foreign signing-oracle mitigation

Unauthenticated foreign notifications are no longer converted into agent inbox
signing work. The response explicitly reports `foreign_signing_disabled`.

Both SDKs now:

- refuse `sign_on_origin_hub` auto-signing;
- accept only the exact local `/v1/agent/v1/sign` origin and path;
- reject credentials, query strings and fragments in signing endpoints; and
- refuse to send a signature or API key to another origin.

The bulk inbox helper now auto-signs only reviewed local incoming-payment
(`payee`) items. Payer and intermediary actions require an explicit
application-level decision.

These are fail-closed mitigations. They intentionally make the incomplete
cross-hub signing flow unavailable until an authenticated inter-hub protocol
exists.

### 5. SDK and Docker correctness

Three additional confirmed defects were fixed:

- `.dockerignore` now includes `NETWORK-GLOBAL.md`, which the Dockerfile copies;
  previously a clean Docker build could not access that source file.
- Python signing now uses deterministic RFC6979/HMAC-SHA256 and canonical low-S
  encoding, matching the Rust/TypeScript expectations. A deterministic/low-S
  regression test was added.
- TypeScript hex decoding now rejects odd-length and non-hex input rather than
  padding or silently converting invalid pairs. Regression tests were added.

## Stop-ship findings

### CRITICAL-1 — Incorrect HAC amount model

Evidence:

- `src/amounts.rs:67-73` discards the unit after `:`.
- Routing and settlement use this value in `src/state.rs`.
- Balance formatting rewrites values into a fixed unit, losing the original
  magnitude.

Impact:

- `1:247`, `1:248` and `1:255` can be priced as the same amount.
- malformed values often become zero through `unwrap_or(0)`;
- routing limits, fees, balances and conservation checks are unreliable.

Required fix:

- introduce one canonical `HacAmount` type using checked mantissa/unit math;
- choose a documented exact internal base unit;
- reject malformed, negative, zero-when-disallowed, non-canonical and
  overflowing values;
- use the same type in routing, policy, fees, bills, invoices and SDKs;
- add cross-language vectors from official Hacash amount encoding;
- version and migrate persisted state.

### CRITICAL-2 — Receipt before atomic balance commit

Evidence:

- `src/state.rs:2127-2139` marks the payment settled, creates a receipt and marks
  its invoice paid before checking whether all balance shifts succeed.
- `src/state.rs:2197-2292` mutates channels one hop at a time with no rollback.
- the `auto_bill_after_settle` error is ignored.

Impact:

- two payments can spend the same liquidity;
- a payment can receive a settled receipt even when its balance update fails;
- an early hop can be debited while a later hop fails;
- retry interleavings can reapply a payment because one
  `last_settle_payment_id` per channel is not an exactly-once ledger.

Required fix:

- durable `prepare -> reserve -> commit | abort` state machine;
- preflight every hop before any mutation;
- unique immutable `(payment_id, channel_id)` applied records;
- one database transaction for payment status, balances, bills, invoice and
  receipt;
- return a receipt only after durable commit.

### CRITICAL-3 — Cross-hub settlement is not implemented

Evidence:

- remote peer advertisements are used for route construction;
- `apply_payment_balance_shifts` skips remote-only channels;
- the origin can still label the session settled and issue a receipt;
- remote notifications are mirrors, not reservations or settlement authority.

Impact:

A route can appear globally settled while no remote hub committed its channel
state. A malicious peer can advertise fake capacity and help produce an
unbacked receipt.

Required fix:

- pinned hub identities and verified L1 channel ownership;
- signed canonical payment envelope;
- per-hop liquidity reservations with expiry;
- participant prepare acknowledgements;
- atomic commit/abort protocol and recovery;
- remote durable commit proof before the origin issues a receipt.

Until this exists, production routing must remain local-only.

### CRITICAL-4 — Persistence is not money-safe

Evidence:

- persistence is optional by default (`src/config.rs`);
- `src/persist.rs` writes periodic JSON snapshots;
- related state is serialized as separate in-memory views;
- there is no WAL, transaction, fsync acknowledgement or recovery invariant
  validation;
- load failure logs a warning and can continue with empty state.

Impact:

A crash can restore stale liquidity beside newer settled sessions, lose a bill
draft, or reopen spendable balance. Corrupt state can turn a production node
into a fresh empty node.

Required fix:

- SQLite in WAL/FULL-sync mode or an equivalent transactional embedded store;
- schema version and migrations;
- atomic commit before sending `settled`;
- checksums and startup invariants;
- fail closed on corruption/provider mismatch;
- encrypted, tested backups and restore drills.

### CRITICAL-5 — No payer-signed intent at admission

Evidence:

- public payment aliases can enqueue a payment with a caller-selected payer;
- verified `agent_id` is looked up but not proven per request;
- several actions trust a body-supplied `by_address`.

The bundled SDK no longer bulk-signs payer/intermediary inbox work, which blocks
the easiest automatic theft path. The protocol itself is still unsafe for
custom agents or future clients that follow inbox instructions blindly.

Required fix:

- payer-signed intent over method, path, canonical body hash, payee, exact
  amount, fee ceiling, expiry, nonce and provider/network domain;
- proof verification before payment enqueue or liquidity reservation;
- one-time nonce/replay store;
- short-lived address-bound sessions only after a signed challenge;
- action-specific signed intents for cancel, close and administrative changes.

## High-severity findings

### HIGH-1 — Invoice can be paid more than once

`Paying` invoices can create another payment and the invoice's `payment_id` is
overwritten. Use an atomic `Open -> Paying(payment_id)` compare-and-swap and a
unique invoice-to-payment constraint.

### HIGH-2 — x402 receipts are unbound and replayable

Verification checks only that a local settled receipt hash exists. It does not
bind resource, merchant, payee, minimum amount, invoice, requester, nonce or
consumption. Use a merchant-signed one-time challenge with exact terms, expiry
and a replay store.

### HIGH-3 — Mesh identity and hello authentication are incomplete

- unsigned hellos are accepted even when invalid signed hellos are rejected;
- a `timestamp_unix` of zero bypasses the freshness check;
- signatures do not cover the full endpoint, liquidity, fee and peer payload;
- provider IDs are not pinned to keys;
- peer records and known-peer URLs can be overwritten.

Require signed hellos for public nodes, sign the full canonical payload, pin
identity keys, define signed key rotation, and maintain a monotonic
sequence/replay cache.

### HIGH-4 — Channel advertisements are not L1-gated

Registration and routing do not require proof that the L1 channel exists, is
open, has the advertised parties/balances, and is controlled by the advertiser.
Cached `l1_status` is not used to exclude closed channels.

### HIGH-5 — Satoshi routing is not capacity-aware

The graph carries HAC directional liquidity but no equivalent satoshi fields.
A satoshi route can be chosen without checking satoshi liquidity and fail only
after signing.

### HIGH-6 — DNS-rebinding SSRF

`src/ssrf.rs` rejects obvious private literal IPs but does not resolve and pin
hostnames. Peer, seed or webhook hostnames can resolve/rebind to loopback,
private networks or cloud metadata.

Resolve every A/AAAA record, reject the URL if any result is non-global, connect
to a validated pinned address while preserving Host/SNI, revalidate on
reconnect, and enforce an OS/network egress policy.

### HIGH-7 — Conservation can mint from unknown/zero balances

Conservation is checked only when the old total is greater than zero and uses
saturating arithmetic. Represent unknown balances explicitly and always use
checked exact equality for known balances.

### HIGH-8 — Fullnode relay and HTTPS handling

The fullnode client strips an input scheme and rebuilds `http://` URLs. The
submit relay can use a privileged token and a caller-influenced path. Preserve
HTTPS, pin the configured origin, use one fixed allowlisted submit endpoint,
and strictly validate transaction hex and size.

### HIGH-9 — Rate limiting and state exhaustion

Without proxy mode every direct client shares the `"direct"` bucket. With proxy
mode the first forwarded address is trusted without a trusted-proxy CIDR.
Several public creation/list APIs bypass the agent policy and can consume
global state.

Use Axum connect information, trusted proxy ranges, bounded LRU buckets,
per-principal quotas, hard collection caps and TTL cleanup.

### HIGH-10 — Privacy exposure

Public list endpoints expose payments, bills, channels, identities, foreign
notifications and ledger information. Separate public discovery data from
operator and participant views; apply participant authorization and pagination.

## Dependency and quality findings

- `cargo audit` reported no known vulnerability in the resolved dependency
  graph.
- Direct dependency `libsecp256k1 0.7.2` is unmaintained
  (RUSTSEC-2025-0161): <https://rustsec.org/advisories/RUSTSEC-2025-0161>.
  Migrate only with Hacash-compatible signature vectors and explicit low-S
  behavior tests.
- `cargo clippy --all-targets --all-features -- -D warnings` currently fails on
  existing warnings/style debt.
- The repository is not consistently `rustfmt` clean.

## Verification performed

- `cargo test --all-targets`: **44 passed, 0 failed**.
- New regression coverage:
  - all intermediaries included on a four-hop route;
  - 16-byte Hacash L1 channel ID accepted and 32-byte ID rejected;
  - active bill remains exportable while a replacement draft is collecting.
- Python SDK: syntax compilation passed.
- TypeScript SDK: Node's TypeScript syntax stripping/parser check passed.
- Full TypeScript type-check/test suite was not run because project dependencies
  are not installed in the workspace.

The existing unit suite does not cover the most important distributed and
crash cases.

## Required test program before mainnet

1. Property tests for canonical HAC parsing, ordering, addition/subtraction and
   round-trip formatting.
2. Two concurrent payments competing for the same directional liquidity.
3. Failure on the last hop proving no prior hop changes.
4. Retry/interleaving tests proving exactly-once application.
5. Crash/restart at every settlement write boundary.
6. Multi-process, multi-hub prepare/commit/abort tests with dropped,
   duplicated, reordered and replayed messages.
7. L1 channel open/closed/party/balance verification fixtures.
8. Invoice CAS and x402 cross-resource replay tests.
9. Signed-request replay, clock-skew and key-rotation tests.
10. DNS rebinding, metadata IP, alternate IP notation and redirect tests.
11. Fuzzing for all public JSON endpoints and persisted-state loading.
12. SDK approval-registry tests ensuring no unapproved payment ID is signed.

## Recommended implementation order

### Gate A — Correct local money state

Canonical amount type, transactional database, reserve/commit/abort settlement,
exactly-once applied ledger, invoice CAS, durable active bills.

### Gate B — Authenticate every economic action

Signed payer intents, signed cancellations/closes, address-bound agent
sessions, x402 one-time challenges, participant-scoped reads.

### Gate C — Build the actual inter-hub protocol

Pinned hub identities, full signed hellos, L1-verified channels, remote
reservations, atomic commit/abort and recovery.

### Gate D — Harden VPS operation

DNS-safe egress, HTTPS fullnode client, least-privilege container/service,
secret files instead of environment variables, backups, monitoring, rate
limits, upgrade/rollback and incident procedures.

Only after all four gates and adversarial multi-node tests should the hub be
used with real funds.
