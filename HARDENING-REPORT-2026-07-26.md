# Hacash L2 Hub — Hardening Report (2026-07-26)


> **Current status — durable 2PC cycle:** authenticated, crash-recoverable
> cross-hub prepare/commit/abort is now implemented and fail-closed without
> persistent state and verified hub identities. This closes the protocol gap,
> but it is not production certification; broader chaos/load/fuzz coverage,
> secure key operations, and an independent audit are still required.
> The final section supersedes earlier "not yet implemented" limitations.
## Αποτέλεσμα

Ο τρέχων κύκλος διόρθωσης έκλεισε κρίσιμα σφάλματα σε ποσά HAC, settlement,
λογαριασμούς καναλιών, invoices, persistence και διαχείριση AI agents.
Η τοπική εκτέλεση πληρωμών είναι πλέον fail-closed και ατομική για όλα τα hops
που εξυπηρετεί το ίδιο hub.

Το authenticated και crash-recoverable cross-hub prepare/commit/abort έχει
πλέον υλοποιηθεί. Παραμένει fail-closed χωρίς persistent state και verified hub
identities. Απαιτούνται ακόμη multi-process chaos/load/fuzz tests, ασφαλής
λειτουργία κλειδιών και ανεξάρτητος έλεγχος πριν χαρακτηριστεί production-ready
για πραγματική αξία.

## Εφαρμοσμένες διορθώσεις

- Ακριβής αναπαράσταση HAC σε ακέραια Zhu (`1 HAC = 100,000,000 Zhu`) με
  canonical financial notation, checked arithmetic και απόρριψη sub-Zhu,
  malformed και overflowing τιμών.
- Protocol 2.0 channel advertisements με ακριβή `*_zhu` liquidity fields.
  Τα παλιά `*_mei` πεδία παραμένουν whole-HAC για wire compatibility.
- Ατομική προδέσμευση και εφαρμογή ρευστότητας σε local multi-hop routes.
  Αποτρέπονται double-spend, partial settlement και δεύτερη εφαρμογή της ίδιας
  πληρωμής.
- Conservation checks σε reconciliation bills για HAC και satoshi. Τα draft
  bills δεν αντικαθιστούν το τελευταίο ενεργό, συνυπογεγραμμένο bill.
- AI-agent idempotency ανά policy principal και υπογεγραμμένα payment intents
  που δεσμεύουν payer, payee, ποσό, fee, route, invoice, nonce, expiry και
  idempotency key.
- Replay protection για agent nonces, αυστηρή λήξη intent και υποχρεωτική
  επαλήθευση όταν ενεργοποιείται `REQUIRE_VERIFIED_AGENT`.
- Invoice takeover/race προστασία: μόνο η ίδια principal-scoped idempotent
  επανάληψη μπορεί να ξαναδιαβάσει invoice που βρίσκεται σε `Paying`.
- Micro-stream όρια και κατανάλωση σε ακριβή Zhu, ώστε ποσά μικρότερα του ενός
  HAC να μη μηδενίζονται.
- Crash-safe snapshots με temporary file, flush/sync, atomic replacement σε
  Unix και ασφαλή backup rotation/recovery σε Windows.
- Docker runtime ως μη προνομιούχος χρήστης, read-only filesystem, dropped
  capabilities, `no-new-privileges` και υποχρεωτικά production secrets/URLs.
- SDK helpers σε TypeScript και Python για δημιουργία και υπογραφή agent intents.

## Επαλήθευση

- Rust unit suite: `73 passed, 0 failed`.
- Multi-process 2PC chaos suite: `2 passed, 0 failed` (opt-in).
- TypeScript: syntax validation σε `types.ts`, `crypto.ts`, `client.ts`,
  `index.ts`.
- Python: bytecode compilation σε όλα τα package modules.
- Docker Compose: επιτυχής validation με προσωρινές test μεταβλητές.

## Υποχρεωτικά επόμενα βήματα πριν από production

1. Multi-process chaos tests σε κάθε fsync boundary, network partitions,
   χαμένα acknowledgements, restart ordering και ταυτόχρονο load.
2. Άμεσο durable event log ή transactional database. Τα crash-safe snapshots
   προστατεύουν την ακεραιότητα αρχείου, αλλά το περιοδικό snapshot μπορεί να
   χάσει τα τελευταία events μετά από απότομη διακοπή.
3. mTLS ή ισοδύναμη αμοιβαία ταυτοποίηση μεταξύ hubs και υπογραφή ολόκληρου του
   channel advertisement, όχι μόνο των channel IDs.
4. HSM/secret manager για operator και agent keys, rotation/revocation και
   περιορισμένα scopes ανά agent/tool.
5. Integration tests με πραγματικό Hacash fullnode, chaos/crash tests,
   concurrent load tests, fuzzing των parsers και ανεξάρτητο security audit.
6. Monitoring για reservation age, settlement failures, nonce replays,
   snapshot failures, liquidity drift και peer quarantine.

## Αρχή ασφαλούς λειτουργίας

Cross-hub routes εκτελούνται μόνο όταν όλοι οι συμμετέχοντες διαθέτουν durable
journal και verified pinned identities. Αποτυχία οποιασδήποτε προϋπόθεσης
κλείνει τη ροή χωρίς commit. Το `settled` παραμένει hub-coordinated κατάσταση,
όχι L1 finality.

## Πρόσθετο hardening — δεύτερος κύκλος

- Τα protocol 2.x signed hellos δεσμεύουν πλέον canonical SHA3-256 commitment
  ολόκληρων των channel advertisements: addresses, provider, legacy/exact
  liquidity και fee hints. Το canonical μήνυμα 1.0 παραμένει αμετάβλητο.
- Κρίσιμα επιτυχημένα API mutations δεν επιστρέφουν απάντηση πριν ολοκληρωθεί
  synchronous `write + sync + atomic replace` του snapshot. Αποτυχία durability
  επιστρέφει retryable `503` και ο client πρέπει να επαναλάβει με το ίδιο
  idempotency key.
- Η περιοδική και η request-triggered αποθήκευση χρησιμοποιούν κοινό lock, ενώ
  το snapshot εξάγεται κάτω από ένα state read-lock. Έτσι δεν συνδυάζεται
  settled payment από μία χρονική στιγμή με channel balances άλλης στιγμής.
- Το persistence format v6 περιλαμβάνει reservations, exactly-once guards,
  nonces, identities, invoices, micro-streams, escrows, rebalances, deferred
  payments και rolling agent ledger.
- Οι agent identities διαθέτουν operator-granted scopes (`pay`, `invoice`,
  `micro`, `escrow`, `read`) και άμεσο persisted revocation. Η διαχείριση
  scopes/revocation είναι fail-closed όταν δεν έχει οριστεί operator API token.
- Προστέθηκαν metrics για επιτυχημένα και αποτυχημένα durable checkpoints.
- Rust verification μετά τον κύκλο durable 2PC: `73 passed, 0 failed`.

Το νέο hash-chained transaction log καλύπτει τις cross-hub αποφάσεις και την
ανάκτησή τους. Τα synchronous snapshots εξακολουθούν να μην αντικαθιστούν ένα
γενικό WAL/transactional database για κάθε άλλο background mutation του hub.

## Current hardening — durable 2PC cycle

- Durable JSONL transaction journal v2 with fsync-before-ack, sequence numbers,
  canonical raw-value hashes, and a chained previous-record hash.
- Authenticated prepare, commit, abort, and acknowledgements using pinned hub
  identities learned from verified signed hellos.
- Every participant verifies exact local route coverage and the complete
  ordered Hacash user signature set before commit.
- Irreversible commit decisions and strictly validated state transitions.
- Persistent abort acknowledgements; failed commit and abort delivery is retried.
- Exactly-once local balance application across crash and replay.
- Cross-hub payment/idempotency recovery even when the general snapshot missed
  the latest coordinator session or retry mapping.
- Content-bound `Idempotency-Key` handling for wallet and low-level clients;
  agent pay already requires an idempotency key.
- Persistence format v6 stores verified peer identity pins.
- Operator transaction view plus prepared, commit-pending, abort-pending, and
  committed Prometheus gauges.
- In-process two-hub HTTP integration coverage injects lost commit and abort
  acknowledgements after participant durability, then verifies retry and
  exactly-once balances on both hubs.
- Real multi-process chaos coverage launches two hub binaries behind a
  controllable TCP proxy. It verifies coordinator-first and participant-first
  restart ordering, crashes at every semantic journal boundary,
  local-apply-before-final-record windows, torn journal-tail repair, live
  network partitions, retry, and exactly-once balances across repeated restarts.
  A separate concurrent case verifies two same-key creates plus independent
  commits under partition.
- A durable commit-decision payment image now supersedes a stale general
  snapshot, restoring the complete verified signature set before retry.
- Snapshot reload now restores `balance_source` and
  `last_settle_payment_id`; losing these markers previously allowed a second
  balance shift after a later restart.
- Concurrent distributed commits exposed a second balance application while
  drafting reconciliation bills. Bill generation now treats the durable
  per-transaction `applied_settlements` set as authoritative instead of relying
  on the channel's single last-payment marker.
- Crash hooks are compiled only in debug builds and require both
  `HACASH_L2_ENABLE_CHAOS=1` and an explicit crash point. Release builds contain
  no active crash path.
- Rust unit verification: `73 passed, 0 failed`.
- Multi-process chaos verification: `2 passed, 0 failed`.
- Linux/Docker three-hub chaos verification passed with real container
  `SIGKILL`, full-cluster cold restarts, a disconnected commit participant,
  randomized restart ordering, same-key retries, and exact balance checks.
  Two clean runs covered 2 and 3 repeated partial-commit rounds respectively.
- The Docker test validates durable prepare recovery, commit-decision recovery,
  participant convergence, and exactly-once balance application across all
  three hubs. It deliberately remains opt-in because it builds an image and
  creates temporary containers, volumes, and a bridge network.
- A separate concurrent Docker soak passed with both 8 payments (`2 x 4`)
  and 18 payments (`3 x 6`). Each batch records commit decisions while HubC
  is partitioned, then kills the coordinator and alternating participants,
  randomizes restart order, retries every idempotency key, and performs a final
  all-hub cold restart. Balances are compared as exact integer Zhu so equivalent
  canonical Hacash unit forms cannot create false mismatches.
- Docker covers process death, container death, bridge partitions, restart
  ordering, and persistent-volume recovery. It does not emulate loss of the
  host kernel page cache or physical VPS storage power failure.
- The production Docker image now copies the compile-time `static` dashboard
  and wallet assets; the missing copy previously made the Linux image fail to build.

Run the opt-in suite with:

```powershell
cargo test --test chaos_2pc -- --ignored --nocapture
cargo test --test docker_chaos_3hub -- --ignored --nocapture
cargo test --test docker_chaos_3hub linux_three_hub_concurrent_partition_soak -- --ignored --nocapture

$env:HACASH_DOCKER_SOAK_BATCHES='3'; $env:HACASH_DOCKER_SOAK_CONCURRENCY='6'
cargo test --test docker_chaos_3hub linux_three_hub_concurrent_partition_soak -- --ignored --nocapture
```

Remaining production gates:

1. Longer repeated partitions, randomized kill schedules, and filesystem/power-loss testing on Linux VPS storage.
2. Multi-hour sustained concurrent load, property/fuzz tests, and repeated
   recovery soak tests under independent Linux/VPS storage conditions.
3. HSM/secret-manager operations and an explicit peer identity rotation flow.
4. Independent protocol and implementation security audit.

The transaction journal now protects distributed decisions. It does not replace
a general WAL or transactional database for unrelated background mutations, and
