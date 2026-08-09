# Πώς δουλεύει το hub network (50 άτομα σε VPS) + wallet + AI agents

## Μοντέλο

Δεν υπάρχει **ένα** κεντρικό hub. Υπάρχουν **πολλά** ανεξάρτητα hubs (Channel Service Providers). Κάθε operator τρέχει το δικό του `hacash-l2-hub` σε VPS.

```
        [Wallet / AI Agent]
                 |
         "Find hubs" / recommend
                 |
        ┌────────┴────────┐
        ▼                 ▼
   Hub #1 (VPS)      Hub #2 (VPS)  ...  Hub #50 (VPS)
   AliceHub          BobHub              ZaraHub
        \               |                  /
         \____ gossip / bootstrap ________/
                      |
                 L1 fullnode(s)
              ChannelOpen / Close
```

## 50 άτομα, ο καθένας με VPS hub

| Βήμα | Τι γίνεται |
|------|------------|
| 1 | Ο καθένας: `hacash-l2-hub --bind 0.0.0.0:9090 --public-url http://IP:9090 --provider-id UniqueName` |
| 2 | Bootstrap σε **1–2 seed hubs** (κοινότητα / φίλοι): `--bootstrap http://seed1:9090,http://seed2:9090` |
| 3 | Gossip (`--gossip-secs 30`) ανταλλάσσει peers + advertised channels |
| 4 | Μετά από λίγα λεπτά, το δίκτυο **γνωρίζει** πολλούς hubs χωρίς κεντρικό master |

**Δεν** συνδέονται και οι 50 μεταξύ τους full mesh από την αρχή.
**Gossip**: A ξέρει B, B ξέρει C → σταδιακά μαθαίνονται.

## Wallet: κουμπί «έρευνα διαθέσιμα hubs»

Το wallet **δεν** χρειάζεται hardcoded λίστα 50 URLs.

1. Ξέρει **1 seed** (ή λίγα) — π.χ. community default, ή QR, ή last-used.
2. Καλεί:
   ```http
   GET http://SEED_HUB/v1/discover
   ```
3. Παίρνει **scored directory** (reachable, freshness, channels, public/wallet flags).
4. Επιλέγει `recommended` ή αφήνει τον χρήστη να διαλέξει.
5. Συνδέεται στο `public_url` **εκείνου** του hub για L2 fast pay.

Άρα: **ένα entry point → λίστα όλων των γνωστών public hubs**.

## AI agent: σε ποιο hub συνδέεται;

| Στρατηγική | Πώς |
|------------|-----|
| **Auto (προτεινόμενο)** | `GET /v1/agent/connect` στο seed → `attach_to` = best scored hub |
| **Pin** | Agent config: `L2_HUB_URL=http://my-vps:9090` (σταθερό) |
| **Re-select** | Περιοδικά ξανα-κάνει recommend αν το hub πέσει |
| **Multi-hub** | Route μπορεί να περνάει channels άλλων hubs (`remote_hops`)· session συντονίζεται από το entry hub |

Το agent **δεν** ανοίγει 50 connections. Ανοίγει **μία** (ή λίγες) στο entry hub. Το multi-hop path μπορεί να διασχίζει κανάλια που διαφημίζουν άλλα hubs.

## Fast pay flow (σύντομα)

1. User/agent έχει channel(s) ανοιχτά στο L1 (ή ανοίγει μέσω wallet).
2. Channel register στο hub που «κρατάει» online το channel.
3. Payment session στο entry hub (auto multi-hop route).
4. Υπογραφές με σειρά payee → … → payer.
5. `settled` off-chain· L1 μόνο για open/close/dispute.

## Τι χρειάζεται για «μεγάλο» δίκτυο

| Ανάγκη | Πρακτική |
|--------|----------|
| Bootstrap seeds | 2–5 σταθερά community VPS |
| Wallet default seed | 1 URL στο app config |
| Unique `provider_id` | AliceHub, BobHub, … |
| Public flag | `--public true` για να φαίνονται στο Find hubs |
| Fullnode | Τοπικό ή shared L1 API (channel query) |

## Σημαντικό

- **50 hubs ≠ 50 υποχρεωτικές συνδέσεις ανά user.**
- User/agent → **1 entry hub** → δίκτυο routes.
- Όποιος θέλει δικό του hub: VPS + binary + bootstrap· γίνεται peer αυτόματα.

---

## Global mesh (πλήρες)

Για **όλες** τις ιδιότητες (signed hello, capacity, fees, rebalance, deferred, close package, VPS install):

→ **[NETWORK-GLOBAL.md](./NETWORK-GLOBAL.md)**
