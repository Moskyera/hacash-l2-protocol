HPAY Fast Pay Hub
=================

This is the standalone Hacash L2 Channel Service Provider hub for HPAY.
It is not a wallet, miner or full node and it never needs user private keys.

What you need
-------------
1. A trusted Hacash full node.
2. A separate hub identity and API token.
3. Persistent storage for hub-state.json and its transaction journal.
4. HTTPS when the hub is reachable from the Internet.

If HPAY Miner Full runs on the same computer, use this full-node endpoint:

  127.0.0.1:8080

Keep the full-node API on localhost. Do not expose port 8080 publicly.
Only the HTTPS reverse proxy for the hub should be public.

Linux VPS one-click
-------------------
The Linux archive includes ONE-CLICK-VPS.sh. It installs the Hub, HTTPS and,
if you choose it, the pinned HPAY-compatible full node. Mining stays disabled.

Before starting:

1. Create a DNS record such as hub.example.com pointing to your VPS.
2. Open public ports 80 and 443 in the VPS provider firewall.
3. Extract the Linux Hub archive and run:

     sudo bash ./ONE-CLICK-VPS.sh

The installer asks only for the domain, a short Hub name, and whether it should
install the full node too. Choose Yes on a new VPS. Choose No only when an
HPAY-compatible full node is already running locally on 127.0.0.1:8080.

After installation, check everything with:

     sudo hpay-status

The full-node API on port 8080 and Hub backend on port 9090 stay private. Only
the HTTPS address is public. A new full node must synchronize before Fast Pay
is used. Re-running the installer preserves the existing Hub identity secrets.

Advanced/manual installation remains available through INSTALL-VPS.sh.

Windows local/private hub
-------------------------
Set strong, unique environment values before starting:

  HACASH_L2_API_TOKEN
  HACASH_L2_IDENTITY_PASSWORD
  HACASH_L2_PROVIDER_ID
  HACASH_L2_FULLNODE=127.0.0.1:8080
  HACASH_L2_STATE_PATH=./data/hub-state.json

Then run hacash-l2-hub.exe. Public Windows hosting also requires HTTPS,
firewall rules and protected persistent backups.

Security status
---------------
A hub response marked "settled" is coordinated L2 state, not automatic L1
finality. Current HPAY mainnet Fast Pay fails closed unless every production
readiness capability is reported. Do not present this release as trustless or
suitable for large mainnet balances until the documented L1 dispute and
rollback-anchor gates are complete.

Verify the download
-------------------
Use GitHub build provenance:

  gh attestation verify <archive> --repo Moskyera/hacash-l2-protocol

The .sha256 file detects corruption but is not a signature.

Documentation
-------------
README.md
SECURITY.md
NETWORK-GLOBAL.md
PROTOCOL-SPEC-V3.md
