//! Phase B: canonical payment message + Hacash L1-compatible secp256k1 verify.
//!
//! Uses standalone `hacash_keys` (same algorithms as fullnode wallets):
//! - message digest: **SHA3-256** (32 bytes)
//! - signature: **secp256k1** ECDSA, 64-byte standard encoding
//! - public key: 33-byte compressed
//! - address: versioned base58check of RIPEMD160(SHA2(pubkey)) via `Account`
//!
//! Wire format for `signature_hex` (preferred): **97-byte Sign** hex
//! (`publickey[33] || signature[64]`) matching Hacash `Sign`.
//! Alternatively: 64-byte `signature_hex` + separate `public_key_hex` (33 bytes).

use crate::hacash_keys::{self, Account};

/// Domain tag — changing this invalidates all prior signatures.
use crate::types::AdvertisedChannel;
pub const PAYMENT_MSG_DOMAIN: &str = "HACASH_L2_PAYMENT_V1";

/// Domain for signed peer hello (global mesh identity).
pub const HELLO_MSG_DOMAIN: &str = "HACASH_L2_HELLO_V1";

/// Fields that form the signed commitment (all signers sign the same hash).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PaymentCommit {
    pub session_id: String,
    pub provider_id: String,
    pub payer: String,
    pub payee: String,
    pub amount_hac: String,
    pub amount_satoshi: u64,
    pub fee_hac: String,
    pub route: Vec<String>,
    pub required_signers: Vec<String>,
    pub created_unix: u64,
}

/// Build the exact UTF-8 string that is hashed. Stable line format (LF only).
pub fn canonical_message(c: &PaymentCommit) -> String {
    // Order is fixed forever for V1. Do not reorder fields.
    format!(
        "\
{domain}\n\
session_id={session_id}\n\
provider_id={provider_id}\n\
payer={payer}\n\
payee={payee}\n\
amount_hac={amount_hac}\n\
amount_satoshi={amount_satoshi}\n\
fee_hac={fee_hac}\n\
route={route}\n\
required_signers={signers}\n\
created_unix={created_unix}\n",
        domain = PAYMENT_MSG_DOMAIN,
        session_id = c.session_id,
        provider_id = c.provider_id,
        payer = c.payer,
        payee = c.payee,
        amount_hac = c.amount_hac,
        amount_satoshi = c.amount_satoshi,
        fee_hac = c.fee_hac,
        route = c.route.join(","),
        signers = c.required_signers.join(","),
        created_unix = c.created_unix,
    )
}

/// SHA3-256 of the canonical message (32 bytes).
pub fn message_hash(c: &PaymentCommit) -> [u8; 32] {
    let msg = canonical_message(c);
    hacash_keys::sha3(msg.as_bytes())
}

pub fn message_hash_hex(c: &PaymentCommit) -> String {
    hex::encode(message_hash(c))
}

/// Parsed signature material.
#[derive(Debug, Clone)]
pub struct ParsedSign {
    pub public_key: [u8; 33],
    pub signature: [u8; 64],
    /// Readable Hacash address derived from the public key.
    pub address_from_key: String,
}

/// Parse wire signature.
///
/// Accepts:
/// 1. `signature_hex` = 97 bytes (33 pubkey + 64 sig) — preferred Hacash `Sign` layout
/// 2. `signature_hex` = 64 bytes + `public_key_hex` = 33 bytes
pub fn parse_sign_payload(
    signature_hex: &str,
    public_key_hex: Option<&str>,
) -> Result<ParsedSign, String> {
    let sig_raw = decode_hex_strict(signature_hex, "signature_hex")?;
    let (pk, sig) = if sig_raw.len() == 97 {
        let mut public_key = [0u8; 33];
        let mut signature = [0u8; 64];
        public_key.copy_from_slice(&sig_raw[..33]);
        signature.copy_from_slice(&sig_raw[33..]);
        (public_key, signature)
    } else if sig_raw.len() == 64 {
        let pk_hex = public_key_hex
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "public_key_hex required when signature_hex is 64 bytes (or pack 97-byte Sign)"
                    .to_string()
            })?;
        let pk_raw = decode_hex_strict(pk_hex, "public_key_hex")?;
        if pk_raw.len() != 33 {
            return Err(format!(
                "public_key_hex must be 33 compressed bytes, got {}",
                pk_raw.len()
            ));
        }
        let mut public_key = [0u8; 33];
        public_key.copy_from_slice(&pk_raw);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig_raw);
        (public_key, signature)
    } else {
        return Err(format!(
            "signature_hex must be 64 bytes (with public_key_hex) or 97-byte Sign, got {} bytes",
            sig_raw.len()
        ));
    };

    if pk[0] != 0x02 && pk[0] != 0x03 {
        return Err("public key must be compressed (0x02 or 0x03 prefix)".into());
    }

    let addr_bytes = Account::get_address_by_public_key(pk);
    let address_from_key = Account::to_readable(&addr_bytes);
    Ok(ParsedSign {
        public_key: pk,
        signature: sig,
        address_from_key,
    })
}

/// Verify that `claimed_address` owns a valid secp256k1 signature over `hash`.
pub fn verify_payment_signature(
    hash: &[u8; 32],
    claimed_address: &str,
    signature_hex: &str,
    public_key_hex: Option<&str>,
) -> Result<ParsedSign, String> {
    let parsed = parse_sign_payload(signature_hex, public_key_hex)?;
    let claimed = claimed_address.trim();
    if claimed != parsed.address_from_key {
        return Err(format!(
            "address mismatch: claimed {claimed} but public key derives {}",
            parsed.address_from_key
        ));
    }
    if !Account::verify_signature(hash, &parsed.public_key, &parsed.signature) {
        return Err("invalid secp256k1 signature for payment message hash".into());
    }
    Ok(parsed)
}

/// Sign a payment/bill hash with a local account (wallets / tests / agents).
/// Returns 97-byte Sign hex (pubkey || sig).
#[allow(dead_code)] // public helper for wallets/agents; used by unit tests
pub fn sign_payment_hash(account: &Account, hash: &[u8; 32]) -> String {
    let mut out = [0u8; 97];
    out[..33].copy_from_slice(&account.public_key().serialize_compressed());
    out[33..].copy_from_slice(&account.do_sign(hash));
    hex::encode(out)
}

// ---------------------------------------------------------------------------
// Global mesh — signed peer hello
// ---------------------------------------------------------------------------

/// Fields that form the signed hello commitment (stable order).
#[derive(Debug, Clone)]
pub struct HelloCommit {
    pub provider_id: String,
    pub public_url: String,
    pub name: String,
    pub timestamp_unix: u64,
    pub protocol_version: String,
    pub identity_address: String,
    /// Channel ids joined by comma (sorted for stability is caller's job).
    pub channel_ids: String,
    pub fee_base_mei: u64,
    pub fee_ppm: u64,
    pub total_capacity_mei: u64,
    /// SHA3-256 of every advertised channel field (required by protocol 2.x).
    pub channel_ads_hash_hex: String,
}

pub fn hello_canonical_message(c: &HelloCommit) -> String {
    let mut message = format!(
        "\
{domain}\n\
provider_id={provider_id}\n\
public_url={public_url}\n\
name={name}\n\
timestamp_unix={timestamp_unix}\n\
protocol_version={protocol_version}\n\
identity_address={identity_address}\n\
channel_ids={channel_ids}\n\
fee_base_mei={fee_base_mei}\n\
fee_ppm={fee_ppm}\n\
total_capacity_mei={total_capacity_mei}\n",
        domain = HELLO_MSG_DOMAIN,
        provider_id = c.provider_id,
        public_url = c.public_url,
        name = c.name,
        timestamp_unix = c.timestamp_unix,
        protocol_version = c.protocol_version,
        identity_address = c.identity_address,
        channel_ids = c.channel_ids,
        fee_base_mei = c.fee_base_mei,
        fee_ppm = c.fee_ppm,
        total_capacity_mei = c.total_capacity_mei,
    );
    if c.protocol_version.starts_with("2.") {
        message.push_str(&format!(
            "channel_ads_hash_hex={}\n",
            c.channel_ads_hash_hex
        ));
    }
    message
}

/// Canonical commitment to complete channel advertisements. This protects
/// liquidity, endpoint addresses, provider attribution and fee hints from
/// modification in transit. Sorting makes the hash independent of JSON order.
pub fn channel_ads_hash_hex(channels: &[AdvertisedChannel]) -> String {
    let mut ordered: Vec<&AdvertisedChannel> = channels.iter().collect();
    ordered.sort_by(|a, b| {
        (
            &a.channel_id,
            &a.left_address,
            &a.right_address,
            &a.via_provider,
            a.capacity_mei,
            a.left_available_mei,
            a.right_available_mei,
            a.capacity_zhu,
            a.left_available_zhu,
            a.right_available_zhu,
            a.fee_ppm,
        )
            .cmp(&(
                &b.channel_id,
                &b.left_address,
                &b.right_address,
                &b.via_provider,
                b.capacity_mei,
                b.left_available_mei,
                b.right_available_mei,
                b.capacity_zhu,
                b.left_available_zhu,
                b.right_available_zhu,
                b.fee_ppm,
            ))
    });
    let mut bytes = Vec::with_capacity(32 + ordered.len() * 160);
    bytes.extend_from_slice(b"HACASH_L2_CHANNEL_ADS_V2\0");
    bytes.extend_from_slice(&(ordered.len() as u64).to_be_bytes());
    for channel in ordered {
        append_len_prefixed(&mut bytes, &channel.channel_id);
        append_len_prefixed(&mut bytes, &channel.left_address);
        append_len_prefixed(&mut bytes, &channel.right_address);
        append_len_prefixed(&mut bytes, &channel.via_provider);
        for value in [
            channel.capacity_mei,
            channel.left_available_mei,
            channel.right_available_mei,
            channel.capacity_zhu,
            channel.left_available_zhu,
            channel.right_available_zhu,
            channel.fee_ppm,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
    hex::encode(hacash_keys::sha3(&bytes))
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

pub fn hello_message_hash(c: &HelloCommit) -> [u8; 32] {
    hacash_keys::sha3(hello_canonical_message(c).as_bytes())
}

#[allow(dead_code)]
pub fn hello_message_hash_hex(c: &HelloCommit) -> String {
    hex::encode(hello_message_hash(c))
}

/// Verify optional hello signature. Empty signature_hex = unsigned (lab OK).
pub fn verify_hello_signature(
    commit: &HelloCommit,
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<(), String> {
    let sig = signature_hex.trim();
    let pk = public_key_hex.trim();
    if sig.is_empty() {
        return Ok(()); // unsigned allowed
    }
    if pk.is_empty() {
        return Err("identity_pubkey_hex required when hello is signed".into());
    }
    let hash = hello_message_hash(commit);
    let pk_opt = if sig.len() >= 190 {
        // 97-byte Sign hex embeds pubkey
        None
    } else {
        Some(pk)
    };
    verify_payment_signature(&hash, &commit.identity_address, sig, pk_opt)?;
    Ok(())
}

/// Build + sign hello fields; returns (timestamp, pubkey_hex, address, signature_hex).
pub fn sign_hello(
    account: &Account,
    provider_id: &str,
    public_url: &str,
    name: &str,
    timestamp_unix: u64,
    protocol_version: &str,
    channel_ids: &str,
    fee_base_mei: u64,
    fee_ppm: u64,
    total_capacity_mei: u64,
    channel_ads_hash_hex: &str,
) -> (String, String, String) {
    let identity_address = account.readable().to_string();
    let commit = HelloCommit {
        provider_id: provider_id.to_string(),
        public_url: public_url.to_string(),
        name: name.to_string(),
        timestamp_unix,
        protocol_version: protocol_version.to_string(),
        identity_address: identity_address.clone(),
        channel_ids: channel_ids.to_string(),
        fee_base_mei,
        fee_ppm,
        total_capacity_mei,
        channel_ads_hash_hex: channel_ads_hash_hex.to_string(),
    };
    let hash = hello_message_hash(&commit);
    let signature_hex = sign_payment_hash(account, &hash);
    let pubkey_hex = hex::encode(account.public_key().serialize_compressed());
    (pubkey_hex, identity_address, signature_hex)
}

// ---------------------------------------------------------------------------
// Phase C — reconciliation bill (last bill only)
// ---------------------------------------------------------------------------

pub const BILL_MSG_DOMAIN: &str = "HACASH_L2_BILL_V1";

/// Signed channel reconciliation commitment (both parties sign the same hash).
#[derive(Debug, Clone)]
pub struct BillCommit {
    pub channel_id: String,
    pub sequence: u64,
    pub provider_id: String,
    pub left_address: String,
    pub right_address: String,
    pub left_hac: String,
    pub right_hac: String,
    pub left_satoshi: u64,
    pub right_satoshi: u64,
    /// SHA3-256 hex of previous active bill (empty if first).
    pub prev_bill_hash: String,
    pub created_unix: u64,
    /// Optional linked payment session id (empty if none).
    pub payment_id: String,
}

pub fn bill_canonical_message(c: &BillCommit) -> String {
    format!(
        "\
{domain}\n\
channel_id={channel_id}\n\
sequence={sequence}\n\
provider_id={provider_id}\n\
left_address={left_address}\n\
right_address={right_address}\n\
left_hac={left_hac}\n\
right_hac={right_hac}\n\
left_satoshi={left_satoshi}\n\
right_satoshi={right_satoshi}\n\
prev_bill_hash={prev_bill_hash}\n\
payment_id={payment_id}\n\
created_unix={created_unix}\n",
        domain = BILL_MSG_DOMAIN,
        channel_id = c.channel_id,
        sequence = c.sequence,
        provider_id = c.provider_id,
        left_address = c.left_address,
        right_address = c.right_address,
        left_hac = c.left_hac,
        right_hac = c.right_hac,
        left_satoshi = c.left_satoshi,
        right_satoshi = c.right_satoshi,
        prev_bill_hash = c.prev_bill_hash,
        payment_id = c.payment_id,
        created_unix = c.created_unix,
    )
}

pub fn bill_message_hash(c: &BillCommit) -> [u8; 32] {
    hacash_keys::sha3(bill_canonical_message(c).as_bytes())
}

pub fn bill_message_hash_hex(c: &BillCommit) -> String {
    hex::encode(bill_message_hash(c))
}

/// Verify signature over a bill hash (same wire as payments).
pub fn verify_bill_signature(
    hash: &[u8; 32],
    claimed_address: &str,
    signature_hex: &str,
    public_key_hex: Option<&str>,
) -> Result<ParsedSign, String> {
    verify_payment_signature(hash, claimed_address, signature_hex, public_key_hex)
        .map_err(|e| e.replace("payment message hash", "bill message hash"))
}

fn decode_hex_strict(s: &str, label: &str) -> Result<Vec<u8>, String> {
    let s = s.trim().trim_start_matches("0x");
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{label} must be hex"));
    }
    if s.len() % 2 != 0 {
        return Err(format!("{label} hex length must be even"));
    }
    hex::decode(s).map_err(|e| format!("{label}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sign_verify() {
        let acc = Account::create_by_password("phase-b-test-key").unwrap();
        let commit = PaymentCommit {
            session_id: "00000000-0000-0000-0000-000000000001".into(),
            provider_id: "HubA".into(),
            payer: acc.readable().to_string(),
            payee: "1Other".into(),
            amount_hac: "1:247".into(),
            amount_satoshi: 0,
            fee_hac: "0".into(),
            route: vec!["aa".repeat(16)],
            required_signers: vec![acc.readable().to_string()],
            created_unix: 1_700_000_000,
        };
        let hash = message_hash(&commit);
        let sig_hex = sign_payment_hash(&acc, &hash);
        assert_eq!(sig_hex.len(), 194);
        let ok = verify_payment_signature(&hash, acc.readable(), &sig_hex, None).unwrap();
        assert_eq!(ok.address_from_key, acc.readable());
    }

    #[test]
    fn rejects_wrong_address() {
        let acc = Account::create_by_password("phase-b-test-key-2").unwrap();
        let other = Account::create_by_password("phase-b-other").unwrap();
        let hash = [9u8; 32];
        let sig_hex = sign_payment_hash(&acc, &hash);
        let err = verify_payment_signature(&hash, other.readable(), &sig_hex, None).unwrap_err();
        assert!(err.contains("address mismatch"), "{err}");
    }

    #[test]
    fn rejects_tampered_message() {
        let acc = Account::create_by_password("phase-b-test-key-3").unwrap();
        let mut commit = PaymentCommit {
            session_id: "s1".into(),
            provider_id: "H".into(),
            payer: acc.readable().to_string(),
            payee: "P".into(),
            amount_hac: "1:247".into(),
            amount_satoshi: 0,
            fee_hac: "0".into(),
            route: vec![],
            required_signers: vec![acc.readable().to_string()],
            created_unix: 1,
        };
        let hash = message_hash(&commit);
        let sig = sign_payment_hash(&acc, &hash);
        commit.amount_hac = "999:247".into();
        let bad = message_hash(&commit);
        let err = verify_payment_signature(&bad, acc.readable(), &sig, None).unwrap_err();
        assert!(err.contains("invalid"), "{err}");
    }

    #[test]
    fn separate_pubkey_and_sig_works() {
        let acc = Account::create_by_password("phase-b-split").unwrap();
        let hash = [3u8; 32];
        let full = sign_payment_hash(&acc, &hash);
        let pk = &full[..66];
        let sig = &full[66..];
        verify_payment_signature(&hash, acc.readable(), sig, Some(pk)).unwrap();
    }

    fn advertised_channel() -> AdvertisedChannel {
        AdvertisedChannel {
            channel_id: "ab".repeat(16),
            left_address: "left".into(),
            right_address: "right".into(),
            via_provider: "HubA".into(),
            capacity_mei: 1,
            left_available_mei: 0,
            right_available_mei: 1,
            capacity_zhu: 100_000_000,
            left_available_zhu: 25_000_000,
            right_available_zhu: 75_000_000,
            fee_ppm: 100,
        }
    }

    #[test]
    fn protocol_v2_hello_signature_binds_complete_channel_advertisement() {
        let account = Account::create_by_password("hello-ads-v2").unwrap();
        let mut channels = vec![advertised_channel()];
        let mut commit = HelloCommit {
            provider_id: "HubA".into(),
            public_url: "https://hub-a.example".into(),
            name: "hub-a".into(),
            timestamp_unix: 1_700_000_000,
            protocol_version: "2.0".into(),
            identity_address: account.readable().to_string(),
            channel_ids: channels[0].channel_id.clone(),
            fee_base_mei: 0,
            fee_ppm: 100,
            total_capacity_mei: 1,
            channel_ads_hash_hex: channel_ads_hash_hex(&channels),
        };
        let signature = sign_payment_hash(&account, &hello_message_hash(&commit));
        verify_hello_signature(
            &commit,
            &signature,
            &hex::encode(account.public_key().serialize_compressed()),
        )
        .unwrap();

        channels[0].left_available_zhu -= 1;
        commit.channel_ads_hash_hex = channel_ads_hash_hex(&channels);
        let error = verify_hello_signature(
            &commit,
            &signature,
            &hex::encode(account.public_key().serialize_compressed()),
        )
        .unwrap_err();
        assert!(error.contains("invalid"), "{error}");
    }

    #[test]
    fn protocol_v1_hello_canonical_message_remains_compatible() {
        let mut commit = HelloCommit {
            provider_id: "legacy".into(),
            public_url: "https://legacy.example".into(),
            name: "legacy".into(),
            timestamp_unix: 1,
            protocol_version: "1.0".into(),
            identity_address: "address".into(),
            channel_ids: String::new(),
            fee_base_mei: 0,
            fee_ppm: 0,
            total_capacity_mei: 0,
            channel_ads_hash_hex: "first".into(),
        };
        let before = hello_canonical_message(&commit);
        commit.channel_ads_hash_hex = "second".into();
        assert_eq!(before, hello_canonical_message(&commit));
        assert!(!before.contains("channel_ads_hash_hex"));
    }
}
