//! Agent identity: bind agent_id to secp256k1 public key (no custody).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::verify_payment_signature;
use crate::hacash_keys::{self, Account};

pub const AGENT_CHALLENGE_DOMAIN: &str = "HACASH_AGENT_IDENTITY_V1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_id: String,
    /// Compressed secp256k1 pubkey hex (33 bytes).
    pub public_key_hex: String,
    /// Hacash address derived from pubkey.
    pub address: String,
    pub registered_unix: u64,
    pub verified: bool,
    pub verified_unix: u64,
    /// Optional display name / skill.
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub contact: String,
    /// Operator-granted capabilities. Empty on legacy records means `pay`.
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub revoked_unix: u64,
}

impl AgentIdentity {
    pub fn allows(&self, scope: &str) -> bool {
        if !self.verified || self.revoked {
            return false;
        }
        if self.scopes.is_empty() {
            return scope == "pay";
        }
        self.scopes
            .iter()
            .any(|value| value == "*" || value == scope)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityChallenge {
    pub agent_id: String,
    pub challenge_id: Uuid,
    pub message: String,
    pub message_hash_hex: String,
    pub expires_unix: u64,
}

#[derive(Debug, Deserialize)]
pub struct RegisterIdentityRequest {
    pub agent_id: String,
    pub public_key_hex: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub contact: String,
}

#[derive(Debug, Deserialize)]
pub struct SetIdentityScopesRequest {
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyIdentityRequest {
    pub agent_id: String,
    pub challenge_id: String,
    /// 97-byte Sign hex over challenge message_hash.
    pub signature_hex: String,
    #[serde(default)]
    pub public_key_hex: String,
}

pub fn challenge_message(
    agent_id: &str,
    challenge_id: Uuid,
    provider_id: &str,
    expires: u64,
) -> String {
    format!(
        "{AGENT_CHALLENGE_DOMAIN}\nagent_id={agent_id}\nchallenge_id={challenge_id}\nprovider_id={provider_id}\nexpires_unix={expires}\n"
    )
}

pub fn challenge_hash_hex(message: &str) -> String {
    hex::encode(hacash_keys::sha3(message.as_bytes()))
}

pub fn address_from_pubkey_hex(public_key_hex: &str) -> Result<String, String> {
    let raw = hex::decode(public_key_hex.trim().trim_start_matches("0x"))
        .map_err(|e| format!("public_key_hex: {e}"))?;
    if raw.len() != 33 {
        return Err("public_key_hex must be 33 compressed bytes".into());
    }
    let mut pk = [0u8; 33];
    pk.copy_from_slice(&raw);
    if pk[0] != 0x02 && pk[0] != 0x03 {
        return Err("public key must be compressed".into());
    }
    let addr = Account::get_address_by_public_key(pk);
    Ok(Account::to_readable(&addr))
}

pub fn verify_challenge_sig(
    hash_hex: &str,
    address: &str,
    signature_hex: &str,
    public_key_hex: Option<&str>,
) -> Result<(), String> {
    let bytes = hex::decode(hash_hex).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err("challenge hash invalid".into());
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    verify_payment_signature(&hash, address, signature_hex, public_key_hex)?;
    Ok(())
}

pub fn normalize_scopes(scopes: &[String]) -> Result<Vec<String>, String> {
    const ALLOWED: &[&str] = &["pay", "invoice", "micro", "escrow", "read"];
    let mut normalized = Vec::new();
    for raw in scopes {
        let scope = raw.trim().to_ascii_lowercase();
        if scope.is_empty() {
            continue;
        }
        if scope == "*" || ALLOWED.contains(&scope.as_str()) {
            if !normalized.contains(&scope) {
                normalized.push(scope);
            }
        } else {
            return Err(format!("unsupported agent scope '{scope}'"));
        }
    }
    if normalized.is_empty() {
        normalized.push("pay".into());
    }
    normalized.sort();
    Ok(normalized)
}
