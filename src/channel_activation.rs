//! Portable, mutually signed opt-in certificate for V2 chain verification.
//!
//! Activation is intentionally limited to strict off-chain verification. It
//! does not grant settlement authority and does not claim L1 enforceability.

#![allow(dead_code)]

use crate::channel_state::ChannelStateSignature;
use crate::hacash_keys::{self, Account};

pub const CHANNEL_ACTIVATION_DOMAIN_V1: &[u8] = b"HACASH_L2_CHANNEL_ACTIVATION_V1";
pub const CHANNEL_ACTIVATION_SCHEMA_V1: u16 = 1;
pub const ACTIVATION_SCOPE_STRICT_VERIFICATION_ONLY: u8 = 1;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelActivationCommitmentV1 {
    pub schema_version: u16,
    pub activation_scope: u8,
    pub network_genesis_hash_hex: String,
    pub channel_id: String,
    pub funding_anchor_hash_hex: String,
    pub initial_state_sequence: u64,
    pub initial_state_hash_hex: String,
    pub left_address: String,
    pub right_address: String,
    /// Must remain false until a separate L1-enforceable protocol is deployed.
    pub settlement_authority: bool,
    /// Must remain false until portable L1 enforcement exists.
    pub l1_enforceable: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelActivationDraftV1 {
    pub schema: String,
    pub commitment: ChannelActivationCommitmentV1,
    pub activation_hash_hex: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedChannelActivationV1 {
    pub commitment: ChannelActivationCommitmentV1,
    pub activation_hash_hex: String,
    pub signatures: Vec<ChannelStateSignature>,
}

impl ChannelActivationCommitmentV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != CHANNEL_ACTIVATION_SCHEMA_V1 {
            return Err(format!(
                "unsupported channel activation schema {}; expected {}",
                self.schema_version, CHANNEL_ACTIVATION_SCHEMA_V1
            ));
        }
        if self.activation_scope != ACTIVATION_SCOPE_STRICT_VERIFICATION_ONLY {
            return Err("unsupported channel activation scope".into());
        }
        decode_lower_hex(
            &self.network_genesis_hash_hex,
            32,
            "network_genesis_hash_hex",
        )?;
        decode_lower_hex(&self.channel_id, 16, "channel_id")?;
        decode_lower_hex(&self.funding_anchor_hash_hex, 32, "funding_anchor_hash_hex")?;
        if self.initial_state_sequence == 0 {
            return Err("activation initial_state_sequence must be greater than zero".into());
        }
        decode_lower_hex(&self.initial_state_hash_hex, 32, "initial_state_hash_hex")?;
        validate_address(&self.left_address, "left_address")?;
        validate_address(&self.right_address, "right_address")?;
        if self.left_address == self.right_address {
            return Err("activation channel parties must be distinct".into());
        }
        if self.settlement_authority {
            return Err("V1 activation must not grant settlement authority".into());
        }
        if self.l1_enforceable {
            return Err("V1 activation must not claim L1 enforceability".into());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut output = Vec::with_capacity(256);
        append_bytes(&mut output, CHANNEL_ACTIVATION_DOMAIN_V1);
        output.extend_from_slice(&self.schema_version.to_be_bytes());
        output.push(self.activation_scope);
        append_hex(&mut output, &self.network_genesis_hash_hex, 32)?;
        append_hex(&mut output, &self.channel_id, 16)?;
        append_hex(&mut output, &self.funding_anchor_hash_hex, 32)?;
        output.extend_from_slice(&self.initial_state_sequence.to_be_bytes());
        append_hex(&mut output, &self.initial_state_hash_hex, 32)?;
        append_string(&mut output, &self.left_address)?;
        append_string(&mut output, &self.right_address)?;
        output.push(u8::from(self.settlement_authority));
        output.push(u8::from(self.l1_enforceable));
        Ok(output)
    }

    pub fn activation_hash(&self) -> Result<[u8; 32], String> {
        Ok(hacash_keys::sha3(&self.canonical_bytes()?))
    }

    pub fn activation_hash_hex(&self) -> Result<String, String> {
        Ok(hex::encode(self.activation_hash()?))
    }
}

impl SignedChannelActivationV1 {
    pub fn validate(&self) -> Result<(), String> {
        self.commitment.validate()?;
        let expected = self.commitment.activation_hash_hex()?;
        if !constant_time_eq(expected.as_bytes(), self.activation_hash_hex.as_bytes()) {
            return Err(
                "activation_hash_hex does not match canonical activation commitment".into(),
            );
        }
        if self.signatures.len() != 2 {
            return Err("channel activation requires exactly two party signatures".into());
        }
        let mut seen = std::collections::HashSet::new();
        for signature in &self.signatures {
            if !seen.insert(signature.address.as_str()) {
                return Err(format!(
                    "duplicate channel activation signature for {}",
                    signature.address
                ));
            }
            self.verify_signature(&signature.address)?;
        }
        if !seen.contains(self.commitment.left_address.as_str())
            || !seen.contains(self.commitment.right_address.as_str())
        {
            return Err("channel activation must be signed by both channel parties".into());
        }
        Ok(())
    }

    pub fn verify_signature(&self, signer_address: &str) -> Result<(), String> {
        let signer = signer_address.trim();
        if signer != self.commitment.left_address && signer != self.commitment.right_address {
            return Err("activation signer is not a channel party".into());
        }
        let signature = self
            .signatures
            .iter()
            .find(|item| item.address == signer)
            .ok_or_else(|| format!("missing activation signature from {signer}"))?;
        let hash = self.commitment.activation_hash()?;
        let public_key = if signature.public_key_hex.trim().is_empty() {
            None
        } else {
            Some(signature.public_key_hex.as_str())
        };
        crate::crypto::verify_payment_signature(
            &hash,
            signer,
            &signature.signature_hex,
            public_key,
        )
        .map_err(|error| error.replace("payment message hash", "activation commitment hash"))?;
        Ok(())
    }
}

pub fn sign_channel_activation(
    account: &Account,
    commitment: ChannelActivationCommitmentV1,
) -> Result<ChannelStateSignature, String> {
    commitment.validate()?;
    let address = account.readable().to_string();
    if address != commitment.left_address && address != commitment.right_address {
        return Err("signing account is not an activation channel party".into());
    }
    let hash = commitment.activation_hash()?;
    Ok(ChannelStateSignature {
        address,
        signature_hex: crate::crypto::sign_payment_hash(account, &hash),
        public_key_hex: String::new(),
    })
}

fn validate_address(address: &str, field: &str) -> Result<(), String> {
    if address.is_empty() || address.len() > 128 || address.trim() != address {
        return Err(format!("{field} must be a trimmed 1..128 byte string"));
    }
    Ok(())
}

fn decode_lower_hex(value: &str, bytes: usize, field: &str) -> Result<Vec<u8>, String> {
    if value.len() != bytes * 2
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(format!(
            "{field} must be exactly {bytes} bytes of lowercase hex"
        ));
    }
    hex::decode(value).map_err(|error| format!("invalid {field}: {error}"))
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn append_hex(output: &mut Vec<u8>, value: &str, bytes: usize) -> Result<(), String> {
    append_bytes(
        output,
        &decode_lower_hex(value, bytes, "canonical hex field")?,
    );
    Ok(())
}

fn append_string(output: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let length = u32::try_from(value.len()).map_err(|_| "canonical activation string too long")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(password: &str) -> Account {
        Account::create_by_password(password).unwrap()
    }

    fn commitment(left: &Account, right: &Account) -> ChannelActivationCommitmentV1 {
        ChannelActivationCommitmentV1 {
            schema_version: CHANNEL_ACTIVATION_SCHEMA_V1,
            activation_scope: ACTIVATION_SCOPE_STRICT_VERIFICATION_ONLY,
            network_genesis_hash_hex: "11".repeat(32),
            channel_id: "22".repeat(16),
            funding_anchor_hash_hex: "33".repeat(32),
            initial_state_sequence: 7,
            initial_state_hash_hex: "44".repeat(32),
            left_address: left.readable().to_string(),
            right_address: right.readable().to_string(),
            settlement_authority: false,
            l1_enforceable: false,
        }
    }

    #[test]
    fn requires_both_parties_and_binds_safety_scope() {
        let left = account("activation-left");
        let right = account("activation-right");
        let commitment = commitment(&left, &right);
        let activation_hash_hex = commitment.activation_hash_hex().unwrap();
        let mut certificate = SignedChannelActivationV1 {
            commitment: commitment.clone(),
            activation_hash_hex,
            signatures: vec![sign_channel_activation(&left, commitment.clone()).unwrap()],
        };
        assert!(certificate.validate().is_err());
        certificate
            .signatures
            .push(sign_channel_activation(&right, commitment).unwrap());
        certificate.validate().unwrap();

        let mut unsafe_commitment = certificate.commitment.clone();
        unsafe_commitment.settlement_authority = true;
        assert!(unsafe_commitment.validate().is_err());
        unsafe_commitment.settlement_authority = false;
        unsafe_commitment.l1_enforceable = true;
        assert!(unsafe_commitment.validate().is_err());
    }

    #[test]
    fn activation_hash_is_deterministic_and_rejects_tampering() {
        let left = account("activation-hash-left");
        let right = account("activation-hash-right");
        let commitment = commitment(&left, &right);
        assert_eq!(
            commitment.activation_hash_hex().unwrap(),
            commitment.activation_hash_hex().unwrap()
        );
        let mut changed = commitment.clone();
        changed.initial_state_sequence += 1;
        assert_ne!(
            commitment.activation_hash_hex().unwrap(),
            changed.activation_hash_hex().unwrap()
        );
    }
}
