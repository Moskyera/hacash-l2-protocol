//! Portable channel-state commitments and equivocation evidence.
//!
//! This V3 primitive is deliberately independent from routing and settlement.
//! It is not advertised or activated on the wire yet.

#![allow(dead_code)]

use crate::hacash_keys::{self, Account};

pub const CHANNEL_STATE_DOMAIN_V2: &[u8] = b"HACASH_L2_CHANNEL_STATE_V2";
pub const CHANNEL_STATE_SCHEMA_V2: u16 = 2;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelStateCommitmentV2 {
    pub schema_version: u16,
    pub network_genesis_hash_hex: String,
    pub channel_id: String,
    pub funding_anchor_hash_hex: String,
    pub sequence: u64,
    pub previous_state_hash_hex: String,
    pub left_address: String,
    pub right_address: String,
    pub left_hac_zhu: u64,
    pub right_hac_zhu: u64,
    pub left_satoshi: u64,
    pub right_satoshi: u64,
    pub funded_hac_zhu: u64,
    pub funded_satoshi: u64,
    #[serde(default)]
    pub conditional_state_root_hex: String,
    #[serde(default)]
    pub expiry_unix: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelStateSignature {
    pub address: String,
    /// Preferred Hacash encoding: compressed pubkey[33] || signature[64].
    pub signature_hex: String,
    #[serde(default)]
    pub public_key_hex: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedChannelStateV2 {
    pub commitment: ChannelStateCommitmentV2,
    pub state_hash_hex: String,
    pub signatures: Vec<ChannelStateSignature>,
}

/// Read-only migration candidate derived from the latest active V1 bill.
/// Parties must independently sign this V2 commitment; V1 signatures are
/// deliberately never copied or treated as valid for the V2 domain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelStateDraftV2 {
    pub schema: String,
    pub commitment: ChannelStateCommitmentV2,
    pub state_hash_hex: String,
    pub source_v1_bill_sequence: u64,
    pub source_v1_bill_message_hash_hex: String,
    pub source_v1_signatures_reused: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelEquivocationProofV2 {
    pub schema: String,
    pub channel_id: String,
    pub sequence: u64,
    pub signer_address: String,
    pub first: SignedChannelStateV2,
    pub second: SignedChannelStateV2,
}

impl ChannelStateCommitmentV2 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != CHANNEL_STATE_SCHEMA_V2 {
            return Err(format!(
                "unsupported channel-state schema {}; expected {}",
                self.schema_version, CHANNEL_STATE_SCHEMA_V2
            ));
        }
        decode_fixed_hex(
            &self.network_genesis_hash_hex,
            32,
            "network_genesis_hash_hex",
        )?;
        decode_fixed_hex(&self.channel_id, 16, "channel_id")?;
        decode_fixed_hex(&self.funding_anchor_hash_hex, 32, "funding_anchor_hash_hex")?;
        if self.sequence == 0 {
            return Err("channel-state sequence must be greater than zero".into());
        }
        if self.sequence == 1 {
            if !self.previous_state_hash_hex.is_empty() {
                return Err("sequence 1 must have an empty previous_state_hash_hex".into());
            }
        } else {
            decode_fixed_hex(&self.previous_state_hash_hex, 32, "previous_state_hash_hex")?;
        }
        validate_address(&self.left_address, "left_address")?;
        validate_address(&self.right_address, "right_address")?;
        if self.left_address == self.right_address {
            return Err("channel parties must be distinct".into());
        }
        let hac_total = self
            .left_hac_zhu
            .checked_add(self.right_hac_zhu)
            .ok_or("HAC balance total overflow")?;
        if hac_total != self.funded_hac_zhu {
            return Err(format!(
                "HAC conservation failed: balances total {hac_total}, funded {}",
                self.funded_hac_zhu
            ));
        }
        let satoshi_total = self
            .left_satoshi
            .checked_add(self.right_satoshi)
            .ok_or("satoshi balance total overflow")?;
        if satoshi_total != self.funded_satoshi {
            return Err(format!(
                "satoshi conservation failed: balances total {satoshi_total}, funded {}",
                self.funded_satoshi
            ));
        }
        if !self.conditional_state_root_hex.is_empty() {
            decode_fixed_hex(
                &self.conditional_state_root_hex,
                32,
                "conditional_state_root_hex",
            )?;
        }
        Ok(())
    }

    /// Canonical byte encoding: fixed field order and length-delimited bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut out = Vec::with_capacity(320);
        append_bytes(&mut out, CHANNEL_STATE_DOMAIN_V2);
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        append_hex(&mut out, &self.network_genesis_hash_hex)?;
        append_hex(&mut out, &self.channel_id)?;
        append_hex(&mut out, &self.funding_anchor_hash_hex)?;
        out.extend_from_slice(&self.sequence.to_be_bytes());
        append_hex(&mut out, &self.previous_state_hash_hex)?;
        append_string(&mut out, &self.left_address)?;
        append_string(&mut out, &self.right_address)?;
        for value in [
            self.left_hac_zhu,
            self.right_hac_zhu,
            self.left_satoshi,
            self.right_satoshi,
            self.funded_hac_zhu,
            self.funded_satoshi,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        append_hex(&mut out, &self.conditional_state_root_hex)?;
        out.extend_from_slice(&self.expiry_unix.to_be_bytes());
        Ok(out)
    }

    pub fn state_hash(&self) -> Result<[u8; 32], String> {
        Ok(hacash_keys::sha3(&self.canonical_bytes()?))
    }

    pub fn state_hash_hex(&self) -> Result<String, String> {
        Ok(hex::encode(self.state_hash()?))
    }
}

impl SignedChannelStateV2 {
    pub fn validate(&self) -> Result<(), String> {
        if self.signatures.is_empty() || self.signatures.len() > 2 {
            return Err("signed channel state must contain one or two party signatures".into());
        }
        let expected_hash = self.commitment.state_hash_hex()?;
        if !constant_time_eq(expected_hash.as_bytes(), self.state_hash_hex.as_bytes()) {
            return Err("state_hash_hex does not match the canonical commitment".into());
        }
        let mut seen = std::collections::HashSet::new();
        for signature in &self.signatures {
            if !seen.insert(signature.address.as_str()) {
                return Err(format!("duplicate signature for {}", signature.address));
            }
            self.verify_signature(&signature.address)?;
        }
        Ok(())
    }

    pub fn verify_signature(&self, signer_address: &str) -> Result<(), String> {
        let signer = signer_address.trim();
        if signer != self.commitment.left_address && signer != self.commitment.right_address {
            return Err("signer is not a channel party".into());
        }
        let signature = self
            .signatures
            .iter()
            .find(|item| item.address == signer)
            .ok_or_else(|| format!("missing signature from {signer}"))?;
        let hash = self.commitment.state_hash()?;
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
        )?;
        Ok(())
    }

    pub fn has_both_party_signatures(&self) -> bool {
        self.verify_signature(&self.commitment.left_address).is_ok()
            && self
                .verify_signature(&self.commitment.right_address)
                .is_ok()
    }
}

impl ChannelEquivocationProofV2 {
    pub fn build(
        signer_address: &str,
        first: SignedChannelStateV2,
        second: SignedChannelStateV2,
    ) -> Result<Self, String> {
        let mut proof = Self {
            schema: "hacash-l2-channel-equivocation-proof/2".into(),
            channel_id: first.commitment.channel_id.clone(),
            sequence: first.commitment.sequence,
            signer_address: signer_address.trim().to_string(),
            first,
            second,
        };
        if proof.first.state_hash_hex > proof.second.state_hash_hex {
            std::mem::swap(&mut proof.first, &mut proof.second);
        }
        proof.validate()?;
        Ok(proof)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != "hacash-l2-channel-equivocation-proof/2" {
            return Err("unsupported equivocation proof schema".into());
        }
        self.first.validate()?;
        self.second.validate()?;
        let a = &self.first.commitment;
        let b = &self.second.commitment;
        if a.channel_id != b.channel_id || a.channel_id != self.channel_id {
            return Err("equivocation proof channel ids differ".into());
        }
        if a.sequence != b.sequence || a.sequence != self.sequence {
            return Err("equivocation proof sequences differ".into());
        }
        if a.network_genesis_hash_hex != b.network_genesis_hash_hex
            || a.funding_anchor_hash_hex != b.funding_anchor_hash_hex
        {
            return Err("equivocation proof anchors differ".into());
        }
        if a.left_address != b.left_address || a.right_address != b.right_address {
            return Err("equivocation proof channel parties differ".into());
        }
        if constant_time_eq(
            self.first.state_hash_hex.as_bytes(),
            self.second.state_hash_hex.as_bytes(),
        ) {
            return Err("equivocation proof states are identical".into());
        }
        self.first.verify_signature(&self.signer_address)?;
        self.second.verify_signature(&self.signer_address)?;
        Ok(())
    }
}

pub fn sign_channel_state(
    account: &Account,
    commitment: ChannelStateCommitmentV2,
) -> Result<SignedChannelStateV2, String> {
    commitment.validate()?;
    let address = account.readable().to_string();
    if address != commitment.left_address && address != commitment.right_address {
        return Err("signing account is not a channel party".into());
    }
    let hash = commitment.state_hash()?;
    Ok(SignedChannelStateV2 {
        commitment,
        state_hash_hex: hex::encode(hash),
        signatures: vec![ChannelStateSignature {
            address,
            signature_hex: crate::crypto::sign_payment_hash(account, &hash),
            public_key_hex: String::new(),
        }],
    })
}

fn validate_address(address: &str, field: &str) -> Result<(), String> {
    if address.is_empty() || address.len() > 128 || address.trim() != address {
        return Err(format!("{field} must be a trimmed 1..128 byte string"));
    }
    Ok(())
}

fn decode_fixed_hex(value: &str, bytes: usize, field: &str) -> Result<Vec<u8>, String> {
    if value.len() != bytes * 2
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(format!("{field} must be exactly {bytes} bytes of hex"));
    }
    hex::decode(value).map_err(|error| format!("invalid {field}: {error}"))
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn append_string(output: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let len = u32::try_from(value.len()).map_err(|_| "canonical string too long")?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn append_hex(output: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let bytes = if value.is_empty() {
        Vec::new()
    } else {
        hex::decode(value).map_err(|error| format!("invalid canonical hex: {error}"))?
    };
    append_bytes(output, &bytes);
    Ok(())
}

fn constant_time_eq(expected: &[u8], actual: &[u8]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    expected
        .iter()
        .zip(actual)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(password: &str) -> Account {
        Account::create_by_password(password).unwrap()
    }

    fn commitment(left: &Account, right: &Account, left_zhu: u64) -> ChannelStateCommitmentV2 {
        ChannelStateCommitmentV2 {
            schema_version: CHANNEL_STATE_SCHEMA_V2,
            network_genesis_hash_hex: "11".repeat(32),
            channel_id: "22".repeat(16),
            funding_anchor_hash_hex: "33".repeat(32),
            sequence: 1,
            previous_state_hash_hex: String::new(),
            left_address: left.readable().to_string(),
            right_address: right.readable().to_string(),
            left_hac_zhu: left_zhu,
            right_hac_zhu: 1_000_000u64.checked_sub(left_zhu).unwrap(),
            left_satoshi: 30,
            right_satoshi: 70,
            funded_hac_zhu: 1_000_000,
            funded_satoshi: 100,
            conditional_state_root_hex: String::new(),
            expiry_unix: 0,
        }
    }

    fn add_signature(state: &mut SignedChannelStateV2, account: &Account) {
        let hash = state.commitment.state_hash().unwrap();
        state.signatures.push(ChannelStateSignature {
            address: account.readable().to_string(),
            signature_hex: crate::crypto::sign_payment_hash(account, &hash),
            public_key_hex: String::new(),
        });
    }

    #[test]
    fn canonical_hash_is_stable_and_binds_every_balance() {
        let left = account("channel-state-left");
        let right = account("channel-state-right");
        let first = commitment(&left, &right, 600_000);
        let mut changed = first.clone();
        changed.left_hac_zhu = 599_999;
        changed.right_hac_zhu = 400_001;
        let hash = first.state_hash_hex().unwrap();
        assert_eq!(
            hash,
            "6fe7ba73e626987afc4f386991ebe25ce0f833a712d43a89e9214db16b757ce6"
        );
        assert_eq!(hash, first.state_hash_hex().unwrap());
        assert_ne!(hash, changed.state_hash_hex().unwrap());
    }

    #[test]
    fn rejects_non_conserving_and_ambiguous_commitments() {
        let left = account("channel-state-left-invalid");
        let right = account("channel-state-right-invalid");
        let mut state = commitment(&left, &right, 600_000);
        state.funded_hac_zhu += 1;
        assert!(state.validate().unwrap_err().contains("conservation"));
        state.funded_hac_zhu -= 1;
        state.sequence = 2;
        assert!(state
            .validate()
            .unwrap_err()
            .contains("previous_state_hash_hex"));
    }

    #[test]
    fn verifies_both_channel_party_signatures() {
        let left = account("channel-state-left-sign");
        let right = account("channel-state-right-sign");
        let mut state = sign_channel_state(&left, commitment(&left, &right, 500_000)).unwrap();
        assert!(!state.has_both_party_signatures());
        add_signature(&mut state, &right);
        assert!(state.has_both_party_signatures());
        state.validate().unwrap();
    }

    #[test]
    fn builds_and_verifies_deterministic_equivocation_proof() {
        let left = account("channel-state-left-equivocation");
        let right = account("channel-state-right-equivocation");
        let first = sign_channel_state(&left, commitment(&left, &right, 600_000)).unwrap();
        let second = sign_channel_state(&left, commitment(&left, &right, 550_000)).unwrap();
        let proof = ChannelEquivocationProofV2::build(left.readable(), second, first).unwrap();
        proof.validate().unwrap();
        assert!(proof.first.state_hash_hex < proof.second.state_hash_hex);
        let encoded = serde_json::to_string(&proof).unwrap();
        let decoded: ChannelEquivocationProofV2 = serde_json::from_str(&encoded).unwrap();
        decoded.validate().unwrap();
    }

    #[test]
    fn rejects_forged_or_non_conflicting_equivocation_proof() {
        let left = account("channel-state-left-forgery");
        let right = account("channel-state-right-forgery");
        let attacker = account("channel-state-attacker");
        let first = sign_channel_state(&left, commitment(&left, &right, 600_000)).unwrap();
        assert!(
            ChannelEquivocationProofV2::build(left.readable(), first.clone(), first.clone())
                .is_err()
        );
        let mut forged = sign_channel_state(&left, commitment(&left, &right, 550_000)).unwrap();
        forged.signatures[0].signature_hex =
            crate::crypto::sign_payment_hash(&attacker, &forged.commitment.state_hash().unwrap());
        assert!(ChannelEquivocationProofV2::build(left.readable(), first, forged).is_err());
    }
}
