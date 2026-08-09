//! Bounded shadow storage for verified V2 channel states and equivocation proofs.
//!
//! Observations never mutate bills, balances, routing, or payment settlement.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::channel_activation::SignedChannelActivationV1;
use crate::channel_state::{ChannelEquivocationProofV2, SignedChannelStateV2};
use crate::types::LocalChannel;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelStateObservationV2 {
    pub observed_unix: u64,
    pub state: SignedChannelStateV2,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelStateObservationOutcomeV2 {
    New,
    Duplicate,
    Stale,
    Equivocation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelStateObservationResultV2 {
    pub outcome: ChannelStateObservationOutcomeV2,
    pub channel_id: String,
    pub sequence: u64,
    pub state_hash_hex: String,
    #[serde(default)]
    pub proof_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelActivationRecordV1 {
    pub activated_unix: u64,
    pub certificate: SignedChannelActivationV1,
    /// Latest mutually signed state accepted through the strict successor chain.
    pub verification_head: SignedChannelStateV2,
}

#[derive(Default)]
struct StoreInner {
    /// At most one latest observation per channel party.
    observations: HashMap<String, ChannelStateObservationV2>,
    /// Durable, deduplicated evidence. Never silently evicted.
    proofs: HashMap<String, ChannelEquivocationProofV2>,
    /// One permanent activation record per channel funding incarnation.
    activations: HashMap<String, ChannelActivationRecordV1>,
}

pub struct ChannelStateStoreV2 {
    inner: RwLock<StoreInner>,
    max_observations: usize,
    max_proofs: usize,
}

impl ChannelStateStoreV2 {
    pub fn new(max_channels: usize) -> Self {
        let channels = max_channels.max(1);
        Self {
            inner: RwLock::new(StoreInner::default()),
            max_observations: channels.saturating_mul(2),
            max_proofs: channels.clamp(128, 100_000),
        }
    }

    pub fn observe(
        &self,
        mut state: SignedChannelStateV2,
    ) -> Result<ChannelStateObservationResultV2, String> {
        state.validate()?;
        let now = now_unix();
        let mut guard = self.inner.write().map_err(|error| error.to_string())?;
        let known_signatures: Vec<_> = guard
            .observations
            .values()
            .filter(|item| {
                item.state.commitment.channel_id == state.commitment.channel_id
                    && item.state.state_hash_hex == state.state_hash_hex
            })
            .flat_map(|item| item.state.signatures.iter().cloned())
            .collect();
        for signature in known_signatures {
            if !state
                .signatures
                .iter()
                .any(|known| known.address == signature.address)
            {
                state.signatures.push(signature);
            }
        }
        state.signatures.sort_by(|a, b| a.address.cmp(&b.address));
        state.validate()?;
        if let Some(activation) = guard.activations.get(&state.commitment.channel_id) {
            validate_successor_against_activation(&state, activation)?;
        }
        let mut conflicts = Vec::new();
        let mut duplicate_count = 0usize;
        let mut stale_count = 0usize;
        let mut updates = Vec::new();

        for signature in &state.signatures {
            let key = observation_key(&state.commitment.channel_id, &signature.address);
            match guard.observations.get(&key) {
                Some(existing)
                    if existing.state.commitment.sequence == state.commitment.sequence =>
                {
                    if existing.state.state_hash_hex == state.state_hash_hex {
                        duplicate_count += 1;
                        if existing.state.signatures.len() < state.signatures.len() {
                            updates.push(key);
                        }
                    } else {
                        conflicts.push(ChannelEquivocationProofV2::build(
                            &signature.address,
                            existing.state.clone(),
                            state.clone(),
                        )?);
                    }
                }
                Some(existing)
                    if existing.state.commitment.sequence > state.commitment.sequence =>
                {
                    stale_count += 1;
                }
                _ => updates.push(key),
            }
        }

        if !conflicts.is_empty() {
            let mut proof_ids = Vec::with_capacity(conflicts.len());
            for proof in &conflicts {
                let id = proof_id_hex(proof)?;
                if !guard.proofs.contains_key(&id) && guard.proofs.len() >= self.max_proofs {
                    return Err(
                        "channel-state proof capacity reached; operator export required".into(),
                    );
                }
                proof_ids.push(id);
            }
            for (id, proof) in proof_ids.iter().cloned().zip(conflicts) {
                guard.proofs.entry(id).or_insert(proof);
            }
            proof_ids.sort();
            proof_ids.dedup();
            return Ok(ChannelStateObservationResultV2 {
                outcome: ChannelStateObservationOutcomeV2::Equivocation,
                channel_id: state.commitment.channel_id.clone(),
                sequence: state.commitment.sequence,
                state_hash_hex: state.state_hash_hex.clone(),
                proof_ids,
            });
        }

        let new_keys = updates
            .iter()
            .filter(|key| !guard.observations.contains_key(*key))
            .count();
        if guard.observations.len().saturating_add(new_keys) > self.max_observations {
            return Err("channel-state observation capacity reached".into());
        }
        let had_updates = !updates.is_empty();
        for key in updates {
            guard.observations.insert(
                key,
                ChannelStateObservationV2 {
                    observed_unix: now,
                    state: state.clone(),
                },
            );
        }

        if state.has_both_party_signatures() {
            if let Some(activation) = guard.activations.get_mut(&state.commitment.channel_id) {
                let head = &activation.verification_head;
                if state.commitment.sequence > head.commitment.sequence
                    || (state.commitment.sequence == head.commitment.sequence
                        && state.state_hash_hex == head.state_hash_hex
                        && state.signatures.len() > head.signatures.len())
                {
                    activation.verification_head = state.clone();
                }
            }
        }

        let outcome = if had_updates {
            ChannelStateObservationOutcomeV2::New
        } else if duplicate_count == state.signatures.len() {
            ChannelStateObservationOutcomeV2::Duplicate
        } else if stale_count == state.signatures.len() {
            ChannelStateObservationOutcomeV2::Stale
        } else {
            ChannelStateObservationOutcomeV2::New
        };
        Ok(ChannelStateObservationResultV2 {
            outcome,
            channel_id: state.commitment.channel_id.clone(),
            sequence: state.commitment.sequence,
            state_hash_hex: state.state_hash_hex.clone(),
            proof_ids: Vec::new(),
        })
    }

    pub fn restore_observation(
        &self,
        observation: ChannelStateObservationV2,
    ) -> Result<(), String> {
        observation.state.validate()?;
        let mut guard = self.inner.write().map_err(|error| error.to_string())?;
        for signature in &observation.state.signatures {
            let key = observation_key(&observation.state.commitment.channel_id, &signature.address);
            if let Some(existing) = guard.observations.get(&key) {
                if existing.state.commitment.sequence == observation.state.commitment.sequence
                    && existing.state.state_hash_hex != observation.state.state_hash_hex
                {
                    return Err("persisted observations contain an unresolved equivocation".into());
                }
                if existing.state.commitment.sequence >= observation.state.commitment.sequence {
                    continue;
                }
            } else if guard.observations.len() >= self.max_observations {
                return Err("persisted channel-state observations exceed capacity".into());
            }
            guard.observations.insert(key, observation.clone());
        }
        Ok(())
    }

    pub fn restore_proof(&self, proof: ChannelEquivocationProofV2) -> Result<(), String> {
        proof.validate()?;
        let id = proof_id_hex(&proof)?;
        let mut guard = self.inner.write().map_err(|error| error.to_string())?;
        if !guard.proofs.contains_key(&id) && guard.proofs.len() >= self.max_proofs {
            return Err("persisted channel-state proofs exceed capacity".into());
        }
        guard.proofs.entry(id).or_insert(proof);
        Ok(())
    }

    pub fn activation_draft_state(
        &self,
        channel_id: &str,
        state_hash_hex: &str,
    ) -> Result<Option<SignedChannelStateV2>, String> {
        validate_hash_hex(state_hash_hex, "state_hash_hex")?;
        let guard = self.inner.read().map_err(|error| error.to_string())?;
        Ok(guard
            .observations
            .values()
            .find(|observation| {
                observation.state.commitment.channel_id == channel_id
                    && observation.state.state_hash_hex == state_hash_hex
                    && observation.state.has_both_party_signatures()
            })
            .map(|observation| observation.state.clone()))
    }

    pub fn activate(
        &self,
        certificate: SignedChannelActivationV1,
    ) -> Result<ChannelActivationRecordV1, String> {
        certificate.validate()?;
        let channel_id = certificate.commitment.channel_id.clone();
        let mut guard = self.inner.write().map_err(|error| error.to_string())?;
        if let Some(existing) = guard.activations.get(&channel_id) {
            if existing.certificate.activation_hash_hex == certificate.activation_hash_hex {
                return Ok(existing.clone());
            }
            return Err(
                "channel already has a different permanent V2 activation certificate".into(),
            );
        }
        let initial_state = guard
            .observations
            .values()
            .find(|observation| {
                activation_matches_state(&certificate, &observation.state)
                    && observation.state.has_both_party_signatures()
            })
            .map(|observation| observation.state.clone())
            .ok_or("activation initial state is not a mutually signed stored V2 observation")?;
        let record = ChannelActivationRecordV1 {
            activated_unix: now_unix(),
            certificate,
            verification_head: initial_state,
        };
        validate_activation_record(&record)?;
        guard.activations.insert(channel_id, record.clone());
        Ok(record)
    }

    pub fn restore_activation(&self, record: ChannelActivationRecordV1) -> Result<(), String> {
        validate_activation_record(&record)?;
        let channel_id = record.certificate.commitment.channel_id.clone();
        let mut guard = self.inner.write().map_err(|error| error.to_string())?;
        if let Some(existing) = guard.activations.get(&channel_id) {
            if existing != &record {
                return Err("persisted channel activations conflict".into());
            }
            return Ok(());
        }
        if guard.activations.len() >= self.max_observations / 2 {
            return Err("persisted channel activations exceed capacity".into());
        }
        guard.activations.insert(channel_id, record);
        Ok(())
    }

    pub fn activation_for_channel(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelActivationRecordV1>, String> {
        let guard = self.inner.read().map_err(|error| error.to_string())?;
        Ok(guard.activations.get(channel_id).cloned())
    }

    pub fn observations_for_channel(
        &self,
        channel_id: &str,
    ) -> Result<Vec<ChannelStateObservationV2>, String> {
        let guard = self.inner.read().map_err(|error| error.to_string())?;
        let mut values: Vec<_> = guard
            .observations
            .values()
            .filter(|item| item.state.commitment.channel_id == channel_id)
            .cloned()
            .collect();
        values.sort_by(|a, b| {
            a.state
                .commitment
                .sequence
                .cmp(&b.state.commitment.sequence)
                .then_with(|| a.state.state_hash_hex.cmp(&b.state.state_hash_hex))
        });
        Ok(values)
    }

    pub fn proofs_for_channel(
        &self,
        channel_id: &str,
    ) -> Result<Vec<(String, ChannelEquivocationProofV2)>, String> {
        let guard = self.inner.read().map_err(|error| error.to_string())?;
        let mut values: Vec<_> = guard
            .proofs
            .iter()
            .filter(|(_, proof)| proof.channel_id == channel_id)
            .map(|(id, proof)| (id.clone(), proof.clone()))
            .collect();
        values.sort_by(|a, b| a.1.sequence.cmp(&b.1.sequence).then_with(|| a.0.cmp(&b.0)));
        Ok(values)
    }

    pub fn get_proof(&self, id: &str) -> Result<Option<ChannelEquivocationProofV2>, String> {
        if id.len() != 64
            || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || id.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err("proof id must be 32 bytes of lowercase hex".into());
        }
        let guard = self.inner.read().map_err(|error| error.to_string())?;
        Ok(guard.proofs.get(id).cloned())
    }

    pub fn export_observations(&self) -> Vec<ChannelStateObservationV2> {
        self.inner
            .read()
            .map(|guard| guard.observations.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn export_proofs(&self) -> Vec<ChannelEquivocationProofV2> {
        self.inner
            .read()
            .map(|guard| guard.proofs.values().cloned().collect())
            .unwrap_or_default()
    }
    pub fn export_activations(&self) -> Vec<ChannelActivationRecordV1> {
        self.inner
            .read()
            .map(|guard| guard.activations.values().cloned().collect())
            .unwrap_or_default()
    }
}

fn activation_matches_state(
    activation: &SignedChannelActivationV1,
    state: &SignedChannelStateV2,
) -> bool {
    let commitment = &activation.commitment;
    let state_commitment = &state.commitment;
    commitment.channel_id == state_commitment.channel_id
        && commitment.network_genesis_hash_hex == state_commitment.network_genesis_hash_hex
        && commitment.funding_anchor_hash_hex == state_commitment.funding_anchor_hash_hex
        && commitment.initial_state_sequence == state_commitment.sequence
        && commitment.initial_state_hash_hex == state.state_hash_hex
        && commitment.left_address == state_commitment.left_address
        && commitment.right_address == state_commitment.right_address
}

fn validate_activation_record(record: &ChannelActivationRecordV1) -> Result<(), String> {
    if record.activated_unix == 0 {
        return Err("channel activation timestamp must be greater than zero".into());
    }
    record.certificate.validate()?;
    record.verification_head.validate()?;
    if !record.verification_head.has_both_party_signatures() {
        return Err("channel activation verification head requires both party signatures".into());
    }
    let activation = &record.certificate.commitment;
    let head = &record.verification_head.commitment;
    if activation.channel_id != head.channel_id
        || activation.network_genesis_hash_hex != head.network_genesis_hash_hex
        || activation.funding_anchor_hash_hex != head.funding_anchor_hash_hex
        || activation.left_address != head.left_address
        || activation.right_address != head.right_address
    {
        return Err("channel activation verification head binding mismatch".into());
    }
    if head.sequence < activation.initial_state_sequence {
        return Err("channel activation verification head precedes its initial state".into());
    }
    if head.sequence == activation.initial_state_sequence
        && record.verification_head.state_hash_hex != activation.initial_state_hash_hex
    {
        return Err("channel activation initial verification head hash mismatch".into());
    }
    Ok(())
}

fn validate_successor_against_activation(
    state: &SignedChannelStateV2,
    activation: &ChannelActivationRecordV1,
) -> Result<(), String> {
    validate_activation_record(activation)?;
    let head = &activation.verification_head;
    if state.commitment.sequence <= head.commitment.sequence {
        return Ok(());
    }
    let expected_sequence = head
        .commitment
        .sequence
        .checked_add(1)
        .ok_or("activated V2 verification head sequence overflow")?;
    if state.commitment.sequence != expected_sequence {
        return Err(format!(
            "activated V2 chain rejects sequence gap: expected {expected_sequence}, got {}",
            state.commitment.sequence
        ));
    }
    if state.commitment.previous_state_hash_hex != head.state_hash_hex {
        return Err("activated V2 successor does not bind the current verification head".into());
    }
    Ok(())
}

fn validate_hash_hex(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(format!("{field} must be 32 bytes of lowercase hex"));
    }
    Ok(())
}

pub fn validate_state_against_channel(
    state: &SignedChannelStateV2,
    channel: &LocalChannel,
) -> Result<(), String> {
    state.validate()?;
    if state.commitment.channel_id != channel.channel_id {
        return Err("channel-state commitment does not match requested channel".into());
    }
    if state.commitment.left_address != channel.left_address
        || state.commitment.right_address != channel.right_address
    {
        return Err("channel-state parties do not match registered L1 channel parties".into());
    }
    if let Some(anchor) = &channel.l1_anchor {
        anchor.validate_against_channel(channel)?;
        if state.commitment.network_genesis_hash_hex != anchor.network_genesis_hash_hex
            || state.commitment.funding_anchor_hash_hex != anchor.funding_incarnation_hash_hex
        {
            return Err("channel-state commitment does not match the registered L1 anchor".into());
        }
    }
    let funded_hac_zhu = crate::amounts::parse_zhu(&channel.left_hac)?
        .checked_add(crate::amounts::parse_zhu(&channel.right_hac)?)
        .ok_or("registered channel HAC total overflow")?;
    if state.commitment.funded_hac_zhu != funded_hac_zhu {
        return Err("channel-state HAC funding total does not match registered channel".into());
    }
    let funded_satoshi = channel
        .left_satoshi
        .checked_add(channel.right_satoshi)
        .ok_or("registered channel satoshi total overflow")?;
    if state.commitment.funded_satoshi != funded_satoshi {
        return Err("channel-state satoshi funding total does not match registered channel".into());
    }
    Ok(())
}

fn observation_key(channel_id: &str, signer: &str) -> String {
    format!("{channel_id}:{signer}")
}

fn proof_id_hex(proof: &ChannelEquivocationProofV2) -> Result<String, String> {
    proof.validate()?;
    let mut bytes = Vec::with_capacity(256);
    append_len(&mut bytes, b"HACASH_L2_EQUIVOCATION_PROOF_ID_V2");
    append_len(&mut bytes, proof.channel_id.as_bytes());
    bytes.extend_from_slice(&proof.sequence.to_be_bytes());
    append_len(&mut bytes, proof.signer_address.as_bytes());
    append_len(&mut bytes, proof.first.state_hash_hex.as_bytes());
    append_len(&mut bytes, proof.second.state_hash_hex.as_bytes());
    Ok(hex::encode(crate::hacash_keys::sha3(&bytes)))
}

fn append_len(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel_activation::{
        sign_channel_activation, ChannelActivationCommitmentV1, SignedChannelActivationV1,
        ACTIVATION_SCOPE_STRICT_VERIFICATION_ONLY, CHANNEL_ACTIVATION_SCHEMA_V1,
    };
    use crate::channel_state::{
        sign_channel_state, ChannelStateCommitmentV2, CHANNEL_STATE_SCHEMA_V2,
    };
    use crate::hacash_keys::Account;
    use crate::types::HubSide;

    fn account(password: &str) -> Account {
        Account::create_by_password(password).unwrap()
    }

    fn commitment(
        left: &Account,
        right: &Account,
        sequence: u64,
        left_zhu: u64,
    ) -> ChannelStateCommitmentV2 {
        ChannelStateCommitmentV2 {
            schema_version: CHANNEL_STATE_SCHEMA_V2,
            network_genesis_hash_hex: "11".repeat(32),
            channel_id: "22".repeat(16),
            funding_anchor_hash_hex: "33".repeat(32),
            sequence,
            previous_state_hash_hex: if sequence == 1 {
                String::new()
            } else {
                "44".repeat(32)
            },
            left_address: left.readable().to_string(),
            right_address: right.readable().to_string(),
            left_hac_zhu: left_zhu,
            right_hac_zhu: 1_000_000 - left_zhu,
            left_satoshi: 30,
            right_satoshi: 70,
            funded_hac_zhu: 1_000_000,
            funded_satoshi: 100,
            conditional_state_root_hex: String::new(),
            expiry_unix: 0,
        }
    }

    fn mutually_signed_state(
        left: &Account,
        right: &Account,
        commitment: ChannelStateCommitmentV2,
    ) -> SignedChannelStateV2 {
        let mut state = sign_channel_state(left, commitment.clone()).unwrap();
        state
            .signatures
            .extend(sign_channel_state(right, commitment).unwrap().signatures);
        state.signatures.sort_by(|a, b| a.address.cmp(&b.address));
        state.validate().unwrap();
        state
    }

    fn activation_certificate(
        left: &Account,
        right: &Account,
        state: &SignedChannelStateV2,
    ) -> SignedChannelActivationV1 {
        let commitment = ChannelActivationCommitmentV1 {
            schema_version: CHANNEL_ACTIVATION_SCHEMA_V1,
            activation_scope: ACTIVATION_SCOPE_STRICT_VERIFICATION_ONLY,
            network_genesis_hash_hex: state.commitment.network_genesis_hash_hex.clone(),
            channel_id: state.commitment.channel_id.clone(),
            funding_anchor_hash_hex: state.commitment.funding_anchor_hash_hex.clone(),
            initial_state_sequence: state.commitment.sequence,
            initial_state_hash_hex: state.state_hash_hex.clone(),
            left_address: state.commitment.left_address.clone(),
            right_address: state.commitment.right_address.clone(),
            settlement_authority: false,
            l1_enforceable: false,
        };
        let mut signatures = vec![
            sign_channel_activation(left, commitment.clone()).unwrap(),
            sign_channel_activation(right, commitment.clone()).unwrap(),
        ];
        signatures.sort_by(|a, b| a.address.cmp(&b.address));
        let certificate = SignedChannelActivationV1 {
            activation_hash_hex: commitment.activation_hash_hex().unwrap(),
            commitment,
            signatures,
        };
        certificate.validate().unwrap();
        certificate
    }

    fn channel(left: &Account, right: &Account) -> LocalChannel {
        LocalChannel {
            channel_id: "22".repeat(16),
            left_address: left.readable().to_string(),
            right_address: right.readable().to_string(),
            left_hac: "6:245".into(),
            right_hac: "4:245".into(),
            left_satoshi: 30,
            right_satoshi: 70,
            l1_status: Some(1),
            open_height: Some(100),
            l1_anchor: None,
            hub_side: HubSide::Left,
            notes: String::new(),
            registered_unix: 1,
            balance_source: "registration".into(),
            last_settle_payment_id: None,
        }
    }

    #[test]
    fn detects_equivocation_without_advancing_observed_state() {
        let left = account("store-left-equivocation");
        let right = account("store-right-equivocation");
        let store = ChannelStateStoreV2::new(1);
        let first = sign_channel_state(&left, commitment(&left, &right, 1, 600_000)).unwrap();
        validate_state_against_channel(&first, &channel(&left, &right)).unwrap();
        assert_eq!(
            store.observe(first.clone()).unwrap().outcome,
            ChannelStateObservationOutcomeV2::New
        );
        assert_eq!(
            store.observe(first.clone()).unwrap().outcome,
            ChannelStateObservationOutcomeV2::Duplicate
        );

        let conflict = sign_channel_state(&left, commitment(&left, &right, 1, 550_000)).unwrap();
        let result = store.observe(conflict).unwrap();
        assert_eq!(
            result.outcome,
            ChannelStateObservationOutcomeV2::Equivocation
        );
        assert_eq!(result.proof_ids.len(), 1);
        let proofs = store.proofs_for_channel(&"22".repeat(16)).unwrap();
        assert_eq!(proofs.len(), 1);
        proofs[0].1.validate().unwrap();
        let observations = store.observations_for_channel(&"22".repeat(16)).unwrap();
        assert!(observations
            .iter()
            .all(|item| item.state.state_hash_hex == first.state_hash_hex));
    }

    #[test]
    fn merges_independent_signatures_and_rejects_stale_replacement() {
        let left = account("store-left-merge");
        let right = account("store-right-merge");
        let store = ChannelStateStoreV2::new(1);
        let commit = commitment(&left, &right, 2, 500_000);
        let signed_left = sign_channel_state(&left, commit.clone()).unwrap();
        let signed_right = sign_channel_state(&right, commit).unwrap();
        store.observe(signed_left).unwrap();
        store.observe(signed_right).unwrap();
        let observations = store.observations_for_channel(&"22".repeat(16)).unwrap();
        assert_eq!(observations.len(), 2);
        assert!(observations
            .iter()
            .all(|item| item.state.has_both_party_signatures()));

        let stale = sign_channel_state(&left, commitment(&left, &right, 1, 500_000)).unwrap();
        assert_eq!(
            store.observe(stale).unwrap().outcome,
            ChannelStateObservationOutcomeV2::Stale
        );
    }

    #[test]
    fn registered_channel_binding_rejects_wrong_funding_total() {
        let left = account("store-left-binding");
        let right = account("store-right-binding");
        let mut state = sign_channel_state(&left, commitment(&left, &right, 1, 600_000)).unwrap();
        state.commitment.funded_hac_zhu = 2_000_000;
        state.commitment.right_hac_zhu = 1_400_000;
        let hash = state.commitment.state_hash().unwrap();
        state.state_hash_hex = hex::encode(hash);
        state.signatures[0].signature_hex = crate::crypto::sign_payment_hash(&left, &hash);
        assert!(
            validate_state_against_channel(&state, &channel(&left, &right))
                .unwrap_err()
                .contains("funding total")
        );
    }
    #[test]
    fn negotiated_activation_enforces_gapless_mutually_signed_chain() {
        let left = account("store-left-activation");
        let right = account("store-right-activation");
        let store = ChannelStateStoreV2::new(2);

        let initial = mutually_signed_state(&left, &right, commitment(&left, &right, 1, 600_000));
        store.observe(initial.clone()).unwrap();
        let certificate = activation_certificate(&left, &right, &initial);
        let activated = store.activate(certificate.clone()).unwrap();
        assert_eq!(
            activated.verification_head.state_hash_hex,
            initial.state_hash_hex
        );
        let replay = store.activate(certificate).unwrap();
        assert_eq!(
            replay.certificate.activation_hash_hex,
            activated.certificate.activation_hash_hex
        );

        let gap = sign_channel_state(&left, commitment(&left, &right, 3, 580_000)).unwrap();
        assert!(store.observe(gap).unwrap_err().contains("sequence gap"));

        let wrong_predecessor =
            sign_channel_state(&left, commitment(&left, &right, 2, 590_000)).unwrap();
        assert!(store
            .observe(wrong_predecessor)
            .unwrap_err()
            .contains("current verification head"));

        let mut successor_commitment = commitment(&left, &right, 2, 590_000);
        successor_commitment.previous_state_hash_hex = initial.state_hash_hex.clone();
        let signed_left = sign_channel_state(&left, successor_commitment.clone()).unwrap();
        let signed_right = sign_channel_state(&right, successor_commitment).unwrap();
        store.observe(signed_left).unwrap();
        assert_eq!(
            store
                .activation_for_channel(&initial.commitment.channel_id)
                .unwrap()
                .unwrap()
                .verification_head
                .commitment
                .sequence,
            1
        );
        store.observe(signed_right).unwrap();
        let head = store
            .activation_for_channel(&initial.commitment.channel_id)
            .unwrap()
            .unwrap()
            .verification_head;
        assert_eq!(head.commitment.sequence, 2);
        assert!(head.has_both_party_signatures());

        let conflicting_initial =
            mutually_signed_state(&left, &right, commitment(&left, &right, 1, 500_000));
        let conflicting_certificate = activation_certificate(&left, &right, &conflicting_initial);
        assert!(store
            .activate(conflicting_certificate)
            .unwrap_err()
            .contains("different permanent"));
    }
}
