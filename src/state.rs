//! In-memory hub state: channels, peers, payment sessions.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::channel_activation::{
    ChannelActivationCommitmentV1, ChannelActivationDraftV1, SignedChannelActivationV1,
    ACTIVATION_SCOPE_STRICT_VERIFICATION_ONLY, CHANNEL_ACTIVATION_SCHEMA_V1,
};
use crate::channel_state::{
    ChannelEquivocationProofV2, ChannelStateCommitmentV2, ChannelStateDraftV2,
    SignedChannelStateV2, CHANNEL_STATE_SCHEMA_V2,
};
use crate::channel_state_store::ChannelActivationRecordV1;
use crate::channel_state_store::{
    validate_state_against_channel, ChannelStateObservationResultV2, ChannelStateObservationV2,
    ChannelStateStoreV2,
};
use crate::crypto::{
    bill_canonical_message, bill_message_hash_hex, canonical_message, message_hash_hex,
    verify_bill_signature, verify_payment_signature, BillCommit, PaymentCommit,
};
use crate::l1_anchor::{L1ChannelAnchorV1, L1ChannelObservationV1};
use crate::route::{find_path_for_amount, merge_network_edges, ordered_signers};
use crate::types::{
    AdvertisedChannel, BillStatus, ChannelBill, ClosePackage, CreateDeferredRequest,
    CreatePaymentRequest, DeferredPayment, DeferredStatus, DisputeExport, ForeignPayment, HubMeta,
    HubSide, LocalChannel, PaymentSession, PaymentSignature, PaymentStatus, PeerHello, PeerHub,
    PeerSeed, ProposeBillRequest, ProposeRebalanceRequest, RebalanceProposal, RebalanceStatus,
    RegisterChannelRequest, RemoteHop, RemotePaymentNotify, SignBillRequest, SignPaymentRequest,
};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Limits / policy knobs for HubState.
#[derive(Debug, Clone)]
pub struct HubLimits {
    pub max_payment_sessions: usize,
    pub max_channels: usize,
    pub max_peers: usize,
    pub max_hops: usize,
    /// 0 = never auto-expire collecting payments.
    pub payment_ttl_secs: u64,
    /// Cap known_peers accepted from a single hello.
    pub max_known_peers_per_hello: usize,
    /// Cap advertised channels per peer hello.
    pub max_channels_per_hello: usize,
    /// Phase B: require secp256k1 verify of payment signatures (default true).
    pub require_sig_verify: bool,
}

impl Default for HubLimits {
    fn default() -> Self {
        Self {
            max_payment_sessions: 10_000,
            max_channels: 50_000,
            max_peers: 5_000,
            max_hops: 8,
            payment_ttl_secs: 3600,
            max_known_peers_per_hello: 64,
            max_channels_per_hello: 512,
            require_sig_verify: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct OperationalStats {
    pub liquidity_reservations: u64,
    pub oldest_reservation_age_seconds: u64,
    pub applied_settlements: u64,
    pub agent_identities: u64,
    pub revoked_agent_identities: u64,
    pub open_micro_streams: u64,
    pub active_agent_intent_nonces: u64,
    pub scheduled_deferred_payments: u64,
    pub active_rebalances: u64,
}

pub struct HubState {
    inner: RwLock<Inner>,
    /// V3 shadow verifier/evidence store; never mutates payment state.
    channel_state_v2: ChannelStateStoreV2,
    limits: HubLimits,
    provider_id: String,
    policy: crate::policy::AgentPolicy,
    /// Optional hub operator key — signs payment receipts (not user funds).
    hub_identity: Option<Arc<crate::hacash_keys::Account>>,
}

/// Idempotent agent pay: key → payment + request fingerprint (prevents body mismatch / double create).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    pub payment_id: Uuid,
    /// SHA3-256 hex of canonical pay request fields.
    pub content_hash: String,
    pub created_unix: u64,
}

/// Liquidity held for a collecting payment. The exact direction is recorded
/// so concurrent payments cannot spend the same channel side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentReservation {
    pub payment_id: Uuid,
    pub amount_zhu: u64,
    pub amount_satoshi: u64,
    pub hops: Vec<ReservedHop>,
    pub created_unix: u64,
    pub expires_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReservedHop {
    pub channel_id: String,
    pub from_address: String,
    pub to_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIntentUse {
    pub idempotency_key: String,
    pub expires_unix: u64,
}

struct Inner {
    channels: HashMap<String, LocalChannel>,
    peers: HashMap<String, PeerHub>,
    payments: HashMap<Uuid, PaymentSession>,
    /// Last fully signed bill per channel. Never replace it with an unsigned draft.
    bills: HashMap<String, ChannelBill>,
    /// Candidate replacement bills, kept separately until both parties sign.
    bill_drafts: HashMap<String, ChannelBill>,
    /// Agent Pay: idempotency_key → record (content-bound)
    idempotency: HashMap<String, IdempotencyRecord>,
    /// Agent metadata per payment
    payment_meta: HashMap<Uuid, crate::agent_pay::AgentPaymentMeta>,
    /// Settled receipts
    receipts: HashMap<Uuid, crate::agent_pay::PaymentReceipt>,
    /// Request-to-pay invoices
    invoices: HashMap<Uuid, crate::invoice::Invoice>,
    /// payment_id → callback_url
    payment_callbacks: HashMap<Uuid, String>,
    /// Agent spend ledger
    ledger: crate::policy::AgentLedger,
    /// Verified agent identities
    identities: HashMap<String, crate::agent_id::AgentIdentity>,
    /// Pending identity challenges
    challenges: HashMap<Uuid, crate::agent_id::IdentityChallenge>,
    /// Micropayment streams
    micro_streams: HashMap<Uuid, crate::micro::MicroStream>,
    /// HVM escrow intents (stub)
    escrows: HashMap<Uuid, crate::hvm_stub::EscrowIntent>,
    /// Channel rebalance proposals (whitepaper capacity shift)
    rebalances: HashMap<Uuid, RebalanceProposal>,
    /// Deferred / scheduled payments
    deferred: HashMap<Uuid, DeferredPayment>,
    /// Multi-hop mirrors from other hubs (notify only; not local authority)
    foreign_payments: HashMap<Uuid, ForeignPayment>,
    /// Collecting payment liquidity holds.
    reservations: HashMap<Uuid, PaymentReservation>,
    /// Exactly-once guard for balance application.
    applied_settlements: HashSet<Uuid>,
    /// agent_id + nonce -> idempotent request claim.
    agent_intents: HashMap<String, AgentIntentUse>,
}

impl HubState {
    #[allow(dead_code)] // convenience + unit tests
    pub fn new(provider_id: String, max_payment_sessions: usize, max_hops: usize) -> Self {
        let mut limits = HubLimits::default();
        limits.max_payment_sessions = max_payment_sessions.max(16);
        limits.max_hops = max_hops.clamp(1, 32);
        Self::with_limits(provider_id, limits)
    }

    pub fn with_limits(provider_id: String, limits: HubLimits) -> Self {
        Self::with_limits_and_policy(provider_id, limits, crate::policy::AgentPolicy::default())
    }

    pub fn with_limits_and_policy(
        provider_id: String,
        limits: HubLimits,
        policy: crate::policy::AgentPolicy,
    ) -> Self {
        let mut limits = limits;
        limits.max_payment_sessions = limits.max_payment_sessions.max(16);
        limits.max_hops = limits.max_hops.clamp(1, 32);
        limits.max_channels = limits.max_channels.max(1);
        limits.max_peers = limits.max_peers.max(1);
        let channel_state_v2 = ChannelStateStoreV2::new(limits.max_channels);
        Self {
            inner: RwLock::new(Inner {
                channels: HashMap::new(),
                peers: HashMap::new(),
                payments: HashMap::new(),
                bills: HashMap::new(),
                bill_drafts: HashMap::new(),
                idempotency: HashMap::new(),
                payment_meta: HashMap::new(),
                receipts: HashMap::new(),
                invoices: HashMap::new(),
                payment_callbacks: HashMap::new(),
                ledger: crate::policy::AgentLedger::default(),
                identities: HashMap::new(),
                challenges: HashMap::new(),
                micro_streams: HashMap::new(),
                escrows: HashMap::new(),
                reservations: HashMap::new(),
                applied_settlements: HashSet::new(),
                rebalances: HashMap::new(),
                deferred: HashMap::new(),
                foreign_payments: HashMap::new(),
                agent_intents: HashMap::new(),
            }),
            channel_state_v2,
            limits,
            provider_id,
            policy,
            hub_identity: None,
        }
    }

    #[allow(dead_code)]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    // --- V3 channel-state shadow verification (no settlement authority) ---

    pub fn observe_channel_state_v2(
        &self,
        channel_id: &str,
        state: SignedChannelStateV2,
    ) -> Result<ChannelStateObservationResultV2, String> {
        let id = normalize_channel_id(channel_id)?;
        if state.commitment.channel_id != id {
            return Err("channel-state commitment does not match URL channel id".into());
        }
        let channel = self
            .get_channel(&id)
            .ok_or_else(|| format!("channel {id} not registered on this hub"))?;
        validate_state_against_channel(&state, &channel)?;
        self.channel_state_v2.observe(state)
    }

    pub fn channel_state_observations_v2(
        &self,
        channel_id: &str,
    ) -> Result<Vec<ChannelStateObservationV2>, String> {
        let id = normalize_channel_id(channel_id)?;
        self.channel_state_v2.observations_for_channel(&id)
    }

    pub fn channel_state_proofs_v2(
        &self,
        channel_id: &str,
    ) -> Result<Vec<(String, ChannelEquivocationProofV2)>, String> {
        let id = normalize_channel_id(channel_id)?;
        self.channel_state_v2.proofs_for_channel(&id)
    }

    pub fn get_channel_state_proof_v2(
        &self,
        channel_id: &str,
        proof_id: &str,
    ) -> Result<Option<ChannelEquivocationProofV2>, String> {
        let id = normalize_channel_id(channel_id)?;
        let proof = self.channel_state_v2.get_proof(proof_id)?;
        Ok(proof.filter(|item| item.channel_id == id))
    }

    pub fn restore_channel_state_observation_v2(
        &self,
        observation: ChannelStateObservationV2,
    ) -> Result<(), String> {
        let id = normalize_channel_id(&observation.state.commitment.channel_id)?;
        let channel = self
            .get_channel(&id)
            .ok_or_else(|| format!("persisted V2 observation references unknown channel {id}"))?;
        validate_state_against_channel(&observation.state, &channel)?;
        self.channel_state_v2.restore_observation(observation)
    }

    pub fn restore_channel_state_proof_v2(
        &self,
        proof: ChannelEquivocationProofV2,
    ) -> Result<(), String> {
        proof.validate()?;
        let id = normalize_channel_id(&proof.channel_id)?;
        let channel = self
            .get_channel(&id)
            .ok_or_else(|| format!("persisted V2 proof references unknown channel {id}"))?;
        validate_state_against_channel(&proof.first, &channel)?;
        validate_state_against_channel(&proof.second, &channel)?;
        self.channel_state_v2.restore_proof(proof)
    }
    pub fn channel_activation_draft_v1(
        &self,
        channel_id: &str,
        state_hash_hex: &str,
    ) -> Result<ChannelActivationDraftV1, String> {
        let id = normalize_channel_id(channel_id)?;
        let channel = self
            .get_channel(&id)
            .ok_or_else(|| format!("channel {id} not registered on this hub"))?;
        if channel.l1_status != Some(0) {
            return Err("V2 activation requires an L1 channel in opening status 0".into());
        }
        let state = self
            .channel_state_v2
            .activation_draft_state(&id, state_hash_hex)?
            .ok_or("activation requires a mutually signed stored V2 state")?;
        validate_state_against_channel(&state, &channel)?;
        let anchor = channel
            .l1_anchor
            .as_ref()
            .ok_or("channel has no verified fullnode anchor; refresh L1 first")?;
        anchor.validate_against_channel(&channel)?;
        let commitment = ChannelActivationCommitmentV1 {
            schema_version: CHANNEL_ACTIVATION_SCHEMA_V1,
            activation_scope: ACTIVATION_SCOPE_STRICT_VERIFICATION_ONLY,
            network_genesis_hash_hex: anchor.network_genesis_hash_hex.clone(),
            channel_id: id,
            funding_anchor_hash_hex: anchor.funding_incarnation_hash_hex.clone(),
            initial_state_sequence: state.commitment.sequence,
            initial_state_hash_hex: state.state_hash_hex,
            left_address: channel.left_address,
            right_address: channel.right_address,
            settlement_authority: false,
            l1_enforceable: false,
        };
        Ok(ChannelActivationDraftV1 {
            schema: "hacash-l2-channel-activation/1".into(),
            activation_hash_hex: commitment.activation_hash_hex()?,
            commitment,
        })
    }

    pub fn activate_channel_v2(
        &self,
        channel_id: &str,
        certificate: SignedChannelActivationV1,
    ) -> Result<ChannelActivationRecordV1, String> {
        let id = normalize_channel_id(channel_id)?;
        if certificate.commitment.channel_id != id {
            return Err("activation certificate does not match URL channel id".into());
        }
        let channel = self
            .get_channel(&id)
            .ok_or_else(|| format!("channel {id} not registered on this hub"))?;
        validate_activation_against_channel(&certificate, &channel, true)?;
        self.channel_state_v2.activate(certificate)
    }

    pub fn channel_activation_v1(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelActivationRecordV1>, String> {
        let id = normalize_channel_id(channel_id)?;
        self.channel_state_v2.activation_for_channel(&id)
    }

    pub fn restore_channel_activation_v1(
        &self,
        record: ChannelActivationRecordV1,
    ) -> Result<(), String> {
        let id = normalize_channel_id(&record.certificate.commitment.channel_id)?;
        let channel = self
            .get_channel(&id)
            .ok_or_else(|| format!("persisted V2 activation references unknown channel {id}"))?;
        validate_activation_against_channel(&record.certificate, &channel, false)?;
        validate_state_against_channel(&record.verification_head, &channel)?;
        self.channel_state_v2.restore_activation(record)
    }

    /// Build a deterministic, unsigned V2 migration candidate from the latest
    /// fully active V1 bill. This is read-only and grants no settlement authority.
    pub fn channel_state_shadow_v2(&self, channel_id: &str) -> Result<ChannelStateDraftV2, String> {
        let id = normalize_channel_id(channel_id)?;
        let channel = self
            .get_channel(&id)
            .ok_or_else(|| format!("channel {id} not registered on this hub"))?;
        let anchor = channel
            .l1_anchor
            .as_ref()
            .ok_or("channel has no verified fullnode anchor; refresh L1 first")?;
        anchor.validate_against_channel(&channel)?;
        if channel.l1_status != Some(0) {
            return Err("V2 shadow draft requires an L1 channel in opening status 0".into());
        }

        let bill = self
            .get_active_bill(&id)
            .ok_or("V2 shadow draft requires a fully signed active V1 bill")?;
        if bill.status != BillStatus::Active {
            return Err("V2 shadow source bill is not active".into());
        }
        if bill.sequence == 0 {
            return Err("V2 shadow source bill sequence must be greater than zero".into());
        }
        if bill.channel_id != id
            || bill.left_address != channel.left_address
            || bill.right_address != channel.right_address
        {
            return Err("active V1 bill does not match registered channel parties".into());
        }
        let v1_commit = BillCommit {
            channel_id: bill.channel_id.clone(),
            sequence: bill.sequence,
            provider_id: self.provider_id.clone(),
            left_address: bill.left_address.clone(),
            right_address: bill.right_address.clone(),
            left_hac: bill.left_hac.clone(),
            right_hac: bill.right_hac.clone(),
            left_satoshi: bill.left_satoshi,
            right_satoshi: bill.right_satoshi,
            prev_bill_hash: bill.prev_bill_hash.clone(),
            created_unix: bill.created_unix,
            payment_id: bill
                .payment_id
                .map(|value| value.to_string())
                .unwrap_or_default(),
        };
        if bill.message != bill_canonical_message(&v1_commit)
            || bill.message_hash_hex != bill_message_hash_hex(&v1_commit)
        {
            return Err("active V1 bill canonical message or hash is invalid".into());
        }
        if bill.required_signers
            != vec![channel.left_address.clone(), channel.right_address.clone()]
        {
            return Err("active V1 bill signer set is not the ordered channel parties".into());
        }
        let hash_bytes = hex::decode(&bill.message_hash_hex)
            .map_err(|error| format!("active V1 bill message hash is invalid: {error}"))?;
        let hash: [u8; 32] = hash_bytes
            .try_into()
            .map_err(|_| "active V1 bill message hash must be 32 bytes")?;
        for party in [&channel.left_address, &channel.right_address] {
            let signature = bill
                .signatures
                .iter()
                .find(|signature| &signature.address == party)
                .ok_or_else(|| format!("active V1 bill is missing the {party} signature"))?;
            let public_key = if signature.public_key_hex.is_empty() {
                None
            } else {
                Some(signature.public_key_hex.as_str())
            };
            verify_bill_signature(&hash, party, &signature.signature_hex, public_key)?;
        }
        if bill.message_hash_hex.len() != 64
            || !bill
                .message_hash_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("active V1 bill has an invalid canonical message hash".into());
        }

        let previous_state_hash_hex = if bill.sequence == 1 {
            String::new()
        } else {
            let predecessor_sequence = bill.sequence - 1;
            let mut predecessors: Vec<_> = self
                .channel_state_v2
                .observations_for_channel(&id)?
                .into_iter()
                .map(|observation| observation.state)
                .filter(|state| {
                    state.commitment.sequence == predecessor_sequence
                        && state.commitment.network_genesis_hash_hex
                            == anchor.network_genesis_hash_hex
                        && state.commitment.funding_anchor_hash_hex
                            == anchor.funding_incarnation_hash_hex
                        && state.has_both_party_signatures()
                })
                .collect();
            predecessors.sort_by(|left, right| left.state_hash_hex.cmp(&right.state_hash_hex));
            predecessors.dedup_by(|left, right| left.state_hash_hex == right.state_hash_hex);
            match predecessors.as_slice() {
                [predecessor] => predecessor.state_hash_hex.clone(),
                [] => {
                    return Err(format!(
                        "V2 sequence {} requires one mutually signed V2 predecessor at sequence {}",
                        bill.sequence, predecessor_sequence
                    ))
                }
                _ => {
                    return Err(format!(
                        "multiple mutually signed V2 predecessors exist at sequence {}; refusing ambiguous chain",
                        predecessor_sequence
                    ))
                }
            }
        };

        let commitment = ChannelStateCommitmentV2 {
            schema_version: CHANNEL_STATE_SCHEMA_V2,
            network_genesis_hash_hex: anchor.network_genesis_hash_hex.clone(),
            channel_id: id,
            funding_anchor_hash_hex: anchor.funding_incarnation_hash_hex.clone(),
            sequence: bill.sequence,
            previous_state_hash_hex,
            left_address: bill.left_address,
            right_address: bill.right_address,
            left_hac_zhu: crate::amounts::parse_zhu(&bill.left_hac)?,
            right_hac_zhu: crate::amounts::parse_zhu(&bill.right_hac)?,
            left_satoshi: bill.left_satoshi,
            right_satoshi: bill.right_satoshi,
            funded_hac_zhu: anchor.funded_hac_zhu()?,
            funded_satoshi: anchor.funded_satoshi()?,
            conditional_state_root_hex: String::new(),
            expiry_unix: 0,
        };
        let state_hash_hex = commitment.state_hash_hex()?;
        Ok(ChannelStateDraftV2 {
            schema: "hacash-l2-channel-state-shadow/2".into(),
            commitment,
            state_hash_hex,
            source_v1_bill_sequence: bill.sequence,
            source_v1_bill_message_hash_hex: bill.message_hash_hex,
            source_v1_signatures_reused: false,
        })
    }
    // --- multi-hop foreign payment mirrors (notify only) ---

    /// Accept a notify from an origin hub if it involves our channels / provider.
    pub fn ingest_remote_payment_notify(
        &self,
        n: RemotePaymentNotify,
    ) -> Result<ForeignPayment, String> {
        let origin = n.origin_provider_id.trim();
        let origin_url = n.origin_public_url.trim().trim_end_matches('/');
        if origin.is_empty() || origin_url.is_empty() {
            return Err("origin_provider_id and origin_public_url required".into());
        }
        if origin == self.provider_id {
            return Err("ignore self-notify".into());
        }
        if n.message_hash_hex.trim().len() != 64 {
            return Err("message_hash_hex must be 64 hex chars".into());
        }
        if n.required_signers.is_empty() {
            return Err("required_signers required".into());
        }
        // Only accept if relevant to this hub
        let relevant = n
            .remote_hops
            .iter()
            .any(|h| h.via_provider == self.provider_id)
            || n.route.iter().any(|cid| {
                normalize_channel_id(cid)
                    .ok()
                    .and_then(|id| self.get_channel(&id))
                    .is_some()
            });
        if !relevant {
            return Err(
                "notify not relevant: no hop via this provider and no local channel in route"
                    .into(),
            );
        }
        let now = now_unix();
        let fp = ForeignPayment {
            origin_provider_id: clamp_str(origin, 64),
            origin_public_url: clamp_str(origin_url, 512),
            payment_id: n.payment_id,
            payer: clamp_str(&n.payer, 128),
            payee: clamp_str(&n.payee, 128),
            amount_hac: clamp_str(&n.amount_hac, 64),
            amount_satoshi: n.amount_satoshi,
            fee_hac: clamp_str(&n.fee_hac, 64),
            message_hash_hex: n.message_hash_hex.trim().to_lowercase(),
            required_signers: n
                .required_signers
                .into_iter()
                .take(32)
                .map(|s| clamp_str(&s, 128))
                .collect(),
            route: n
                .route
                .into_iter()
                .take(32)
                .filter_map(|c| normalize_channel_id(&c).ok())
                .collect(),
            status: clamp_str(&n.status, 32),
            next_signer: clamp_str(&n.next_signer, 128),
            expires_unix: n.expires_unix,
            created_unix: if n.created_unix > 0 {
                n.created_unix
            } else {
                now
            },
            sign_endpoint: clamp_str(&n.sign_endpoint, 512),
            status_endpoint: clamp_str(&n.status_endpoint, 512),
            notified_unix: now,
            updated_unix: now,
        };
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        if !g.foreign_payments.contains_key(&fp.payment_id) && g.foreign_payments.len() >= 20_000 {
            // Drop oldest half by updated_unix
            let mut ids: Vec<_> = g
                .foreign_payments
                .iter()
                .map(|(id, f)| (*id, f.updated_unix))
                .collect();
            ids.sort_by_key(|(_, t)| *t);
            let n_drop = ids.len() / 2;
            for (id, _) in ids.into_iter().take(n_drop) {
                g.foreign_payments.remove(&id);
            }
        }
        g.foreign_payments.insert(fp.payment_id, fp.clone());
        Ok(fp)
    }

    pub fn list_foreign_payments(&self, limit: usize) -> Vec<ForeignPayment> {
        let mut list: Vec<_> = self
            .inner
            .read()
            .map(|g| g.foreign_payments.values().cloned().collect())
            .unwrap_or_default();
        list.sort_by(|a, b| b.updated_unix.cmp(&a.updated_unix));
        list.truncate(limit.max(1).min(500));
        list
    }

    pub fn foreign_payments_for_address(&self, address: &str, limit: usize) -> Vec<ForeignPayment> {
        let addr = address.trim();
        let mut list: Vec<_> = self
            .list_foreign_payments(500)
            .into_iter()
            .filter(|f| {
                f.payer == addr
                    || f.payee == addr
                    || f.required_signers.iter().any(|s| s == addr)
                    || f.next_signer == addr
            })
            .collect();
        list.truncate(limit.max(1).min(200));
        list
    }

    /// Atomically claim an agent intent nonce. A retry of the same logical
    /// idempotent request is accepted; reuse for another request is rejected.
    pub fn claim_agent_intent(
        &self,
        agent_id: &str,
        nonce: &str,
        idempotency_key: &str,
        expires_unix: u64,
    ) -> Result<bool, String> {
        let now = now_unix();
        if expires_unix <= now {
            return Err("agent intent expired".into());
        }
        let key = format!("{}\u{0}{}", agent_id.trim(), nonce);
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        g.agent_intents.retain(|_, used| used.expires_unix >= now);
        if let Some(used) = g.agent_intents.get(&key) {
            if used.idempotency_key == idempotency_key {
                return Ok(false);
            }
            return Err("agent intent nonce was already used for another request".into());
        }
        if g.agent_intents.len() >= 50_000 {
            return Err("too many active agent intent nonces; retry after expiry".into());
        }
        g.agent_intents.insert(
            key,
            AgentIntentUse {
                idempotency_key: idempotency_key.to_string(),
                expires_unix,
            },
        );
        Ok(true)
    }

    pub fn release_agent_intent(&self, agent_id: &str, nonce: &str, idempotency_key: &str) {
        let key = format!("{}\u{0}{}", agent_id.trim(), nonce);
        if let Ok(mut g) = self.inner.write() {
            if g.agent_intents
                .get(&key)
                .map(|used| used.idempotency_key == idempotency_key)
                .unwrap_or(false)
            {
                g.agent_intents.remove(&key);
            }
        }
    }

    #[allow(dead_code)]
    pub fn get_foreign_payment(&self, id: Uuid) -> Option<ForeignPayment> {
        self.inner
            .read()
            .ok()
            .and_then(|g| g.foreign_payments.get(&id).cloned())
    }

    /// Attach hub identity for receipt signatures (called once at startup).
    pub fn set_hub_identity(&mut self, account: crate::hacash_keys::Account) {
        self.hub_identity = Some(Arc::new(account));
    }

    #[allow(dead_code)]
    pub fn hub_identity_address(&self) -> Option<String> {
        self.hub_identity.as_ref().map(|a| a.readable().to_string())
    }

    pub fn create_escrow(
        &self,
        req: crate::hvm_stub::CreateEscrowRequest,
    ) -> Result<crate::hvm_stub::EscrowIntent, String> {
        if req.payer.trim().is_empty() || req.payee.trim().is_empty() {
            return Err("payer and payee required".into());
        }
        let e = crate::hvm_stub::EscrowIntent {
            id: Uuid::new_v4(),
            payer: clamp_str(req.payer.trim(), 128),
            payee: clamp_str(req.payee.trim(), 128),
            amount_hac: clamp_str(&req.amount_hac, 64),
            amount_satoshi: req.amount_satoshi,
            release_condition: clamp_str(&req.release_condition, 256),
            status: "intent_recorded".into(),
            created_unix: now_unix(),
            note: clamp_str(&req.note, 256),
            hvm_target: clamp_str(&req.hvm_target, 128),
        };
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        g.escrows.insert(e.id, e.clone());
        Ok(e)
    }

    pub fn list_escrows(&self) -> Vec<crate::hvm_stub::EscrowIntent> {
        self.inner
            .read()
            .map(|g| g.escrows.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_receipt_by_hash(&self, hash_hex: &str) -> Option<crate::agent_pay::PaymentReceipt> {
        let h = hash_hex.trim().to_lowercase();
        self.inner.read().ok().and_then(|g| {
            g.receipts
                .values()
                .find(|r| r.receipt_hash_hex.to_lowercase() == h)
                .cloned()
        })
    }

    /// Batch-settle micro stream: sum remaining pushes that created payments still open — N/A.
    /// Returns stream summary for agents to close and bill.
    pub fn micro_settle_summary(&self, id: Uuid) -> Result<serde_json::Value, String> {
        let s = self
            .get_micro_stream(id)
            .ok_or_else(|| "stream not found".to_string())?;
        let payment_ids: Vec<_> = s.entries.iter().filter_map(|e| e.payment_id).collect();
        let mut settled = 0usize;
        let mut open = 0usize;
        for pid in &payment_ids {
            if let Some(p) = self.get_payment(*pid) {
                match p.status {
                    PaymentStatus::Settled => settled += 1,
                    PaymentStatus::Failed | PaymentStatus::TimedOut => {}
                    _ => open += 1,
                }
            }
        }
        Ok(serde_json::json!({
            "stream_id": s.id,
            "status": s.status,
            "spent_hac_mei": s.spent_hac_mei,
            "spent_hac_zhu": s.spent_hac_zhu,
            "spent_satoshi": s.spent_satoshi,
            "payment_ids": payment_ids,
            "payments_settled": settled,
            "payments_open": open,
            "hint": "Drain inbox for open payments; then close stream and propose last bill"
        }))
    }

    pub fn policy(&self) -> &crate::policy::AgentPolicy {
        &self.policy
    }

    // --- channels ---

    pub fn register_channel(&self, req: RegisterChannelRequest) -> Result<LocalChannel, String> {
        let id = normalize_channel_id(&req.channel_id)?;
        let left = req.left_address.trim();
        let right = req.right_address.trim();
        if left.is_empty() || right.is_empty() {
            return Err("left_address and right_address required".into());
        }
        if left == right {
            return Err("left and right addresses must differ".into());
        }
        if left.len() > 128 || right.len() > 128 {
            return Err("address too long (max 128)".into());
        }
        if req.notes.len() > 512 {
            return Err("notes too long (max 512)".into());
        }
        let left_hac = if req.left_hac.trim().is_empty() {
            "0".to_string()
        } else {
            crate::amounts::normalize_hac(&req.left_hac)?
        };
        let right_hac = if req.right_hac.trim().is_empty() {
            "0".to_string()
        } else {
            crate::amounts::normalize_hac(&req.right_hac)?
        };
        let ch = LocalChannel {
            channel_id: id.clone(),
            left_address: left.to_string(),
            right_address: right.to_string(),
            left_hac,
            right_hac,
            left_satoshi: req.left_satoshi,
            right_satoshi: req.right_satoshi,
            l1_status: None,
            open_height: None,
            l1_anchor: None,
            hub_side: req.hub_side.unwrap_or(HubSide::Unknown),
            notes: clamp_str(&req.notes, 512),
            registered_unix: now_unix(),
            balance_source: "registration".into(),
            last_settle_payment_id: None,
        };
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        if g.reservations
            .values()
            .any(|reservation| reservation.hops.iter().any(|hop| hop.channel_id == id))
        {
            return Err("channel has reserved liquidity for an open payment".into());
        }
        if !g.channels.contains_key(&id) && g.channels.len() >= self.limits.max_channels {
            return Err(format!(
                "too many channels (max {})",
                self.limits.max_channels
            ));
        }
        g.channels.insert(id, ch.clone());
        Ok(ch)
    }

    pub fn list_channels(&self) -> Vec<LocalChannel> {
        self.inner
            .read()
            .map(|g| g.channels.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_channel(&self, id: &str) -> Option<LocalChannel> {
        let id = normalize_channel_id(id).ok()?;
        self.inner
            .read()
            .ok()
            .and_then(|g| g.channels.get(&id).cloned())
    }

    /// Restore fields that are not accepted from the public registration API
    /// but are required for exactly-once settlement after snapshot reload.
    pub(crate) fn restore_channel_persist_metadata(
        &self,
        id: &str,
        registered_unix: u64,
        balance_source: &str,
        last_settle_payment_id: Option<Uuid>,
    ) -> Result<(), String> {
        let id = normalize_channel_id(id)?;
        if !matches!(
            balance_source,
            "registration" | "payment_settle" | "active_bill" | "distributed_2pc_commit"
        ) {
            return Err("persisted channel has an invalid balance_source".into());
        }
        let mut state = self.inner.write().map_err(|error| error.to_string())?;
        let channel = state
            .channels
            .get_mut(&id)
            .ok_or_else(|| format!("channel {id} not found during metadata recovery"))?;
        channel.registered_unix = registered_unix;
        channel.balance_source = balance_source.to_string();
        channel.last_settle_payment_id = last_settle_payment_id;
        Ok(())
    }

    pub fn update_channel_l1(
        &self,
        id: &str,
        status: Option<u8>,
        open_height: Option<u64>,
    ) -> Result<(), String> {
        let id = normalize_channel_id(id)?;
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let ch = g
            .channels
            .get_mut(&id)
            .ok_or_else(|| format!("channel {id} not registered on this hub"))?;
        if let Some(s) = status {
            ch.l1_status = Some(s);
        }
        if let Some(h) = open_height {
            ch.open_height = Some(h);
        }
        Ok(())
    }

    /// Apply a strictly parsed fullnode observation. A registered channel is
    /// permanently bound to its first observed funding incarnation; reuse
    /// requires an explicit new registration lifecycle instead of silently
    /// mixing old bills/evidence with new L1 funds.
    pub fn apply_l1_channel_observation(
        &self,
        id: &str,
        observation: L1ChannelObservationV1,
    ) -> Result<LocalChannel, String> {
        let id = normalize_channel_id(id)?;
        let channel = self
            .get_channel(&id)
            .ok_or_else(|| format!("channel {id} not registered on this hub"))?;
        observation.anchor.validate_against_channel(&channel)?;
        self.validate_anchor_against_evidence(&observation.anchor)?;

        let mut state = self.inner.write().map_err(|error| error.to_string())?;
        let channel = state
            .channels
            .get_mut(&id)
            .ok_or_else(|| format!("channel {id} not registered on this hub"))?;
        if let Some(existing) = &channel.l1_anchor {
            if existing.network_genesis_hash_hex != observation.anchor.network_genesis_hash_hex
                || existing.funding_incarnation_hash_hex
                    != observation.anchor.funding_incarnation_hash_hex
            {
                return Err(
                    "L1 channel funding incarnation changed; explicit channel re-registration is required"
                        .into(),
                );
            }
            if observation.anchor.observed_height < existing.observed_height {
                return Err("stale L1 channel observation would roll back anchor height".into());
            }
        }
        channel.l1_status = Some(observation.status);
        channel.open_height = Some(observation.anchor.open_height);
        channel.l1_anchor = Some(observation.anchor);
        Ok(channel.clone())
    }

    pub(crate) fn restore_channel_l1_anchor(
        &self,
        id: &str,
        anchor: L1ChannelAnchorV1,
    ) -> Result<(), String> {
        let id = normalize_channel_id(id)?;
        let channel = self
            .get_channel(&id)
            .ok_or_else(|| format!("persisted L1 anchor references unknown channel {id}"))?;
        anchor.validate_against_channel(&channel)?;
        if !matches!(channel.l1_status, Some(0..=3)) {
            return Err("persisted channel with an L1 anchor has an invalid L1 status".into());
        }
        if let Some(open_height) = channel.open_height {
            if open_height != anchor.open_height {
                return Err("persisted channel open_height conflicts with its L1 anchor".into());
            }
        }
        let mut state = self.inner.write().map_err(|error| error.to_string())?;
        let channel = state
            .channels
            .get_mut(&id)
            .ok_or_else(|| format!("persisted L1 anchor references unknown channel {id}"))?;
        channel.open_height = Some(anchor.open_height);
        channel.l1_anchor = Some(anchor);
        Ok(())
    }

    fn validate_anchor_against_evidence(&self, anchor: &L1ChannelAnchorV1) -> Result<(), String> {
        for observation in self
            .channel_state_v2
            .observations_for_channel(&anchor.channel_id)?
        {
            let commitment = &observation.state.commitment;
            if commitment.network_genesis_hash_hex != anchor.network_genesis_hash_hex
                || commitment.funding_anchor_hash_hex != anchor.funding_incarnation_hash_hex
            {
                return Err(
                    "existing V2 evidence is bound to a different or unverified L1 anchor".into(),
                );
            }
        }
        for (_, proof) in self
            .channel_state_v2
            .proofs_for_channel(&anchor.channel_id)?
        {
            let commitment = &proof.first.commitment;
            if commitment.network_genesis_hash_hex != anchor.network_genesis_hash_hex
                || commitment.funding_anchor_hash_hex != anchor.funding_incarnation_hash_hex
            {
                return Err(
                    "existing V2 equivocation proof is bound to a different L1 anchor".into(),
                );
            }
        }
        Ok(())
    }
    pub fn channel_count(&self) -> usize {
        self.inner.read().map(|g| g.channels.len()).unwrap_or(0)
    }

    pub fn operational_stats(&self) -> OperationalStats {
        let now = now_unix();
        let Ok(g) = self.inner.read() else {
            return OperationalStats::default();
        };
        let oldest_created = g
            .reservations
            .values()
            .map(|reservation| reservation.created_unix)
            .min()
            .unwrap_or(now);
        OperationalStats {
            liquidity_reservations: g.reservations.len() as u64,
            oldest_reservation_age_seconds: if g.reservations.is_empty() {
                0
            } else {
                now.saturating_sub(oldest_created)
            },
            applied_settlements: g.applied_settlements.len() as u64,
            agent_identities: g.identities.len() as u64,
            revoked_agent_identities: g
                .identities
                .values()
                .filter(|identity| identity.revoked)
                .count() as u64,
            open_micro_streams: g
                .micro_streams
                .values()
                .filter(|stream| stream.status == crate::micro::MicroStreamStatus::Open)
                .count() as u64,
            active_agent_intent_nonces: g
                .agent_intents
                .values()
                .filter(|intent| intent.expires_unix >= now)
                .count() as u64,
            scheduled_deferred_payments: g
                .deferred
                .values()
                .filter(|deferred| {
                    matches!(
                        deferred.status,
                        DeferredStatus::Scheduled | DeferredStatus::Ready
                    )
                })
                .count() as u64,
            active_rebalances: g
                .rebalances
                .values()
                .filter(|rebalance| {
                    matches!(
                        rebalance.status,
                        RebalanceStatus::Proposed | RebalanceStatus::Collecting
                    )
                })
                .count() as u64,
        }
    }
    pub fn advertise_channels(&self) -> Vec<AdvertisedChannel> {
        self.list_channels()
            .into_iter()
            .map(|ch| {
                let left_zhu = crate::amounts::parse_zhu(&ch.left_hac).unwrap_or(0);
                let right_zhu = crate::amounts::parse_zhu(&ch.right_hac).unwrap_or(0);
                let capacity_zhu = left_zhu.checked_add(right_zhu).unwrap_or(0);
                AdvertisedChannel {
                    channel_id: ch.channel_id,
                    left_address: ch.left_address,
                    right_address: ch.right_address,
                    via_provider: self.provider_id.clone(),
                    capacity_mei: capacity_zhu / crate::amounts::ZHU_PER_MEI,
                    left_available_mei: left_zhu / crate::amounts::ZHU_PER_MEI,
                    right_available_mei: right_zhu / crate::amounts::ZHU_PER_MEI,
                    capacity_zhu,
                    left_available_zhu: left_zhu,
                    right_available_zhu: right_zhu,
                    fee_ppm: 0,
                }
            })
            .collect()
    }

    /// Fill capacity / channel_count fields on hub meta for hello advertise.
    pub fn enrich_meta_capacity(&self, mut meta: HubMeta) -> HubMeta {
        let ads = self.advertise_channels();
        meta.channel_count = ads.len();
        meta.total_capacity_mei = ads.iter().map(|c| c.capacity_mei).sum();
        meta.max_channel_capacity_mei = ads.iter().map(|c| c.capacity_mei).max().unwrap_or(0);
        meta
    }

    pub fn capacity_summary(&self) -> serde_json::Value {
        let ads = self.advertise_channels();
        let total: u64 = ads.iter().map(|c| c.capacity_mei).sum();
        let max = ads.iter().map(|c| c.capacity_mei).max().unwrap_or(0);
        let total_zhu = ads
            .iter()
            .try_fold(0u64, |sum, channel| sum.checked_add(channel.capacity_zhu))
            .unwrap_or(u64::MAX);
        serde_json::json!({
            "channel_count": ads.len(),
            "total_capacity_mei": total,
            "max_channel_capacity_mei": max,
            "total_capacity_zhu": total_zhu,
            "channels": ads,
        })
    }

    // --- peers ---

    pub fn list_peers(&self) -> Vec<PeerHub> {
        self.inner
            .read()
            .map(|g| g.peers.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_peer(&self, provider_id: &str) -> Option<PeerHub> {
        self.inner
            .read()
            .ok()
            .and_then(|g| g.peers.get(provider_id).cloned())
    }

    pub fn peer_counts(&self) -> (usize, usize) {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return (0, 0),
        };
        let total = g.peers.len();
        let reachable = g.peers.values().filter(|p| p.reachable).count();
        (total, reachable)
    }

    pub fn peer_seeds(&self) -> Vec<PeerSeed> {
        self.list_peers()
            .into_iter()
            .map(|p| PeerSeed {
                provider_id: p.provider_id,
                public_url: p.public_url,
                region: p.meta.region,
                notes: String::new(),
            })
            .collect()
    }

    pub fn remember_seed(&self, provider_id: &str, public_url: &str) -> Result<(), String> {
        if provider_id == self.provider_id {
            return Ok(());
        }
        let pid = provider_id.trim();
        if pid.is_empty() || pid.len() > 64 || pid.contains('_') || pid.contains(' ') {
            return Err("invalid provider_id for seed".into());
        }
        let url = public_url.trim().trim_end_matches('/');
        if url.is_empty() || url.len() > 512 {
            return Err("invalid public_url for seed".into());
        }
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        if !g.peers.contains_key(pid) && g.peers.len() >= self.limits.max_peers {
            return Err(format!("too many peers (max {})", self.limits.max_peers));
        }
        g.peers
            .entry(pid.to_string())
            .and_modify(|p| {
                p.public_url = url.to_string();
            })
            .or_insert_with(|| PeerHub {
                provider_id: pid.to_string(),
                public_url: url.to_string(),
                name: pid.to_string(),
                channels: Vec::new(),
                last_seen_unix: 0,
                reachable: false,
                meta: HubMeta::default(),
                identity_verified: false,
            });
        Ok(())
    }

    /// Restore a previously verified peer identity pin from the local durable
    /// snapshot. Reachability is reset until the next successful hello.
    pub fn restore_trusted_peer(&self, mut peer: PeerHub) -> Result<(), String> {
        let provider = peer.provider_id.trim();
        if provider.is_empty()
            || provider == self.provider_id
            || provider.len() > 64
            || provider.contains('_')
            || provider.contains(' ')
        {
            return Err("invalid persisted trusted peer provider".into());
        }
        if !peer.identity_verified
            || peer.meta.identity_address.trim().is_empty()
            || peer.meta.identity_pubkey_hex.trim().is_empty()
        {
            return Err("persisted trusted peer lacks verified identity pin".into());
        }
        peer.reachable = false;
        peer.channels.truncate(self.limits.max_channels_per_hello);
        let mut state = self.inner.write().map_err(|error| error.to_string())?;
        if !state.peers.contains_key(provider) && state.peers.len() >= self.limits.max_peers {
            return Err("too many persisted peers".into());
        }
        state.peers.insert(provider.to_string(), peer);
        Ok(())
    }

    pub fn upsert_peer_from_hello(&self, hello: &PeerHello, reachable: bool) -> Result<(), String> {
        if hello.provider_id == self.provider_id {
            return Ok(());
        }
        let pid = hello.provider_id.trim();
        let url = hello.public_url.trim();
        if pid.is_empty() || url.is_empty() {
            return Err("provider_id and public_url required".into());
        }
        if pid.len() > 64 || pid.contains('_') || pid.contains(' ') {
            return Err("invalid peer provider_id".into());
        }
        if url.len() > 512 {
            return Err("public_url too long".into());
        }
        let mut channels = Vec::new();
        for c in hello
            .channels
            .iter()
            .take(self.limits.max_channels_per_hello)
        {
            let id = match normalize_channel_id(&c.channel_id) {
                Ok(id) => id,
                Err(_) => continue, // skip bad ads, don't fail whole hello
            };
            let left = c.left_address.trim();
            let right = c.right_address.trim();
            if left.is_empty() || right.is_empty() || left.len() > 128 || right.len() > 128 {
                continue;
            }
            channels.push(AdvertisedChannel {
                channel_id: id,
                left_address: left.to_string(),
                right_address: right.to_string(),
                via_provider: if c.via_provider.trim().is_empty() {
                    pid.to_string()
                } else {
                    clamp_str(&c.via_provider, 64)
                },
                capacity_mei: c.capacity_mei,
                left_available_mei: c.left_available_mei,
                right_available_mei: c.right_available_mei,
                fee_ppm: c.fee_ppm,
                capacity_zhu: c.capacity_zhu,
                left_available_zhu: c.left_available_zhu,
                right_available_zhu: c.right_available_zhu,
            });
        }
        let mut meta = sanitize_meta(&hello.meta);
        // Prefer top-level identity fields from signed hello
        if !hello.identity_address.trim().is_empty() {
            meta.identity_address = clamp_str(&hello.identity_address, 128);
        }
        if !hello.identity_pubkey_hex.trim().is_empty() {
            meta.identity_pubkey_hex = clamp_str(&hello.identity_pubkey_hex, 128);
        }
        if meta.channel_count == 0 {
            meta.channel_count = channels.len();
        }
        if meta.total_capacity_mei == 0 {
            meta.total_capacity_mei = channels.iter().map(|c| c.capacity_mei).sum();
        }
        let peer = PeerHub {
            provider_id: pid.to_string(),
            public_url: url.trim_end_matches('/').to_string(),
            name: if hello.name.trim().is_empty() {
                pid.to_string()
            } else {
                clamp_str(&hello.name, 128)
            },
            channels,
            last_seen_unix: now_unix(),
            reachable,
            identity_verified: !hello.signature_hex.trim().is_empty(),
            meta,
        };
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        if let Some(existing) = g.peers.get(pid) {
            if existing.identity_verified {
                if !peer.identity_verified {
                    return Err(format!(
                        "unsigned hello cannot replace pinned identity for {pid}"
                    ));
                }
                if existing.meta.identity_address != peer.meta.identity_address
                    || !existing
                        .meta
                        .identity_pubkey_hex
                        .eq_ignore_ascii_case(&peer.meta.identity_pubkey_hex)
                {
                    return Err(format!(
                        "hub identity rotation for {pid} requires an explicit operator action"
                    ));
                }
            }
        }
        if !g.peers.contains_key(pid) && g.peers.len() >= self.limits.max_peers {
            return Err(format!("too many peers (max {})", self.limits.max_peers));
        }
        g.peers.insert(peer.provider_id.clone(), peer);
        Ok(())
    }

    /// Accept a bounded slice of known_peers from an inbound hello.
    pub fn ingest_known_peers(&self, seeds: &[PeerSeed]) {
        for s in seeds.iter().take(self.limits.max_known_peers_per_hello) {
            let _ = self.remember_seed(&s.provider_id, &s.public_url);
        }
    }

    /// Snapshot of this hub as a PeerHub (for discovery directory).
    pub fn self_as_peer(&self, public_url: &str, name: &str, meta: HubMeta) -> PeerHub {
        PeerHub {
            provider_id: self.provider_id.clone(),
            public_url: public_url.trim_end_matches('/').to_string(),
            name: name.to_string(),
            channels: self.advertise_channels(),
            last_seen_unix: now_unix(),
            reachable: true,
            identity_verified: true,
            meta,
        }
    }

    pub fn mark_peer_unreachable(&self, provider_id: &str) {
        if let Ok(mut g) = self.inner.write() {
            if let Some(p) = g.peers.get_mut(provider_id) {
                p.reachable = false;
            }
        }
    }

    // --- payments ---

    pub fn payment_counts(&self) -> (usize, usize) {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return (0, 0),
        };
        let mut open = 0usize;
        let mut settled = 0usize;
        for p in g.payments.values() {
            match p.status {
                PaymentStatus::Settled => settled += 1,
                PaymentStatus::Failed | PaymentStatus::TimedOut => {}
                _ => open += 1,
            }
        }
        (open, settled)
    }

    /// Local-only settlement entry point. Existing internal features keep this
    /// fail-closed so they cannot accidentally create an unprepared cross-hub payment.
    pub fn create_payment(&self, req: CreatePaymentRequest) -> Result<PaymentSession, String> {
        self.create_payment_mode(req, false)
    }

    /// Create a cross-hub candidate. Callers must synchronously run
    /// `DistributedTxManager::prepare_origin` before acknowledging it.
    pub fn create_distributed_payment(
        &self,
        req: CreatePaymentRequest,
    ) -> Result<PaymentSession, String> {
        self.create_payment_mode(req, true)
    }

    fn create_payment_mode(
        &self,
        req: CreatePaymentRequest,
        allow_distributed: bool,
    ) -> Result<PaymentSession, String> {
        if req.payer.trim().is_empty() || req.payee.trim().is_empty() {
            return Err("payer and payee required".into());
        }
        if req.payer.trim() == req.payee.trim() {
            return Err("payer and payee must differ".into());
        }
        if req.amount_hac.trim().is_empty() && req.amount_satoshi == 0 {
            return Err("amount_hac or amount_satoshi required".into());
        }

        let g_read = self.inner.read().map_err(|e| e.to_string())?;
        let local: Vec<_> = g_read.channels.values().cloned().collect();
        let peers: Vec<_> = g_read.peers.values().cloned().collect();
        drop(g_read);

        let amount_hac = if req.amount_hac.trim().is_empty() {
            "0".to_string()
        } else {
            crate::amounts::normalize_hac(&req.amount_hac)?
        };
        let amount_zhu = crate::amounts::parse_zhu(&amount_hac)?;
        let mut edges = if req.local_only {
            local
                .iter()
                .map(|c| crate::route::edge_from_local(c, &self.provider_id))
                .collect::<Vec<_>>()
        } else {
            merge_network_edges(&local, &peers, &self.provider_id)
        };
        // Total capacity filter when amount known and edge publishes capacity (>0).
        if amount_zhu > 0 {
            edges = crate::route::filter_edges_by_capacity(edges, amount_zhu);
        }

        let path_edges = if req.route.is_empty() {
            // Directional liquidity when balances are known (local channels always known)
            find_path_for_amount(
                &edges,
                &req.payer,
                &req.payee,
                self.limits.max_hops,
                amount_zhu,
            )?
        } else {
            let mut out = Vec::new();
            let mut at = req.payer.trim().to_string();
            for cid in &req.route {
                let id = normalize_channel_id(cid)?;
                let e = edges
                    .iter()
                    .find(|e| e.channel_id == id)
                    .ok_or_else(|| format!("route channel {id} not found in network graph"))?
                    .clone();
                if amount_zhu > 0 && !crate::route::can_send_from(&e, &at, amount_zhu) {
                    return Err(format!(
                        "insufficient directional liquidity on channel {id} from {at} for {amount_zhu} Zhu"
                    ));
                }
                at = if e.a == at {
                    e.b.clone()
                } else if e.b == at {
                    e.a.clone()
                } else {
                    return Err(format!(
                        "explicit route broken at channel {id}: not incident to {at}"
                    ));
                };
                out.push(e);
            }
            if at != req.payee.trim() {
                return Err(format!(
                    "explicit route ends at {at}, expected payee {}",
                    req.payee.trim()
                ));
            }
            out
        };

        let route: Vec<String> = path_edges.iter().map(|e| e.channel_id.clone()).collect();
        let required_signers = ordered_signers(&path_edges, &req.payer, &req.payee);
        let mut remote_hops: Vec<RemoteHop> = path_edges
            .iter()
            .filter(|e| e.via_provider != self.provider_id)
            .map(|e| {
                let url = peers
                    .iter()
                    .find(|p| p.provider_id == e.via_provider)
                    .map(|p| p.public_url.clone());
                RemoteHop {
                    channel_id: e.channel_id.clone(),
                    via_provider: e.via_provider.clone(),
                    public_url: url,
                    from_address: String::new(),
                    to_address: String::new(),
                }
            })
            .collect();
        if !remote_hops.is_empty() && !allow_distributed {
            return Err(
                "cross-hub route requires the durable distributed transaction coordinator".into(),
            );
        }
        let mut reservation_hops = Vec::with_capacity(path_edges.len());
        let mut seen_channels = HashSet::new();
        let mut seen_addresses = HashSet::new();
        let mut walker = req.payer.trim().to_string();
        seen_addresses.insert(walker.clone());
        for edge in &path_edges {
            if !seen_channels.insert(edge.channel_id.clone()) {
                return Err("payment routes may not repeat a channel".into());
            }
            let next = if edge.a == walker {
                edge.b.clone()
            } else if edge.b == walker {
                edge.a.clone()
            } else {
                return Err(format!("payment route is broken at {}", edge.channel_id));
            };
            if !seen_addresses.insert(next.clone()) {
                return Err("payment routes may not revisit an address".into());
            }
            let hop = ReservedHop {
                channel_id: edge.channel_id.clone(),
                from_address: walker,
                to_address: next.clone(),
            };
            if edge.via_provider == self.provider_id {
                reservation_hops.push(hop.clone());
            } else {
                let remote = remote_hops
                    .iter_mut()
                    .find(|remote| {
                        remote.channel_id == edge.channel_id
                            && remote.via_provider == edge.via_provider
                    })
                    .ok_or_else(|| {
                        format!("remote hop metadata missing for {}", edge.channel_id)
                    })?;
                remote.from_address = hop.from_address.clone();
                remote.to_address = hop.to_address.clone();
            }
            walker = next;
        }

        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        if g.payments.len() >= self.limits.max_payment_sessions {
            let droppable: Vec<Uuid> = g
                .payments
                .iter()
                .filter(|(_, p)| {
                    matches!(
                        p.status,
                        PaymentStatus::Settled | PaymentStatus::Failed | PaymentStatus::TimedOut
                    )
                })
                .map(|(id, _)| *id)
                .take(64)
                .collect();
            for id in droppable {
                g.payments.remove(&id);
            }
            if g.payments.len() >= self.limits.max_payment_sessions {
                return Err("too many payment sessions; try again later".into());
            }
        }

        let now = now_unix();
        let expires = if self.limits.payment_ttl_secs > 0 {
            now.saturating_add(self.limits.payment_ttl_secs)
        } else {
            0
        };
        let id = Uuid::new_v4();
        let payer = clamp_str(req.payer.trim(), 128);
        let payee = clamp_str(req.payee.trim(), 128);
        let fee_hac = if req.fee_hac.trim().is_empty() {
            "0".to_string()
        } else {
            crate::amounts::normalize_hac(&req.fee_hac)?
        };
        if amount_hac == "0" && req.amount_satoshi == 0 {
            return Err("payment amount must be greater than zero".into());
        }
        let commit = PaymentCommit {
            session_id: id.to_string(),
            provider_id: self.provider_id.clone(),
            payer: payer.clone(),
            payee: payee.clone(),
            amount_hac: amount_hac.clone(),
            amount_satoshi: req.amount_satoshi,
            fee_hac: fee_hac.clone(),
            route: route.clone(),
            required_signers: required_signers.clone(),
            created_unix: now,
        };
        let message = canonical_message(&commit);
        let message_hash_hex = message_hash_hex(&commit);
        let session = PaymentSession {
            id,
            status: PaymentStatus::CollectingSignatures,
            finality: "hub_coordinated_not_l1".into(),
            message,
            message_hash_hex,
            route,
            required_signers,
            payer,
            payee,
            amount_hac,
            amount_satoshi: req.amount_satoshi,
            fee_hac,
            created_unix: now,
            updated_unix: now,
            expires_unix: expires,
            last_error: None,
            signatures: Vec::new(),
            remote_hops,
        };
        let reservation = PaymentReservation {
            payment_id: session.id,
            amount_zhu,
            amount_satoshi: session.amount_satoshi,
            hops: reservation_hops,
            created_unix: now,
            expires_unix: expires,
        };
        reserve_payment_liquidity(&mut g, reservation)?;
        g.payments.insert(session.id, session.clone());
        Ok(session)
    }

    /// Content-bound retry key for wallet and low-level HTTP cross-hub creates.
    /// The namespace should be stable for the caller (normally the payer address).
    pub fn create_distributed_payment_idempotent(
        &self,
        req: CreatePaymentRequest,
        idempotency_key: &str,
        namespace: &str,
    ) -> Result<(PaymentSession, bool), String> {
        let key = idempotency_key.trim();
        if key.is_empty() || key.len() > 128 {
            return Err("idempotency key must contain 1..=128 characters".into());
        }
        if namespace.trim().is_empty() {
            return Err("idempotency namespace required".into());
        }
        let scoped_key = format!("http:{}\0{}", namespace.trim(), key);
        let content_hash = pay_request_fingerprint(
            &req.payer,
            &req.payee,
            &req.amount_hac,
            req.amount_satoshi,
            &req.fee_hac,
            req.local_only,
            &req.route,
            None,
        );
        {
            let state = self.inner.read().map_err(|error| error.to_string())?;
            if let Some(record) = state.idempotency.get(&scoped_key) {
                if record.content_hash != content_hash {
                    return Err(
                        "idempotency_conflict: key was used with different payment fields".into(),
                    );
                }
                if let Some(payment) = state.payments.get(&record.payment_id) {
                    return Ok((payment.clone(), true));
                }
            }
        }

        let created = self.create_distributed_payment(req)?;
        let mut state = self.inner.write().map_err(|error| error.to_string())?;
        if let Some(record) = state.idempotency.get(&scoped_key) {
            if record.content_hash != content_hash {
                state.payments.remove(&created.id);
                state.reservations.remove(&created.id);
                return Err(
                    "idempotency_conflict: key was used with different payment fields".into(),
                );
            }
            if let Some(existing) = state.payments.get(&record.payment_id).cloned() {
                state.payments.remove(&created.id);
                state.reservations.remove(&created.id);
                return Ok((existing, true));
            }
        }
        state.idempotency.insert(
            scoped_key,
            IdempotencyRecord {
                payment_id: created.id,
                content_hash,
                created_unix: now_unix(),
            },
        );
        Ok((created, false))
    }

    pub fn idempotency_for_payment(&self, payment_id: Uuid) -> Option<(String, IdempotencyRecord)> {
        self.inner.read().ok().and_then(|state| {
            state
                .idempotency
                .iter()
                .find(|(_, record)| record.payment_id == payment_id)
                .map(|(key, record)| (key.clone(), record.clone()))
        })
    }

    pub fn restore_distributed_idempotency(&self, key: String, record: IdempotencyRecord) {
        if let Ok(mut state) = self.inner.write() {
            if state.payments.contains_key(&record.payment_id) {
                state.idempotency.entry(key).or_insert(record);
            }
        }
    }

    // --- Agent Pay protocol ---

    /// Dry-run route (no session stored).
    pub fn quote_payment(
        &self,
        payer: &str,
        payee: &str,
        amount_hac: &str,
        amount_satoshi: u64,
        local_only: bool,
        route: &[String],
    ) -> Result<crate::agent_pay::QuoteResult, String> {
        if payer.trim().is_empty() || payee.trim().is_empty() {
            return Err("from and to required".into());
        }
        let g_read = self.inner.read().map_err(|e| e.to_string())?;
        let local: Vec<_> = g_read.channels.values().cloned().collect();
        let peers: Vec<_> = g_read.peers.values().cloned().collect();
        drop(g_read);

        let normalized_hac = if amount_hac.trim().is_empty() {
            "0".to_string()
        } else {
            crate::amounts::normalize_hac(amount_hac)?
        };
        let amount_zhu = crate::amounts::parse_zhu(&normalized_hac)?;
        let mut edges = if local_only {
            local
                .iter()
                .map(|c| crate::route::edge_from_local(c, &self.provider_id))
                .collect::<Vec<_>>()
        } else {
            merge_network_edges(&local, &peers, &self.provider_id)
        };
        if amount_zhu > 0 {
            edges = crate::route::filter_edges_by_capacity(edges, amount_zhu);
        }

        let path_edges = if route.is_empty() {
            find_path_for_amount(
                edges.as_slice(),
                payer,
                payee,
                self.limits.max_hops,
                amount_zhu,
            )?
        } else {
            let mut out = Vec::new();
            let mut at = payer.trim().to_string();
            for cid in route {
                let id = normalize_channel_id(cid)?;
                let e = edges
                    .iter()
                    .find(|e| e.channel_id == id)
                    .ok_or_else(|| format!("route channel {id} not found"))?
                    .clone();
                if amount_zhu > 0 && !crate::route::can_send_from(&e, &at, amount_zhu) {
                    return Err(format!(
                        "insufficient directional liquidity on channel {id} from {at} for {amount_zhu} Zhu"
                    ));
                }
                at = if e.a == at {
                    e.b.clone()
                } else if e.b == at {
                    e.a.clone()
                } else {
                    return Err(format!(
                        "explicit route broken at channel {id}: not incident to {at}"
                    ));
                };
                out.push(e);
            }
            if at != payee.trim() {
                return Err(format!(
                    "explicit route ends at {at}, expected payee {}",
                    payee.trim()
                ));
            }
            out
        };

        let route_ids: Vec<String> = path_edges.iter().map(|e| e.channel_id.clone()).collect();
        let required_signers = ordered_signers(&path_edges, payer, payee);
        let remote_hubs = path_edges
            .iter()
            .filter(|e| e.via_provider != self.provider_id)
            .count();

        // Fee fields filled by agent_quote with hub schedule (HubState has no fee config).
        Ok(crate::agent_pay::quote_from_session_preview(
            payer.trim(),
            payee.trim(),
            &normalized_hac,
            amount_satoshi,
            route_ids,
            required_signers,
            remote_hubs,
            local_only,
        ))
    }

    /// Quote with CSP fee schedule (agent path).
    pub fn quote_payment_with_fees(
        &self,
        payer: &str,
        payee: &str,
        amount_hac: &str,
        amount_satoshi: u64,
        local_only: bool,
        route: &[String],
        schedule: &crate::types::FeeSchedule,
    ) -> Result<crate::agent_pay::QuoteResult, String> {
        let mut q =
            self.quote_payment(payer, payee, amount_hac, amount_satoshi, local_only, route)?;
        let fee = crate::agent_pay::resolve_fee_hac("", amount_hac, schedule)?;
        q.fee_hac_estimate = fee;
        q.fee_base_mei = schedule.fee_base_mei;
        q.fee_ppm = schedule.fee_ppm;
        q.note = "Quote only — no payment created. If fee_hac omitted on pay, hub applies fee_hac_estimate into the signed message.".into();
        Ok(q)
    }

    /// Idempotent agent payment create.
    /// Returns (session, replayed).
    #[allow(dead_code)]
    pub fn agent_create_payment(
        &self,
        req: CreatePaymentRequest,
        idempotency_key: &str,
        meta: crate::agent_pay::AgentPaymentMeta,
    ) -> Result<(PaymentSession, bool), String> {
        self.agent_create_payment_ex(req, idempotency_key, meta, None, "")
    }

    /// Extended create with optional invoice link + callback.
    ///
    /// Idempotency is content-bound: same key + different from/to/amount → error.
    /// Invoice amounts always win when `invoice_id` is set (cannot underpay).
    pub fn agent_create_payment_ex(
        &self,
        req: CreatePaymentRequest,
        idempotency_key: &str,
        meta: crate::agent_pay::AgentPaymentMeta,
        invoice_id: Option<Uuid>,
        callback_url: &str,
    ) -> Result<(PaymentSession, bool), String> {
        self.agent_create_payment_ex_mode(
            req,
            idempotency_key,
            meta,
            invoice_id,
            callback_url,
            false,
        )
    }

    /// AI-agent entry point that may return a cross-hub candidate. The HTTP
    /// layer must finish durable prepare before acknowledging a new session.
    pub fn agent_create_distributed_payment_ex(
        &self,
        req: CreatePaymentRequest,
        idempotency_key: &str,
        meta: crate::agent_pay::AgentPaymentMeta,
        invoice_id: Option<Uuid>,
        callback_url: &str,
    ) -> Result<(PaymentSession, bool), String> {
        self.agent_create_payment_ex_mode(
            req,
            idempotency_key,
            meta,
            invoice_id,
            callback_url,
            true,
        )
    }

    fn agent_create_payment_ex_mode(
        &self,
        mut req: CreatePaymentRequest,
        idempotency_key: &str,
        meta: crate::agent_pay::AgentPaymentMeta,
        invoice_id: Option<Uuid>,
        callback_url: &str,
        allow_distributed: bool,
    ) -> Result<(PaymentSession, bool), String> {
        let raw_key = idempotency_key.trim();
        if raw_key.is_empty() {
            return Err("missing_idempotency_key".into());
        }
        if raw_key.len() > 128 {
            return Err("idempotency_key max 128 chars".into());
        }
        let agent_id_owned = if meta.agent_id.trim().is_empty() {
            "anonymous".to_string()
        } else {
            meta.agent_id.trim().to_string()
        };
        let agent_id = agent_id_owned.as_str();
        if let Some(identity) = self.get_identity(agent_id) {
            if identity.revoked {
                return Err("agent identity revoked".into());
            }
            if identity.verified && !identity.allows("pay") {
                return Err("agent identity lacks 'pay' scope".into());
            }
        }
        let now = now_unix();

        // --- Invoice lock: force amounts + validate (under read) ---
        if let Some(iid) = invoice_id {
            let g = self.inner.read().map_err(|e| e.to_string())?;
            let inv = g
                .invoices
                .get(&iid)
                .ok_or_else(|| format!("invoice {iid} not found"))?;
            if inv.status == crate::invoice::InvoiceStatus::Paying {
                let verified_addr = g
                    .identities
                    .get(agent_id)
                    .and_then(|id| id.verified.then_some(id.address.as_str()));
                let principal =
                    crate::policy::policy_principal(agent_id, req.payer.trim(), verified_addr);
                let scoped_key = format!("{principal}\u{0}{raw_key}");
                let linked_id = inv
                    .payment_id
                    .ok_or_else(|| "paying invoice is missing payment_id".to_string())?;
                if g.idempotency
                    .get(&scoped_key)
                    .map(|record| record.payment_id == linked_id)
                    .unwrap_or(false)
                {
                    if let Some(payment) = g.payments.get(&linked_id) {
                        return Ok((payment.clone(), true));
                    }
                }
                return Err("invoice is already paying via another idempotent request".into());
            }
            if inv.status != crate::invoice::InvoiceStatus::Open {
                return Err(format!("invoice is {:?}", inv.status));
            }
            if inv.expires_unix > 0 && now >= inv.expires_unix {
                return Err("invoice expired".into());
            }
            if !inv.payer_hint.is_empty() && inv.payer_hint != req.payer.trim() {
                return Err("invoice payer_hint does not match from".into());
            }
            // Client may omit amount (or send 0) — then invoice wins.
            // If client sends a positive/non-zero amount, it must match invoice exactly.
            let client_hac = req.amount_hac.trim();
            let client_sat = req.amount_satoshi;
            let client_hac_set = !client_hac.is_empty() && client_hac != "0";
            if client_hac_set
                && crate::amounts::parse_zhu(client_hac)?
                    != crate::amounts::parse_zhu(&inv.amount_hac)?
            {
                return Err(format!(
                    "invoice amount mismatch: payment amount_hac '{client_hac}' != invoice '{}'",
                    inv.amount_hac
                ));
            }
            if client_sat != 0 && client_sat != inv.amount_satoshi {
                return Err(format!(
                    "invoice amount mismatch: payment amount_satoshi {client_sat} != invoice {}",
                    inv.amount_satoshi
                ));
            }
            if !req.payee.trim().is_empty() && req.payee.trim() != inv.payee.trim() {
                return Err("invoice payee does not match to".into());
            }
            // Force invoice amounts (cannot underpay)
            req.payee = inv.payee.clone();
            req.amount_hac = inv.amount_hac.clone();
            req.amount_satoshi = inv.amount_satoshi;
        }

        // Namespace idempotency by the hub-authoritative policy principal.
        // Different agents may safely choose the same local retry key.
        let initial_verified_addr = self
            .get_identity(agent_id)
            .and_then(|id| id.verified.then_some(id.address));
        let initial_principal = crate::policy::policy_principal(
            agent_id,
            req.payer.trim(),
            initial_verified_addr.as_deref(),
        );
        let scoped_key = format!("{initial_principal}\u{0}{raw_key}");
        let key = scoped_key.as_str();

        let content_hash = pay_request_fingerprint(
            &req.payer,
            &req.payee,
            &req.amount_hac,
            req.amount_satoshi,
            &req.fee_hac,
            req.local_only,
            &req.route,
            invoice_id,
        );

        // --- Idempotent replay (content-bound) ---
        {
            let g = self.inner.read().map_err(|e| e.to_string())?;
            if let Some(rec) = g.idempotency.get(key) {
                if rec.content_hash != content_hash {
                    return Err(
                        "idempotency_conflict: same key used with different payment parameters"
                            .into(),
                    );
                }
                if let Some(p) = g.payments.get(&rec.payment_id) {
                    return Ok((p.clone(), true));
                }
            }
            // Policy principal: verified → v:address (rotation-proof); else u:agent_id / a:payer
            let verified_addr = g.identities.get(agent_id).and_then(|id| {
                if id.verified {
                    Some(id.address.clone())
                } else {
                    None
                }
            });
            let principal = crate::policy::policy_principal(
                agent_id,
                req.payer.trim(),
                verified_addr.as_deref(),
            );
            let open_for_agent = g
                .payments
                .values()
                .filter(|p| {
                    matches!(
                        p.status,
                        PaymentStatus::Pending | PaymentStatus::CollectingSignatures
                    ) && g
                        .payment_meta
                        .get(&p.id)
                        .map(|m| {
                            crate::policy::meta_matches_principal(
                                &m.agent_id,
                                &m.policy_principal,
                                &m.identity_address,
                                &principal,
                            )
                        })
                        .unwrap_or(false)
                })
                .count() as u32;
            let creates = g.ledger.creates_last_hour(&principal, now);
            crate::policy::check_pay_policy(
                &self.policy,
                agent_id,
                req.payee.trim(),
                req.amount_hac.trim(),
                open_for_agent,
                creates,
            )?;
        }

        // Recompute principal after invoice may have changed payer (stable for ledger write)
        let verified_addr =
            self.get_identity(agent_id)
                .and_then(|id| if id.verified { Some(id.address) } else { None });
        let principal =
            crate::policy::policy_principal(agent_id, req.payer.trim(), verified_addr.as_deref());

        let session = if allow_distributed {
            self.create_distributed_payment(req)?
        } else {
            self.create_payment(req)?
        };
        let mut g = self.inner.write().map_err(|e| e.to_string())?;

        // Double-check after create (race: concurrent same key)
        if let Some(rec) = g.idempotency.get(key) {
            if rec.content_hash != content_hash {
                // Drop orphan session we just created
                g.payments.remove(&session.id);
                g.reservations.remove(&session.id);
                return Err(
                    "idempotency_conflict: same key used with different payment parameters".into(),
                );
            }
            if let Some(p) = g.payments.get(&rec.payment_id) {
                let existing = p.clone();
                if session.id != existing.id {
                    g.payments.remove(&session.id);
                    g.reservations.remove(&session.id);
                }
                return Ok((existing, true));
            }
        }

        prune_idempotency_lru(&mut g.idempotency, 50_000, now);
        g.idempotency.insert(
            key.to_string(),
            IdempotencyRecord {
                payment_id: session.id,
                content_hash,
                created_unix: now,
            },
        );
        let mut meta = sanitize_agent_meta(meta);
        if meta.agent_id.is_empty() {
            meta.agent_id = agent_id.to_string();
        }
        // Hub-authoritative principal (ignore any client-supplied values)
        meta.policy_principal = principal.clone();
        meta.identity_address = verified_addr.unwrap_or_default();
        if let Some(iid) = invoice_id {
            meta.invoice_id = iid.to_string();
            if let Some(inv) = g.invoices.get_mut(&iid) {
                inv.status = crate::invoice::InvoiceStatus::Paying;
                inv.payment_id = Some(session.id);
                inv.updated_unix = now;
            }
        }
        g.payment_meta.insert(session.id, meta);
        if !callback_url.trim().is_empty() {
            g.payment_callbacks
                .insert(session.id, clamp_str(callback_url, 512));
        }
        g.ledger.record_create(&principal, now);
        Ok((session, false))
    }

    /// One consistent persistence view captured under a single state read-lock.
    pub fn export_persist_bundle(&self) -> PersistBundle {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return PersistBundle::default(),
        };
        let channels = g.channels.values().cloned().collect();
        let peers = g
            .peers
            .values()
            .map(|peer| PeerSeed {
                provider_id: peer.provider_id.clone(),
                public_url: peer.public_url.clone(),
                region: peer.meta.region.clone(),
                notes: String::new(),
            })
            .collect();
        let trusted_peers = g
            .peers
            .values()
            .filter(|peer| peer.identity_verified)
            .cloned()
            .collect();
        let bills = g
            .bills
            .values()
            .chain(g.bill_drafts.values())
            .cloned()
            .collect();
        let open_payments: Vec<_> = g
            .payments
            .values()
            .filter(|payment| {
                matches!(
                    payment.status,
                    PaymentStatus::Pending
                        | PaymentStatus::CollectingSignatures
                        | PaymentStatus::Committing
                        | PaymentStatus::Settled
                )
            })
            .cloned()
            .collect();
        let mut settled: Vec<_> = open_payments
            .iter()
            .filter(|payment| payment.status == PaymentStatus::Settled)
            .cloned()
            .collect();
        settled.sort_by(|a, b| b.updated_unix.cmp(&a.updated_unix));
        settled.truncate(500);
        let mut payments: Vec<_> = open_payments
            .into_iter()
            .filter(|payment| {
                matches!(
                    payment.status,
                    PaymentStatus::Pending
                        | PaymentStatus::CollectingSignatures
                        | PaymentStatus::Committing
                )
            })
            .collect();
        payments.extend(settled);
        let payment_ids: HashSet<_> = payments.iter().map(|payment| payment.id).collect();
        let agent = AgentPersistSnapshot {
            payment_meta: g
                .payment_meta
                .iter()
                .filter(|(id, _)| payment_ids.contains(id))
                .map(|(id, meta)| (id.to_string(), meta.clone()))
                .collect(),
            receipts: g
                .receipts
                .values()
                .filter(|receipt| payment_ids.contains(&receipt.payment_id))
                .cloned()
                .collect(),
            invoices: g.invoices.values().cloned().collect(),
            identities: g.identities.values().cloned().collect(),
            idempotency: g
                .idempotency
                .iter()
                .map(|(key, record)| (key.clone(), record.clone()))
                .collect(),
            callbacks: g
                .payment_callbacks
                .iter()
                .filter(|(id, _)| payment_ids.contains(id))
                .map(|(id, url)| (id.to_string(), url.clone()))
                .collect(),
            reservations: g
                .reservations
                .values()
                .filter(|reservation| payment_ids.contains(&reservation.payment_id))
                .cloned()
                .collect(),
            applied_settlements: g.applied_settlements.iter().copied().collect(),
            agent_intents: g.agent_intents.clone(),
            micro_streams: g.micro_streams.values().cloned().collect(),
            escrows: g.escrows.values().cloned().collect(),
            rebalances: g.rebalances.values().cloned().collect(),
            deferred: g.deferred.values().cloned().collect(),
            ledger: g.ledger.clone(),
            payments,
        };
        PersistBundle {
            channels,
            peers,
            trusted_peers,
            bills,
            agent,
            channel_state_observations_v2: self.channel_state_v2.export_observations(),
            channel_state_proofs_v2: self.channel_state_v2.export_proofs(),
            channel_activations_v1: self.channel_state_v2.export_activations(),
        }
    }
    /// Snapshot for persistence (agent recovery after restart).
    pub fn export_agent_persist(&self) -> AgentPersistSnapshot {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(_) => {
                return AgentPersistSnapshot::default();
            }
        };
        let open_payments: Vec<_> = g
            .payments
            .values()
            .filter(|p| {
                matches!(
                    p.status,
                    PaymentStatus::Pending
                        | PaymentStatus::CollectingSignatures
                        | PaymentStatus::Settled
                )
            })
            .cloned()
            .collect();
        // Cap settled retained (newest by updated_unix)
        let mut settled: Vec<_> = open_payments
            .iter()
            .filter(|p| p.status == PaymentStatus::Settled)
            .cloned()
            .collect();
        settled.sort_by(|a, b| b.updated_unix.cmp(&a.updated_unix));
        settled.truncate(500);
        let collecting: Vec<_> = open_payments
            .into_iter()
            .filter(|p| {
                matches!(
                    p.status,
                    PaymentStatus::Pending | PaymentStatus::CollectingSignatures
                )
            })
            .collect();
        let mut payments = collecting;
        payments.extend(settled);

        let payment_ids: std::collections::HashSet<_> = payments.iter().map(|p| p.id).collect();
        let payment_meta: HashMap<_, _> = g
            .payment_meta
            .iter()
            .filter(|(id, _)| payment_ids.contains(id))
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let receipts: Vec<_> = g
            .receipts
            .values()
            .filter(|r| payment_ids.contains(&r.payment_id))
            .cloned()
            .collect();
        let invoices: Vec<_> = g.invoices.values().cloned().collect();
        let identities: Vec<_> = g.identities.values().cloned().collect();
        let idempotency: Vec<(String, IdempotencyRecord)> = g
            .idempotency
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let callbacks: HashMap<String, String> = g
            .payment_callbacks
            .iter()
            .filter(|(id, _)| payment_ids.contains(id))
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        let reservations: Vec<_> = g
            .reservations
            .values()
            .filter(|r| payment_ids.contains(&r.payment_id))
            .cloned()
            .collect();
        let applied_settlements: Vec<_> = g.applied_settlements.iter().copied().collect();
        let agent_intents = g.agent_intents.clone();
        let micro_streams = g.micro_streams.values().cloned().collect();
        let escrows = g.escrows.values().cloned().collect();
        let rebalances = g.rebalances.values().cloned().collect();
        let deferred = g.deferred.values().cloned().collect();
        let ledger = g.ledger.clone();
        AgentPersistSnapshot {
            payments,
            payment_meta: payment_meta
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            receipts,
            invoices,
            identities,
            idempotency,
            callbacks,
            reservations,
            applied_settlements,
            agent_intents,
            micro_streams,
            escrows,
            rebalances,
            deferred,
            ledger,
        }
    }

    pub fn import_agent_persist(&self, snap: AgentPersistSnapshot) -> Result<(), String> {
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        for p in snap.payments {
            g.payments.entry(p.id).or_insert(p);
        }
        for (k, v) in snap.payment_meta {
            if let Ok(id) = Uuid::parse_str(&k) {
                g.payment_meta.entry(id).or_insert(v);
            }
        }
        for r in snap.receipts {
            g.receipts.entry(r.payment_id).or_insert(r);
        }
        for inv in snap.invoices {
            g.invoices.entry(inv.id).or_insert(inv);
        }
        for id in snap.identities {
            g.identities.entry(id.agent_id.clone()).or_insert(id);
        }
        for (k, rec) in snap.idempotency {
            g.idempotency.entry(k).or_insert(rec);
        }
        for stream in snap.micro_streams {
            g.micro_streams.entry(stream.id).or_insert(stream);
        }
        for escrow in snap.escrows {
            g.escrows.entry(escrow.id).or_insert(escrow);
        }
        for rebalance in snap.rebalances {
            g.rebalances.entry(rebalance.id).or_insert(rebalance);
        }
        for deferred in snap.deferred {
            g.deferred.entry(deferred.id).or_insert(deferred);
        }
        for (k, url) in snap.callbacks {
            if let Ok(id) = Uuid::parse_str(&k) {
                g.payment_callbacks.entry(id).or_insert(url);
            }
        }
        for reservation in snap.reservations {
            if g.payments.contains_key(&reservation.payment_id) {
                g.reservations
                    .entry(reservation.payment_id)
                    .or_insert(reservation);
            }
        }
        g.applied_settlements.extend(snap.applied_settlements);
        let now = now_unix();
        g.agent_intents.extend(
            snap.agent_intents
                .into_iter()
                .filter(|(_, used)| used.expires_unix >= now),
        );
        let mut ledger = snap.ledger;
        for entry in ledger.by_agent.values_mut() {
            entry
                .recent_creates
                .retain(|created| now.saturating_sub(*created) <= 3600);
        }
        g.ledger = ledger;
        Ok(())
    }

    pub fn get_payment_callback(&self, id: Uuid) -> Option<String> {
        self.inner
            .read()
            .ok()
            .and_then(|g| g.payment_callbacks.get(&id).cloned())
    }

    // --- Invoices ---

    pub fn create_invoice(
        &self,
        req: crate::invoice::CreateInvoiceRequest,
    ) -> Result<crate::invoice::Invoice, String> {
        let invoice_agent = req.meta.agent_id.trim();
        if !invoice_agent.is_empty() {
            if let Some(identity) = self.get_identity(invoice_agent) {
                if identity.revoked {
                    return Err("agent identity revoked".into());
                }
                if identity.verified && !identity.allows("invoice") {
                    return Err("agent identity lacks 'invoice' scope".into());
                }
            }
        }
        if req.payee.trim().is_empty() {
            return Err("payee required".into());
        }
        if req.amount_hac.trim().is_empty() && req.amount_satoshi == 0 {
            return Err("amount_hac or amount_satoshi required".into());
        }
        let now = now_unix();
        let ttl = if req.ttl_secs == 0 {
            3600
        } else {
            req.ttl_secs.min(7 * 24 * 3600)
        };
        let inv = crate::invoice::Invoice {
            id: Uuid::new_v4(),
            status: crate::invoice::InvoiceStatus::Open,
            payee: clamp_str(req.payee.trim(), 128),
            payer_hint: clamp_str(req.payer_hint.trim(), 128),
            amount_hac: clamp_str(&req.amount_hac, 64),
            amount_satoshi: req.amount_satoshi,
            description: clamp_str(&req.description, 256),
            meta: sanitize_agent_meta(req.meta),
            created_unix: now,
            expires_unix: now.saturating_add(ttl),
            updated_unix: now,
            payment_id: None,
            callback_url: clamp_str(req.callback_url.trim(), 512),
        };
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        if g.invoices.len() >= 20_000 {
            // drop oldest cancelled/expired
            let drop: Vec<Uuid> = g
                .invoices
                .iter()
                .filter(|(_, i)| {
                    matches!(
                        i.status,
                        crate::invoice::InvoiceStatus::Cancelled
                            | crate::invoice::InvoiceStatus::Expired
                            | crate::invoice::InvoiceStatus::Paid
                    )
                })
                .map(|(id, _)| *id)
                .take(1000)
                .collect();
            for id in drop {
                g.invoices.remove(&id);
            }
        }
        g.invoices.insert(inv.id, inv.clone());
        Ok(inv)
    }

    pub fn get_invoice(&self, id: Uuid) -> Option<crate::invoice::Invoice> {
        self.inner
            .read()
            .ok()
            .and_then(|g| g.invoices.get(&id).cloned())
    }

    pub fn list_invoices_for(&self, address: &str, limit: usize) -> Vec<crate::invoice::Invoice> {
        let addr = address.trim();
        let mut list: Vec<_> = self
            .inner
            .read()
            .map(|g| {
                g.invoices
                    .values()
                    .filter(|i| i.payee == addr || i.payer_hint == addr)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        list.sort_by(|a, b| b.created_unix.cmp(&a.created_unix));
        list.truncate(limit.max(1).min(200));
        list
    }

    pub fn cancel_invoice(
        &self,
        id: Uuid,
        by_address: &str,
    ) -> Result<crate::invoice::Invoice, String> {
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let inv = g
            .invoices
            .get_mut(&id)
            .ok_or_else(|| format!("invoice {id} not found"))?;
        if inv.payee != by_address.trim() {
            return Err("only payee can cancel invoice".into());
        }
        if !matches!(
            inv.status,
            crate::invoice::InvoiceStatus::Open | crate::invoice::InvoiceStatus::Paying
        ) {
            return Err(format!("cannot cancel invoice in {:?}", inv.status));
        }
        inv.status = crate::invoice::InvoiceStatus::Cancelled;
        inv.updated_unix = now_unix();
        Ok(inv.clone())
    }

    pub fn mark_invoice_paid_for_payment(&self, payment_id: Uuid) {
        if let Ok(mut g) = self.inner.write() {
            let inv_id = g
                .invoices
                .iter()
                .find(|(_, i)| i.payment_id == Some(payment_id))
                .map(|(id, _)| *id);
            if let Some(id) = inv_id {
                if let Some(inv) = g.invoices.get_mut(&id) {
                    inv.status = crate::invoice::InvoiceStatus::Paid;
                    inv.updated_unix = now_unix();
                }
            }
            if let Some(meta) = g.payment_meta.get(&payment_id) {
                let aid = meta.agent_id.clone();
                g.ledger.record_settled(&aid);
            }
        }
    }

    pub fn ledger_snapshot(&self) -> Vec<crate::policy::AgentLedgerEntry> {
        self.inner
            .read()
            .map(|g| g.ledger.snapshot())
            .unwrap_or_default()
    }

    // --- Agent identity ---

    pub fn register_identity(
        &self,
        req: crate::agent_id::RegisterIdentityRequest,
    ) -> Result<crate::agent_id::AgentIdentity, String> {
        let agent_id = clamp_str(req.agent_id.trim(), 64);
        if agent_id.is_empty() || agent_id.contains(' ') {
            return Err("agent_id required (no spaces)".into());
        }
        let address = crate::agent_id::address_from_pubkey_hex(&req.public_key_hex)?;
        let now = now_unix();
        let mut id = crate::agent_id::AgentIdentity {
            agent_id: agent_id.clone(),
            public_key_hex: req
                .public_key_hex
                .trim()
                .trim_start_matches("0x")
                .to_lowercase(),
            address,
            registered_unix: now,
            verified: false,
            verified_unix: 0,
            label: clamp_str(&req.label, 64),
            contact: clamp_str(&req.contact, 128),
            scopes: vec!["pay".into()],
            revoked: false,
            revoked_unix: 0,
        };
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        if let Some(old) = g.identities.get(&agent_id) {
            if old.public_key_hex != id.public_key_hex && old.verified {
                return Err("agent_id already verified with different key".into());
            }
            id.verified = old.verified;
            id.verified_unix = old.verified_unix;
            id.registered_unix = old.registered_unix;
            id.scopes = old.scopes.clone();
            id.revoked = old.revoked;
            id.revoked_unix = old.revoked_unix;
        }
        g.identities.insert(agent_id, id.clone());
        Ok(id)
    }

    pub fn get_identity(&self, agent_id: &str) -> Option<crate::agent_id::AgentIdentity> {
        self.inner
            .read()
            .ok()
            .and_then(|g| g.identities.get(agent_id).cloned())
    }

    pub fn list_identities(&self) -> Vec<crate::agent_id::AgentIdentity> {
        self.inner
            .read()
            .map(|g| g.identities.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn issue_identity_challenge(
        &self,
        agent_id: &str,
    ) -> Result<crate::agent_id::IdentityChallenge, String> {
        let id = {
            let g = self.inner.read().map_err(|e| e.to_string())?;
            g.identities
                .get(agent_id)
                .cloned()
                .ok_or_else(|| "register identity first".to_string())?
        };
        if id.revoked {
            return Err("agent identity revoked".into());
        }
        let now = now_unix();
        let challenge_id = Uuid::new_v4();
        let expires = now + 300;
        let message = crate::agent_id::challenge_message(
            &id.agent_id,
            challenge_id,
            &self.provider_id,
            expires,
        );
        let message_hash_hex = crate::agent_id::challenge_hash_hex(&message);
        let ch = crate::agent_id::IdentityChallenge {
            agent_id: id.agent_id,
            challenge_id,
            message,
            message_hash_hex,
            expires_unix: expires,
        };
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        // prune old challenges
        let drop: Vec<Uuid> = g
            .challenges
            .iter()
            .filter(|(_, c)| c.expires_unix < now)
            .map(|(id, _)| *id)
            .collect();
        for d in drop {
            g.challenges.remove(&d);
        }
        g.challenges.insert(challenge_id, ch.clone());
        Ok(ch)
    }

    pub fn verify_identity(
        &self,
        req: crate::agent_id::VerifyIdentityRequest,
    ) -> Result<crate::agent_id::AgentIdentity, String> {
        let cid = Uuid::parse_str(req.challenge_id.trim())
            .map_err(|_| "invalid challenge_id".to_string())?;
        let now = now_unix();
        let (ch, address, pk) = {
            let g = self.inner.read().map_err(|e| e.to_string())?;
            let ch = g
                .challenges
                .get(&cid)
                .cloned()
                .ok_or_else(|| "challenge not found".to_string())?;
            if ch.agent_id != req.agent_id.trim() {
                return Err("agent_id mismatch".into());
            }
            if ch.expires_unix < now {
                return Err("challenge expired".into());
            }
            let id = g
                .identities
                .get(&ch.agent_id)
                .cloned()
                .ok_or_else(|| "identity not registered".to_string())?;
            if id.revoked {
                return Err("agent identity revoked".into());
            }
            (ch, id.address, id.public_key_hex)
        };
        let pk_opt = if req.public_key_hex.trim().is_empty() {
            Some(pk.as_str())
        } else {
            Some(req.public_key_hex.trim())
        };
        crate::agent_id::verify_challenge_sig(
            &ch.message_hash_hex,
            &address,
            &req.signature_hex,
            pk_opt,
        )?;
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        g.challenges.remove(&cid);
        let id = g
            .identities
            .get_mut(&req.agent_id)
            .ok_or_else(|| "identity missing".to_string())?;
        id.verified = true;
        id.verified_unix = now;
        Ok(id.clone())
    }

    // --- Micropayment streams ---

    pub fn set_identity_scopes(
        &self,
        agent_id: &str,
        scopes: &[String],
    ) -> Result<crate::agent_id::AgentIdentity, String> {
        let normalized = crate::agent_id::normalize_scopes(scopes)?;
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let identity = g
            .identities
            .get_mut(agent_id.trim())
            .ok_or_else(|| "identity not found".to_string())?;
        if identity.revoked {
            return Err("agent identity revoked".into());
        }
        identity.scopes = normalized;
        Ok(identity.clone())
    }

    pub fn revoke_identity(
        &self,
        agent_id: &str,
    ) -> Result<crate::agent_id::AgentIdentity, String> {
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let identity = g
            .identities
            .get_mut(agent_id.trim())
            .ok_or_else(|| "identity not found".to_string())?;
        identity.revoked = true;
        identity.revoked_unix = now_unix();
        let revoked_agent = identity.agent_id.clone();
        let result = identity.clone();
        g.challenges
            .retain(|_, challenge| challenge.agent_id != revoked_agent);
        Ok(result)
    }

    pub fn open_micro_stream(
        &self,
        req: crate::micro::OpenMicroRequest,
    ) -> Result<crate::micro::MicroStream, String> {
        let stream_agent = if req.agent_id.trim().is_empty() {
            req.meta.agent_id.trim()
        } else {
            req.agent_id.trim()
        };
        if !stream_agent.is_empty() {
            if let Some(identity) = self.get_identity(stream_agent) {
                if identity.revoked {
                    return Err("agent identity revoked".into());
                }
                if identity.verified && !identity.allows("micro") {
                    return Err("agent identity lacks 'micro' scope".into());
                }
            }
        }
        if req.payer.trim().is_empty() || req.payee.trim().is_empty() {
            return Err("payer and payee required".into());
        }
        let max_hac_zhu = if req.max_hac_zhu > 0 {
            req.max_hac_zhu
        } else {
            req.max_hac_mei
                .checked_mul(crate::amounts::ZHU_PER_MEI)
                .ok_or("max_hac_mei exceeds the L2 u64 Zhu range")?
        };
        if max_hac_zhu == 0 && req.max_satoshi == 0 {
            return Err("set max_hac_zhu, max_hac_mei and/or max_satoshi".into());
        }
        let now = now_unix();
        let mut s = crate::micro::MicroStream {
            id: Uuid::new_v4(),
            status: crate::micro::MicroStreamStatus::Open,
            payer: clamp_str(req.payer.trim(), 128),
            payee: clamp_str(req.payee.trim(), 128),
            max_hac_mei: req.max_hac_mei,
            max_hac_zhu,
            max_satoshi: req.max_satoshi,
            spent_hac_mei: 0,
            spent_hac_zhu: 0,
            spent_satoshi: 0,
            sequence: 0,
            create_payments: req.create_payments,
            local_only: req.local_only,
            agent_id: clamp_str(&req.agent_id, 64),
            meta: sanitize_agent_meta(req.meta),
            created_unix: now,
            updated_unix: now,
            entries: vec![],
            last_state_hash_hex: String::new(),
            last_signatures: vec![],
        };
        let msg = crate::micro::stream_state_message(&s);
        s.last_state_hash_hex = hex::encode(crate::hacash_keys::sha3(msg.as_bytes()));
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        if g.micro_streams.len() >= 10_000 {
            return Err("too many micro streams".into());
        }
        g.micro_streams.insert(s.id, s.clone());
        Ok(s)
    }

    pub fn get_micro_stream(&self, id: Uuid) -> Option<crate::micro::MicroStream> {
        self.inner
            .read()
            .ok()
            .and_then(|g| g.micro_streams.get(&id).cloned())
    }

    pub fn list_micro_streams(&self, address: &str) -> Vec<crate::micro::MicroStream> {
        let addr = address.trim();
        self.inner
            .read()
            .map(|g| {
                g.micro_streams
                    .values()
                    .filter(|s| s.payer == addr || s.payee == addr)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Push a micropayment. Optionally creates a real HAP payment.
    /// Sequence is reserved under write lock to avoid concurrent double-push races.
    pub fn push_micro(
        &self,
        req: crate::micro::PushMicroRequest,
    ) -> Result<(crate::micro::MicroStream, Option<PaymentSession>), String> {
        let sid =
            Uuid::parse_str(req.stream_id.trim()).map_err(|_| "invalid stream_id".to_string())?;
        let amount = crate::amounts::AmountInput {
            amount_hac: req.amount_hac.clone(),
            amount_satoshi: req.amount_satoshi,
            amount_mei: req.amount_mei,
            satoshi: req.satoshi,
            mei: 0,
        }
        .resolve()?;
        if amount.is_zero() {
            return Err("amount required (satoshi and/or HAC)".into());
        }
        let zhu = amount.hac_zhu;
        let sats = amount.amount_satoshi;

        // Reserve sequence + validate under exclusive lock, then release for crypto/pay
        let (payer, payee, sequence, create_payments, local_only, agent_id) = {
            let mut g = self.inner.write().map_err(|e| e.to_string())?;
            let s = g
                .micro_streams
                .get_mut(&sid)
                .ok_or_else(|| "stream not found".to_string())?;
            if s.status != crate::micro::MicroStreamStatus::Open {
                return Err("stream closed".into());
            }
            if s.spent_hac_zhu
                .checked_add(zhu)
                .ok_or("micro HAC spend overflow")?
                > s.max_hac_zhu
                && zhu > 0
            {
                return Err("exceeds max_hac_zhu".into());
            }
            if s.spent_satoshi.saturating_add(sats) > s.max_satoshi && sats > 0 {
                return Err("exceeds max_satoshi".into());
            }
            // Reserve sequence slot immediately (prevents concurrent same sequence)
            let sequence = s.sequence + 1;
            s.sequence = sequence;
            // Tentative spend; rolled back on later failure via compensating subtract
            s.spent_hac_zhu = s
                .spent_hac_zhu
                .checked_add(zhu)
                .ok_or("micro HAC spend overflow")?;
            s.spent_hac_mei = s.spent_hac_zhu / crate::amounts::ZHU_PER_MEI;
            s.spent_satoshi = s.spent_satoshi.saturating_add(sats);
            (
                s.payer.clone(),
                s.payee.clone(),
                sequence,
                s.create_payments,
                s.local_only,
                s.agent_id.clone(),
            )
        };

        let commit_msg =
            crate::micro::push_commit_message(sid, sequence, &payer, &payee, &amount, &req.note);
        let commit_hash = hex::encode(crate::hacash_keys::sha3(commit_msg.as_bytes()));

        let sig_result = if self.limits.require_sig_verify {
            if req.signature_hex.trim().is_empty() {
                Err("signature_hex required for micro push (payer signs commit)".to_string())
            } else {
                let bytes = hex::decode(&commit_hash).map_err(|e| e.to_string());
                match bytes {
                    Ok(b) if b.len() == 32 => {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&b);
                        let pk = if req.public_key_hex.is_empty() {
                            None
                        } else {
                            Some(req.public_key_hex.as_str())
                        };
                        crate::crypto::verify_payment_signature(
                            &hash,
                            &payer,
                            &req.signature_hex,
                            pk,
                        )
                        .map(|_| ())
                    }
                    Ok(_) => Err("commit hash corrupt".into()),
                    Err(e) => Err(e),
                }
            }
        } else {
            Ok(())
        };

        if let Err(e) = sig_result {
            // Rollback reservation
            if let Ok(mut g) = self.inner.write() {
                if let Some(s) = g.micro_streams.get_mut(&sid) {
                    if s.sequence == sequence {
                        s.sequence = sequence.saturating_sub(1);
                        s.spent_hac_zhu = s.spent_hac_zhu.saturating_sub(zhu);
                        s.spent_hac_mei = s.spent_hac_zhu / crate::amounts::ZHU_PER_MEI;
                        s.spent_satoshi = s.spent_satoshi.saturating_sub(sats);
                    }
                }
            }
            return Err(e);
        }

        let mut payment_session = None;
        if create_payments {
            let (hac, sat) = amount.for_payment();
            let idem = if req.idempotency_key.trim().is_empty() {
                format!("micro-{sid}-{sequence}")
            } else {
                req.idempotency_key.trim().to_string()
            };
            let meta = crate::agent_pay::AgentPaymentMeta {
                agent_id: agent_id.clone(),
                purpose: format!("micro_stream_{sid}"),
                invoice_id: String::new(),
                skill: "micropay".into(),
                conversation_id: sid.to_string(),
                extra: clamp_str(&req.note, 256),
                ..Default::default()
            };
            match self.agent_create_payment_ex(
                CreatePaymentRequest {
                    payer: payer.clone(),
                    payee: payee.clone(),
                    amount_hac: hac,
                    amount_satoshi: sat,
                    fee_hac: "0".into(),
                    route: vec![],
                    local_only,
                },
                &idem,
                meta,
                None,
                "",
            ) {
                Ok((p, _)) => payment_session = Some(p),
                Err(e) => {
                    if let Ok(mut g) = self.inner.write() {
                        if let Some(s) = g.micro_streams.get_mut(&sid) {
                            if s.sequence == sequence {
                                s.sequence = sequence.saturating_sub(1);
                                s.spent_hac_zhu = s.spent_hac_zhu.saturating_sub(zhu);
                                s.spent_hac_mei = s.spent_hac_zhu / crate::amounts::ZHU_PER_MEI;
                                s.spent_satoshi = s.spent_satoshi.saturating_sub(sats);
                            }
                        }
                    }
                    return Err(e);
                }
            }
        }

        let now = now_unix();
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let s = g
            .micro_streams
            .get_mut(&sid)
            .ok_or_else(|| "stream missing".to_string())?;
        // sequence + spent already applied; just record entry
        s.updated_unix = now;
        let entry = crate::micro::MicroEntry {
            sequence,
            amount_hac: amount.amount_hac.clone(),
            amount_satoshi: sats,
            note: clamp_str(&req.note, 256),
            created_unix: now,
            payment_id: payment_session.as_ref().map(|p| p.id),
            signature_hex: req.signature_hex.trim().to_lowercase(),
        };
        s.entries.push(entry);
        if s.entries.len() > 100 {
            let skip = s.entries.len() - 100;
            s.entries = s.entries.split_off(skip);
        }
        let state_msg = crate::micro::stream_state_message(s);
        s.last_state_hash_hex = hex::encode(crate::hacash_keys::sha3(state_msg.as_bytes()));
        let out = s.clone();
        Ok((out, payment_session))
    }

    pub fn close_micro_stream(
        &self,
        id: Uuid,
        by_address: &str,
    ) -> Result<crate::micro::MicroStream, String> {
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let s = g
            .micro_streams
            .get_mut(&id)
            .ok_or_else(|| "stream not found".to_string())?;
        let by = by_address.trim();
        if s.payer != by && s.payee != by {
            return Err("only stream parties can close".into());
        }
        s.status = crate::micro::MicroStreamStatus::Closed;
        s.updated_unix = now_unix();
        let msg = crate::micro::stream_state_message(s);
        s.last_state_hash_hex = hex::encode(crate::hacash_keys::sha3(msg.as_bytes()));
        Ok(s.clone())
    }

    pub fn cancel_payment(&self, id: Uuid, by_address: &str) -> Result<PaymentSession, String> {
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let p = g
            .payments
            .get_mut(&id)
            .ok_or_else(|| format!("payment {id} not found"))?;
        if !matches!(
            p.status,
            PaymentStatus::Pending | PaymentStatus::CollectingSignatures
        ) {
            return Err(format!("cannot cancel payment in {:?}", p.status));
        }
        let by = by_address.trim();
        if p.payer != by && p.payee != by && !p.required_signers.iter().any(|s| s == by) {
            return Err("only a party on the payment may cancel".into());
        }
        p.status = PaymentStatus::Failed;
        p.last_error = Some(format!("cancelled by {by}"));
        p.updated_unix = now_unix();
        let out = p.clone();
        g.reservations.remove(&id);
        if let Some(meta) = g.payment_meta.get(&id) {
            let aid = meta.agent_id.clone();
            g.ledger.record_failed(&aid);
        }
        Ok(out)
    }

    pub fn get_payment_meta(&self, id: Uuid) -> crate::agent_pay::AgentPaymentMeta {
        self.inner
            .read()
            .ok()
            .and_then(|g| g.payment_meta.get(&id).cloned())
            .unwrap_or_default()
    }

    pub fn all_payment_metas(&self) -> HashMap<Uuid, crate::agent_pay::AgentPaymentMeta> {
        self.inner
            .read()
            .map(|g| g.payment_meta.clone())
            .unwrap_or_default()
    }

    /// After settle (or terminal fail), store receipt if not present.
    pub fn ensure_receipt(&self, id: Uuid) -> Option<crate::agent_pay::PaymentReceipt> {
        let p = self.get_payment(id)?;
        if !matches!(
            p.status,
            PaymentStatus::Settled | PaymentStatus::Failed | PaymentStatus::TimedOut
        ) {
            return None;
        }
        {
            let g = self.inner.read().ok()?;
            if let Some(r) = g.receipts.get(&id) {
                return Some(r.clone());
            }
        }
        let meta = self.get_payment_meta(id);
        let mut receipt = crate::agent_pay::build_receipt(&p, &self.provider_id, meta);
        if let Some(ref acc) = self.hub_identity {
            crate::agent_pay::sign_receipt_with_hub(&mut receipt, acc);
        }
        if let Ok(mut g) = self.inner.write() {
            g.receipts.insert(id, receipt.clone());
        }
        Some(receipt)
    }

    pub fn get_receipt(&self, id: Uuid) -> Option<crate::agent_pay::PaymentReceipt> {
        if let Some(r) = self
            .inner
            .read()
            .ok()
            .and_then(|g| g.receipts.get(&id).cloned())
        {
            return Some(r);
        }
        self.ensure_receipt(id)
    }

    /// Rebuild commit from a stored session (for GET /message).
    pub fn payment_commit(session: &PaymentSession, provider_id: &str) -> PaymentCommit {
        PaymentCommit {
            session_id: session.id.to_string(),
            provider_id: provider_id.to_string(),
            payer: session.payer.clone(),
            payee: session.payee.clone(),
            amount_hac: session.amount_hac.clone(),
            amount_satoshi: session.amount_satoshi,
            fee_hac: session.fee_hac.clone(),
            route: session.route.clone(),
            required_signers: session.required_signers.clone(),
            created_unix: session.created_unix,
        }
    }

    pub fn get_payment(&self, id: Uuid) -> Option<PaymentSession> {
        self.inner
            .read()
            .ok()
            .and_then(|g| g.payments.get(&id).cloned())
    }

    pub fn list_payments(&self, limit: usize) -> Vec<PaymentSession> {
        let mut list: Vec<_> = self
            .inner
            .read()
            .map(|g| g.payments.values().cloned().collect())
            .unwrap_or_default();
        list.sort_by(|a, b| b.created_unix.cmp(&a.created_unix));
        list.truncate(limit.max(1).min(500));
        list
    }

    /// Channels where address is left or right.
    pub fn channels_for_address(&self, address: &str) -> Vec<LocalChannel> {
        let addr = address.trim();
        self.list_channels()
            .into_iter()
            .filter(|c| c.left_address == addr || c.right_address == addr)
            .collect()
    }

    /// Bills involving address.
    pub fn bills_for_address(&self, address: &str) -> Vec<crate::types::ChannelBill> {
        let addr = address.trim();
        self.list_bills()
            .into_iter()
            .filter(|b| b.left_address == addr || b.right_address == addr)
            .collect()
    }

    /// Payments involving address as payer, payee, or required signer.
    pub fn payments_for_address(&self, address: &str, limit: usize) -> Vec<PaymentSession> {
        let addr = address.trim();
        let mut list: Vec<_> = self
            .list_payments(500)
            .into_iter()
            .filter(|p| {
                p.payer == addr || p.payee == addr || p.required_signers.iter().any(|s| s == addr)
            })
            .collect();
        list.truncate(limit.max(1).min(200));
        list
    }

    /// Restore a coordinator payment from the hash-chained transaction journal
    /// when the general snapshot was lost before the prepare acknowledgement.
    pub fn restore_distributed_payment(&self, payment: PaymentSession) -> Result<(), String> {
        self.restore_distributed_payment_inner(payment, false)
    }

    /// Reconcile the coordinator payment with the image fsynced together with
    /// an irreversible commit decision. This image is newer than a periodic
    /// snapshot and contains the complete verified signature set.
    pub fn restore_distributed_commit_payment(
        &self,
        payment: PaymentSession,
    ) -> Result<(), String> {
        self.restore_distributed_payment_inner(payment, true)
    }

    fn restore_distributed_payment_inner(
        &self,
        payment: PaymentSession,
        commit_decision_is_authoritative: bool,
    ) -> Result<(), String> {
        if payment.remote_hops.is_empty() {
            return Err("journal recovery payment is not cross-hub".into());
        }
        if matches!(
            payment.status,
            PaymentStatus::Settled | PaymentStatus::Failed | PaymentStatus::TimedOut
        ) {
            return Err("journal recovery image has an invalid terminal status".into());
        }
        let commit = Self::payment_commit(&payment, &self.provider_id);
        let expected_message = canonical_message(&commit);
        let expected_hash = message_hash_hex(&commit);
        if payment.message != expected_message || payment.message_hash_hex != expected_hash {
            return Err("journal payment recovery image failed canonical hash validation".into());
        }
        if commit_decision_is_authoritative {
            let has_every_signature = payment.required_signers.iter().all(|required| {
                payment
                    .signatures
                    .iter()
                    .any(|signature| signature.address == *required && signature.verified)
            });
            if payment.status != PaymentStatus::Committing || !has_every_signature {
                return Err(
                    "durable commit payment image lacks its complete verified authorization".into(),
                );
            }
        }
        let mut state = self.inner.write().map_err(|error| error.to_string())?;
        if let Some(existing_hash) = state
            .payments
            .get(&payment.id)
            .map(|existing| existing.message_hash_hex.clone())
        {
            if existing_hash != payment.message_hash_hex {
                return Err("payment id conflicts with journal recovery image".into());
            }
            if commit_decision_is_authoritative {
                state.payments.insert(payment.id, payment);
            }
            return Ok(());
        }
        if state.payments.len() >= self.limits.max_payment_sessions {
            return Err("payment state is full during journal recovery".into());
        }
        state.payments.insert(payment.id, payment);
        Ok(())
    }

    pub fn payment_reservation(&self, id: Uuid) -> Option<PaymentReservation> {
        self.inner
            .read()
            .ok()
            .and_then(|state| state.reservations.get(&id).cloned())
    }

    /// Reserve participant-owned hops. Replaying an identical prepare is safe.
    pub fn prepare_distributed_reservation(
        &self,
        tx_id: Uuid,
        amount_zhu: u64,
        amount_satoshi: u64,
        hops: &[ReservedHop],
        expires_unix: u64,
    ) -> Result<(), String> {
        if hops.len() > self.limits.max_hops {
            return Err(format!(
                "distributed participant hops exceed max {}",
                self.limits.max_hops
            ));
        }
        let mut seen = HashSet::new();
        for hop in hops {
            let normalized = normalize_channel_id(&hop.channel_id)?;
            if normalized != hop.channel_id {
                return Err("distributed hop channel id is not normalized".into());
            }
            if !seen.insert(normalized) {
                return Err("distributed transaction repeats a local channel".into());
            }
            if hop.from_address.trim().is_empty()
                || hop.to_address.trim().is_empty()
                || hop.from_address == hop.to_address
            {
                return Err("distributed hop direction is invalid".into());
            }
        }
        let reservation = PaymentReservation {
            payment_id: tx_id,
            amount_zhu,
            amount_satoshi,
            hops: hops.to_vec(),
            created_unix: now_unix(),
            expires_unix,
        };
        let mut state = self.inner.write().map_err(|error| error.to_string())?;
        if state.applied_settlements.contains(&tx_id) {
            return Ok(());
        }
        if let Some(existing) = state.reservations.get(&tx_id) {
            if existing.amount_zhu == reservation.amount_zhu
                && existing.amount_satoshi == reservation.amount_satoshi
                && existing.hops == reservation.hops
                && existing.expires_unix == reservation.expires_unix
            {
                return Ok(());
            }
            return Err("transaction id already has a different reservation".into());
        }
        reserve_payment_liquidity(&mut state, reservation)
    }

    pub fn release_distributed_reservation(&self, tx_id: Uuid) {
        if let Ok(mut state) = self.inner.write() {
            if !state.applied_settlements.contains(&tx_id) {
                state.reservations.remove(&tx_id);
            }
        }
    }

    /// Apply only this hub's prepared channel hops. The transaction id is the
    /// exactly-once key and the live ledger is updated only after full preflight.
    pub fn apply_distributed_settlement(
        &self,
        tx_id: Uuid,
        amount_zhu: u64,
        amount_satoshi: u64,
        hops: &[ReservedHop],
    ) -> Result<Vec<String>, String> {
        let mut state = self.inner.write().map_err(|error| error.to_string())?;
        apply_distributed_reserved_settlement(&mut state, tx_id, amount_zhu, amount_satoshi, hops)
    }

    pub fn mark_distributed_committing(
        &self,
        tx_id: Uuid,
        detail: &str,
    ) -> Result<PaymentSession, String> {
        let mut state = self.inner.write().map_err(|error| error.to_string())?;
        let payment = state
            .payments
            .get_mut(&tx_id)
            .ok_or_else(|| format!("payment {tx_id} not found"))?;
        if payment.status != PaymentStatus::Settled {
            payment.status = PaymentStatus::Committing;
            payment.finality = "distributed_2pc_commit_decided_not_l1".into();
            payment.last_error = Some(clamp_str(detail, 256));
            payment.updated_unix = now_unix();
        }
        Ok(payment.clone())
    }

    pub fn mark_distributed_settled(&self, tx_id: Uuid) -> Result<PaymentSession, String> {
        let output = {
            let mut state = self.inner.write().map_err(|error| error.to_string())?;
            if !state.applied_settlements.contains(&tx_id) {
                return Err("cannot settle before local durable commit application".into());
            }
            let payment = state
                .payments
                .get_mut(&tx_id)
                .ok_or_else(|| format!("payment {tx_id} not found"))?;
            payment.status = PaymentStatus::Settled;
            payment.finality = "distributed_2pc_committed_not_l1".into();
            payment.last_error = None;
            payment.updated_unix = now_unix();
            payment.clone()
        };
        let _ = self.ensure_receipt(tx_id);
        self.mark_invoice_paid_for_payment(tx_id);
        let _ = self.auto_bill_after_settle(&output);
        Ok(output)
    }

    pub fn add_signature(
        &self,
        id: Uuid,
        req: SignPaymentRequest,
    ) -> Result<PaymentSession, String> {
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let p = g
            .payments
            .get_mut(&id)
            .ok_or_else(|| format!("payment {id} not found"))?;
        // Expire on access if TTL elapsed.
        if is_expired(p, now_unix()) {
            p.status = PaymentStatus::TimedOut;
            p.last_error = Some("payment session expired (TTL)".into());
            p.updated_unix = now_unix();
            g.reservations.remove(&id);
            return Err("payment timed out; create a new session".into());
        }
        if !matches!(
            p.status,
            PaymentStatus::Pending | PaymentStatus::CollectingSignatures
        ) {
            return Err(format!("payment is {:?}; cannot add signatures", p.status));
        }
        if req.address.trim().is_empty() || req.signature_hex.trim().is_empty() {
            return Err("address and signature_hex required".into());
        }
        let sig = req.signature_hex.trim();
        let addr = clamp_str(req.address.trim(), 128);
        let order_index = p
            .required_signers
            .iter()
            .position(|s| s == &addr)
            .ok_or_else(|| {
                format!(
                    "address {addr} is not a required signer for this payment (need {:?})",
                    p.required_signers
                )
            })?;

        // Ordered multi-sig: must sign in order (payee first … payer last).
        for (i, signer) in p.required_signers.iter().enumerate() {
            if i >= order_index {
                break;
            }
            if !p.signatures.iter().any(|s| &s.address == signer) {
                return Err(format!(
                    "signature order violated: {signer} must sign before {addr} (index {i} < {order_index})"
                ));
            }
        }

        // Phase B: cryptographic verification against session message_hash.
        let mut verified = false;
        let mut public_key_hex = req.public_key_hex.trim().to_string();
        if self.limits.require_sig_verify {
            let hash_hex = p.message_hash_hex.clone();
            if hash_hex.len() != 64 {
                return Err("payment missing message_hash_hex (internal error)".into());
            }
            let hash_bytes =
                hex::decode(&hash_hex).map_err(|e| format!("message_hash_hex corrupt: {e}"))?;
            let mut hash = [0u8; 32];
            if hash_bytes.len() != 32 {
                return Err("message_hash_hex must be 32 bytes".into());
            }
            hash.copy_from_slice(&hash_bytes);
            let pk_opt = if public_key_hex.is_empty() {
                None
            } else {
                Some(public_key_hex.as_str())
            };
            let parsed = verify_payment_signature(&hash, &addr, sig, pk_opt)?;
            public_key_hex = hex::encode(parsed.public_key);
            verified = true;
        } else {
            // Soft shape check only (dev / --no-sig-verify).
            let cleaned = sig.trim_start_matches("0x");
            if cleaned.len() < 8
                || cleaned.len() > 400
                || !cleaned.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err("signature_hex must be hex, 8..=400 chars".into());
            }
        }

        // Normalize stored signature: keep original packed form when 97 bytes.
        let store_sig = sig.trim_start_matches("0x").to_lowercase();

        p.signatures.retain(|s| s.address != addr);
        p.signatures.push(PaymentSignature {
            address: addr,
            signature_hex: store_sig,
            public_key_hex,
            signed_unix: now_unix(),
            order_index,
            verified,
        });
        p.status = PaymentStatus::CollectingSignatures;
        p.updated_unix = now_unix();
        p.finality = "hub_coordinated_not_l1".into();

        let all_signed = p
            .required_signers
            .iter()
            .all(|need| p.signatures.iter().any(|s| &s.address == need));
        if all_signed && self.limits.require_sig_verify && !p.signatures.iter().all(|s| s.verified)
        {
            return Err("internal: not all signatures verified".into());
        }
        let settlement_candidate = all_signed.then(|| p.clone());
        if let Some(candidate) = settlement_candidate {
            if !candidate.remote_hops.is_empty() {
                let payment = g
                    .payments
                    .get_mut(&id)
                    .ok_or_else(|| "payment disappeared before distributed commit".to_string())?;
                payment.status = PaymentStatus::Committing;
                payment.finality = "distributed_2pc_commit_pending_not_l1".into();
                payment.last_error = None;
                payment.updated_unix = now_unix();
            } else {
                if let Err(e) = apply_reserved_settlement(&mut g, &candidate) {
                    if let Some(payment) = g.payments.get_mut(&id) {
                        payment.last_error = Some(format!("atomic settlement blocked: {e}"));
                        payment.updated_unix = now_unix();
                    }
                    return Err(format!("atomic settlement failed: {e}"));
                }
                let payment = g
                    .payments
                    .get_mut(&id)
                    .ok_or_else(|| "payment disappeared during settlement".to_string())?;
                payment.status = PaymentStatus::Settled;
                payment.finality = "hub_coordinated_not_l1".into();
                payment.last_error = None;
                payment.updated_unix = now_unix();
            }
        }
        let out = g.payments.get(&id).cloned().ok_or("payment disappeared")?;
        let settled = matches!(out.status, PaymentStatus::Settled);
        // end borrow of map before receipt write
        drop(g);
        if settled {
            let _ = self.ensure_receipt(out.id);
            self.mark_invoice_paid_for_payment(out.id);
            // Update hub routing balances + draft last bills (idempotent)
            let _ = self.auto_bill_after_settle(&out);
        }
        Ok(out)
    }

    /// After hub settle: shift balances on each **local** hop for routing liquidity,
    /// then draft last-bill proposals (parties still must sign bills for L1 evidence).
    ///
    /// Idempotent per payment_id (safe if called from add_signature and agent_api).
    /// Active bill later remains authoritative (`balance_source = active_bill`).
    pub fn auto_bill_after_settle(&self, pay: &PaymentSession) -> Result<Vec<ChannelBill>, String> {
        if !matches!(pay.status, PaymentStatus::Settled) {
            return Err("payment not settled".into());
        }
        let mei = crate::amounts::parse_zhu(&pay.amount_hac)?;
        let sats = pay.amount_satoshi;
        if mei == 0 && sats == 0 {
            return Ok(vec![]);
        }

        let distributed_balance_already_applied = self
            .inner
            .read()
            .map_err(|error| error.to_string())?
            .applied_settlements
            .contains(&pay.id);
        let shifted = if distributed_balance_already_applied {
            pay.route.clone()
        } else {
            self.apply_payment_balance_shifts(pay)?
        };
        let mut bills = Vec::new();
        for cid in shifted {
            // Idempotent: reuse bill already linked to this payment
            if let Some(b) = self.get_bill(&cid) {
                if b.payment_id == Some(pay.id) {
                    bills.push(b);
                    continue;
                }
            }
            let Some(ch) = self.get_channel(&cid) else {
                continue;
            };
            match self.propose_bill(
                &cid,
                ProposeBillRequest {
                    sequence: 0,
                    left_hac: ch.left_hac.clone(),
                    right_hac: ch.right_hac.clone(),
                    left_satoshi: ch.left_satoshi,
                    right_satoshi: ch.right_satoshi,
                    payment_id: Some(pay.id),
                    notes: format!("auto_bill after payment {}", pay.id),
                    signatures: vec![],
                },
            ) {
                Ok(b) => bills.push(b),
                Err(e) => {
                    // Non-fatal: balances already shifted for routing
                    tracing::debug!(channel = %cid, error = %e, "auto_bill propose skipped");
                }
            }
        }
        Ok(bills)
    }

    /// Apply payment amount along route to local channel balances (directional).
    /// Skips remote-only hops. Skips channels already updated for this payment_id.
    pub fn apply_payment_balance_shifts(
        &self,
        pay: &PaymentSession,
    ) -> Result<Vec<String>, String> {
        let mei = crate::amounts::parse_zhu(&pay.amount_hac)?;
        let sats = pay.amount_satoshi;
        if mei == 0 && sats == 0 {
            return Ok(vec![]);
        }
        let mut at = pay.payer.trim().to_string();
        let mut updated = Vec::new();
        for cid_raw in &pay.route {
            let id = match normalize_channel_id(cid_raw) {
                Ok(id) => id,
                Err(_) => continue,
            };
            let mut g = self.inner.write().map_err(|e| e.to_string())?;
            let Some(ch) = g.channels.get_mut(&id) else {
                // Remote hop — not registered here
                // Advance walker using payment route graph from bill? Without local ch we
                // cannot know the other side from channel; use required path via addresses
                // only when we have the channel. For remote-only hop, try peer ads.
                drop(g);
                if let Some(other) = self.hop_counterparty_from_ads(&id, &at) {
                    at = other;
                }
                continue;
            };
            if ch.last_settle_payment_id == Some(pay.id) {
                // Already applied — advance walker
                at = if at == ch.left_address {
                    ch.right_address.clone()
                } else {
                    ch.left_address.clone()
                };
                updated.push(id);
                continue;
            }

            let left_mei = crate::amounts::parse_zhu(&ch.left_hac)?;
            let right_mei = crate::amounts::parse_zhu(&ch.right_hac)?;
            let (new_left_mei, new_right_mei, new_left_sat, new_right_sat, next_at) =
                if at == ch.left_address {
                    if left_mei < mei {
                        return Err(format!(
                            "insufficient left balance on {id}: have {left_mei} mei need {mei}"
                        ));
                    }
                    if ch.left_satoshi < sats {
                        return Err(format!(
                            "insufficient left satoshi on {id}: have {} need {sats}",
                            ch.left_satoshi
                        ));
                    }
                    (
                        left_mei - mei,
                        right_mei
                            .checked_add(mei)
                            .ok_or("right HAC balance overflow")?,
                        ch.left_satoshi - sats,
                        ch.right_satoshi
                            .checked_add(sats)
                            .ok_or("right satoshi balance overflow")?,
                        ch.right_address.clone(),
                    )
                } else if at == ch.right_address {
                    if right_mei < mei {
                        return Err(format!(
                            "insufficient right balance on {id}: have {right_mei} mei need {mei}"
                        ));
                    }
                    if ch.right_satoshi < sats {
                        return Err(format!(
                            "insufficient right satoshi on {id}: have {} need {sats}",
                            ch.right_satoshi
                        ));
                    }
                    (
                        left_mei
                            .checked_add(mei)
                            .ok_or("left HAC balance overflow")?,
                        right_mei - mei,
                        ch.left_satoshi
                            .checked_add(sats)
                            .ok_or("left satoshi balance overflow")?,
                        ch.right_satoshi - sats,
                        ch.left_address.clone(),
                    )
                } else {
                    return Err(format!(
                        "payment path broken at channel {id}: walker {at} not on channel"
                    ));
                };

            ch.left_hac = crate::amounts::format_zhu(new_left_mei);
            ch.right_hac = crate::amounts::format_zhu(new_right_mei);
            ch.left_satoshi = new_left_sat;
            ch.right_satoshi = new_right_sat;
            ch.balance_source = "payment_settle".into();
            ch.last_settle_payment_id = Some(pay.id);
            at = next_at;
            updated.push(id);
        }
        Ok(updated)
    }

    /// Find other party of a channel from peer advertisements (remote hop walker).
    fn hop_counterparty_from_ads(&self, channel_id: &str, at: &str) -> Option<String> {
        let peers = self.list_peers();
        for p in peers {
            for c in p.channels {
                if c.channel_id == channel_id {
                    if c.left_address == at {
                        return Some(c.right_address);
                    }
                    if c.right_address == at {
                        return Some(c.left_address);
                    }
                }
            }
        }
        None
    }

    pub fn fail_payment(&self, id: Uuid, reason: &str) -> Result<PaymentSession, String> {
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let p = g
            .payments
            .get_mut(&id)
            .ok_or_else(|| format!("payment {id} not found"))?;
        if matches!(p.status, PaymentStatus::Committing | PaymentStatus::Settled) {
            return Err(
                "cannot fail a committing or settled payment; a durable commit may exist".into(),
            );
        }
        p.status = PaymentStatus::Failed;
        p.last_error = Some(clamp_str(reason, 256));
        p.updated_unix = now_unix();
        let out = p.clone();
        g.reservations.remove(&id);
        Ok(out)
    }

    /// Mark collecting sessions past expires_unix as TimedOut. Returns count timed out.
    pub fn expire_stale_payments(&self) -> usize {
        let now = now_unix();
        let Ok(mut g) = self.inner.write() else {
            return 0;
        };
        let mut expired_ids = Vec::new();
        let mut n = 0usize;
        for p in g.payments.values_mut() {
            if is_expired(p, now) {
                p.status = PaymentStatus::TimedOut;
                p.last_error = Some("payment session expired (TTL)".into());
                p.updated_unix = now;
                expired_ids.push(p.id);
                n += 1;
            }
        }
        for id in expired_ids {
            g.reservations.remove(&id);
        }
        n
    }

    #[cfg(test)]
    fn force_payment_expires_unix(&self, id: Uuid, expires_unix: u64) {
        if let Ok(mut g) = self.inner.write() {
            if let Some(p) = g.payments.get_mut(&id) {
                p.expires_unix = expires_unix;
            }
        }
    }

    // --- Phase C: reconciliation bills (last only) ---

    pub fn bill_counts(&self) -> (usize, usize) {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return (0, 0),
        };
        (g.bills.len(), g.bill_drafts.len())
    }

    pub fn list_bills(&self) -> Vec<ChannelBill> {
        self.inner
            .read()
            .map(|g| {
                g.bills
                    .values()
                    .chain(g.bill_drafts.values())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return the candidate bill when present so API clients can sign it;
    /// otherwise return the last fully signed bill.
    pub fn get_bill(&self, channel_id: &str) -> Option<ChannelBill> {
        let id = normalize_channel_id(channel_id).ok()?;
        self.inner
            .read()
            .ok()
            .and_then(|g| g.bill_drafts.get(&id).or_else(|| g.bills.get(&id)).cloned())
    }

    fn get_active_bill(&self, channel_id: &str) -> Option<ChannelBill> {
        let id = normalize_channel_id(channel_id).ok()?;
        self.inner
            .read()
            .ok()
            .and_then(|g| g.bills.get(&id).cloned())
    }

    /// Restore a bill from persistence (trusted local disk; skips re-sign).
    pub fn restore_bill(&self, bill: ChannelBill) -> Result<(), String> {
        let id = normalize_channel_id(&bill.channel_id)?;
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let mut bill = bill;
        bill.channel_id = id.clone();
        match bill.status {
            BillStatus::Active => {
                g.bills.insert(id, bill);
            }
            BillStatus::CollectingSignatures => {
                g.bill_drafts.insert(id, bill);
            }
        }
        Ok(())
    }

    /// Propose a new last bill. Replaces collecting draft of same channel;
    /// must have sequence > last Active sequence. Hub never invents balances.
    pub fn propose_bill(
        &self,
        channel_id: &str,
        req: ProposeBillRequest,
    ) -> Result<ChannelBill, String> {
        let id = normalize_channel_id(channel_id)?;
        if req.left_hac.trim().is_empty()
            && req.right_hac.trim().is_empty()
            && req.left_satoshi == 0
            && req.right_satoshi == 0
        {
            return Err("bill balances empty — hub will not invent balances".into());
        }

        let left_hac = if req.left_hac.trim().is_empty() {
            "0".to_string()
        } else {
            crate::amounts::normalize_hac(&req.left_hac)?
        };
        let right_hac = if req.right_hac.trim().is_empty() {
            "0".to_string()
        } else {
            crate::amounts::normalize_hac(&req.right_hac)?
        };
        let g_read = self.inner.read().map_err(|e| e.to_string())?;
        if g_read
            .reservations
            .values()
            .any(|reservation| reservation.hops.iter().any(|hop| hop.channel_id == id))
        {
            return Err("channel has reserved liquidity for an open payment".into());
        }
        let ch = g_read
            .channels
            .get(&id)
            .cloned()
            .ok_or_else(|| format!("channel {id} not registered on this hub"))?;
        // Conservation: HAC mei sum and satoshi sum must match channel registration totals
        // when channel has known balances.
        validate_channel_balance_conservation(
            &ch,
            &left_hac,
            &right_hac,
            req.left_satoshi,
            req.right_satoshi,
        )?;
        let prev_active = g_read
            .bills
            .get(&id)
            .filter(|b| b.status == BillStatus::Active);
        let prev_seq = prev_active.map(|b| b.sequence).unwrap_or(0);
        let prev_hash = prev_active
            .map(|b| b.message_hash_hex.clone())
            .unwrap_or_default();
        // Allow replacing a collecting draft even with same sequence if still collecting
        let existing_collecting = g_read.bill_drafts.get(&id).cloned();
        drop(g_read);

        let sequence = if req.sequence == 0 {
            prev_seq.saturating_add(1).max(1)
        } else {
            req.sequence
        };
        if sequence <= prev_seq {
            return Err(format!(
                "sequence must be > last active sequence {prev_seq} (got {sequence})"
            ));
        }
        if let Some(ref draft) = existing_collecting {
            if draft.sequence == sequence {
                // replace draft ok
            } else if sequence < draft.sequence {
                return Err(format!(
                    "sequence {sequence} is behind collecting draft {}",
                    draft.sequence
                ));
            }
        }

        if let Some(pid) = req.payment_id {
            let g = self.inner.read().map_err(|e| e.to_string())?;
            let pay = g
                .payments
                .get(&pid)
                .ok_or_else(|| format!("payment_id {pid} not found on hub"))?;
            if !pay.route.iter().any(|c| c == &id) {
                return Err("payment_id route does not include this channel".into());
            }
        }

        let now = now_unix();
        let left_address = ch.left_address.clone();
        let right_address = ch.right_address.clone();
        let payment_id_str = req.payment_id.map(|u| u.to_string()).unwrap_or_default();

        let commit = BillCommit {
            channel_id: id.clone(),
            sequence,
            provider_id: self.provider_id.clone(),
            left_address: left_address.clone(),
            right_address: right_address.clone(),
            left_hac: left_hac.clone(),
            right_hac: right_hac.clone(),
            left_satoshi: req.left_satoshi,
            right_satoshi: req.right_satoshi,
            prev_bill_hash: prev_hash.clone(),
            created_unix: now,
            payment_id: payment_id_str,
        };
        let message = bill_canonical_message(&commit);
        let message_hash_hex = bill_message_hash_hex(&commit);

        let mut bill = ChannelBill {
            channel_id: id.clone(),
            sequence,
            status: BillStatus::CollectingSignatures,
            left_address: left_address.clone(),
            right_address: right_address.clone(),
            left_hac,
            right_hac,
            left_satoshi: req.left_satoshi,
            right_satoshi: req.right_satoshi,
            prev_bill_hash: prev_hash,
            message,
            message_hash_hex,
            required_signers: vec![left_address, right_address],
            signatures: Vec::new(),
            created_unix: now,
            updated_unix: now,
            payment_id: req.payment_id,
            notes: clamp_str(&req.notes, 512),
            source: "client_submitted".into(),
        };

        // Apply any signatures included in the proposal.
        for s in req.signatures {
            self.apply_bill_signature_inner(&mut bill, &s)?;
        }

        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        // A bill may have become active while signatures were verified outside
        // the write lock. Refuse a stale candidate instead of replacing it.
        let current_prev_seq = g.bills.get(&id).map(|b| b.sequence).unwrap_or(0);
        if current_prev_seq != prev_seq {
            return Err("active bill changed while proposing; retry with current state".into());
        }
        if let Some(current_draft) = g.bill_drafts.get(&id) {
            if current_draft.sequence > sequence {
                return Err(format!(
                    "sequence {sequence} is behind collecting draft {}",
                    current_draft.sequence
                ));
            }
        }
        // If activated and complete, mirror balances onto channel registration.
        if bill.status == BillStatus::Active {
            if let Some(ch) = g.channels.get_mut(&id) {
                apply_bill_to_channel(ch, &bill);
            }
            g.bill_drafts.remove(&id);
            g.bills.insert(id, bill.clone());
        } else {
            g.bill_drafts.insert(id, bill.clone());
        }
        Ok(bill)
    }

    pub fn sign_bill(&self, channel_id: &str, req: SignBillRequest) -> Result<ChannelBill, String> {
        let id = normalize_channel_id(channel_id)?;
        let sign_req = SignPaymentRequest {
            address: req.address,
            signature_hex: req.signature_hex,
            public_key_hex: req.public_key_hex,
        };
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let out = {
            let bill = g
                .bill_drafts
                .get_mut(&id)
                .ok_or_else(|| format!("no collecting bill for channel {id}; propose one first"))?;
            if bill.status != BillStatus::CollectingSignatures {
                return Err(format!(
                    "bill is {:?} (sequence {}); propose a higher sequence to update",
                    bill.status, bill.sequence
                ));
            }
            Self::apply_bill_signature_static(bill, &sign_req, self.limits.require_sig_verify)?;
            bill.clone()
        };
        if out.status == BillStatus::Active {
            if let Some(ch) = g.channels.get_mut(&id) {
                apply_bill_to_channel(ch, &out);
            }
            g.bill_drafts.remove(&id);
            g.bills.insert(id, out.clone());
        }
        Ok(out)
    }

    fn apply_bill_signature_inner(
        &self,
        bill: &mut ChannelBill,
        req: &SignPaymentRequest,
    ) -> Result<(), String> {
        Self::apply_bill_signature_static(bill, req, self.limits.require_sig_verify)
    }

    fn apply_bill_signature_static(
        bill: &mut ChannelBill,
        req: &SignPaymentRequest,
        require_sig_verify: bool,
    ) -> Result<(), String> {
        if req.address.trim().is_empty() || req.signature_hex.trim().is_empty() {
            return Err("address and signature_hex required".into());
        }
        let addr = clamp_str(req.address.trim(), 128);
        if !bill.required_signers.iter().any(|s| s == &addr) {
            return Err(format!(
                "address {addr} is not a channel party (need {:?})",
                bill.required_signers
            ));
        }
        let sig = req.signature_hex.trim();
        let mut public_key_hex = req.public_key_hex.trim().to_string();
        let mut verified = false;
        if require_sig_verify {
            let hash_bytes = hex::decode(&bill.message_hash_hex)
                .map_err(|e| format!("message_hash_hex corrupt: {e}"))?;
            if hash_bytes.len() != 32 {
                return Err("message_hash_hex must be 32 bytes".into());
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_bytes);
            let pk_opt = if public_key_hex.is_empty() {
                None
            } else {
                Some(public_key_hex.as_str())
            };
            let parsed = verify_bill_signature(&hash, &addr, sig, pk_opt)?;
            public_key_hex = hex::encode(parsed.public_key);
            verified = true;
        } else {
            let cleaned = sig.trim_start_matches("0x");
            if cleaned.len() < 8 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("signature_hex must be hex".into());
            }
        }
        let store_sig = sig.trim_start_matches("0x").to_lowercase();
        let order_index = bill
            .required_signers
            .iter()
            .position(|s| s == &addr)
            .unwrap_or(0);
        bill.signatures.retain(|s| s.address != addr);
        bill.signatures.push(PaymentSignature {
            address: addr,
            signature_hex: store_sig,
            public_key_hex,
            signed_unix: now_unix(),
            order_index,
            verified,
        });
        bill.updated_unix = now_unix();
        let both = bill
            .required_signers
            .iter()
            .all(|need| bill.signatures.iter().any(|s| &s.address == need));
        if both {
            if require_sig_verify && !bill.signatures.iter().all(|s| s.verified) {
                return Err("not all bill signatures verified".into());
            }
            bill.status = BillStatus::Active;
        }
        Ok(())
    }

    /// Build dispute/export package for L1 arbitration (wallet submits; hub does not).
    pub fn export_dispute(
        &self,
        channel_id: &str,
        fullnode_host: &str,
    ) -> Result<DisputeExport, String> {
        let id = normalize_channel_id(channel_id)?;
        let ch = self.get_channel(&id);
        let bill = self.get_active_bill(&id);
        let bill_active = bill
            .as_ref()
            .map(|b| b.status == BillStatus::Active)
            .unwrap_or(false);
        let mut evidence_notes = Vec::new();
        if bill.is_none() {
            evidence_notes.push(
                "No bill stored — parties should propose+sign a reconciliation bill first".into(),
            );
        } else if !bill_active {
            evidence_notes
                .push("Bill is still collecting signatures — both left and right must sign".into());
        } else {
            evidence_notes.push(
                "Last active bill is the sole reconciliation credential (history discarded per whitepaper)".into(),
            );
            if let Some(ref b) = bill {
                evidence_notes.push(format!(
                    "sequence={} left_hac={} right_hac={} left_sat={} right_sat={}",
                    b.sequence, b.left_hac, b.right_hac, b.left_satoshi, b.right_satoshi
                ));
                evidence_notes.push(format!("bill_hash={}", b.message_hash_hex));
            }
        }
        if let Some(ref c) = ch {
            if let Some(st) = c.l1_status {
                evidence_notes.push(format!(
                    "hub-cached l1_status={st} (refresh via /v1/channels/:id/refresh)"
                ));
            }
        } else {
            evidence_notes.push("Channel not registered on this hub".into());
        }
        let close_package = bill.as_ref().map(|b| {
            let both = b.signatures.len() >= 2
                && b.required_signers.iter().all(|addr| {
                    b.signatures
                        .iter()
                        .any(|s| s.address == *addr && s.verified)
                });
            ClosePackage {
                schema: "hacash-l2-close-package/1",
                channel_id: id.clone(),
                left_address: b.left_address.clone(),
                right_address: b.right_address.clone(),
                distribution_left_hac: b.left_hac.clone(),
                distribution_right_hac: b.right_hac.clone(),
                distribution_left_satoshi: b.left_satoshi,
                distribution_right_satoshi: b.right_satoshi,
                bill_sequence: b.sequence,
                bill_message: b.message.clone(),
                bill_message_hash_hex: b.message_hash_hex.clone(),
                bill_signatures: b.signatures.clone(),
                both_signed: both || bill_active,
                ready_for_l1_close: false,
                l1_actions: vec![
                    "query_l1_exit_readiness",
                    "verify_enabled_l1_action_semantics",
                    "build_and_sign_in_wallet_with_fresh_l1_transaction_signatures",
                    "broadcast_only_after_wallet_verification",
                    "refresh_hub_channel_status",
                ],
            }
        });
        Ok(DisputeExport {
            purpose: "l1_arbitration_evidence_package",
            channel_id: id.clone(),
            channel: ch,
            last_bill: bill,
            bill_active,
            fullnode_l1_query: format!(
                "http://{}/query/channel?id={}&unit=fin",
                fullnode_host.trim(),
                id
            ),
            disclaimer: "This hub is a CSP backup/coordinator only — it does not custody keys and does not submit ChannelClose. Wallet/fullnode must submit L1 close/arbitration using protocol rules.",
            next_steps: vec![
                "Confirm last_bill.status == active and both signatures verified",
                "Fetch /v1/channels/:id/l1-exit/readiness",
                "Require the configured fullnode to report the exact action as registered and enabled",
                "Do not use action 3 for a negotiated distribution; it returns original funding",
                "Build and sign the exact L1 transaction in the wallet; never reuse bill/V2 signatures",
                "Broadcast only after wallet verification; then monitor inclusion and refresh the hub",
            ],
            evidence_notes,
            close_package,
        })
    }

    // --- rebalance (whitepaper capacity shift) ---

    pub fn propose_rebalance(
        &self,
        req: ProposeRebalanceRequest,
    ) -> Result<RebalanceProposal, String> {
        let a = normalize_channel_id(&req.channel_a)?;
        let b = normalize_channel_id(&req.channel_b)?;
        if a == b {
            return Err("channel_a and channel_b must differ".into());
        }
        let ch_a = self
            .get_channel(&a)
            .ok_or_else(|| format!("channel_a {a} not registered"))?;
        let ch_b = self
            .get_channel(&b)
            .ok_or_else(|| format!("channel_b {b} not registered"))?;
        if req.amount_mei == 0 && req.amount_satoshi == 0 {
            return Err("amount_mei or amount_satoshi required".into());
        }
        // Shared party required for rebalance coordination
        let share = ch_a.left_address == ch_b.left_address
            || ch_a.left_address == ch_b.right_address
            || ch_a.right_address == ch_b.left_address
            || ch_a.right_address == ch_b.right_address;
        if !share {
            return Err(
                "rebalance requires a shared address between channel_a and channel_b".into(),
            );
        }
        let now = now_unix();
        let p = RebalanceProposal {
            id: Uuid::new_v4(),
            status: RebalanceStatus::Proposed,
            channel_a: a,
            channel_b: b,
            amount_mei: req.amount_mei,
            amount_satoshi: req.amount_satoshi,
            note: clamp_str(&req.note, 256),
            created_unix: now,
            updated_unix: now,
            bill_a_id: None,
            bill_b_id: None,
        };
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        if g.rebalances.len() >= 10_000 {
            return Err("too many rebalance proposals".into());
        }
        g.rebalances.insert(p.id, p.clone());
        Ok(p)
    }

    pub fn list_rebalances(&self) -> Vec<RebalanceProposal> {
        self.inner
            .read()
            .map(|g| g.rebalances.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_rebalance(&self, id: Uuid) -> Option<RebalanceProposal> {
        self.inner
            .read()
            .ok()
            .and_then(|g| g.rebalances.get(&id).cloned())
    }

    pub fn mark_rebalance_status(
        &self,
        id: Uuid,
        status: RebalanceStatus,
    ) -> Result<RebalanceProposal, String> {
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let r = g
            .rebalances
            .get_mut(&id)
            .ok_or_else(|| "rebalance not found".to_string())?;
        r.status = status;
        r.updated_unix = now_unix();
        Ok(r.clone())
    }

    /// After parties sign new bills on both channels, mark rebalance completed.
    pub fn complete_rebalance(&self, id: Uuid) -> Result<RebalanceProposal, String> {
        let r = self
            .get_rebalance(id)
            .ok_or_else(|| "rebalance not found".to_string())?;
        let bill_a = self.get_active_bill(&r.channel_a);
        let bill_b = self.get_active_bill(&r.channel_b);
        if bill_a.as_ref().map(|b| b.status) != Some(BillStatus::Active)
            || bill_b.as_ref().map(|b| b.status) != Some(BillStatus::Active)
        {
            return Err(
                "both channels need an active last bill before rebalance can complete".into(),
            );
        }
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let r = g
            .rebalances
            .get_mut(&id)
            .ok_or_else(|| "rebalance not found".to_string())?;
        r.status = RebalanceStatus::Completed;
        r.updated_unix = now_unix();
        r.bill_a_id = bill_a.map(|b| format!("{}:{}", b.channel_id, b.sequence));
        r.bill_b_id = bill_b.map(|b| format!("{}:{}", b.channel_id, b.sequence));
        Ok(r.clone())
    }

    // --- deferred payments ---

    pub fn create_deferred(&self, req: CreateDeferredRequest) -> Result<DeferredPayment, String> {
        if req.payer.trim().is_empty() || req.payee.trim().is_empty() {
            return Err("payer and payee required".into());
        }
        if req.amount_hac.trim().is_empty() && req.amount_satoshi == 0 {
            return Err("amount_hac or amount_satoshi required".into());
        }
        let now = now_unix();
        // Allow any past timestamp (Ready) or future schedule; only reject absurd future skew
        if req.execute_after_unix > now.saturating_add(86400 * 365 * 20) {
            return Err("execute_after_unix too far in the future".into());
        }
        let d = DeferredPayment {
            id: Uuid::new_v4(),
            status: if req.execute_after_unix <= now {
                DeferredStatus::Ready
            } else {
                DeferredStatus::Scheduled
            },
            payer: clamp_str(req.payer.trim(), 128),
            payee: clamp_str(req.payee.trim(), 128),
            amount_hac: clamp_str(&req.amount_hac, 64),
            amount_satoshi: req.amount_satoshi,
            fee_hac: clamp_str(&req.fee_hac, 64),
            execute_after_unix: req.execute_after_unix,
            created_unix: now,
            updated_unix: now,
            local_only: req.local_only,
            route: req
                .route
                .into_iter()
                .take(32)
                .map(|s| clamp_str(&s, 128))
                .collect(),
            payment_id: None,
            last_error: None,
            note: clamp_str(&req.note, 256),
        };
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        if g.deferred.len() >= 50_000 {
            return Err("too many deferred payments".into());
        }
        g.deferred.insert(d.id, d.clone());
        Ok(d)
    }

    pub fn list_deferred(&self) -> Vec<DeferredPayment> {
        self.inner
            .read()
            .map(|g| g.deferred.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_deferred(&self, id: Uuid) -> Option<DeferredPayment> {
        self.inner
            .read()
            .ok()
            .and_then(|g| g.deferred.get(&id).cloned())
    }

    pub fn cancel_deferred(&self, id: Uuid) -> Result<DeferredPayment, String> {
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let d = g
            .deferred
            .get_mut(&id)
            .ok_or_else(|| "deferred payment not found".to_string())?;
        if matches!(
            d.status,
            DeferredStatus::Promoted | DeferredStatus::Cancelled
        ) {
            return Err(format!("cannot cancel deferred in status {:?}", d.status));
        }
        d.status = DeferredStatus::Cancelled;
        d.updated_unix = now_unix();
        Ok(d.clone())
    }

    /// Promote a single deferred payment into a live payment session.
    pub fn promote_deferred(&self, id: Uuid) -> Result<(DeferredPayment, PaymentSession), String> {
        let d = self
            .get_deferred(id)
            .ok_or_else(|| "deferred payment not found".to_string())?;
        if d.status == DeferredStatus::Cancelled || d.status == DeferredStatus::Promoted {
            return Err(format!("deferred not promotable: {:?}", d.status));
        }
        let now = now_unix();
        if d.execute_after_unix > now {
            return Err(format!(
                "not yet due (execute_after_unix={}, now={})",
                d.execute_after_unix, now
            ));
        }
        let session = self.create_payment(CreatePaymentRequest {
            payer: d.payer.clone(),
            payee: d.payee.clone(),
            amount_hac: d.amount_hac.clone(),
            amount_satoshi: d.amount_satoshi,
            fee_hac: d.fee_hac.clone(),
            route: d.route.clone(),
            local_only: d.local_only,
        })?;
        let mut g = self.inner.write().map_err(|e| e.to_string())?;
        let d = g
            .deferred
            .get_mut(&id)
            .ok_or_else(|| "deferred payment not found".to_string())?;
        d.status = DeferredStatus::Promoted;
        d.payment_id = Some(session.id);
        d.updated_unix = now_unix();
        Ok((d.clone(), session))
    }

    /// Auto-promote all due deferred payments. Returns count promoted.
    pub fn promote_due_deferred(&self) -> usize {
        let now = now_unix();
        let due: Vec<Uuid> = self
            .list_deferred()
            .into_iter()
            .filter(|d| {
                matches!(d.status, DeferredStatus::Scheduled | DeferredStatus::Ready)
                    && d.execute_after_unix <= now
            })
            .map(|d| d.id)
            .collect();
        let mut n = 0usize;
        for id in due {
            match self.promote_deferred(id) {
                Ok(_) => n += 1,
                Err(e) => {
                    if let Ok(mut g) = self.inner.write() {
                        if let Some(d) = g.deferred.get_mut(&id) {
                            d.status = DeferredStatus::Failed;
                            d.last_error = Some(clamp_str(&e, 256));
                            d.updated_unix = now_unix();
                        }
                    }
                }
            }
        }
        n
    }
}
fn validate_activation_against_channel(
    certificate: &SignedChannelActivationV1,
    channel: &LocalChannel,
    require_open: bool,
) -> Result<(), String> {
    certificate.validate()?;
    if require_open && channel.l1_status != Some(0) {
        return Err("V2 activation requires an L1 channel in opening status 0".into());
    }
    let anchor = channel
        .l1_anchor
        .as_ref()
        .ok_or("channel has no verified fullnode anchor; refresh L1 first")?;
    anchor.validate_against_channel(channel)?;
    let commitment = &certificate.commitment;
    if commitment.channel_id != channel.channel_id
        || commitment.network_genesis_hash_hex != anchor.network_genesis_hash_hex
        || commitment.funding_anchor_hash_hex != anchor.funding_incarnation_hash_hex
        || commitment.left_address != channel.left_address
        || commitment.right_address != channel.right_address
    {
        return Err(
            "activation certificate does not match the registered L1 channel anchor".into(),
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct PersistBundle {
    pub channels: Vec<LocalChannel>,
    pub peers: Vec<PeerSeed>,
    pub trusted_peers: Vec<PeerHub>,
    pub bills: Vec<ChannelBill>,
    pub agent: AgentPersistSnapshot,
    pub channel_state_observations_v2: Vec<ChannelStateObservationV2>,
    pub channel_state_proofs_v2: Vec<ChannelEquivocationProofV2>,
    pub channel_activations_v1: Vec<ChannelActivationRecordV1>,
}

fn is_expired(p: &PaymentSession, now: u64) -> bool {
    matches!(
        p.status,
        PaymentStatus::Pending | PaymentStatus::CollectingSignatures
    ) && p.expires_unix > 0
        && now >= p.expires_unix
}

fn clamp_str(s: &str, max: usize) -> String {
    let t = s.trim();
    if t.len() <= max {
        t.to_string()
    } else {
        t.chars().take(max).collect()
    }
}

/// Authoritative mirror of active last bill onto hub channel (routing + advertise).
fn apply_bill_to_channel(ch: &mut LocalChannel, bill: &ChannelBill) {
    ch.left_hac = bill.left_hac.clone();
    ch.right_hac = bill.right_hac.clone();
    ch.left_satoshi = bill.left_satoshi;
    ch.right_satoshi = bill.right_satoshi;
    ch.balance_source = "active_bill".into();
}

/// Stable fingerprint of pay request (for content-bound idempotency).
fn pay_request_fingerprint(
    payer: &str,
    payee: &str,
    amount_hac: &str,
    amount_satoshi: u64,
    fee_hac: &str,
    local_only: bool,
    route: &[String],
    invoice_id: Option<Uuid>,
) -> String {
    let mut route_sorted: Vec<_> = route.iter().map(|s| s.trim().to_lowercase()).collect();
    route_sorted.sort();
    let canon = format!(
        "v1\npayer={}\npayee={}\namount_hac={}\namount_satoshi={}\nfee_hac={}\nlocal_only={}\nroute={}\ninvoice={}\n",
        payer.trim(),
        payee.trim(),
        amount_hac.trim(),
        amount_satoshi,
        fee_hac.trim(),
        local_only,
        route_sorted.join(","),
        invoice_id.map(|u| u.to_string()).unwrap_or_default(),
    );
    hex::encode(crate::hacash_keys::sha3(canon.as_bytes()))
}

/// Evict oldest idempotency records when over cap (not full clear).
fn prune_idempotency_lru(map: &mut HashMap<String, IdempotencyRecord>, max: usize, _now: u64) {
    if map.len() < max {
        return;
    }
    let overflow = map.len().saturating_sub(max.saturating_sub(max / 10));
    if overflow == 0 {
        return;
    }
    let mut entries: Vec<(String, u64)> = map
        .iter()
        .map(|(k, v)| (k.clone(), v.created_unix))
        .collect();
    entries.sort_by_key(|(_, t)| *t);
    for (k, _) in entries.into_iter().take(overflow) {
        map.remove(&k);
    }
}

/// Agent-related state persisted across restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentPersistSnapshot {
    #[serde(default)]
    pub payments: Vec<PaymentSession>,
    #[serde(default)]
    pub payment_meta: HashMap<String, crate::agent_pay::AgentPaymentMeta>,
    #[serde(default)]
    pub receipts: Vec<crate::agent_pay::PaymentReceipt>,
    #[serde(default)]
    pub invoices: Vec<crate::invoice::Invoice>,
    #[serde(default)]
    pub identities: Vec<crate::agent_id::AgentIdentity>,
    #[serde(default)]
    pub idempotency: Vec<(String, IdempotencyRecord)>,
    #[serde(default)]
    pub callbacks: HashMap<String, String>,
    #[serde(default)]
    pub reservations: Vec<PaymentReservation>,
    #[serde(default)]
    pub applied_settlements: Vec<Uuid>,
    #[serde(default)]
    pub agent_intents: HashMap<String, AgentIntentUse>,
    #[serde(default)]
    pub micro_streams: Vec<crate::micro::MicroStream>,
    #[serde(default)]
    pub escrows: Vec<crate::hvm_stub::EscrowIntent>,
    #[serde(default)]
    pub rebalances: Vec<RebalanceProposal>,
    #[serde(default)]
    pub deferred: Vec<DeferredPayment>,
    #[serde(default)]
    pub ledger: crate::policy::AgentLedger,
}
fn sanitize_agent_meta(
    m: crate::agent_pay::AgentPaymentMeta,
) -> crate::agent_pay::AgentPaymentMeta {
    crate::agent_pay::AgentPaymentMeta {
        agent_id: clamp_str(&m.agent_id, 64),
        purpose: clamp_str(&m.purpose, 128),
        invoice_id: clamp_str(&m.invoice_id, 128),
        skill: clamp_str(&m.skill, 64),
        conversation_id: clamp_str(&m.conversation_id, 128),
        extra: clamp_str(&m.extra, 512),
        // Cleared — hub overwrites after sanitize (clients must not set trust fields)
        policy_principal: String::new(),
        identity_address: String::new(),
    }
}

/// HAC mei + satoshi totals must be conserved vs channel registration when known.
fn validate_channel_balance_conservation(
    ch: &LocalChannel,
    left_hac: &str,
    right_hac: &str,
    left_sat: u64,
    right_sat: u64,
) -> Result<(), String> {
    let old_l = crate::amounts::parse_zhu(&ch.left_hac)?;
    let old_r = crate::amounts::parse_zhu(&ch.right_hac)?;
    let old_zhu = old_l
        .checked_add(old_r)
        .ok_or("registered HAC total overflow")?;
    let new_l = crate::amounts::parse_zhu(left_hac)?;
    let new_r = crate::amounts::parse_zhu(right_hac)?;
    let new_zhu = new_l.checked_add(new_r).ok_or("bill HAC total overflow")?;
    if new_zhu != old_zhu {
        return Err(format!(
            "HAC total not conserved: channel had {old_zhu} Zhu, bill has {new_zhu} Zhu"
        ));
    }
    let old_sat = ch
        .left_satoshi
        .checked_add(ch.right_satoshi)
        .ok_or("registered satoshi total overflow")?;
    let new_sat = left_sat
        .checked_add(right_sat)
        .ok_or("bill satoshi total overflow")?;
    if new_sat != old_sat {
        return Err(format!(
            "satoshi total not conserved: channel had {old_sat}, bill has {new_sat}"
        ));
    }
    Ok(())
}

fn apply_reserved_settlement(g: &mut Inner, pay: &PaymentSession) -> Result<Vec<String>, String> {
    if g.applied_settlements.contains(&pay.id) {
        g.reservations.remove(&pay.id);
        return Ok(pay.route.clone());
    }
    let reservation = g
        .reservations
        .get(&pay.id)
        .cloned()
        .ok_or_else(|| "payment liquidity reservation is missing".to_string())?;
    let amount_zhu = crate::amounts::parse_zhu(&pay.amount_hac)?;
    if reservation.amount_zhu != amount_zhu
        || reservation.amount_satoshi != pay.amount_satoshi
        || reservation.hops.len() != pay.route.len()
    {
        return Err("payment reservation does not match the signed payment".into());
    }

    // Preflight on clones. Nothing in the live ledger changes until every hop
    // has passed all balance, direction and overflow checks.
    let mut updates: Vec<(String, LocalChannel)> = Vec::with_capacity(reservation.hops.len());
    let mut walker = pay.payer.clone();
    for (index, hop) in reservation.hops.iter().enumerate() {
        if pay.route.get(index) != Some(&hop.channel_id) || hop.from_address != walker {
            return Err(format!(
                "signed route no longer matches reservation at hop {}",
                hop.channel_id
            ));
        }
        let mut ch = g
            .channels
            .get(&hop.channel_id)
            .cloned()
            .ok_or_else(|| format!("local channel {} disappeared", hop.channel_id))?;
        if ch.last_settle_payment_id == Some(pay.id) {
            return Err(format!(
                "partial prior settlement detected on channel {}",
                hop.channel_id
            ));
        }
        let left_zhu = crate::amounts::parse_zhu(&ch.left_hac)?;
        let right_zhu = crate::amounts::parse_zhu(&ch.right_hac)?;
        if ch.left_address == hop.from_address && ch.right_address == hop.to_address {
            let new_left = left_zhu
                .checked_sub(amount_zhu)
                .ok_or_else(|| format!("insufficient HAC on {}", hop.channel_id))?;
            let new_right = right_zhu
                .checked_add(amount_zhu)
                .ok_or("right HAC balance overflow")?;
            ch.left_hac = crate::amounts::format_zhu(new_left);
            ch.right_hac = crate::amounts::format_zhu(new_right);
            ch.left_satoshi = ch
                .left_satoshi
                .checked_sub(pay.amount_satoshi)
                .ok_or_else(|| format!("insufficient satoshi on {}", hop.channel_id))?;
            ch.right_satoshi = ch
                .right_satoshi
                .checked_add(pay.amount_satoshi)
                .ok_or("right satoshi balance overflow")?;
        } else if ch.right_address == hop.from_address && ch.left_address == hop.to_address {
            let new_right = right_zhu
                .checked_sub(amount_zhu)
                .ok_or_else(|| format!("insufficient HAC on {}", hop.channel_id))?;
            let new_left = left_zhu
                .checked_add(amount_zhu)
                .ok_or("left HAC balance overflow")?;
            ch.left_hac = crate::amounts::format_zhu(new_left);
            ch.right_hac = crate::amounts::format_zhu(new_right);
            ch.right_satoshi = ch
                .right_satoshi
                .checked_sub(pay.amount_satoshi)
                .ok_or_else(|| format!("insufficient satoshi on {}", hop.channel_id))?;
            ch.left_satoshi = ch
                .left_satoshi
                .checked_add(pay.amount_satoshi)
                .ok_or("left satoshi balance overflow")?;
        } else {
            return Err(format!(
                "reservation direction changed on {}",
                hop.channel_id
            ));
        }
        ch.balance_source = "payment_settle".into();
        ch.last_settle_payment_id = Some(pay.id);
        walker = hop.to_address.clone();
        updates.push((hop.channel_id.clone(), ch));
    }
    if walker != pay.payee {
        return Err("settlement route does not end at payee".into());
    }
    for (channel_id, channel) in updates {
        g.channels.insert(channel_id, channel);
    }
    g.reservations.remove(&pay.id);
    g.applied_settlements.insert(pay.id);
    Ok(pay.route.clone())
}

fn apply_distributed_reserved_settlement(
    state: &mut Inner,
    tx_id: Uuid,
    amount_zhu: u64,
    amount_satoshi: u64,
    expected_hops: &[ReservedHop],
) -> Result<Vec<String>, String> {
    if state.applied_settlements.contains(&tx_id) {
        state.reservations.remove(&tx_id);
        return Ok(expected_hops
            .iter()
            .map(|hop| hop.channel_id.clone())
            .collect());
    }
    let reservation = state
        .reservations
        .get(&tx_id)
        .cloned()
        .ok_or_else(|| "distributed liquidity reservation is missing".to_string())?;
    if reservation.amount_zhu != amount_zhu
        || reservation.amount_satoshi != amount_satoshi
        || reservation.hops != expected_hops
    {
        return Err("distributed reservation does not match durable descriptor".into());
    }

    let mut updates = Vec::with_capacity(expected_hops.len());
    for hop in expected_hops {
        let mut channel = state
            .channels
            .get(&hop.channel_id)
            .cloned()
            .ok_or_else(|| format!("local channel {} disappeared", hop.channel_id))?;
        if channel.last_settle_payment_id == Some(tx_id) {
            return Err(format!(
                "partial prior distributed settlement detected on {}",
                hop.channel_id
            ));
        }
        let left_zhu = crate::amounts::parse_zhu(&channel.left_hac)?;
        let right_zhu = crate::amounts::parse_zhu(&channel.right_hac)?;
        if channel.left_address == hop.from_address && channel.right_address == hop.to_address {
            channel.left_hac = crate::amounts::format_zhu(
                left_zhu
                    .checked_sub(amount_zhu)
                    .ok_or_else(|| format!("insufficient HAC on {}", hop.channel_id))?,
            );
            channel.right_hac = crate::amounts::format_zhu(
                right_zhu
                    .checked_add(amount_zhu)
                    .ok_or("right HAC overflow")?,
            );
            channel.left_satoshi = channel
                .left_satoshi
                .checked_sub(amount_satoshi)
                .ok_or_else(|| format!("insufficient satoshi on {}", hop.channel_id))?;
            channel.right_satoshi = channel
                .right_satoshi
                .checked_add(amount_satoshi)
                .ok_or("right satoshi overflow")?;
        } else if channel.right_address == hop.from_address
            && channel.left_address == hop.to_address
        {
            channel.right_hac = crate::amounts::format_zhu(
                right_zhu
                    .checked_sub(amount_zhu)
                    .ok_or_else(|| format!("insufficient HAC on {}", hop.channel_id))?,
            );
            channel.left_hac = crate::amounts::format_zhu(
                left_zhu
                    .checked_add(amount_zhu)
                    .ok_or("left HAC overflow")?,
            );
            channel.right_satoshi = channel
                .right_satoshi
                .checked_sub(amount_satoshi)
                .ok_or_else(|| format!("insufficient satoshi on {}", hop.channel_id))?;
            channel.left_satoshi = channel
                .left_satoshi
                .checked_add(amount_satoshi)
                .ok_or("left satoshi overflow")?;
        } else {
            return Err(format!(
                "distributed direction changed on {}",
                hop.channel_id
            ));
        }
        channel.balance_source = "distributed_2pc_commit".into();
        channel.last_settle_payment_id = Some(tx_id);
        updates.push((hop.channel_id.clone(), channel));
    }
    for (channel_id, channel) in updates {
        state.channels.insert(channel_id, channel);
    }
    state.reservations.remove(&tx_id);
    state.applied_settlements.insert(tx_id);
    Ok(expected_hops
        .iter()
        .map(|hop| hop.channel_id.clone())
        .collect())
}

fn reserve_payment_liquidity(g: &mut Inner, reservation: PaymentReservation) -> Result<(), String> {
    for hop in &reservation.hops {
        let ch = g
            .channels
            .get(&hop.channel_id)
            .ok_or_else(|| format!("local channel {} disappeared", hop.channel_id))?;
        let (hac_balance, sat_balance) =
            if ch.left_address == hop.from_address && ch.right_address == hop.to_address {
                (crate::amounts::parse_zhu(&ch.left_hac)?, ch.left_satoshi)
            } else if ch.right_address == hop.from_address && ch.left_address == hop.to_address {
                (crate::amounts::parse_zhu(&ch.right_hac)?, ch.right_satoshi)
            } else {
                return Err(format!(
                    "reservation direction does not match channel {}",
                    hop.channel_id
                ));
            };

        let mut held_hac = 0u64;
        let mut held_sat = 0u64;
        for existing in g.reservations.values() {
            if existing
                .hops
                .iter()
                .any(|h| h.channel_id == hop.channel_id && h.from_address == hop.from_address)
            {
                held_hac = held_hac
                    .checked_add(existing.amount_zhu)
                    .ok_or("reserved HAC overflow")?;
                held_sat = held_sat
                    .checked_add(existing.amount_satoshi)
                    .ok_or("reserved satoshi overflow")?;
            }
        }
        let available_hac = hac_balance
            .checked_sub(held_hac)
            .ok_or("existing HAC reservations exceed channel balance")?;
        let available_sat = sat_balance
            .checked_sub(held_sat)
            .ok_or("existing satoshi reservations exceed channel balance")?;
        if available_hac < reservation.amount_zhu {
            return Err(format!(
                "insufficient unreserved HAC on {} from {}: have {} Zhu, need {} Zhu",
                hop.channel_id, hop.from_address, available_hac, reservation.amount_zhu
            ));
        }
        if available_sat < reservation.amount_satoshi {
            return Err(format!(
                "insufficient unreserved satoshi on {} from {}: have {}, need {}",
                hop.channel_id, hop.from_address, available_sat, reservation.amount_satoshi
            ));
        }
    }
    if g.reservations
        .insert(reservation.payment_id, reservation)
        .is_some()
    {
        return Err("duplicate payment reservation".into());
    }
    Ok(())
}

fn sanitize_meta(m: &HubMeta) -> HubMeta {
    HubMeta {
        public: m.public,
        accepts_wallets: m.accepts_wallets,
        accepts_agents: m.accepts_agents,
        region: clamp_str(&m.region, 32),
        fee_hint: clamp_str(&m.fee_hint, 64),
        contact: clamp_str(&m.contact, 128),
        protocol_version: clamp_str(&m.protocol_version, 16),
        started_unix: m.started_unix,
        fee_base_mei: m.fee_base_mei,
        fee_ppm: m.fee_ppm.min(1_000_000),
        total_capacity_mei: m.total_capacity_mei,
        max_channel_capacity_mei: m.max_channel_capacity_mei,
        channel_count: m.channel_count.min(1_000_000),
        features: m
            .features
            .iter()
            .take(32)
            .map(|f| clamp_str(f, 64))
            .collect(),
        identity_address: clamp_str(&m.identity_address, 128),
        identity_pubkey_hex: clamp_str(&m.identity_pubkey_hex, 128),
    }
}

fn normalize_channel_id(raw: &str) -> Result<String, String> {
    let s = raw.trim().trim_start_matches("0x").to_lowercase();
    if s.len() != 32 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "channel_id must be 16-byte hex (32 chars), got len {}",
            s.len()
        ));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sign_payment_hash;
    use crate::hacash_keys::Account;

    fn acc(pass: &str) -> Account {
        Account::create_by_password(pass).unwrap()
    }

    fn ch(id_byte: u8, left: &str, right: &str) -> RegisterChannelRequest {
        RegisterChannelRequest {
            channel_id: format!("{:02x}", id_byte).repeat(16),
            left_address: left.into(),
            right_address: right.into(),
            left_hac: "10:247".into(),
            right_hac: "5:247".into(),
            left_satoshi: 0,
            right_satoshi: 0,
            hub_side: Some(HubSide::Right),
            notes: String::new(),
        }
    }

    fn sign_req(account: &Account, message_hash_hex: &str) -> SignPaymentRequest {
        let mut hash = [0u8; 32];
        let bytes = hex::decode(message_hash_hex).unwrap();
        hash.copy_from_slice(&bytes);
        SignPaymentRequest {
            address: account.readable().to_string(),
            signature_hex: sign_payment_hash(account, &hash),
            public_key_hex: String::new(),
        }
    }
    fn l1_observation(
        channel_id: &str,
        left: &Account,
        right: &Account,
        reuse_version: u32,
        open_height: u64,
        observed_height: u64,
    ) -> L1ChannelObservationV1 {
        crate::l1_anchor::parse_fullnode_channel_observation(
            channel_id,
            &serde_json::json!({
                "ret": 0,
                "id": channel_id,
                "status": 0,
                "open_height": open_height,
                "close_height": 0,
                "reuse_version": reuse_version,
                "arbitration_lock": 5000,
                "interest_attribution": 0,
                "left": {
                    "address": left.readable(),
                    "hacash": "1:248",
                    "satoshi": 0
                },
                "right": {
                    "address": right.readable(),
                    "hacash": "5:247",
                    "satoshi": 0
                }
            }),
            observed_height,
            1_700_000_000,
        )
        .unwrap()
    }

    fn activate_bill(
        state: &HubState,
        channel_id: &str,
        left: &Account,
        right: &Account,
        sequence: u64,
    ) -> ChannelBill {
        let draft = state
            .propose_bill(
                channel_id,
                ProposeBillRequest {
                    sequence,
                    left_hac: "1:248".into(),
                    right_hac: "5:247".into(),
                    left_satoshi: 0,
                    right_satoshi: 0,
                    payment_id: None,
                    notes: "V2 shadow migration source".into(),
                    signatures: Vec::new(),
                },
            )
            .unwrap();
        let left_signature = sign_req(left, &draft.message_hash_hex);
        state
            .sign_bill(
                channel_id,
                SignBillRequest {
                    address: left_signature.address,
                    signature_hex: left_signature.signature_hex,
                    public_key_hex: left_signature.public_key_hex,
                },
            )
            .unwrap();
        let right_signature = sign_req(right, &draft.message_hash_hex);
        state
            .sign_bill(
                channel_id,
                SignBillRequest {
                    address: right_signature.address,
                    signature_hex: right_signature.signature_hex,
                    public_key_hex: right_signature.public_key_hex,
                },
            )
            .unwrap()
    }

    #[test]
    fn channel_id_uses_hacash_l1_sixteen_byte_width() {
        let real_width = "548c304352e677bbad58ec4c888f966d";
        assert_eq!(normalize_channel_id(real_width).unwrap(), real_width);
        assert_eq!(
            normalize_channel_id(&format!("0x{}", real_width.to_uppercase())).unwrap(),
            real_width
        );
        assert!(normalize_channel_id(&"aa".repeat(32)).is_err());
    }

    #[test]
    fn multi_hop_and_ordered_sign() {
        let a = acc("hub-test-a");
        let b = acc("hub-test-b");
        let c = acc("hub-test-c");
        let st = HubState::new("HubA".into(), 100, 8);
        st.register_channel(ch(0xaa, a.readable(), b.readable()))
            .unwrap();
        st.register_channel(ch(0xbb, b.readable(), c.readable()))
            .unwrap();

        let pay = st
            .create_payment(CreatePaymentRequest {
                payer: a.readable().into(),
                payee: c.readable().into(),
                amount_hac: "1:247".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![],
                local_only: true,
            })
            .unwrap();
        assert_eq!(pay.route.len(), 2);
        assert_eq!(pay.required_signers[0], c.readable());
        assert_eq!(pay.required_signers.last().unwrap(), a.readable());
        assert_eq!(pay.message_hash_hex.len(), 64);
        assert!(pay.message.starts_with("HACASH_L2_PAYMENT_V1"));

        // Payer cannot sign first
        let err = st
            .add_signature(pay.id, sign_req(&a, &pay.message_hash_hex))
            .unwrap_err();
        assert!(err.contains("order"), "{err}");

        st.add_signature(pay.id, sign_req(&c, &pay.message_hash_hex))
            .unwrap();
        st.add_signature(pay.id, sign_req(&b, &pay.message_hash_hex))
            .unwrap();
        let pay = st
            .add_signature(pay.id, sign_req(&a, &pay.message_hash_hex))
            .unwrap();
        assert_eq!(pay.status, PaymentStatus::Settled);
        assert!(pay.signatures.iter().all(|s| s.verified));
    }

    #[test]
    fn rejects_bad_signature() {
        let a = acc("hub-bad-a");
        let b = acc("hub-bad-b");
        let st = HubState::new("HubA".into(), 100, 8);
        st.register_channel(ch(0xaa, a.readable(), b.readable()))
            .unwrap();
        let pay = st
            .create_payment(CreatePaymentRequest {
                payer: a.readable().into(),
                payee: b.readable().into(),
                amount_hac: "1:247".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![],
                local_only: true,
            })
            .unwrap();
        let err = st
            .add_signature(
                pay.id,
                SignPaymentRequest {
                    address: b.readable().into(),
                    signature_hex: "00".repeat(97),
                    public_key_hex: String::new(),
                },
            )
            .unwrap_err();
        assert!(
            err.contains("invalid") || err.contains("public key") || err.contains("signature"),
            "{err}"
        );
    }

    #[test]
    fn peer_hello_upsert() {
        let st = HubState::new("HubA".into(), 10, 8);
        st.upsert_peer_from_hello(
            &PeerHello {
                provider_id: "HubB".into(),
                public_url: "http://127.0.0.1:9091".into(),
                name: "B".into(),
                channels: vec![AdvertisedChannel {
                    channel_id: "cc".repeat(16),
                    left_address: "X".into(),
                    right_address: "Y".into(),
                    via_provider: "HubB".into(),
                    capacity_mei: 200,
                    left_available_mei: 100,
                    right_available_mei: 100,
                    fee_ppm: 0,
                    capacity_zhu: 0,
                    left_available_zhu: 0,
                    right_available_zhu: 0,
                }],
                known_peers: vec![],
                meta: HubMeta {
                    accepts_agents: true,
                    ..HubMeta::default()
                },
                timestamp_unix: 0,
                identity_pubkey_hex: String::new(),
                identity_address: String::new(),
                signature_hex: String::new(),
            },
            true,
        )
        .unwrap();
        assert_eq!(st.peer_counts().0, 1);
        assert_eq!(st.list_peers()[0].channels.len(), 1);
    }

    #[test]
    fn settled_is_hub_coordinated_not_l1() {
        let a = acc("hub-fin-a");
        let b = acc("hub-fin-b");
        let st = HubState::new("HubA".into(), 100, 8);
        st.register_channel(ch(0xaa, a.readable(), b.readable()))
            .unwrap();
        let pay = st
            .create_payment(CreatePaymentRequest {
                payer: a.readable().into(),
                payee: b.readable().into(),
                amount_hac: "1:247".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![],
                local_only: true,
            })
            .unwrap();
        assert_eq!(pay.finality, "hub_coordinated_not_l1");
        assert!(pay.expires_unix > 0);
        st.add_signature(pay.id, sign_req(&b, &pay.message_hash_hex))
            .unwrap();
        let pay = st
            .add_signature(pay.id, sign_req(&a, &pay.message_hash_hex))
            .unwrap();
        assert_eq!(pay.status, PaymentStatus::Settled);
        assert_eq!(pay.finality, "hub_coordinated_not_l1");
    }

    #[test]
    fn payment_ttl_expires() {
        let a = acc("hub-ttl-a");
        let b = acc("hub-ttl-b");
        let mut limits = HubLimits::default();
        limits.payment_ttl_secs = 3600;
        let st = HubState::with_limits("HubA".into(), limits);
        st.register_channel(ch(0xaa, a.readable(), b.readable()))
            .unwrap();
        let pay = st
            .create_payment(CreatePaymentRequest {
                payer: a.readable().into(),
                payee: b.readable().into(),
                amount_hac: "1:247".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![],
                local_only: true,
            })
            .unwrap();
        st.force_payment_expires_unix(pay.id, 1); // far past
        assert_eq!(st.expire_stale_payments(), 1);
        let p = st.get_payment(pay.id).unwrap();
        assert_eq!(p.status, PaymentStatus::TimedOut);
    }

    fn bill_sign(account: &Account, message_hash_hex: &str) -> SignBillRequest {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hex::decode(message_hash_hex).unwrap());
        SignBillRequest {
            address: account.readable().to_string(),
            signature_hex: sign_payment_hash(account, &hash),
            public_key_hex: String::new(),
        }
    }

    #[test]
    fn last_bill_only_and_dispute_export() {
        let left = acc("bill-left");
        let right = acc("bill-right");
        let st = HubState::new("HubA".into(), 100, 8);
        st.register_channel(ch(0xdd, left.readable(), right.readable()))
            .unwrap();

        // Hub refuses empty invent
        let err = st
            .propose_bill(
                &format!("{:02x}", 0xdd).repeat(16),
                ProposeBillRequest {
                    sequence: 0,
                    left_hac: String::new(),
                    right_hac: String::new(),
                    left_satoshi: 0,
                    right_satoshi: 0,
                    payment_id: None,
                    notes: String::new(),
                    signatures: vec![],
                },
            )
            .unwrap_err();
        assert!(err.contains("invent") || err.contains("empty"), "{err}");

        let cid = format!("{:02x}", 0xdd).repeat(16);
        let b1 = st
            .propose_bill(
                &cid,
                ProposeBillRequest {
                    sequence: 0,
                    left_hac: "8:247".into(),
                    right_hac: "7:247".into(),
                    left_satoshi: 0,
                    right_satoshi: 0,
                    payment_id: None,
                    notes: "after pay".into(),
                    signatures: vec![],
                },
            )
            .unwrap();
        assert_eq!(b1.sequence, 1);
        assert_eq!(b1.status, BillStatus::CollectingSignatures);
        assert!(b1.message.starts_with("HACASH_L2_BILL_V1"));

        st.sign_bill(&cid, bill_sign(&left, &b1.message_hash_hex))
            .unwrap();
        let b1 = st
            .sign_bill(&cid, bill_sign(&right, &b1.message_hash_hex))
            .unwrap();
        assert_eq!(b1.status, BillStatus::Active);
        assert_eq!(st.bill_counts().0, 1);

        // Channel mirrors last active balances
        let ch = st.get_channel(&cid).unwrap();
        assert_eq!(ch.left_hac, "8:247");
        assert_eq!(ch.right_hac, "7:247");

        // Sequence 2 replaces (last only)
        let b2 = st
            .propose_bill(
                &cid,
                ProposeBillRequest {
                    sequence: 0,
                    left_hac: "5:247".into(),
                    right_hac: "10:247".into(),
                    left_satoshi: 0,
                    right_satoshi: 0,
                    payment_id: None,
                    notes: String::new(),
                    signatures: vec![],
                },
            )
            .unwrap();
        assert_eq!(b2.sequence, 2);
        assert_eq!(b2.prev_bill_hash, b1.message_hash_hex);
        // The unsigned candidate must not erase the last arbitration proof.
        let exp_during_draft = st.export_dispute(&cid, "127.0.0.1:8080").unwrap();
        assert!(exp_during_draft.bill_active);
        assert_eq!(exp_during_draft.last_bill.unwrap().sequence, 1);
        assert_eq!(st.list_bills().len(), 2);

        st.sign_bill(&cid, bill_sign(&left, &b2.message_hash_hex))
            .unwrap();
        let b2 = st
            .sign_bill(&cid, bill_sign(&right, &b2.message_hash_hex))
            .unwrap();
        assert_eq!(b2.status, BillStatus::Active);
        assert_eq!(st.list_bills().len(), 1); // still one bill slot
        assert_eq!(st.get_bill(&cid).unwrap().sequence, 2);
        assert_eq!(st.get_channel(&cid).unwrap().balance_source, "active_bill");

        let exp = st.export_dispute(&cid, "127.0.0.1:8080").unwrap();
        assert!(exp.bill_active);
        assert!(exp.fullnode_l1_query.contains(&cid));
        assert_eq!(exp.purpose, "l1_arbitration_evidence_package");
        let pack = exp.close_package.expect("close package");
        assert!(!pack.ready_for_l1_close);
        assert_eq!(pack.schema, "hacash-l2-close-package/1");
    }

    #[test]
    fn settle_updates_channel_balances_and_blocks_overpay() {
        let a = acc("bal-a");
        let b = acc("bal-b");
        let st = HubState::new("HubA".into(), 100, 8);
        // small channel: 3+2=5 mei total
        st.register_channel(RegisterChannelRequest {
            channel_id: format!("{:02x}", 0x77u8).repeat(16),
            left_address: a.readable().into(),
            right_address: b.readable().into(),
            left_hac: "3:247".into(),
            right_hac: "2:247".into(),
            left_satoshi: 0,
            right_satoshi: 0,
            hub_side: Some(HubSide::Right),
            notes: String::new(),
        })
        .unwrap();
        let pay = st
            .create_payment(CreatePaymentRequest {
                payer: a.readable().into(),
                payee: b.readable().into(),
                amount_hac: "2:247".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![],
                local_only: true,
            })
            .unwrap();
        let h = pay.message_hash_hex.clone();
        st.add_signature(pay.id, sign_req(&b, &h)).unwrap();
        let settled = st.add_signature(pay.id, sign_req(&a, &h)).unwrap();
        assert_eq!(settled.status, PaymentStatus::Settled);

        let ch = st.get_channel(&pay.route[0]).unwrap();
        assert_eq!(ch.balance_source, "payment_settle");
        // left 3-2=1, right 2+2=4
        assert_eq!(crate::amounts::parse_zhu(&ch.left_hac).unwrap(), 10_000_000);
        assert_eq!(
            crate::amounts::parse_zhu(&ch.right_hac).unwrap(),
            40_000_000
        );
        assert_eq!(ch.last_settle_payment_id, Some(settled.id));

        // Idempotent auto_bill
        let bills1 = st.auto_bill_after_settle(&settled).unwrap();
        let bills2 = st.auto_bill_after_settle(&settled).unwrap();
        assert_eq!(bills1.len(), bills2.len());
        assert_eq!(bills1[0].sequence, bills2[0].sequence);

        // Cannot pay 5 more from left (only 1 left)
        let err = st
            .create_payment(CreatePaymentRequest {
                payer: a.readable().into(),
                payee: b.readable().into(),
                amount_hac: "5:247".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![],
                local_only: true,
            })
            .unwrap_err();
        assert!(
            err.contains("liquidity") || err.contains("no path"),
            "{err}"
        );
    }

    #[test]
    fn verified_identity_shares_policy_principal() {
        let a = acc("pol-a");
        let b = acc("pol-b");
        let st = HubState::new("HubA".into(), 100, 8);
        st.register_channel(ch(0x55, a.readable(), b.readable()))
            .unwrap();
        // Register + mark verified identity for bot-1 at address of a
        let pk = hex::encode(a.public_key().serialize_compressed());
        st.register_identity(crate::agent_id::RegisterIdentityRequest {
            agent_id: "bot-1".into(),
            public_key_hex: pk.clone(),
            label: String::new(),
            contact: String::new(),
        })
        .unwrap();
        // Force verified (skip challenge) for unit test via second register path —
        // use verify with real challenge
        let ch = st.issue_identity_challenge("bot-1").unwrap();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hex::decode(&ch.message_hash_hex).unwrap());
        let sig = crate::crypto::sign_payment_hash(&a, &hash);
        st.verify_identity(crate::agent_id::VerifyIdentityRequest {
            agent_id: "bot-1".into(),
            challenge_id: ch.challenge_id.to_string(),
            signature_hex: sig,
            public_key_hex: pk,
        })
        .unwrap();

        let (p1, _) = st
            .agent_create_payment(
                CreatePaymentRequest {
                    payer: a.readable().into(),
                    payee: b.readable().into(),
                    amount_hac: "1:247".into(),
                    amount_satoshi: 0,
                    fee_hac: "0".into(),
                    route: vec![],
                    local_only: true,
                },
                "pol-key-1",
                crate::agent_pay::AgentPaymentMeta {
                    agent_id: "bot-1".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        let meta1 = st.get_payment_meta(p1.id);
        assert!(
            meta1.policy_principal.starts_with("v:"),
            "{}",
            meta1.policy_principal
        );
        assert_eq!(meta1.identity_address, a.readable());

        // Same verified key under different agent_id string is not auto-shared unless
        // that id is also verified — register bot-2 with same key and verify
        st.register_identity(crate::agent_id::RegisterIdentityRequest {
            agent_id: "bot-2".into(),
            public_key_hex: hex::encode(a.public_key().serialize_compressed()),
            label: String::new(),
            contact: String::new(),
        })
        .unwrap();
        let ch2 = st.issue_identity_challenge("bot-2").unwrap();
        let mut hash2 = [0u8; 32];
        hash2.copy_from_slice(&hex::decode(&ch2.message_hash_hex).unwrap());
        let sig2 = crate::crypto::sign_payment_hash(&a, &hash2);
        st.verify_identity(crate::agent_id::VerifyIdentityRequest {
            agent_id: "bot-2".into(),
            challenge_id: ch2.challenge_id.to_string(),
            signature_hex: sig2,
            public_key_hex: hex::encode(a.public_key().serialize_compressed()),
        })
        .unwrap();

        let (p2, _) = st
            .agent_create_payment(
                CreatePaymentRequest {
                    payer: a.readable().into(),
                    payee: b.readable().into(),
                    amount_hac: "1:247".into(),
                    amount_satoshi: 0,
                    fee_hac: "0".into(),
                    route: vec![],
                    local_only: true,
                },
                "pol-key-2",
                crate::agent_pay::AgentPaymentMeta {
                    agent_id: "bot-2".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        let meta2 = st.get_payment_meta(p2.id);
        assert_eq!(meta1.policy_principal, meta2.policy_principal);
        // Ledger counts under one principal (2 creates)
        let snap = st.ledger_snapshot();
        let entry = snap
            .iter()
            .find(|e| e.agent_id == meta1.policy_principal)
            .expect("principal ledger");
        assert_eq!(entry.payments_created, 2);
    }

    #[test]
    fn foreign_payment_notify_relevant_only() {
        let a = acc("fn-a");
        let b = acc("fn-b");
        let st = HubState::new("HubLocal".into(), 100, 8);
        let cid = format!("{:02x}", 0x44u8).repeat(16);
        st.register_channel(ch(0x44, a.readable(), b.readable()))
            .unwrap();
        let pid = Uuid::new_v4();
        let n = RemotePaymentNotify {
            origin_provider_id: "HubOrigin".into(),
            origin_public_url: "http://origin.example:9090".into(),
            payment_id: pid,
            payer: a.readable().into(),
            payee: b.readable().into(),
            amount_hac: "1:247".into(),
            amount_satoshi: 0,
            fee_hac: "0".into(),
            message_hash_hex: "ab".repeat(32),
            required_signers: vec![b.readable().into(), a.readable().into()],
            route: vec![cid.clone()],
            remote_hops: vec![RemoteHop {
                channel_id: cid,
                via_provider: "HubLocal".into(),
                public_url: Some("http://local.example:9090".into()),
                from_address: a.readable().into(),
                to_address: b.readable().into(),
            }],
            status: "collecting".into(),
            next_signer: b.readable().into(),
            expires_unix: 0,
            created_unix: now_unix(),
            sign_endpoint: "http://origin.example:9090/v1/agent/v1/sign".into(),
            status_endpoint: format!("http://origin.example:9090/v1/agent/v1/payment/{pid}"),
        };
        let fp = st.ingest_remote_payment_notify(n.clone()).unwrap();
        assert_eq!(fp.payment_id, pid);
        assert_eq!(st.foreign_payments_for_address(b.readable(), 10).len(), 1);

        // Irrelevant notify (other provider, no local channel) rejected
        let mut bad = n;
        bad.payment_id = Uuid::new_v4();
        bad.remote_hops[0].via_provider = "OtherHub".into();
        bad.route = vec![format!("{:02x}", 0x99u8).repeat(16)];
        let err = st.ingest_remote_payment_notify(bad).unwrap_err();
        assert!(err.contains("not relevant"), "{err}");
    }

    #[test]
    fn invoice_forces_amount_and_idempotency_content_bound() {
        let a = acc("inv-a");
        let b = acc("inv-b");
        let st = HubState::new("HubA".into(), 100, 8);
        st.register_channel(ch(0x33, a.readable(), b.readable()))
            .unwrap();
        let inv = st
            .create_invoice(crate::invoice::CreateInvoiceRequest {
                payee: b.readable().into(),
                payer_hint: a.readable().into(),
                amount_hac: "3:247".into(),
                amount_satoshi: 0,
                description: "test".into(),
                ttl_secs: 3600,
                meta: Default::default(),
                callback_url: String::new(),
            })
            .unwrap();
        // Underpay attempt rejected
        let err = st
            .agent_create_payment_ex(
                CreatePaymentRequest {
                    payer: a.readable().into(),
                    payee: b.readable().into(),
                    amount_hac: "1:247".into(),
                    amount_satoshi: 0,
                    fee_hac: "0".into(),
                    route: vec![],
                    local_only: true,
                },
                "idem-inv-1",
                Default::default(),
                Some(inv.id),
                "",
            )
            .unwrap_err();
        assert!(err.contains("mismatch"), "{err}");

        // Correct amount (or omit via 0) — force invoice amount
        let (p, replay) = st
            .agent_create_payment_ex(
                CreatePaymentRequest {
                    payer: a.readable().into(),
                    payee: b.readable().into(),
                    amount_hac: "0".into(),
                    amount_satoshi: 0,
                    fee_hac: "0".into(),
                    route: vec![],
                    local_only: true,
                },
                "idem-inv-2",
                Default::default(),
                Some(inv.id),
                "",
            )
            .unwrap();
        assert!(!replay);
        assert_eq!(p.amount_hac, "3:247");

        // Same key + same body → replay
        let (p2, replay2) = st
            .agent_create_payment_ex(
                CreatePaymentRequest {
                    payer: a.readable().into(),
                    payee: b.readable().into(),
                    amount_hac: "0".into(),
                    amount_satoshi: 0,
                    fee_hac: "0".into(),
                    route: vec![],
                    local_only: true,
                },
                "idem-inv-2",
                Default::default(),
                Some(inv.id),
                "",
            )
            .unwrap();
        assert!(replay2);
        assert_eq!(p.id, p2.id);

        // Same key + different amount without invoice → conflict
        let (p3, _) = st
            .agent_create_payment(
                CreatePaymentRequest {
                    payer: a.readable().into(),
                    payee: b.readable().into(),
                    amount_hac: "1:247".into(),
                    amount_satoshi: 0,
                    fee_hac: "0".into(),
                    route: vec![],
                    local_only: true,
                },
                "idem-body-1",
                Default::default(),
            )
            .unwrap();
        let err2 = st
            .agent_create_payment(
                CreatePaymentRequest {
                    payer: a.readable().into(),
                    payee: b.readable().into(),
                    amount_hac: "2:247".into(),
                    amount_satoshi: 0,
                    fee_hac: "0".into(),
                    route: vec![],
                    local_only: true,
                },
                "idem-body-1",
                Default::default(),
            )
            .unwrap_err();
        assert!(err2.contains("idempotency_conflict"), "{err2}");
        assert_eq!(p3.amount_hac, "1:247");
    }

    #[test]
    fn rebalance_and_deferred() {
        let a = acc("reb-a");
        let b = acc("reb-b");
        let c = acc("reb-c");
        let st = HubState::new("HubA".into(), 100, 8);
        st.register_channel(ch(0x21, a.readable(), b.readable()))
            .unwrap();
        st.register_channel(ch(0x22, b.readable(), c.readable()))
            .unwrap();
        let r = st
            .propose_rebalance(ProposeRebalanceRequest {
                channel_a: format!("{:02x}", 0x21u8).repeat(16),
                channel_b: format!("{:02x}", 0x22u8).repeat(16),
                amount_mei: 10,
                amount_satoshi: 0,
                note: "shift".into(),
            })
            .unwrap();
        assert_eq!(r.status, RebalanceStatus::Proposed);

        let d = st
            .create_deferred(CreateDeferredRequest {
                payer: a.readable().into(),
                payee: b.readable().into(),
                amount_hac: "1:247".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                execute_after_unix: now_unix().saturating_sub(10), // past → Ready
                local_only: true,
                route: vec![],
                note: "later".into(),
            })
            .unwrap();
        assert!(matches!(
            d.status,
            DeferredStatus::Ready | DeferredStatus::Scheduled
        ));
        let (_d2, pay) = st.promote_deferred(d.id).unwrap();
        assert_eq!(pay.payer, a.readable());
    }

    #[test]
    fn human_payment_idempotency_is_content_bound() {
        let payer = acc("human-idempotency-payer");
        let payee = acc("human-idempotency-payee");
        let state = HubState::new("HubA".into(), 100, 8);
        state
            .register_channel(ch(0x10, payer.readable(), payee.readable()))
            .unwrap();
        let request = CreatePaymentRequest {
            payer: payer.readable().into(),
            payee: payee.readable().into(),
            amount_hac: "1:247".into(),
            amount_satoshi: 0,
            fee_hac: "0".into(),
            route: vec![],
            local_only: true,
        };

        let (first, first_replay) = state
            .create_distributed_payment_idempotent(
                request.clone(),
                "wallet-request-1",
                payer.readable(),
            )
            .unwrap();
        let (second, second_replay) = state
            .create_distributed_payment_idempotent(
                request.clone(),
                "wallet-request-1",
                payer.readable(),
            )
            .unwrap();
        assert!(!first_replay);
        assert!(second_replay);
        assert_eq!(first.id, second.id);

        let mut conflicting = request;
        conflicting.amount_hac = "2:247".into();
        let error = state
            .create_distributed_payment_idempotent(
                conflicting,
                "wallet-request-1",
                payer.readable(),
            )
            .unwrap_err();
        assert!(error.contains("idempotency_conflict"), "{error}");
    }

    #[test]
    fn agent_idempotent_pay_and_receipt() {
        let a = acc("agent-pay-a");
        let b = acc("agent-pay-b");
        let st = HubState::new("HubA".into(), 100, 8);
        st.register_channel(ch(0x11, a.readable(), b.readable()))
            .unwrap();
        let req = CreatePaymentRequest {
            payer: a.readable().into(),
            payee: b.readable().into(),
            amount_hac: "1:247".into(),
            amount_satoshi: 0,
            fee_hac: "0".into(),
            route: vec![],
            local_only: true,
        };
        let meta = crate::agent_pay::AgentPaymentMeta {
            agent_id: "bot-1".into(),
            purpose: "test".into(),
            invoice_id: "inv1".into(),
            ..Default::default()
        };
        let (p1, replay1) = st
            .agent_create_payment(req.clone(), "key-1", meta.clone())
            .unwrap();
        assert!(!replay1);
        let (p2, replay2) = st.agent_create_payment(req, "key-1", meta).unwrap();
        assert!(replay2);
        assert_eq!(p1.id, p2.id);

        // sign both → receipt
        let h = p1.message_hash_hex.clone();
        st.add_signature(p1.id, sign_req(&b, &h)).unwrap();
        let p = st.add_signature(p1.id, sign_req(&a, &h)).unwrap();
        assert_eq!(p.status, PaymentStatus::Settled);
        let r = st.get_receipt(p.id).unwrap();
        assert_eq!(r.status, "settled");
        assert_eq!(r.receipt_hash_hex.len(), 64);
        assert_eq!(r.meta.agent_id, "bot-1");
    }

    #[test]
    fn reject_lower_sequence() {
        let left = acc("bill-seq-l");
        let right = acc("bill-seq-r");
        let st = HubState::new("HubA".into(), 100, 8);
        let cid = format!("{:02x}", 0xee).repeat(16);
        st.register_channel(ch(0xee, left.readable(), right.readable()))
            .unwrap();
        // Channel ch() has 10+5=15 mei total — bills must conserve
        let b = st
            .propose_bill(
                &cid,
                ProposeBillRequest {
                    sequence: 5,
                    left_hac: "10:247".into(),
                    right_hac: "5:247".into(),
                    left_satoshi: 0,
                    right_satoshi: 0,
                    payment_id: None,
                    notes: String::new(),
                    signatures: vec![],
                },
            )
            .unwrap();
        st.sign_bill(&cid, bill_sign(&left, &b.message_hash_hex))
            .unwrap();
        st.sign_bill(&cid, bill_sign(&right, &b.message_hash_hex))
            .unwrap();
        let err = st
            .propose_bill(
                &cid,
                ProposeBillRequest {
                    sequence: 3,
                    left_hac: "8:247".into(),
                    right_hac: "7:247".into(),
                    left_satoshi: 0,
                    right_satoshi: 0,
                    payment_id: None,
                    notes: String::new(),
                    signatures: vec![],
                },
            )
            .unwrap_err();
        assert!(err.contains("sequence"), "{err}");
    }

    #[test]
    fn reservations_prevent_double_spend_and_release_on_cancel() {
        let payer = acc("reserve-payer");
        let payee = acc("reserve-payee");
        let st = HubState::new("HubA".into(), 100, 8);
        st.register_channel(ch(0x61, payer.readable(), payee.readable()))
            .unwrap();

        let first = st
            .create_payment(CreatePaymentRequest {
                payer: payer.readable().into(),
                payee: payee.readable().into(),
                amount_hac: "8:247".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![],
                local_only: true,
            })
            .unwrap();
        let blocked = st
            .create_payment(CreatePaymentRequest {
                payer: payer.readable().into(),
                payee: payee.readable().into(),
                amount_hac: "3:247".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![],
                local_only: true,
            })
            .unwrap_err();
        assert!(blocked.contains("unreserved"), "{blocked}");

        st.cancel_payment(first.id, payer.readable()).unwrap();
        st.create_payment(CreatePaymentRequest {
            payer: payer.readable().into(),
            payee: payee.readable().into(),
            amount_hac: "3:247".into(),
            amount_satoshi: 0,
            fee_hac: "0".into(),
            route: vec![],
            local_only: true,
        })
        .unwrap();
    }

    #[test]
    fn multi_hop_settlement_rolls_back_every_hop_on_preflight_failure() {
        let a = acc("atomic-a");
        let b = acc("atomic-b");
        let c = acc("atomic-c");
        let st = HubState::new("HubA".into(), 100, 8);
        let first_cid = format!("{:02x}", 0x62).repeat(16);
        let second_cid = format!("{:02x}", 0x63).repeat(16);
        st.register_channel(ch(0x62, a.readable(), b.readable()))
            .unwrap();
        st.register_channel(ch(0x63, b.readable(), c.readable()))
            .unwrap();
        let pay = st
            .create_payment(CreatePaymentRequest {
                payer: a.readable().into(),
                payee: c.readable().into(),
                amount_hac: "2:247".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![],
                local_only: true,
            })
            .unwrap();

        // Simulate corrupted/stale storage after reservation. Atomic preflight
        // must catch this without changing the already-checked first channel.
        {
            let mut g = st.inner.write().unwrap();
            g.channels.get_mut(&second_cid).unwrap().left_hac = "1:247".into();
        }
        st.add_signature(pay.id, sign_req(&c, &pay.message_hash_hex))
            .unwrap();
        st.add_signature(pay.id, sign_req(&b, &pay.message_hash_hex))
            .unwrap();
        let err = st
            .add_signature(pay.id, sign_req(&a, &pay.message_hash_hex))
            .unwrap_err();
        assert!(err.contains("atomic settlement failed"), "{err}");
        let first = st.get_channel(&first_cid).unwrap();
        assert_eq!(first.left_hac, "1:248");
        assert_eq!(first.right_hac, "5:247");
        assert_eq!(
            st.get_payment(pay.id).unwrap().status,
            PaymentStatus::CollectingSignatures
        );
    }

    #[test]
    fn settled_payment_is_applied_exactly_once() {
        let a = acc("once-a");
        let b = acc("once-b");
        let st = HubState::new("HubA".into(), 100, 8);
        let cid = format!("{:02x}", 0x64).repeat(16);
        st.register_channel(ch(0x64, a.readable(), b.readable()))
            .unwrap();
        let pay = st
            .create_payment(CreatePaymentRequest {
                payer: a.readable().into(),
                payee: b.readable().into(),
                amount_hac: "2:247".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![],
                local_only: true,
            })
            .unwrap();
        st.add_signature(pay.id, sign_req(&b, &pay.message_hash_hex))
            .unwrap();
        let settled = st
            .add_signature(pay.id, sign_req(&a, &pay.message_hash_hex))
            .unwrap();
        let once = st.get_channel(&cid).unwrap();
        st.auto_bill_after_settle(&settled).unwrap();
        st.auto_bill_after_settle(&settled).unwrap();
        let repeated = st.get_channel(&cid).unwrap();
        assert_eq!(once.left_hac, repeated.left_hac);
        assert_eq!(once.right_hac, repeated.right_hac);
    }

    #[test]
    fn interleaved_distributed_settlements_are_not_shifted_again_by_bill_drafts() {
        let payer = acc("distributed-concurrent-payer");
        let payee = acc("distributed-concurrent-payee");
        let st = HubState::new("HubA".into(), 100, 8);
        let cid = format!("{:02x}", 0x65).repeat(16);
        st.register_channel(ch(0x65, payer.readable(), payee.readable()))
            .unwrap();

        let create = || {
            st.create_payment(CreatePaymentRequest {
                payer: payer.readable().into(),
                payee: payee.readable().into(),
                amount_hac: "1:247".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![cid.clone()],
                local_only: true,
            })
            .unwrap()
        };
        let first = create();
        let second = create();
        let amount_zhu = crate::amounts::parse_zhu("1:247").unwrap();
        let first_hops = st.payment_reservation(first.id).unwrap().hops;
        let second_hops = st.payment_reservation(second.id).unwrap().hops;

        st.apply_distributed_settlement(first.id, amount_zhu, 0, &first_hops)
            .unwrap();
        st.apply_distributed_settlement(second.id, amount_zhu, 0, &second_hops)
            .unwrap();
        let after_application = st.get_channel(&cid).unwrap();
        assert_eq!(after_application.left_hac, "8:247");
        assert_eq!(after_application.right_hac, "7:247");

        st.mark_distributed_settled(first.id).unwrap();
        st.mark_distributed_settled(second.id).unwrap();
        let after_bill_drafts = st.get_channel(&cid).unwrap();
        assert_eq!(after_bill_drafts.left_hac, after_application.left_hac);
        assert_eq!(after_bill_drafts.right_hac, after_application.right_hac);
    }
    #[test]
    fn agent_intent_nonce_allows_only_same_idempotent_retry() {
        let st = HubState::new("HubA".into(), 100, 8);
        let now = now_unix();
        assert!(st
            .claim_agent_intent("agent-1", "nonce-0123456789", "key-a", now + 60)
            .unwrap());
        assert!(!st
            .claim_agent_intent("agent-1", "nonce-0123456789", "key-a", now + 60)
            .unwrap());
        let err = st
            .claim_agent_intent("agent-1", "nonce-0123456789", "key-b", now + 60)
            .unwrap_err();
        assert!(err.contains("already used"), "{err}");
        st.release_agent_intent("agent-1", "nonce-0123456789", "key-a");
        assert!(st
            .claim_agent_intent("agent-1", "nonce-0123456789", "key-b", now + 60)
            .unwrap());
    }

    #[test]
    fn operator_scopes_and_revocation_are_enforced_by_state() {
        let account = acc("agent-scope-control");
        let state = HubState::new("HubA".into(), 100, 8);
        let public_key_hex = hex::encode(account.public_key().serialize_compressed());
        state
            .register_identity(crate::agent_id::RegisterIdentityRequest {
                agent_id: "controlled-agent".into(),
                public_key_hex: public_key_hex.clone(),
                label: String::new(),
                contact: String::new(),
            })
            .unwrap();
        let challenge = state.issue_identity_challenge("controlled-agent").unwrap();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hex::decode(&challenge.message_hash_hex).unwrap());
        state
            .verify_identity(crate::agent_id::VerifyIdentityRequest {
                agent_id: "controlled-agent".into(),
                challenge_id: challenge.challenge_id.to_string(),
                signature_hex: crate::crypto::sign_payment_hash(&account, &hash),
                public_key_hex,
            })
            .unwrap();

        let scoped = state
            .set_identity_scopes("controlled-agent", &["micro".into()])
            .unwrap();
        assert!(scoped.allows("micro"));
        assert!(!scoped.allows("pay"));
        let error = state
            .agent_create_payment(
                CreatePaymentRequest {
                    payer: account.readable().into(),
                    payee: "payee".into(),
                    amount_hac: "1:248".into(),
                    amount_satoshi: 0,
                    fee_hac: "0".into(),
                    route: vec![],
                    local_only: true,
                },
                "scope-denied",
                crate::agent_pay::AgentPaymentMeta {
                    agent_id: "controlled-agent".into(),
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(error.contains("pay") && error.contains("scope"), "{error}");

        let revoked = state.revoke_identity("controlled-agent").unwrap();
        assert!(revoked.revoked);
        assert!(!revoked.allows("micro"));
        let error = state
            .issue_identity_challenge("controlled-agent")
            .unwrap_err();
        assert!(error.contains("revoked"), "{error}");
    }
    #[test]
    fn l1_anchor_and_sequence_one_shadow_are_bound_without_reusing_v1_signatures() {
        let left = acc("shadow-v2-left");
        let right = acc("shadow-v2-right");
        let channel_id = "d1".repeat(16);
        let state = HubState::new("HubA".into(), 100, 8);
        state
            .register_channel(ch(0xd1, left.readable(), right.readable()))
            .unwrap();
        let observation = l1_observation(&channel_id, &left, &right, 0, 100, 200);
        let expected_anchor = observation.anchor.funding_incarnation_hash_hex.clone();
        state
            .apply_l1_channel_observation(&channel_id, observation)
            .unwrap();
        let bill = activate_bill(&state, &channel_id, &left, &right, 1);

        let draft = state.channel_state_shadow_v2(&channel_id).unwrap();
        assert_eq!(draft.commitment.sequence, 1);
        assert!(draft.commitment.previous_state_hash_hex.is_empty());
        assert_eq!(draft.commitment.funding_anchor_hash_hex, expected_anchor);
        assert_eq!(draft.source_v1_bill_message_hash_hex, bill.message_hash_hex);
        assert!(!draft.source_v1_signatures_reused);
        assert_eq!(
            draft.state_hash_hex,
            draft.commitment.state_hash_hex().unwrap()
        );

        let stale = l1_observation(&channel_id, &left, &right, 0, 100, 199);
        assert!(state
            .apply_l1_channel_observation(&channel_id, stale)
            .unwrap_err()
            .contains("stale"));
        let reused = l1_observation(&channel_id, &left, &right, 1, 300, 350);
        assert!(state
            .apply_l1_channel_observation(&channel_id, reused)
            .unwrap_err()
            .contains("re-registration"));
    }

    #[test]
    fn later_shadow_sequence_requires_one_mutually_signed_v2_predecessor() {
        use crate::channel_state::sign_channel_state;

        let left = acc("shadow-v2-predecessor-left");
        let right = acc("shadow-v2-predecessor-right");
        let channel_id = "d2".repeat(16);
        let state = HubState::new("HubA".into(), 100, 8);
        state
            .register_channel(ch(0xd2, left.readable(), right.readable()))
            .unwrap();
        state
            .apply_l1_channel_observation(
                &channel_id,
                l1_observation(&channel_id, &left, &right, 0, 100, 200),
            )
            .unwrap();
        activate_bill(&state, &channel_id, &left, &right, 2);

        let error = state.channel_state_shadow_v2(&channel_id).unwrap_err();
        assert!(error.contains("mutually signed V2 predecessor"), "{error}");

        let anchor = state.get_channel(&channel_id).unwrap().l1_anchor.unwrap();
        let predecessor_commitment = ChannelStateCommitmentV2 {
            schema_version: CHANNEL_STATE_SCHEMA_V2,
            network_genesis_hash_hex: anchor.network_genesis_hash_hex.clone(),
            channel_id: channel_id.clone(),
            funding_anchor_hash_hex: anchor.funding_incarnation_hash_hex.clone(),
            sequence: 1,
            previous_state_hash_hex: String::new(),
            left_address: left.readable().to_string(),
            right_address: right.readable().to_string(),
            left_hac_zhu: crate::amounts::parse_zhu("1:248").unwrap(),
            right_hac_zhu: crate::amounts::parse_zhu("5:247").unwrap(),
            left_satoshi: 0,
            right_satoshi: 0,
            funded_hac_zhu: anchor.funded_hac_zhu().unwrap(),
            funded_satoshi: 0,
            conditional_state_root_hex: String::new(),
            expiry_unix: 0,
        };
        let mut predecessor = sign_channel_state(&left, predecessor_commitment.clone()).unwrap();
        predecessor.signatures.extend(
            sign_channel_state(&right, predecessor_commitment)
                .unwrap()
                .signatures,
        );
        predecessor.validate().unwrap();
        let predecessor_hash = predecessor.state_hash_hex.clone();
        state
            .observe_channel_state_v2(&channel_id, predecessor)
            .unwrap();

        let draft = state.channel_state_shadow_v2(&channel_id).unwrap();
        assert_eq!(draft.commitment.sequence, 2);
        assert_eq!(draft.commitment.previous_state_hash_hex, predecessor_hash);
        assert!(!draft.source_v1_signatures_reused);
    }
}
