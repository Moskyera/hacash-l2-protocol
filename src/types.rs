//! Shared types for the L2 hub API (v1 + Phase 2 hub network).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Channels
// ---------------------------------------------------------------------------

/// Local registration of a channel this hub services (mirrors L1 after open).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalChannel {
    /// 16-byte Hacash L1 channel id as hex (32 chars).
    pub channel_id: String,
    pub left_address: String,
    pub right_address: String,
    pub left_hac: String,
    pub right_hac: String,
    pub left_satoshi: u64,
    pub right_satoshi: u64,
    pub l1_status: Option<u8>,
    pub open_height: Option<u64>,
    /// Versioned binding to one concrete L1 channel incarnation. Missing on
    /// legacy registrations until an exact fullnode refresh succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l1_anchor: Option<crate::l1_anchor::L1ChannelAnchorV1>,
    pub hub_side: HubSide,
    pub notes: String,
    pub registered_unix: u64,
    /// Where hub balances came from: `registration` | `payment_settle` | `active_bill`.
    #[serde(default = "default_balance_source")]
    pub balance_source: String,
    /// Last payment whose settle shift was applied (idempotent multi-hop).
    #[serde(default)]
    pub last_settle_payment_id: Option<Uuid>,
}

fn default_balance_source() -> String {
    "registration".into()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum HubSide {
    Left,
    Right,
    #[default]
    Unknown,
}

// ---------------------------------------------------------------------------
// Peers / hub network
// ---------------------------------------------------------------------------

/// Another hub in the Channel Service Provider network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHub {
    pub provider_id: String,
    /// Base URL this peer can be reached at (e.g. http://1.2.3.4:9090).
    pub public_url: String,
    pub name: String,
    /// Advertised channel edges (for multi-hop routing across hubs).
    pub channels: Vec<AdvertisedChannel>,
    pub last_seen_unix: u64,
    pub reachable: bool,
    /// Phase 3: capability flags for wallet / agent discovery.
    /// True only when the last direct hello carried a signature that the
    /// networking layer accepted. Distributed settlement requires this pin.
    #[serde(default)]
    pub identity_verified: bool,
    #[serde(default)]
    pub meta: HubMeta,
}

/// Optional hub metadata advertised in hello (Phase 3 + global mesh).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubMeta {
    /// Listed in public wallet "Find hubs" results.
    #[serde(default = "default_true")]
    pub public: bool,
    /// Wallet clients may connect for fast pay.
    #[serde(default = "default_true")]
    pub accepts_wallets: bool,
    /// AI agents may attach and create payments.
    #[serde(default = "default_true")]
    pub accepts_agents: bool,
    /// Free-form region hint (eu, us, asia, …).
    #[serde(default)]
    pub region: String,
    /// Human fee hint (not enforced on-chain).
    #[serde(default)]
    pub fee_hint: String,
    /// Operator contact / notes for agents.
    #[serde(default)]
    pub contact: String,
    /// Protocol version string advertised to peers (e.g. "1.0").
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String,
    /// Hub process start unix (uptime for discovery scoring).
    #[serde(default)]
    pub started_unix: u64,
    /// Flat routing fee in HAC mei integer part (hint for path selection).
    #[serde(default)]
    pub fee_base_mei: u64,
    /// Parts-per-million fee on amount (1_000_000 = 100%). Hint only.
    #[serde(default)]
    pub fee_ppm: u64,
    /// Sum of local channel HAC mei capacity advertised (hint).
    #[serde(default)]
    pub total_capacity_mei: u64,
    /// Max single-channel capacity mei (hint).
    #[serde(default)]
    pub max_channel_capacity_mei: u64,
    /// Number of local channels this hub services.
    #[serde(default)]
    pub channel_count: usize,
    /// Capability feature flags for mesh discovery.
    #[serde(default)]
    pub features: Vec<String>,
    /// Hacash address of hub operator identity (derived from identity key).
    #[serde(default)]
    pub identity_address: String,
    /// Compressed secp256k1 pubkey hex (33 bytes) for verifying signed hellos.
    #[serde(default)]
    pub identity_pubkey_hex: String,
}

fn default_true() -> bool {
    true
}

fn default_protocol_version() -> String {
    "1.0".into()
}

impl Default for HubMeta {
    fn default() -> Self {
        Self {
            public: true,
            accepts_wallets: true,
            accepts_agents: true,
            region: String::new(),
            fee_hint: String::new(),
            contact: String::new(),
            protocol_version: default_protocol_version(),
            started_unix: 0,
            fee_base_mei: 0,
            fee_ppm: 0,
            total_capacity_mei: 0,
            max_channel_capacity_mei: 0,
            channel_count: 0,
            features: Vec::new(),
            identity_address: String::new(),
            identity_pubkey_hex: String::new(),
        }
    }
}

/// Structured fee schedule (CSP market — whitepaper fee hints).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeSchedule {
    pub fee_base_mei: u64,
    pub fee_ppm: u64,
    pub fee_hint: String,
    pub currency: &'static str,
    pub note: &'static str,
}

impl FeeSchedule {
    /// Estimate fee mei for a payment amount (integer mei + ppm).
    pub fn estimate_mei(&self, amount_mei: u64) -> u64 {
        let ppm_part = amount_mei.saturating_mul(self.fee_ppm) / 1_000_000;
        self.fee_base_mei.saturating_add(ppm_part)
    }

    /// Exact fee in Zhu. `fee_base_mei` is whole HAC (unit 248), while the
    /// proportional component is calculated from the exact Zhu amount.
    pub fn estimate_zhu(&self, amount_zhu: u64) -> Result<u64, String> {
        let base_zhu = (self.fee_base_mei as u128)
            .checked_mul(crate::amounts::ZHU_PER_MEI as u128)
            .ok_or("fee base overflow")?;
        let ppm_zhu = (amount_zhu as u128)
            .checked_mul(self.fee_ppm as u128)
            .ok_or("proportional fee overflow")?
            / 1_000_000u128;
        let total = base_zhu.checked_add(ppm_zhu).ok_or("fee overflow")?;
        u64::try_from(total).map_err(|_| "fee exceeds the L2 u64 Zhu range".to_string())
    }
}

/// Compact channel edge shared between hubs for routing + capacity hints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvertisedChannel {
    pub channel_id: String,
    pub left_address: String,
    pub right_address: String,
    /// Provider id of the hub that advertised this edge.
    pub via_provider: String,
    /// Total HAC mei locked on channel (left+right) — capacity for routing filters.
    #[serde(default)]
    pub capacity_mei: u64,
    /// Available on left side (mei) if known; 0 = unknown / not published.
    #[serde(default)]
    pub left_available_mei: u64,
    /// Available on right side (mei) if known.
    #[serde(default)]
    pub right_available_mei: u64,
    /// Exact total capacity in Zhu (10^-8 HAC). Protocol v2 peers prefer this.
    #[serde(default)]
    pub capacity_zhu: u64,
    /// Exact available liquidity on the left side in Zhu.
    #[serde(default)]
    pub left_available_zhu: u64,
    /// Exact available liquidity on the right side in Zhu.
    #[serde(default)]
    pub right_available_zhu: u64,
    /// Per-channel fee ppm override (0 = use hub meta fee_ppm).
    #[serde(default)]
    pub fee_ppm: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHello {
    pub provider_id: String,
    pub public_url: String,
    pub name: String,
    #[serde(default)]
    pub channels: Vec<AdvertisedChannel>,
    /// Optional list of other peers this hub knows (gossip).
    #[serde(default)]
    pub known_peers: Vec<PeerSeed>,
    #[serde(default)]
    pub meta: HubMeta,
    /// Unix time when this hello was built (replay window for signed hellos).
    #[serde(default)]
    pub timestamp_unix: u64,
    /// Compressed pubkey hex signing this hello (optional; empty = unsigned lab mode).
    #[serde(default)]
    pub identity_pubkey_hex: String,
    /// Operator address derived from identity key.
    #[serde(default)]
    pub identity_address: String,
    /// 64-byte ECDSA sig hex over hello message hash, or 97-byte Sign hex.
    #[serde(default)]
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSeed {
    pub provider_id: String,
    pub public_url: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Deserialize)]
pub struct BootstrapPeerRequest {
    /// Base URL of a seed hub, e.g. http://127.0.0.1:9091
    pub url: String,
}

/// Proactive announce: introduce self to a remote hub (same as hello, named for ops).
#[derive(Debug, Deserialize)]
pub struct AnnounceRequest {
    /// Target peer base URL to announce to.
    pub url: String,
}

/// Load / refresh community seeds from remote JSON URL.
#[derive(Debug, Deserialize)]
pub struct BootstrapSeedsRequest {
    /// Optional override URL; empty = use configured seeds_url / local file.
    #[serde(default)]
    pub url: String,
}

// ---------------------------------------------------------------------------
// Payments
// ---------------------------------------------------------------------------

/// Off-chain payment session (instant payment coordination).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentSession {
    pub id: Uuid,
    pub status: PaymentStatus,
    /// What "settled" means on this hub — never L1 final by itself.
    ///
    /// `hub_coordinated` = all required ordered signatures collected here.
    /// Real L1 finality only after ChannelClose / arbitration on fullnode.
    #[serde(default = "default_finality")]
    pub finality: String,
    /// Canonical UTF-8 message all parties must sign (Phase B).
    #[serde(default)]
    pub message: String,
    /// SHA3-256 hex of `message` (32 bytes) — feed to secp256k1 sign.
    #[serde(default)]
    pub message_hash_hex: String,
    /// Ordered hop list: channel_id hex along the path.
    pub route: Vec<String>,
    /// Ordered multi-sig: payee → intermediates → payer (whitepaper-style).
    pub required_signers: Vec<String>,
    pub payer: String,
    pub payee: String,
    pub amount_hac: String,
    pub amount_satoshi: u64,
    pub fee_hac: String,
    pub created_unix: u64,
    pub updated_unix: u64,
    /// Session expires if still collecting after this unix time.
    #[serde(default)]
    pub expires_unix: u64,
    pub last_error: Option<String>,
    pub signatures: Vec<PaymentSignature>,
    /// Hops that cross remote hubs (for agents / multi-hub coordination).
    pub remote_hops: Vec<RemoteHop>,
}

fn default_finality() -> String {
    "hub_coordinated_not_l1".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteHop {
    pub channel_id: String,
    pub via_provider: String,
    pub public_url: Option<String>,
    /// Direction committed by the origin route; participants reserve exactly this side.
    #[serde(default)]
    pub from_address: String,
    /// Counterparty reached after this hop.
    #[serde(default)]
    pub to_address: String,
}

/// Hub-to-hub: origin notifies remote CSPs about a multi-hop payment involving their channels.
/// Session of truth stays on **origin**; remotes only mirror for agent inbox discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemotePaymentNotify {
    pub origin_provider_id: String,
    pub origin_public_url: String,
    pub payment_id: Uuid,
    pub payer: String,
    pub payee: String,
    pub amount_hac: String,
    #[serde(default)]
    pub amount_satoshi: u64,
    #[serde(default)]
    pub fee_hac: String,
    pub message_hash_hex: String,
    pub required_signers: Vec<String>,
    pub route: Vec<String>,
    #[serde(default)]
    pub remote_hops: Vec<RemoteHop>,
    /// collecting | settled | failed | timed_out
    pub status: String,
    /// Next address that must sign (empty when done).
    #[serde(default)]
    pub next_signer: String,
    #[serde(default)]
    pub expires_unix: u64,
    #[serde(default)]
    pub created_unix: u64,
    /// Always origin: agents must POST signatures here (not to remote).
    pub sign_endpoint: String,
    pub status_endpoint: String,
}

/// Local mirror of a payment owned by another hub (notify only — no local settle authority).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForeignPayment {
    pub origin_provider_id: String,
    pub origin_public_url: String,
    pub payment_id: Uuid,
    pub payer: String,
    pub payee: String,
    pub amount_hac: String,
    pub amount_satoshi: u64,
    pub fee_hac: String,
    pub message_hash_hex: String,
    pub required_signers: Vec<String>,
    pub route: Vec<String>,
    pub status: String,
    pub next_signer: String,
    pub expires_unix: u64,
    pub created_unix: u64,
    pub sign_endpoint: String,
    pub status_endpoint: String,
    pub notified_unix: u64,
    pub updated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentSignature {
    pub address: String,
    /// Prefer 97-byte Hacash Sign hex (pubkey||sig); may store 64-byte sig only.
    pub signature_hex: String,
    /// Compressed pubkey hex (33 bytes) when not packed into signature_hex.
    #[serde(default)]
    pub public_key_hex: String,
    pub signed_unix: u64,
    /// Index in required_signers when accepted (0 = first / payee side).
    pub order_index: usize,
    /// true when secp256k1 verified against message_hash (Phase B).
    #[serde(default)]
    pub verified: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    Pending,
    CollectingSignatures,
    /// Signatures are complete and a durable cross-hub commit is being delivered.
    /// This state must never be timed out or cancelled.
    Committing,
    /// All ordered signatures collected on this hub.
    /// **Not** L1 ChannelClose — see `finality` and SECURITY.md.
    Settled,
    Failed,
    TimedOut,
}

#[derive(Debug, Deserialize)]
pub struct RegisterChannelRequest {
    pub channel_id: String,
    pub left_address: String,
    pub right_address: String,
    #[serde(default)]
    pub left_hac: String,
    #[serde(default)]
    pub right_hac: String,
    #[serde(default)]
    pub left_satoshi: u64,
    #[serde(default)]
    pub right_satoshi: u64,
    #[serde(default)]
    pub hub_side: Option<HubSide>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreatePaymentRequest {
    pub payer: String,
    pub payee: String,
    pub amount_hac: String,
    #[serde(default)]
    pub amount_satoshi: u64,
    #[serde(default)]
    pub fee_hac: String,
    /// Explicit route of channel_id hex. Empty = auto multi-hop search.
    #[serde(default)]
    pub route: Vec<String>,
    /// Prefer path using only local channels (true) or full hub network graph.
    #[serde(default)]
    pub local_only: bool,
}

#[derive(Debug, Deserialize)]
pub struct SignPaymentRequest {
    /// Readable Hacash address (must match derived address of the public key).
    pub address: String,
    /// 97-byte Sign hex (pubkey||sig) **or** 64-byte signature hex.
    pub signature_hex: String,
    /// Required when signature_hex is only 64 bytes (33-byte compressed pubkey hex).
    #[serde(default)]
    pub public_key_hex: String,
}

// ---------------------------------------------------------------------------
// Phase C — reconciliation bills (last bill only per channel)
// ---------------------------------------------------------------------------

/// Last agreed (or collecting) reconciliation bill for one channel.
/// Whitepaper: only the **latest** bill is kept; history is discarded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelBill {
    pub channel_id: String,
    /// Strictly increasing; new bill must have sequence > previous active.
    pub sequence: u64,
    pub status: BillStatus,
    pub left_address: String,
    pub right_address: String,
    pub left_hac: String,
    pub right_hac: String,
    pub left_satoshi: u64,
    pub right_satoshi: u64,
    /// Hash of previous active bill (empty for sequence 1 / first).
    #[serde(default)]
    pub prev_bill_hash: String,
    /// Canonical message both parties sign.
    #[serde(default)]
    pub message: String,
    /// SHA3-256 hex of `message`.
    #[serde(default)]
    pub message_hash_hex: String,
    /// left then right (both required for Active).
    pub required_signers: Vec<String>,
    pub signatures: Vec<PaymentSignature>,
    pub created_unix: u64,
    pub updated_unix: u64,
    /// Optional payment that motivated this reconciliation.
    #[serde(default)]
    pub payment_id: Option<Uuid>,
    #[serde(default)]
    pub notes: String,
    /// Hub only stores/backs up — never invents balances.
    #[serde(default = "default_bill_source")]
    pub source: String,
}

fn default_bill_source() -> String {
    "client_submitted".into()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BillStatus {
    /// Waiting for left + right signatures.
    CollectingSignatures,
    /// Fully signed last bill for this channel (only one active per channel).
    Active,
}

#[derive(Debug, Deserialize)]
pub struct ProposeBillRequest {
    /// 0 = auto (last active sequence + 1, or 1).
    #[serde(default)]
    pub sequence: u64,
    pub left_hac: String,
    pub right_hac: String,
    #[serde(default)]
    pub left_satoshi: u64,
    #[serde(default)]
    pub right_satoshi: u64,
    /// Optional link to a hub payment session.
    #[serde(default)]
    pub payment_id: Option<Uuid>,
    #[serde(default)]
    pub notes: String,
    /// Optional signatures included with the proposal.
    #[serde(default)]
    pub signatures: Vec<SignPaymentRequest>,
}

#[derive(Debug, Deserialize)]
pub struct SignBillRequest {
    pub address: String,
    pub signature_hex: String,
    #[serde(default)]
    pub public_key_hex: String,
}

/// Export package for L1 arbitration / wallet ChannelClose (hub does not submit txs).
#[derive(Debug, Clone, Serialize)]
pub struct DisputeExport {
    pub purpose: &'static str,
    pub channel_id: String,
    pub channel: Option<LocalChannel>,
    pub last_bill: Option<ChannelBill>,
    pub bill_active: bool,
    pub fullnode_l1_query: String,
    pub disclaimer: &'static str,
    pub next_steps: Vec<&'static str>,
    pub evidence_notes: Vec<String>,
    /// Structured close package for wallets / fullnode builders.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_package: Option<ClosePackage>,
}

/// Wallet-ready ChannelClose / arbitration evidence (CSP backup only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosePackage {
    pub schema: &'static str,
    pub channel_id: String,
    pub left_address: String,
    pub right_address: String,
    pub distribution_left_hac: String,
    pub distribution_right_hac: String,
    pub distribution_left_satoshi: u64,
    pub distribution_right_satoshi: u64,
    pub bill_sequence: u64,
    pub bill_message: String,
    pub bill_message_hash_hex: String,
    pub bill_signatures: Vec<PaymentSignature>,
    pub both_signed: bool,
    /// Conservative compatibility gate. Must remain false until a capability-checked
    /// L1 action can verify the exact evidence/signing domain.
    pub ready_for_l1_close: bool,
    pub l1_actions: Vec<&'static str>,
}

// ---------------------------------------------------------------------------
// Whitepaper: rebalancing + deferred payments
// ---------------------------------------------------------------------------

/// Propose coordinated rebalance across two local channels (capacity shift).
/// Parties still sign bills; hub only coordinates (no custody).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebalanceProposal {
    pub id: Uuid,
    pub status: RebalanceStatus,
    pub channel_a: String,
    pub channel_b: String,
    /// Amount of HAC mei to shift (hint for bill proposals).
    pub amount_mei: u64,
    pub amount_satoshi: u64,
    pub note: String,
    pub created_unix: u64,
    pub updated_unix: u64,
    /// Optional bill sequence hints after rebalance complete.
    #[serde(default)]
    pub bill_a_id: Option<String>,
    #[serde(default)]
    pub bill_b_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RebalanceStatus {
    Proposed,
    Collecting,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Deserialize)]
pub struct ProposeRebalanceRequest {
    pub channel_a: String,
    pub channel_b: String,
    pub amount_mei: u64,
    #[serde(default)]
    pub amount_satoshi: u64,
    #[serde(default)]
    pub note: String,
}

/// Deferred / scheduled payment intent (execute after unix, still needs signatures).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredPayment {
    pub id: Uuid,
    pub status: DeferredStatus,
    pub payer: String,
    pub payee: String,
    pub amount_hac: String,
    pub amount_satoshi: u64,
    pub fee_hac: String,
    pub execute_after_unix: u64,
    pub created_unix: u64,
    pub updated_unix: u64,
    #[serde(default)]
    pub local_only: bool,
    #[serde(default)]
    pub route: Vec<String>,
    /// Filled when promoted to a live payment session.
    #[serde(default)]
    pub payment_id: Option<Uuid>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeferredStatus {
    Scheduled,
    Ready,
    Promoted,
    Cancelled,
    Failed,
}

#[derive(Debug, Deserialize)]
pub struct CreateDeferredRequest {
    pub payer: String,
    pub payee: String,
    pub amount_hac: String,
    #[serde(default)]
    pub amount_satoshi: u64,
    #[serde(default)]
    pub fee_hac: String,
    /// Unix timestamp; payment may be promoted after this time.
    pub execute_after_unix: u64,
    #[serde(default)]
    pub local_only: bool,
    #[serde(default)]
    pub route: Vec<String>,
    #[serde(default)]
    pub note: String,
}

// ---------------------------------------------------------------------------
// Status / agent
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct HubStatus {
    pub name: String,
    pub provider_id: String,
    pub bind: String,
    pub public_url: String,
    pub fullnode: String,
    pub fullnode_reachable: bool,
    pub fullnode_height: Option<u64>,
    pub channels_registered: usize,
    pub peers_known: usize,
    pub peers_reachable: usize,
    pub payments_open: usize,
    pub payments_settled: usize,
    pub bills_active: usize,
    pub bills_collecting: usize,
    pub l2_model: &'static str,
    pub phase: &'static str,
    pub notes: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct AgentCapabilities {
    pub service: &'static str,
    pub version: &'static str,
    pub phase: &'static str,
    pub provider_id: String,
    pub public_url: String,
    pub capabilities: Vec<&'static str>,
    pub endpoints: Vec<AgentEndpoint>,
    pub payment_rules: PaymentRules,
    pub bill_rules: BillRules,
}

#[derive(Debug, Serialize)]
pub struct BillRules {
    pub model: &'static str,
    pub storage: &'static str,
    pub activate_when: &'static str,
    pub hub_role: &'static str,
    pub dispute: &'static str,
    pub domain: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AgentEndpoint {
    pub method: &'static str,
    pub path: &'static str,
    pub purpose: &'static str,
}

#[derive(Debug, Serialize)]
pub struct PaymentRules {
    pub signature_order: &'static str,
    pub settle_when: &'static str,
    /// Explicit: hub "settled" ≠ on-chain ChannelClose.
    pub finality: &'static str,
    pub multi_hop: bool,
    pub hub_network: bool,
    pub custody: &'static str,
    /// Phase B crypto rules for agents/wallets.
    pub crypto: PaymentCryptoRules,
}

#[derive(Debug, Serialize)]
pub struct PaymentCryptoRules {
    pub domain: &'static str,
    pub hash: &'static str,
    pub curve: &'static str,
    pub sign_wire: &'static str,
    pub how_to_sign: &'static str,
}
