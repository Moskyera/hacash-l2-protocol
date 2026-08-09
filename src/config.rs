//! CLI / env configuration for the L2 channel hub.

use clap::Parser;

/// Hacash L2 Channel Chain hub (Channel Service Provider).
///
/// Phase 3: public discovery for wallets + AI agent hub selection; anyone can
/// run a VPS hub and join the network via bootstrap/gossip.
#[derive(Debug, Clone, Parser)]
#[command(name = "hacash-l2-hub", version, about)]
pub struct HubArgs {
    /// HTTP bind address for the hub API (wallets / other hubs / agents).
    #[arg(long, env = "HACASH_L2_BIND", default_value = "127.0.0.1:9090")]
    pub bind: String,

    /// Public URL others should use to reach this hub (for peer network).
    /// Defaults to http://{bind} when empty.
    #[arg(long, env = "HACASH_L2_PUBLIC_URL", default_value = "")]
    pub public_url: String,

    /// Upstream fullnode miner/query API host:port (no http://).
    #[arg(long, env = "HACASH_L2_FULLNODE", default_value = "127.0.0.1:8080")]
    pub fullnode: String,

    /// Optional X-Api-Token for the fullnode when [server] api_token is set.
    #[arg(long, env = "HACASH_L2_FULLNODE_TOKEN", default_value = "")]
    pub fullnode_token: String,

    /// Public provider identifier (PaySer-style suffix). Must be unique in the network.
    #[arg(long, env = "HACASH_L2_PROVIDER_ID", default_value = "LocalHub")]
    pub provider_id: String,

    /// Human-readable hub name for discovery / status.
    #[arg(long, env = "HACASH_L2_NAME", default_value = "hacash-l2-hub")]
    pub name: String,

    /// Comma-separated seed hub base URLs to bootstrap the peer network.
    /// Example: http://127.0.0.1:9091,http://hub.example:9090
    #[arg(long, env = "HACASH_L2_BOOTSTRAP", default_value = "")]
    pub bootstrap: String,

    /// Seconds between peer gossip hello rounds (0 = disable background gossip).
    #[arg(long, env = "HACASH_L2_GOSSIP_SECS", default_value_t = 30)]
    pub gossip_secs: u64,

    /// Max hops for automatic multi-hop path search.
    #[arg(long, default_value_t = 8)]
    pub max_hops: usize,

    /// Max concurrent payment sessions.
    #[arg(long, default_value_t = 10_000)]
    pub max_payment_sessions: usize,

    /// Default arbitration lock hint (blocks) for docs; L1 uses its own.
    #[arg(long, default_value_t = 5000)]
    pub arbitration_lock_blocks: u32,

    /// List this hub in public wallet discovery (Find hubs).
    #[arg(long, env = "HACASH_L2_PUBLIC", default_value_t = true)]
    pub public: bool,

    /// Accept wallet fast-pay connections.
    #[arg(long, default_value_t = true)]
    pub accepts_wallets: bool,

    /// Accept AI agent attachments.
    #[arg(long, default_value_t = true)]
    pub accepts_agents: bool,

    /// Region hint for discovery scoring (eu, us, asia, …).
    #[arg(long, env = "HACASH_L2_REGION", default_value = "")]
    pub region: String,

    /// Free-form fee hint shown in directory (not on-chain enforced).
    #[arg(long, default_value = "")]
    pub fee_hint: String,

    /// Operator contact / URL / email for discovery.
    #[arg(long, env = "HACASH_L2_CONTACT", default_value = "")]
    pub contact: String,

    /// Flat routing fee in HAC mei (fee market hint).
    #[arg(long, env = "HACASH_L2_FEE_BASE_MEI", default_value_t = 0)]
    pub fee_base_mei: u64,

    /// Parts-per-million fee on amount (fee market hint; 1000 = 0.1%).
    #[arg(long, env = "HACASH_L2_FEE_PPM", default_value_t = 0)]
    pub fee_ppm: u64,

    /// Hub identity password → deterministic secp256k1 key for signed hellos.
    /// Prefer env; never commit production secrets.
    #[arg(long, env = "HACASH_L2_IDENTITY_PASSWORD", default_value = "")]
    pub identity_password: String,

    /// Alternative: 32-byte secret key hex for hub identity (signed peer hello).
    #[arg(long, env = "HACASH_L2_IDENTITY_SECRET_HEX", default_value = "")]
    pub identity_secret_hex: String,

    /// Remote community seeds JSON URL (http/https). Fetched at start + optional refresh.
    #[arg(long, env = "HACASH_L2_SEEDS_URL", default_value = "")]
    pub seeds_url: String,

    /// After start, announce (hello) to all bootstrap/seed peers immediately.
    #[arg(long, env = "HACASH_L2_ANNOUNCE_ON_START", default_value_t = true)]
    pub announce_on_start: bool,

    /// Reject inbound hellos that claim a signature but fail verify (default true).
    #[arg(
        long,
        env = "HACASH_L2_REQUIRE_VALID_HELLO_SIG",
        default_value_t = true
    )]
    pub require_valid_hello_sig: bool,

    /// Max age (seconds) for signed hello timestamps (0 = do not check age).
    #[arg(long, env = "HACASH_L2_HELLO_MAX_AGE_SECS", default_value_t = 600)]
    pub hello_max_age_secs: u64,

    /// Seconds between L1 channel status refresh (0 = off).
    #[arg(long, env = "HACASH_L2_WATCH_SECS", default_value_t = 60)]
    pub watch_secs: u64,

    /// Optional operator API token. When set, protects register/bootstrap/fail
    /// (X-Api-Token or Authorization: Bearer). Wallet create/sign stay open.
    #[arg(long, env = "HACASH_L2_API_TOKEN", default_value = "")]
    pub api_token: String,

    /// Allow bootstrap/gossip to loopback/private IPs (local multi-hub tests).
    #[arg(long, env = "HACASH_L2_ALLOW_PRIVATE_PEERS", default_value_t = false)]
    pub allow_private_peers: bool,

    /// Payment session TTL seconds while collecting signatures (0 = no expiry).
    #[arg(long, env = "HACASH_L2_PAYMENT_TTL_SECS", default_value_t = 3600)]
    pub payment_ttl_secs: u64,

    /// Max registered local channels (DoS cap).
    #[arg(long, default_value_t = 50_000)]
    pub max_channels: usize,

    /// Max known peer hubs (DoS cap).
    #[arg(long, default_value_t = 5_000)]
    pub max_peers: usize,

    /// Max request body bytes (JSON).
    #[arg(long, default_value_t = 262_144)]
    pub max_body_bytes: usize,

    /// Optional path to persist channels + peer seeds as JSON (empty = memory only).
    #[arg(long, env = "HACASH_L2_STATE_PATH", default_value = "")]
    pub state_path: String,

    /// Seconds between state flushes when state_path is set (0 = only on graceful... n/a; use interval).
    #[arg(long, env = "HACASH_L2_PERSIST_SECS", default_value_t = 30)]
    pub persist_secs: u64,

    /// Phase B: verify secp256k1 payment signatures (default true).
    /// Set false only for local demos with non-crypto stubs.
    #[arg(long, env = "HACASH_L2_SIG_VERIFY", default_value_t = true)]
    pub sig_verify: bool,

    /// Soft max HAC integer part per agent payment (e.g. 1000 → "1000:247" max).
    #[arg(long, env = "HACASH_L2_MAX_AMOUNT_MEI", default_value_t = 1_000_000)]
    pub max_amount_mei: u64,

    /// Max agent payments created per agent_id per hour.
    #[arg(long, env = "HACASH_L2_MAX_PAY_PER_HOUR", default_value_t = 500)]
    pub max_payments_per_hour: u32,

    /// Max concurrent open payments per agent_id.
    #[arg(long, env = "HACASH_L2_MAX_OPEN_PAY", default_value_t = 50)]
    pub max_open_payments: u32,

    /// Comma-separated agent_id allowlist (empty = all allowed).
    #[arg(long, env = "HACASH_L2_AGENT_ALLOWLIST", default_value = "")]
    pub agent_allowlist: String,

    /// Comma-separated payee address allowlist (empty = all).
    #[arg(long, env = "HACASH_L2_PAYEE_ALLOWLIST", default_value = "")]
    pub payee_allowlist: String,

    /// Webhook HMAC secret (X-Hacash-Signature = sha3(secret||body) hex).
    #[arg(long, env = "HACASH_L2_WEBHOOK_SECRET", default_value = "")]
    pub webhook_secret: String,

    /// Optional agent API key for /v1/agent/v1/* mutators (empty = open).
    #[arg(long, env = "HACASH_L2_AGENT_API_KEY", default_value = "")]
    pub agent_api_key: String,

    /// Require verified agent identity for pay (agent_id must be verified).
    #[arg(
        long,
        env = "HACASH_L2_REQUIRE_VERIFIED_AGENT",
        default_value_t = false
    )]
    pub require_verified_agent: bool,

    /// Max agent HTTP requests per IP per window.
    #[arg(long, env = "HACASH_L2_RATE_LIMIT", default_value_t = 120)]
    pub rate_limit_per_window: u32,

    /// Rate limit window seconds.
    #[arg(long, env = "HACASH_L2_RATE_WINDOW_SECS", default_value_t = 60)]
    pub rate_window_secs: u64,

    /// Fullnode tx submit path (e.g. /submit/transaction). Empty = default.
    #[arg(
        long,
        env = "HACASH_L2_SUBMIT_TX_PATH",
        default_value = "/submit/transaction"
    )]
    pub submit_tx_path: String,

    /// Path to community seeds JSON (empty = seeds.example.json if present).
    #[arg(long, env = "HACASH_L2_SEEDS_PATH", default_value = "")]
    pub seeds_path: String,

    /// Auto-propose last bill on single-hop settle (client can still re-sign).
    #[arg(long, env = "HACASH_L2_AUTO_BILL", default_value_t = true)]
    pub auto_bill: bool,

    /// Trust X-Forwarded-For / X-Real-IP for rate limiting (only behind a reverse proxy).
    #[arg(long, env = "HACASH_L2_TRUST_PROXY", default_value_t = false)]
    pub trust_proxy: bool,
}

impl HubArgs {
    pub fn agent_policy(&self) -> crate::policy::AgentPolicy {
        crate::policy::AgentPolicy {
            max_amount_mei: self.max_amount_mei,
            max_payments_per_hour: self.max_payments_per_hour,
            max_open_payments: self.max_open_payments,
            agent_allowlist: self
                .agent_allowlist
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            payee_allowlist: self
                .payee_allowlist
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }

    pub fn resolved_public_url(&self) -> String {
        let u = self.public_url.trim();
        if !u.is_empty() {
            return u.trim_end_matches('/').to_string();
        }
        format!("http://{}", self.bind.trim())
    }

    pub fn bootstrap_urls(&self) -> Vec<String> {
        self.bootstrap
            .split(',')
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    pub fn hub_meta(&self) -> crate::types::HubMeta {
        self.hub_meta_with_capacity(0, 0, 0)
    }

    pub fn hub_meta_with_capacity(
        &self,
        channel_count: usize,
        total_capacity_mei: u64,
        max_channel_capacity_mei: u64,
    ) -> crate::types::HubMeta {
        let mut features = vec![
            "channel-chain".into(),
            "multi-hop".into(),
            "last-bill".into(),
            "dispute-export".into(),
            "gossip".into(),
            "discover".into(),
            "rebalance".into(),
            "deferred-pay".into(),
            "fee-schedule".into(),
            "signed-hello".into(),
            "durable-txlog".into(),
            "distributed-2pc".into(),
            "capacity-advertise".into(),
            "agent-pay".into(),
            "exact-zhu-liquidity".into(),
        ];
        if self.public {
            features.push("public-directory".into());
        }
        let (identity_address, identity_pubkey_hex) = self
            .identity_account()
            .map(|a| {
                (
                    a.readable().to_string(),
                    hex::encode(a.public_key().serialize_compressed()),
                )
            })
            .unwrap_or_default();
        crate::types::HubMeta {
            public: self.public,
            accepts_wallets: self.accepts_wallets,
            accepts_agents: self.accepts_agents,
            region: self.region.clone(),
            fee_hint: self.fee_hint.clone(),
            contact: self.contact.clone(),
            protocol_version: "2.0".into(),
            started_unix: 0, // filled by NetClient at runtime
            fee_base_mei: self.fee_base_mei,
            fee_ppm: self.fee_ppm,
            total_capacity_mei,
            max_channel_capacity_mei,
            channel_count,
            features,
            identity_address,
            identity_pubkey_hex,
        }
    }

    /// Optional hub operator key for signing peer hellos (global mesh authenticity).
    pub fn identity_account(&self) -> Option<crate::hacash_keys::Account> {
        let hex_key = self.identity_secret_hex.trim();
        if !hex_key.is_empty() {
            let raw = hex::decode(hex_key).ok()?;
            if raw.len() != 32 {
                return None;
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&raw);
            return crate::hacash_keys::Account::create_by_secret_key_value(key).ok();
        }
        let pass = self.identity_password.trim();
        if pass.is_empty() {
            return None;
        }
        crate::hacash_keys::Account::create_by_password(pass).ok()
    }

    pub fn fee_schedule(&self) -> crate::types::FeeSchedule {
        crate::types::FeeSchedule {
            fee_base_mei: self.fee_base_mei,
            fee_ppm: self.fee_ppm,
            fee_hint: self.fee_hint.clone(),
            currency: "HAC",
            note: "CSP fee market hint only — not L1 enforced; wallets may ignore",
        }
    }

    pub fn state_path_opt(&self) -> Option<std::path::PathBuf> {
        let p = self.state_path.trim();
        if p.is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(p))
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.provider_id.trim().is_empty() {
            return Err("provider_id must not be empty".into());
        }
        if self.provider_id.contains('_') || self.provider_id.contains(' ') {
            return Err("provider_id must not contain spaces or underscores".into());
        }
        if self.provider_id.len() > 64 {
            return Err("provider_id max 64 chars".into());
        }
        if self.bind.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!("invalid bind address: {}", self.bind));
        }
        if self.fullnode.trim().is_empty() {
            return Err("fullnode host:port required".into());
        }
        if self.max_body_bytes < 1024 {
            return Err("max_body_bytes must be >= 1024".into());
        }
        if self.max_channels < 1 || self.max_peers < 1 {
            return Err("max_channels and max_peers must be >= 1".into());
        }
        Ok(())
    }
}
