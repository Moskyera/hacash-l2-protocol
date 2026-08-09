//! Hub-to-hub networking: signed hello, gossip, bootstrap, seeds URL, announce.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;
use tracing::{debug, info, warn};

use crate::crypto::{channel_ads_hash_hex, sign_hello, verify_hello_signature, HelloCommit};
use crate::distributed_tx::{TxPhase, TxWireRequest, TxWireResponse};
use crate::hacash_keys::Account;
use crate::ssrf::{validate_peer_url, UrlSafety};
use crate::state::HubState;
use crate::types::PaymentSession;
use crate::types::{AdvertisedChannel, HubMeta, PeerHello, PeerHub, PeerSeed, RemotePaymentNotify};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone)]
pub struct NetClient {
    client: Client,
    local_provider: String,
    local_public_url: String,
    local_name: String,
    local_meta: HubMeta,
    allow_private_peers: bool,
    identity: Option<Arc<Account>>,
    started_unix: u64,
    hello_max_age_secs: u64,
    require_valid_hello_sig: bool,
}

impl NetClient {
    #[allow(dead_code)]
    pub fn new(
        local_provider: String,
        local_public_url: String,
        local_name: String,
        local_meta: HubMeta,
        allow_private_peers: bool,
    ) -> Self {
        Self::with_identity(
            local_provider,
            local_public_url,
            local_name,
            local_meta,
            allow_private_peers,
            None,
            600,
            true,
        )
    }

    pub fn with_identity(
        local_provider: String,
        local_public_url: String,
        local_name: String,
        mut local_meta: HubMeta,
        allow_private_peers: bool,
        identity: Option<Account>,
        hello_max_age_secs: u64,
        require_valid_hello_sig: bool,
    ) -> Self {
        let started = now_unix();
        local_meta.started_unix = started;
        if let Some(ref acc) = identity {
            local_meta.identity_address = acc.readable().to_string();
            local_meta.identity_pubkey_hex = hex::encode(acc.public_key().serialize_compressed());
        }
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(8))
                .connect_timeout(Duration::from_secs(5))
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| Client::new()),
            local_provider,
            local_public_url,
            local_name,
            local_meta,
            allow_private_peers,
            identity: identity.map(Arc::new),
            started_unix: started,
            hello_max_age_secs,
            require_valid_hello_sig,
        }
    }

    #[allow(dead_code)]
    pub fn started_unix(&self) -> u64 {
        self.started_unix
    }
    pub fn local_provider(&self) -> &str {
        &self.local_provider
    }

    pub fn local_public_url(&self) -> &str {
        &self.local_public_url
    }

    /// Distributed settlement is fail-closed unless this hub can sign every
    /// phase and validates signed peer identities strictly.
    pub fn distributed_identity_ready(&self) -> bool {
        self.identity.is_some() && self.require_valid_hello_sig
    }

    pub fn local_identity_public(&self) -> Result<(String, String), String> {
        let account = self
            .identity
            .as_ref()
            .ok_or_else(|| "hub identity key is required".to_string())?;
        Ok((
            account.readable().to_string(),
            hex::encode(account.public_key().serialize_compressed()),
        ))
    }

    pub fn sign_protocol_hash(&self, hash: &[u8; 32]) -> Result<String, String> {
        let account = self
            .identity
            .as_ref()
            .ok_or_else(|| "hub identity key is required".to_string())?;
        Ok(crate::crypto::sign_payment_hash(account, hash))
    }

    pub fn verify_peer_protocol_hash(
        &self,
        state: &HubState,
        provider_id: &str,
        identity_address: &str,
        identity_pubkey_hex: &str,
        signature_hex: &str,
        hash: &[u8; 32],
    ) -> Result<(), String> {
        if !self.require_valid_hello_sig {
            return Err("strict signed-hello verification is required".into());
        }
        let peer = state
            .get_peer(provider_id)
            .ok_or_else(|| format!("unknown peer identity for provider {provider_id}"))?;
        if !peer.identity_verified {
            return Err(format!(
                "peer {provider_id} identity hello was not verified"
            ));
        }
        if peer.meta.identity_address.is_empty() || peer.meta.identity_pubkey_hex.is_empty() {
            return Err(format!("peer {provider_id} has no pinned identity"));
        }
        if peer.meta.identity_address != identity_address
            || !peer
                .meta
                .identity_pubkey_hex
                .eq_ignore_ascii_case(identity_pubkey_hex)
        {
            return Err(format!(
                "peer identity pin mismatch for provider {provider_id}"
            ));
        }
        crate::crypto::verify_payment_signature(
            hash,
            identity_address,
            signature_hex,
            Some(identity_pubkey_hex),
        )
        .map(|_| ())
    }

    pub fn local_meta(&self) -> &HubMeta {
        &self.local_meta
    }

    fn check_url(&self, url: &str) -> Result<(), String> {
        match validate_peer_url(url, self.allow_private_peers) {
            UrlSafety::Ok => Ok(()),
            UrlSafety::Reject(msg) => Err(msg),
        }
    }

    #[allow(dead_code)]
    pub fn hello_payload(
        &self,
        channels: Vec<AdvertisedChannel>,
        known: Vec<PeerSeed>,
    ) -> PeerHello {
        self.hello_payload_with_meta(channels, known, self.local_meta.clone())
    }

    pub fn hello_payload_with_meta(
        &self,
        channels: Vec<AdvertisedChannel>,
        known: Vec<PeerSeed>,
        mut meta: HubMeta,
    ) -> PeerHello {
        meta.started_unix = self.started_unix;
        meta.channel_count = channels.len();
        if meta.total_capacity_mei == 0 {
            meta.total_capacity_mei = channels.iter().map(|c| c.capacity_mei).sum();
        }
        if meta.max_channel_capacity_mei == 0 {
            meta.max_channel_capacity_mei =
                channels.iter().map(|c| c.capacity_mei).max().unwrap_or(0);
        }
        if meta.identity_address.is_empty() {
            meta.identity_address = self.local_meta.identity_address.clone();
            meta.identity_pubkey_hex = self.local_meta.identity_pubkey_hex.clone();
        }

        let ts = now_unix();
        let mut channel_ids: Vec<_> = channels.iter().map(|c| c.channel_id.clone()).collect();
        channel_ids.sort();
        let channel_ads_hash = channel_ads_hash_hex(&channels);
        let channel_ids_joined = channel_ids.join(",");

        let (identity_pubkey_hex, identity_address, signature_hex) =
            if let Some(ref acc) = self.identity {
                let (pk, addr, sig) = sign_hello(
                    acc,
                    &self.local_provider,
                    &self.local_public_url,
                    &self.local_name,
                    ts,
                    &meta.protocol_version,
                    &channel_ids_joined,
                    meta.fee_base_mei,
                    meta.fee_ppm,
                    meta.total_capacity_mei,
                    &channel_ads_hash,
                );
                meta.identity_address = addr.clone();
                meta.identity_pubkey_hex = pk.clone();
                (pk, addr, sig)
            } else {
                (
                    meta.identity_pubkey_hex.clone(),
                    meta.identity_address.clone(),
                    String::new(),
                )
            };

        PeerHello {
            provider_id: self.local_provider.clone(),
            public_url: self.local_public_url.clone(),
            name: self.local_name.clone(),
            channels,
            known_peers: known,
            meta,
            timestamp_unix: ts,
            identity_pubkey_hex,
            identity_address,
            signature_hex,
        }
    }

    /// Validate inbound hello signature + timestamp window.
    pub fn validate_inbound_hello(&self, hello: &PeerHello) -> Result<(), String> {
        if hello.signature_hex.trim().is_empty() {
            return Ok(());
        }
        if self.require_valid_hello_sig {
            let mut channel_ids: Vec<_> = hello
                .channels
                .iter()
                .map(|c| c.channel_id.clone())
                .collect();
            channel_ids.sort();
            let commit = HelloCommit {
                provider_id: hello.provider_id.clone(),
                public_url: hello.public_url.clone(),
                name: hello.name.clone(),
                timestamp_unix: hello.timestamp_unix,
                protocol_version: hello.meta.protocol_version.clone(),
                identity_address: if hello.identity_address.is_empty() {
                    hello.meta.identity_address.clone()
                } else {
                    hello.identity_address.clone()
                },
                channel_ids: channel_ids.join(","),
                fee_base_mei: hello.meta.fee_base_mei,
                fee_ppm: hello.meta.fee_ppm,
                total_capacity_mei: hello.meta.total_capacity_mei,
                channel_ads_hash_hex: channel_ads_hash_hex(&hello.channels),
            };
            if commit.identity_address.is_empty() {
                return Err("signed hello missing identity_address".into());
            }
            let pk = if hello.identity_pubkey_hex.is_empty() {
                &hello.meta.identity_pubkey_hex
            } else {
                &hello.identity_pubkey_hex
            };
            verify_hello_signature(&commit, &hello.signature_hex, pk)?;
            if self.hello_max_age_secs > 0 && hello.timestamp_unix > 0 {
                let now = now_unix();
                let age = now.saturating_sub(hello.timestamp_unix);
                // Allow small clock skew into the future
                if hello.timestamp_unix > now.saturating_add(120) {
                    return Err("hello timestamp too far in the future".into());
                }
                if age > self.hello_max_age_secs {
                    return Err(format!(
                        "hello timestamp too old (age {age}s > max {}s)",
                        self.hello_max_age_secs
                    ));
                }
            }
        }
        Ok(())
    }

    /// POST /v1/net/hello to a peer URL; returns their hello body if ok.
    pub async fn exchange_hello(
        &self,
        peer_base: &str,
        payload: &PeerHello,
    ) -> Result<PeerHello, String> {
        self.check_url(peer_base)?;
        let base = peer_base.trim_end_matches('/');
        let url = format!("{base}/v1/net/hello");
        debug!(%url, "hub hello");
        let resp = self
            .client
            .post(&url)
            .json(payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let body = if body.len() > 512 {
                format!("{}…", &body[..512])
            } else {
                body
            };
            return Err(format!("peer HTTP {status}: {body}"));
        }
        let body = resp.text().await.map_err(|e| e.to_string())?;
        if body.len() > 2_000_000 {
            return Err("peer hello response too large".into());
        }
        let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        let remote: PeerHello = if let Some(peer) = v.get("peer") {
            serde_json::from_value(peer.clone()).map_err(|e| e.to_string())?
        } else {
            serde_json::from_value(v).map_err(|e| e.to_string())?
        };
        if let Err(e) = self.validate_inbound_hello(&remote) {
            warn!(provider = %remote.provider_id, error = %e, "remote hello sig invalid");
            // Still accept for mesh resilience but mark in log; hard fail if required
            if self.require_valid_hello_sig && !remote.signature_hex.trim().is_empty() {
                return Err(format!("remote hello rejected: {e}"));
            }
        }
        Ok(remote)
    }

    pub async fn fetch_peers(&self, peer_base: &str) -> Result<Vec<PeerHub>, String> {
        self.check_url(peer_base)?;
        let base = peer_base.trim_end_matches('/');
        let url = format!("{base}/v1/net/peers");
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("peer HTTP {}", resp.status()));
        }
        let body = resp.text().await.map_err(|e| e.to_string())?;
        if body.len() > 2_000_000 {
            return Err("peer list response too large".into());
        }
        let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        let list = v
            .get("peers")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]));
        let mut peers: Vec<PeerHub> = serde_json::from_value(list).map_err(|e| e.to_string())?;
        peers.truncate(512);
        Ok(peers)
    }

    /// POST multi-hop payment notify to a peer hub (best-effort).
    pub async fn notify_payment(
        &self,
        peer_base: &str,
        notify: &RemotePaymentNotify,
    ) -> Result<(), String> {
        self.check_url(peer_base)?;
        let base = peer_base.trim_end_matches('/');
        let url = format!("{base}/v1/net/payment-notify");
        let resp = self
            .client
            .post(&url)
            .json(notify)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let body = if body.len() > 256 {
                format!("{}…", &body[..256])
            } else {
                body
            };
            return Err(format!("peer HTTP {status}: {body}"));
        }
        Ok(())
    }

    /// Fetch community seeds JSON from remote URL or parse body.
    pub async fn fetch_seeds_json(&self, url: &str) -> Result<Vec<PeerSeed>, String> {
        self.check_url(url)?;
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("seeds URL HTTP {}", resp.status()));
        }
        let body = resp.text().await.map_err(|e| e.to_string())?;
        if body.len() > 1_000_000 {
            return Err("seeds JSON too large".into());
        }
        parse_seeds_json(&body)
    }

    /// Send one signed 2PC phase to a participant and decode its signed ack.
    pub async fn post_distributed_tx(
        &self,
        peer_base: &str,
        request: &TxWireRequest,
    ) -> Result<TxWireResponse, String> {
        self.check_url(peer_base)?;
        let phase = match request.phase {
            TxPhase::Prepare => "prepare",
            TxPhase::Commit => "commit",
            TxPhase::Abort => "abort",
        };
        let base = peer_base.trim_end_matches('/');
        let url = format!("{base}/v1/net/tx/{phase}");
        let response = self
            .client
            .post(&url)
            .json(request)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let status = response.status();
        let body = response.text().await.map_err(|error| error.to_string())?;
        if body.len() > 256_000 {
            return Err("distributed transaction response too large".into());
        }
        if !status.is_success() {
            let detail = if body.len() > 512 {
                format!("{}…", &body[..512])
            } else {
                body
            };
            return Err(format!("peer HTTP {status}: {detail}"));
        }
        serde_json::from_str(&body)
            .map_err(|error| format!("decode distributed transaction acknowledgement: {error}"))
    }
}

/// Parse seeds.example.json style documents.
pub fn parse_seeds_json(raw: &str) -> Result<Vec<PeerSeed>, String> {
    let v: serde_json::Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    let arr = if let Some(a) = v.get("seeds").and_then(|s| s.as_array()) {
        a.clone()
    } else if let Some(a) = v.as_array() {
        a.clone()
    } else {
        return Err("seeds JSON must be array or { seeds: [...] }".into());
    };
    let mut out = Vec::new();
    for item in arr.into_iter().take(256) {
        let provider_id = item
            .get("provider_id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let public_url = item
            .get("public_url")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .trim_end_matches('/')
            .to_string();
        if provider_id.is_empty() || public_url.is_empty() {
            continue;
        }
        out.push(PeerSeed {
            provider_id,
            public_url,
            region: item
                .get("region")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            notes: item
                .get("notes")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        });
    }
    Ok(out)
}

/// Load seeds from local file path.
pub fn load_seeds_file(path: &str) -> Result<Vec<PeerSeed>, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    parse_seeds_json(&raw)
}

/// Background loop: refresh L1 status for registered channels.
pub async fn l1_watch_loop(
    fullnode: crate::fullnode::FullnodeClient,
    state: std::sync::Arc<crate::state::HubState>,
    interval_secs: u64,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(interval_secs.max(10)));
    loop {
        tick.tick().await;
        let channels = state.list_channels();
        for ch in channels {
            match fullnode.query_channel_observation(&ch.channel_id).await {
                Ok(observation) => {
                    if let Err(error) =
                        state.apply_l1_channel_observation(&ch.channel_id, observation)
                    {
                        warn!(channel = %ch.channel_id, error = %error, "L1 observation rejected");
                    }
                }
                Err(e) => {
                    debug!(channel = %ch.channel_id, error = %e, "L1 watch query failed");
                }
            }
        }
    }
}

/// Background loop: re-hello all known peers periodically.
pub async fn gossip_loop(
    net: NetClient,
    state: std::sync::Arc<crate::state::HubState>,
    interval_secs: u64,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(interval_secs.max(5)));
    loop {
        tick.tick().await;
        let peers = state.list_peers();
        let channels = state.advertise_channels();
        let seeds: Vec<PeerSeed> = peers
            .iter()
            .map(|p| PeerSeed {
                provider_id: p.provider_id.clone(),
                public_url: p.public_url.clone(),
                region: p.meta.region.clone(),
                notes: String::new(),
            })
            .collect();
        let mut meta = net.local_meta().clone();
        meta = state.enrich_meta_capacity(meta);
        let payload = net.hello_payload_with_meta(channels, seeds, meta);
        for peer in peers {
            if peer.provider_id == net.local_provider {
                continue;
            }
            match net.exchange_hello(&peer.public_url, &payload).await {
                Ok(remote) => {
                    if let Err(e) = state.upsert_peer_from_hello(&remote, true) {
                        warn!(error = %e, "upsert peer failed");
                    } else {
                        debug!(provider = %remote.provider_id, "gossip ok");
                    }
                    state.ingest_known_peers(
                        &remote
                            .known_peers
                            .into_iter()
                            .filter(|s| s.provider_id != net.local_provider)
                            .collect::<Vec<_>>(),
                    );
                }
                Err(e) => {
                    warn!(url = %peer.public_url, error = %e, "gossip hello failed");
                    state.mark_peer_unreachable(&peer.provider_id);
                }
            }
        }
    }
}

pub async fn bootstrap_peer(
    net: &NetClient,
    state: &crate::state::HubState,
    url: &str,
) -> Result<PeerHub, String> {
    net.check_url(url)?;
    let channels = state.advertise_channels();
    let seeds = state.peer_seeds();
    let mut meta = net.local_meta().clone();
    meta = state.enrich_meta_capacity(meta);
    let payload = net.hello_payload_with_meta(channels, seeds, meta);
    let remote = net.exchange_hello(url, &payload).await?;
    state.upsert_peer_from_hello(&remote, true)?;
    info!(
        provider = %remote.provider_id,
        url = %remote.public_url,
        signed = !remote.signature_hex.is_empty(),
        "bootstrapped peer hub"
    );
    if let Ok(more) = net.fetch_peers(url).await {
        let seeds: Vec<PeerSeed> = more
            .into_iter()
            .filter(|p| p.provider_id != net.local_provider)
            .map(|p| PeerSeed {
                provider_id: p.provider_id,
                public_url: p.public_url,
                region: String::new(),
                notes: String::new(),
            })
            .collect();
        state.ingest_known_peers(&seeds);
    }
    state
        .get_peer(&remote.provider_id)
        .ok_or_else(|| "peer missing after upsert".into())
}

/// Announce self to a target URL (alias of bootstrap for ops clarity).
pub async fn announce_to(
    net: &NetClient,
    state: &crate::state::HubState,
    url: &str,
) -> Result<PeerHub, String> {
    bootstrap_peer(net, state, url).await
}

/// Bootstrap from a list of seed URLs (best-effort).
pub async fn bootstrap_seed_list(
    net: &NetClient,
    state: &crate::state::HubState,
    seeds: &[PeerSeed],
) -> usize {
    let mut ok = 0usize;
    for s in seeds {
        if s.provider_id == net.local_provider {
            continue;
        }
        let _ = state.remember_seed(&s.provider_id, &s.public_url);
        match bootstrap_peer(net, state, &s.public_url).await {
            Ok(_) => ok += 1,
            Err(e) => warn!(url = %s.public_url, error = %e, "seed bootstrap failed"),
        }
    }
    ok
}

/// Build notify payload for a local session (origin hub).
pub fn payment_notify_payload(
    p: &PaymentSession,
    origin_provider: &str,
    origin_public_url: &str,
) -> RemotePaymentNotify {
    let base = origin_public_url.trim_end_matches('/');
    let status = match p.status {
        crate::types::PaymentStatus::Settled => "settled",
        crate::types::PaymentStatus::Failed => "failed",
        crate::types::PaymentStatus::Committing => "committing",
        crate::types::PaymentStatus::TimedOut => "timed_out",
        crate::types::PaymentStatus::CollectingSignatures => "collecting",
        crate::types::PaymentStatus::Pending => "collecting",
    };
    let next_signer = crate::smart::next_signer(p).unwrap_or_default();
    RemotePaymentNotify {
        origin_provider_id: origin_provider.to_string(),
        origin_public_url: base.to_string(),
        payment_id: p.id,
        payer: p.payer.clone(),
        payee: p.payee.clone(),
        amount_hac: p.amount_hac.clone(),
        amount_satoshi: p.amount_satoshi,
        fee_hac: p.fee_hac.clone(),
        message_hash_hex: p.message_hash_hex.clone(),
        required_signers: p.required_signers.clone(),
        route: p.route.clone(),
        remote_hops: p.remote_hops.clone(),
        status: status.into(),
        next_signer,
        expires_unix: p.expires_unix,
        created_unix: p.created_unix,
        sign_endpoint: format!("{base}/v1/agent/v1/sign"),
        status_endpoint: format!("{base}/v1/agent/v1/payment/{}", p.id),
    }
}

/// Best-effort notify each unique remote hub URL involved in `p.remote_hops`.
/// Origin remains session authority; remotes only mirror for inbox discovery.
pub async fn notify_remote_hops(net: &NetClient, p: &PaymentSession) {
    if p.remote_hops.is_empty() {
        return;
    }
    let payload = payment_notify_payload(p, &net.local_provider, &net.local_public_url);
    let mut seen = std::collections::HashSet::new();
    for hop in &p.remote_hops {
        let Some(url) = hop
            .public_url
            .as_ref()
            .map(|u| u.trim().trim_end_matches('/'))
        else {
            debug!(
                provider = %hop.via_provider,
                "remote hop has no public_url; skip notify"
            );
            continue;
        };
        if url.is_empty() || !seen.insert(url.to_string()) {
            continue;
        }
        if hop.via_provider == net.local_provider {
            continue;
        }
        match net.notify_payment(url, &payload).await {
            Ok(()) => info!(
                to = %url,
                payment = %p.id,
                status = %payload.status,
                "remote payment notify ok"
            ),
            Err(e) => warn!(
                to = %url,
                payment = %p.id,
                error = %e,
                "remote payment notify failed (session still local)"
            ),
        }
    }
}

/// Spawn best-effort notify (does not block payment path).
pub fn spawn_notify_remote_hops(net: NetClient, payment: PaymentSession) {
    if payment.remote_hops.is_empty() {
        return;
    }
    tokio::spawn(async move {
        notify_remote_hops(&net, &payment).await;
    });
}

/// Background: expire stale payment sessions (TTL).
pub async fn payment_ttl_loop(state: std::sync::Arc<crate::state::HubState>, interval_secs: u64) {
    let mut tick = tokio::time::interval(Duration::from_secs(interval_secs.max(5)));
    loop {
        tick.tick().await;
        let n = state.expire_stale_payments();
        if n > 0 {
            info!(timed_out = n, "expired payment sessions (TTL)");
        }
        // Promote deferred payments that are due
        let promoted = state.promote_due_deferred();
        if promoted > 0 {
            info!(promoted, "promoted deferred payments to live sessions");
        }
    }
}
