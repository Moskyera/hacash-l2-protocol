//! Phase 3: public hub discovery + scoring for wallets and AI agents.
//!
//! Wallet "Find hubs" → GET /v1/discover
//! Agent "which hub?" → GET /v1/discover/recommend

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::types::{HubMeta, PeerHub};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Scored directory entry for wallets / agents.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredHub {
    pub provider_id: String,
    pub public_url: String,
    pub name: String,
    pub reachable: bool,
    pub last_seen_unix: u64,
    pub channels: usize,
    pub score: i32,
    pub reasons: Vec<&'static str>,
    pub meta: HubMeta,
    /// true = this process (local hub)
    pub is_self: bool,
}

/// Score a hub for wallet connect / agent attachment.
/// Higher = better candidate for "connect to L2 fast pay".
pub fn score_hub(peer: &PeerHub, now: u64, is_self: bool) -> DiscoveredHub {
    let mut score: i32 = 0;
    let mut reasons = Vec::new();

    if is_self {
        score += 5;
        reasons.push("local_hub");
    }

    if peer.reachable {
        score += 40;
        reasons.push("reachable");
    } else {
        score -= 30;
        reasons.push("unreachable");
    }

    let age = now.saturating_sub(peer.last_seen_unix);
    if peer.last_seen_unix == 0 {
        score -= 10;
        reasons.push("never_seen");
    } else if age <= 60 {
        score += 25;
        reasons.push("fresh_<1m");
    } else if age <= 300 {
        score += 15;
        reasons.push("fresh_<5m");
    } else if age <= 1800 {
        score += 5;
        reasons.push("seen_<30m");
    } else {
        score -= 15;
        reasons.push("stale");
    }

    let n = peer.channels.len();
    if n == 0 {
        score -= 5;
        reasons.push("no_channels");
    } else if n < 3 {
        score += 10;
        reasons.push("few_channels");
    } else if n < 20 {
        score += 20;
        reasons.push("good_channels");
    } else {
        score += 25;
        reasons.push("many_channels");
    }

    if peer.meta.accepts_agents {
        score += 10;
        reasons.push("accepts_agents");
    }
    if peer.meta.accepts_wallets {
        score += 10;
        reasons.push("accepts_wallets");
    }
    if peer.meta.public {
        score += 5;
        reasons.push("public");
    }

    // Reputation-ish: fee_hint "low" / contact present / many channels
    if !peer.meta.fee_hint.is_empty() {
        score += 3;
        reasons.push("fee_hint");
    }
    if !peer.meta.contact.is_empty() {
        score += 2;
        reasons.push("contact");
    }
    if !peer.meta.region.is_empty() {
        score += 2;
        reasons.push("region");
    }
    if peer.meta.total_capacity_mei > 0
        || peer
            .channels
            .iter()
            .any(|c| c.capacity_mei > 0 || c.capacity_zhu > 0)
    {
        score += 8;
        reasons.push("capacity_advertised");
    }
    if peer.meta.fee_ppm > 0 || peer.meta.fee_base_mei > 0 {
        score += 2;
        reasons.push("fee_schedule");
    }
    if !peer.meta.identity_pubkey_hex.is_empty() || !peer.meta.identity_address.is_empty() {
        score += 10;
        reasons.push("identity_present");
    }

    DiscoveredHub {
        provider_id: peer.provider_id.clone(),
        public_url: peer.public_url.clone(),
        name: peer.name.clone(),
        reachable: peer.reachable,
        last_seen_unix: peer.last_seen_unix,
        channels: n,
        score,
        reasons,
        meta: peer.meta.clone(),
        is_self,
    }
}

/// Build directory: self + all known peers, sorted by score desc.
pub fn build_directory(self_peer: &PeerHub, peers: &[PeerHub]) -> Vec<DiscoveredHub> {
    let now = now_unix();
    let mut list = Vec::new();
    list.push(score_hub(self_peer, now, true));
    for p in peers {
        if p.provider_id == self_peer.provider_id {
            continue;
        }
        list.push(score_hub(p, now, false));
    }
    list.sort_by(|a, b| b.score.cmp(&a.score));
    list
}

/// Best hub for an AI agent to attach to (among directory).
pub fn recommend_for_agent(directory: &[DiscoveredHub]) -> Option<DiscoveredHub> {
    directory
        .iter()
        .filter(|h| h.reachable && h.meta.accepts_agents && h.meta.public)
        .max_by_key(|h| h.score)
        .cloned()
        .or_else(|| {
            // Fall back: any reachable hub that accepts agents
            directory
                .iter()
                .filter(|h| h.reachable && h.meta.accepts_agents)
                .max_by_key(|h| h.score)
                .cloned()
        })
        .or_else(|| {
            directory
                .iter()
                .filter(|h| h.reachable)
                .max_by_key(|h| h.score)
                .cloned()
        })
}

/// Best hub for a wallet "Find hubs / connect L2" button.
pub fn recommend_for_wallet(directory: &[DiscoveredHub]) -> Option<DiscoveredHub> {
    directory
        .iter()
        .filter(|h| h.reachable && h.meta.accepts_wallets && h.meta.public)
        .max_by_key(|h| h.score)
        .cloned()
        .or_else(|| recommend_for_agent(directory))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HubMeta;

    fn peer(id: &str, reachable: bool, channels: usize, agents: bool) -> PeerHub {
        PeerHub {
            provider_id: id.into(),
            public_url: format!("http://{id}.example:9090"),
            name: id.into(),
            channels: (0..channels)
                .map(|i| crate::types::AdvertisedChannel {
                    channel_id: format!("{:02x}", i % 255).repeat(16),
                    left_address: format!("L{i}"),
                    right_address: format!("R{i}"),
                    via_provider: id.into(),
                    capacity_mei: 100,
                    left_available_mei: 50,
                    right_available_mei: 50,
                    fee_ppm: 0,
                    capacity_zhu: 0,
                    left_available_zhu: 0,
                    right_available_zhu: 0,
                })
                .collect(),
            last_seen_unix: now_unix(),
            reachable,
            identity_verified: false,
            meta: HubMeta {
                public: true,
                accepts_wallets: true,
                accepts_agents: agents,
                region: "eu".into(),
                fee_hint: "low".into(),
                ..HubMeta::default()
            },
        }
    }

    #[test]
    fn recommend_prefers_reachable_with_channels() {
        let self_p = peer("Self", true, 2, true);
        let peers = vec![
            peer("Dead", false, 50, true),
            peer("Good", true, 15, true),
            peer("Empty", true, 0, true),
        ];
        let dir = build_directory(&self_p, &peers);
        let rec = recommend_for_agent(&dir).unwrap();
        // Self has bonus but Good has more channels; either Self or Good is fine if both high
        assert!(rec.reachable);
        assert!(rec.score > 0);
        // Dead should not win
        assert_ne!(rec.provider_id, "Dead");
    }
}
