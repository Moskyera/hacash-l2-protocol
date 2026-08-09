//! Multi-hop path finding over the hub-network channel graph.
//!
//! When amount is known and edge liquidity is published, paths require
//! **directional** available mei on the sender side of each hop.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::types::{AdvertisedChannel, LocalChannel, PeerHub};

/// Unified undirected edge for routing.
#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub channel_id: String,
    pub a: String,
    pub b: String,
    pub via_provider: String,
    /// Total mei if known; 0 = unknown (do not total-filter).
    pub capacity_zhu: u64,
    /// Available on side `a` (mei). Meaningful only if `liquidity_known`.
    pub a_available_zhu: u64,
    /// Available on side `b` (mei). Meaningful only if `liquidity_known`.
    pub b_available_zhu: u64,
    /// When true, 0 available means empty (block); when false, skip directional checks.
    pub liquidity_known: bool,
}

pub fn edge_from_local(ch: &LocalChannel, provider_id: &str) -> GraphEdge {
    let left = crate::amounts::parse_zhu(&ch.left_hac).unwrap_or(0);
    let right = crate::amounts::parse_zhu(&ch.right_hac).unwrap_or(0);
    GraphEdge {
        channel_id: ch.channel_id.clone(),
        a: ch.left_address.clone(),
        b: ch.right_address.clone(),
        via_provider: provider_id.to_string(),
        capacity_zhu: left.checked_add(right).unwrap_or(0),
        a_available_zhu: left,
        b_available_zhu: right,
        // Local registered balances are authoritative for this hub
        liquidity_known: true,
    }
}

pub fn edge_from_advertised(ch: &AdvertisedChannel) -> GraphEdge {
    // Prefer protocol-v2 exact fields. Convert protocol-v1 whole HAC to Zhu.
    let exact_v2 = ch.capacity_zhu > 0 || ch.left_available_zhu > 0 || ch.right_available_zhu > 0;
    let scale = crate::amounts::ZHU_PER_MEI;
    let capacity = if exact_v2 {
        ch.capacity_zhu
    } else {
        ch.capacity_mei.checked_mul(scale).unwrap_or(0)
    };
    let left = if exact_v2 {
        ch.left_available_zhu
    } else {
        ch.left_available_mei.checked_mul(scale).unwrap_or(0)
    };
    let right = if exact_v2 {
        ch.right_available_zhu
    } else {
        ch.right_available_mei.checked_mul(scale).unwrap_or(0)
    };
    let liquidity_known = left > 0 || right > 0 || capacity > 0;
    // If only total capacity is known, use it as soft upper bound on both sides
    // (optimistic — better than ignoring; full accuracy needs side balances)
    let (a_avail, b_avail) = if left == 0 && right == 0 && capacity > 0 {
        (capacity, capacity)
    } else {
        (left, right)
    };
    GraphEdge {
        channel_id: ch.channel_id.clone(),
        a: ch.left_address.clone(),
        b: ch.right_address.clone(),
        via_provider: ch.via_provider.clone(),
        capacity_zhu: capacity,
        a_available_zhu: a_avail,
        b_available_zhu: b_avail,
        liquidity_known,
    }
}

/// Drop edges that publish capacity_mei > 0 but below required amount.
/// Edges with capacity_mei == 0 (unknown) are kept for backward compatibility.
pub fn filter_edges_by_capacity(edges: Vec<GraphEdge>, min_zhu: u64) -> Vec<GraphEdge> {
    if min_zhu == 0 {
        return edges;
    }
    edges
        .into_iter()
        .filter(|e| e.capacity_zhu == 0 || e.capacity_zhu >= min_zhu)
        .collect()
}

/// Can `from` send `amount_mei` across this edge (directional)?
pub fn can_send_from(e: &GraphEdge, from: &str, amount_zhu: u64) -> bool {
    if amount_zhu == 0 || !e.liquidity_known {
        return true;
    }
    let avail = if from == e.a {
        e.a_available_zhu
    } else if from == e.b {
        e.b_available_zhu
    } else {
        return false;
    };
    avail >= amount_zhu
}

/// Build adjacency: address -> list of (peer_address, edge_index).
pub fn build_graph(edges: &[GraphEdge]) -> HashMap<String, Vec<(String, usize)>> {
    let mut adj: HashMap<String, Vec<(String, usize)>> = HashMap::new();
    for (i, e) in edges.iter().enumerate() {
        adj.entry(e.a.clone()).or_default().push((e.b.clone(), i));
        adj.entry(e.b.clone()).or_default().push((e.a.clone(), i));
    }
    adj
}

/// BFS shortest path (no amount / liquidity filter).
pub fn find_path(
    edges: &[GraphEdge],
    payer: &str,
    payee: &str,
    max_hops: usize,
) -> Result<Vec<GraphEdge>, String> {
    find_path_for_amount(edges, payer, payee, max_hops, 0)
}

/// BFS path that respects directional available mei when `amount_mei > 0`
/// and edges publish `liquidity_known`.
pub fn find_path_for_amount(
    edges: &[GraphEdge],
    payer: &str,
    payee: &str,
    max_hops: usize,
    amount_zhu: u64,
) -> Result<Vec<GraphEdge>, String> {
    let payer = payer.trim();
    let payee = payee.trim();
    if payer.is_empty() || payee.is_empty() {
        return Err("payer and payee required".into());
    }
    if payer == payee {
        return Err("payer and payee must differ".into());
    }
    if edges.is_empty() {
        return Err("no channels in routing graph".into());
    }

    let adj = build_graph(edges);
    if !adj.contains_key(payer) {
        return Err(format!(
            "payer {payer} has no channel edges in the network graph"
        ));
    }
    if !adj.contains_key(payee) {
        return Err(format!(
            "payee {payee} has no channel edges in the network graph"
        ));
    }

    // BFS: state = current address; parent map stores (prev_addr, edge_index)
    let mut parent: HashMap<String, (String, usize)> = HashMap::new();
    let mut q = VecDeque::new();
    let mut seen = HashSet::new();
    q.push_back(payer.to_string());
    seen.insert(payer.to_string());

    let mut found = false;
    while let Some(cur) = q.pop_front() {
        if cur == payee {
            found = true;
            break;
        }
        let depth = {
            let mut d = 0usize;
            let mut c = cur.as_str();
            while let Some((p, _)) = parent.get(c) {
                d += 1;
                c = p.as_str();
                if d > max_hops {
                    break;
                }
            }
            d
        };
        if depth >= max_hops {
            continue;
        }
        if let Some(nbs) = adj.get(&cur) {
            for (nb, ei) in nbs {
                let e = &edges[*ei];
                if !can_send_from(e, &cur, amount_zhu) {
                    continue;
                }
                if seen.insert(nb.clone()) {
                    parent.insert(nb.clone(), (cur.clone(), *ei));
                    q.push_back(nb.clone());
                }
            }
        }
    }

    if !found {
        return Err(if amount_zhu > 0 {
            format!(
                "no path from {payer} to {payee} within {max_hops} hops with directional liquidity for {amount_zhu} Zhu"
            )
        } else {
            format!("no path from {payer} to {payee} within {max_hops} hops")
        });
    }

    let mut path_edges = Vec::new();
    let mut cur = payee.to_string();
    while cur != payer {
        let (prev, ei) = parent
            .get(&cur)
            .ok_or_else(|| "internal route reconstruction failed".to_string())?
            .clone();
        path_edges.push(edges[ei].clone());
        cur = prev;
    }
    path_edges.reverse();

    // Final directional check along reconstructed path (sender = walker from payer)
    if amount_zhu > 0 {
        let mut at = payer.to_string();
        for e in &path_edges {
            if !can_send_from(e, &at, amount_zhu) {
                return Err(format!(
                    "insufficient directional liquidity on channel {} from {at} for {amount_zhu} Zhu",
                    e.channel_id
                ));
            }
            at = if e.a == at { e.b.clone() } else { e.a.clone() };
        }
    }

    Ok(path_edges)
}

/// Ordered signers: start at payee, walk each hop's far endpoint, end at payer.
/// Whitepaper-style: receiver side first, payer signs last.
pub fn ordered_signers(path: &[GraphEdge], payer: &str, payee: &str) -> Vec<String> {
    let mut signers = Vec::new();
    signers.push(payee.trim().to_string());
    let mut at = payee.trim().to_string();
    // `path` is ordered payer -> payee. Signature collection walks in the
    // opposite direction, so traverse the edges in reverse. Iterating forward
    // skips intermediaries on routes longer than two hops.
    for e in path.iter().rev() {
        let next = if e.a == at {
            e.b.clone()
        } else if e.b == at {
            e.a.clone()
        } else {
            continue;
        };
        if next != payee && next != payer && !signers.contains(&next) {
            signers.push(next.clone());
        }
        at = next;
    }
    if !signers.iter().any(|s| s == payer) {
        signers.push(payer.trim().to_string());
    }
    signers
}

/// Merge local channels + all peer advertisements into one edge list (dedupe by channel_id).
/// Prefer local edges (known liquidity) over remote ads for the same channel_id.
pub fn merge_network_edges(
    local: &[LocalChannel],
    peers: &[PeerHub],
    local_provider: &str,
) -> Vec<GraphEdge> {
    let mut by_id: HashMap<String, GraphEdge> = HashMap::new();
    for ch in local {
        by_id.insert(ch.channel_id.clone(), edge_from_local(ch, local_provider));
    }
    for peer in peers {
        for adv in &peer.channels {
            by_id
                .entry(adv.channel_id.clone())
                .or_insert_with(|| edge_from_advertised(adv));
        }
    }
    by_id.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(id: &str, a: &str, b: &str) -> GraphEdge {
        GraphEdge {
            channel_id: id.into(),
            a: a.into(),
            b: b.into(),
            via_provider: "Hub".into(),
            capacity_zhu: 0,
            a_available_zhu: 0,
            b_available_zhu: 0,
            liquidity_known: false,
        }
    }

    fn e_liq(id: &str, a: &str, b: &str, a_avail: u64, b_avail: u64) -> GraphEdge {
        GraphEdge {
            channel_id: id.into(),
            a: a.into(),
            b: b.into(),
            via_provider: "Hub".into(),
            capacity_zhu: a_avail + b_avail,
            a_available_zhu: a_avail,
            b_available_zhu: b_avail,
            liquidity_known: true,
        }
    }

    #[test]
    fn multi_hop_path_a_to_c_via_b() {
        let edges = vec![e("c1", "A", "B"), e("c2", "B", "C")];
        let path = find_path(&edges, "A", "C", 8).unwrap();
        assert_eq!(path.len(), 2);
        assert_eq!(path[0].channel_id, "c1");
        assert_eq!(path[1].channel_id, "c2");
        let signers = ordered_signers(&path, "A", "C");
        assert_eq!(signers[0], "C");
        assert_eq!(signers.last().unwrap(), "A");
        assert!(signers.contains(&"B".to_string()));
    }

    #[test]
    fn ordered_signers_include_every_intermediary_on_long_route() {
        let edges = vec![
            e("c1", "A", "B"),
            e("c2", "B", "C"),
            e("c3", "C", "D"),
            e("c4", "D", "E"),
        ];
        let path = find_path(&edges, "A", "E", 8).unwrap();
        assert_eq!(
            ordered_signers(&path, "A", "E"),
            vec!["E", "D", "C", "B", "A"]
        );
    }

    #[test]
    fn one_hop() {
        let edges = vec![e("c1", "A", "B")];
        let path = find_path(&edges, "A", "B", 8).unwrap();
        assert_eq!(path.len(), 1);
    }

    #[test]
    fn advertised_v2_liquidity_preserves_fractional_hac() {
        let advertised = AdvertisedChannel {
            channel_id: "11".repeat(16),
            left_address: "A".into(),
            right_address: "B".into(),
            via_provider: "Hub".into(),
            capacity_mei: 0,
            left_available_mei: 0,
            right_available_mei: 0,
            capacity_zhu: 100_000_000,
            left_available_zhu: 25_000_000,
            right_available_zhu: 75_000_000,
            fee_ppm: 0,
        };
        let edge = edge_from_advertised(&advertised);
        assert_eq!(edge.capacity_zhu, 100_000_000);
        assert!(can_send_from(&edge, "A", 25_000_000));
        assert!(!can_send_from(&edge, "A", 25_000_001));
    }

    #[test]
    fn advertised_v1_whole_hac_is_scaled_to_zhu() {
        let advertised = AdvertisedChannel {
            channel_id: "22".repeat(16),
            left_address: "A".into(),
            right_address: "B".into(),
            via_provider: "LegacyHub".into(),
            capacity_mei: 3,
            left_available_mei: 1,
            right_available_mei: 2,
            capacity_zhu: 0,
            left_available_zhu: 0,
            right_available_zhu: 0,
            fee_ppm: 0,
        };
        let edge = edge_from_advertised(&advertised);
        assert_eq!(edge.capacity_zhu, 300_000_000);
        assert_eq!(edge.a_available_zhu, 100_000_000);
        assert_eq!(edge.b_available_zhu, 200_000_000);
    }

    #[test]
    fn directional_blocks_empty_sender_side() {
        // A has 0, B has 100 — A cannot pay B 10
        let edges = vec![e_liq("c1", "A", "B", 0, 100)];
        let err = find_path_for_amount(&edges, "A", "B", 8, 10).unwrap_err();
        assert!(
            err.contains("liquidity") || err.contains("no path"),
            "{err}"
        );
        // B can pay A 10
        let path = find_path_for_amount(&edges, "B", "A", 8, 10).unwrap();
        assert_eq!(path.len(), 1);
    }

    #[test]
    fn directional_multi_hop() {
        // A--50/50--B--0/100--C : A→C needs B to forward; B has 0 toward C → fail
        let edges = vec![e_liq("c1", "A", "B", 50, 50), e_liq("c2", "B", "C", 0, 100)];
        let err = find_path_for_amount(&edges, "A", "C", 8, 10).unwrap_err();
        assert!(
            err.contains("liquidity") || err.contains("no path"),
            "{err}"
        );
        // C→A: C has 100, B has 50 toward A
        let path = find_path_for_amount(&edges, "C", "A", 8, 10).unwrap();
        assert_eq!(path.len(), 2);
    }

    #[test]
    fn unknown_liquidity_allows_path() {
        let edges = vec![e("c1", "A", "B")];
        let path = find_path_for_amount(&edges, "A", "B", 8, 999).unwrap();
        assert_eq!(path.len(), 1);
    }
}
