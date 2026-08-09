//! hacash-l2-hub — standalone Channel Service Provider for Hacash L2.
//!
//! This binary is the **L2 Channel Chain protocol** project (not part of the miner).
//! Discovery, smart wallet/agent API, secp256k1 payments, last bills, dispute export.
//! No custody of user keys.

mod agent_api;
mod agent_id;
mod agent_pay;
mod amounts;
mod api;
mod auth;
mod channel_activation;
mod channel_state;
mod channel_state_store;
mod close_plan;
mod config;
mod crypto;
mod discover;
mod distributed_tx;
mod fullnode;
mod hacash_keys;
mod hvm_stub;
mod invoice;
mod l1_anchor;
mod l1_exit;
mod metrics;
mod micro;
mod net;
mod persist;
mod policy;
mod ratelimit;
mod route;
mod smart;
mod ssrf;
mod state;
mod types;
mod webhook;
mod x402;

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use tracing::{debug, info, warn};

use crate::api::{router, AppState};
use crate::config::HubArgs;
use crate::fullnode::FullnodeClient;
use crate::net::{
    bootstrap_peer, bootstrap_seed_list, gossip_loop, l1_watch_loop, load_seeds_file,
    payment_ttl_loop, NetClient,
};
use crate::persist::{load_into, persist_loop};
use crate::state::{HubLimits, HubState};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "l2_hub=info,hacash_l2_hub=info".into()),
        )
        .init();

    let args = HubArgs::parse();
    if let Err(e) = args.validate() {
        eprintln!("config error: {e}");
        std::process::exit(2);
    }

    let public_url = args.resolved_public_url();
    let fullnode = FullnodeClient::new(args.fullnode.clone(), args.fullnode_token.clone());

    let limits = HubLimits {
        max_payment_sessions: args.max_payment_sessions,
        max_channels: args.max_channels,
        max_peers: args.max_peers,
        max_hops: args.max_hops,
        payment_ttl_secs: args.payment_ttl_secs,
        require_sig_verify: args.sig_verify,
        ..HubLimits::default()
    };
    let mut hub_state =
        HubState::with_limits_and_policy(args.provider_id.clone(), limits, args.agent_policy());

    let identity = args.identity_account();
    if let Some(ref acc) = identity {
        info!(
            identity = %acc.readable(),
            "hub identity loaded — peer hellos + receipts will be signed"
        );
        hub_state.set_hub_identity(args.identity_account().expect("identity already resolved"));
    } else {
        info!("hub identity not set — hellos/receipts unsigned (lab mode). Set HACASH_L2_IDENTITY_PASSWORD for global mesh authenticity");
    }

    let hub = Arc::new(hub_state);

    if let Some(path) = args.state_path_opt() {
        match load_into(hub.as_ref(), &path, &args.provider_id) {
            Ok(n) => info!(channels = n, path = %path.display(), "state loaded"),
            Err(error) => {
                eprintln!("state load failed; refusing unsafe empty startup: {error}");
                std::process::exit(2);
            }
        }
    }

    let distributed =
        match crate::distributed_tx::DistributedTxManager::open(args.state_path_opt().as_deref()) {
            Ok(manager) => Arc::new(manager),
            Err(error) => {
                eprintln!("durable transaction journal error: {error}");
                std::process::exit(2);
            }
        };
    match distributed.recover_local(&hub) {
        Ok(recovered) if recovered > 0 => {
            info!(recovered, "replayed durable distributed transaction state")
        }
        Ok(_) => {}
        Err(error) => {
            eprintln!("distributed transaction recovery failed: {error}");
            std::process::exit(2);
        }
    }

    let mut meta = args.hub_meta();
    meta = hub.enrich_meta_capacity(meta);
    let net = NetClient::with_identity(
        args.provider_id.clone(),
        public_url.clone(),
        args.name.clone(),
        meta,
        args.allow_private_peers,
        identity,
        args.hello_max_age_secs,
        args.require_valid_hello_sig,
    );

    // 1) Explicit bootstrap URLs
    for url in args.bootstrap_urls() {
        match bootstrap_peer(&net, hub.as_ref(), &url).await {
            Ok(p) => info!(provider = %p.provider_id, %url, "bootstrap ok"),
            Err(e) => warn!(%url, error = %e, "bootstrap failed (hub still starts)"),
        }
    }

    // 2) Remote seeds URL
    if !args.seeds_url.trim().is_empty() {
        match net.fetch_seeds_json(args.seeds_url.trim()).await {
            Ok(seeds) => {
                info!(count = seeds.len(), url = %args.seeds_url, "loaded remote community seeds");
                let n = bootstrap_seed_list(&net, hub.as_ref(), &seeds).await;
                info!(bootstrapped = n, "remote seeds bootstrap done");
            }
            Err(e) => warn!(error = %e, "remote seeds_url fetch failed"),
        }
    }

    // 3) Local seeds file (if present and no remote-only)
    {
        let path = if args.seeds_path.trim().is_empty() {
            "seeds.example.json".to_string()
        } else {
            args.seeds_path.clone()
        };
        if std::path::Path::new(&path).exists() && args.bootstrap_urls().is_empty() {
            match load_seeds_file(&path) {
                Ok(seeds) if !seeds.is_empty() => {
                    info!(count = seeds.len(), %path, "loading local seeds file");
                    let n = bootstrap_seed_list(&net, hub.as_ref(), &seeds).await;
                    info!(bootstrapped = n, "local seeds bootstrap done");
                }
                Ok(_) => {}
                Err(e) => debug!(error = %e, "seeds file not loaded"),
            }
        }
    }

    if args.announce_on_start {
        let peers = hub.list_peers();
        for p in peers {
            if p.provider_id == args.provider_id {
                continue;
            }
            match bootstrap_peer(&net, hub.as_ref(), &p.public_url).await {
                Ok(_) => info!(to = %p.provider_id, "announce-on-start ok"),
                Err(e) => debug!(to = %p.provider_id, error = %e, "announce-on-start skip"),
            }
        }
    }

    if args.gossip_secs > 0 {
        let net_g = net.clone();
        let hub_g = hub.clone();
        let secs = args.gossip_secs;
        tokio::spawn(async move {
            gossip_loop(net_g, hub_g, secs).await;
        });
        info!(interval_secs = secs, "peer gossip loop started");
    }

    if args.watch_secs > 0 {
        let fn_w = fullnode.clone();
        let hub_w = hub.clone();
        let secs = args.watch_secs;
        tokio::spawn(async move {
            l1_watch_loop(fn_w, hub_w, secs).await;
        });
        info!(interval_secs = secs, "L1 channel watch loop started");
    }

    let persist_lock = Arc::new(tokio::sync::Mutex::new(()));
    if args.payment_ttl_secs > 0 {
        let hub_t = hub.clone();
        tokio::spawn(async move {
            payment_ttl_loop(hub_t, 15).await;
        });
        info!(ttl_secs = args.payment_ttl_secs, "payment TTL loop started");
    }

    if let Some(path) = args.state_path_opt() {
        let hub_p = hub.clone();
        let lock_p = persist_lock.clone();
        let pid = args.provider_id.clone();
        let secs = args.persist_secs.max(5);
        tokio::spawn(async move {
            persist_loop(hub_p, path, pid, secs, lock_p).await;
        });
        info!(interval_secs = secs, "state persist loop started");
    }

    if distributed.enabled() {
        let manager = distributed.clone();
        let hub_recovery = hub.clone();
        let net_recovery = net.clone();
        tokio::spawn(async move {
            crate::distributed_tx::recovery_loop(manager, hub_recovery, net_recovery, 10).await;
        });
        info!("durable distributed transaction recovery loop started");
    }

    let state = AppState {
        args: args.clone(),
        fullnode,
        hub,
        net,
        distributed,
        webhooks: crate::webhook::WebhookClient::new(
            args.allow_private_peers,
            args.webhook_secret.clone(),
        ),
        persist_lock,
        metrics: Arc::new(crate::metrics::HubMetrics::default()),
        rate_limit: Arc::new(crate::ratelimit::RateLimiter::new(
            args.rate_limit_per_window,
            args.rate_window_secs,
        )),
    };

    let addr: SocketAddr = args
        .bind
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:9090".parse().unwrap());

    info!(
        "hacash-l2-hub phase=global-mesh name={} provider_id={} bind={} public_url={} fullnode={} api_token={} allow_private={} fee_ppm={}",
        args.name,
        args.provider_id,
        addr,
        public_url,
        args.fullnode,
        if args.api_token.trim().is_empty() {
            "off"
        } else {
            "on"
        },
        args.allow_private_peers,
        args.fee_ppm
    );
    info!("Global mesh: signed hello · capacity · fees · seeds · announce · rebalance · deferred");
    info!("Wallet Find hubs → GET /v1/discover");
    info!("AI agents → GET /v1/agent/connect");
    info!("Trust: settled = hub-coordinated only (not L1 final) — see SECURITY.md / NETWORK-GLOBAL.md");
    info!(
        "Phase B sig_verify={} (SHA3-256 + secp256k1 Hacash Sign)",
        args.sig_verify
    );
    info!("API root: http://{addr}/");

    let app = router(state).layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {addr}: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}
