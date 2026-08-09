//! Opt-in Linux Docker chaos coverage for three-hub distributed payments.
//!
//! cargo test --test docker_chaos_3hub -- --ignored --nocapture

#[allow(dead_code, clippy::manual_is_multiple_of)]
#[path = "../src/amounts.rs"]
mod amounts;
#[path = "../src/hacash_keys.rs"]
mod hacash_keys;

use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::future::join_all;
use hacash_keys::Account;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use uuid::Uuid;

const IMAGE: &str = "hacash-l2-hub:chaos-3hub";
const TOKEN: &str = "docker-chaos-operator-token";
const TIMEOUT: Duration = Duration::from_secs(45);
static DOCKER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone)]
struct Hub {
    provider: String,
    container: String,
    volume: String,
    host_url: String,
    internal_url: String,
}

struct Lab {
    network: String,
    hubs: Vec<Hub>,
    client: Client,
    keep: bool,
}

impl Lab {
    async fn start(suffix: &str) -> Result<Self, String> {
        let mut lab = Self {
            network: format!("hacash-l2-chaos-net-{suffix}"),
            hubs: Vec::new(),
            client: Client::builder()
                .timeout(Duration::from_secs(20))
                .connect_timeout(Duration::from_secs(3))
                .no_proxy()
                .build()
                .map_err(|e| e.to_string())?,
            keep: false,
        };
        docker(&["network", "create", "--driver", "bridge", &lab.network])?;
        for (letter, provider) in [("a", "HubA"), ("b", "HubB"), ("c", "HubC")] {
            let container = format!("hacash-l2-chaos-{letter}-{suffix}");
            let volume = format!("hacash-l2-chaos-{letter}-data-{suffix}");
            let port = reserve_port()?;
            let hub = Hub {
                provider: provider.into(),
                internal_url: format!("http://{container}:9090"),
                container,
                volume,
                host_url: format!("http://127.0.0.1:{port}"),
            };
            docker(&["volume", "create", &hub.volume])?;
            lab.hubs.push(hub.clone());
            let port_map = format!("127.0.0.1:{port}:9090");
            let volume_map = format!("{}:/data", hub.volume);
            let public_url = format!("HACASH_L2_PUBLIC_URL={}", hub.internal_url);
            let provider_id = format!("HACASH_L2_PROVIDER_ID={provider}");
            let name = format!("HACASH_L2_NAME={provider}-docker-chaos");
            let identity = format!("HACASH_L2_IDENTITY_PASSWORD={provider}-docker-chaos-identity");
            let token = format!("HACASH_L2_API_TOKEN={TOKEN}");
            docker(&[
                "run",
                "-d",
                "--name",
                &hub.container,
                "--hostname",
                &hub.container,
                "--network",
                &lab.network,
                "-p",
                &port_map,
                "-v",
                &volume_map,
                "-e",
                "HACASH_L2_BIND=0.0.0.0:9090",
                "-e",
                &public_url,
                "-e",
                &provider_id,
                "-e",
                &name,
                "-e",
                &identity,
                "-e",
                &token,
                "-e",
                "HACASH_L2_STATE_PATH=/data/hub-state.json",
                "-e",
                "HACASH_L2_ALLOW_PRIVATE_PEERS=true",
                "-e",
                "HACASH_L2_REQUIRE_VALID_HELLO_SIG=true",
                "-e",
                "HACASH_L2_SIG_VERIFY=true",
                "-e",
                "HACASH_L2_ANNOUNCE_ON_START=false",
                "-e",
                "HACASH_L2_GOSSIP_SECS=0",
                "-e",
                "HACASH_L2_WATCH_SECS=0",
                "-e",
                "HACASH_L2_PAYMENT_TTL_SECS=0",
                "-e",
                "HACASH_L2_PERSIST_SECS=3600",
                "-e",
                "HACASH_L2_SEEDS_URL=",
                "-e",
                "HACASH_L2_SEEDS_PATH=/dev/null",
                "-e",
                "RUST_LOG=hacash_l2_hub=warn",
                "--health-cmd",
                "curl -fsS http://127.0.0.1:9090/health || exit 1",
                "--health-interval",
                "2s",
                "--health-timeout",
                "2s",
                "--health-retries",
                "15",
                IMAGE,
            ])?;
        }
        for index in 0..3 {
            lab.wait_ready(index).await?;
        }
        Ok(lab)
    }

    async fn wait_ready(&self, index: usize) -> Result<(), String> {
        let hub = &self.hubs[index];
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut last = String::new();
        while Instant::now() < deadline {
            match get(self, index, "/health", None).await {
                Ok(_) => return Ok(()),
                Err(error) => last = error,
            }
            if docker(&["inspect", "--format", "{{.State.Status}}", &hub.container])
                .is_ok_and(|s| s == "exited" || s == "dead")
            {
                return Err(format!(
                    "{} exited\n{}",
                    hub.container,
                    logs(&hub.container)
                ));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(format!("{} readiness timeout: {last}", hub.container))
    }

    fn kill(&self, index: usize) -> Result<(), String> {
        docker(&["kill", "--signal", "KILL", &self.hubs[index].container]).map(|_| ())
    }

    async fn start_hub(&self, index: usize) -> Result<(), String> {
        docker(&["start", &self.hubs[index].container])?;
        self.wait_ready(index).await
    }

    async fn start_order(&self, order: &[usize]) -> Result<(), String> {
        for index in order {
            self.start_hub(*index).await?;
        }
        Ok(())
    }

    fn disconnect(&self, index: usize) -> Result<(), String> {
        docker(&[
            "network",
            "disconnect",
            "--force",
            &self.network,
            &self.hubs[index].container,
        ])
        .map(|_| ())
    }

    fn connect(&self, index: usize) -> Result<(), String> {
        docker(&[
            "network",
            "connect",
            &self.network,
            &self.hubs[index].container,
        ])
        .map(|_| ())
    }

    fn diagnostics(&self) -> String {
        let mut out = format!("network={}\n", self.network);
        for hub in &self.hubs {
            out.push_str(&format!(
                "\n===== {} ({}) =====\n{}",
                hub.provider,
                hub.container,
                logs(&hub.container)
            ));
        }
        out
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        if self.keep || std::env::var("HACASH_KEEP_DOCKER_CHAOS").as_deref() == Ok("1") {
            eprintln!("preserving Docker resources: {}", self.network);
            return;
        }
        for hub in &self.hubs {
            let _ = docker(&["rm", "-f", &hub.container]);
        }
        let _ = docker(&["network", "rm", &self.network]);
        for hub in &self.hubs {
            let _ = docker(&["volume", "rm", "-f", &hub.volume]);
        }
    }
}

struct Fixture {
    payer: Account,
    middle_one: Account,
    middle_two: Account,
    payee: Account,
    channels: [String; 3],
}

impl Fixture {
    fn new(suffix: &str) -> Result<Self, String> {
        Ok(Self {
            payer: Account::create_by_password(&format!("{suffix}-payer"))?,
            middle_one: Account::create_by_password(&format!("{suffix}-middle-one"))?,
            middle_two: Account::create_by_password(&format!("{suffix}-middle-two"))?,
            payee: Account::create_by_password(&format!("{suffix}-payee"))?,
            channels: ["a1".repeat(16), "b2".repeat(16), "c3".repeat(16)],
        })
    }
}

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }
    fn shuffle<T>(&mut self, values: &mut [T]) {
        for i in (1..values.len()).rev() {
            let j = self.next() as usize % (i + 1);
            values.swap(i, j);
        }
    }
}

async fn configure(lab: &Lab, f: &Fixture) -> Result<(), String> {
    configure_capacity(lab, f, "8:248").await
}

async fn configure_capacity(lab: &Lab, f: &Fixture, left_hac: &str) -> Result<(), String> {
    register(
        lab,
        0,
        &f.channels[0],
        f.payer.readable(),
        f.middle_one.readable(),
        left_hac,
    )
    .await?;
    register(
        lab,
        1,
        &f.channels[1],
        f.middle_one.readable(),
        f.middle_two.readable(),
        left_hac,
    )
    .await?;
    register(
        lab,
        2,
        &f.channels[2],
        f.middle_two.readable(),
        f.payee.readable(),
        left_hac,
    )
    .await?;
    for participant in 1..=2 {
        post(
            lab,
            0,
            "/v1/net/bootstrap",
            json!({"url": lab.hubs[participant].internal_url}),
            Some(TOKEN),
            None,
        )
        .await?;
    }
    wait_peer(lab, 0, "HubB").await?;
    wait_peer(lab, 0, "HubC").await?;
    wait_peer(lab, 1, "HubA").await?;
    wait_peer(lab, 2, "HubA").await?;
    // A second critical mutation persists the verified identity pins too.
    register(
        lab,
        0,
        &f.channels[0],
        f.payer.readable(),
        f.middle_one.readable(),
        left_hac,
    )
    .await?;
    register(
        lab,
        1,
        &f.channels[1],
        f.middle_one.readable(),
        f.middle_two.readable(),
        left_hac,
    )
    .await?;
    register(
        lab,
        2,
        &f.channels[2],
        f.middle_two.readable(),
        f.payee.readable(),
        left_hac,
    )
    .await
}

async fn register(
    lab: &Lab,
    index: usize,
    id: &str,
    left: &str,
    right: &str,
    left_hac: &str,
) -> Result<(), String> {
    post(
        lab,
        index,
        "/v1/channels",
        json!({
            "channel_id": id, "left_address": left, "right_address": right,
            "left_hac": left_hac, "right_hac": "0", "left_satoshi": 0, "right_satoshi": 0,
            "notes": "three-hub Linux Docker chaos fixture"
        }),
        Some(TOKEN),
        None,
    )
    .await
    .map(|_| ())
}

async fn wait_peer(lab: &Lab, index: usize, provider: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last = String::new();
    while Instant::now() < deadline {
        match get(lab, index, "/v1/net/peers", None).await {
            Ok(v)
                if v["peers"].as_array().is_some_and(|peers| {
                    peers
                        .iter()
                        .any(|p| p["provider_id"] == provider && p["identity_verified"] == true)
                }) =>
            {
                return Ok(())
            }
            Ok(v) => last = v.to_string(),
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(format!(
        "{} did not verify {provider}: {last}",
        lab.hubs[index].provider
    ))
}

async fn create(lab: &Lab, f: &Fixture, key: &str) -> Result<Value, String> {
    let v = post(
        lab,
        0,
        "/v1/payments",
        json!({
            "payer": f.payer.readable(), "payee": f.payee.readable(), "amount_hac": "1:248",
            "amount_satoshi": 0, "fee_hac": "0", "route": f.channels.clone(), "local_only": false
        }),
        None,
        Some(key),
    )
    .await?;
    Ok(v["payment"].clone())
}

fn payment_id(payment: &Value) -> Result<String, String> {
    payment["id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "payment id missing".into())
}

fn packed_signature(account: &Account, hash_hex: &str) -> Result<String, String> {
    let hash: [u8; 32] = hex::decode(hash_hex)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "payment hash must be 32 bytes")?;
    let mut packed = Vec::with_capacity(97);
    packed.extend_from_slice(&account.public_key().serialize_compressed());
    packed.extend_from_slice(&account.do_sign(&hash));
    Ok(hex::encode(packed))
}

async fn sign(lab: &Lab, payment: &Value, account: &Account) -> Result<Value, String> {
    let id = payment_id(payment)?;
    let hash = payment["message_hash_hex"]
        .as_str()
        .ok_or("payment hash missing")?;
    post(lab, 0, &format!("/v1/payments/{id}/sign"), json!({
        "address": account.readable(), "signature_hex": packed_signature(account, hash)?, "public_key_hex": ""
    }), None, None).await
}

async fn sign_before_payer(lab: &Lab, f: &Fixture, p: &Value) -> Result<(), String> {
    sign(lab, p, &f.payee).await?;
    sign(lab, p, &f.middle_two).await?;
    sign(lab, p, &f.middle_one).await?;
    Ok(())
}

async fn wait_tx(lab: &Lab, index: usize, id: &str, expected: &str) -> Result<(), String> {
    let deadline = Instant::now() + TIMEOUT;
    let mut last = String::new();
    while Instant::now() < deadline {
        match get(lab, index, "/v1/net/transactions", Some(TOKEN)).await {
            Ok(v) => {
                let state = v["transactions"]
                    .as_array()
                    .and_then(|xs| xs.iter().find(|x| x["tx_id"] == id))
                    .and_then(|x| x["state"].as_str())
                    .unwrap_or("missing");
                if state == expected {
                    return Ok(());
                }
                last = state.into();
            }
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(format!(
        "{} transaction {id} did not reach {expected}: {last}",
        lab.hubs[index].provider
    ))
}

async fn wait_committed(lab: &Lab, id: &str) -> Result<(), String> {
    wait_tx(lab, 0, id, "coordinator_committed").await?;
    wait_tx(lab, 1, id, "participant_committed").await?;
    wait_tx(lab, 2, id, "participant_committed").await
}

async fn wait_balances(lab: &Lab, f: &Fixture, expected: &str) -> Result<(), String> {
    let expected_zhu = amounts::parse_zhu(expected)?;
    for (index, channel) in f.channels.iter().enumerate() {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let last = match get(lab, index, &format!("/v1/channels/{channel}"), None).await {
                Ok(v) => match v["channel"]["left_hac"].as_str() {
                    Some(left) => match amounts::parse_zhu(left) {
                        Ok(actual_zhu) if actual_zhu == expected_zhu => break,
                        Ok(actual_zhu) => format!(
                            "expected {expected} ({expected_zhu} Zhu), got {left} ({actual_zhu} Zhu)"
                        ),
                        Err(error) => format!("invalid left_hac {left}: {error}"),
                    },
                    None => "left_hac missing".into(),
                },
                Err(error) => error,
            };
            if Instant::now() >= deadline {
                return Err(format!(
                    "{} channel {channel} did not converge: {last}",
                    lab.hubs[index].provider
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    Ok(())
}

async fn run_chaos(lab: &mut Lab, f: &Fixture, rng: &mut Rng, rounds: usize) -> Result<(), String> {
    configure(lab, f).await?;
    let mut committed = Vec::new();

    let key = "docker-prepared-crash";
    let first = create(lab, f, key).await?;
    let first_id = payment_id(&first)?;
    for i in 0..3 {
        lab.kill(i)?;
    }
    let mut order = vec![0, 1, 2];
    rng.shuffle(&mut order);
    lab.start_order(&order).await?;
    let replay = create(lab, f, key).await?;
    if payment_id(&replay)? != first_id {
        return Err("prepared retry changed payment id".into());
    }
    sign_before_payer(lab, f, &replay).await?;
    sign(lab, &replay, &f.payer).await?;
    wait_committed(lab, &first_id).await?;
    committed.push(first_id);
    wait_balances(lab, f, "7:248").await?;

    for round in 0..rounds {
        let key = format!("docker-partial-commit-{round}");
        let payment = create(lab, f, &key).await?;
        let id = payment_id(&payment)?;
        sign_before_payer(lab, f, &payment).await?;
        lab.disconnect(2)?;
        let final_response = sign(lab, &payment, &f.payer).await?;
        if final_response["payment"]["status"] != "committing" {
            return Err(format!(
                "round {round} did not expose commit pending: {final_response}"
            ));
        }
        lab.kill(0)?;
        let kill_b = rng.coin();
        let kill_c = rng.coin();
        if kill_b {
            lab.kill(1)?;
        }
        lab.connect(2)?;
        if kill_c {
            lab.kill(2)?;
        }
        let mut killed = vec![0];
        if kill_b {
            killed.push(1);
        }
        if kill_c {
            killed.push(2);
        }
        rng.shuffle(&mut killed);
        lab.start_order(&killed).await?;
        wait_committed(lab, &id).await?;
        let replay = create(lab, f, &key).await?;
        if payment_id(&replay)? != id {
            return Err(format!("round {round} retry changed payment id"));
        }
        committed.push(id);
        wait_balances(
            lab,
            f,
            &format!("{}:248", 8usize.saturating_sub(committed.len())),
        )
        .await?;
    }

    for i in 0..3 {
        lab.kill(i)?;
    }
    let mut order = vec![0, 1, 2];
    rng.shuffle(&mut order);
    lab.start_order(&order).await?;
    for id in &committed {
        wait_committed(lab, id).await?;
    }
    wait_balances(
        lab,
        f,
        &format!("{}:248", 8usize.saturating_sub(committed.len())),
    )
    .await
}

async fn run_concurrent_soak(
    lab: &mut Lab,
    f: &Fixture,
    rng: &mut Rng,
    batches: usize,
    concurrency: usize,
) -> Result<(), String> {
    configure_capacity(lab, f, "64:248").await?;
    let mut committed_ids = Vec::new();

    for batch in 0..batches {
        let keys: Vec<String> = (0..concurrency)
            .map(|index| format!("docker-soak-{batch}-{index}"))
            .collect();
        let created_results = join_all(keys.iter().map(|key| create(lab, f, key))).await;
        let mut payments = Vec::with_capacity(concurrency);
        for (index, result) in created_results.into_iter().enumerate() {
            payments.push(result.map_err(|error| {
                format!("batch {batch} concurrent create {index} failed: {error}")
            })?);
        }

        let signing_results = join_all(
            payments
                .iter()
                .map(|payment| sign_before_payer(lab, f, payment)),
        )
        .await;
        for (index, result) in signing_results.into_iter().enumerate() {
            result.map_err(|error| {
                format!("batch {batch} pre-payer signature {index} failed: {error}")
            })?;
        }

        lab.disconnect(2)?;
        let final_results =
            join_all(payments.iter().map(|payment| sign(lab, payment, &f.payer))).await;
        for (index, result) in final_results.into_iter().enumerate() {
            let response = result.map_err(|error| {
                format!("batch {batch} final signature {index} failed: {error}")
            })?;
            if response["payment"]["status"] != "committing" {
                return Err(format!(
                    "batch {batch} payment {index} did not expose commit pending: {response}"
                ));
            }
        }

        // Every acknowledged response has a durable coordinator commit decision.
        // Kill the coordinator, then at least one alternating participant.
        lab.kill(0)?;
        let kill_b = batch % 2 == 0 || rng.coin();
        let kill_c = batch % 2 == 1 || rng.coin();
        if kill_b {
            lab.kill(1)?;
        }
        lab.connect(2)?;
        if kill_c {
            lab.kill(2)?;
        }
        let mut killed = vec![0];
        if kill_b {
            killed.push(1);
        }
        if kill_c {
            killed.push(2);
        }
        rng.shuffle(&mut killed);
        lab.start_order(&killed).await?;

        let mut batch_ids = Vec::with_capacity(concurrency);
        for payment in &payments {
            let id = payment_id(payment)?;
            wait_committed(lab, &id).await?;
            batch_ids.push(id);
        }
        let replay_results = join_all(keys.iter().map(|key| create(lab, f, key))).await;
        for (index, result) in replay_results.into_iter().enumerate() {
            let replay = result.map_err(|error| {
                format!("batch {batch} idempotent replay {index} failed: {error}")
            })?;
            if payment_id(&replay)? != batch_ids[index] {
                return Err(format!(
                    "batch {batch} idempotent replay {index} changed payment id"
                ));
            }
        }
        committed_ids.extend(batch_ids);
        let expected = format!("{}:248", 64usize.saturating_sub(committed_ids.len()));
        wait_balances(lab, f, &expected).await?;
    }

    for index in 0..3 {
        lab.kill(index)?;
    }
    let mut order = vec![0, 1, 2];
    rng.shuffle(&mut order);
    lab.start_order(&order).await?;
    for id in &committed_ids {
        wait_committed(lab, id).await?;
    }
    let expected = format!("{}:248", 64usize.saturating_sub(committed_ids.len()));
    wait_balances(lab, f, &expected).await
}
async fn get(lab: &Lab, index: usize, path: &str, token: Option<&str>) -> Result<Value, String> {
    // Docker Desktop can leave a published port pointing at the old bridge IP
    // after network disconnect/connect. Querying localhost inside the target
    // container guarantees that assertions observe the intended hub.
    let url = format!("http://127.0.0.1:9090{path}");
    let token_header = token.map(|value| format!("X-Api-Token: {value}"));
    let mut args = vec!["exec", &lab.hubs[index].container, "curl", "-sS"];
    if let Some(header) = token_header.as_deref() {
        args.extend(["-H", header]);
    }
    args.push(&url);
    let text = docker(&args)?;
    let value: Value = serde_json::from_str(&text).map_err(|error| {
        format!(
            "{} returned invalid JSON: {error}",
            lab.hubs[index].provider
        )
    })?;
    if value["ok"] == false {
        Err(format!("container GET {path}: {value}"))
    } else {
        Ok(value)
    }
}
async fn post(
    lab: &Lab,
    index: usize,
    path: &str,
    body: Value,
    token: Option<&str>,
    key: Option<&str>,
) -> Result<Value, String> {
    request(
        &lab.client,
        Method::POST,
        &lab.hubs[index].host_url,
        path,
        Some(body),
        token,
        key,
    )
    .await
}
async fn request(
    client: &Client,
    method: Method,
    base: &str,
    path: &str,
    body: Option<Value>,
    token: Option<&str>,
    key: Option<&str>,
) -> Result<Value, String> {
    let mut req = client.request(method, format!("{base}{path}"));
    if let Some(v) = body {
        req = req.json(&v);
    }
    if let Some(v) = token {
        req = req.header("X-Api-Token", v);
    }
    if let Some(v) = key {
        req = req.header("Idempotency-Key", v);
    }
    let response = req.send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    let text = response.text().await.map_err(|e| e.to_string())?;
    let value = serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text}));
    if status.is_success() {
        Ok(value)
    } else {
        Err(format!("HTTP {status}: {value}"))
    }
}

fn docker(args: &[&str]) -> Result<String, String> {
    let output = Command::new("docker")
        .args(args)
        .output()
        .map_err(|e| format!("launch docker {}: {e}", args.join(" ")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "docker {} failed with {}\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            output.status,
            stdout,
            stderr
        ))
    }
}
fn logs(container: &str) -> String {
    docker(&["logs", "--tail", "200", container]).unwrap_or_else(|e| e)
}
fn reserve_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    drop(listener);
    Ok(port)
}
fn build_image() -> Result<(), String> {
    if std::env::var("HACASH_DOCKER_CHAOS_SKIP_BUILD").as_deref() == Ok("1") {
        docker(&["image", "inspect", IMAGE]).map(|_| ())
    } else {
        eprintln!("building Linux chaos image {IMAGE}");
        docker(&["build", "--tag", IMAGE, env!("CARGO_MANIFEST_DIR")]).map(|_| ())
    }
}
fn default_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "builds Linux image and injects Docker SIGKILL/network partitions"]
async fn linux_three_hub_randomized_kill_partition_recovery() {
    let _docker_guard = DOCKER_TEST_LOCK.lock().await;
    build_image().unwrap();
    let seed = std::env::var("HACASH_DOCKER_CHAOS_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(default_seed);
    let rounds = std::env::var("HACASH_DOCKER_CHAOS_ROUNDS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2)
        .clamp(1, 5);
    let suffix = Uuid::new_v4().simple().to_string()[..10].to_string();
    eprintln!("docker chaos seed={seed} rounds={rounds} suffix={suffix}");
    let mut lab = Lab::start(&suffix).await.unwrap();
    let fixture = Fixture::new(&suffix).unwrap();
    let mut rng = Rng::new(seed);
    if let Err(error) = run_chaos(&mut lab, &fixture, &mut rng, rounds).await {
        let diagnostics = lab.diagnostics();
        lab.keep = true;
        panic!("three-hub Docker chaos failed: {error}\nseed={seed}\n{diagnostics}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "runs concurrent three-hub Docker load with SIGKILL and partitions"]
async fn linux_three_hub_concurrent_partition_soak() {
    let _docker_guard = DOCKER_TEST_LOCK.lock().await;
    build_image().unwrap();
    let seed = std::env::var("HACASH_DOCKER_SOAK_SEED")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(default_seed);
    let batches = std::env::var("HACASH_DOCKER_SOAK_BATCHES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(2)
        .clamp(1, 6);
    let concurrency = std::env::var("HACASH_DOCKER_SOAK_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(4)
        .clamp(2, 8);
    let suffix = Uuid::new_v4().simple().to_string()[..10].to_string();
    eprintln!(
        "docker soak seed={seed} batches={batches} concurrency={concurrency} suffix={suffix}"
    );
    let mut lab = Lab::start(&suffix).await.unwrap();
    let fixture = Fixture::new(&suffix).unwrap();
    let mut rng = Rng::new(seed);
    if let Err(error) =
        run_concurrent_soak(&mut lab, &fixture, &mut rng, batches, concurrency).await
    {
        let diagnostics = lab.diagnostics();
        lab.keep = true;
        panic!("three-hub Docker soak failed: {error}\nseed={seed}\n{diagnostics}");
    }
}
