//! Multi-process durability and network-fault coverage for distributed 2PC.
//!
//! This test launches real hub binaries and is intentionally ignored during
//! the fast unit suite. Run with:
//! cargo test --test chaos_2pc -- --ignored --nocapture

#[path = "../src/hacash_keys.rs"]
mod hacash_keys;

#[path = "chaos_2pc/matrix.rs"]
mod matrix;

use std::fs::{self, File};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hacash_keys::Account;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::task::JoinHandle;
use uuid::Uuid;

const API_TOKEN: &str = "chaos-operator-token";
const CRASH_EXIT_CODE: i32 = 86;
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(18);
static PROCESS_LOG_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct HubSpec {
    provider_id: String,
    bind: SocketAddr,
    public_url: String,
    state_path: PathBuf,
    work_dir: PathBuf,
}

impl HubSpec {
    fn direct_url(&self) -> String {
        format!("http://{}", self.bind)
    }
}

struct HubProcess {
    child: Child,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl HubProcess {
    fn start(spec: &HubSpec, crash_at: Option<&str>) -> Result<Self, String> {
        let log_id = PROCESS_LOG_ID.fetch_add(1, Ordering::Relaxed);
        let stdout_path = spec
            .work_dir
            .join(format!("{}-{log_id}.stdout.log", spec.provider_id));
        let stderr_path = spec
            .work_dir
            .join(format!("{}-{log_id}.stderr.log", spec.provider_id));
        let stdout = File::create(&stdout_path).map_err(|error| error.to_string())?;
        let stderr = File::create(&stderr_path).map_err(|error| error.to_string())?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_hacash-l2-hub"));
        command
            .current_dir(&spec.work_dir)
            .arg("--bind")
            .arg(spec.bind.to_string())
            .arg("--public-url")
            .arg(&spec.public_url)
            .arg("--provider-id")
            .arg(&spec.provider_id)
            .arg("--name")
            .arg(&spec.provider_id)
            .arg("--state-path")
            .arg(&spec.state_path)
            .arg("--identity-password")
            .arg(format!("{}-identity-secret", spec.provider_id))
            .arg("--api-token")
            .arg(API_TOKEN)
            .arg("--seeds-path")
            .arg(spec.work_dir.join("no-seeds.json"))
            .env("HACASH_L2_ALLOW_PRIVATE_PEERS", "true")
            .env("HACASH_L2_ANNOUNCE_ON_START", "false")
            .env("HACASH_L2_GOSSIP_SECS", "0")
            .env("HACASH_L2_WATCH_SECS", "0")
            .env("HACASH_L2_PAYMENT_TTL_SECS", "0")
            .env("HACASH_L2_PERSIST_SECS", "3600")
            .env("HACASH_L2_SIG_VERIFY", "true")
            .env("HACASH_L2_REQUIRE_VALID_HELLO_SIG", "true")
            .env("RUST_LOG", "warn")
            .env_remove("HACASH_L2_ENABLE_CHAOS")
            .env_remove("HACASH_L2_CHAOS_CRASH_AT")
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        if let Some(point) = crash_at {
            command
                .env("HACASH_L2_ENABLE_CHAOS", "1")
                .env("HACASH_L2_CHAOS_CRASH_AT", point);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let child = command.spawn().map_err(|error| error.to_string())?;
        Ok(Self {
            child,
            stdout_path,
            stderr_path,
        })
    }

    fn logs(&self) -> String {
        let stdout = fs::read_to_string(&self.stdout_path).unwrap_or_default();
        let stderr = fs::read_to_string(&self.stderr_path).unwrap_or_default();
        format!("stdout:\n{stdout}\nstderr:\n{stderr}")
    }

    fn stop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }

    async fn expect_chaos_exit(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    if status.code() == Some(CRASH_EXIT_CODE) {
                        tokio::time::sleep(Duration::from_millis(150)).await;
                        return Ok(());
                    }
                    return Err(format!(
                        "expected chaos exit {CRASH_EXIT_CODE}, got {status}\n{}",
                        self.logs()
                    ));
                }
                Ok(None) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Ok(None) => {
                    return Err(format!("hub did not reach chaos exit\n{}", self.logs()));
                }
                Err(error) => return Err(error.to_string()),
            }
        }
    }
}

impl Drop for HubProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

struct PartitionProxy {
    public_url: String,
    partitioned: Arc<AtomicBool>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
    task: JoinHandle<()>,
}

impl PartitionProxy {
    async fn start(target: SocketAddr) -> Result<Self, String> {
        let listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let partitioned = Arc::new(AtomicBool::new(false));
        let gate = partitioned.clone();
        let connections = Arc::new(Mutex::new(Vec::new()));
        let active = connections.clone();
        let task = tokio::spawn(async move {
            while let Ok((inbound, _)) = listener.accept().await {
                let gate = gate.clone();
                let connection = tokio::spawn(async move {
                    let mut inbound = inbound;
                    if gate.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(mut outbound) = TcpStream::connect(target).await else {
                        return;
                    };
                    let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
                });
                if let Ok(mut handles) = active.lock() {
                    handles.push(connection);
                }
            }
        });
        Ok(Self {
            public_url: format!("http://{address}"),
            partitioned,
            connections,
            task,
        })
    }

    fn set_partitioned(&self, partitioned: bool) {
        self.partitioned.store(partitioned, Ordering::SeqCst);
        if partitioned {
            if let Ok(mut connections) = self.connections.lock() {
                for connection in connections.drain(..) {
                    connection.abort();
                }
            }
        }
    }
}

impl Drop for PartitionProxy {
    fn drop(&mut self) {
        self.task.abort();
        if let Ok(mut connections) = self.connections.lock() {
            for connection in connections.drain(..) {
                connection.abort();
            }
        }
    }
}

struct Cluster {
    root: PathBuf,
    client: Client,
    proxy: PartitionProxy,
    a_spec: HubSpec,
    b_spec: HubSpec,
    a: Option<HubProcess>,
    b: Option<HubProcess>,
    payer: Account,
    intermediary: Account,
    payee: Account,
    a_channel: String,
    b_channel: String,
}

impl Cluster {
    async fn start(
        label: &str,
        channel_seed: u8,
        a_crash_at: Option<&str>,
        b_crash_at: Option<&str>,
    ) -> Result<Self, String> {
        let root = std::env::temp_dir().join(format!("hacash-l2-chaos-{label}-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).map_err(|error| error.to_string())?;
        let a_bind = reserve_address()?;
        let b_bind = reserve_address()?;
        let proxy = PartitionProxy::start(b_bind).await?;
        let a_spec = HubSpec {
            provider_id: "HubA".into(),
            bind: a_bind,
            public_url: format!("http://{a_bind}"),
            state_path: root.join("hub-a-state.json"),
            work_dir: root.clone(),
        };
        let b_spec = HubSpec {
            provider_id: "HubB".into(),
            bind: b_bind,
            public_url: proxy.public_url.clone(),
            state_path: root.join("hub-b-state.json"),
            work_dir: root.clone(),
        };
        let client = Client::builder()
            .timeout(Duration::from_secs(12))
            .connect_timeout(Duration::from_secs(2))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string())?;
        let payer = Account::create_by_password(&format!("{label}-payer"))?;
        let intermediary = Account::create_by_password(&format!("{label}-intermediary"))?;
        let payee = Account::create_by_password(&format!("{label}-payee"))?;
        let mut cluster = Self {
            root,
            client,
            proxy,
            a_spec,
            b_spec,
            a: None,
            b: None,
            payer,
            intermediary,
            payee,
            a_channel: format!("{channel_seed:02x}").repeat(16),
            b_channel: format!("{:02x}", channel_seed.saturating_add(1)).repeat(16),
        };
        cluster.start_b(b_crash_at).await?;
        cluster.start_a(a_crash_at).await?;
        cluster.configure_network().await?;
        Ok(cluster)
    }

    async fn start_a(&mut self, crash_at: Option<&str>) -> Result<(), String> {
        if self.a.is_some() {
            return Err("HubA already running".into());
        }
        let process = HubProcess::start(&self.a_spec, crash_at)?;
        self.a = Some(process);
        wait_ready(
            &self.client,
            &self.a_spec.direct_url(),
            self.a.as_mut().expect("HubA inserted"),
        )
        .await
    }

    async fn start_b(&mut self, crash_at: Option<&str>) -> Result<(), String> {
        if self.b.is_some() {
            return Err("HubB already running".into());
        }
        let process = HubProcess::start(&self.b_spec, crash_at)?;
        self.b = Some(process);
        wait_ready(
            &self.client,
            &self.b_spec.direct_url(),
            self.b.as_mut().expect("HubB inserted"),
        )
        .await
    }

    fn stop_a(&mut self) {
        if let Some(mut process) = self.a.take() {
            process.stop();
        }
    }

    fn stop_b(&mut self) {
        if let Some(mut process) = self.b.take() {
            process.stop();
        }
    }

    async fn expect_a_crash(&mut self) -> Result<(), String> {
        let mut process = self.a.take().ok_or("HubA process missing")?;
        process.expect_chaos_exit().await
    }

    async fn expect_b_crash(&mut self) -> Result<(), String> {
        let mut process = self.b.take().ok_or("HubB process missing")?;
        process.expect_chaos_exit().await
    }

    async fn configure_network(&self) -> Result<(), String> {
        self.register_primary_channels().await?;
        post_json(
            &self.client,
            &self.a_spec.direct_url(),
            "/v1/net/bootstrap",
            json!({ "url": self.proxy.public_url }),
            Some(API_TOKEN),
            None,
        )
        .await?;
        // Registration is a synchronous durable checkpoint. Re-registering the
        // same idle channel persists the verified peer pins learned above.
        self.register_primary_channels().await?;
        let peers = get_json(
            &self.client,
            &self.a_spec.direct_url(),
            "/v1/net/peers",
            None,
        )
        .await?;
        let peer_b = peers["peers"]
            .as_array()
            .and_then(|peers| peers.iter().find(|peer| peer["provider_id"] == "HubB"))
            .ok_or("HubA did not pin HubB")?;
        if peer_b["identity_verified"] != true {
            return Err("HubB identity was not verified".into());
        }
        Ok(())
    }

    async fn register_primary_channels(&self) -> Result<(), String> {
        register_channel(
            &self.client,
            &self.a_spec.direct_url(),
            &self.a_channel,
            self.payer.readable(),
            self.intermediary.readable(),
        )
        .await?;
        register_channel(
            &self.client,
            &self.b_spec.direct_url(),
            &self.b_channel,
            self.intermediary.readable(),
            self.payee.readable(),
        )
        .await
    }

    async fn create_payment(&self, idempotency_key: &str) -> Result<Value, String> {
        let response = post_json(
            &self.client,
            &self.a_spec.direct_url(),
            "/v1/payments",
            json!({
                "payer": self.payer.readable(),
                "payee": self.payee.readable(),
                "amount_hac": "1:248",
                "amount_satoshi": 0,
                "fee_hac": "0",
                "route": [self.a_channel, self.b_channel],
                "local_only": false,
            }),
            None,
            Some(idempotency_key),
        )
        .await?;
        Ok(response["payment"].clone())
    }

    async fn sign(&self, payment: &Value, account: &Account) -> Result<Value, String> {
        let id = payment["id"].as_str().ok_or("payment id missing")?;
        let hash = payment["message_hash_hex"]
            .as_str()
            .ok_or("payment hash missing")?;
        post_json(
            &self.client,
            &self.a_spec.direct_url(),
            &format!("/v1/payments/{id}/sign"),
            json!({
                "address": account.readable(),
                "signature_hex": packed_signature(account, hash)?,
                "public_key_hex": "",
            }),
            None,
            None,
        )
        .await
    }

    async fn sign_first_two(&self, payment: &Value) -> Result<(), String> {
        self.sign(payment, &self.payee).await?;
        self.sign(payment, &self.intermediary).await?;
        Ok(())
    }

    async fn fail_payment(&self, payment_id: &str, reason: &str) -> Result<Value, String> {
        post_json(
            &self.client,
            &self.a_spec.direct_url(),
            &format!("/v1/payments/{payment_id}/fail"),
            json!({ "reason": reason }),
            Some(API_TOKEN),
            None,
        )
        .await
    }

    async fn payment_status(&self, payment_id: &str) -> Result<String, String> {
        let response = get_json(
            &self.client,
            &self.a_spec.direct_url(),
            &format!("/v1/payments/{payment_id}"),
            None,
        )
        .await?;
        response["payment"]["status"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "payment status missing".into())
    }

    async fn wait_payment_status(&self, payment_id: &str, expected: &str) -> Result<(), String> {
        let deadline = Instant::now() + RECOVERY_TIMEOUT;
        let mut last = String::new();
        while Instant::now() < deadline {
            match self.payment_status(payment_id).await {
                Ok(status) if status == expected => return Ok(()),
                Ok(status) => last = status,
                Err(error) => last = error,
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(format!(
            "payment {payment_id} did not reach {expected}; last={last}"
        ))
    }

    async fn transaction_state(&self, hub_url: &str, payment_id: &str) -> Result<String, String> {
        let response = get_json(
            &self.client,
            hub_url,
            "/v1/net/transactions",
            Some(API_TOKEN),
        )
        .await?;
        response["transactions"]
            .as_array()
            .and_then(|transactions| {
                transactions
                    .iter()
                    .find(|transaction| transaction["tx_id"] == payment_id)
            })
            .and_then(|transaction| transaction["state"].as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("transaction {payment_id} missing on {hub_url}"))
    }

    async fn wait_transaction_state(
        &self,
        hub_url: &str,
        payment_id: &str,
        expected: &str,
    ) -> Result<(), String> {
        let deadline = Instant::now() + RECOVERY_TIMEOUT;
        let mut last = String::new();
        while Instant::now() < deadline {
            match self.transaction_state(hub_url, payment_id).await {
                Ok(state) if state == expected => return Ok(()),
                Ok(state) => last = state,
                Err(error) => last = error,
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(format!(
            "transaction {payment_id} did not reach {expected}; last={last}"
        ))
    }

    async fn left_hac(&self, hub_url: &str, channel_id: &str) -> Result<String, String> {
        let response = get_json(
            &self.client,
            hub_url,
            &format!("/v1/channels/{channel_id}"),
            None,
        )
        .await?;
        response["channel"]["left_hac"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "left_hac missing".into())
    }

    async fn assert_left_balances(&self, expected: &str) -> Result<(), String> {
        let origin = self
            .left_hac(&self.a_spec.direct_url(), &self.a_channel)
            .await?;
        let participant = self
            .left_hac(&self.b_spec.direct_url(), &self.b_channel)
            .await?;
        if origin != expected || participant != expected {
            return Err(format!(
                "balance mismatch: expected {expected}, origin={origin}, participant={participant}; artifacts={}",
                self.root.display()
            ));
        }
        Ok(())
    }

    async fn only_payment(&self) -> Result<Value, String> {
        let response = get_json(
            &self.client,
            &self.a_spec.direct_url(),
            "/v1/payments?limit=10",
            None,
        )
        .await?;
        let payments = response["payments"]
            .as_array()
            .ok_or("payments array missing")?;
        if payments.len() != 1 {
            return Err(format!("expected one payment, got {}", payments.len()));
        }
        Ok(payments[0].clone())
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        self.stop_a();
        self.stop_b();
        self.proxy.task.abort();
        if !std::thread::panicking()
            && std::env::var("HACASH_KEEP_CHAOS_ARTIFACTS").as_deref() != Ok("1")
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn reserve_address() -> Result<SocketAddr, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    drop(listener);
    Ok(address)
}

async fn wait_ready(
    client: &Client,
    base_url: &str,
    process: &mut HubProcess,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = process
            .child
            .try_wait()
            .map_err(|error| error.to_string())?
        {
            return Err(format!(
                "hub exited during startup with {status}\n{}",
                process.logs()
            ));
        }
        if client
            .get(format!("{base_url}/"))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("hub startup timeout\n{}", process.logs()));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn register_channel(
    client: &Client,
    base_url: &str,
    channel_id: &str,
    left: &str,
    right: &str,
) -> Result<(), String> {
    post_json(
        client,
        base_url,
        "/v1/channels",
        json!({
            "channel_id": channel_id,
            "left_address": left,
            "right_address": right,
            "left_hac": "4:248",
            "right_hac": "0",
            "left_satoshi": 0,
            "right_satoshi": 0,
            "notes": "multi-process chaos fixture",
        }),
        Some(API_TOKEN),
        None,
    )
    .await
    .map(|_| ())
}

fn packed_signature(account: &Account, hash_hex: &str) -> Result<String, String> {
    let decoded = hex::decode(hash_hex).map_err(|error| error.to_string())?;
    let hash: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "payment hash must be 32 bytes".to_string())?;
    let mut packed = Vec::with_capacity(97);
    packed.extend_from_slice(&account.public_key().serialize_compressed());
    packed.extend_from_slice(&account.do_sign(&hash));
    Ok(hex::encode(packed))
}

async fn get_json(
    client: &Client,
    base_url: &str,
    path: &str,
    token: Option<&str>,
) -> Result<Value, String> {
    request_json(client, Method::GET, base_url, path, None, token, None).await
}

async fn post_json(
    client: &Client,
    base_url: &str,
    path: &str,
    body: Value,
    token: Option<&str>,
    idempotency_key: Option<&str>,
) -> Result<Value, String> {
    request_json(
        client,
        Method::POST,
        base_url,
        path,
        Some(body),
        token,
        idempotency_key,
    )
    .await
}

async fn request_json(
    client: &Client,
    method: Method,
    base_url: &str,
    path: &str,
    body: Option<Value>,
    token: Option<&str>,
    idempotency_key: Option<&str>,
) -> Result<Value, String> {
    let mut request = client.request(method, format!("{base_url}{path}"));
    if let Some(body) = body {
        request = request.json(&body);
    }
    if let Some(token) = token {
        request = request.header("X-Api-Token", token);
    }
    if let Some(key) = idempotency_key {
        request = request.header("Idempotency-Key", key);
    }
    let response = request.send().await.map_err(|error| error.to_string())?;
    let status = response.status();
    let text = response.text().await.map_err(|error| error.to_string())?;
    let json: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));
    if !status.is_success() {
        return Err(format!("HTTP {status}: {json}"));
    }
    Ok(json)
}

async fn coordinator_commit_decision_crash_recovers_in_reverse_order() -> Result<(), String> {
    let mut cluster = Cluster::start(
        "coordinator-decision",
        0xa0,
        Some("coordinator_after_commit_decision_fsync"),
        None,
    )
    .await?;
    let payment = cluster
        .create_payment("coordinator-decision-payment")
        .await?;
    let payment_id = payment["id"]
        .as_str()
        .ok_or("payment id missing")?
        .to_string();
    cluster.sign_first_two(&payment).await?;
    if cluster.sign(&payment, &cluster.payer).await.is_ok() {
        return Err("final signature unexpectedly survived coordinator crash".into());
    }
    cluster.expect_a_crash().await?;
    if cluster
        .transaction_state(&cluster.b_spec.direct_url(), &payment_id)
        .await?
        != "participant_prepared"
    {
        return Err("participant was not durably prepared".into());
    }

    cluster.stop_b();
    // Reverse dependency order: coordinator starts while participant is down.
    cluster.start_a(None).await?;
    cluster
        .wait_payment_status(&payment_id, "committing")
        .await?;
    cluster.start_b(None).await?;
    cluster.wait_payment_status(&payment_id, "settled").await?;
    cluster
        .wait_transaction_state(
            &cluster.a_spec.direct_url(),
            &payment_id,
            "coordinator_committed",
        )
        .await?;
    cluster
        .wait_transaction_state(
            &cluster.b_spec.direct_url(),
            &payment_id,
            "participant_committed",
        )
        .await?;
    if cluster
        .left_hac(&cluster.a_spec.direct_url(), &cluster.a_channel)
        .await?
        != "3:248"
        || cluster
            .left_hac(&cluster.b_spec.direct_url(), &cluster.b_channel)
            .await?
            != "3:248"
    {
        return Err("coordinator crash recovery produced incorrect balances".into());
    }

    cluster.stop_a();
    cluster.start_a(None).await?;
    cluster.wait_payment_status(&payment_id, "settled").await?;
    let replay_balance = cluster
        .left_hac(&cluster.a_spec.direct_url(), &cluster.a_channel)
        .await?;
    if replay_balance != "3:248" {
        return Err(format!(
            "coordinator replay balance mismatch: expected 3:248, got {replay_balance}; artifacts={}",
            cluster.root.display()
        ));
    }
    Ok(())
}

async fn participant_commit_decision_crash_recovers_exactly_once() -> Result<(), String> {
    let mut cluster = Cluster::start(
        "participant-decision",
        0xb0,
        None,
        Some("participant_after_commit_decision_fsync"),
    )
    .await?;
    let payment = cluster
        .create_payment("participant-decision-payment")
        .await?;
    let payment_id = payment["id"]
        .as_str()
        .ok_or("payment id missing")?
        .to_string();
    cluster.sign_first_two(&payment).await?;
    let final_response = cluster.sign(&payment, &cluster.payer).await?;
    if final_response["payment"]["status"] != "committing" {
        return Err(format!(
            "origin did not retain commit decision: {final_response}"
        ));
    }
    cluster.expect_b_crash().await?;
    cluster.start_b(None).await?;
    cluster.wait_payment_status(&payment_id, "settled").await?;
    if cluster
        .left_hac(&cluster.a_spec.direct_url(), &cluster.a_channel)
        .await?
        != "3:248"
        || cluster
            .left_hac(&cluster.b_spec.direct_url(), &cluster.b_channel)
            .await?
            != "3:248"
    {
        return Err("participant decision recovery produced incorrect balances".into());
    }
    cluster.stop_b();
    cluster.start_b(None).await?;
    if cluster
        .left_hac(&cluster.b_spec.direct_url(), &cluster.b_channel)
        .await?
        != "3:248"
    {
        return Err("participant replay applied settlement twice".into());
    }
    Ok(())
}

async fn lost_prepare_ack_is_durably_aborted_after_restart() -> Result<(), String> {
    let mut cluster = Cluster::start(
        "prepare-ack",
        0xc0,
        None,
        Some("participant_after_prepare_fsync"),
    )
    .await?;
    if cluster.create_payment("prepare-ack-payment").await.is_ok() {
        return Err("prepare unexpectedly succeeded despite participant crash".into());
    }
    cluster.expect_b_crash().await?;
    let payment = cluster.only_payment().await?;
    let payment_id = payment["id"]
        .as_str()
        .ok_or("payment id missing")?
        .to_string();
    if payment["status"] != "failed"
        || cluster
            .transaction_state(&cluster.a_spec.direct_url(), &payment_id)
            .await?
            != "coordinator_abort_decided"
    {
        return Err(format!(
            "origin did not retain presumed-abort decision: {payment}"
        ));
    }

    cluster.stop_a();
    // Participant-first restart order: its prepared reservation must remain
    // blocked until the coordinator returns with the signed abort decision.
    cluster.start_b(None).await?;
    if cluster
        .transaction_state(&cluster.b_spec.direct_url(), &payment_id)
        .await?
        != "participant_prepared"
    {
        return Err("participant did not recover its prepared reservation".into());
    }
    cluster.start_a(None).await?;
    cluster
        .wait_transaction_state(
            &cluster.a_spec.direct_url(),
            &payment_id,
            "coordinator_aborted",
        )
        .await?;
    cluster
        .wait_transaction_state(
            &cluster.b_spec.direct_url(),
            &payment_id,
            "participant_aborted",
        )
        .await?;
    if cluster
        .left_hac(&cluster.a_spec.direct_url(), &cluster.a_channel)
        .await?
        != "4:248"
        || cluster
            .left_hac(&cluster.b_spec.direct_url(), &cluster.b_channel)
            .await?
            != "4:248"
    {
        return Err("prepare-abort recovery changed balances".into());
    }
    Ok(())
}

async fn live_network_partition_retries_commit() -> Result<(), String> {
    let cluster = Cluster::start("network-partition", 0xd0, None, None).await?;
    let payment = cluster.create_payment("partition-payment").await?;
    let payment_id = payment["id"]
        .as_str()
        .ok_or("payment id missing")?
        .to_string();
    cluster.sign_first_two(&payment).await?;
    cluster.proxy.set_partitioned(true);
    let final_response = cluster.sign(&payment, &cluster.payer).await?;
    if final_response["payment"]["status"] != "committing" {
        return Err(format!(
            "origin did not expose durable commit pending: {final_response}"
        ));
    }
    if cluster
        .left_hac(&cluster.a_spec.direct_url(), &cluster.a_channel)
        .await?
        != "3:248"
        || cluster
            .left_hac(&cluster.b_spec.direct_url(), &cluster.b_channel)
            .await?
            != "4:248"
    {
        return Err("partition did not isolate participant application".into());
    }
    cluster.proxy.set_partitioned(false);
    cluster.wait_payment_status(&payment_id, "settled").await?;
    if cluster
        .left_hac(&cluster.b_spec.direct_url(), &cluster.b_channel)
        .await?
        != "3:248"
    {
        return Err("partition recovery did not apply participant exactly once".into());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "launches real hub processes and injects crashes/network partitions"]
async fn multi_process_2pc_survives_crashes_restart_order_and_partition() {
    coordinator_commit_decision_crash_recovers_in_reverse_order()
        .await
        .unwrap();
    participant_commit_decision_crash_recovers_exactly_once()
        .await
        .unwrap();
    lost_prepare_ack_is_durably_aborted_after_restart()
        .await
        .unwrap();
    live_network_partition_retries_commit().await.unwrap();
    matrix::run_remaining_fault_matrix().await.unwrap();
}
