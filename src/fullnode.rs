//! L1 fullnode HTTP client (query APIs used by the L2 hub).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde_json::Value as JV;
use tracing::{debug, warn};

#[derive(Clone)]
pub struct FullnodeClient {
    base: String,
    token: String,
    client: Client,
}

impl FullnodeClient {
    pub fn new(host_port: String, token: String) -> Self {
        let base = host_port
            .trim()
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .to_string();
        Self {
            base,
            token: token.trim().to_string(),
            client: Client::builder()
                .timeout(Duration::from_secs(15))
                .connect_timeout(Duration::from_secs(2))
                .no_proxy()
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }

    /// Fast liveness probe (short timeout — health checks must not hang).
    pub async fn ping_quick(&self) -> bool {
        let url = format!("http://{}/query/latest", self.base);
        let client = Client::builder()
            .timeout(Duration::from_millis(800))
            .connect_timeout(Duration::from_millis(400))
            .no_proxy()
            .build()
            .unwrap_or_else(|_| Client::new());
        let mut req = client.get(&url);
        if !self.token.is_empty() {
            req = req.header("x-api-token", &self.token);
        }
        match req.send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    fn apply_token(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if self.token.is_empty() {
            req
        } else {
            req.header("x-api-token", &self.token)
        }
    }

    pub async fn latest_height(&self) -> Result<u64, String> {
        let url = format!("http://{}/query/latest", self.base);
        let req = self.apply_token(self.client.get(&url));
        let resp = req.send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("fullnode HTTP {}", resp.status()));
        }
        let v: JV = resp.json().await.map_err(|e| e.to_string())?;
        if v.get("ret").and_then(JV::as_u64) != Some(0) {
            return Err(format!(
                "fullnode latest query failed: {}",
                v.get("err")
                    .and_then(JV::as_str)
                    .unwrap_or("invalid response")
            ));
        }
        v.get("height")
            .and_then(JV::as_u64)
            .ok_or_else(|| "fullnode latest response missing integer height".to_string())
    }

    /// Query on-chain channel state via fullnode `/query/channel?id=...`.
    pub async fn query_channel(&self, channel_id_hex: &str) -> Result<JV, String> {
        let id = channel_id_hex.trim().trim_start_matches("0x");
        let url = format!("http://{}/query/channel?id={id}&unit=fin", self.base);
        debug!(%url, "query L1 channel");
        let req = self.apply_token(self.client.get(&url));
        let resp = req.send().await.map_err(|e| e.to_string())?;
        let status = resp.status();
        let body = resp.text().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            warn!(%status, %body, "channel query failed");
            return Err(format!("fullnode HTTP {status}: {body}"));
        }
        let value: JV =
            serde_json::from_str(&body).map_err(|e| format!("invalid channel JSON: {e}"))?;
        if value.get("ret").and_then(JV::as_u64) != Some(0) {
            return Err(format!(
                "fullnode channel query failed: {}",
                value
                    .get("err")
                    .and_then(JV::as_str)
                    .unwrap_or("invalid response")
            ));
        }
        Ok(value)
    }

    pub async fn query_channel_observation(
        &self,
        channel_id_hex: &str,
    ) -> Result<crate::l1_anchor::L1ChannelObservationV1, String> {
        let observed_height = self.latest_height().await?;
        let value = self.query_channel(channel_id_hex).await?;
        let observed_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        crate::l1_anchor::parse_fullnode_channel_observation(
            channel_id_hex,
            &value,
            observed_height,
            observed_unix,
        )
    }

    /// Query the node's actually registered and height-enabled action codecs.
    /// Exit readiness must be capability-gated; source-code-only action models
    /// are not consensus features.
    pub async fn query_exit_capabilities(
        &self,
    ) -> Result<crate::l1_exit::FullnodeExitCapabilitiesV1, String> {
        let url = format!("http://{}/query/capabilities", self.base);
        let req = self.apply_token(self.client.get(&url));
        let resp = req.send().await.map_err(|error| error.to_string())?;
        let status = resp.status();
        let body = resp.text().await.map_err(|error| error.to_string())?;
        if !status.is_success() {
            return Err(format!(
                "fullnode capabilities HTTP {status}: {}",
                body.chars().take(512).collect::<String>()
            ));
        }
        let value: JV = serde_json::from_str(&body)
            .map_err(|error| format!("invalid fullnode capabilities JSON: {error}"))?;
        crate::l1_exit::FullnodeExitCapabilitiesV1::parse(&value)
    }

    pub async fn ping(&self) -> bool {
        self.latest_height().await.is_ok()
    }

    /// Submit a raw signed transaction hex to fullnode (best-effort paths).
    /// Operators may set custom path via `submit_tx` config on the hub.
    pub async fn submit_tx_hex(&self, tx_hex: &str, path: &str) -> Result<JV, String> {
        let path = if path.trim().is_empty() {
            "/submit/transaction"
        } else {
            path.trim()
        };
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let url = format!("http://{}{path}", self.base);
        let hex = tx_hex.trim().trim_start_matches("0x");
        // try JSON body first
        let req = self.apply_token(
            self.client
                .post(&url)
                .json(&serde_json::json!({ "txhex": hex, "hex": hex })),
        );
        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                if status.is_success() {
                    return serde_json::from_str(&text)
                        .or_else(|_| Ok(serde_json::json!({ "ok": true, "raw": text })));
                }
                // fallback query param style
                let url2 = format!("{url}?txhex={hex}");
                let req2 = self.apply_token(self.client.post(&url2));
                let resp2 = req2.send().await.map_err(|e| e.to_string())?;
                let status2 = resp2.status();
                let text2 = resp2.text().await.unwrap_or_default();
                if status2.is_success() {
                    serde_json::from_str(&text2)
                        .or_else(|_| Ok(serde_json::json!({ "ok": true, "raw": text2 })))
                } else {
                    Err(format!(
                        "fullnode submit failed HTTP {status}/{status2}: {text} | {text2}"
                    ))
                }
            }
            Err(e) => Err(e.to_string()),
        }
    }
}
