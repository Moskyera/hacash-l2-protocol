//! SSRF-safe outbound webhooks for payment/invoice events (+ HMAC + retries).

use std::time::Duration;

use reqwest::Client;
use serde::Serialize;
use tracing::{debug, warn};

use crate::hacash_keys;
use crate::ssrf::{validate_peer_url, UrlSafety};

#[derive(Clone)]
pub struct WebhookClient {
    client: Client,
    allow_private: bool,
    /// Optional HMAC secret; when set, sends X-Hacash-Signature: hex(sha3(secret||body))
    hmac_secret: String,
    max_retries: u32,
}

impl WebhookClient {
    pub fn new(allow_private: bool, hmac_secret: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(5))
                .connect_timeout(Duration::from_secs(3))
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| Client::new()),
            allow_private,
            hmac_secret: hmac_secret.trim().to_string(),
            max_retries: 3,
        }
    }

    pub async fn post_json<T: Serialize + ?Sized>(&self, url: &str, body: &T) -> bool {
        let url = url.trim();
        if url.is_empty() {
            return false;
        }
        match validate_peer_url(url, self.allow_private) {
            UrlSafety::Ok => {}
            UrlSafety::Reject(msg) => {
                warn!(%url, %msg, "webhook blocked (SSRF policy)");
                return false;
            }
        }
        let payload = match serde_json::to_vec(body) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "webhook serialize failed");
                return false;
            }
        };
        let sig = if self.hmac_secret.is_empty() {
            String::new()
        } else {
            let mut data = self.hmac_secret.as_bytes().to_vec();
            data.extend_from_slice(&payload);
            hex::encode(hacash_keys::sha3(&data))
        };

        for attempt in 1..=self.max_retries {
            let mut req = self
                .client
                .post(url)
                .header("content-type", "application/json")
                .body(payload.clone());
            if !sig.is_empty() {
                req = req
                    .header("x-hacash-signature", &sig)
                    .header("x-hacash-signature-alg", "sha3-256(secret||body)");
            }
            match req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    debug!(%url, attempt, status = %resp.status(), "webhook delivered");
                    return true;
                }
                Ok(resp) => {
                    warn!(%url, attempt, status = %resp.status(), "webhook non-success");
                }
                Err(e) => {
                    warn!(%url, attempt, error = %e, "webhook failed");
                }
            }
            if attempt < self.max_retries {
                tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
            }
        }
        false
    }
}

#[derive(Debug, Serialize)]
pub struct WebhookEvent {
    pub protocol: &'static str,
    pub event: String,
    pub payment_id: Option<String>,
    pub invoice_id: Option<String>,
    pub status: String,
    pub ts_unix: u64,
    pub detail: serde_json::Value,
}
