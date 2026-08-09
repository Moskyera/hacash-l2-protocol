//! Optional API token for operator-sensitive mutators.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Check `X-Api-Token` (or `Authorization: Bearer …`) against configured token.
///
/// - Empty `configured` → open (no auth required).
/// - Non-empty → must match exactly.
pub fn require_api_token(headers: &HeaderMap, configured: &str) -> Result<(), Response> {
    let expected = configured.trim();
    if expected.is_empty() {
        return Ok(());
    }
    let provided = headers
        .get("x-api-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| {
                    let s = s.trim();
                    s.strip_prefix("Bearer ")
                        .or_else(|| s.strip_prefix("bearer "))
                        .map(|t| t.trim().to_string())
                })
        })
        .unwrap_or_default();

    if provided == expected {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({
                "ok": false,
                "err": "missing or invalid API token (X-Api-Token or Authorization: Bearer)",
                "hint": "Operator endpoints require --api-token when configured",
            })),
        )
            .into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn open_when_empty() {
        let h = HeaderMap::new();
        assert!(require_api_token(&h, "").is_ok());
        assert!(require_api_token(&h, "   ").is_ok());
    }

    #[test]
    fn rejects_missing() {
        let h = HeaderMap::new();
        assert!(require_api_token(&h, "secret").is_err());
    }

    #[test]
    fn accepts_header() {
        let mut h = HeaderMap::new();
        h.insert("x-api-token", HeaderValue::from_static("secret"));
        assert!(require_api_token(&h, "secret").is_ok());
    }

    #[test]
    fn accepts_bearer() {
        let mut h = HeaderMap::new();
        h.insert("authorization", HeaderValue::from_static("Bearer secret"));
        assert!(require_api_token(&h, "secret").is_ok());
    }
}
