//! SSRF-safe URL checks for outbound hub bootstrap / gossip targets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Result of validating a peer base URL before any outbound HTTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlSafety {
    Ok,
    Reject(String),
}

/// Validate a hub base URL used for bootstrap / peer hello.
///
/// - Only `http` / `https`
/// - Host required; no credentials
/// - Blocks link-local / loopback / private / multicast unless `allow_private`
/// - Blocks obvious cloud metadata hostnames
pub fn validate_peer_url(raw: &str, allow_private: bool) -> UrlSafety {
    let raw = raw.trim();
    if raw.is_empty() {
        return UrlSafety::Reject("url is empty".into());
    }
    if raw.len() > 512 {
        return UrlSafety::Reject("url too long (max 512)".into());
    }
    // Reject schemes other than http(s) early (no file:, gopher:, etc.)
    let lower = raw.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return UrlSafety::Reject("only http:// or https:// peer URLs allowed".into());
    }
    if raw.contains('@') {
        return UrlSafety::Reject("credentials in URL are not allowed".into());
    }

    let without_scheme = if lower.starts_with("https://") {
        &raw[8..]
    } else {
        &raw[7..]
    };
    let host_port_path = without_scheme.split('/').next().unwrap_or("");
    if host_port_path.is_empty() {
        return UrlSafety::Reject("missing host".into());
    }

    // strip IPv6 brackets if present
    let host = if host_port_path.starts_with('[') {
        let end = match host_port_path.find(']') {
            Some(i) => i,
            None => return UrlSafety::Reject("invalid IPv6 host".into()),
        };
        &host_port_path[1..end]
    } else {
        host_port_path
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host_port_path)
    };

    let host_l = host.to_ascii_lowercase();
    if host_l.is_empty() {
        return UrlSafety::Reject("empty host".into());
    }
    if is_blocked_hostname(&host_l) {
        return UrlSafety::Reject(format!("blocked hostname: {host_l}"));
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if !allow_private && is_unsafe_ip(ip) {
            return UrlSafety::Reject(format!(
                "private/loopback/link-local IP not allowed (set --allow-private-peers for local nets): {ip}"
            ));
        }
        return UrlSafety::Ok;
    }

    // Hostname (not raw IP): still block localhost names when private disallowed
    if !allow_private && is_local_hostname(&host_l) {
        return UrlSafety::Reject(format!(
            "local hostname not allowed without --allow-private-peers: {host_l}"
        ));
    }

    UrlSafety::Ok
}

fn is_blocked_hostname(host: &str) -> bool {
    matches!(
        host,
        "metadata"
            | "metadata.google.internal"
            | "metadata.goog"
            | "instance-data"
            | "kubernetes.default"
            | "kubernetes.default.svc"
    ) || host.ends_with(".internal")
        || host.ends_with(".localdomain")
        || host == "0.0.0.0"
}

fn is_local_hostname(host: &str) -> bool {
    host == "localhost"
        || host == "localhost.localdomain"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
}

fn is_unsafe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_unsafe_v4(v4),
        IpAddr::V6(v6) => is_unsafe_v6(v6),
    }
}

fn is_unsafe_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.octets()[0] == 0
        // Carrier-grade NAT 100.64/10
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64)
        // AWS/GCP metadata often 169.254.169.254 (already link_local)
        || ip.octets()[0] == 169 && ip.octets()[1] == 254
}

fn is_unsafe_v6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || (ip.to_ipv4_mapped().map(is_unsafe_v4).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_file_and_creds() {
        assert!(matches!(
            validate_peer_url("file:///etc/passwd", false),
            UrlSafety::Reject(_)
        ));
        assert!(matches!(
            validate_peer_url("http://user:pass@evil.com", false),
            UrlSafety::Reject(_)
        ));
    }

    #[test]
    fn rejects_private_by_default() {
        assert!(matches!(
            validate_peer_url("http://127.0.0.1:9090", false),
            UrlSafety::Reject(_)
        ));
        assert!(matches!(
            validate_peer_url("http://10.0.0.5:9090", false),
            UrlSafety::Reject(_)
        ));
        assert!(matches!(
            validate_peer_url("http://169.254.169.254/", false),
            UrlSafety::Reject(_)
        ));
        assert!(matches!(
            validate_peer_url("http://localhost:9090", false),
            UrlSafety::Reject(_)
        ));
    }

    #[test]
    fn allows_private_when_flag() {
        assert_eq!(
            validate_peer_url("http://127.0.0.1:9090", true),
            UrlSafety::Ok
        );
        assert_eq!(
            validate_peer_url("http://10.1.2.3:9090", true),
            UrlSafety::Ok
        );
    }

    #[test]
    fn allows_public_https() {
        assert_eq!(
            validate_peer_url("https://hub.example.com:9090", false),
            UrlSafety::Ok
        );
    }
}
