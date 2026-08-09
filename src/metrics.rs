//! In-process Prometheus-style metrics (text exposition).

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct HubMetrics {
    pub payments_created: AtomicU64,
    pub payments_settled: AtomicU64,
    pub payments_failed: AtomicU64,
    pub invoices_created: AtomicU64,
    pub invoices_paid: AtomicU64,
    pub micro_pushes: AtomicU64,
    pub agent_requests: AtomicU64,
    pub webhooks_sent: AtomicU64,
    pub webhooks_failed: AtomicU64,
    pub durable_checkpoints: AtomicU64,
    pub durable_checkpoint_failures: AtomicU64,
    pub x402_challenges: AtomicU64,
    pub rate_limited: AtomicU64,
}

impl HubMetrics {
    pub fn inc(a: &AtomicU64) {
        a.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        let g = |name: &str, help: &str, v: &AtomicU64| {
            format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {}\n",
                v.load(Ordering::Relaxed)
            )
        };
        let mut out = String::from("# Hacash L2 hub metrics\n");
        out.push_str(&g(
            "hacash_l2_payments_created_total",
            "Payment sessions created",
            &self.payments_created,
        ));
        out.push_str(&g(
            "hacash_l2_payments_settled_total",
            "Payments settled on hub",
            &self.payments_settled,
        ));
        out.push_str(&g(
            "hacash_l2_payments_failed_total",
            "Payments failed/cancelled",
            &self.payments_failed,
        ));
        out.push_str(&g(
            "hacash_l2_invoices_created_total",
            "Invoices created",
            &self.invoices_created,
        ));
        out.push_str(&g(
            "hacash_l2_invoices_paid_total",
            "Invoices marked paid",
            &self.invoices_paid,
        ));
        out.push_str(&g(
            "hacash_l2_micro_pushes_total",
            "Micropayment pushes",
            &self.micro_pushes,
        ));
        out.push_str(&g(
            "hacash_l2_agent_requests_total",
            "Agent API requests",
            &self.agent_requests,
        ));
        out.push_str(&g(
            "hacash_l2_webhooks_sent_total",
            "Webhooks delivered",
            &self.webhooks_sent,
        ));
        out.push_str(&g(
            "hacash_l2_webhooks_failed_total",
            "Webhooks failed",
            &self.webhooks_failed,
        ));
        out.push_str(&g(
            "hacash_l2_x402_challenges_total",
            "HTTP 402 payment challenges issued",
            &self.x402_challenges,
        ));
        out.push_str(&g(
            "hacash_l2_durable_checkpoints_total",
            "Successful synchronous checkpoints after critical mutations",
            &self.durable_checkpoints,
        ));
        out.push_str(&g(
            "hacash_l2_durable_checkpoint_failures_total",
            "Failed synchronous checkpoints after critical mutations",
            &self.durable_checkpoint_failures,
        ));
        out.push_str(&g(
            "hacash_l2_rate_limited_total",
            "Rate limited requests",
            &self.rate_limited,
        ));
        out
    }

    pub fn render_with_operational(&self, stats: &crate::state::OperationalStats) -> String {
        let mut output = self.render();
        let gauge = |name: &str, help: &str, value: u64| {
            format!("# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n")
        };
        for (name, help, value) in [
            (
                "hacash_l2_liquidity_reservations",
                "Active payment liquidity reservations",
                stats.liquidity_reservations,
            ),
            (
                "hacash_l2_oldest_reservation_age_seconds",
                "Age of the oldest active liquidity reservation",
                stats.oldest_reservation_age_seconds,
            ),
            (
                "hacash_l2_applied_settlements",
                "Exactly-once settlement guards retained",
                stats.applied_settlements,
            ),
            (
                "hacash_l2_agent_identities",
                "Registered agent identities",
                stats.agent_identities,
            ),
            (
                "hacash_l2_revoked_agent_identities",
                "Revoked agent identities",
                stats.revoked_agent_identities,
            ),
            (
                "hacash_l2_open_micro_streams",
                "Open micropayment streams",
                stats.open_micro_streams,
            ),
            (
                "hacash_l2_active_agent_intent_nonces",
                "Unexpired signed agent intent nonces",
                stats.active_agent_intent_nonces,
            ),
            (
                "hacash_l2_scheduled_deferred_payments",
                "Scheduled or ready deferred payments",
                stats.scheduled_deferred_payments,
            ),
            (
                "hacash_l2_active_rebalances",
                "Proposed or collecting rebalances",
                stats.active_rebalances,
            ),
        ] {
            output.push_str(&gauge(name, help, value));
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operational_gauges_are_rendered_with_current_values() {
        let metrics = HubMetrics::default();
        let output = metrics.render_with_operational(&crate::state::OperationalStats {
            liquidity_reservations: 2,
            revoked_agent_identities: 1,
            open_micro_streams: 3,
            ..Default::default()
        });
        assert!(output.contains("hacash_l2_liquidity_reservations 2"));
        assert!(output.contains("hacash_l2_revoked_agent_identities 1"));
        assert!(output.contains("hacash_l2_open_micro_streams 3"));
    }
}
