//! Typed, deterministic egress audit events.
//!
//! Every allow, deny, error, rate-limit, and unsupported-protocol decision in
//! both brokers emits exactly one [`AuditEvent`] through an [`AuditSink`].
//! Events are serializable to stable JSON (fixed field order per variant) so
//! they can be asserted in tests and shipped to a host audit trail. Errors are
//! surfaced as events, never swallowed.

use std::net::IpAddr;
use std::sync::Mutex;

use serde::Serialize;

use crate::dns_budget::DnsLimit;

/// A single, self-describing egress decision record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// A DNS query was answered with validated addresses.
    DnsAllowed {
        name: String,
        qtype: &'static str,
        answers: usize,
        ttl_secs: u32,
    },
    /// A DNS query was refused by policy (blocked domain, restricted address
    /// class, upstream failure, or malformed content).
    DnsDenied {
        name: String,
        response_code: &'static str,
        reason: &'static str,
    },
    /// A DNS query was rejected by a per-query structural limit.
    DnsStructuralRejected { name: String, limit: DnsLimit },
    /// A DNS query was rejected by a per-window exfiltration budget.
    DnsRateLimited { name: String, limit: DnsLimit },
    /// A DNS query used a QTYPE outside the allowlist.
    DnsUnsupportedQtype { name: String, qtype: &'static str },
    /// Inbound bytes could not be decoded as a DNS message.
    DnsMalformed,
    /// A CONNECT request was allowed and the tunnel opened.
    ConnectAllowed {
        target: String,
        ip: IpAddr,
        port: u16,
    },
    /// A CONNECT request was denied.
    ConnectDenied {
        target: String,
        port: u16,
        status: &'static str,
    },
    /// A CONNECT request used a non-TCP protocol (UDP/QUIC), which is always
    /// denied.
    ConnectUnsupportedProtocol { target: String, port: u16 },
    /// A CONNECT request was rejected because the concurrent-connection limit
    /// was already saturated.
    ConnectLimitExceeded,
    /// A CONNECT request frame could not be parsed, or the handshake timed
    /// out.
    ConnectError { detail: &'static str },
}

impl AuditEvent {
    /// Deterministic JSON encoding for logging or transport.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_owned())
    }
}

/// A destination for audit events. Implementations must be cheap and
/// non-blocking; the brokers call [`AuditSink::record`] on their hot path.
pub trait AuditSink: Send + Sync {
    fn record(&self, event: AuditEvent);
}

/// Discards every event. Used when auditing is disabled.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullAuditSink;

impl AuditSink for NullAuditSink {
    fn record(&self, _event: AuditEvent) {}
}

/// Collects events in memory for tests and deterministic diagnostics.
#[derive(Debug, Default)]
pub struct CollectingAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl CollectingAuditSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of every recorded event, in order.
    #[must_use]
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .expect("audit sink mutex poisoned")
            .clone()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.events.lock().expect("audit sink mutex poisoned").len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AuditSink for CollectingAuditSink {
    fn record(&self, event: AuditEvent) {
        self.events
            .lock()
            .expect("audit sink mutex poisoned")
            .push(event);
    }
}

/// Writes each event as one JSON line to stderr.
#[derive(Debug, Default, Clone, Copy)]
pub struct StderrJsonAuditSink;

impl AuditSink for StderrJsonAuditSink {
    fn record(&self, event: AuditEvent) {
        eprintln!("{}", event.to_json());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn events_serialize_with_stable_tag_and_fields() {
        let event = AuditEvent::ConnectAllowed {
            target: "example.com".to_owned(),
            ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            port: 443,
        };
        let json = event.to_json();
        assert!(json.starts_with("{\"event\":\"connect_allowed\""));
        assert!(json.contains("\"target\":\"example.com\""));
        assert!(json.contains("\"port\":443"));
    }

    #[test]
    fn dns_rate_limited_serializes_limit() {
        let event = AuditEvent::DnsRateLimited {
            name: "a.example".to_owned(),
            limit: DnsLimit::DynamicLabels,
        };
        let json = event.to_json();
        assert!(json.contains("\"event\":\"dns_rate_limited\""));
        assert!(json.contains("\"limit\":\"dynamic_labels\""));
    }

    #[test]
    fn collecting_sink_records_in_order() {
        let sink = CollectingAuditSink::new();
        assert!(sink.is_empty());
        sink.record(AuditEvent::DnsMalformed);
        sink.record(AuditEvent::ConnectLimitExceeded);
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], AuditEvent::DnsMalformed);
        assert_eq!(events[1], AuditEvent::ConnectLimitExceeded);
    }

    #[test]
    fn null_sink_drops_events() {
        let sink = NullAuditSink;
        sink.record(AuditEvent::DnsMalformed);
    }
}
