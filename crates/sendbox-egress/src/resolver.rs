//! Injectable upstream DNS resolution used by the DNS broker.
//!
//! The broker performs real DNS message decode/encode via `hickory-proto` and
//! delegates the actual name→address lookup to an [`UpstreamResolver`]. The
//! production implementation is
//! [`crate::forwarding_resolver::ForwardingResolver`]; tests and the local
//! harness use [`crate::fixture_resolver::StaticResolver`].

use std::io;
use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use hickory_proto::rr::Name;
use sendbox_policy::DnsRecordType;
use serde::Serialize;
use thiserror::Error;

/// A resolved address with its authoritative TTL, prior to any policy TTL
/// cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedAddress {
    pub ip: IpAddr,
    pub ttl_secs: u32,
}

/// The full result of resolving a name: every intermediate CNAME hop (in
/// query order, excluding the original queried name and the final owner
/// name), the final canonical owner name, and every address record returned
/// for that final name.
#[derive(Debug, Clone)]
pub struct ResolvedChain {
    pub cname_chain: Vec<Name>,
    pub final_name: Name,
    pub addresses: Vec<ResolvedAddress>,
}

impl ResolvedChain {
    /// Every domain name that must be validated against policy: each CNAME
    /// hop plus the final owner name. The originally queried name is
    /// validated separately by the caller since it is known before
    /// resolution begins.
    pub fn names_to_validate(&self) -> impl Iterator<Item = &Name> {
        self.cname_chain
            .iter()
            .chain(std::iter::once(&self.final_name))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveFailureKind {
    Nxdomain,
    Timeout,
    BrokerTimeout,
    Io,
    InvalidResponse,
    ResponseCode,
    Upstream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsOperation {
    Bind,
    Connect,
    Send,
    Receive,
    ReadLength,
    ReadBody,
}

/// Safe to expose in audit events and proxy errors: never includes an upstream
/// error's free-form message, response bytes or client credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolveFailure {
    pub kind: ResolveFailureKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<SocketAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qtype: Option<DnsRecordType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<DnsTransport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<DnsOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_error: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<u16>,
}

impl ResolveFailure {
    #[must_use]
    pub const fn new(kind: ResolveFailureKind) -> Self {
        Self {
            kind,
            upstream: None,
            qtype: None,
            transport: None,
            operation: None,
            io_kind: None,
            os_error: None,
            detail: None,
            response_code: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("name '{0}' does not exist")]
    NxDomain(Name),
    #[error("upstream resolution failed: {0}")]
    Upstream(String),
    #[error("resolution exceeded the configured timeout")]
    Timeout,
    #[error("DNS {transport:?} {operation:?} exceeded the query deadline")]
    ExchangeTimeout {
        transport: DnsTransport,
        operation: DnsOperation,
    },
    #[error("DNS {transport:?} {operation:?} failed: {source}")]
    Transport {
        transport: DnsTransport,
        operation: DnsOperation,
        #[source]
        source: io::Error,
    },
    #[error("invalid DNS response: {0}")]
    InvalidResponse(&'static str),
    #[error("upstream DNS response code {0}")]
    ResponseCode(u16),
    #[error("DNS {qtype:?} query to {upstream} failed: {source}")]
    Query {
        upstream: SocketAddr,
        qtype: DnsRecordType,
        #[source]
        source: Box<Self>,
    },
}

impl ResolveError {
    #[must_use]
    pub fn diagnostic(&self) -> ResolveFailure {
        match self {
            Self::Query {
                upstream,
                qtype,
                source,
            } => {
                let mut failure = source.diagnostic();
                failure.upstream = Some(*upstream);
                failure.qtype = Some(*qtype);
                failure
            }
            Self::ExchangeTimeout {
                transport,
                operation,
            } => ResolveFailure {
                transport: Some(*transport),
                operation: Some(*operation),
                ..ResolveFailure::new(ResolveFailureKind::Timeout)
            },
            Self::Transport {
                transport,
                operation,
                source,
            } => ResolveFailure {
                transport: Some(*transport),
                operation: Some(*operation),
                io_kind: Some(format!("{:?}", source.kind())),
                os_error: source.raw_os_error(),
                ..ResolveFailure::new(if source.kind() == io::ErrorKind::TimedOut {
                    ResolveFailureKind::Timeout
                } else {
                    ResolveFailureKind::Io
                })
            },
            Self::InvalidResponse(detail) => ResolveFailure {
                detail: Some(detail),
                ..ResolveFailure::new(ResolveFailureKind::InvalidResponse)
            },
            Self::ResponseCode(code) => ResolveFailure {
                response_code: Some(*code),
                ..ResolveFailure::new(ResolveFailureKind::ResponseCode)
            },
            Self::NxDomain(_) => ResolveFailure::new(ResolveFailureKind::Nxdomain),
            Self::Timeout => ResolveFailure::new(ResolveFailureKind::Timeout),
            Self::Upstream(_) => ResolveFailure::new(ResolveFailureKind::Upstream),
        }
    }
}

/// Injectable upstream resolver. Implementations may be a real forwarding DNS
/// client, a static fixture map, or a test double that simulates rebinding.
#[async_trait]
pub trait UpstreamResolver: Send + Sync {
    async fn resolve(&self, name: &Name) -> Result<ResolvedChain, ResolveError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_keep_query_and_os_codes_but_not_free_form_errors() {
        let error = ResolveError::Query {
            upstream: "192.0.2.53:53".parse().unwrap(),
            qtype: DnsRecordType::Aaaa,
            source: Box::new(ResolveError::Transport {
                transport: DnsTransport::Udp,
                operation: DnsOperation::Receive,
                source: io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "synthetic-private-error-detail",
                ),
            }),
        };
        let json = serde_json::to_value(error.diagnostic()).unwrap();
        assert_eq!(json["kind"], "io");
        assert_eq!(json["upstream"], "192.0.2.53:53");
        assert_eq!(json["qtype"], "AAAA");
        assert_eq!(json["operation"], "receive");
        assert_eq!(json["io_kind"], "ConnectionRefused");
        assert!(!json.to_string().contains("synthetic-private-error-detail"));
        let legacy = ResolveError::Upstream("synthetic-private-error-detail".to_owned());
        assert_eq!(
            serde_json::to_string(&legacy.diagnostic()).unwrap(),
            r#"{"kind":"upstream"}"#
        );
    }
}
