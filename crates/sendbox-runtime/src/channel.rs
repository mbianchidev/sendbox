use std::{fmt, path::PathBuf, time::Duration};

use sendbox_core::SessionId;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::{BoxFuture, CancellationToken, ContainerId, RuntimeError};

pub const MIN_READINESS_TIMEOUT: Duration = Duration::from_millis(10);
pub const MAX_READINESS_TIMEOUT: Duration = Duration::from_secs(300);
pub const MIN_BOOTSTRAP_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ControlEndpointKind {
    Vsock,
    PublishedUnixSocket,
    InheritedStdio,
    InheritedFileDescriptor,
    RuntimeExecStdio,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostAddress {
    Vsock { cid: u32, port: u32 },
    UnixSocket(PathBuf),
    Stdio,
    FileDescriptor(u32),
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestAddress {
    Vsock { cid: u32, port: u32 },
    UnixSocket(PathBuf),
    Stdio,
    FileDescriptor(u32),
    RuntimeDefined(String),
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelOwnership {
    RuntimeLifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelLifetime {
    UntilRuntimeCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapDelivery {
    PreopenedFileDescriptor { descriptor: u32 },
    RuntimeInjection { target: String },
}

pub struct BootstrapMaterial(Zeroizing<Vec<u8>>);

impl BootstrapMaterial {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, RuntimeError> {
        let bytes = bytes.into();
        if bytes.len() < MIN_BOOTSTRAP_BYTES {
            return Err(RuntimeError::InvalidControlChannel {
                reason: format!(
                    "bootstrap material must contain at least {MIN_BOOTSTRAP_BYTES} bytes"
                ),
            });
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for BootstrapMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrapMaterial([REDACTED])")
    }
}

#[derive(Debug)]
pub struct ControlChannelRequest {
    pub session_id: SessionId,
    pub container_id: ContainerId,
    pub endpoint_kind: ControlEndpointKind,
    pub ownership: ChannelOwnership,
    pub lifetime: ChannelLifetime,
    pub readiness_timeout: Duration,
    pub bootstrap_delivery: BootstrapDelivery,
    pub bootstrap_material: BootstrapMaterial,
}

impl ControlChannelRequest {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        if !(MIN_READINESS_TIMEOUT..=MAX_READINESS_TIMEOUT).contains(&self.readiness_timeout) {
            return Err(RuntimeError::InvalidControlChannel {
                reason: format!(
                    "readiness timeout must be between {MIN_READINESS_TIMEOUT:?} and {MAX_READINESS_TIMEOUT:?}"
                ),
            });
        }
        if self.endpoint_kind == ControlEndpointKind::Unavailable {
            return Err(RuntimeError::TransportUnavailable {
                endpoint: self.endpoint_kind,
                reason: "the requested control transport is explicitly unavailable".to_owned(),
            });
        }
        if matches!(
            self.bootstrap_delivery,
            BootstrapDelivery::PreopenedFileDescriptor { descriptor: 0..=2 }
        ) {
            return Err(RuntimeError::InvalidControlChannel {
                reason: "control bootstrap cannot use standard input, output, or error descriptors"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedControlChannelDescriptor {
    pub endpoint_kind: ControlEndpointKind,
    pub host_address: HostAddress,
    pub guest_address: GuestAddress,
    pub ownership: ChannelOwnership,
    pub lifetime: ChannelLifetime,
}

pub trait ControlStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ControlStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A single-use control channel owned by the runtime lifecycle.
///
/// `accept` returns exactly one stream. The owning agent must call `cleanup`
/// before runtime cleanup; repeated cleanup calls must succeed without work.
pub trait ProvisionedControlChannel: Send {
    fn descriptor(&self) -> &ProvisionedControlChannelDescriptor;

    fn accept<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn ControlStream>, RuntimeError>>;

    fn cleanup<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), RuntimeError>>;
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sendbox_core::SessionId;

    use crate::ContainerId;

    use super::{
        BootstrapDelivery, BootstrapMaterial, ChannelLifetime, ChannelOwnership,
        ControlChannelRequest, ControlEndpointKind,
    };

    fn request(kind: ControlEndpointKind) -> ControlChannelRequest {
        ControlChannelRequest {
            session_id: SessionId::from_bytes([7; 16]),
            container_id: ContainerId::new("channel-test").expect("container"),
            endpoint_kind: kind,
            ownership: ChannelOwnership::RuntimeLifecycle,
            lifetime: ChannelLifetime::UntilRuntimeCleanup,
            readiness_timeout: Duration::from_secs(5),
            bootstrap_delivery: BootstrapDelivery::PreopenedFileDescriptor { descriptor: 3 },
            bootstrap_material: BootstrapMaterial::new([9; 32]).expect("bootstrap"),
        }
    }

    #[test]
    fn rejects_unavailable_transport_and_standard_descriptors() {
        assert!(
            request(ControlEndpointKind::Unavailable)
                .validate()
                .is_err()
        );
        let mut request = request(ControlEndpointKind::InheritedFileDescriptor);
        request.bootstrap_delivery = BootstrapDelivery::PreopenedFileDescriptor { descriptor: 1 };
        assert!(request.validate().is_err());
    }

    #[test]
    fn validates_all_declared_transport_kinds() {
        for kind in [
            ControlEndpointKind::Vsock,
            ControlEndpointKind::PublishedUnixSocket,
            ControlEndpointKind::InheritedStdio,
            ControlEndpointKind::InheritedFileDescriptor,
            ControlEndpointKind::RuntimeExecStdio,
        ] {
            request(kind).validate().expect("valid request");
        }
    }
}
