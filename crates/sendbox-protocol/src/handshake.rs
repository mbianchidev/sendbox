use std::fmt;

use getrandom::fill;
use sendbox_core::SessionId;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use zeroize::Zeroizing;

use crate::codec::{encode_negotiation_core, encode_readiness_core};
use crate::crypto::SessionKeys;
use crate::frame::{
    ConnectionParameters, NegotiatedSession, read_bounded_message, write_bounded_message,
};
use crate::types::{MAC_BYTES, NONCE_BYTES};
use crate::{
    AuthenticatedConnection, CapabilitySet, FrameLimits, Hello, Message, Negotiation,
    PROTOCOL_MAGIC, PeerRole, ProtocolError, Readiness, VersionRange,
};

pub struct BootstrapSecret(Zeroizing<Vec<u8>>);

impl BootstrapSecret {
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, ProtocolError> {
        let secret = secret.into();
        if secret.len() < 32 {
            return Err(ProtocolError::BootstrapSecretTooShort);
        }
        Ok(Self(Zeroizing::new(secret)))
    }

    fn expose(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for BootstrapSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrapSecret([REDACTED])")
    }
}

#[derive(Debug)]
pub struct HandshakeConfig {
    pub session_id: SessionId,
    pub versions: VersionRange,
    pub capabilities: CapabilitySet,
    pub required_capabilities: CapabilitySet,
    pub limits: FrameLimits,
    pub bootstrap_secret: BootstrapSecret,
}

impl HandshakeConfig {
    pub fn new(
        session_id: SessionId,
        versions: VersionRange,
        capabilities: CapabilitySet,
        required_capabilities: CapabilitySet,
        limits: FrameLimits,
        bootstrap_secret: BootstrapSecret,
    ) -> Result<Self, ProtocolError> {
        if !versions.is_valid() {
            return Err(ProtocolError::UnsupportedVersion {
                minimum: versions.minimum,
                maximum: versions.maximum,
            });
        }
        if !required_capabilities.is_subset(&capabilities) {
            return Err(ProtocolError::MissingRequiredCapabilities);
        }
        Ok(Self {
            session_id,
            versions,
            capabilities,
            required_capabilities,
            limits,
            bootstrap_secret,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeState {
    Initial,
    InProgress,
    Established,
    Failed,
}

impl HandshakeState {
    const fn name(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::InProgress => "in_progress",
            Self::Established => "established",
            Self::Failed => "failed",
        }
    }
}

pub struct HostHandshake {
    config: HandshakeConfig,
    state: HandshakeState,
}

impl HostHandshake {
    #[must_use]
    pub fn new(config: HandshakeConfig) -> Self {
        Self {
            config,
            state: HandshakeState::Initial,
        }
    }

    pub async fn establish<S>(
        &mut self,
        mut stream: S,
    ) -> Result<AuthenticatedConnection<ReadHalf<S>, WriteHalf<S>>, ProtocolError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if self.state != HandshakeState::Initial {
            return Err(ProtocolError::RepeatedHandshake(self.state.name()));
        }
        self.state = HandshakeState::InProgress;
        let result = self.establish_inner(&mut stream).await;
        match result {
            Ok(established) => {
                self.state = HandshakeState::Established;
                let (reader, writer) = tokio::io::split(stream);
                Ok(connection_from_established(
                    reader,
                    writer,
                    PeerRole::HostClient,
                    established,
                ))
            }
            Err(error) => {
                self.state = HandshakeState::Failed;
                Err(error)
            }
        }
    }

    async fn establish_inner<S>(&self, stream: &mut S) -> Result<Established, ProtocolError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let client_nonce = random_nonce()?;
        let hello = Hello {
            magic: PROTOCOL_MAGIC,
            versions: self.config.versions,
            session_id: self.config.session_id,
            role: PeerRole::HostClient,
            nonce: client_nonce,
            capabilities: self.config.capabilities.clone(),
            required_capabilities: self.config.required_capabilities.clone(),
            max_frame_bytes: u32::try_from(self.config.limits.max_frame_bytes())
                .map_err(|_| ProtocolError::InvalidNegotiatedFrameLimit)?,
        };
        let hello_message = Message::Hello(hello.clone());
        let hello_bytes = crate::encode_message(&hello_message)?;
        write_bounded_message(stream, &hello_message, self.config.limits).await?;

        let (message, _) = read_bounded_message(stream, self.config.limits).await?;
        let negotiation = match message {
            Message::CapabilityNegotiation(negotiation) => negotiation,
            other => {
                return Err(ProtocolError::UnexpectedHandshakeMessage {
                    expected: "capability_negotiation",
                    actual: other.kind() as u8,
                });
            }
        };
        validate_negotiation(&self.config, &hello, &negotiation)?;
        let negotiation_core = encode_negotiation_core(&negotiation)?;
        let (keys, transcript_hash) = SessionKeys::derive(
            self.config.bootstrap_secret.expose(),
            &hello_bytes,
            &negotiation_core,
        )?;
        keys.verify_negotiation_proof(&hello_bytes, &negotiation_core, &negotiation.proof)?;

        let host_readiness =
            readiness(PeerRole::HostClient, &negotiation, &keys, &transcript_hash)?;
        write_bounded_message(
            stream,
            &Message::Readiness(host_readiness),
            self.config.limits,
        )
        .await?;

        let (message, _) = read_bounded_message(stream, self.config.limits).await?;
        let guest_readiness = match message {
            Message::Readiness(readiness) => readiness,
            other => {
                return Err(ProtocolError::UnexpectedHandshakeMessage {
                    expected: "readiness",
                    actual: other.kind() as u8,
                });
            }
        };
        validate_readiness(
            PeerRole::GuestServer,
            &negotiation,
            &guest_readiness,
            &keys,
            &transcript_hash,
        )?;

        Ok(Established {
            version: negotiation.selected_version,
            session_id: negotiation.session_id,
            capabilities: negotiation.negotiated_capabilities,
            limits: FrameLimits::new(negotiation.max_frame_bytes as usize)?,
            keys,
        })
    }
}

pub struct GuestHandshake {
    config: HandshakeConfig,
    state: HandshakeState,
}

impl GuestHandshake {
    #[must_use]
    pub fn new(config: HandshakeConfig) -> Self {
        Self {
            config,
            state: HandshakeState::Initial,
        }
    }

    pub async fn establish<S>(
        &mut self,
        mut stream: S,
    ) -> Result<AuthenticatedConnection<ReadHalf<S>, WriteHalf<S>>, ProtocolError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if self.state != HandshakeState::Initial {
            return Err(ProtocolError::RepeatedHandshake(self.state.name()));
        }
        self.state = HandshakeState::InProgress;
        let result = self.establish_inner(&mut stream).await;
        match result {
            Ok(established) => {
                self.state = HandshakeState::Established;
                let (reader, writer) = tokio::io::split(stream);
                Ok(connection_from_established(
                    reader,
                    writer,
                    PeerRole::GuestServer,
                    established,
                ))
            }
            Err(error) => {
                self.state = HandshakeState::Failed;
                Err(error)
            }
        }
    }

    async fn establish_inner<S>(&self, stream: &mut S) -> Result<Established, ProtocolError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (message, hello_bytes) = read_bounded_message(stream, self.config.limits).await?;
        let hello = match message {
            Message::Hello(hello) => hello,
            other => {
                return Err(ProtocolError::UnexpectedHandshakeMessage {
                    expected: "hello",
                    actual: other.kind() as u8,
                });
            }
        };
        validate_hello(&self.config, &hello)?;

        let selected_version = hello.versions.negotiate(self.config.versions).ok_or(
            ProtocolError::UnsupportedVersion {
                minimum: hello.versions.minimum,
                maximum: hello.versions.maximum,
            },
        )?;
        let negotiated_capabilities = hello.capabilities.intersection(&self.config.capabilities);
        validate_capabilities(
            &negotiated_capabilities,
            &hello.required_capabilities,
            &self.config.required_capabilities,
        )?;
        let max_frame_bytes = hello.max_frame_bytes.min(
            u32::try_from(self.config.limits.max_frame_bytes())
                .map_err(|_| ProtocolError::InvalidNegotiatedFrameLimit)?,
        );
        let server_nonce = random_nonce()?;
        let mut negotiation = Negotiation {
            magic: PROTOCOL_MAGIC,
            versions: self.config.versions,
            selected_version,
            session_id: self.config.session_id,
            role: PeerRole::GuestServer,
            client_nonce: hello.nonce,
            server_nonce,
            capabilities: self.config.capabilities.clone(),
            required_capabilities: self.config.required_capabilities.clone(),
            negotiated_capabilities,
            max_frame_bytes,
            proof: [0; MAC_BYTES],
        };
        let negotiation_core = encode_negotiation_core(&negotiation)?;
        let (keys, transcript_hash) = SessionKeys::derive(
            self.config.bootstrap_secret.expose(),
            &hello_bytes,
            &negotiation_core,
        )?;
        negotiation.proof = keys.negotiation_proof(&hello_bytes, &negotiation_core)?;
        write_bounded_message(
            stream,
            &Message::CapabilityNegotiation(negotiation.clone()),
            self.config.limits,
        )
        .await?;

        let (message, _) = read_bounded_message(stream, self.config.limits).await?;
        let host_readiness = match message {
            Message::Readiness(readiness) => readiness,
            other => {
                return Err(ProtocolError::UnexpectedHandshakeMessage {
                    expected: "readiness",
                    actual: other.kind() as u8,
                });
            }
        };
        validate_readiness(
            PeerRole::HostClient,
            &negotiation,
            &host_readiness,
            &keys,
            &transcript_hash,
        )?;

        let guest_readiness =
            readiness(PeerRole::GuestServer, &negotiation, &keys, &transcript_hash)?;
        write_bounded_message(
            stream,
            &Message::Readiness(guest_readiness),
            self.config.limits,
        )
        .await?;

        Ok(Established {
            version: negotiation.selected_version,
            session_id: negotiation.session_id,
            capabilities: negotiation.negotiated_capabilities,
            limits: FrameLimits::new(negotiation.max_frame_bytes as usize)?,
            keys,
        })
    }
}

struct Established {
    version: u16,
    session_id: SessionId,
    capabilities: CapabilitySet,
    limits: FrameLimits,
    keys: SessionKeys,
}

fn connection_from_established<R, W>(
    reader: R,
    writer: W,
    role: PeerRole,
    established: Established,
) -> AuthenticatedConnection<R, W> {
    let Established {
        version,
        session_id,
        capabilities,
        limits,
        keys,
    } = established;
    let (host_to_guest, guest_to_host) = keys.into_directional();
    let (send_key, receive_key) = match role {
        PeerRole::HostClient => (host_to_guest, guest_to_host),
        PeerRole::GuestServer => (guest_to_host, host_to_guest),
    };
    AuthenticatedConnection::new(
        reader,
        writer,
        ConnectionParameters {
            negotiated: NegotiatedSession {
                version,
                session_id,
                capabilities,
                limits,
            },
            local_direction: role.direction(),
            send_key,
            receive_key,
        },
    )
}

fn validate_hello(config: &HandshakeConfig, hello: &Hello) -> Result<(), ProtocolError> {
    if hello.magic != PROTOCOL_MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    if hello.role != PeerRole::HostClient {
        return Err(ProtocolError::RoleMismatch {
            expected: PeerRole::HostClient,
            actual: hello.role,
        });
    }
    if hello.session_id != config.session_id {
        return Err(ProtocolError::SessionMismatch {
            expected: config.session_id,
            actual: hello.session_id,
        });
    }
    if !hello.versions.is_valid() {
        return Err(ProtocolError::UnsupportedVersion {
            minimum: hello.versions.minimum,
            maximum: hello.versions.maximum,
        });
    }
    FrameLimits::new(hello.max_frame_bytes as usize)?;
    if !hello.required_capabilities.is_subset(&hello.capabilities) {
        return Err(ProtocolError::MissingRequiredCapabilities);
    }
    Ok(())
}

fn validate_negotiation(
    config: &HandshakeConfig,
    hello: &Hello,
    negotiation: &Negotiation,
) -> Result<(), ProtocolError> {
    if negotiation.magic != PROTOCOL_MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    if negotiation.role != PeerRole::GuestServer {
        return Err(ProtocolError::RoleMismatch {
            expected: PeerRole::GuestServer,
            actual: negotiation.role,
        });
    }
    if negotiation.session_id != config.session_id {
        return Err(ProtocolError::SessionMismatch {
            expected: config.session_id,
            actual: negotiation.session_id,
        });
    }
    if negotiation.client_nonce != hello.nonce {
        return Err(ProtocolError::AuthenticationFailed);
    }
    if !negotiation.versions.is_valid() {
        return Err(ProtocolError::UnsupportedVersion {
            minimum: negotiation.versions.minimum,
            maximum: negotiation.versions.maximum,
        });
    }
    let expected_version = hello.versions.negotiate(negotiation.versions).ok_or(
        ProtocolError::UnsupportedVersion {
            minimum: hello.versions.minimum,
            maximum: hello.versions.maximum,
        },
    )?;
    if negotiation.selected_version != expected_version {
        return Err(ProtocolError::VersionMismatch(negotiation.selected_version));
    }
    let expected_capabilities = hello.capabilities.intersection(&negotiation.capabilities);
    if negotiation.negotiated_capabilities != expected_capabilities {
        return Err(ProtocolError::AuthenticationFailed);
    }
    validate_capabilities(
        &negotiation.negotiated_capabilities,
        &hello.required_capabilities,
        &negotiation.required_capabilities,
    )?;
    let expected_limit = hello.max_frame_bytes.min(
        u32::try_from(config.limits.max_frame_bytes())
            .map_err(|_| ProtocolError::InvalidNegotiatedFrameLimit)?,
    );
    if negotiation.max_frame_bytes != expected_limit {
        return Err(ProtocolError::InvalidNegotiatedFrameLimit);
    }
    FrameLimits::new(negotiation.max_frame_bytes as usize)?;
    Ok(())
}

fn validate_capabilities(
    negotiated: &CapabilitySet,
    host_required: &CapabilitySet,
    guest_required: &CapabilitySet,
) -> Result<(), ProtocolError> {
    if negotiated.is_empty() {
        return Err(ProtocolError::EmptyCapabilityIntersection);
    }
    if !host_required.is_subset(negotiated) || !guest_required.is_subset(negotiated) {
        return Err(ProtocolError::MissingRequiredCapabilities);
    }
    Ok(())
}

fn readiness(
    role: PeerRole,
    negotiation: &Negotiation,
    keys: &SessionKeys,
    transcript_hash: &[u8; 32],
) -> Result<Readiness, ProtocolError> {
    let mut readiness = Readiness {
        role,
        session_id: negotiation.session_id,
        selected_version: negotiation.selected_version,
        negotiated_capabilities: negotiation.negotiated_capabilities.clone(),
        max_frame_bytes: negotiation.max_frame_bytes,
        proof: [0; MAC_BYTES],
    };
    let core = encode_readiness_core(&readiness)?;
    readiness.proof = keys.readiness_proof(role == PeerRole::HostClient, transcript_hash, &core)?;
    Ok(readiness)
}

fn validate_readiness(
    expected_role: PeerRole,
    negotiation: &Negotiation,
    readiness: &Readiness,
    keys: &SessionKeys,
    transcript_hash: &[u8; 32],
) -> Result<(), ProtocolError> {
    if readiness.role != expected_role {
        return Err(ProtocolError::RoleMismatch {
            expected: expected_role,
            actual: readiness.role,
        });
    }
    if readiness.session_id != negotiation.session_id {
        return Err(ProtocolError::SessionMismatch {
            expected: negotiation.session_id,
            actual: readiness.session_id,
        });
    }
    if readiness.selected_version != negotiation.selected_version {
        return Err(ProtocolError::VersionMismatch(readiness.selected_version));
    }
    if readiness.negotiated_capabilities != negotiation.negotiated_capabilities
        || readiness.max_frame_bytes != negotiation.max_frame_bytes
    {
        return Err(ProtocolError::AuthenticationFailed);
    }
    let core = encode_readiness_core(readiness)?;
    keys.verify_readiness_proof(
        expected_role == PeerRole::HostClient,
        transcript_hash,
        &core,
        &readiness.proof,
    )
}

fn random_nonce() -> Result<[u8; NONCE_BYTES], ProtocolError> {
    let mut nonce = [0_u8; NONCE_BYTES];
    fill(&mut nonce).map_err(|error| ProtocolError::Randomness(error.to_string()))?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Capability, PROTOCOL_VERSION};

    const SECRET: [u8; 32] = [0x23; 32];

    fn config(
        session: [u8; 16],
        versions: VersionRange,
        capabilities: CapabilitySet,
        required: CapabilitySet,
        secret: [u8; 32],
    ) -> HandshakeConfig {
        HandshakeConfig::new(
            SessionId::from_bytes(session),
            versions,
            capabilities,
            required,
            FrameLimits::new(32 * 1024).expect("limits"),
            BootstrapSecret::new(secret).expect("secret"),
        )
        .expect("config")
    }

    fn standard_capabilities() -> CapabilitySet {
        [
            Capability::Lifecycle,
            Capability::Exec,
            Capability::StreamedIo,
            Capability::Health,
        ]
        .into()
    }

    #[tokio::test]
    async fn negotiates_highest_version_capabilities_and_limit() {
        let session = [7; 16];
        let (host_stream, guest_stream) = tokio::io::duplex(16 * 1024);
        let mut host = HostHandshake::new(config(
            session,
            VersionRange::new(1, 3),
            standard_capabilities(),
            [Capability::Lifecycle].into(),
            SECRET,
        ));
        let mut guest = GuestHandshake::new(config(
            session,
            VersionRange::new(1, 2),
            [Capability::Lifecycle, Capability::Health, Capability::Audit].into(),
            [Capability::Health].into(),
            SECRET,
        ));
        let (host_result, guest_result) =
            tokio::join!(host.establish(host_stream), guest.establish(guest_stream));
        let host_connection = host_result.expect("host handshake");
        let guest_connection = guest_result.expect("guest handshake");
        let expected = [Capability::Lifecycle, Capability::Health].into();
        assert_eq!(host_connection.negotiated().version, 2);
        assert_eq!(host_connection.negotiated().capabilities, expected);
        assert_eq!(host_connection.negotiated(), guest_connection.negotiated());
    }

    #[tokio::test]
    async fn wrong_secret_fails_authentication() {
        let session = [7; 16];
        let (host_stream, guest_stream) = tokio::io::duplex(16 * 1024);
        let mut host = HostHandshake::new(config(
            session,
            VersionRange::default(),
            standard_capabilities(),
            CapabilitySet::default(),
            SECRET,
        ));
        let mut guest = GuestHandshake::new(config(
            session,
            VersionRange::default(),
            standard_capabilities(),
            CapabilitySet::default(),
            [0x99; 32],
        ));
        let (host_result, guest_result) =
            tokio::join!(host.establish(host_stream), guest.establish(guest_stream));
        assert!(matches!(
            host_result,
            Err(ProtocolError::AuthenticationFailed)
        ));
        assert!(guest_result.is_err());
    }

    #[tokio::test]
    async fn session_version_and_capability_mismatches_fail() {
        async fn run(
            host_config: HandshakeConfig,
            guest_config: HandshakeConfig,
        ) -> (
            Result<
                AuthenticatedConnection<
                    ReadHalf<tokio::io::DuplexStream>,
                    WriteHalf<tokio::io::DuplexStream>,
                >,
                ProtocolError,
            >,
            Result<
                AuthenticatedConnection<
                    ReadHalf<tokio::io::DuplexStream>,
                    WriteHalf<tokio::io::DuplexStream>,
                >,
                ProtocolError,
            >,
        ) {
            let (host_stream, guest_stream) = tokio::io::duplex(16 * 1024);
            let mut host = HostHandshake::new(host_config);
            let mut guest = GuestHandshake::new(guest_config);
            tokio::join!(host.establish(host_stream), guest.establish(guest_stream))
        }

        let (host, guest) = run(
            config(
                [1; 16],
                VersionRange::default(),
                standard_capabilities(),
                CapabilitySet::default(),
                SECRET,
            ),
            config(
                [2; 16],
                VersionRange::default(),
                standard_capabilities(),
                CapabilitySet::default(),
                SECRET,
            ),
        )
        .await;
        assert!(host.is_err());
        assert!(matches!(guest, Err(ProtocolError::SessionMismatch { .. })));

        let (host, guest) = run(
            config(
                [1; 16],
                VersionRange::new(1, 1),
                standard_capabilities(),
                CapabilitySet::default(),
                SECRET,
            ),
            config(
                [1; 16],
                VersionRange::new(2, 2),
                standard_capabilities(),
                CapabilitySet::default(),
                SECRET,
            ),
        )
        .await;
        assert!(host.is_err());
        assert!(matches!(
            guest,
            Err(ProtocolError::UnsupportedVersion { .. })
        ));

        let (host, guest) = run(
            config(
                [1; 16],
                VersionRange::default(),
                [Capability::Exec].into(),
                CapabilitySet::default(),
                SECRET,
            ),
            config(
                [1; 16],
                VersionRange::default(),
                [Capability::Health].into(),
                CapabilitySet::default(),
                SECRET,
            ),
        )
        .await;
        assert!(host.is_err());
        assert!(matches!(
            guest,
            Err(ProtocolError::EmptyCapabilityIntersection)
        ));
    }

    #[tokio::test]
    async fn reflected_role_and_repeated_handshake_fail() {
        let session = [4; 16];
        let (mut peer, guest_stream) = tokio::io::duplex(4096);
        let hello = Message::Hello(Hello {
            magic: PROTOCOL_MAGIC,
            versions: VersionRange::default(),
            session_id: SessionId::from_bytes(session),
            role: PeerRole::GuestServer,
            nonce: [3; NONCE_BYTES],
            capabilities: standard_capabilities(),
            required_capabilities: CapabilitySet::default(),
            max_frame_bytes: 4096,
        });
        write_bounded_message(&mut peer, &hello, FrameLimits::default())
            .await
            .expect("write reflected hello");
        drop(peer);

        let mut guest = GuestHandshake::new(config(
            session,
            VersionRange::default(),
            standard_capabilities(),
            CapabilitySet::default(),
            SECRET,
        ));
        assert!(matches!(
            guest.establish(guest_stream).await,
            Err(ProtocolError::RoleMismatch { .. })
        ));
        let (_, retry_stream) = tokio::io::duplex(64);
        assert!(matches!(
            guest.establish(retry_stream).await,
            Err(ProtocolError::RepeatedHandshake("failed"))
        ));
    }

    #[test]
    fn configuration_rejects_invalid_required_capabilities_and_versions() {
        let missing = HandshakeConfig::new(
            SessionId::from_bytes([1; 16]),
            VersionRange::default(),
            [Capability::Exec].into(),
            [Capability::Health].into(),
            FrameLimits::default(),
            BootstrapSecret::new(SECRET).expect("secret"),
        );
        assert!(matches!(
            missing,
            Err(ProtocolError::MissingRequiredCapabilities)
        ));

        let invalid = HandshakeConfig::new(
            SessionId::from_bytes([1; 16]),
            VersionRange::new(2, 1),
            standard_capabilities(),
            CapabilitySet::default(),
            FrameLimits::default(),
            BootstrapSecret::new(SECRET).expect("secret"),
        );
        assert!(matches!(
            invalid,
            Err(ProtocolError::UnsupportedVersion { .. })
        ));
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
