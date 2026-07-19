#![forbid(unsafe_code)]

mod credential;
mod envelope;
mod error;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod record;
mod types;

pub use credential::{
    AuditSafeRequestMetadata, BrokerRequest, CredentialInjection, CredentialPolicy,
    CredentialPolicyError, GUARDED_GITHUB_CREDENTIALS, RedirectPolicy, SensitiveBytes,
    SensitiveUrl, TlsVerification, TransformedRequest, requires_guarded_github_forwarding,
};
pub use envelope::{
    EnvelopeBinding, EnvelopeCipher, EnvelopeError, RecipientRole, ReplayGuard, SessionKeyMaterial,
};
pub use error::SecretStoreError;
#[cfg(target_os = "linux")]
pub use linux::LinuxFileStore;
#[cfg(target_os = "macos")]
pub use macos::{
    KeychainMigrationPlan, KeychainStore, MigrationAuthorization, SigningIdentityChange,
};
pub use types::{
    MAX_SECRET_NAME_BYTES, MAX_SECRET_VALUE_BYTES, RecordVersion, Secret, SecretMetadata,
    SecretName, SecretStore, SecretValue,
};

#[doc(hidden)]
pub mod fuzzing {
    pub fn decode_envelope(bytes: &[u8]) -> Result<(), String> {
        crate::envelope::validate_encoded_envelope(bytes).map_err(|error| error.to_string())
    }

    pub fn decode_persisted_record(bytes: &[u8]) -> Result<(), String> {
        crate::record::decode_record(bytes)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}
