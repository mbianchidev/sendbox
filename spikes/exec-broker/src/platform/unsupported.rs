//! Stub platform support for every non-Linux target. Every function
//! returns [`crate::error::PlatformError::UnsupportedPlatform`], so the
//! rest of the crate — and its pure unit tests — still compile and run on
//! macOS, while every binary emits a clear "unsupported platform" error at
//! runtime instead of attempting to do anything Linux-specific.

#![forbid(unsafe_code)]

use crate::error::PlatformError;
use crate::platform::{SeccompProfile, unsupported_platform_error};

/// Always fails on non-Linux platforms.
pub fn set_no_new_privs() -> Result<(), PlatformError> {
    Err(unsupported_platform_error())
}

/// Always fails on non-Linux platforms.
pub fn install_seccomp_filter(_profile: SeccompProfile) -> Result<(), PlatformError> {
    Err(unsupported_platform_error())
}

/// Always fails on non-Linux platforms.
pub fn drop_all_capabilities() -> Result<(), PlatformError> {
    Err(unsupported_platform_error())
}

/// Always fails on non-Linux platforms.
pub fn apply_default_rlimits() -> Result<(), PlatformError> {
    Err(unsupported_platform_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_primitive_reports_unsupported_platform() {
        assert!(matches!(
            set_no_new_privs(),
            Err(PlatformError::UnsupportedPlatform(_))
        ));
        assert!(matches!(
            install_seccomp_filter(SeccompProfile::AgentBootstrap),
            Err(PlatformError::UnsupportedPlatform(_))
        ));
        assert!(matches!(
            drop_all_capabilities(),
            Err(PlatformError::UnsupportedPlatform(_))
        ));
        assert!(matches!(
            apply_default_rlimits(),
            Err(PlatformError::UnsupportedPlatform(_))
        ));
    }
}
