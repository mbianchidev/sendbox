//! Platform qualification and Linux implementation.

#![deny(unsafe_code)]

use std::os::unix::net::UnixStream;

use crate::error::{KernelPrimitive, PlatformError, UnsupportedKernel};

#[cfg(target_os = "linux")]
pub mod linux;

/// Result of a live primitive qualification without silently skipping it.
#[derive(Debug)]
pub enum LiveGate<T> {
    Available(T),
    Unsupported(UnsupportedKernel),
}

impl<T> LiveGate<T> {
    pub fn from_result(result: Result<T, PlatformError>) -> Result<Self, PlatformError> {
        match result {
            Ok(value) => Ok(Self::Available(value)),
            Err(PlatformError::UnsupportedKernel(error)) => Ok(Self::Unsupported(error)),
            Err(error) => Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32, PlatformError> {
    use std::os::fd::AsRawFd;
    linux::raw::peer_uid(stream.as_raw_fd())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn peer_uid(_stream: &UnixStream) -> Result<u32, PlatformError> {
    Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
}

/// Returns a precise diagnostic for a Linux-only primitive on other targets.
#[cfg(not(target_os = "linux"))]
pub fn require_linux(primitive: KernelPrimitive) -> Result<(), PlatformError> {
    Err(UnsupportedKernel::new(
        primitive,
        None,
        format!("target_os={} is not Linux", std::env::consts::OS),
    )
    .into())
}

#[cfg(target_os = "linux")]
pub fn require_linux(_primitive: KernelPrimitive) -> Result<(), PlatformError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "linux"))]
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_targets_name_the_exact_primitive() {
        let error =
            require_linux(KernelPrimitive::Clone3IntoCgroup).expect_err("must fail outside Linux");
        assert!(matches!(
            error,
            PlatformError::UnsupportedKernel(UnsupportedKernel {
                primitive: KernelPrimitive::Clone3IntoCgroup,
                ..
            })
        ));
    }
}
