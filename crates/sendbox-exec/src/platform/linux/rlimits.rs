//! Configurable resource-limit application.

#![forbid(unsafe_code)]

use rlimit::Resource;

use crate::api::ResourceLimits;
use crate::error::PlatformError;

pub fn apply(limits: &ResourceLimits) -> Result<(), PlatformError> {
    for (resource, value) in [
        (Resource::NOFILE, limits.open_files),
        (Resource::NPROC, limits.processes),
        (Resource::CORE, limits.core_bytes),
        (Resource::FSIZE, limits.file_bytes),
        (Resource::AS, limits.address_space_bytes),
    ] {
        resource.set(value, value).map_err(|error| {
            PlatformError::SecuritySetup(format!("failed to set {resource:?}={value}: {error}"))
        })?;
    }
    Ok(())
}
