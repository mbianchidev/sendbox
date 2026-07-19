//! Capability removal before entering an untrusted executable.

#![forbid(unsafe_code)]

use caps::CapSet;

use crate::error::PlatformError;

pub fn drop_all() -> Result<(), PlatformError> {
    caps::clear(None, CapSet::Bounding).map_err(|error| {
        PlatformError::SecuritySetup(format!("failed to clear capability bounding set: {error}"))
    })?;
    for set in [CapSet::Effective, CapSet::Permitted, CapSet::Inheritable] {
        caps::clear(None, set).map_err(|error| {
            PlatformError::SecuritySetup(format!("failed to clear {set:?} capabilities: {error}"))
        })?;
    }
    Ok(())
}
