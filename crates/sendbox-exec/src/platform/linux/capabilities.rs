//! Capability removal before entering an untrusted executable.

#![forbid(unsafe_code)]

use caps::CapSet;

use crate::error::PlatformError;

pub fn drop_all() -> Result<(), PlatformError> {
    clear_bounding()?;
    clear_process_sets()
}

pub fn drop_to_user(uid: u32, gid: u32) -> Result<(), PlatformError> {
    if uid == 0 || gid == 0 {
        return Err(PlatformError::SecuritySetup(
            "privilege drop requires a non-root uid and gid".to_owned(),
        ));
    }
    clear_bounding()?;
    crate::platform::linux::raw::set_process_identity(uid, gid).map_err(|error| {
        PlatformError::SecuritySetup(format!(
            "failed to switch to uid {uid} and gid {gid}: {error}"
        ))
    })?;
    clear_process_sets()
}

fn clear_bounding() -> Result<(), PlatformError> {
    caps::clear(None, CapSet::Bounding).map_err(|error| {
        PlatformError::SecuritySetup(format!("failed to clear capability bounding set: {error}"))
    })
}

fn clear_process_sets() -> Result<(), PlatformError> {
    for set in [CapSet::Effective, CapSet::Permitted, CapSet::Inheritable] {
        caps::clear(None, set).map_err(|error| {
            PlatformError::SecuritySetup(format!("failed to clear {set:?} capabilities: {error}"))
        })?;
    }
    Ok(())
}
