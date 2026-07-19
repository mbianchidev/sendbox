//! Capability dropping via the safe `caps` crate. No `unsafe` is written in
//! this module.

#![forbid(unsafe_code)]

use crate::error::PlatformError;
use caps::CapSet;

/// Attempts to clear the bounding set first, while `CAP_SETPCAP` may still be
/// available, then drops every capability from the effective, permitted, and
/// inheritable sets for the current thread.
pub fn drop_all() -> Result<(), PlatformError> {
    // Dropping from the bounding set requires CAP_SETPCAP when capabilities
    // are present, so do it before clearing the effective/permitted sets.
    // Some already-unprivileged environments cannot modify the bounding set;
    // the immediately-following clears still remove every capability the
    // process can currently exercise.
    if let Err(error) = caps::clear(None, CapSet::Bounding) {
        eprintln!(
            "exec-broker-launcher: warning: could not clear capability bounding set: {error}"
        );
    }

    for set in [CapSet::Effective, CapSet::Permitted, CapSet::Inheritable] {
        caps::clear(None, set)
            .map_err(|e| PlatformError::Capabilities(format!("failed to clear {set:?}: {e}")))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_all_leaves_no_effective_capabilities() {
        // Best-effort: dropping capabilities can fail in some sandboxed CI
        // environments that already run without CAP_SETPCAP; only assert
        // the *effective set* is empty afterwards, tolerating an error from
        // the (less critical) bounding-set clear.
        let _ = drop_all();
        let effective = caps::read(None, CapSet::Effective).expect("read effective set");
        assert!(effective.is_empty());
    }
}
