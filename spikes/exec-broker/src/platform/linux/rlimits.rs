//! Resource limit application via the safe `rlimit` crate. No `unsafe` is
//! written in this module.

#![forbid(unsafe_code)]

use crate::error::PlatformError;
use rlimit::Resource;

/// One resource limit to apply: soft and hard limits are set to the same
/// value, since the contained-launcher never needs to raise them again
/// after this point.
#[derive(Debug, Clone, Copy)]
pub struct RlimitSpec {
    pub resource: Resource,
    pub limit: u64,
}

/// Conservative default limits applied by `contained-launcher` to itself
/// (and therefore inherited by the target it execs) immediately before
/// spawning the target: max open files, max processes/threads, no core
/// dumps, a bounded max file size, and a bounded virtual address space.
#[must_use]
pub fn default_specs() -> Vec<RlimitSpec> {
    vec![
        RlimitSpec {
            resource: Resource::NOFILE,
            limit: 256,
        },
        RlimitSpec {
            resource: Resource::NPROC,
            // RLIMIT_NPROC is charged across every process and thread for
            // the real UID, including the broker test harness itself. Keep
            // enough headroom for realistic development tools to create
            // worker threads while still enforcing a finite fork ceiling.
            limit: 256,
        },
        RlimitSpec {
            resource: Resource::CORE,
            limit: 0,
        },
        RlimitSpec {
            resource: Resource::FSIZE,
            limit: 512 * 1024 * 1024,
        },
        RlimitSpec {
            resource: Resource::AS,
            limit: 2 * 1024 * 1024 * 1024,
        },
    ]
}

/// Applies [`default_specs`].
pub fn apply_defaults() -> Result<(), PlatformError> {
    apply(&default_specs())
}

/// Applies each spec in `specs`, setting soft and hard limits equal.
pub fn apply(specs: &[RlimitSpec]) -> Result<(), PlatformError> {
    for spec in specs {
        spec.resource
            .set(spec.limit, spec.limit)
            .map_err(PlatformError::Rlimit)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // `apply_defaults`/`apply` are intentionally *not* exercised in this
    // unit test: `cargo test` runs every unit test in one shared process,
    // and rlimits (especially `NOFILE`/`NPROC`/`AS`) are process-wide and,
    // once tightened, cannot be raised back by an unprivileged process.
    // Actually calling `apply_defaults()` here would permanently affect
    // every other test running in the same binary (e.g. `NOFILE = 256`
    // could starve the tokio runtime used by broker tests). The real
    // effect of applying these limits is instead exercised end to end
    // whenever `contained-launcher` runs as its own process.
    #[test]
    fn default_specs_match_documented_values() {
        let specs = default_specs();
        let get = |resource: Resource| {
            specs
                .iter()
                .find(|s| format!("{:?}", s.resource) == format!("{resource:?}"))
                .map(|s| s.limit)
        };
        assert_eq!(get(Resource::NOFILE), Some(256));
        assert_eq!(get(Resource::NPROC), Some(256));
        assert_eq!(get(Resource::CORE), Some(0));
        assert_eq!(get(Resource::FSIZE), Some(512 * 1024 * 1024));
        assert_eq!(get(Resource::AS), Some(2 * 1024 * 1024 * 1024));
    }
}
