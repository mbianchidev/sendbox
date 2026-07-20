//! Kernel/tool preflight for the Linux enforcement layer.
//!
//! `arm` never proceeds unless the environment can actually enforce: cgroup v2
//! must be mounted, `nft` must be present and support `socket cgroupv2`, the
//! process must hold `CAP_NET_ADMIN`, and `SO_MARK` must be settable. A missing
//! capability is a hard, explicit failure, never a silent downgrade.

use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::linux::cgroup;
use crate::linux::mark;
use crate::linux::nft::NftRunner;

/// Linux capability number for `CAP_NET_ADMIN`.
pub const CAP_NET_ADMIN_BIT: u32 = 12;

/// A precise, machine-readable readiness verdict, suitable to publish as a CI
/// artifact so a runner that cannot enforce fails explicitly instead of
/// silently skipping.
#[derive(Debug, Clone, Serialize)]
pub struct Preflight {
    pub cgroup2_root: Option<String>,
    pub cap_net_admin: bool,
    pub so_mark_settable: bool,
    pub nft_version: Option<String>,
    pub nft_socket_cgroupv2: bool,
}

impl Preflight {
    /// True only when every enforcement prerequisite is satisfied.
    #[must_use]
    pub fn all_ready(&self) -> bool {
        self.cgroup2_root.is_some()
            && self.cap_net_admin
            && self.so_mark_settable
            && self.nft_version.is_some()
            && self.nft_socket_cgroupv2
    }

    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_owned())
    }

    /// Runs every probe against the given `nft` runner.
    #[must_use]
    pub fn probe(runner: &dyn NftRunner) -> Self {
        let cgroup2_root = cgroup::detect_cgroup2_root()
            .ok()
            .map(|p| p.display().to_string());
        let nft_socket_cgroupv2 = match cgroup2_root.as_deref() {
            Some(root) => probe_nft_socket_cgroupv2(runner, Path::new(root)),
            None => false,
        };
        Self {
            cgroup2_root,
            cap_net_admin: current_has_cap_net_admin(),
            so_mark_settable: mark::probe_can_set_mark().is_ok(),
            nft_version: nft_version(runner),
            nft_socket_cgroupv2,
        }
    }
}

/// Parses the `CapEff` effective-capability mask from `/proc/<pid>/status`
/// content. Pure, for unit testing.
#[must_use]
pub fn parse_cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(str::trim)
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
}

/// Whether the effective capability set includes `CAP_NET_ADMIN`. Pure.
#[must_use]
pub fn has_cap_net_admin(status: &str) -> bool {
    parse_cap_eff(status).is_some_and(|mask| mask & (1u64 << CAP_NET_ADMIN_BIT) != 0)
}

/// Reads `/proc/self/status` and reports whether `CAP_NET_ADMIN` is effective.
#[must_use]
pub fn current_has_cap_net_admin() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .as_deref()
        .map(has_cap_net_admin)
        .unwrap_or(false)
}

/// Runs `nft --version` and returns the first line of output when it succeeds.
#[must_use]
pub fn nft_version(runner: &dyn NftRunner) -> Option<String> {
    let output = runner.run(&["--version"], None).ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .map(str::to_owned)
}

/// Probes whether `nft` (and the kernel) support `socket cgroupv2`. Creates a
/// throwaway cgroup under `root`, validates a ruleset referencing it with
/// `nft --check` (no commit), and removes the cgroup. Returns `false` on any
/// failure rather than assuming support.
#[must_use]
pub fn probe_nft_socket_cgroupv2(runner: &dyn NftRunner, root: &Path) -> bool {
    let probe_name = format!("sendbox_cgprobe_{}", std::process::id());
    let probe_dir = root.join(&probe_name);
    let created = fs::create_dir_all(&probe_dir).is_ok();
    let ruleset = format!(
        "table inet sendbox_cgprobe {{\n  chain c {{\n    type filter hook output priority filter; policy accept;\n    socket cgroupv2 level 1 \"{probe_name}\" accept\n  }}\n}}\n"
    );
    let supported = runner
        .run(&["--check", "-f", "-"], Some(ruleset.as_bytes()))
        .map(|output| output.status.success())
        .unwrap_or(false);
    if created {
        // Best-effort cleanup of the throwaway probe cgroup; the probe result
        // does not depend on it.
        let _ = fs::remove_dir(&probe_dir);
    }
    supported
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::nft::NftRunner;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Output;
    use std::sync::Mutex;

    #[test]
    fn parses_cap_eff_and_detects_net_admin() {
        // CAP_NET_ADMIN is bit 12 (0x1000).
        let with = "Name:\tx\nCapEff:\t0000000000001000\n";
        assert_eq!(parse_cap_eff(with), Some(0x1000));
        assert!(has_cap_net_admin(with));

        let full = "CapEff:\t000001ffffffffff\n";
        assert!(has_cap_net_admin(full));

        let without = "CapEff:\t0000000000000000\n";
        assert!(!has_cap_net_admin(without));

        let missing = "Name:\tx\n";
        assert!(!has_cap_net_admin(missing));
    }

    struct FakeRunner {
        version_ok: bool,
        check_ok: bool,
        seen: Mutex<Vec<Vec<String>>>,
    }

    impl NftRunner for FakeRunner {
        fn run(&self, args: &[&str], _stdin: Option<&[u8]>) -> std::io::Result<Output> {
            self.seen
                .lock()
                .unwrap()
                .push(args.iter().map(|s| (*s).to_owned()).collect());
            let success = if args.first() == Some(&"--version") {
                self.version_ok
            } else {
                self.check_ok
            };
            Ok(Output {
                status: std::process::ExitStatus::from_raw(if success { 0 } else { 1 }),
                stdout: b"nftables v1.0.9 (probe)\n".to_vec(),
                stderr: Vec::new(),
            })
        }
    }

    #[test]
    fn nft_version_reads_first_line_on_success() {
        let runner = FakeRunner {
            version_ok: true,
            check_ok: true,
            seen: Mutex::new(Vec::new()),
        };
        assert_eq!(
            nft_version(&runner).as_deref(),
            Some("nftables v1.0.9 (probe)")
        );
    }

    #[test]
    fn nft_version_none_on_failure() {
        let runner = FakeRunner {
            version_ok: false,
            check_ok: true,
            seen: Mutex::new(Vec::new()),
        };
        assert!(nft_version(&runner).is_none());
    }

    #[test]
    fn socket_cgroupv2_probe_reflects_check_result() {
        let root = tempfile::tempdir().unwrap();
        let ok = FakeRunner {
            version_ok: true,
            check_ok: true,
            seen: Mutex::new(Vec::new()),
        };
        assert!(probe_nft_socket_cgroupv2(&ok, root.path()));
        let unsupported = FakeRunner {
            version_ok: true,
            check_ok: false,
            seen: Mutex::new(Vec::new()),
        };
        assert!(!probe_nft_socket_cgroupv2(&unsupported, root.path()));
    }
}
