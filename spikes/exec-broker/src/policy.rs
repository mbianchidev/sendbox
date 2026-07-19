//! Execution policy: an allowlist of canonical executable paths and an
//! approved root directory, plus environment sanitization rules.
//!
//! This module performs filesystem metadata reads (via `std::fs`, no
//! `unsafe`) to canonicalize and classify candidate executables, but never
//! spawns a process itself. It forbids `unsafe`.

#![forbid(unsafe_code)]

use crate::protocol::{Limits, RejectionCode, contains_nul, validate_structure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Environment variable names that are denied outright, regardless of
/// value, because they can redirect dynamic linking, language-runtime
/// startup hooks, or shell initialization to attacker-influenced code.
const DANGEROUS_ENV_EXACT: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "PS4",
    "PROMPT_COMMAND",
    "IFS",
    "RUBYOPT",
    "RUBYLIB",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_REPL_HISTORY",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "_JAVA_OPTIONS",
    "CLASSPATH",
    "GCONV_PATH",
    "PERL5LIB",
    "PERL5OPT",
    "PERLLIB",
    "TCLLIBPATH",
    "R_PROFILE",
    "R_PROFILE_USER",
    "R_ENVIRON",
    "R_ENVIRON_USER",
    "PYTHONSTARTUP",
    "GLIBC_TUNABLES",
    "LOCPATH",
    "NLSPATH",
    "MALLOC_CHECK_",
    "GIT_SSH_COMMAND",
];

/// Environment variable name *prefixes* that are denied outright. Checked
/// with `starts_with`, so e.g. `LD_PRELOAD` and `LD_LIBRARY_PATH` are both
/// caught by the `"LD_"` entry.
const DANGEROUS_ENV_PREFIXES: &[&str] = &["LD_", "PYTHON", "RUBY", "JAVA_", "NODE_"];

/// Basenames of dynamic linker / loader binaries. An executable resolving
/// to one of these is always denied, independent of allowlist membership,
/// since invoking the loader directly is a classic sandbox-escape /
/// arbitrary-code-loading primitive.
const DENIED_INTERPRETER_BASENAMES: &[&str] = &[
    "ld.so",
    "ld-linux.so.2",
    "ld-linux-x86-64.so.2",
    "ld-linux-aarch64.so.1",
    "ld-linux-armhf.so.3",
    "ld-musl-x86_64.so.1",
    "ld-musl-aarch64.so.1",
    "ld64.so.1",
    "ld64.so.2",
];

/// ELF magic bytes (`\x7fELF`).
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// A fully validated, ready-to-spawn execution request. Every field has
/// already passed structural, allowlist, and environment checks.
///
/// Serializable so the broker can hand it to `contained-launcher` (a
/// separate process) as JSON over a pipe, without re-deriving it from an
/// untrusted client message a second time in a different process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedExecute {
    pub correlation_id: String,
    /// `argv[0]` is the canonical executable path (equal to
    /// `canonical_executable`), matching POSIX exec semantics.
    pub argv: Vec<String>,
    pub canonical_executable: PathBuf,
    pub canonical_cwd: PathBuf,
    /// The fully-resolved environment to pass to the child: the broker's
    /// fixed `PATH`/`LANG` plus the caller-supplied, sanitized entries.
    pub env: BTreeMap<String, String>,
    pub timeout: Duration,
}

/// The execution allowlist and approved root.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Canonicalized directory under which every approved `cwd` must fall.
    allowed_root: PathBuf,
    /// Canonical, absolute paths of executables that may be run.
    allowlisted_executables: BTreeSet<PathBuf>,
    /// Fixed `PATH` the broker supplies to every child (never inherited).
    fixed_path: String,
    /// Fixed `LANG` the broker supplies to every child.
    fixed_lang: String,
    limits: Limits,
}

/// An immutable, serializable snapshot of a [`Policy`], derived only from
/// the broker's own trusted configuration (never from client-supplied
/// data), that the broker hands to `contained-launcher` alongside a
/// [`ValidatedExecute`] so the launcher can reconstruct the exact same
/// policy and independently re-validate immediately before `exec`,
/// without taking any policy configuration over its own CLI (which would
/// otherwise have to be supplied fresh, and unverified, by whatever
/// spawned it).
///
/// See [`Policy::snapshot`] / [`Policy::from_snapshot`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub allowed_root: PathBuf,
    pub allowlisted_executables: BTreeSet<PathBuf>,
    pub fixed_path: String,
    pub fixed_lang: String,
    pub limits: Limits,
}

impl Policy {
    /// Creates a policy, canonicalizing `allowed_root` up front.
    ///
    /// # Errors
    /// Returns an IO error if `allowed_root` cannot be canonicalized (e.g.
    /// it does not exist).
    pub fn new(
        allowed_root: impl AsRef<Path>,
        allowlisted_executables: impl IntoIterator<Item = PathBuf>,
        fixed_path: impl Into<String>,
        fixed_lang: impl Into<String>,
        limits: Limits,
    ) -> std::io::Result<Self> {
        let allowed_root = fs::canonicalize(allowed_root)?;
        Ok(Self {
            allowed_root,
            allowlisted_executables: allowlisted_executables.into_iter().collect(),
            fixed_path: fixed_path.into(),
            fixed_lang: fixed_lang.into(),
            limits,
        })
    }

    /// Captures an immutable, serializable snapshot of this policy's
    /// already-canonicalized, already-trusted configuration — safe to
    /// hand to a subprocess (`contained-launcher`) as-is, since it is
    /// derived purely from the broker's own trusted state.
    #[must_use]
    pub fn snapshot(&self) -> PolicySnapshot {
        PolicySnapshot {
            allowed_root: self.allowed_root.clone(),
            allowlisted_executables: self.allowlisted_executables.clone(),
            fixed_path: self.fixed_path.clone(),
            fixed_lang: self.fixed_lang.clone(),
            limits: self.limits.clone(),
        }
    }

    /// Reconstructs a [`Policy`] directly from an already-trusted
    /// [`PolicySnapshot`] — no filesystem access, no re-canonicalization,
    /// since every field in the snapshot was already canonical/validated
    /// by the broker that produced it. Used exclusively by
    /// `contained-launcher`, which receives the snapshot over its stdin
    /// pipe from the broker (never from client-controlled data) and must
    /// not re-derive policy from its own (absent) CLI arguments.
    #[must_use]
    pub fn from_snapshot(snapshot: PolicySnapshot) -> Self {
        Self {
            allowed_root: snapshot.allowed_root,
            allowlisted_executables: snapshot.allowlisted_executables,
            fixed_path: snapshot.fixed_path,
            fixed_lang: snapshot.fixed_lang,
            limits: snapshot.limits,
        }
    }

    #[must_use]
    pub fn allowed_root(&self) -> &Path {
        &self.allowed_root
    }

    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Evaluates a candidate execution request end to end: structural
    /// limits, environment sanitization, executable allowlisting, and `cwd`
    /// containment. A denied request is guaranteed to never reach the
    /// spawn path, because `evaluate` is the only way to construct a
    /// [`ValidatedExecute`].
    pub fn evaluate(
        &self,
        correlation_id: &str,
        argv: &[String],
        cwd: &str,
        env: &BTreeMap<String, String>,
        timeout: Duration,
    ) -> Result<ValidatedExecute, RejectionCode> {
        validate_structure(correlation_id, argv, cwd, env, timeout, &self.limits)?;

        let requested_executable = Path::new(&argv[0]);
        let canonical_executable = self.validate_executable(requested_executable)?;
        let canonical_cwd = self.validate_cwd(Path::new(cwd))?;
        let sanitized_env = self.sanitize_env(env)?;

        let mut argv = argv.to_vec();
        argv[0] = path_to_string(&canonical_executable);

        Ok(ValidatedExecute {
            correlation_id: correlation_id.to_string(),
            argv,
            canonical_executable,
            canonical_cwd,
            env: sanitized_env,
            timeout,
        })
    }

    /// Re-validates the executable and `cwd` of an already-[`evaluate`]d
    /// request immediately before spawn, to detect a symlink swap performed
    /// between the initial validation and now. This *narrows* the TOCTOU
    /// window but cannot close it entirely: see
    /// [`crate::error::BrokerError::ResidualToctou`] for the residual race
    /// that remains between this check and the kernel's own path resolution
    /// inside `execve`.
    pub fn revalidate_before_spawn(
        &self,
        validated: &ValidatedExecute,
    ) -> Result<(), RejectionCode> {
        let now_executable = self.validate_executable(&validated.canonical_executable)?;
        if now_executable != validated.canonical_executable {
            return Err(RejectionCode::ExecutableChangedSinceValidation);
        }
        let now_cwd = self.validate_cwd(&validated.canonical_cwd)?;
        if now_cwd != validated.canonical_cwd {
            return Err(RejectionCode::ExecutableChangedSinceValidation);
        }
        Ok(())
    }

    fn validate_executable(&self, requested: &Path) -> Result<PathBuf, RejectionCode> {
        if !requested.is_absolute() {
            return Err(RejectionCode::ExecutableNotAbsolute);
        }

        // Reject `env`-style indirection outright, by raw path, before any
        // canonicalization: never invoke `env` (any `.../env` binary) as
        // the target, since it is a generic "look up and exec something
        // else" primitive that would let a request bypass the allowlist.
        if requested.file_name().and_then(|n| n.to_str()) == Some("env") {
            return Err(RejectionCode::ExecutableInterpreterDenied);
        }

        let canonical =
            fs::canonicalize(requested).map_err(|_| RejectionCode::ExecutableNotAllowlisted)?;

        // The path as supplied by the client must already be canonical: a
        // symlink (or any path with symlink components) is rejected by
        // default. Operators who intend to approve a symlink alias must add
        // that literal alias path as its own allowlist entry.
        if canonical != requested {
            return Err(RejectionCode::ExecutableNotCanonical);
        }

        // Defense in depth, independent of (and evaluated before) the
        // allowlist: never allow `/proc/.../exe`, `/proc/.../fd/*`, or a
        // dynamic linker, even if a misconfigured allowlist were to somehow
        // contain one.
        if is_proc_self_exe_or_fd(&canonical) {
            return Err(RejectionCode::ExecutableInterpreterDenied);
        }
        if let Some(name) = canonical.file_name().and_then(|n| n.to_str())
            && DENIED_INTERPRETER_BASENAMES.contains(&name)
        {
            return Err(RejectionCode::ExecutableInterpreterDenied);
        }

        if !self.allowlisted_executables.contains(&canonical) {
            return Err(RejectionCode::ExecutableNotAllowlisted);
        }

        let metadata =
            fs::metadata(&canonical).map_err(|_| RejectionCode::ExecutableNotRegularFile)?;
        if !metadata.is_file() {
            return Err(RejectionCode::ExecutableNotRegularFile);
        }

        if !is_elf(&canonical) {
            // Covers scripts/shebangs and any other non-ELF executable.
            return Err(RejectionCode::ExecutableInterpreterDenied);
        }

        Ok(canonical)
    }

    fn validate_cwd(&self, requested: &Path) -> Result<PathBuf, RejectionCode> {
        if !requested.is_absolute() {
            return Err(RejectionCode::CwdNotAbsolute);
        }
        let canonical = fs::canonicalize(requested).map_err(|_| RejectionCode::CwdNotApproved)?;
        if canonical != self.allowed_root && !canonical.starts_with(&self.allowed_root) {
            return Err(RejectionCode::CwdNotApproved);
        }
        let metadata = fs::metadata(&canonical).map_err(|_| RejectionCode::CwdNotDirectory)?;
        if !metadata.is_dir() {
            return Err(RejectionCode::CwdNotDirectory);
        }
        Ok(canonical)
    }

    fn sanitize_env(
        &self,
        requested: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>, RejectionCode> {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), self.fixed_path.clone());
        env.insert("LANG".to_string(), self.fixed_lang.clone());

        for (key, value) in requested {
            if contains_nul(key) || contains_nul(value) {
                return Err(RejectionCode::NulByte);
            }
            if key.eq_ignore_ascii_case("PATH") || key.eq_ignore_ascii_case("LANG") {
                // The broker always supplies these; a caller-provided value
                // is silently superseded rather than accepted, since
                // accepting it would let a caller redefine the search path.
                continue;
            }
            if is_dangerous_env_var(key) {
                return Err(RejectionCode::DangerousEnvVar);
            }
            env.insert(key.clone(), value.clone());
        }

        Ok(env)
    }
}

fn is_dangerous_env_var(name: &str) -> bool {
    DANGEROUS_ENV_EXACT.contains(&name)
        || DANGEROUS_ENV_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

fn is_proc_self_exe_or_fd(canonical: &Path) -> bool {
    let s = canonical.to_string_lossy();
    s == "/proc/self/exe"
        || (s.starts_with("/proc/") && (s.ends_with("/exe") || s.contains("/fd/")))
}

fn is_elf(path: &Path) -> bool {
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    use std::io::Read;
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return false;
    }
    magic == ELF_MAGIC
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn write_fake_elf(path: &Path) {
        let mut file = fs::File::create(path).expect("create");
        file.write_all(&ELF_MAGIC).expect("write magic");
        file.write_all(&[0u8; 12]).expect("write padding");
        let mut perms = file.metadata().expect("metadata").permissions();
        perms.set_mode(0o755);
        file.set_permissions(perms).expect("chmod");
    }

    fn write_script(path: &Path) {
        fs::write(path, b"#!/bin/sh\necho hi\n").expect("write script");
        let mut perms = fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod");
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        root: PathBuf,
        bin: PathBuf,
        policy: Policy,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        // Canonicalize the tempdir's own path up front: on some platforms
        // (notably macOS, where `$TMPDIR` is itself reached through a
        // symlink, e.g. `/var/folders/... -> /private/var/folders/...`)
        // the raw path handed back by `tempfile` is not yet canonical, even
        // before any test-specific symlink is introduced. Building every
        // other fixture path from the already-canonical base keeps
        // `validate_executable`'s "client-supplied path must already be
        // canonical" check meaningful and portable, rather than spuriously
        // failing due to an OS-specific tmp-dir quirk unrelated to what
        // each test actually means to exercise.
        let base = fs::canonicalize(dir.path()).expect("canonicalize tempdir");
        let root = base.join("workspace");
        fs::create_dir_all(&root).expect("mkdir workspace");
        let bin_dir = base.join("bin");
        fs::create_dir_all(&bin_dir).expect("mkdir bin");
        let bin = bin_dir.join("tool");
        write_fake_elf(&bin);

        let policy = Policy::new(
            &root,
            vec![fs::canonicalize(&bin).expect("canonicalize bin")],
            "/usr/bin:/bin",
            "C.UTF-8",
            Limits::default(),
        )
        .expect("policy");

        Fixture {
            _dir: dir,
            root,
            bin,
            policy,
        }
    }

    #[test]
    fn accepts_allowlisted_executable_under_root() {
        let fx = fixture();
        let validated = fx
            .policy
            .evaluate(
                "corr-1",
                &[fx.bin.to_string_lossy().into_owned(), "--flag".into()],
                &fx.root.to_string_lossy(),
                &BTreeMap::new(),
                Duration::from_secs(1),
            )
            .expect("must accept");
        assert_eq!(
            validated.canonical_executable,
            fs::canonicalize(&fx.bin).unwrap()
        );
        assert_eq!(
            validated.env.get("PATH"),
            Some(&"/usr/bin:/bin".to_string())
        );
    }

    #[test]
    fn rejects_executable_not_in_allowlist() {
        let fx = fixture();
        let other = fx.bin.parent().unwrap().join("other");
        write_fake_elf(&other);
        let err = fx
            .policy
            .evaluate(
                "corr-1",
                &[other.to_string_lossy().into_owned()],
                &fx.root.to_string_lossy(),
                &BTreeMap::new(),
                Duration::from_secs(1),
            )
            .expect_err("must reject");
        assert_eq!(err, RejectionCode::ExecutableNotAllowlisted);
    }

    #[test]
    fn rejects_relative_executable() {
        let fx = fixture();
        let err = fx
            .policy
            .evaluate(
                "corr-1",
                &["relative/tool".into()],
                &fx.root.to_string_lossy(),
                &BTreeMap::new(),
                Duration::from_secs(1),
            )
            .expect_err("must reject");
        assert_eq!(err, RejectionCode::ExecutableNotAbsolute);
    }

    #[test]
    fn rejects_symlink_to_allowlisted_executable() {
        let fx = fixture();
        let link = fx.bin.parent().unwrap().join("tool-link");
        symlink(&fx.bin, &link).expect("symlink");
        let err = fx
            .policy
            .evaluate(
                "corr-1",
                &[link.to_string_lossy().into_owned()],
                &fx.root.to_string_lossy(),
                &BTreeMap::new(),
                Duration::from_secs(1),
            )
            .expect_err("must reject");
        assert_eq!(err, RejectionCode::ExecutableNotCanonical);
    }

    #[test]
    fn rejects_env_style_indirection() {
        let fx = fixture();
        let env_bin = fx.bin.parent().unwrap().join("env");
        write_fake_elf(&env_bin);
        let err = fx
            .policy
            .evaluate(
                "corr-1",
                &[env_bin.to_string_lossy().into_owned()],
                &fx.root.to_string_lossy(),
                &BTreeMap::new(),
                Duration::from_secs(1),
            )
            .expect_err("must reject");
        assert_eq!(err, RejectionCode::ExecutableInterpreterDenied);
    }

    #[test]
    fn rejects_script_with_shebang_even_if_allowlisted() {
        let fx = fixture();
        let script = fx.bin.parent().unwrap().join("script.sh");
        write_script(&script);
        // Simulate a misconfigured allowlist that includes the script.
        let mut allowlist = BTreeSet::new();
        allowlist.insert(fs::canonicalize(&fx.bin).unwrap());
        allowlist.insert(fs::canonicalize(&script).unwrap());
        let policy = Policy {
            allowlisted_executables: allowlist,
            ..fx.policy.clone()
        };
        let err = policy
            .evaluate(
                "corr-1",
                &[script.to_string_lossy().into_owned()],
                &fx.root.to_string_lossy(),
                &BTreeMap::new(),
                Duration::from_secs(1),
            )
            .expect_err("must reject");
        assert_eq!(err, RejectionCode::ExecutableInterpreterDenied);
    }

    #[test]
    fn rejects_cwd_outside_allowed_root() {
        let fx = fixture();
        let outside = fx._dir.path().join("outside");
        fs::create_dir_all(&outside).expect("mkdir outside");
        let err = fx
            .policy
            .evaluate(
                "corr-1",
                &[fx.bin.to_string_lossy().into_owned()],
                &outside.to_string_lossy(),
                &BTreeMap::new(),
                Duration::from_secs(1),
            )
            .expect_err("must reject");
        assert_eq!(err, RejectionCode::CwdNotApproved);
    }

    /// A `cwd` string containing literal `..` traversal components that,
    /// once canonicalized, resolve to a path outside `allowed_root` must
    /// be rejected exactly like any other out-of-root `cwd` — the
    /// traversal syntax itself is not special-cased or blocked textually;
    /// `validate_cwd` always canonicalizes first (resolving every `..`
    /// and symlink component) and only then checks containment, so a
    /// traversal string can never be used to bypass the containment
    /// check by construction.
    #[test]
    fn rejects_cwd_traversal_that_escapes_allowed_root() {
        let fx = fixture();
        // `fx.root` is `<base>/workspace`; `<base>/bin` is a sibling
        // directory that exists but is not under `allowed_root`, so
        // `<root>/../bin` canonicalizes to a real, existing directory
        // that must still be rejected.
        let traversal_cwd = fx.root.join("..").join("bin");
        assert!(
            traversal_cwd.exists(),
            "the traversal target must exist, so this test proves \
             containment is enforced on the canonicalized path, not \
             merely on filesystem-existence checks"
        );
        let err = fx
            .policy
            .evaluate(
                "corr-1",
                &[fx.bin.to_string_lossy().into_owned()],
                &traversal_cwd.to_string_lossy(),
                &BTreeMap::new(),
                Duration::from_secs(1),
            )
            .expect_err("must reject a traversal cwd that escapes allowed_root");
        assert_eq!(err, RejectionCode::CwdNotApproved);
    }

    /// A `cwd` that does not exist at all (so `fs::canonicalize` itself
    /// fails) is rejected as `CwdNotApproved` — there is no distinct
    /// "does not exist" rejection code; a nonexistent path can never be
    /// approved, so it is folded into the same code as "exists but is
    /// outside the root", both of which are simply "not an approved
    /// cwd".
    #[test]
    fn rejects_cwd_that_does_not_exist() {
        let fx = fixture();
        let missing = fx.root.join("this-directory-does-not-exist");
        assert!(!missing.exists());
        let err = fx
            .policy
            .evaluate(
                "corr-1",
                &[fx.bin.to_string_lossy().into_owned()],
                &missing.to_string_lossy(),
                &BTreeMap::new(),
                Duration::from_secs(1),
            )
            .expect_err("must reject a nonexistent cwd");
        assert_eq!(err, RejectionCode::CwdNotApproved);
    }

    /// A `cwd` that exists, canonicalizes cleanly, and falls under
    /// `allowed_root` — but is a regular file, not a directory — is
    /// rejected distinctly as `CwdNotDirectory`, one step later in
    /// `validate_cwd` than the containment check.
    #[test]
    fn rejects_cwd_that_is_a_regular_file_not_a_directory() {
        let fx = fixture();
        let file_cwd = fx.root.join("not-a-directory.txt");
        fs::write(&file_cwd, b"not a directory").expect("write file cwd");
        let err = fx
            .policy
            .evaluate(
                "corr-1",
                &[fx.bin.to_string_lossy().into_owned()],
                &file_cwd.to_string_lossy(),
                &BTreeMap::new(),
                Duration::from_secs(1),
            )
            .expect_err("must reject a non-directory cwd");
        assert_eq!(err, RejectionCode::CwdNotDirectory);
    }

    #[test]
    fn rejects_dangerous_env_vars() {
        let fx = fixture();
        for name in [
            "LD_PRELOAD",
            "BASH_ENV",
            "PYTHONPATH",
            "NODE_OPTIONS",
            "RUBYOPT",
        ] {
            let mut env = BTreeMap::new();
            env.insert(name.to_string(), "evil".to_string());
            let err = fx
                .policy
                .evaluate(
                    "corr-1",
                    &[fx.bin.to_string_lossy().into_owned()],
                    &fx.root.to_string_lossy(),
                    &env,
                    Duration::from_secs(1),
                )
                .expect_err("must reject");
            assert_eq!(err, RejectionCode::DangerousEnvVar, "name={name}");
        }
    }

    #[test]
    fn caller_supplied_path_and_lang_are_overridden_not_accepted() {
        let fx = fixture();
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), "/evil".to_string());
        env.insert("LANG".to_string(), "whatever".to_string());
        let validated = fx
            .policy
            .evaluate(
                "corr-1",
                &[fx.bin.to_string_lossy().into_owned()],
                &fx.root.to_string_lossy(),
                &env,
                Duration::from_secs(1),
            )
            .expect("must accept");
        assert_eq!(
            validated.env.get("PATH"),
            Some(&"/usr/bin:/bin".to_string())
        );
        assert_eq!(validated.env.get("LANG"), Some(&"C.UTF-8".to_string()));
    }

    #[test]
    fn revalidate_before_spawn_detects_symlink_swap() {
        let fx = fixture();
        let validated = fx
            .policy
            .evaluate(
                "corr-1",
                &[fx.bin.to_string_lossy().into_owned()],
                &fx.root.to_string_lossy(),
                &BTreeMap::new(),
                Duration::from_secs(1),
            )
            .expect("must accept");
        fx.policy
            .revalidate_before_spawn(&validated)
            .expect("must still be valid");

        // Simulate a swap: replace the allowlisted binary with a directory
        // at the same canonical path is not possible without removing it
        // first; instead, remove it to make it no longer a regular file.
        fs::remove_file(&validated.canonical_executable).expect("remove");
        let err = fx
            .policy
            .revalidate_before_spawn(&validated)
            .expect_err("must reject after removal");
        assert_eq!(err, RejectionCode::ExecutableNotAllowlisted);
    }

    /// A genuine symlink swap (as opposed to the plain-removal case
    /// above): between `evaluate` and `revalidate_before_spawn`, the
    /// canonical executable path is removed and replaced with a symlink
    /// pointing at a *different* binary. `validate_executable`
    /// canonicalizes the (now-symlink) path, resolving through it to the
    /// swapped-in target, which no longer equals the originally-requested
    /// (symlink) path itself — rejected as `ExecutableNotCanonical`,
    /// distinct from the `ExecutableNotAllowlisted` a plain removal
    /// produces. This is the exact race `exec-broker-launcher` re-checks
    /// for immediately before `execve` (see `launcher::run`, which calls
    /// this same `revalidate_before_spawn`); the residual TOCTOU that
    /// remains *even after* this check — the kernel's own path
    /// resolution inside `execve` itself racing a swap performed after
    /// this very call returns `Ok` — is documented at
    /// [`crate::error::BrokerError::ResidualToctou`] and is not, and
    /// cannot be, further narrowed by a userspace check.
    #[test]
    fn revalidate_before_spawn_detects_symlink_swap_to_a_different_target() {
        let fx = fixture();
        let validated = fx
            .policy
            .evaluate(
                "corr-1",
                &[fx.bin.to_string_lossy().into_owned()],
                &fx.root.to_string_lossy(),
                &BTreeMap::new(),
                Duration::from_secs(1),
            )
            .expect("must accept");
        fx.policy
            .revalidate_before_spawn(&validated)
            .expect("must still be valid");

        // A different real binary, deliberately *not* on the allowlist,
        // to swap in at the exact path the launcher believes it already
        // validated.
        let swapped_target = fx.bin.parent().unwrap().join("swapped-in-tool");
        write_fake_elf(&swapped_target);

        fs::remove_file(&validated.canonical_executable).expect("remove original");
        symlink(&swapped_target, &validated.canonical_executable).expect("symlink swap");

        let err = fx
            .policy
            .revalidate_before_spawn(&validated)
            .expect_err("must reject a symlink swapped in after validation");
        assert_eq!(err, RejectionCode::ExecutableNotCanonical);
    }

    #[test]
    fn policy_snapshot_round_trips_through_json_and_reconstructs_equivalent_policy() {
        let fx = fixture();
        let snapshot = fx.policy.snapshot();

        let json = serde_json::to_vec(&snapshot).expect("encode snapshot");
        let decoded: PolicySnapshot = serde_json::from_slice(&json).expect("decode snapshot");
        assert_eq!(decoded.allowed_root, fx.root);
        assert_eq!(
            decoded.allowlisted_executables,
            std::iter::once(fs::canonicalize(&fx.bin).expect("canonicalize"))
                .collect::<BTreeSet<_>>()
        );

        let reconstructed = Policy::from_snapshot(decoded);
        // The reconstructed policy must evaluate a request exactly the
        // same way the original policy would, since it never touched the
        // filesystem to rebuild itself.
        let validated = reconstructed
            .evaluate(
                "corr-1",
                &[fx.bin.to_string_lossy().into_owned()],
                &fx.root.to_string_lossy(),
                &BTreeMap::new(),
                Duration::from_secs(1),
            )
            .expect("reconstructed policy must accept the same request");
        assert_eq!(validated.canonical_executable, fx.bin);
    }
}
