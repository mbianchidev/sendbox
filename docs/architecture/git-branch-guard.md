# Native Git branch guard

`sendbox-git` is the native Rust admission engine for selected-repository
`git push` and `git pull` operations. `sendbox-host` resolves the selected
repository, signs the guard policy into the boundary plan, and Apple/Kata guests
install trusted wrapper copies before workload execution. The crate remains
usable as a small standalone policy API.

## Policy and identity

The version 1 policy document contains:

- the selected repository as normalized `host`, `owner`, and repository `name`;
- the selected workspace as an absolute path captured by canonical path and
  filesystem identity;
- protected branches, allowed glob patterns, and optional `{username}`
  expansion;
- the inherited environment-key allowlist and fixed executable search path;
- probe timeout, output, and policy-size bounds.

Remote parsing accepts HTTPS, HTTP, SSH, Git protocol, SCP-style SSH, and
owner/name shorthand on the selected host. Repository paths must contain exactly
two decoded components. Unsupported helpers, local paths, encoded separators,
multiple effective push URLs, and mixed identities are ambiguous and fail
closed for selected-repository operations.

Protected branches always override allowed patterns. The current branch must be
non-detached and allowed. Selected-repository clones are guarded regardless of
workspace path, while positively resolved other repositories pass through.

## Git grammar

The parser separates global options, resolves non-shell aliases with an
eight-expansion limit, and models supported push/pull repository options.
`-C`, `-c`, `--git-dir`, and `--work-tree` are forwarded unchanged to every
probe and final execution. `--config-env` is rejected because it can create a
different configuration view.

The guard resolves branch remotes, `remote.pushDefault`, branch push remotes,
upstreams, configured push/merge refspecs, and every `push.default` mode. Exact
force-prefixed and deletion refspecs are normalized. Wildcard, negative,
revision-expression, tag, mirror, matching, and other unbounded updates fail
closed when they cannot be reduced to exact local source and remote branch
destinations.

The pull check preserves the existing policy intent: the current branch and
integration source branches must be allowed. This does not prevent equivalent
`fetch` plus `merge` or `rebase` sequences.

## Process contract

`GitProcessRunner` is injected. The system runner:

- requires a canonical absolute, regular, executable Git path;
- rejects symlinks, group/world-writable binaries, untrusted ownership,
  recursive guard identity, and metadata changes after verification;
- verifies that the binary identifies itself as Git;
- bounds probe time and stdout/stderr while draining both streams;
- uses one sanitized environment for probes and final Git;
- rejects Git configuration/path injection and dynamic-loader variables;
- rejects caller-selected askpass programs, configured credential helpers, and
  `--exec-path`; production GitHub HTTPS and SSH authentication use fixed
  guest-installed wrappers;
- never includes environment values, credentials, probe output, or complete
  argv in diagnostics;
- replaces the guard process with Git on Unix, preserving standard streams,
  signals, and exit status without a shell or generated executable.

The standalone protocol is:

```text
sendbox-git-guard --policy /absolute/root-owned/policy.json \
  --git /absolute/trusted/git -- <git arguments>
```

Standalone deployment must place the policy, wrapper invocation, guard, and Git
binary in root-owned non-writable locations. Production guest deployment copies
the verified binaries and signed policy into the root-owned runtime boundary
and supplies fixed trusted values.

## Security boundary

This component admits one Git invocation. It does not block direct execution of
another Git binary, `git send-pack`, remote helpers, SSH receive-pack, alternate
clients, or GitHub APIs. Local inspection and final Git execution are also not
an atomic transaction. Server-side branch rules remain mandatory.
