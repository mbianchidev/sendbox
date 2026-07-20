# Security Records Architecture

`sendbox-security` provides persistence foundations for audit records, provenance,
and workspace snapshots. These APIs are intentionally not wired into
`sendbox-rs run`, runtime adapters, guest services, secrets, or credential handling.

## Secure filesystem boundary

All security state is accessed relative to an already trusted root directory.
On macOS and Linux, each path component is opened with descriptor-relative
operations and `O_NOFOLLOW`. Reads and writes validate the final descriptor's type,
owner, device, and size. Atomic replacement writes a mode-restricted temporary file
in the destination directory, syncs it, renames it, and syncs the parent directory.
macOS file commits also request `F_FULLFSYNC`.

Paths must be relative and contain only normal components. Cleanup failures are
returned with the primary failure instead of being discarded. The current adapter
supports Unix platforms; other platforms return an explicit unsupported-platform
error rather than silently using weaker path operations.

## Audit format

Rust audit logs use `sendbox-audit` version 1:

- Canonical compact JSON header and canonical JSON records separated by newlines.
- Contiguous sequence numbers and one session identifier.
- SHA-256 hash chaining over domain-separated canonical event bytes.
- Bounded actions, subjects, metadata, record count, and persisted file size.
- RFC 6962-style domain separation between Merkle leaves and internal nodes.
- Single-writer file locking and atomic whole-log commits.

Redaction is export-only and runs after integrity verification. It never changes the
committed event or its hash. Partial writes, malformed records, reordering, replayed
records, and chain corruption are rejected. As with any local append-only file, a
complete valid suffix can only be proven missing when a previously published head or
Merkle root is available externally.

Swift audit version 1 remains a separate read-only format. Its JSON array,
pipe-delimited hash input, ISO-8601 timestamps, genesis string, and non-domain-
separated padded Merkle tree are reproduced only by the legacy verifier.

## Provenance format

Rust detached signatures use `sendbox-provenance` version 1:

- Ed25519 keys with SHA-256 public-key fingerprints.
- Domain-separated canonical payloads for content, configuration, and artifacts.
- Detached signatures with unique IDs, signing time, optional expiry, and bounded
  metadata.
- Multi-signer trust stores with distinct-signer thresholds and required signers.
- Identity validity, expiry, revocation, signature expiry, and replay checks.

Private key representations are zeroized and their debug output is always redacted.
Trust stores use the secure atomic persistence boundary. Swift version 1 signatures
remain read-only and verify the original raw content bytes; the Rust verifier never
falls back between legacy and version 1 signing constructions.

## Snapshot format

Rust snapshots use `sendbox-snapshot` version 1. A canonical manifest references
immutable SHA-256 objects under a sharded object directory. Traversal is relative to
an open workspace descriptor and never follows symbolic links.

Manifests explicitly record directories, regular files, symbolic links, and
hardlinks. Capture rejects cross-device entries, sparse files, sockets, FIFOs,
devices, unsafe mode bits, invalid paths, and configured exclusions. File metadata
and content are obtained from the same open descriptor.

Restore verifies every object, populates a fresh sibling staging directory, moves the
current workspace to a backup, commits the staging rename, and rolls back if commit
fails. Pruning holds the store lock and removes only objects unreferenced by retained
manifests. Swift version 1 manifests are read-only; legacy tarballs are never passed
to an external extractor or unpacked into a workspace.
