# Security records migration

The production security lifecycle writes the native versioned formats. Existing
pre-rewrite state remains readable through explicit, bounded compatibility APIs.

| Data | Legacy support | Rust format | Migration behavior |
|---|---|---|---|
| Audit | Swift `entries.json` and `tree.json` v1 | `sendbox-audit` v1 | Verify legacy bytes in place; new events start a Rust v1 log. Do not rewrite legacy hashes. |
| Provenance | Swift detached signature and trust-store v1 | `sendbox-provenance` v1 | Verify legacy signatures over raw content. Re-sign with the Rust domain-separated format when rotating policy. |
| Snapshot | Swift JSON manifest v1 | `sendbox-snapshot` v1 | Inventory and validate legacy metadata. Capture future snapshots into the object store. Legacy tarballs are not trusted for direct extraction. |

Swift v1 readers are supported throughout SendBox 2.x and cannot be removed before
SendBox 3.0. Removal requires a major-release migration notice and a tested export
path. Every Rust persisted-format reader remains supported for at least two major
versions after a successor format becomes writable.

Compatibility readers are bounded and read-only. They preserve original
cryptographic semantics even where the replacement format is stronger. Unsupported
versions, malformed paths, invalid ownership, corruption, and policy failures return
explicit errors; they do not trigger automatic repair or fallback.

The runtime publishes signed audit heads, exposes explicit migration commands,
validates archived snapshot metadata without trusting legacy tar extraction, and
uses the secure host secret store for signing material. Compatibility readers do
not create an automatic downgrade or fallback path.
