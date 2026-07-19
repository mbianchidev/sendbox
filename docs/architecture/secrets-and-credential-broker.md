# Secrets and Credential Broker Foundation

Status: **pre-1.0 production foundation**. `sendbox-secrets` owns host secret
storage, explicit legacy migration, ephemeral session envelopes, and pure
credential request transformation. Runtime wiring and a network listener are
deliberately outside this crate.

## Secret values and names

`SecretValue` owns zeroizing bytes and always redacts `Debug` and `Display`.
Callers must explicitly use `expose_secret()` at the final trusted boundary.
Names are non-empty, NFC-normalized UTF-8 without control characters and are
bounded to 128 bytes. Values are bounded to 64 KiB.

The `SecretStore` contract has distinct create and update operations plus
retrieve, delete, list, exists, and explicit migration. Not-found,
access-denied, corrupt, insecure-store, duplicate, and size failures remain
distinct. No API exports all plaintext values or generates shell source.

## macOS Keychain

The default generic-password service remains `com.sendbox.secrets`, matching
the Swift implementation. Values use a versioned record inside the Keychain;
legacy Swift values remain readable and are rewritten only through `migrate`.
Tests use unique service identifiers and delete their own entries.

`KeychainMigrationPlan` models service-name and signing-identity changes. A
changed signing identity may trigger the existing Keychain ACL prompt. SendBox
does not weaken ACLs or silently create replacement credentials. Cross-service
migration requires a `MigrationAuthorization` produced after user
confirmation; values move directly between Keychain operations and are never
returned as an export bundle. Final release signing must run the ignored ACL
qualification test in the intended signing environment.

## Linux protected file store

The compatibility path remains:

```text
~/.sendbox/secrets/<hex(service)>/<hex(secret-name)>
```

Directories are opened as capabilities and must be owned by the effective user
with mode `0700`. Secret and lock files must be regular, owner-owned `0600`
files. Existing symlinks, wrong types, owners, or modes are rejected; the store
does not chmod attacker-controlled paths.

All child operations are descriptor-relative. Opens use `O_NOFOLLOW`.
Mutations hold a stable service lock file across validation, write, file
`fsync`, atomic rename, and directory `fsync`. This protects cooperating
SendBox processes on a local filesystem; network filesystems with unreliable
advisory locks are unsupported. Interrupted temporary files are never treated
as secrets.

Swift Linux raw UTF-8 files remain readable as version 0. The explicit
`migrate` operation captures filesystem timestamps and atomically replaces the
raw value with the versioned record. A record magic prefix beginning with an
invalid UTF-8 byte distinguishes new records from every value the Swift store
could write. A malformed prefixed record is corrupt and never falls back to
plaintext.

## Session secret envelopes

`EnvelopeCipher` derives a 256-bit XChaCha20-Poly1305 key from authenticated
bootstrap/protocol material using HKDF-SHA256 and session-specific domain
separation. Each envelope authenticates a canonical CBOR associated-data tuple:

- protocol domain and version;
- session ID and recipient role;
- secret name and sequence;
- expiration time;
- policy digest.

Each seal uses a fresh 192-bit operating-system nonce and rejects duplicate
sequence or nonce issuance within the cipher instance. Opening verifies the
expected binding, authentication tag, expiration, and a bounded session replay
guard before returning a zeroizing value. Replay state is intentionally
session-scoped: session bootstrap material and IDs must never be reused after a
process restart. Guest plaintext persistence is not provided by this crate.

## Credential broker policy

Policies require an exact canonical target host, absolute path prefix, explicit
allowed methods, request and response limits, redirect policy, and HTTPS with
TLS verification. Injection supports bearer, validated custom header, query,
and complete path-segment replacement. Userinfo, host suffix tricks, trailing
dots, control characters, duplicate query parameters, invalid header values,
cross-target redirects, and oversized bodies fail closed.

Transformed URLs, headers, and bodies use redacted wrappers. Audit metadata
contains only method, original path, exact target, injection kind, secret name,
and body size. Bearer injection writes `Bearer <actual secret>`; the Swift
placeholder regression is covered by a unit test.

Repository credentials including `GITHUB_TOKEN`, `GH_TOKEN`, Git askpass/SSH
forwarding variables, GitHub OAuth/PAT values, and GitHub App private keys are
explicitly denied. They must use the guarded GitHub forwarding subsystem.

## Remaining integration

- Bind the envelope key derivation to the final authenticated protocol key
  export and host-to-guest message type.
- Add the production local credential listener and upstream HTTP client with
  response streaming, timeout, and connection limits.
- Apply redirect authorization before every hop and never forward credentials
  across an unauthorized redirect.
- Connect repository credentials only through guarded GitHub forwarding.
- Run signed Keychain ACL qualification before the Rust CLI replaces Swift.
