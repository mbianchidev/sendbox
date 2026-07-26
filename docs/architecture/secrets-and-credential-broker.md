# Secrets and Credential Broker

Status: **pre-1.0 production libraries**. `sendbox-secrets` owns host secret
storage, explicit legacy migration, ephemeral session envelopes, and pure
credential request transformation. `sendbox-credentials` owns the bounded local
listener, certificate-verifying HTTPS forwarding, guarded GitHub repository
authorization, and session-bound agent configuration. Runtime and CLI lifecycle
wiring remain intentionally deferred.

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

## Credential broker policy and listener

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

`sendbox-credentials` exposes one explicit HTTP base URL per credential rule.
The listener binds to IPv4 or IPv6 loopback by default. A non-loopback address
must be selected through the explicit bind variant; wildcard and multicast
binds are rejected.

The listener accepts one origin-form HTTP/1.1 request per connection and then
closes it. It enforces bounded request lines, aggregate headers, header count,
body length, read time, concurrent connections, response headers, response
body, redirects, and shutdown time. Bare line feeds, obsolete folding,
duplicate `Host` or `Content-Length`, `Transfer-Encoding`, absolute-form
targets, pipelined bytes, control characters, and unsupported `CONNECT`
credential injection fail closed.

The broker constructs the upstream URL itself after the local rule route,
method, host, and path have matched. It strips hop-by-hop and
`Connection`-nominated headers, then calls the `sendbox-secrets`
transformation. Upstream traffic is HTTPS-only on port 443 with hostname and
certificate verification enabled. Automatic redirects and system proxies are
disabled. Each redirect is bounded, re-authorized against the exact host and
path policy, and transformed again before sending.

DNS is resolved before each hop. Every returned address is classified with the
production egress address classifier, restricted addresses require exact
explicit approval, and the approved addresses are pinned into the HTTPS client
for that hop while the original hostname remains the TLS SNI and certificate
identity. This prevents a second resolver lookup from changing the destination
between authorization and connect.

### Agent compatibility

Agents and SDKs must support replacing an API base URL and must append the
original upstream path and query to the returned per-rule endpoint. The local
URL is HTTP because it is a loopback host process; the broker performs the
verified HTTPS connection to the real service.

The broker is not a generic HTTP proxy. It does not set `HTTP_PROXY` or
`HTTPS_PROXY`, intercept TLS, synthesize certificates, rewrite DNS, or inject
credentials into CONNECT tunnels. Clients that hardcode their service origin or
only support HTTPS proxy tunneling are incompatible until they gain an explicit
base-URL setting.

## Guarded GitHub repository authentication

`GitHubMetadataClient` separates repository metadata from the production `gh`
adapter. The adapter executes an absolute `gh` path with fixed-shape GraphQL
argv, variables for repository owner/name and cursors, bounded output and time,
no output publication, a cleared environment, and explicit `GH_CONFIG_DIR`,
`HOME`, host, prompt, pager, and update settings. Authentication tokens never
appear in argv or diagnostics.

Authorization resolves the selected repository owner type and visibility, then
paginates the complete viewer repository set and filters all non-public
repositories. Malformed JSON, command failure, timeout, cancellation, truncated
output, a missing or repeated cursor, or the hard page limit aborts
authorization. The token is requested only after scope authorization succeeds.

The repository policy preserves the Swift behavior:

- the selected non-public repository must be accessible;
- a public selected repository cannot use credentials with non-public scope;
- an additional non-public repository requires an organization owner matching
  the selected repository and the explicit private-access override;
- user-owned repositories are not treated as an organization;
- cross-organization non-public scope is always denied.

Copilot authentication is independently gated by
`forward_copilot_auth`. `SessionCredentialConfiguration` returns the broker
listener and per-rule agent endpoints plus zeroizing GitHub/Copilot values for a
specific session. It does not install environment variables or start a runtime.

## Remaining integration

- Bind the envelope key derivation to the final authenticated protocol key
  export and host-to-guest message type.
- Connect the session-bound broker and guarded GitHub outputs to the final
  security lifecycle after runtime/agent integration lands.
- Run signed Keychain ACL qualification before the Rust CLI replaces Swift.
