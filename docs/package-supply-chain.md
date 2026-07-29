# Package supply-chain proxy

SendBox can place an npm-compatible registry proxy between a persistent guest
workload and its configured upstream registry. The proxy downloads packages
into quarantine, verifies and scans them without executing package code, and
serves artifact bytes only after an explicit `allow` verdict.

The npm adapter is production-supported on Apple and Kata persistent runtimes.
Hyperlight rejects package analysis because its one-shot runtime cannot compose
the trusted proxy, egress gateways, persistent cache, and authenticated report
retrieval. PyPI, Cargo, Go modules, Maven, and OCI are extension contracts only;
their adapters are not implemented yet.

## Enable the npm proxy

Add `policy.packages` to the sandbox configuration:

```yaml
policy:
  network:
    default_action: deny
    allow_dns: true
    allowed_domains:
      - registry.npmjs.org
    blocked_domains: []

  packages:
    enabled: true
    registries:
      - ecosystem: npm
        url: https://registry.npmjs.org/
        allow_insecure_http: false
        signature: if_present
        provenance: if_present
    default_finding_action: deny
    finding_actions:
      - finding: lifecycle_script
        action: deny
      - finding: subprocess_api
        action: deny
    exceptions: []
    allow_legacy_sha1: true
    limits:
      max_metadata_bytes: 16777216
      max_download_bytes: 268435456
      max_unpacked_bytes: 1073741824
      max_entry_bytes: 67108864
      max_entries: 100000
      max_path_bytes: 4096
      max_depth: 64
      max_source_scan_bytes: 8388608
      request_timeout_secs: 120
      scan_timeout_secs: 30
      max_report_findings: 4096
      max_report_bytes: 98304
    cache:
      enabled: true
      max_bytes: 4294967296
      max_entries: 100000
      retain_quarantined: false
```

The npm-first implementation requires exactly one npm registry. Its URL must
also be admitted by `policy.network`; SendBox uses the original network policy
for the trusted upstream gateway and derives a workload policy that denies the
registry directly.

At launch, SendBox sets both uppercase and lowercase npm registry variables to
the workload-facing loopback proxy and sets npm's `ignore-scripts` option in
both forms. A workload-supplied npm registry override does not grant direct
network access to the configured upstream. The proxy rewrites every packument
tarball URL to an opaque local artifact route, so npm never receives the
upstream tarball URL.

## Private registries

Store the raw npm token in the SendBox vault and reference its name from the
registry policy:

```bash
sendbox secrets add PRIVATE_NPM_TOKEN
```

```yaml
policy:
  packages:
    enabled: true
    registries:
      - ecosystem: npm
        url: https://npm.example.internal/
        credential_secret: PRIVATE_NPM_TOKEN
        allow_insecure_http: false
        signature: if_present
        provenance: if_present
    # Remaining package fields omitted here; use the annotated example config.

secrets:
  - DATABASE_URL
```

`credential_secret` is a vault reference, not an environment-variable
declaration. It must not also appear in the top-level `secrets` list. The host
resolves the token into the authenticated registry bootstrap, the proxy builds
the upstream bearer header, and debug output redacts the value. The workload
does not receive the token in its environment, launch secret envelope,
filesystem, report, or audit record.

## Verification and inspection

Artifact delivery follows this order:

1. Resolve package identity and versions from bounded upstream metadata.
2. Bind rewritten artifact routes to package, version, source URL, declared
   integrity, and the resolved metadata revision.
3. Download into a private, content-addressed quarantine store through the
   registry-only SOCKS gateway.
4. Verify package identity, the strongest declared npm SRI value, and the
   legacy `dist.shasum` when `allow_legacy_sha1` permits it.
5. Verify advertised npm registry signatures against bounded registry key
   metadata. `signature: required` also rejects packages with no signature.
6. Verify advertised npm provenance offline against the pinned Sigstore trust
   root, including the SLSA subject, Fulcio chain, SCT, DSSE signature, Rekor
   entry, inclusion proof, checkpoint, signed entry timestamp, and integrated
   time. `provenance: required` rejects packages with no provenance.
7. Enumerate gzip/tar content without extracting or executing it. Enforce
   compressed, unpacked, per-entry, entry-count, path, depth, source-scan, and
   time limits.
8. Reject unsafe paths and links, device/FIFO/sparse/unsupported entries,
   unexpected executable bits, native add-ons, prebuilt or embedded
   executables, lifecycle scripts, and high-risk subprocess or shell APIs.
9. Evaluate normalized findings deterministically and either promote the blob
   to the approved cache, deny it, or retain only the configured quarantine
   evidence.

Integrity failures, identity mismatches, signature or provenance failures,
unsupported content, scanner failures, timeouts, decompression excess, and
oversized entries are always fail-closed. Policy rules and exceptions cannot
change those finding kinds to `allow` or `quarantine`.

Static inspection is a policy signal, not proof that arbitrary package code is
safe. SendBox never executes package code during metadata retrieval, download,
cache population, or default analysis.

## Finding policy and false positives

`default_finding_action` applies when a finding has no entry in
`finding_actions`. A `quarantine` verdict withholds artifact bytes just like a
deny verdict but distinguishes packages that require human review.

Use this workflow for a suspected false positive:

1. Run the workload and inspect the denied record with
   `sendbox package report`.
2. Independently verify the package source and the exact `sha256:` or
   `sha512:` artifact digest in the report.
3. Add the smallest exception: one ecosystem, exact package, optional exact
   version, exact artifact digest, and only the reviewed finding kinds.
4. Prefer `quarantine` while investigating. Use `allow` only after review.
5. Re-run the workload. A changed artifact digest, policy digest, scanner
   version, or trust-metadata digest forces new analysis.

Example:

```yaml
policy:
  packages:
    exceptions:
      - ecosystem: npm
        package: reviewed-package
        version: 1.2.3
        artifact_digest: sha512:<lowercase-hex>
        findings:
          - subprocess_api
        action: allow
```

Never create broad package-name-only exceptions. Digest binding prevents a
later release or republished artifact from inheriting an old approval.

## Cache and invalidation

The host mounts a private package cache into the trusted guest services. Cache
keys include:

- ecosystem and verified artifact digest;
- scanner version;
- canonical package-policy digest; and
- trust-metadata digest.

Per-route filesystem locks deduplicate concurrent requests and cross-session
analysis. A policy, scanner, artifact, or trust change therefore misses the old
verdict automatically. Approved blobs are reusable only with an exact key
match. Rejected artifact bytes are deleted by default;
`cache.retain_quarantined` controls whether quarantined bytes are retained.
`cache.enabled: false` forces analysis for every request.

## Reports and CLI

After the workload reaches its terminal response, the host requests the report
once over the authenticated control channel, verifies its digest and canonical
schema, and writes it atomically with mode `0600`:

```text
~/.sendbox/run/sessions/<session-id>/package-security-report.json
```

Each record contains package identity, upstream source, artifact digest,
verification evidence, findings, policy digest, scanner version, verdict,
cache outcome, and requesting session. Secrets are never included.

```bash
# Latest completed package-enabled session
sendbox package status
sendbox package report

# A specific 32-character session ID
sendbox package status --session <session-id> --json
sendbox package report --session <session-id> --json
```

`sendbox run --json` includes a `package_report` summary with the path, digest,
proxy state, record count, and allow/deny/quarantine totals. The host also
records a secret-free `package_security_report_persisted` provenance audit
event. Missing, oversized, non-canonical, symlinked, incorrectly owned, or
digest-mismatched reports fail the package-enabled run.

## Configuration reference

| Key | Purpose |
|---|---|
| `enabled` | Enable the mandatory package proxy for the run |
| `registries` | Allowed upstream registries and evidence requirements |
| `registries[].credential_secret` | Vault reference delivered only to the trusted proxy |
| `signature`, `provenance` | `if_present` verifies advertised evidence; `required` also rejects absence |
| `default_finding_action` | Default `allow`, `deny`, or `quarantine` decision |
| `finding_actions` | Per-finding overrides; fail-closed findings must remain `deny` |
| `exceptions` | Exact digest-bound package exceptions |
| `allow_legacy_sha1` | Permit verification of npm's legacy SHA-1 `dist.shasum` |
| `limits` | Metadata, artifact, archive, scan, timeout, and report bounds |
| `limits.max_report_bytes` | Hard-bounded authenticated report size; maximum 98304 |
| `cache` | Persistent approved-blob and verdict cache controls |

All package-policy structures reject unknown YAML fields.

## Future adapter contract

The core policy engine has no npm metadata dependency. `RegistryAdapter`
separates these ecosystem operations:

- identify the ecosystem and advertised capabilities;
- resolve versions through a bounded `UpstreamClient`;
- rewrite client-facing metadata;
- fetch the selected artifact;
- fetch registry keys, trust roots, and provenance bundles;
- verify artifact integrity, signatures, and provenance through a separate
  `PackageProvenanceVerifier`;
- normalize the package manifest;
- enumerate archive entries or image layers; and
- emit normalized risk findings for the shared verdict engine.

Adapters declare whether they rewrite metadata, support signatures, support
provenance, or handle layered artifacts. The expected extension mapping is:

| Ecosystem | Resolution and metadata | Artifact model | Verification and risk inputs |
|---|---|---|---|
| PyPI | Simple/JSON project and release metadata; rewrite file links | wheel ZIP or source archive | hashes, attestations, `METADATA`, entry and build-script risks |
| Cargo | sparse index/version records; rewrite crate download | `.crate` gzip/tar | index checksum, `Cargo.toml`, build scripts, native/executable content |
| Go modules | module proxy list/info/mod/zip endpoints | module ZIP plus `go.mod` | module checksum database evidence, path rules, generators and executable content |
| Maven | repository metadata and POM resolution | JAR/ZIP and related artifacts | checksums, detached signatures, POM plugins, native/executable content |
| OCI | manifest or index resolution and blob routing | ordered filesystem layers | descriptor digests, signatures/attestations, whiteouts, layer paths and executables |

Future adapters should reuse these contracts rather than add ecosystem logic to
the cache, policy evaluator, report schema, or egress service.
