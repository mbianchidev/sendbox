# Package registry proxy architecture

## Purpose

The package registry proxy is a mandatory pre-delivery control for configured
npm registries. It prevents the untrusted workload from receiving package
artifact bytes until a trusted service has verified identity and integrity,
inspected the archive without execution, evaluated package policy, and recorded
a machine-readable verdict.

The implementation is split across existing trust boundaries:

- `sendbox-policy` owns strict package policy, finding actions, exceptions, and
  resource limits.
- `sendbox-registry` owns adapter contracts, npm behavior, verification,
  inspection, deterministic verdicts, cache records, and reports.
- `sendbox-egress` owns the three-cgroup network topology and kernel rules.
- `sendbox-host` resolves isolated registry credentials, mounts private cache
  state, revalidates reports, and persists audit evidence.
- `sendbox-agent`, `sendbox-protocol`, and `sendbox-guest` own authenticated
  bootstrap, service readiness, launch ordering, and terminal report retrieval.

## Process and network topology

```text
untrusted workload cgroup
  |-- HTTP 127.0.0.1:14873 ----------------------+
  |-- SOCKS 127.0.0.1:15080 --> public gateway --+--> policy-approved network
  `-- DNS   127.0.0.1:15053 --> DNS gateway -----+

registry proxy cgroup
  `-- SOCKS 127.0.0.1:15081 --> trusted gateway ----> configured npm upstream

broker cgroup
  `-- only marked external sockets are accepted by nftables
```

The workload can reach the public SOCKS/DNS listeners and npm proxy, but not
the registry-only SOCKS listener. The registry proxy can reach only the trusted
loopback SOCKS listener, not the public listener or any external destination.
Only gateway processes enter the broker cgroup and set the fixed `SO_MARK`;
the registry proxy runs as UID/GID 65532, receives no mark capability, clears
capabilities, and applies a bounded seccomp/resource profile.

When package analysis is enabled, the public gateway uses an effective network
policy with the npm upstream denied. The trusted registry gateway retains the
original policy and is reachable only from the registry cgroup. A compromised
workload therefore cannot bypass the proxy with an npm CLI override or direct
tarball URL, and a compromised proxy cannot dial the network without the
trusted gateway.

The egress instance identifier remains at most 24 lowercase
`[a-z0-9_]` characters. The nftables table is `sbxeg_<instance_id>`, keeping it
within the kernel's 31-character table-name limit.

## Startup and teardown

1. The host validates that package policy has exactly one npm registry, that
   the runtime supports mandatory egress services, and that registry credential
   references do not overlap workload secrets.
2. The host creates or validates the private package cache and includes package
   policy, ports, paths, proxy identity, and zeroizing credentials in the
   encrypted authenticated bootstrap.
3. The guest starts cgroup/nft enforcement before the workload, then starts the
   public gateway, trusted registry gateway, and isolated registry proxy.
4. Readiness requires every mandatory service. Any missing listener, invalid
   policy, credential mismatch, privilege-drop failure, or report path failure
   aborts launch.
5. npm environment variables are fixed to the local proxy and script execution
   is disabled before the exact workload argv starts.
6. After the terminal response, the agent fetches the package report once,
   then performs graceful close and teardown.
7. The host validates and persists the report before marking the security
   session complete.

Early exit of a mandatory process is fatal. Cleanup removes nftables state,
cgroups, runtime credentials, sockets, and rejected quarantine files.

## Request path

Packument requests are fetched through the trusted SOCKS gateway with bounded
metadata size and timeout. The npm adapter validates the response and replaces
each `dist.tarball` with an opaque proxy route. The route maps internally to an
artifact descriptor bound to the resolved package name, version, upstream URL,
integrity claims, signatures, provenance references, and metadata revision.

An artifact request acquires a per-route filesystem lock. A valid exact cache
entry is returned immediately. Otherwise the proxy:

1. downloads to a private quarantine file;
2. computes the content digest and verifies npm integrity claims;
3. fetches and verifies bounded trust metadata and advertised evidence;
4. normalizes `package.json`, enumerates gzip/tar entries, and scans risks;
5. evaluates normalized findings against canonical package policy;
6. atomically writes the verdict record; and
7. promotes only allowed bytes to the approved content-addressed store.

The cache key is the ecosystem, artifact digest, scanner version, canonical
policy digest, and trust-metadata digest. This makes cache invalidation
implicit and reproducible. Filesystem locks allow concurrent requests and
separate sessions to share one completed analysis without trusting a partial
record.

## Authenticated report lifecycle

The registry proxy updates a bounded owner-only report as verdicts complete.
The report is not streamed through workload output.

`package.report` uses authenticated request ID `2` and schema version `1`. It is
legal only after the launch request's terminal response and before graceful
close, and it can succeed only once. The request carries the maximum accepted
byte count. The response carries the exact JSON string and a
`sha256:<lowercase-hex>` digest.

The guest reads the report descriptor-relatively without following symlinks and
requires the expected owner, group, mode `0600`, regular-file type, and link
count. The agent verifies the transport digest. The host then independently
checks the byte limit, digest, strict schema, summary counts, canonical JSON,
session ID, and canonical package-policy digest before atomically persisting
the report under host session state.

This terminal-only retrieval keeps verdict evidence correlated with the
authenticated run while avoiding report races during package installation.

## Adapter boundary

`RegistryAdapter` is capability-oriented rather than npm-shaped. It composes
`UpstreamClient` for bounded, credential-aware retrieval and
`PackageProvenanceVerifier` for ecosystem evidence. It covers identity/version
resolution, metadata rewriting, artifact retrieval, trust metadata, integrity
and provenance verification, manifest normalization, archive/layer
enumeration, and ecosystem risk inspection.

The shared cache, policy evaluator, and report model consume only normalized
identities, evidence, entries, manifests, and findings. PyPI, Cargo, Go
modules, Maven, and OCI adapters can therefore implement different metadata
and artifact models without changing the core decision path. OCI declares
layered artifacts; archive-oriented ecosystems enumerate their native package
containers. The npm adapter is currently the only runtime implementation.
