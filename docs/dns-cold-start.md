# Cold-start DNS diagnostics

This diagnostic measures the first application request in each new Apple VM.
It contains no agent loop, personal credentials, application retry, preceding
lookup, cache priming, or startup sleep. A later successful request is not a
replacement for the first result.

## What the evidence establishes

On 2026-10-20, the installed macOS host and signed aarch64 guest were compared
with the checksum- and GitHub-attestation-verified official 0.2.1 archive:

| Artifact | SHA-256 |
|---|---|
| Host | `0dd8dde709673a4eb5dd890091ec190a1c2b53b4237c6271a2fe23621fc5d9f2` |
| Guest | `5d0fc5c65d042f2b04922eeb7c7a85039fb839adb7d197c8440fd5ab40ca8f21` |

Both the Apple CLI and service reported 0.10.0, commit `6bdb647`. The guest
manifest required host/guest 0.2.1, architecture aarch64 and release sequence 5.

The original missing-first-reply symptom **did not recur in 20 sequential
released-guest VMs**. Every first request reached the API over verified TLS and
received the expected credential-free HTTP 400. This is transport evidence,
not authenticated model access, and not proof that the reported transient has
been resolved.

Header-only captures reconfirmed the selected upstream as `192.168.64.1:53`,
not an assumed historical value. Additional fresh released-guest captures saw
both initial A/AAAA queries leave the guest and matching replies return:
matching IDs, question types, source address and source port. The observed
canonical name was `glb-db52c2cf8be544.github.com`. A separate fresh, non-root,
direct-upstream diagnostic received its first A/AAAA replies in approximately
2.3/23.6 ms.

These observations establish that this path was healthy during those runs.
They do **not** establish an Apple bridge, host DNS proxy, or upstream resolver
defect. Guest-only capture cannot distinguish those external boundaries when
no reply arrives. Do not flush host caches, change the selected resolver, or
restart unrelated services to manufacture a different result.

The deterministic failure boundary is in SendBox's loss handling:

1. Released forwarding sends one UDP datagram per QTYPE.
2. If that query or reply is lost, the resolver times out after three seconds.
   TCP is attempted only after a validated truncated UDP response, not after
   silence.
3. A and AAAA run concurrently, but an error in either fails the combined
   resolution. A completed A result alone cannot authorize a connection.
4. An empty authorization cache therefore produces SOCKS REP `0x04` or HTTP
   CONNECT 502. No address is cached on that failed resolution.
5. A later request performs another resolution and may succeed. That outcome
   does not repair the first request or identify where a packet was lost.

A generated UDP fixture that discards the first datagram reproduced this
failure before the change. The corrected resolver passes the same fixture.
This establishes a SendBox resilience defect consistent with the reported
missing-reply evidence; it does not identify the cause of the original live
packet loss.

## Bounded mitigation

Each A/AAAA query now has one absolute three-second budget covering socket
setup, UDP transmission/receive and any truncated-response TCP fallback.
If the first UDP reply is still missing halfway through that budget, the same
question and ID are sent **once** on the same connected, marked socket to the
same selected upstream. Neither the deadline nor the application request is
restarted. The brokers retain their independent five-second resolution bound.

There is no new public resolver, readiness lookup, sleep, background warm-up,
unsandboxed fallback, or hostname/CNAME/IP grant. Permanent DNS errors, malformed
responses and policy denials are not retried. Both completed family results
still undergo the existing CNAME agreement, address-class, QTYPE, budget and
authorization checks. A TCP response that is still truncated is rejected.

This only mitigates a single missing UDP exchange per QTYPE within the budget.
Persistent loss or a genuinely unavailable resolver still fails closed.
Gateway readiness continues to mean that authenticated local services and
mandatory controls are ready, not that an external DNS server has been probed.

DNS failures produce typed audit metadata with the failure kind, QTYPE,
selected numeric upstream, transport, operation and OS code when available.
Broker-deadline expiry is distinguished from resolver exchange timeout.
HTTP DNS failures remain 502, with `Proxy-Status: sendbox; error=dns_error` and
a bounded JSON diagnostic. Free-form resolver messages, DNS packet contents,
credentials, bootstrap files and gateway control tokens are never included.
SOCKS and native CONNECT reply codes remain compatible.

## Qualification results

The official 0.2.1 host was also used with a separately signed development
guest built from this change. The test trust root was
`dns-cold-test-b5f8686b`, release sequence 6, with matching host/guest version
0.2.1. The guest SHA-256 was
`681105e407d4625d2e19698340c138acd853cc174f346df8afd747cbc0c255f9`.
The unchanged signed-release launcher and BPF object were reused; both
executables passed static ELF verification. The temporary signing seed was
destroyed, and the official installed bundle/key were not replaced.

Each cohort below used sequential, unique-boot VMs. Within each VM there was
no preceding DNS lookup, warm-up, or application retry. Shared host/upstream
caches were not flushed or claimed to be empty. First-request time runs from
opening the loopback proxy through receipt of the unauthenticated API response headers,
including CONNECT and verified TLS; VM boot/cleanup and response bodies are
excluded.

| Guest | Fresh VMs | First failures | Median ms | p95 ms | Maximum ms |
|---|---:|---:|---:|---:|---:|
| Official 0.2.1, no injected loss | 20 | 0 | 596.795 | 706.852 | 732.704 |
| Patched test guest, no injected loss | 20 | 0 | 566.914 | 675.600 | 2136.019 |

All first responses were HTTP 400 after successful SOCKS/HTTP CONNECT and TLS.
Both cohorts passed 40/40 deny checks. Every measured workload was non-root,
with `NoNewPrivs=1`, `Seccomp=2`, and zero effective/permitted/ambient
capabilities. Every cohort reported zero owned VMs remaining, also confirmed
by the final scoped container listing.

The patched per-VM results, including the slowest sample without discarding it:

| VM | Front end | CONNECT ms | First request ms | Result |
|---:|---|---:|---:|---|
| 1 | SOCKS | 123.389 | 549.224 | pass |
| 2 | HTTP | 132.087 | 675.600 | pass |
| 3 | SOCKS | 166.293 | 665.139 | pass |
| 4 | HTTP | 106.548 | 531.070 | pass |
| 5 | SOCKS | 103.443 | 506.896 | pass |
| 6 | HTTP | 105.750 | 518.138 | pass |
| 7 | SOCKS | 109.215 | 523.824 | pass |
| 8 | HTTP | 110.875 | 423.481 | pass |
| 9 | SOCKS | 137.089 | 566.320 | pass |
| 10 | HTTP | 105.425 | 391.788 | pass |
| 11 | SOCKS | 194.434 | 629.375 | pass |
| 12 | HTTP | 212.704 | 648.495 | pass |
| 13 | SOCKS | 108.735 | 569.387 | pass |
| 14 | HTTP | 190.937 | 612.174 | pass |
| 15 | SOCKS | 125.839 | 567.507 | pass |
| 16 | HTTP | 467.981 | 2136.019 | pass |
| 17 | SOCKS | 218.164 | 593.784 | pass |
| 18 | HTTP | 147.900 | 667.463 | pass |
| 19 | SOCKS | 112.161 | 534.874 | pass |
| 20 | HTTP | 104.305 | 529.690 | pass |

The trace observed `eth0` up with carrier, a default route through
`192.168.64.1`, and the original upstream in `/etc/resolv.conf` at approximately
0.38 seconds guest uptime. At the first query, resolver configuration had
changed to `127.0.0.1` while the broker's actual upstream packets still targeted
`192.168.64.1:53`. Link/route readiness is not proof of DNS-server readiness.

Controlled loss was then compared in separate fresh VMs. A test-only guest
input rule dropped the first two upstream replies, one A and one AAAA:

| Guest | Front end | First result | First request ms |
|---|---|---|---:|
| Official 0.2.1 | SOCKS | REP `0x04`, failure | 3004.633 |
| Official 0.2.1 | HTTP | CONNECT 502, failure | 3002.812 |
| Patched test guest | SOCKS | REP `0x00`, TLS, HTTP 400 | 2063.331 |
| Patched test guest | HTTP | CONNECT 200, TLS, HTTP 400 | 2809.843 |

The drop counters verified exactly two lost replies in each experiment.
Patched retransmissions retained each original question, ID and source port,
at approximately 1502 ms after the initial send. There was no retry of the
measured application request. Both patched cold requests passed, and all four
VMs kept both denials and containment checks intact and were deleted.

In the released fault-injection runs, the *later denial check* on API port 444
caused a new resolution around three seconds later, which received replies but
still denied the forbidden port. That later DNS success was not substituted
for the failed first request.

The injected loss boundary was deliberately inside the owned guest, between
interface capture and the resolver socket: the trace can see the replies that
the test rule drops. This is not evidence that the original naturally missing
replies were lost at that boundary. The natural incident's external cause
remains unconfirmed; this delivery fixes and verifies SendBox's identified
single-loss handling, not an established Apple/upstream defect.

## Build the standalone fixture

Use the existing Apple service without restarting or reconfiguring it:

```bash
container build --no-cache --tag sendbox-dns-cold:local \
  test-fixtures/dns-cold-start
DIGEST="$(container image inspect sendbox-dns-cold:local |
  python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["index"]["digest"])')"
container image tag sendbox-dns-cold:local "sendbox-dns-cold@$DIGEST"
```

The image adds Python, certificates and nftables to a digest-pinned Alpine
base. Its Python entry executable is a regular file rather than a symlink.
SendBox still launches the workload non-root with NNP, seccomp and cleared
capabilities. Only a separate diagnostic control exec needs root for passive
capture or the explicit packet-loss fixture.

```bash
python3 scripts/qualify-dns-cold-start.py \
  --bundle /usr/local/share/sendbox/guest/aarch64/bundle \
  --trust-root /usr/local/share/sendbox/guest/aarch64/release-public.key \
  --image "sendbox-dns-cold@$DIGEST" \
  --allowed-cname glb-db52c2cf8be544.github.com \
  --count 20 --trace \
  --output /absolute/path/to/new/cold-dns-results.jsonl
```

Use the exact, explicitly approved canonical hostname observed for your target,
not a wildcard or an automatically accepted alias. The generated fixture policy
permits only that hostname, `api.githubcopilot.com`, and TCP 443. It forwards no
GitHub/Copilot credentials and references no secrets. It is not a modification
of your project's policy.

The runner alternates SOCKS DOMAIN CONNECT and HTTP CONNECT across 20
sequential `sendbox run` invocations. Each VM must report a unique kernel boot
ID. The probe opens only the loopback proxy before the measured request; it
never invokes the OS resolver. After recording that first result, it checks
that `denied.example:443` and the API on port 444 remain denied. Those later
checks cannot turn a failed first request into a pass.

JSONL records include every first-request and CONNECT latency, containment
checks, denials, cleanup status and summary percentiles. A batch header records
the unique owned-VM prefix before launch, including for interrupted batches.
`--trace` captures scoped DNS headers plus numeric resolver, link and route
metadata in the owned VM. It does not delay the workload waiting for capture
and does not retain raw packets. The runner bounds a host invocation
to 120 seconds, allows cancellation cleanup, and targets only its unique VM
names. It never stops the Apple service or touches unrelated containers.

To verify the mitigation against controlled loss, add `--drop-first-replies`.
This opts into an additional nftables table **inside each owned test VM** that
drops exactly the first two upstream UDP replies. Its earlier input hook
cannot bypass the mandatory SendBox filter. The fixture records its drop
counter; a run cannot pass this qualification without verifying two drops and
capturing both initial A/AAAA exchanges.
Use a separate output file and report these runs as fault injection, not as
natural upstream failures.

For patched-guest qualification, rebuild and sign the guest with a separate
test-only key and root-owned bundle/trust-root path, then pass that path and
`--trust-root-id`. Follow the
[guest artifact instructions](architecture/guest-artifact-bundles.md#reproduce-locally).
Do not replace the installed official bundle or trust root. A locally signed
development bundle is not a release attestation.

## Direct-upstream diagnostic

To test the Apple network/upstream path independently of SendBox, without
performing any application or authenticated model request:

```bash
container run --rm --name sendbox-dns-upstream-UNIQUE --user 1000 \
  --entrypoint /usr/local/bin/sendbox-dns-python \
  "sendbox-dns-cold@$DIGEST" /opt/sendbox-dns/probe.py upstream --attempts 1
```

This reads the VM's selected numeric nameserver and sends the measured A/AAAA
questions directly. It is a diagnostic, never a runtime fallback. The optional
`--attempts 2` labels a separate retransmission after the first three-second
receive window; its success must not be reported as first-attempt success.
Only header/question metadata and scoped CNAMEs are emitted, never packet
bytes or response bodies.

## Regression checks

```bash
cargo test --locked -p sendbox-egress --all-targets
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s test-fixtures/dns-cold-start -p 'test_*.py'
```

Paused-clock fixtures cover first-datagram loss, the retry boundary, the
two-send cap, overall deadline, a late successful family with a missing AAAA
reply, TCP fallback/body deadlines, cancellation in UDP and TCP, permanent
errors, failed-resolution cache isolation, broker timeout, cancellation racing
retry, and CNAME denial after retransmission. No test uses personal credentials
or customer data.

Local checks passed on macOS and in the native aarch64 guest build environment,
including 50 repetitions of the 24-case resolver/cold-gateway suite, the
11-test standalone harness suite, dependent guest/MCP/Apple adapter tests,
release build and staged host installation, and dependency audit.
Local host Rust 1.99.1 also reported two pre-existing, untouched warnings:
deprecated `Atomic::fetch_update` in `sendbox-testkit` and an unused `BodyExt`
test import in `sendbox-mcp`. The native guest used the pinned Rust 1.93.1.
