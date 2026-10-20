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
checks, denials, cleanup status and summary percentiles. `--trace` captures only
scoped DNS headers in the owned VM. It does not delay the workload waiting for
capture and does not retain raw packets. The runner bounds a host invocation
to 120 seconds, allows cancellation cleanup, and targets only its unique VM
names. It never stops the Apple service or touches unrelated containers.

To verify the mitigation against controlled loss, add `--drop-first-replies`.
This opts into an additional nftables table **inside each owned test VM** that
drops exactly the first two upstream UDP replies. Its earlier input hook
cannot bypass the mandatory SendBox filter. The fixture records its drop
counter; a run cannot pass this qualification without verifying two drops.
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
