# Authenticated Host/Guest Protocol

This document defines the protocol invariants implemented by
`sendbox-protocol` and qualified through the Apple and Kata runtime transports.

## Security boundary

Each sandbox session receives a high-entropy bootstrap secret before untrusted
agent code starts. `sendbox-runtime` owns the transport-neutral provisioning and
lifecycle contract; concrete runtime endpoint mappings remain outside this
crate. The secret must be unique per session and available only to the trusted
host and guest bootstrap processes.

The protocol provides mutual session authentication and integrity. It does not
encrypt general payloads. Runtime adapters must provide transport confidentiality
for ordinary confidential messages. Secret values are never placed directly in
frames: `agent.launch` carries XChaCha20-Poly1305 envelopes bound to the session,
guest role, secret name, sequence, expiry, and policy digest.
Long-lived trust roots, release signing, policy signing, and rollback floors are
separate versioned trust domains rather than protocol-session keys.

Apple and Kata bootstrap also carry the session-derived egress runtime policy
and the exact delegated execution cgroup parent. The guest validates both before
starting mandatory services, starts Egress before Exec, and exposes readiness
only after the DNS/SOCKS5 gateway and kernel rules are armed.

## Roles and versions

- `HostClient` initiates the handshake.
- `GuestServer` responds.
- Post-handshake frames explicitly declare `HostToGuest` or `GuestToHost`.
- The current protocol version is `1`.
- Each peer advertises an inclusive supported version range. The negotiated
  version is the highest common version.

Role, version-range, session, nonce, capability, required-capability, and frame
limit fields are authenticated. A reflected role, wrong session, unsupported
range, altered negotiation, or repeated handshake is terminal.

## Canonical wire encoding

Messages use deterministic CBOR encoded by `minicbor`. Wire objects are
fixed-length arrays with fixed field order and numeric discriminants. Maps,
indefinite arrays, duplicate capability identifiers, trailing values, alternate
integer widths, and other noncanonical encodings are rejected by decoding and
canonical re-encoding.

Message kinds are:

1. hello
2. capability negotiation
3. readiness
4. request
5. response
6. event
7. cancellation
8. graceful close
9. protocol error

Capabilities are typed identifiers for lifecycle, exec, streamed I/O, signals,
mounts, network, MCP, audit, health, and Safe Outputs. Authenticated framing
remains version 1. The launch schema is separately versioned by
`OPERATION_SCHEMA_VERSION = 2`: `agent.launch` carries an exact program,
argument vector, absolute working directory, bounded non-secret environment,
policy-bound secret envelopes, and timeout; its terminal response carries
exit/signal or a typed cancellation/failure state plus broker cleanup
completion. Existing frame vectors are unchanged.

Interactive launch schemas are negotiated by operation name rather than by adding a
wire capability. Legacy hosts use `agent.launch.interactive` with the V1 request.
Flow-controlled hosts use `agent.launch.interactive.v2`, whose request also selects
optional stderr separation. A new guest accepts both operations; an old guest rejects
the unknown V2 operation before either peer can exchange V2-only event kinds.

After accepting V2, the guest may emit `TerminalInputCredit` events carrying a
strictly positive credit count no larger than the negotiated 64-chunk window. The
host does not read terminal input until the first grant arrives. `StandardInput`,
`StandardInputEof`, and `TerminalResize` retain their existing discriminants;
`TerminalInputCredit` is appended as event kind 9, so old discriminants and persisted
readers remain stable.

Safe Outputs uses `safe_outputs.collect` schema version 1. The host can request
it only after a terminal result with complete broker cleanup. The guest returns
one bounded base64 artifact and authenticated seal, then rejects duplicate
collection. Requiring Safe Outputs when capability 10 was not negotiated is a
hard downgrade failure. When the capability is required, authenticated
readiness must also include healthy mandatory `exec` and `safe_outputs` service
identities.

## Handshake

1. The host sends a hello containing magic, version range, session ID,
   `HostClient`, a 32-byte operating-system-generated nonce, advertised and
   required capabilities, and its frame limit.
2. The guest validates the hello, selects the highest common version, computes
   the capability intersection, verifies both peers' required capabilities, and
   selects the lower frame limit.
3. The guest sends its version range, selected version, session ID,
   `GuestServer`, both nonces, advertised and required capabilities, negotiated
   capabilities, frame limit, and a negotiation proof.
4. HKDF-SHA256 uses the injected bootstrap secret and a transcript hash as salt.
   Distinct labels derive negotiation, host-to-guest, and guest-to-host
   HMAC-SHA256 keys.
5. The host verifies the negotiation proof using canonical hello bytes and
   canonical negotiation bytes excluding the proof field.
6. The host and guest exchange directional authenticated readiness proofs. No
   application message is accepted before both proofs verify.

The transcript binds both advertised version ranges, both capability sets, both
required-capability sets, both nonces, both roles, the session ID, the selected
version, the negotiated capabilities, and the negotiated frame limit.

## Authenticated frame layout

Each stream frame is:

```text
u32 big-endian CBOR length
CBOR [
  magic,
  version,
  session_id,
  direction,
  sequence,
  message,
  hmac_sha256
]
```

The HMAC covers the canonical unsigned CBOR array containing every field except
the HMAC. The four-byte length prefix is not authenticated; it is validated
before allocation and is bounded independently.

Sequence numbers start at zero and increase strictly by one in each direction.
Replay, gaps, overflow, wrong direction, wrong session, tampering, and
noncanonical frames fail explicitly. A rejected frame never advances receive
state and terminally poisons the connection.

## Limits and backpressure

- Hard frame ceiling: 1 MiB.
- Default frame ceiling: 256 KiB.
- Peers may configure lower limits; the handshake authenticates the lower value.
- The decoder reads only the four-byte prefix before validating the declared
  length. Payload storage is allocated only after validation.
- Receive buffering never exceeds the validated frame plus its prefix.
- Async writes use `write_all` and naturally apply transport backpressure.
- V2 terminal input is additionally bounded to 64 authenticated chunks of at most
  4 KiB each. Credits travel guest-to-host without blocking the guest socket reader,
  and end of file remains outside the credit budget.

Dropping a receive future is resumable because already-read bytes remain in the
bounded reader buffer. Dropping a send future can leave a partial frame on the
stream, so it terminally poisons the local connection instead of allowing an
ambiguous retry.

## Transport abstraction and errors

Handshake and framed APIs operate on `AsyncRead + AsyncWrite`. The crate contains
no runtime adapter and assigns no vsock, Unix-socket, control-socket, or stdio
mapping. In-memory duplex and real Unix-domain socket tests prove the adapter
point on macOS and Linux.

EOF before a frame is distinct from EOF during a frame. Authentication,
canonicalization, negotiation, replay, ordering, sequence exhaustion, frame
limit, and I/O failures are explicit errors. There is no success-shaped fallback
or resynchronization after an invalid authenticated frame.

## Remaining qualification

Before a runtime mapping is accepted, ADR-002 and ADR-005 still require:

- confidentiality and trust-root decisions for that transport;
- live Apple, Kata, and Hyperlight cancellation, streaming, backpressure, and
  lifecycle qualification;
- timeout and resource-exhaustion policy at the adapter/supervisor layer;
- bootstrap-secret provisioning, rotation, rollback prevention, and compromise
  response;
- runtime-specific capability removal when a lifecycle behavior cannot be
  proven.
