# Authenticated Host/Guest Protocol

Status: **pre-1.0 foundation**. This document defines the protocol invariants
implemented by `sendbox-protocol`. Runtime-specific transports and operational
message schemas remain subject to qualification.

## Security boundary

Each sandbox session receives a high-entropy bootstrap secret before untrusted
agent code starts. The runtime-specific provisioning mechanism is outside this
crate. The secret must be unique per session and available only to the trusted
host and guest bootstrap processes.

The protocol provides mutual session authentication and integrity. It does not
encrypt payloads. A runtime adapter must provide a transport whose
confidentiality matches the data it carries, or a future protocol version must
add encryption before secrets or other confidential payloads use that transport.
Long-lived trust roots, release signing, policy signing, and key rotation remain
part of ADR-005 qualification.

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
mounts, network, MCP, audit, and health. Their operational payload schemas are
not frozen by this foundation.

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
