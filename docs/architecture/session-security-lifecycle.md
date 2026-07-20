# Session security lifecycle

`sendbox-session-security` is the adapter-neutral coordination layer between
`sendbox-security`, `sendbox-secrets`, and future host orchestration. It does not
start a runtime, open a credential listener, expose CLI commands, or change guest
controls.

## Lifecycle

`SecuritySession::prepare` runs the security prerequisites in this order:

1. Verify policy and configuration bytes against injected trust stores.
2. Capture the before-state snapshot.
3. Create the session audit chain using the canonical `SessionId` hex value.
4. Validate secret references and produce authenticated, session-bound envelopes.
5. Prepare credential rules and notify an injected bounded listener.
6. Initialize the injected permission supervisor and anchor its generation and
   state hash in the audit chain.

Runtime-independent callers can then record audit events through the thread-safe
`AuditRecorder`. Completion and failure finalization capture the after-state,
compute the snapshot diff, record rollback and cleanup outcomes, and publish the
final audit Merkle root and chain head through an injected signing/publication
hook.

Any failed preparation or finalization stage attempts rollback and cleanup. The
returned error retains the primary, rollback, cleanup, audit, and publication
failures that occurred; failures are not converted into success-shaped results.

## Permission supervisor

The version 1 permission supervisor preserves the Swift categories and risk
classification intent while making decisions replay-safe and deterministic:

- categories: command, network, file write, secret access, and system call;
- one-time, session, and glob-pattern approvals;
- expiry and use limits;
- exact deny-always rules with deny-first precedence;
- prompt budgets, non-interactive denial, and injected approval handlers;
- caller-clock deadline checks without UI or real-time sleeps;
- revocation and bounded decision history.

Canonical JSON state includes the session ID, generation, previous state hash,
current state hash, grants, deny rules, replay set, prompt counters, and history.
Every mutation advances the generation and is emitted through a
`PermissionEventSink`. `AuditPermissionEventSink` records the generation and
state hash in the session audit chain.

The supervisor checkpoint is an external high-water mark. Loading an older
generation, an equivocated state at the same generation, an unlinked next
generation, or a generation jump is rejected. The checkpoint must be stored
outside the supervisor file, normally in the tamper-evident audit publication.

## Migration

Migration inspection is bounded and dry-run-only. Readers cover:

| Source | Verification/report behavior |
|---|---|
| Swift audit entries and Merkle tree | Verifies the legacy hash chain and optional tree |
| Swift snapshot manifest | Validates ordering, paths, hashes, sizes, and permissions |
| Swift provenance trust store | Reports unsigned or zero-threshold policy broadening |
| Swift provenance signature | Validates structure; cryptographic verification still requires caller content and key |
| Secret metadata | Lists record versions without retrieving or rewriting values |
| Swift Codable grants | Observational import reader; no persisted Swift grant store is assumed |

Conversion proposals require an authorization derived from the exact dry-run
report. Permission-broadening proposals also require a separate explicit
acknowledgement. These APIs never write artifacts, migrate secrets, or weaken
permissions automatically.

## Integration status

The lifecycle, grant state machine, versioned persistence, legacy readers, and
test fakes are implemented as Rust library surfaces. Host agent wiring, runtime
adapter calls, CLI commands, MCP integration, credential network listeners, and
guest platform enforcement are intentionally outside this change.
