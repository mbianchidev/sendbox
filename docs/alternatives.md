# Choosing an agent sandbox

The right sandbox depends on what you need to isolate and who should operate
it. A reproducible development environment, an interactive agent session, and
an API that executes code for many users solve related but different problems.

SendBox focuses on **CLI agent sessions on a Mac or Linux host you control**,
with a VM boundary and a reviewable policy for workspace access, entry commands,
network destinations, credentials, and MCP tools.

## Options and tradeoffs

| Option | Deployment and isolation model | Good fit | What to evaluate |
|---|---|---|---|
| **[Agent Substrate](https://github.com/agent-substrate/substrate)** | Kubernetes runtime with gVisor or Cloud Hypervisor microVM backends. Actors are stateful workloads multiplexed across worker pools. | Stateful agent fleets, full-state suspend/resume, per-actor identity, and credential injection outside the actor. | You operate Kubernetes and its control plane. gVisor's userspace kernel and a microVM's dedicated guest kernel are different isolation mechanisms. The project is pre-1.0. |
| **[Chainguard Workspaces](https://edu.chainguard.dev/chainguard/workspaces/overview/)** | Remote Linux microVM sessions in Chainguard's cloud, accessed with `chainctl develop`. A local directory is synced, not mounted from the host. | Keeping a terminal workflow while offloading compute, keeping long-lived credentials outside the VM, and parking/resuming the full session. | Currently beta/Technology Preview. Default sessions have public internet access; an egress allowlist requires opening on an appropriately configured check. Service limits and data-use terms apply. |
| **[Docker Sandboxes](https://docs.docker.com/ai/sandboxes/)** | Local sandboxes use a microVM with a dedicated Linux kernel. Docker also offers cloud sandboxes with separate behavior and lifecycle controls. | An agent-focused sandbox product, including workflows that need a Docker Engine inside the local sandbox. | Compare local versus cloud support, workspace modes, credential handling, network defaults, and where MCP servers execute. |
| **[E2B](https://docs.e2b.dev/)** | API/SDK-driven cloud Linux VMs, with a separately documented self-hosting path. | Building applications that provision environments, execute agent-generated code, and pause/resume full sandbox state programmatically. | Hosted versus self-hosted operations, environment lifecycle and limits, data placement, network controls, and how to connect your agent tooling. |
| **[Daytona](https://www.daytona.io/docs/en/sandboxes/)** | An API-first remote sandbox platform. Current documentation distinguishes default Linux container sandboxes from Linux/Windows VM sandboxes and other classes. | Programmatically managing environments with SDKs, process/filesystem APIs, snapshots, and remote-access tooling. | Select the actual sandbox class and deployment before comparing isolation or lifecycle guarantees. VM-specific capabilities are not universal container-sandbox capabilities. |
| **[microsandbox](https://github.com/superradcompany/microsandbox)** | Local hardware-isolated microVMs on Apple-silicon macOS, KVM-enabled Linux, and WHP-enabled Windows. Supports OCI images and CLI/SDK use. | Embedding sandbox execution into an application, local shell workflows, and forking or snapshotting running sandboxes. | Beta software with changing APIs. Compare the controls provided by the runtime with the agent policies and integrations your application would need to supply. |
| **[Dev containers](https://containers.dev/overview)** | A development-environment specification used by local and remote tools. Isolation depends on the backing container/VM runtime and configured mounts. | Sharing reproducible dependencies, editor settings, and development setup across a team. | The specification alone does not provide a per-agent VM or enforce SendBox-style command, network, credential, or MCP policy. |
| **SendBox** | Self-managed macOS/Linux hosts. Apple and Kata sessions have a dedicated Linux guest kernel; Hyperlight is a separate one-shot path. | Switching between CLI agents while retaining explicit session controls, scoped integrations, snapshots, and audit records. | You supply virtualization-capable hosts, a tooling image, verified guest artifacts, and operational setup. No hosted service, Windows runtime, or fleet scheduler. |

These are workflow comparisons, **not a security ranking or a feature-parity
claim**. Local and hosted variants can have different boundaries. Product
capabilities change; verify the current documentation for your chosen
deployment rather than relying on a product name alone.

## Distinctive SendBox built-ins

These two workflows distinguish SendBox's integrated CLI stack in the reviewed
sources. This is a comparison of documented built-ins, not proof that another
project cannot provide equivalent behavior. An undocumented capability is
**unknown**, not unsupported.

| Workflow | What SendBox implements | Related capabilities and limits |
|---|---|---|
| **Pre-delivery npm package gate** | A trusted registry proxy quarantines tarballs, verifies package identity and integrity, enforces configured signature/provenance requirements, and inspects archive content without executing package code. Only an `allow` verdict releases bytes to the workload. Exceptions bind to an exact artifact digest. | The reviewed alternative sources do not establish an equivalent built-in tarball pipeline. Chainguard's product page advertises lockfile verification; that should not be equated with SendBox's static archive inspection. Generic registry access controls or installing a scanner inside a sandbox are also different boundaries. |
| **Post-session GitHub Safe Outputs** | A native partial-conformance gateway records bounded GitHub requests with session/policy provenance. After guest teardown, the host verifies the batch and either persists a preview or applies permitted writes with a host-only token. | This is an integration of the GitHub Agentic Workflows design, not an invention of SendBox. Docker Sandboxes is also a supported runtime for GitHub Agentic Workflows, where a separate Safe Outputs job performs writes. That is a documented alternative when CI orchestration, rather than a local CLI integration, fits your workflow. |

Both controls are disabled by default and supported on Apple/Kata persistent
sessions only. Package inspection is npm-only; other package adapters are not
implemented. Signature/provenance checks default to verifying evidence when
present; use `required` to reject its absence. Static inspection is not proof
that a package is safe. See the [package guide](package-supply-chain.md).

Safe Outputs defaults to staged mode when enabled and supports only a subset
of GitHub.com operations. Apply mode prevalidates the batch but performs remote
writes sequentially, so a later API failure can leave earlier writes applied.
See the [gateway architecture and limitations](architecture/safe-outputs.md).

VM isolation, network policies, external credential injection, MCP support,
snapshots, and audit records are not claimed as SendBox-only features. Agent
Substrate, Chainguard, Docker, and other tools provide overlapping controls.
Some alternatives also offer capabilities SendBox does not: cluster scheduling,
managed compute, durable full-VM resume, Windows environments, or an embedded
sandbox SDK.

## When SendBox is a good fit

Choose SendBox when you want to keep using terminal agents on infrastructure
you manage, avoid granting them broad access to your host environment, and
review their permissions in one configuration.

It is especially relevant when you need the combination of a VM boundary,
explicit model-provider egress, per-server MCP tool rules, registry inspection,
and GitHub workflows without tying the session to one coding agent.

Choose a different approach when your primary need is a managed execution API,
large-scale environment scheduling, or simply a shared development setup. A
cloud sandbox platform can own more infrastructure for you; a devcontainer may
be sufficient when reproducibility, rather than containing untrusted code, is
the main goal.

## Questions to ask before choosing

1. **What is outside the boundary?** Does the workload share a kernel with the
   host or other workloads? Which host files, runtime sockets, and MCP servers
   remain reachable?
2. **What can leave the environment?** Are outbound destinations restricted,
   and what happens when an agent or plugin ignores proxy settings?
3. **Where do credentials live?** Can the agent read them, or does a trusted
   service inject them only for approved upstream requests?
4. **How do changes reach your repository?** Is the workspace shared read/write,
   copied, or synchronized? What must you review before running changed files?
5. **What does failure look like?** Do missing controls stop execution? What
   evidence, cleanup, and rollback are available?
6. **Who operates it?** Who patches the runtime, verifies artifacts, provisions
   compute, and handles concurrency and tenant separation?

For SendBox, the shared workspace is writable, workload secrets are accessible
to the workload, and command policy does not recursively authorize descendant
argv. See [security expectations](../README.md#limitations-and-security-expectations) and the
[security model](security-model.md) before treating any control as a guarantee.

## Sources

The comparison was reviewed against these official sources on October 29, 2026.
It is a documentation review, not a head-to-head benchmark or an exhaustive
audit of every deployment and integration:

- [Agent Substrate README at the reviewed revision](https://github.com/agent-substrate/substrate/blob/eaf0e85c7622d021d833c13e8f8911e2854f9794/README.md),
  including its backends, credential model, actor snapshots, and pre-1.0 status.
- [Chainguard Workspaces overview](https://edu.chainguard.dev/chainguard/workspaces/overview/),
  [session environment and network defaults](https://edu.chainguard.dev/chainguard/workspaces/session-environment/),
  and [Checks/Workspaces security model](https://edu.chainguard.dev/get-started/checks-and-workspaces/how-it-works/).
  Prefer these operational docs over assuming that every feature advertised on
  the [product page](https://www.chainguard.dev/products/workspaces) applies to
  every session configuration.
- [Docker Sandboxes overview](https://docs.docker.com/ai/sandboxes/) and
  [local isolation layers](https://docs.docker.com/ai/sandboxes/security/isolation/),
  including direct-mount and clone workspaces. Docker's
  [GitHub Actions integration walkthrough](https://www.docker.com/blog/running-ai-agents-in-github-actions-with-docker-sandboxes/)
  demonstrates Safe Outputs supplied by GitHub Agentic Workflows.
- [E2B overview](https://docs.e2b.dev/),
  [sandbox lifecycle](https://docs.e2b.dev/sandbox), and
  [project self-hosting section](https://github.com/e2b-dev/E2B#self-hosting).
- [Daytona sandbox classes and lifecycle](https://www.daytona.io/docs/en/sandboxes/).
- [microsandbox README at the reviewed revision](https://github.com/superradcompany/microsandbox/blob/8ff916f38a628390fff21e26339495272f20d782/README.md),
  including CLI/SDK use, platform requirements, snapshots, and beta status.
- [Dev Container Specification overview](https://containers.dev/overview).
- SendBox's [runtime security model](security-model.md),
  [package delivery pipeline](package-supply-chain.md), and
  [Safe Outputs implementation](architecture/safe-outputs.md). The gateway
  documents its partial conformance to the upstream
  [Safe Outputs specification](https://github.github.com/gh-aw/specs/safe-outputs-specification/).
