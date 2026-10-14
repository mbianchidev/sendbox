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
| **SendBox** | Self-managed macOS/Linux hosts. Apple and Kata sessions have a dedicated Linux guest kernel; Hyperlight is a separate one-shot path. | Switching between CLI agents while retaining explicit session controls, scoped integrations, snapshots, and audit records. | You supply virtualization-capable hosts, a tooling image, verified guest artifacts, and operational setup. No hosted service or fleet scheduler. |
| **[Docker Sandboxes](https://docs.docker.com/ai/sandboxes/)** | Local sandboxes use a microVM with a dedicated Linux kernel. Docker also offers cloud sandboxes with separate behavior and lifecycle controls. | An agent-focused sandbox product, including workflows that need a Docker Engine inside the local sandbox. | Compare local versus cloud support, workspace modes, credential handling, network defaults, and where MCP servers execute. |
| **[Dev containers](https://containers.dev/overview)** | A development-environment specification used by local and remote tools. Isolation depends on the backing container/VM runtime and configured mounts. | Sharing reproducible dependencies, editor settings, and development setup across a team. | The specification alone does not provide a per-agent VM or enforce SendBox-style command, network, credential, or MCP policy. |
| **[E2B](https://github.com/e2b-dev/E2B#what-is-e2b)** | API/SDK-driven isolated cloud sandboxes, with a separately documented self-hosting path. | Building applications that provision environments and execute agent-generated code programmatically. | Hosted versus self-hosted operations, environment lifecycle, data placement, network controls, and how to connect your agent tooling. |
| **[Daytona](https://www.daytona.io/docs/)** | An API-first sandbox platform with SDKs, process/filesystem APIs, snapshots, and remote-access tooling. | Programmatically managing agent environments and persistent remote workflows. | Current deployment options, isolation guarantees for that deployment, governance, workspace access, and service dependencies. |

These are workflow comparisons, **not a security ranking or a feature-parity
claim**. Local and hosted variants can have different boundaries. Product
capabilities change; verify the current documentation for your chosen
deployment rather than relying on a product name alone.

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
argv. See [security expectations](../README.md#security-expectations) and the
[security model](security-model.md) before treating any control as a guarantee.

## Sources

The comparison was reviewed against these official sources on October 14, 2026:

- [Docker Sandboxes overview](https://docs.docker.com/ai/sandboxes/) and
  [local isolation layers](https://docs.docker.com/ai/sandboxes/security/isolation/).
- [Dev Container Specification overview](https://containers.dev/overview).
- [E2B project overview, SDK examples, and self-hosting links](https://github.com/e2b-dev/E2B).
- [Daytona project overview and documentation links](https://github.com/daytonaio/daytona).
  That historical public repository now carries a maintenance notice; do not
  assume it represents the supported deployment or licensing of the current
  service. Consult [current product documentation](https://www.daytona.io/docs/).
