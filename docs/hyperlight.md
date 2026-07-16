# Hyperlight

SendBox can execute commands and MCP servers in one-shot
[Hyperlight](https://github.com/hyperlight-dev/hyperlight) micro-VMs through
the official
[`hyperlight-unikraft`](https://github.com/hyperlight-dev/hyperlight-unikraft)
host CLI.

## Requirements

- Linux with readable and writable `/dev/kvm`
- `hyperlight-unikraft` installed on the host
- A Unikraft shell kernel and CPIO rootfs containing every executable needed by
  the command or MCP server

Hyperlight does not support Apple's macOS hypervisor. Use the Apple runtime on
macOS.

## Configuration

```yaml
runtime:
  provider: hyperlight
  hyperlight:
    executable: /usr/local/bin/hyperlight-unikraft
    kernel_path: /opt/hyperlight/shell-kernel
    initrd_path: /opt/hyperlight/shell.cpio
    stack_mb: 8
```

The configured guest application must be a shell because SendBox passes each
approved argv vector to `hyperlight-unikraft --exec`. Arguments are
single-quoted before becoming shell input.

The host executable must be an absolute, root-owned file that is not writable
by group or other users. SendBox launches it with only `PATH=/usr/bin:/bin` and
`LANG=C`; project configuration cannot select a repository-local host program.

The initial runtime command and every `exec` or `mcpExec` argv vector are
evaluated against a command policy before the host process is spawned. Each
execution starts a fresh micro-VM and changes to its staged read-only mount
copies are discarded when that invocation exits. Commands start in the
configured workspace directory.

Hyperlight resolves every network policy entry as a concrete hostname or IP
address. Wildcards such as `*.github.com` are rejected before launch; list each
required hostname explicitly. For default-deny policies, blocked entries take
priority over matching allowed entries.

```yaml
policy:
  boundaries:
    enabled: false
  network:
    default_action: deny
    allowed_domains:
      - github.com
      - api.github.com
      - raw.githubusercontent.com
    blocked_domains: []
    allow_dns: true
```

Network-transport MCP servers use
`HyperlightRuntime.mcpExec(containerId:command:listenPort:policy:)`, which maps
the validated guest listen port to Hyperlight's `--port` option and returns a
`HyperlightMCPSession` process handle. The session exposes `listenPort` and is
stopped with its parent runtime. Include the server and its runtime (for
example, Node.js or Python) in the CPIO rootfs and configure its destinations
in `policy.network.allowed_domains`. Stdio MCP is not supported because
`hyperlight-unikraft` does not forward host stdin into the guest.

## Limitations

- OCI image references and environment-variable injection are not supported by
  `hyperlight-unikraft`; use a purpose-built CPIO rootfs.
- The existing eBPF MCP inspector cannot run in the Unikraft guest.
- The eBPF/seccomp boundary bootstrap is not supported in a Unikraft guest;
  configure `policy.boundaries.enabled: false` when selecting Hyperlight.
- Hyperlight always permits resolver traffic when networking is enabled, so
  SendBox fails closed when a policy combines network access with
  `allow_dns: false`.
- Hyperlight cannot enforce a maximum connection count, so SendBox fails closed
  when networking is enabled and `max_connections` is configured.
- Hyperlight network allow/block entries must be concrete hostnames or IP
  addresses; wildcard domain entries are not supported.
- Hyperlight is selected explicitly; `runtime.provider: auto` continues to use
  Apple Containerization on macOS and Kata Containers on Linux.
