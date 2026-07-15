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

Each runtime `exec` starts a fresh micro-VM. The command policy is evaluated
before the host process is spawned. The existing `policy.network` allowlist or
blocklist is mapped to Hyperlight's network options. Read-only mounts are
staged in private temporary directories so the guest cannot modify their host
sources.

MCP servers use `HyperlightRuntime.mcpExec`, which returns a
`HyperlightMCPSession` with `send`, `receive`, and `receiveError` methods for
stdio JSON-RPC. The server is stopped with its parent runtime. Include the
server and its runtime (for example, Node.js or Python) in the CPIO rootfs.
HTTP MCP servers additionally need their destinations in
`policy.network.allowed_domains`.

## Limitations

- OCI image references and environment-variable injection are not supported by
  `hyperlight-unikraft`; use a purpose-built CPIO rootfs.
- The existing eBPF MCP inspector cannot run in the Unikraft guest.
- Hyperlight always permits resolver traffic when networking is enabled, so
  SendBox fails closed when a policy combines network access with
  `allow_dns: false`.
- Hyperlight is selected explicitly; `runtime.provider: auto` continues to use
  Apple Containerization on macOS and Kata Containers on Linux.
