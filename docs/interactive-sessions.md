# Interactive terminal sessions

`sendbox run --interactive` runs a workload on a pseudoterminal inside the
sandbox and forwards the current terminal's keystrokes and window size. Terminal
agents such as GitHub Copilot CLI, Claude Code, Codex, and Gemini can therefore
render and accept input normally.

```bash
sendbox run --interactive \
  --config .sendbox.yaml \
  --runtime kata \
  --image registry.example/workload@sha256:<digest> \
  --bundle /usr/local/share/sendbox/guest/x86_64/bundle \
  --trust-root /usr/local/share/sendbox/guest/x86_64/release-public.key \
  -- /usr/bin/copilot
```

Tarball users can point the bundle and trust-root flags at
`guest/<architecture>/` inside the extracted release directory. A bundled
public key is not self-authenticating; trust it only after verifying the host or
standalone guest archive attestation.

## Behavior

Keystrokes ride the same authenticated control channel as workload output, so
they inherit its message authentication, replay protection, and session
binding. No additional port, socket, or privilege is introduced.

The launcher grants a bounded window of 64 input chunks, each at most 4 KiB, and
the CLI stops reading stdin when that credit is exhausted. A workload that
temporarily stops reading therefore applies backpressure instead of losing
pasted bytes.

Standard error remains merged into the controlling terminal by default. Use
`--separate-stderr` when diagnostics need their own stream while remaining a
TTY:

```bash
sendbox run --interactive --separate-stderr \
  --config .sendbox.yaml \
  --runtime kata \
  --image registry.example/workload@sha256:<digest> \
  --bundle /usr/local/share/sendbox/guest/x86_64/bundle \
  --trust-root /usr/local/share/sendbox/guest/x86_64/release-public.key \
  -- /usr/bin/copilot
```

## Requirements and limitations

- Both stdin and stdout must be a terminal and `sendbox` must be in that
  terminal's foreground process group. Otherwise the run fails instead of
  silently falling back to a workload with no input.
- `--interactive` cannot be combined with `--json`; machine-readable output and
  a raw terminal are mutually exclusive.
- Only the `apple` and `kata` runtimes provide a terminal. `hyperlight` rejects
  `--interactive` before anything is created or started.
- `Ctrl-C`, `Ctrl-Z`, and `Ctrl-D` are delivered to the workload's terminal, not
  to `sendbox`. Use the agent's own quit command to end the session.
- The host `TERM` is authoritative for the workload and replaces any configured
  `TERM`.
- Terminal output merges stdout and stderr by default. `--separate-stderr` gives
  file descriptor 2 a second, non-controlling pseudoterminal and reports it as
  stderr. Ordering between stdout and stderr is no longer strict.
- `--separate-stderr` requires `--interactive` and consumes one additional
  pseudoterminal pair per session.
- Interactive input is lossless within a bounded 64 x 4 KiB credit window. End
  of file is outside the credit budget and remains ordered behind preceding
  input.
- Window size changes are tracked through `SIGWINCH` for as long as the run
  lasts.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `--interactive requires a terminal but stdin is not one` | `sendbox` is being piped or run from a job runner | Run it from a terminal, or drop `--interactive` |
| `--interactive requires the foreground process group` | Started with `&` or under a job-control shell in the background | Bring the job to the foreground |
| `the hyperlight runtime cannot provide an interactive terminal` | `--runtime hyperlight` | Use `--runtime apple` or `--runtime kata` |
| `interactive execution needs a controlling terminal, but the command policy denies: ioctl` | `policy.boundaries.syscalls.additional_denylist` blocks terminal syscalls | Remove `ioctl`, `setsid`, `dup2`, and `dup3` from the denylist, or run without `--interactive` |
| The guest rejects `agent.launch.interactive.v2` | The host is using an older guest bundle that predates credit flow control | Install the guest bundle shipped with the same SendBox release |
| Pseudoterminal allocation reports resource exhaustion | Concurrent interactive sessions reached the host PTY limit | Reduce concurrency or inspect `/proc/sys/kernel/pty/max` and `/proc/sys/kernel/pty/nr` |
| stdout and stderr appear out of order | `--separate-stderr` uses independent PTY buffers | Remove `--separate-stderr` for a single strictly ordered terminal stream |
| The agent renders as garbled boxes | The guest image has no terminfo entry for the host `TERM` | Set `TERM=xterm-256color` before running |

See the [interactive terminal architecture](architecture/interactive-terminal.md)
for negotiation, flow-control rules, and qualification evidence.
