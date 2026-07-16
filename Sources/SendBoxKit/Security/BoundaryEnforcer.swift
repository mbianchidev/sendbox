import Foundation

/// Generates the trusted guest components that enforce syscall and MCP boundaries.
public struct BoundaryEnforcer: Sendable {
    public typealias Configuration = PolicyConfiguration.BoundaryPolicyConfig

    public static let rootPath = "/run/sendbox-boundary"
    public static let proxyPath = rootPath + "/mcp-proxy"
    public static let proxyClientSourcePath = rootPath + "/mcp-proxy-client.py"
    public static let proxyDaemonSourcePath = rootPath + "/mcp-proxy-daemon.py"
    public static let proxySocketPath = rootPath + "/mcp-proxy.sock"
    public static let proxyDaemonPIDPath = rootPath + "/mcp-proxy-daemon.pid"
    public static let proxyDaemonPIDPlaceholder = "__SENDBOX_MCP_DAEMON_PID__"
    public static let agentEnvironmentPath = rootPath + "/agent.env"
    public static let launcherPath = rootPath + "/seccomp-launcher"
    public static let launcherSourcePath = rootPath + "/seccomp-launcher.c"
    public static let bpftracePath = rootPath + "/boundary.bt"
    public static let bpftracePIDPath = rootPath + "/boundary.pid"
    public static let readyPath = rootPath + "/ready"
    public static let beginMarker = "SENDBOX_BOUNDARY_BEGIN"
    public static let eventMarker = "SENDBOX_BOUNDARY"
    public static let bpftraceStringLength = 4096

    private let config: Configuration
    private let serverCommandPatterns: [String]
    private let blockedSyscalls: [String]
    private let runAsUID: UInt32
    private let runAsGID: UInt32

    public enum ValidationError: Error, LocalizedError, Equatable {
        case rootUserUnsupported
        case invalidMaxFrameBytes(Int)
        case logPathMustBeAbsolute(String)
        case requiredSyscallDenied(String)
        case invalidServerCommand([String])
        case serverCommandTooLong([String])
        case unrecognizedServerCommand([String])
        case serverCommandArgumentTooLong(String)
        case serverPatternTooLong(String)

        public var errorDescription: String? {
            switch self {
            case .rootUserUnsupported:
                return
                    "Boundary enforcement requires SendBox to be launched by a non-root host user"
            case .invalidMaxFrameBytes(let value):
                return
                    "Boundary tool_calls.max_frame_bytes must be greater than zero (got \(value))"
            case .logPathMustBeAbsolute(let path):
                return "Boundary log_path must be absolute: \(path)"
            case .requiredSyscallDenied(let name):
                return
                    "Boundary syscall denylist cannot include '\(name)' because the launcher requires it"
            case .invalidServerCommand(let command):
                return "Boundary allowed_server_commands entries must start with an absolute, "
                    + "non-shell executable path: \(command.joined(separator: " "))"
            case .serverCommandTooLong(let command):
                return "Boundary allowed_server_commands entries may contain at most 16 "
                    + "arguments: \(command.joined(separator: " "))"
            case .unrecognizedServerCommand(let command):
                return "Boundary allowed_server_commands entry does not match any "
                    + "server_command_patterns value: \(command.joined(separator: " "))"
            case .serverCommandArgumentTooLong(let argument):
                return "Boundary MCP command argument exceeds "
                    + "\(BoundaryEnforcer.bpftraceStringLength - 1) UTF-8 bytes: \(argument)"
            case .serverPatternTooLong(let pattern):
                return "Boundary MCP server pattern exceeds "
                    + "\(BoundaryEnforcer.bpftraceStringLength - 1) UTF-8 bytes: \(pattern)"
            }
        }
    }

    public init(
        config: Configuration,
        serverCommandPatterns: [String],
        runAsUID: UInt32,
        runAsGID: UInt32,
        hardening: ContainerHardening = ContainerHardening(profile: .standard)
    ) {
        self.config = config
        self.serverCommandPatterns =
            serverCommandPatterns.isEmpty
            ? PolicyConfiguration.ToolCallPolicyConfig.defaultServerCommandPatterns
            : serverCommandPatterns
        self.blockedSyscalls = Array(
            Set(
                hardening.blockedSyscalls() + config.syscalls.additionalDenylist
            )
        ).sorted()
        self.runAsUID = runAsUID
        self.runAsGID = runAsGID
    }

    public func validate() throws {
        guard runAsUID != 0 else {
            throw ValidationError.rootUserUnsupported
        }
        guard config.toolCalls.maxFrameBytes > 0 else {
            throw ValidationError.invalidMaxFrameBytes(config.toolCalls.maxFrameBytes)
        }
        guard config.logPath.hasPrefix("/") else {
            throw ValidationError.logPathMustBeAbsolute(config.logPath)
        }

        let required = Set(["execve", "exit", "exit_group", "rt_sigreturn"])
        if let denied = blockedSyscalls.first(where: required.contains) {
            throw ValidationError.requiredSyscallDenied(denied)
        }

        for pattern in serverCommandPatterns
        where pattern.utf8.count >= Self.bpftraceStringLength {
            throw ValidationError.serverPatternTooLong(pattern)
        }

        let forbiddenExecutables = Set([
            "sh", "bash", "zsh", "fish", "env",
            "npx", "npm", "pnpm", "yarn", "bunx", "pipx", "uvx",
        ])
        for command in config.toolCalls.allowedServerCommands {
            guard let executable = command.first, executable.hasPrefix("/"),
                !forbiddenExecutables.contains(
                    URL(fileURLWithPath: executable).lastPathComponent
                )
            else {
                throw ValidationError.invalidServerCommand(command)
            }
            guard command.count <= 16 else {
                throw ValidationError.serverCommandTooLong(command)
            }
            if let argument = command.first(where: {
                $0.utf8.count >= Self.bpftraceStringLength
            }) {
                throw ValidationError.serverCommandArgumentTooLong(argument)
            }
            guard
                command.dropFirst().contains(where: { argument in
                    serverCommandPatterns.contains(where: { pattern in
                        argument.contains(pattern)
                    })
                })
            else {
                throw ValidationError.unrecognizedServerCommand(command)
            }
        }
    }

    public var execPrefix: [String] {
        [Self.launcherPath, "--"]
    }

    public func proxyCommand(for serverCommand: [String]) -> [String] {
        [Self.proxyPath, "--"] + serverCommand
    }

    public static func bootstrapEnvironment(
        agentEnvironment: [String: String],
        workingDirectory: String
    ) -> [String: String] {
        var finalEnvironment = agentEnvironment
        finalEnvironment["HOME"] = "/home/sendbox"
        finalEnvironment["SENDBOX_MCP_PROXY"] = Self.proxyPath
        finalEnvironment["SENDBOX_WORKING_DIRECTORY"] = workingDirectory

        let encoded = (try? JSONEncoder().encode(finalEnvironment)) ?? Data("{}".utf8)
        return [
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/root",
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8",
            "SENDBOX_AGENT_ENV_B64": encoded.base64EncodedString(),
            "SENDBOX_WORKING_DIRECTORY": workingDirectory,
        ]
    }

    public func generateProxyScript() -> String {
        let allowlist = jsonLiteral(config.toolCalls.allowlist)
        let denylist = jsonLiteral(config.toolCalls.denylist)
        let allowedServerCommands = jsonLiteral(config.toolCalls.allowedServerCommands)
        let defaultAction = config.toolCalls.defaultAction.rawValue
        let maxFrameBytes = max(1, config.toolCalls.maxFrameBytes)

        return #"""
            import fnmatch
            import json
            import os
            import socket
            import subprocess
            import sys
            import threading

            ALLOWLIST = \#(allowlist)
            DENYLIST = \#(denylist)
            ALLOWED_SERVER_COMMANDS = \#(allowedServerCommands)
            DEFAULT_ACTION = "\#(defaultAction)"
            MAX_FRAME_BYTES = \#(maxFrameBytes)
            DENIED_CODE = -32001
            SOCKET_PATH = "\#(Self.proxySocketPath)"
            PID_PATH = "\#(Self.proxyDaemonPIDPath)"
            LAUNCHER_PATH = "\#(Self.launcherPath)"
            RUN_AS_GID = \#(runAsGID)
            WORKING_DIRECTORY = os.environ.get("SENDBOX_WORKING_DIRECTORY", "/")


            def log(message):
                sys.stderr.write(f"[sendbox-mcp-daemon] {message}\n")
                sys.stderr.flush()


            def is_allowed(tool):
                for pattern in DENYLIST:
                    if fnmatch.fnmatchcase(tool, pattern):
                        return False, f"Tool '{tool}' matches deny pattern '{pattern}'"
                for pattern in ALLOWLIST:
                    if fnmatch.fnmatchcase(tool, pattern):
                        return True, ""
                if DEFAULT_ACTION == "allow":
                    return True, ""
                return False, f"Tool '{tool}' is not in the allowlist"


            def denial_response(request_id, tool, reason):
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": DENIED_CODE,
                        "message": "Tool call denied by SendBox boundary policy",
                        "data": {"tool": tool, "reason": reason},
                    },
                }


            def handle_connection(connection):
                server = None
                ready = False
                reader = connection.makefile("rb", buffering=0)
                write_lock = threading.Lock()

                def send(data):
                    with write_lock:
                        connection.sendall(data)

                def pump_server_stdout():
                    try:
                        while True:
                            data = server.stdout.read(65536)
                            if not data:
                                break
                            send(data)
                    except (BrokenPipeError, ConnectionError, OSError):
                        pass

                try:
                    handshake = reader.readline(65537)
                    if not handshake or len(handshake) > 65536 or not handshake.endswith(b"\n"):
                        raise RuntimeError("invalid MCP proxy handshake")
                    request = json.loads(handshake)
                    command = request.get("command")
                    if not isinstance(command, list) or not all(
                        isinstance(argument, str) for argument in command
                    ):
                        raise RuntimeError("invalid MCP server command")
                    if command not in ALLOWED_SERVER_COMMANDS:
                        raise RuntimeError("MCP server command is not in allowed_server_commands")

                    server = subprocess.Popen(
                        [LAUNCHER_PATH, "--"] + command,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=None,
                        bufsize=0,
                        close_fds=True,
                        cwd=WORKING_DIRECTORY,
                    )
                    send(b"SENDBOX_MCP_READY\n")
                    ready = True
                    output_thread = threading.Thread(target=pump_server_stdout, daemon=True)
                    output_thread.start()

                    while True:
                        frame = reader.readline(MAX_FRAME_BYTES + 1)
                        if not frame:
                            break
                        if len(frame) > MAX_FRAME_BYTES or not frame.endswith(b"\n"):
                            raise RuntimeError(
                                f"MCP frame exceeds {MAX_FRAME_BYTES} bytes or is incomplete"
                            )

                        try:
                            message = json.loads(frame)
                        except (UnicodeDecodeError, json.JSONDecodeError) as error:
                            raise RuntimeError(f"invalid MCP JSON-RPC frame: {error}") from error

                        if message.get("jsonrpc") != "2.0":
                            raise RuntimeError("invalid MCP JSON-RPC version")

                        if message.get("method") == "tools/call":
                            params = message.get("params")
                            tool = params.get("name") if isinstance(params, dict) else None
                            if not isinstance(tool, str) or not tool:
                                raise RuntimeError("MCP tools/call request is missing params.name")
                            allowed, reason = is_allowed(tool)
                            if not allowed:
                                log(reason)
                                if "id" in message and message["id"] is not None:
                                    response = denial_response(message["id"], tool, reason)
                                    send(
                                        json.dumps(response, separators=(",", ":")).encode() + b"\n"
                                    )
                                continue

                        server.stdin.write(frame)
                        server.stdin.flush()
                except (
                    BrokenPipeError,
                    ConnectionError,
                    json.JSONDecodeError,
                    OSError,
                    RuntimeError,
                ) as error:
                    log(str(error))
                    if not ready:
                        try:
                            message = str(error).replace("\n", " ").replace("\t", " ")
                            send(f"SENDBOX_MCP_ERROR\t{message}\n".encode())
                        except (BrokenPipeError, ConnectionError, OSError):
                            pass
                finally:
                    if server is not None:
                        if server.stdin:
                            server.stdin.close()
                        try:
                            server.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            server.terminate()
                            server.wait(timeout=2)
                    reader.close()
                    connection.close()


            def daemonize():
                first_child = os.fork()
                if first_child > 0:
                    os._exit(0)
                os.setsid()
                second_child = os.fork()
                if second_child > 0:
                    os._exit(0)
                with open(PID_PATH, "w", encoding="ascii") as pid_file:
                    pid_file.write(str(os.getpid()))


            def main():
                daemonize()
                if os.path.exists(SOCKET_PATH):
                    os.unlink(SOCKET_PATH)

                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(SOCKET_PATH)
                os.chown(SOCKET_PATH, 0, RUN_AS_GID)
                os.chmod(SOCKET_PATH, 0o660)
                listener.listen(64)
                log("SENDBOX_MCP_DAEMON_READY")

                while True:
                    connection, _ = listener.accept()
                    threading.Thread(
                        target=handle_connection,
                        args=(connection,),
                        daemon=True,
                    ).start()


            main()
            """#
    }

    public func generateProxyClientScript() -> String {
        return #"""
            import json
            import socket
            import sys
            import threading

            SOCKET_PATH = "\#(Self.proxySocketPath)"


            def log(message):
                sys.stderr.write(f"[sendbox-mcp-proxy] {message}\n")
                sys.stderr.flush()


            def pump_output(reader):
                try:
                    while True:
                        data = reader.read(65536)
                        if not data:
                            break
                        sys.stdout.buffer.write(data)
                        sys.stdout.buffer.flush()
                except (ConnectionError, OSError):
                    pass


            def main():
                if "--" not in sys.argv:
                    log("usage: mcp-proxy -- <stdio-server> [args...]")
                    return 64
                separator = sys.argv.index("--")
                command = sys.argv[separator + 1:]
                if not command:
                    log("missing MCP server command")
                    return 64

                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                reader = None
                try:
                    connection.connect(SOCKET_PATH)
                    handshake = json.dumps(
                        {"command": command},
                        separators=(",", ":"),
                    ).encode() + b"\n"
                    connection.sendall(handshake)

                    reader = connection.makefile("rb", buffering=0)
                    ready = reader.readline(65537)
                    if ready != b"SENDBOX_MCP_READY\n":
                        message = ready.decode(errors="replace").strip()
                        log(message or "MCP policy daemon rejected the server command")
                        return 126

                    output_thread = threading.Thread(
                        target=pump_output,
                        args=(reader,),
                        daemon=True,
                    )
                    output_thread.start()

                    while True:
                        data = sys.stdin.buffer.read(65536)
                        if not data:
                            break
                        connection.sendall(data)
                    connection.shutdown(socket.SHUT_WR)
                    output_thread.join()
                    return 0
                except (BrokenPipeError, ConnectionError, OSError) as error:
                    log(str(error))
                    return 126
                finally:
                    if reader is not None:
                        reader.close()
                    connection.close()


            if __name__ == "__main__":
                raise SystemExit(main())
            """#
    }

    public func generateSeccompLauncherSource() -> String {
        let entries =
            blockedSyscalls
            .map { "    \"\(cEscape($0))\"," }
            .joined(separator: "\n")
        let logBlocked = config.syscalls.logBlocked ? "1" : "0"

        return #"""
            #define _GNU_SOURCE
            #include <errno.h>
            #include <grp.h>
            #include <seccomp.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>
            #include <sys/prctl.h>
            #include <sys/types.h>
            #include <unistd.h>

            extern int clearenv(void);

            static const char *blocked_syscalls[] = {
            \#(entries)
            };

            static const char *agent_environment_path = "\#(Self.agentEnvironmentPath)";

            static void fail(const char *message) {
                fprintf(stderr, "[sendbox-boundary] %s: %s\n", message, strerror(errno));
                exit(126);
            }

            static void load_agent_environment(void) {
                FILE *file = fopen(agent_environment_path, "rb");
                if (file == NULL) {
                    fail("failed to open agent environment");
                }
                if (fseek(file, 0, SEEK_END) != 0) {
                    fclose(file);
                    fail("failed to seek agent environment");
                }
                long length = ftell(file);
                if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
                    fclose(file);
                    fail("failed to size agent environment");
                }

                char *buffer = calloc((size_t)length + 1, 1);
                if (buffer == NULL) {
                    fclose(file);
                    errno = ENOMEM;
                    fail("failed to allocate agent environment");
                }
                if (length > 0 && fread(buffer, 1, (size_t)length, file) != (size_t)length) {
                    free(buffer);
                    fclose(file);
                    fail("failed to read agent environment");
                }
                fclose(file);

                if (clearenv() != 0) {
                    free(buffer);
                    fail("failed to clear bootstrap environment");
                }

                char *cursor = buffer;
                char *end = buffer + length;
                while (cursor < end) {
                    size_t entry_length = strlen(cursor);
                    if (entry_length == 0 || cursor + entry_length >= end) {
                        free(buffer);
                        errno = EINVAL;
                        fail("invalid agent environment entry");
                    }
                    char *entry = strdup(cursor);
                    if (entry == NULL || putenv(entry) != 0) {
                        free(entry);
                        free(buffer);
                        fail("failed to restore agent environment");
                    }
                    cursor += entry_length + 1;
                }
                free(buffer);
            }

            int main(int argc, char **argv) {
                if (argc < 3 || strcmp(argv[1], "--") != 0) {
                    fprintf(stderr, "usage: seccomp-launcher -- <command> [args...]\n");
                    return 64;
                }

                uid_t target_uid = (uid_t)\#(runAsUID);
                gid_t target_gid = (gid_t)\#(runAsGID);
                load_agent_environment();
                if (geteuid() == 0) {
                    if (setgroups(0, NULL) != 0) {
                        fail("failed to clear supplementary groups");
                    }
                    if (setgid(target_gid) != 0) {
                        fail("failed to drop group privileges");
                    }
                    if (setuid(target_uid) != 0) {
                        fail("failed to drop user privileges");
                    }
                } else if (geteuid() != target_uid || getegid() != target_gid) {
                    errno = EPERM;
                    fail("launcher invoked by an unexpected user");
                }

                if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
                    fail("failed to set no_new_privs");
                }

                scmp_filter_ctx context = seccomp_init(SCMP_ACT_ALLOW);
                if (context == NULL) {
                    errno = ENOMEM;
                    fail("failed to initialize seccomp");
                }

                if (\#(logBlocked) && seccomp_attr_set(context, SCMP_FLTATR_CTL_LOG, 1) != 0) {
                    seccomp_release(context);
                    fail("failed to enable seccomp logging");
                }

                size_t count = sizeof(blocked_syscalls) / sizeof(blocked_syscalls[0]);
                for (size_t index = 0; index < count; index++) {
                    int syscall_number = seccomp_syscall_resolve_name(blocked_syscalls[index]);
                    if (syscall_number == __NR_SCMP_ERROR) {
                        fprintf(
                            stderr,
                            "[sendbox-boundary] unknown syscall in policy: %s\n",
                            blocked_syscalls[index]
                        );
                        seccomp_release(context);
                        return 126;
                    }
                    if (seccomp_rule_add(
                            context,
                            SCMP_ACT_ERRNO(EPERM),
                            syscall_number,
                            0
                        ) != 0) {
                        fprintf(
                            stderr,
                            "[sendbox-boundary] failed to add syscall rule: %s\n",
                            blocked_syscalls[index]
                        );
                        seccomp_release(context);
                        return 126;
                    }
                }

                if (seccomp_load(context) != 0) {
                    seccomp_release(context);
                    fail("failed to load seccomp policy");
                }
                seccomp_release(context);

                execvp(argv[2], &argv[2]);
                fail("failed to execute command");
                return 126;
            }
            """#
    }

    public func generateBpftraceProgram() -> String {
        let maximumCommandCount =
            config.toolCalls.allowedServerCommands
            .map(\.count)
            .max() ?? 0
        let argumentCount = max(8, maximumCommandCount + 1)
        let argumentVariables = (0..<argumentCount).map { "$a\($0)" }
        let argumentDeclarations = argumentVariables.enumerated()
            .map { index, variable in
                "    \(variable) = str(args->argv[\(index)]);"
            }
            .joined(separator: "\n")
        let serverPredicate = argvPredicate(
            patterns: serverCommandPatterns,
            variables: ["$filename"] + argumentVariables
        )
        let allowedCommandPredicate = exactAllowedCommandPredicate(
            argumentVariables: argumentVariables
        )
        let mcpServerPredicate = "(\(serverPredicate)) || (\(allowedCommandPredicate))"
        let syscallPredicate =
            blockedSyscalls
            .map { "probe == \"tracepoint:syscalls:sys_enter_\(bpfEscape($0))\"" }
            .joined(separator: " ||\n        ")

        return #"""
            #!/usr/bin/env bpftrace

            BEGIN {
                printf("\#(Self.beginMarker)\t%lld\n", nsecs);
            }

            tracepoint:sched:sched_process_fork /pid == \#(Self.proxyDaemonPIDPlaceholder)/ {
                @trusted[args->child_pid] = 1;
            }

            tracepoint:syscalls:sys_enter_execve {
                $filename = str(args->filename);
            \#(argumentDeclarations)

                if ((\#(mcpServerPredicate)) && !@trusted[pid]) {
                    printf(
                        "\#(Self.eventMarker)\t%lld\t%d\t%d\t%s\tmcp_proxy_bypass\t%s %s %s\n",
                        nsecs,
                        pid,
                        ppid,
                        comm,
                        $a0,
                        $a1,
                        $a2
                    );
                    signal("SIGKILL");
                }
            }

            tracepoint:syscalls:sys_enter_* {
                if (uid == \#(runAsUID) && (
                    \#(syscallPredicate)
                )) {
                    printf(
                        "\#(Self.eventMarker)\t%lld\t%d\t%d\t%s\tsyscall_denied\t%s\n",
                        nsecs,
                        pid,
                        ppid,
                        comm,
                        probe
                    );
                }
            }

            tracepoint:sched:sched_process_exit {
                delete(@trusted[args->pid]);
            }

            END {
                clear(@trusted);
            }
            """#
    }

    public func generateBootstrapScript(
        command: [String],
        preflightScripts: [String] = []
    ) -> String {
        let logDirectory = (config.logPath as NSString).deletingLastPathComponent
        let commandLine = ([Self.launcherPath, "--"] + command)
            .map(ShellEscaping.quote)
            .joined(separator: " ")

        var lines: [String] = [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "umask 077",
            "",
            "log() { echo \"[sendbox-boundary] $*\" >&2; }",
            "fail() { log \"ERROR: $*\"; exit 126; }",
            "",
            "[ \"$(id -u)\" = \"0\" ] || fail 'boundary bootstrap must run as root'",
            "[ -w /proc/sys/kernel/yama/ptrace_scope ] "
                + "|| fail 'Yama ptrace_scope is required'",
            "printf '2\\n' > /proc/sys/kernel/yama/ptrace_scope "
                + "|| fail 'failed to enforce Yama ptrace_scope=2'",
            "[ \"$(cat /proc/sys/kernel/yama/ptrace_scope)\" = \"2\" ] "
                + "|| fail 'Yama ptrace_scope verification failed'",
            "mkdir -p \(ShellEscaping.quote(Self.rootPath))",
            "chmod 0755 \(ShellEscaping.quote(Self.rootPath))",
            "",
            "command -v python3 >/dev/null 2>&1 || fail 'python3 unavailable'",
            "command -v bpftrace >/dev/null 2>&1 || fail 'bpftrace unavailable'",
            "command -v cc >/dev/null 2>&1 || fail 'C compiler unavailable'",
            "[ -f /usr/include/seccomp.h ] || fail 'libseccomp headers unavailable'",
            "",
            "cat > \(ShellEscaping.quote(Self.proxyDaemonSourcePath)) << 'SENDBOX_MCP_DAEMON'",
            generateProxyScript().trimmingCharacters(in: .newlines),
            "SENDBOX_MCP_DAEMON",
            "chmod 0400 \(ShellEscaping.quote(Self.proxyDaemonSourcePath))",
            "cat > \(ShellEscaping.quote(Self.proxyClientSourcePath)) << 'SENDBOX_MCP_CLIENT'",
            generateProxyClientScript().trimmingCharacters(in: .newlines),
            "SENDBOX_MCP_CLIENT",
            "chmod 0444 \(ShellEscaping.quote(Self.proxyClientSourcePath))",
            "PYTHON_BIN=\"$(command -v python3)\"",
            "printf '%s\\0%s\\0' "
                + "\(ShellEscaping.quote("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")) "
                + "\(ShellEscaping.quote("HOME=/home/sendbox")) "
                + "> \(ShellEscaping.quote(Self.agentEnvironmentPath))",
            "chmod 0400 \(ShellEscaping.quote(Self.agentEnvironmentPath))",
            "cat > \(ShellEscaping.quote(Self.proxyPath)) << SENDBOX_MCP_WRAPPER",
            "#!/bin/sh",
            "exec \"$PYTHON_BIN\" -I -B \(ShellEscaping.quote(Self.proxyClientSourcePath)) \"\\$@\"",
            "SENDBOX_MCP_WRAPPER",
            "chmod 0555 \(ShellEscaping.quote(Self.proxyPath))",
            "",
            "cat > \(ShellEscaping.quote(Self.launcherSourcePath)) << 'SENDBOX_SECCOMP_SOURCE'",
            generateSeccompLauncherSource().trimmingCharacters(in: .newlines),
            "SENDBOX_SECCOMP_SOURCE",
            "SECCOMP_FLAGS=\"$(pkg-config --cflags --libs libseccomp 2>/dev/null || echo -lseccomp)\"",
            "cc -O2 -std=c11 -Wall -Wextra -Werror "
                + "\(ShellEscaping.quote(Self.launcherSourcePath)) "
                + "-o \(ShellEscaping.quote(Self.launcherPath)) $SECCOMP_FLAGS",
            "chmod 0555 \(ShellEscaping.quote(Self.launcherPath))",
            "\(ShellEscaping.quote(Self.launcherPath)) -- /bin/true "
                + "|| fail 'seccomp launcher self-test failed'",
            "",
            "mkdir -p \(ShellEscaping.quote(logDirectory))",
            "touch \(ShellEscaping.quote(config.logPath))",
            "chmod 0600 \(ShellEscaping.quote(config.logPath))",
            "install -d -m 0700 -o \(runAsUID) -g \(runAsGID) /home/sendbox",
            "export HOME=/home/sendbox",
            "export SENDBOX_MCP_PROXY=\(Self.proxyPath)",
            "",
            "rm -f \(ShellEscaping.quote(Self.proxyDaemonPIDPath)) "
                + "\(ShellEscaping.quote(Self.proxySocketPath))",
            "\"$PYTHON_BIN\" -I -B \(ShellEscaping.quote(Self.proxyDaemonSourcePath)) "
                + ">> \(ShellEscaping.quote(config.logPath)) 2>&1",
            "attempt=0",
            "while [ \"$attempt\" -lt 50 ]; do",
            "    [ -s \(ShellEscaping.quote(Self.proxyDaemonPIDPath)) ] "
                + "&& [ -S \(ShellEscaping.quote(Self.proxySocketPath)) ] "
                + "&& grep -q 'SENDBOX_MCP_DAEMON_READY' "
                + "\(ShellEscaping.quote(config.logPath)) && break",
            "    attempt=$((attempt + 1))",
            "    sleep 0.1",
            "done",
            "[ -s \(ShellEscaping.quote(Self.proxyDaemonPIDPath)) ] "
                + "|| fail 'MCP policy daemon did not publish its PID'",
            "proxy_daemon_pid=\"$(cat \(ShellEscaping.quote(Self.proxyDaemonPIDPath)))\"",
            "kill -0 \"$proxy_daemon_pid\" 2>/dev/null "
                + "|| fail 'MCP policy daemon exited during startup'",
            "[ -S \(ShellEscaping.quote(Self.proxySocketPath)) ] "
                + "|| fail 'MCP policy daemon did not create its socket'",
            "grep -q 'SENDBOX_MCP_DAEMON_READY' \(ShellEscaping.quote(config.logPath)) "
                + "|| fail 'MCP policy daemon did not become ready'",
            "",
            "cat > \(ShellEscaping.quote(Self.bpftracePath)) << 'SENDBOX_BOUNDARY_BPF'",
            generateBpftraceProgram().trimmingCharacters(in: .newlines),
            "SENDBOX_BOUNDARY_BPF",
            "sed -i \"s/\(Self.proxyDaemonPIDPlaceholder)/${proxy_daemon_pid}/g\" "
                + "\(ShellEscaping.quote(Self.bpftracePath))",
            "chmod 0400 \(ShellEscaping.quote(Self.bpftracePath))",
            "export BPFTRACE_STRLEN=\(Self.bpftraceStringLength)",
            "nohup bpftrace --unsafe \(ShellEscaping.quote(Self.bpftracePath)) "
                + ">> \(ShellEscaping.quote(config.logPath)) 2>&1 &",
            "boundary_pid=$!",
            "echo \"$boundary_pid\" > \(ShellEscaping.quote(Self.bpftracePIDPath))",
            "attempt=0",
            "while [ \"$attempt\" -lt 50 ]; do",
            "    grep -q \(ShellEscaping.quote(Self.beginMarker)) "
                + "\(ShellEscaping.quote(config.logPath)) && break",
            "    kill -0 \"$boundary_pid\" 2>/dev/null "
                + "|| fail 'eBPF boundary process exited during startup'",
            "    attempt=$((attempt + 1))",
            "    sleep 0.1",
            "done",
            "grep -q \(ShellEscaping.quote(Self.beginMarker)) "
                + "\(ShellEscaping.quote(config.logPath)) "
                + "|| fail 'eBPF boundary did not become ready'",
            "",
        ]

        for (index, script) in preflightScripts.enumerated() where !script.isEmpty {
            let path = "\(Self.rootPath)/preflight-\(index).sh"
            let delimiter = "SENDBOX_PREFLIGHT_\(index)"
            lines.append("cat > \(ShellEscaping.quote(path)) << '\(delimiter)'")
            lines.append(script.trimmingCharacters(in: .newlines))
            lines.append(delimiter)
            lines.append("chmod 0700 \(ShellEscaping.quote(path))")
            lines.append("/bin/bash \(ShellEscaping.quote(path))")
            lines.append("")
        }

        lines.append(contentsOf: [
            "\"$PYTHON_BIN\" -I -B - \(ShellEscaping.quote(Self.agentEnvironmentPath)) "
                + "<< 'SENDBOX_AGENT_ENV'",
            "import base64",
            "import json",
            "import os",
            "import sys",
            "",
            "encoded = os.environ.get(\"SENDBOX_AGENT_ENV_B64\")",
            "if not encoded:",
            "    raise SystemExit(\"missing SENDBOX_AGENT_ENV_B64\")",
            "values = json.loads(base64.b64decode(encoded, validate=True))",
            "if not isinstance(values, dict):",
            "    raise SystemExit(\"invalid agent environment\")",
            "with open(sys.argv[1], \"wb\") as output:",
            "    for key, value in values.items():",
            "        if not isinstance(key, str) or not isinstance(value, str):",
            "            raise SystemExit(\"invalid agent environment entry\")",
            "        entry = f\"{key}={value}\".encode()",
            "        if b\"\\0\" in entry:",
            "            raise SystemExit(\"NUL in agent environment\")",
            "        output.write(entry + b\"\\0\")",
            "SENDBOX_AGENT_ENV",
            "unset SENDBOX_AGENT_ENV_B64",
            "chmod 0400 \(ShellEscaping.quote(Self.agentEnvironmentPath))",
            "",
        ])

        lines.append(contentsOf: [
            "touch \(ShellEscaping.quote(Self.readyPath))",
            "chmod 0444 \(ShellEscaping.quote(Self.readyPath))",
            "log 'boundary enforcement ready'",
            "exec \(commandLine)",
            "",
        ])

        return lines.joined(separator: "\n")
    }

    private func argvPredicate(patterns: [String], variables: [String]) -> String {
        return patterns.flatMap { pattern in
            variables.map { variable in
                "strcontains(\(variable), \"\(bpfEscape(pattern))\")"
            }
        }.joined(separator: " ||\n        ")
    }

    private func exactAllowedCommandPredicate(
        argumentVariables: [String]
    ) -> String {
        guard !config.toolCalls.allowedServerCommands.isEmpty else {
            return "0"
        }

        return config.toolCalls.allowedServerCommands.map { command in
            var clauses = [
                "$filename == \"\(bpfEscape(command[0]))\""
            ]
            for (index, argument) in command.enumerated() {
                clauses.append(
                    "\(argumentVariables[index]) == \"\(bpfEscape(argument))\""
                )
            }
            clauses.append("\(argumentVariables[command.count]) == \"\"")
            return "(" + clauses.joined(separator: " && ") + ")"
        }.joined(separator: " ||\n        ")
    }

    private func jsonLiteral<T: Encodable>(_ value: T) -> String {
        let data = (try? JSONEncoder().encode(value)) ?? Data("[]".utf8)
        return (String(data: data, encoding: .utf8) ?? "[]")
            .replacingOccurrences(of: "\\/", with: "/")
    }

    private func bpfEscape(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
    }

    private func cEscape(_ value: String) -> String {
        bpfEscape(value)
    }
}
