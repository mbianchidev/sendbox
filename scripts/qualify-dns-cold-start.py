#!/usr/bin/env python3
"""Run sequential, credential-free first requests in genuinely fresh Apple VMs."""

import argparse
import json
import math
from pathlib import Path
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid


PROBE = "/usr/local/bin/sendbox-dns-python /opt/sendbox-dns/probe.py"


def owned_vms(prefix, running=False):
    result = subprocess.run(
        ["container", "list", "--format", "json"], capture_output=True, check=True,
        text=True, timeout=30,
    )
    return [
        row["configuration"]["id"] for row in json.loads(result.stdout)
        if row.get("configuration", {}).get("id", "").startswith(prefix + "-")
        and (not running or row.get("status") == "running")
    ]


def cleanup(prefix):
    remaining = owned_vms(prefix)
    for identifier in remaining:
        stopped = subprocess.run(["container", "stop", "--time", "5", identifier],
                                 capture_output=True, timeout=30)
        if stopped.returncode and identifier in owned_vms(prefix, running=True):
            raise RuntimeError(f"stopping owned diagnostic VM failed (exit {stopped.returncode})")
        deleted = subprocess.run(["container", "delete", identifier],
                                 capture_output=True, timeout=30)
        if deleted.returncode and identifier in owned_vms(prefix):
            raise RuntimeError(f"deleting owned diagnostic VM failed (exit {deleted.returncode})")
    if owned_vms(prefix):
        raise RuntimeError("owned diagnostic VM cleanup failed")
    return len(remaining)


def cancelled(_signal, _frame):
    raise KeyboardInterrupt


def configuration(name, project, aliases):
    return {
        "name": name, "project_path": str(project),
        "resources": {"cpus": 2, "memory_mb": 1024, "disk_size_mb": 2048},
        "policy": {
            "commands": {"default_action": "deny",
                         "allowlist": [f"{PROBE} {mode} --check-denials"
                                       for mode in ("socks", "http")],
                         "denylist": [], "log_blocked": True},
            "network": {
                "default_action": "deny",
                "allowed_domains": ["api.githubcopilot.com", *aliases],
                "blocked_domains": [], "allow_dns": True,
                "allowed_ports": [{"protocol": "tcp", "port": 443}],
            },
        },
        "secrets": [],
        "github": {"forward_auth": False, "forward_copilot_auth": False,
                   "branch_protection": {"enabled": False}},
    }


def trace_vm(name, done, records, drop_first):
    try:
        while not done.wait(0.02):
            identifiers = owned_vms(name, running=True)
            if not identifiers:
                continue
            command = ["container", "exec", "--user", "0:0", identifiers[0],
                       "/usr/local/bin/sendbox-dns-python", "/opt/sendbox-dns/trace.py"]
            if drop_first:
                command.append("--drop-first-replies")
            result = subprocess.run(
                command,
                capture_output=True, timeout=18,
            )
            for line in result.stdout.splitlines():
                records.append(json.loads(line))
            records.append({"event": "dns_trace_finished", "exit_code": result.returncode})
            return
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        records.append({"event": "dns_trace_error", "error_type": type(error).__name__})


def execute(command, name, trace, drop_first):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out, interrupted = False, False
    done, trace_records = threading.Event(), []
    watcher = threading.Thread(target=trace_vm, args=(name, done, trace_records, drop_first)) if trace else None
    if watcher:
        watcher.start()
    try:
        stdout, stderr = process.communicate(timeout=120)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        timed_out = not interrupted
        process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
    finally:
        done.set()
        if watcher:
            watcher.join()
    if interrupted:
        raise KeyboardInterrupt
    return process.returncode, stdout, stderr, timed_out, trace_records


def decode_output(stdout):
    guest = {"stdout": bytearray(), "stderr": bytearray()}
    terminal = None
    for line in stdout.splitlines():
        envelope = json.loads(line)
        if envelope.get("event") == "output":
            guest[envelope["stream"]].extend(bytes.fromhex(envelope["data"]))
        else:
            terminal = envelope
    records = []
    for data in guest.values():
        for line in data.splitlines():
            record = json.loads(line)
            if record.get("event") in ("dns_cold_start", "dns_denial_check"):
                records.append(record)
    return records, terminal


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sendbox", default="/usr/local/bin/sendbox")
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--trust-root", required=True, type=Path)
    parser.add_argument("--trust-root-id", default="external-release-root")
    parser.add_argument("--image", required=True)
    parser.add_argument("--allowed-cname", action="append", required=True)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--mode", choices=("socks", "http", "alternate"), default="alternate")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--trace", action="store_true",
                        help="passively capture only DNS headers in each owned VM")
    parser.add_argument("--drop-first-replies", action="store_true",
                        help="add an owned-VM-only rule dropping the first two upstream UDP replies")
    arguments = parser.parse_args()
    if arguments.count < 1 or "@sha256:" not in arguments.image:
        parser.error("positive count and digest-pinned image are required")
    if any("*" in name or "/" in name for name in arguments.allowed_cname):
        parser.error("CNAME permissions must be exact observed hostnames")
    arguments.trace |= arguments.drop_first_replies
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    boot_ids, checks = set(), []
    prefix = "sendbox-dns-" + uuid.uuid4().hex[:12]
    with arguments.output.open("x") as output:
        def record(value):
            line = json.dumps(value, sort_keys=True)
            print(line, flush=True)
            output.write(line + "\n")
            output.flush()

        record({
            "event": "fresh_vm_batch", "vm_prefix": prefix,
            "count": arguments.count, "mode": arguments.mode,
            "image": arguments.image, "trace": arguments.trace,
            "drop_first_replies": arguments.drop_first_replies,
        })
        with tempfile.TemporaryDirectory(prefix=prefix + "-", dir=arguments.output.parent) as root:
            root = Path(root)
            for index in range(arguments.count):
                name = f"{prefix}-{index + 1:02d}"
                project = root / name
                project.mkdir(mode=0o755)
                config = root / f"{name}.json"
                config.write_text(json.dumps(configuration(
                    name, project, arguments.allowed_cname)))
                mode = arguments.mode
                if mode == "alternate":
                    mode = "socks" if index % 2 == 0 else "http"
                command = [
                    arguments.sendbox, "run", "--json", "--runtime", "apple",
                    "--config", str(config), "--image", arguments.image,
                    "--bundle", str(arguments.bundle.resolve()),
                    "--trust-root", str(arguments.trust_root.resolve()),
                    "--trust-root-id", arguments.trust_root_id, "--",
                    *PROBE.split(), mode, "--check-denials",
                ]
                started = time.monotonic()
                try:
                    code, stdout, stderr, timed_out, trace_records = execute(
                        command, name, arguments.trace, arguments.drop_first_replies)
                    records, terminal = decode_output(stdout)
                finally:
                    recovered = cleanup(name)
                first = next((r for r in records if r["event"] == "dns_cold_start"), None)
                denials = [r for r in records if r["event"] == "dns_denial_check"]
                controls = first.get("containment", {}) if first else {}
                boot = controls.get("boot_id")
                hardened = (
                    controls.get("uid", 0) != 0
                    and controls.get("NoNewPrivs") == "1"
                    and controls.get("Seccomp") == "2"
                    and all(int(controls.get(key, "1"), 16) == 0
                            for key in ("CapEff", "CapPrm", "CapAmb"))
                )
                ok = (code == 0 and not timed_out and first is not None and first["ok"]
                      and boot and boot not in boot_ids and hardened
                      and len(denials) == 2 and all(r["ok"] for r in denials)
                      and recovered == 0)
                trace_started = any(r["event"] == "dns_trace_started" for r in trace_records)
                drops = max((r["dropped_replies"] for r in trace_records
                             if r["event"] == "dns_fault_state"), default=0)
                first_sends = [r["qtype"] for r in trace_records
                               if r["event"] == "dns_trace_udp" and not r["reply"]][:2]
                first_replies = [r["qtype"] for r in trace_records
                                 if r["event"] == "dns_trace_udp" and r["reply"]][:2]
                verified_loss = drops == 2 and set(first_sends) == {1, 28} and set(first_replies) == {1, 28}
                if arguments.trace:
                    ok = ok and trace_started
                if arguments.drop_first_replies:
                    ok = ok and verified_loss
                boot_ids.add(boot)
                check = {
                    "event": "fresh_vm_check", "index": index + 1, "mode": mode,
                    "vm_name_prefix": name,
                    "ok": bool(ok), "host_exit_code": code, "timed_out": timed_out,
                    "hardened": hardened, "recovered_vms": recovered,
                    "host_elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                    "first": first, "denials": denials,
                }
                if arguments.trace:
                    check["trace"] = trace_records
                if arguments.drop_first_replies:
                    check["injected_dropped_replies"] = drops
                    check["verified_reply_loss"] = verified_loss
                if first is None:
                    check["host_result"] = terminal
                    check["host_stderr_bytes"] = len(stderr)
                record(check)
                checks.append(check)
        latencies = [c["first"]["elapsed_ms"] for c in checks if c["first"] is not None]
        latencies.sort()
        summary = {
            "event": "fresh_vm_summary", "checks": len(checks),
            "failures": [c["index"] for c in checks if not c["ok"]],
            "unique_boot_ids": len(boot_ids - {None}),
            "owned_vms_remaining": len(owned_vms(prefix)),
        }
        if latencies:
            summary["first_request_ms"] = {
                "min": min(latencies), "median": statistics.median(latencies),
                "p95": latencies[math.ceil(len(latencies) * 0.95) - 1],
                "max": max(latencies),
            }
        record(summary)
        return not summary["failures"] and summary["owned_vms_remaining"] == 0


if __name__ == "__main__":
    try:
        signal.signal(signal.SIGTERM, cancelled)
        sys.exit(0 if main() else 1)
    except KeyboardInterrupt:
        print("cold-start qualification cancelled", file=sys.stderr)
        sys.exit(130)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"cold-start qualification failed: {error}", file=sys.stderr)
        sys.exit(2)
