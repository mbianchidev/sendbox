import importlib.util
import io
import json
from pathlib import Path
import signal
import socket
import struct
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import probe


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "dns_qualification", ROOT / "scripts/qualify-dns-cold-start.py")
QUALIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFY)
TRACE_SPEC = importlib.util.spec_from_file_location(
    "cold_dns_trace", Path(__file__).resolve().parent / "trace.py")
TRACE = importlib.util.module_from_spec(TRACE_SPEC)
TRACE_SPEC.loader.exec_module(TRACE)


class Stream:
    def __init__(self, incoming):
        self.incoming = io.BytesIO(incoming)
        self.sent = []
        self.connected = None
        self.closed = False

    def connect(self, address):
        self.connected = address

    def settimeout(self, _timeout):
        pass

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        return self.incoming.read(size)

    def close(self):
        self.closed = True


class ProbeTests(unittest.TestCase):
    def test_first_socks_request_uses_domain_without_os_lookup_or_retry(self):
        stream = Stream(b"\x05\x00\x05\x04\x00\x01" + bytes(6))
        with patch.dict(probe.os.environ, {"ALL_PROXY": "socks5h://127.0.0.1:15080"}), \
                patch.object(probe.socket, "socket", return_value=stream) as factory, \
                patch.object(probe.socket, "getaddrinfo", side_effect=AssertionError("OS lookup")), \
                patch.object(probe, "containment", return_value={}), \
                patch.object(probe, "emit") as emit:
            self.assertFalse(probe.application_probe("socks", False))
        factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        self.assertEqual(stream.connected, ("127.0.0.1", 15080))
        self.assertEqual(len(stream.sent), 2)
        self.assertEqual(stream.sent[0], b"\x05\x01\x00")
        self.assertTrue(stream.sent[1].startswith(b"\x05\x01\x00\x03"))
        self.assertIn(probe.HOST.encode("ascii"), stream.sent[1])
        self.assertEqual(emit.call_args.kwargs["proxy_status"], 4)
        self.assertTrue(stream.closed)

    def test_http_failure_retains_structured_fields_without_dumping_other_data(self):
        body = json.dumps({
            "error": "resolution_failed",
            "dns": {"kind": "timeout", "transport": "udp", "operation": "receive",
                    "qtype": "AAAA", "unrecognized": "synthetic-private-detail"},
        }).encode()
        header = (f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\n"
                  f"Content-Length: {len(body)}\r\n\r\n").encode()
        stream = Stream(header + body)
        with patch.dict(probe.os.environ, {"HTTPS_PROXY": "http://127.0.0.1:15083"}), \
                patch.object(probe.socket, "socket", return_value=stream), \
                patch.object(probe.socket, "getaddrinfo", side_effect=AssertionError("OS lookup")), \
                patch.object(probe, "containment", return_value={}), \
                patch.object(probe, "emit") as emit:
            self.assertFalse(probe.application_probe("http", False))
        self.assertEqual(len(stream.sent), 1)
        self.assertEqual(emit.call_args.kwargs["proxy_status"], 502)
        self.assertEqual(emit.call_args.kwargs["proxy_error"]["dns"]["kind"], "timeout")
        self.assertNotIn("synthetic-private-detail", json.dumps(emit.call_args.kwargs))
        self.assertTrue(stream.closed)

    def test_proxy_credentials_are_rejected_before_any_socket_is_opened(self):
        with patch.dict(probe.os.environ, {"HTTPS_PROXY": "http://synthetic:secret@127.0.0.1:15083"}), \
                patch.object(probe.socket, "socket") as factory:
            with self.assertRaises(ValueError):
                probe.proxy_connect("http")
        factory.assert_not_called()

    def test_dns_compression_loop_is_rejected(self):
        packet = struct.pack("!6H", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
        with self.assertRaises(ValueError):
            probe.dns_header(packet)

    def test_loss_fixture_only_adds_two_drops_for_the_selected_upstream(self):
        with patch.object(TRACE.subprocess, "run") as execute, \
                patch.object(TRACE, "emit"):
            TRACE.install_loss_fixture(["127.0.0.1", "192.0.2.53"])
        self.assertEqual(execute.call_args.args[0], ["nft", "--file", "-"])
        rules = execute.call_args.kwargs["input"]
        self.assertIn("ip saddr 192.0.2.53 udp sport 53", rules)
        self.assertIn("numgen inc mod 2147483647 < 2 counter drop", rules)
        self.assertIn("hook input priority -10", rules)
        self.assertNotIn("flush", rules)
        self.assertNotIn("destroy", rules)
        self.assertNotIn("meta mark", rules)
        self.assertTrue(all(TRACE.FAULT_TABLE in line for line in rules.splitlines()))


class QualificationTests(unittest.TestCase):
    def test_generated_policy_is_exact_deny_first_and_credential_free(self):
        config = QUALIFY.configuration(
            "sendbox-dns-unit", Path("/fixture/project"), ["canonical.example"])
        self.assertEqual(config["secrets"], [])
        self.assertFalse(config["github"]["forward_auth"])
        self.assertFalse(config["github"]["forward_copilot_auth"])
        network = config["policy"]["network"]
        self.assertEqual(network["default_action"], "deny")
        self.assertEqual(network["allowed_domains"], [probe.HOST, "canonical.example"])
        self.assertEqual(network["allowed_ports"], [{"port": 443, "protocol": "tcp"}])
        self.assertNotIn("allowed_networks", network)
        self.assertTrue(all("*" not in rule for rule in config["policy"]["commands"]["allowlist"]))

    def test_guest_json_split_across_protocol_frames_is_reassembled(self):
        guest = json.dumps({"event": "dns_cold_start", "ok": False, "phase": "first"}).encode() + b"\n"
        frames = [
            {"event": "output", "stream": "stdout", "data": chunk.hex()}
            for chunk in (guest[:9], guest[9:])
        ] + [{"event": "result", "exit_code": 1}]
        records, terminal = QUALIFY.decode_output(
            b"\n".join(json.dumps(frame).encode() for frame in frames))
        self.assertEqual(records, [{"event": "dns_cold_start", "ok": False, "phase": "first"}])
        self.assertEqual(terminal["exit_code"], 1)

    def test_cleanup_never_targets_another_vm(self):
        prefix = "sendbox-dns-unit-01"
        owned = {"configuration": {"id": prefix + "-session"}, "status": "running"}
        unrelated = {"configuration": {"id": "porto-k0s-smoke-server-1"}, "status": "running"}
        similar = {"configuration": {"id": prefix + "not-owned"}, "status": "running"}
        listings = iter(([owned, unrelated, similar], [unrelated, similar]))

        def run(command, **_kwargs):
            if command[:2] == ["container", "list"]:
                return SimpleNamespace(stdout=json.dumps(next(listings)), returncode=0)
            return SimpleNamespace(returncode=0)

        with patch.object(QUALIFY.subprocess, "run", side_effect=run) as execute:
            self.assertEqual(QUALIFY.cleanup(prefix), 1)
        mutations = [call.args[0] for call in execute.call_args_list
                     if call.args[0][1] != "list"]
        self.assertEqual(mutations, [
            ["container", "stop", "--time", "5", prefix + "-session"],
            ["container", "delete", prefix + "-session"],
        ])

    def test_cleanup_tolerates_concurrent_host_cleanup_without_broadening_scope(self):
        prefix = "sendbox-dns-unit-01"
        child = Mock()
        child.returncode = 1
        with patch.object(QUALIFY, "owned_vms",
                          side_effect=[[prefix + "-session"], [], [], []]), \
                patch.object(QUALIFY.subprocess, "run", return_value=child):
            self.assertEqual(QUALIFY.cleanup(prefix), 1)

    def test_cancellation_interrupts_the_batch_after_signalling_only_its_host_process(self):
        process = Mock()
        process.communicate.side_effect = [KeyboardInterrupt(), (b"", b"")]
        with patch.object(QUALIFY.subprocess, "Popen", return_value=process):
            with self.assertRaises(KeyboardInterrupt):
                QUALIFY.execute(["sendbox"], "sendbox-dns-unit", False, False)
        process.send_signal.assert_called_once_with(signal.SIGINT)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()

    def test_host_timeout_has_bounded_escalation(self):
        process = Mock()
        process.returncode = -9
        process.communicate.side_effect = [
            subprocess.TimeoutExpired("sendbox", 120),
            subprocess.TimeoutExpired("sendbox", 20),
            subprocess.TimeoutExpired("sendbox", 5),
            (b"", b""),
        ]
        with patch.object(QUALIFY.subprocess, "Popen", return_value=process):
            result = QUALIFY.execute(["sendbox"], "sendbox-dns-unit", False, False)
        self.assertTrue(result[3])
        process.send_signal.assert_called_once_with(signal.SIGINT)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()


if __name__ == "__main__":
    unittest.main()
