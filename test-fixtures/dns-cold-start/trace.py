"""Header-only capture and optional reply loss inside one owned diagnostic VM."""

import argparse
import ipaddress
import json
import socket
import struct
import subprocess
import time
from pathlib import Path

from probe import HOST, dns_header, emit


FAULT_TABLE = "sendbox_dns_cold_fixture"


def install_loss_fixture(nameservers):
    upstream = next(ipaddress.ip_address(value) for value in nameservers
                    if not ipaddress.ip_address(value).is_loopback)
    address_family = "ip" if upstream.version == 4 else "ip6"
    rules = (
        f"add table inet {FAULT_TABLE}\n"
        f"add chain inet {FAULT_TABLE} input {{ type filter hook input priority -10; policy accept; }}\n"
        f"add rule inet {FAULT_TABLE} input {address_family} saddr {upstream} "
        "udp sport 53 numgen inc mod 2147483647 < 2 counter drop\n"
    )
    subprocess.run(["nft", "--file", "-"], input=rules, text=True,
                   capture_output=True, check=True, timeout=2)
    emit("dns_fault_installed", upstream=str(upstream), drop_limit=2)


def dropped_replies():
    result = subprocess.run(["nft", "--json", "list", "table", "inet", FAULT_TABLE],
                            capture_output=True, check=True, text=True, timeout=2)
    return sum(expression["counter"]["packets"]
               for item in json.loads(result.stdout)["nftables"] if "rule" in item
               for expression in item["rule"]["expr"] if "counter" in expression)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drop-first-replies", action="store_true")
    arguments = parser.parse_args()
    started = time.monotonic()
    nameservers = [
        fields[1] for line in Path("/etc/resolv.conf").read_text().splitlines()
        if len(fields := line.split()) >= 2 and fields[0] == "nameserver"
    ]
    if arguments.drop_first_replies:
        install_loss_fixture(nameservers)
    observed_drops = 0
    emit("dns_trace_started", nameservers=nameservers,
         guest_uptime_s=float(Path("/proc/uptime").read_text().split()[0]))
    with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003)) as capture:
        capture.settimeout(0.5)
        while time.monotonic() - started < 12:
            try:
                packet, link = capture.recvfrom(65535)
            except socket.timeout:
                continue
            if link[1] != 0x0800 or len(packet) < 28 or packet[0] >> 4 != 4:
                continue
            header_length = (packet[0] & 15) * 4
            if header_length < 20 or len(packet) < header_length + 8:
                continue
            if struct.unpack_from("!H", packet, 6)[0] & 0x3FFF:
                continue
            source, destination = socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20])
            protocol = packet[9]
            if protocol not in (6, 17):
                continue
            source_port, destination_port = struct.unpack_from("!HH", packet, header_length)
            if 53 not in (source_port, destination_port) or source == "127.0.0.1" or destination == "127.0.0.1":
                continue
            fields = {
                "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                "source": source, "destination": destination,
                "source_port": source_port, "destination_port": destination_port,
                "direction": "send" if link[2] == socket.PACKET_OUTGOING else "receive",
            }
            if protocol == 6:
                if len(packet) >= header_length + 14:
                    emit("dns_trace_tcp", flags=packet[header_length + 13], **fields)
                continue
            try:
                header = dns_header(packet[header_length + 8:])
            except (ValueError, UnicodeError, struct.error):
                emit("dns_trace_invalid_header", **fields)
                continue
            if header["qname"] == HOST:
                emit("dns_trace_udp", **fields, **header)
                if arguments.drop_first_replies and header["reply"] and observed_drops < 2:
                    observed_drops = dropped_replies()
                    emit("dns_fault_state", dropped_replies=observed_drops)
    if arguments.drop_first_replies:
        subprocess.run(["nft", "delete", "table", "inet", FAULT_TABLE],
                       capture_output=True, check=True, timeout=2)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, StopIteration, subprocess.SubprocessError) as error:
        emit("dns_trace_error", error_type=type(error).__name__)
        raise SystemExit(2) from None
