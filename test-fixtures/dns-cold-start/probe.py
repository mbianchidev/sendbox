"""Credential-free first-request probe. No OS lookup, warm-up or HTTP retry."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import selectors
import socket
import ssl
import struct
import sys
import time
from urllib.parse import urlsplit


HOST = "api.githubcopilot.com"


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise EOFError("incomplete proxy reply")
        data.extend(chunk)
    return bytes(data)


def read_http_head(stream):
    header = bytearray()
    while not header.endswith(b"\r\n\r\n"):
        if len(header) >= 8192:
            raise ValueError("HTTP header exceeds diagnostic limit")
        header.extend(read_exact(stream, 1))
    lines = header.decode("ascii").split("\r\n")
    headers = {}
    for line in lines[1:]:
        if line:
            key, value = line.split(":", 1)
            headers[key.lower()] = value.strip()
    return int(lines[0].split(" ", 2)[1]), headers


def read_http_status(stream):
    return read_http_head(stream)[0]


def proxy_connect(mode, host=HOST, port=443):
    variable = "ALL_PROXY" if mode == "socks" else "HTTPS_PROXY"
    proxy = urlsplit(os.environ[variable])
    if proxy.hostname != "127.0.0.1" or proxy.username or proxy.password:
        raise ValueError("probe requires a credential-free loopback proxy")
    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    stream.settimeout(12)
    try:
        stream.connect(("127.0.0.1", proxy.port))
        if mode == "http":
            stream.sendall(
                f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode(
                    "ascii"
                )
            )
            status, headers = read_http_head(stream)
            failure = None
            if status == 502 and headers.get("content-type") == "application/json":
                length = int(headers["content-length"])
                if not 0 < length <= 4096:
                    raise ValueError("proxy diagnostic exceeds the size limit")
                body = json.loads(read_exact(stream, length))
                failure = {
                    "error": body.get("error"),
                    "dns": {key: value for key, value in body.get("dns", {}).items()
                            if key in ("kind", "upstream", "qtype", "transport", "operation",
                                       "io_kind", "os_error", "detail", "response_code")},
                }
            return stream, status, failure
        stream.sendall(b"\x05\x01\x00")
        if read_exact(stream, 2) != b"\x05\x00":
            raise ValueError("unexpected SOCKS negotiation")
        name = host.encode("ascii")
        stream.sendall(
            b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", port)
        )
        version, reply, reserved, address_type = read_exact(stream, 4)
        if version != 5 or reserved != 0:
            raise ValueError("unexpected SOCKS reply")
        length = {1: 4, 4: 16}.get(address_type)
        if address_type == 3:
            length = read_exact(stream, 1)[0]
        if length is None:
            raise ValueError("unexpected SOCKS address type")
        read_exact(stream, length + 2)
        return stream, reply, None
    except BaseException:
        stream.close()
        raise


def containment():
    status = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in ("NoNewPrivs", "Seccomp", "CapEff", "CapPrm", "CapAmb"):
            status[key] = value.strip()
    return {
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "uid": os.geteuid(),
        **status,
    }


def application_probe(mode, check_denials):
    started = time.monotonic()
    result = {"mode": mode, "phase": "first", "authenticated": False}
    stream = None
    try:
        stream, status, failure = proxy_connect(mode)
        result["proxy_status"] = status
        result["connect_ms"] = round((time.monotonic() - started) * 1000, 3)
        if failure is not None:
            result["proxy_error"] = failure
        if status == (0 if mode == "socks" else 200):
            context = ssl.create_default_context()
            stream = context.wrap_socket(stream, server_hostname=HOST)
            stream.sendall(
                (
                    f"POST /chat/completions HTTP/1.1\r\nHost: {HOST}\r\n"
                    "Content-Type: application/json\r\nContent-Length: 2\r\n"
                    "Connection: close\r\n\r\n{}"
                ).encode("ascii")
            )
            result["api_status"] = read_http_status(stream)
        result["ok"] = result.get("api_status") == 400
    except (OSError, EOFError, ValueError) as error:
        result.update(ok=False, error_type=type(error).__name__)
        if isinstance(error, OSError):
            result["errno"] = error.errno
    finally:
        if stream is not None:
            stream.close()
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    result["containment"] = containment()
    emit("dns_cold_start", **result)
    denied = True
    if check_denials:
        for destination, port in (("denied.example", 443), (HOST, 444)):
            with_proxy, status, _ = proxy_connect(mode, destination, port)
            with_proxy.close()
            ok = status == (2 if mode == "socks" else 403)
            denied &= ok
            emit("dns_denial_check", mode=mode, target=destination, port=port,
                 proxy_status=status, ok=ok)
    return result["ok"] and denied


def dns_name(data, offset):
    labels, visited, end = [], set(), None
    while True:
        if offset in visited or len(visited) >= 128 or offset >= len(data):
            raise ValueError("invalid DNS name")
        visited.add(offset)
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("incomplete DNS pointer")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        offset += 1
        if length == 0:
            return ".".join(labels).lower(), end or offset
        if length > 63 or offset + length > len(data):
            raise ValueError("invalid DNS label")
        labels.append(data[offset:offset + length].decode("ascii"))
        offset += length


def dns_header(data):
    if len(data) < 12:
        raise ValueError("incomplete DNS header")
    identifier, flags, questions, answers, _, _ = struct.unpack("!6H", data[:12])
    if questions != 1 or answers > 128:
        raise ValueError("unexpected DNS counts")
    name, offset = dns_name(data, 12)
    qtype, qclass = struct.unpack_from("!HH", data, offset)
    offset += 4
    aliases = []
    for _ in range(answers):
        _, offset = dns_name(data, offset)
        record_type, _, _, size = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        if record_type == 5:
            alias, _ = dns_name(data, offset)
            aliases.append(alias)
        offset += size
        if offset > len(data):
            raise ValueError("incomplete DNS record")
    return {
        "id": identifier, "reply": bool(flags & 0x8000),
        "truncated": bool(flags & 0x0200), "rcode": flags & 15,
        "qname": name, "qtype": qtype, "qclass": qclass,
        "answers": answers, "cnames": aliases,
    }


def upstream_probe(attempts):
    upstream = next(
        fields[1]
        for line in Path("/etc/resolv.conf").read_text().splitlines()
        if len(fields := line.split()) >= 2
        and fields[0] == "nameserver"
        and not ipaddress.ip_address(fields[1]).is_loopback
    )
    family = socket.AF_INET6 if ":" in upstream else socket.AF_INET
    question = b"".join(bytes([len(label)]) + label.encode("ascii")
                        for label in HOST.split(".")) + b"\0"
    sockets = []
    started = time.monotonic()
    try:
        with selectors.DefaultSelector() as selector:
            for qtype in (1, 28):
                stream = socket.socket(family, socket.SOCK_DGRAM)
                sockets.append(stream)
                stream.connect((upstream, 53))
                stream.setblocking(False)
                identifier = struct.unpack("!H", os.urandom(2))[0]
                query = (struct.pack("!6H", identifier, 0x0100, 1, 0, 0, 0)
                         + question + struct.pack("!HH", qtype, 1))
                selector.register(stream, selectors.EVENT_READ,
                                  (identifier, qtype, query))
            for attempt in range(1, attempts + 1):
                for key in list(selector.get_map().values()):
                    key.fileobj.send(key.data[2])
                    emit("dns_wire", direction="send", upstream=upstream, attempt=attempt,
                         id=key.data[0], qtype=key.data[1],
                         elapsed_ms=round((time.monotonic() - started) * 1000, 3))
                deadline = time.monotonic() + 3
                while selector.get_map() and time.monotonic() < deadline:
                    for key, _ in selector.select(max(0, deadline - time.monotonic())):
                        header = dns_header(key.fileobj.recv(4096))
                        matching = (header["id"] == key.data[0]
                                    and header["qname"] == HOST
                                    and header["qtype"] == key.data[1]
                                    and header["qclass"] == 1 and header["reply"])
                        emit("dns_wire", direction="receive", upstream=upstream,
                             attempt=attempt, matching=matching,
                             elapsed_ms=round((time.monotonic() - started) * 1000, 3),
                             **header)
                        if matching:
                            selector.unregister(key.fileobj)
                if not selector.get_map():
                    return True
            emit("dns_upstream_timeout", upstream=upstream,
                 pending_types=[key.data[1] for key in selector.get_map().values()])
            return False
    finally:
        for stream in sockets:
            stream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("socks", "http", "upstream"))
    parser.add_argument("--check-denials", action="store_true")
    parser.add_argument("--attempts", type=int, choices=(1, 2), default=1)
    arguments = parser.parse_args()
    if arguments.mode == "upstream":
        return upstream_probe(arguments.attempts)
    return application_probe(arguments.mode, arguments.check_denials)


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
