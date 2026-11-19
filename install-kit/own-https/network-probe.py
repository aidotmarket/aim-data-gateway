#!/usr/bin/env python3
"""Explicit negative diagnostics in the existing gateway network namespace.

No seller mounts, control protocol, pairing, download or authorization code.
Fixed output only. Success does not establish canary correlation or readiness.
"""
import re
import socket
import ssl
import struct
import sys
import time

TIMEOUT = 1


def tcp(host, port):
    return socket.create_connection((host, port), timeout=TIMEOUT)


def dns_answer(host):
    # A fixed public name with no seller/account information. One bounded query.
    query = b"\x53\x19\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendto(query, (host, 53))
        reply = sock.recv(512)
    return len(reply) >= 12 and reply[:2] == query[:2] and reply[3] & 15 == 0 and struct.unpack("!H", reply[6:8])[0] > 0


def status_line(sock):
    response = bytearray()
    deadline = time.monotonic() + TIMEOUT
    while len(response) < 4096:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        block = sock.recv(1)
        if not block:
            return None
        response.extend(block)
        if block == b"\n":
            match = re.fullmatch(rb"HTTP/1\.[01][ \t]+([0-9]{3})(?:[ \t]+[^\r\n]*)?\r?\n", response)
            if not match or not 100 <= int(match[1]) <= 599:
                return None
            return int(match[1])
    return None


def connect(host, port, destination):
    try:
        with tcp(host, port) as sock:
            sock.sendall(("CONNECT " + destination + " HTTP/1.1\r\nHost: " + destination + "\r\n\r\n").encode("ascii"))
            status = status_line(sock)
            if status is None:
                return None
            # Only an explicit policy denial proves the negative test.
            return True if 200 <= status < 300 else False if status in (403, 405, 407) else None
    except OSError:
        return None


def denied(action):
    try:
        result = action()
        if hasattr(result, "close"):
            result.close()
            return False
        return None if result is None else not result
    except (OSError, ValueError):
        return True


def allowed_aim_tls():
    with tcp("172.30.196.3", 3128) as sock:
        sock.sendall(b"CONNECT api.ai.market:443 HTTP/1.1\r\nHost: api.ai.market:443\r\n\r\n")
        response = bytearray()
        while b"\r\n\r\n" not in response and len(response) < 4096:
            block = sock.recv(1)
            if not block:
                return False
            response.extend(block)
        if not re.match(rb"HTTP/1\.[01] 2[0-9]{2} ", response):
            return False
        # System trust and hostname checks stay enabled. No inspection bypass.
        with ssl.create_default_context().wrap_socket(sock, server_hostname="api.ai.market"):
            return True


def main():
    try:
        if not allowed_aim_tls():
            return 1
        resolvers = re.findall(r"(?m)^nameserver\s+([0-9.]+)", open("/etc/resolv.conf", encoding="ascii").read())
        if not resolvers:
            return 1
        checks = [denied(lambda: tcp("1.1.1.1", 443)),
                  denied(lambda: connect("172.30.196.3", 3128, "example.com:443")),
                  denied(lambda: connect("172.30.196.3", 3128, "api.ai.market:80"))]
        checks.extend(denied(lambda host=host: dns_answer(host)) for host in set(resolvers + ["1.1.1.1", "172.30.196.3", "172.30.196.4", "172.30.196.5"]))
        for helper in ("172.30.196.4", "172.30.196.5"):
            for port in (3128, 8080, 8443):
                checks.append(denied(lambda host=helper, port=port: connect(host, port, "example.com:443")))
        if all(value is True for value in checks):
            print("isolation-negative-probes:pass")
            return 0
    except (OSError, ValueError):
        pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
