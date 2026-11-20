#!/usr/bin/env python3
"""Explicit negative diagnostics in the existing gateway network namespace.

No seller mounts, control protocol, pairing, download or authorization code.
Negative probe verdicts: True denied, False reached, None inconclusive.
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


def tcp_denied(host, port):
    """True = denied, False = reached, None = inconclusive, as for all probes."""
    try:
        connection = tcp(host, port)
    except ConnectionRefusedError:
        # Only refusal while opening proves this destination/port unavailable.
        return True
    except OSError:
        return None
    try:
        with connection:
            return False
    except OSError:
        return None


def dns_name(packet, offset, known=None):
    """Decode a bounded DNS name, including compression, or reject the packet."""
    labels, seen, end = [], set(), None
    if known is None:
        known = set()
    while True:
        if offset >= len(packet) or offset in seen:
            raise ValueError()
        seen.add(offset)
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            if offset + 1 >= len(packet):
                raise ValueError()
            target = ((length & 0x3f) << 8) | packet[offset + 1]
            if target >= offset or target not in known:
                raise ValueError()
            known.add(offset)
            if end is None:
                end = offset + 2
            offset = target
            continue
        if length & 0xc0 or offset + 1 + length > len(packet):
            raise ValueError()
        known.add(offset)
        offset += 1
        if not length:
            if sum(len(label) + 1 for label in labels) + 1 > 255:
                raise ValueError()
            return tuple(labels), end if end is not None else offset
        labels.append(packet[offset:offset + length].lower())
        offset += length


def dns_result(reply, query):
    """Classify only a complete matching DNS response; opaque failures are unknown."""
    if len(reply) < 12 or len(reply) > 512 or reply[:2] != query[:2]:
        return None
    _, flags, questions, answers, authority, additional = struct.unpack("!6H", reply[:12])
    # QR, standard opcode, no truncation or reserved Z bit. AD/CD are permitted.
    if not flags & 0x8000 or flags & 0x7a40 or questions != 1:
        return None
    rcode = flags & 15
    if rcode not in (0, 3, 5):
        return None
    try:
        known = set()
        name, offset = dns_name(reply, 12, known)
        expected, _ = dns_name(query, 12)
        if name != expected or reply[offset:offset + 4] != query[-4:]:
            return None
        offset += 4
        records = []
        for index in range(answers + authority + additional):
            owner, offset = dns_name(reply, offset, known)
            if offset + 10 > len(reply):
                return None
            kind, cls, _, length = struct.unpack("!HHIH", reply[offset:offset + 10])
            offset += 10
            end = offset + length
            if end > len(reply):
                return None
            value = None
            if kind in (1, 28):
                if length != (4 if kind == 1 else 16):
                    return None
            elif kind in (2, 5, 12):
                value, name_end = dns_name(reply, offset, known)
                if name_end != end:
                    return None
            elif kind == 15:  # MX preference followed by a name.
                if length < 3 or dns_name(reply, offset + 2, known)[1] != end:
                    return None
            elif kind == 6:  # SOA has two names and five uint32 values.
                _, next_offset = dns_name(reply, offset, known)
                _, next_offset = dns_name(reply, next_offset, known)
                if next_offset + 20 != end:
                    return None
            elif kind == 16:  # TXT is a sequence of length-prefixed strings.
                cursor = offset
                if not length:
                    return None
                while cursor < end:
                    cursor += 1 + reply[cursor]
                if cursor != end:
                    return None
            else:
                # Unsupported RDATA cannot supply well-formed denial evidence.
                return None
            if index < answers:
                records.append((owner, kind, cls, value))
            offset = end
        if offset != len(reply):
            return None
        if not answers:
            return True  # Matching NOERROR/no-answer, NXDOMAIN or REFUSED.
        if rcode != 0:
            return None  # An error with answer records is contradictory evidence.
        # Require an A answer for the queried name (possibly through CNAMEs).
        names = {expected}
        for _ in range(len(records)):
            names.update(value for owner, kind, cls, value in records
                         if owner in names and kind == 5 and cls == 1)
        if any(owner in names and kind == 1 and cls == 1
               for owner, kind, cls, _ in records):
            return False
    except (ValueError, struct.error):
        pass
    return None


def dns_answer(host):
    # A fixed public name with no seller/account information. One bounded query.
    query = b"\x53\x19\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT)
            # Connected UDP also filters datagrams from unrelated source peers.
            sock.connect((host, 53))
            sock.send(query)
            reply = sock.recv(513)
        return dns_result(reply, query)
    except OSError:
        return None


def response_line(sock, deadline):
    response = bytearray()
    while len(response) < 4096:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        block = sock.recv(1)
        if not block:
            return b"" if not response else None
        response.extend(block)
        if block == b"\n":
            return bytes(response)
    return None


def status_line(sock, clean_close=False, deadline=None):
    if deadline is None:
        deadline = time.monotonic() + TIMEOUT
    response = response_line(sock, deadline)
    if response == b"":
        # Zero is an internal marker for EOF before any response bytes.
        return (0, False) if clean_close else None
    if response is None:
        return None
    match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3}) [\t\x20-\x7e\x80-\xff]*\r\n", response)
    if not match or not 100 <= int(match[1]) <= 599:
        return None
    return int(match[1]), response.startswith(b"HTTP/1.0 ")


def valid_framing(fields, status, http10):
    """Accept only unambiguous framing that this HTTP/1 probe understands."""
    lengths = fields.get(b"content-length", [])
    transfers = fields.get(b"transfer-encoding", [])
    if lengths and transfers:
        return False
    if (lengths or transfers) and (status < 200 or status == 204):
        return False
    if lengths:
        values = [value.strip(b" \t") for field in lengths for value in field.split(b",")]
        if any(not re.fullmatch(rb"[0-9]+", value) for value in values):
            return False
        # Compare decimal values without unbounded integer conversion.
        if len({value.lstrip(b"0") or b"0" for value in values}) != 1:
            return False
    if transfers:
        # Other codings/parameters and repeated chunked are unsupported evidence.
        values = [value.strip(b" \t").lower() for field in transfers for value in field.split(b",")]
        if http10 or values != [b"chunked"]:
            return False
    return True


def final_status(sock, clean_close=False):
    deadline = time.monotonic() + TIMEOUT
    for informational in range(6):
        parsed = status_line(sock, clean_close=clean_close and informational == 0,
                             deadline=deadline)
        if parsed is None:
            return None
        status, http10 = parsed
        if status == 0:
            return 0
        # 101 switches protocols; no subsequent HTTP final response is valid.
        if status == 101 or (status < 200 and informational == 5):
            return None
        # Validate every response's complete header section before classifying it.
        # Per-response byte/count bounds and one deadline also bound 1xx chains.
        header_bytes = 0
        fields = {}
        for field_count in range(65):  # At most 64 fields, then the terminating CRLF.
            line = response_line(sock, deadline)
            if not line:
                return None
            header_bytes += len(line)
            if header_bytes > 4096:
                return None
            if line == b"\r\n":
                break
            if field_count == 64 or not re.fullmatch(
                    rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e\x80-\xff]*\r\n", line):
                return None
            name, value = line[:-2].split(b":", 1)
            fields.setdefault(name.lower(), []).append(value)
        else:
            return None
        if not valid_framing(fields, status, http10=http10):
            return None
        if status >= 200:
            return status
    return None


def tls_final_status(sock):
    return final_status(sock, clean_close=True)


def connect_tls_door(host, port, destination):
    # Trust is deliberately not checked here: this tests the listener protocol,
    # not certificate deployment. A completed handshake AND certificate are
    # positive evidence of TLS before any CONNECT denial can count.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with tcp(host, port) as connection:
            # Do not turn a truncated TLS stream into an apparently clean EOF.
            with context.wrap_socket(connection, server_hostname=host,
                                     suppress_ragged_eofs=False) as sock:
                if not sock.getpeercert(binary_form=True):
                    return None
                sock.sendall(("CONNECT " + destination + " HTTP/1.1\r\nHost: " + destination + "\r\n\r\n").encode("ascii"))
                status = tls_final_status(sock)
                if status is None:
                    return None
                return not 200 <= status < 300
    except (OSError, ValueError):
        return None


def connect(host, port, destination, inspected_door=False):
    if inspected_door and port == 8443:
        return connect_tls_door(host, port, destination)
    # Only refusal while opening a listener on the already-inspected door proves
    # that listener closed. Failures after connecting remain inconclusive.
    try:
        connection = tcp(host, port)
    except ConnectionRefusedError:
        return True if inspected_door else None
    except OSError:
        return None
    try:
        with connection as sock:
            sock.sendall(("CONNECT " + destination + " HTTP/1.1\r\nHost: " + destination + "\r\n\r\n").encode("ascii"))
            status = final_status(sock)
            if status is None:
                return None
            # Established plaintext replies still need an explicit rejection.
            return not 200 <= status < 300
    except OSError:
        return None


def denied(action):
    """Preserve explicit probe verdicts; truthiness and exceptions prove nothing."""
    try:
        result = action()
        return result if result is True or result is False else None
    except (OSError, ValueError):
        return None


def allowed_aim_tls():
    with tcp("172.30.196.3", 3128) as sock:
        sock.sendall(b"CONNECT api.ai.market:443 HTTP/1.1\r\nHost: api.ai.market:443\r\n\r\n")
        status = final_status(sock)
        if status is None or not 200 <= status < 300:
            return False
        # System trust and hostname checks stay enabled. No inspection bypass.
        with ssl.create_default_context().wrap_socket(sock, server_hostname="api.ai.market"):
            return True


def main():
    try:
        if sys.argv[1:] == ["--door"]:
            # Run in the selected door namespace, not the gateway namespace.
            resolvers = re.findall(r"(?m)^nameserver\s+([0-9.]+)", open("/etc/resolv.conf", encoding="ascii").read())
            checks = [denied(lambda: tcp_denied("1.1.1.1", 443))]
            checks.extend(denied(lambda host=host: dns_answer(host)) for host in set(resolvers + ["1.1.1.1"]))
            if resolvers and all(value is True for value in checks):
                print("door-negative-probes:pass")
                return 0
            return 1
        if sys.argv[1:]:
            return 1
        if not allowed_aim_tls():
            return 1
        resolvers = re.findall(r"(?m)^nameserver\s+([0-9.]+)", open("/etc/resolv.conf", encoding="ascii").read())
        if not resolvers:
            return 1
        checks = [denied(lambda: tcp_denied("1.1.1.1", 443)),
                  denied(lambda: connect("172.30.196.3", 3128, "example.com:443")),
                  denied(lambda: connect("172.30.196.3", 3128, "api.ai.market:80"))]
        checks.extend(denied(lambda host=host: dns_answer(host)) for host in set(resolvers + ["1.1.1.1", "172.30.196.3", "172.30.196.4"]))
        for helper in ("172.30.196.4",):
            for port in (3128, 8080, 8443):
                checks.append(denied(lambda host=helper, port=port: connect(host, port, "example.com:443", inspected_door=True)))
        if all(value is True for value in checks):
            print("isolation-negative-probes:pass")
            return 0
    except (OSError, ValueError):
        pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
