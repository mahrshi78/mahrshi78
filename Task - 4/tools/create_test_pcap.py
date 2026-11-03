"""Generate a harmless synthetic PCAP to validate local Suricata alert rules.

Only documentation/example IP addresses are used. No packets are transmitted.
"""
from __future__ import annotations

import argparse
import ipaddress
import struct
from pathlib import Path


def checksum(data: bytes) -> int:
    """Return the Internet checksum for an IPv4 header or ICMP message."""
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_header(source: str, destination: str, protocol: int, payload_length: int, ident: int) -> bytes:
    src = ipaddress.IPv4Address(source).packed
    dst = ipaddress.IPv4Address(destination).packed
    total_length = 20 + payload_length
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, ident & 0xFFFF, 0x4000,
        64, protocol, 0, src, dst,
    )
    value = checksum(header)
    return header[:10] + struct.pack("!H", value) + header[12:]


def ethernet_frame(payload: bytes) -> bytes:
    destination_mac = bytes.fromhex("020000000002")
    source_mac = bytes.fromhex("020000000001")
    return destination_mac + source_mac + struct.pack("!H", 0x0800) + payload


def tcp_syn_frame(source: str, destination: str, destination_port: int, ident: int) -> bytes:
    source_port = 40000 + (ident % 20000)
    sequence = 100000 + ident
    tcp_zero = struct.pack(
        "!HHLLBBHHH",
        source_port, destination_port, sequence, 0,
        5 << 4, 0x02, 64240, 0, 0,
    )
    pseudo = (
        ipaddress.IPv4Address(source).packed
        + ipaddress.IPv4Address(destination).packed
        + struct.pack("!BBH", 0, 6, len(tcp_zero))
    )
    tcp_sum = checksum(pseudo + tcp_zero)
    tcp = tcp_zero[:16] + struct.pack("!H", tcp_sum) + tcp_zero[18:]
    ip = ipv4_header(source, destination, 6, len(tcp), ident)
    return ethernet_frame(ip + tcp)


def icmp_echo_frame(source: str, destination: str, ident: int) -> bytes:
    message = struct.pack("!BBHHH", 8, 0, 0, 0x1234, ident & 0xFFFF)
    message = message[:2] + struct.pack("!H", checksum(message)) + message[4:]
    ip = ipv4_header(source, destination, 1, len(message), ident + 500)
    return ethernet_frame(ip + message)


def create_test_pcap(output: str | Path, destination: str = "192.168.1.10") -> int:
    """Write TCP SYN bursts and ICMP echo requests to a classic PCAP file."""
    ipaddress.IPv4Address(destination)
    source = "198.51.100.24"  # RFC 5737 TEST-NET-2 documentation range.
    packets: list[bytes] = []

    # 110 TCP SYN packets in a short window: 25 to SSH/22 and 85 to
    # varied ports. These meet the educational rules' alert thresholds.
    for index in range(110):
        port = 22 if index < 25 else 1000 + (index % 50000)
        packets.append(tcp_syn_frame(source, destination, port, index + 1))

    # ICMP echo requests are included to exercise the ICMP threshold rule.
    for index in range(12):
        packets.append(icmp_echo_frame(source, destination, index + 1))

    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as target:
        # Little-endian classic PCAP, Ethernet link type.
        target.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        base_seconds = 1793700000
        for index, packet in enumerate(packets):
            seconds = base_seconds + (index // 100)
            microseconds = (index % 100) * 10000
            target.write(struct.pack("<IIII", seconds, microseconds, len(packet), len(packet)))
            target.write(packet)

    return len(packets)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="sample-data/task4-test-traffic.pcap")
    parser.add_argument("--dest-ip", default="192.168.1.10", help="Address inside configured HOME_NET")
    args = parser.parse_args()
    count = create_test_pcap(args.output, args.dest_ip)
    print(f"Created {args.output} with {count} synthetic packets.")
    print("No network traffic was transmitted; this PCAP is for offline replay only.")


if __name__ == "__main__":
    main()
