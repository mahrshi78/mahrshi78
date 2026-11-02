"""Short, bounded network packet analyzer using Scapy."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime

try:
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, sniff
except ImportError:
    print("Scapy missing. Install: python -m pip install scapy")
    raise SystemExit(1)

MAX_TRACKED = 2048
MAX_TEXT = 120
DEFAULT_COUNT = 1000
DEFAULT_SECONDS = 30
MAX_SECONDS = 3600
OTHER = "<other addresses>"


def safe_terminal_text(value: object, limit: int = MAX_TEXT) -> str:
    """Remove terminal control characters and limit displayed text."""
    text = "".join(ch if ch.isprintable() else "?" for ch in str(value))
    return text if len(text) <= limit else text[:limit - 3] + "..."


def increment_bounded(counter: Counter[str], key: str, limit: int) -> None:
    """Keep address counters within a fixed memory budget."""
    if key in counter:
        counter[key] += 1
    elif len(counter) < limit:
        counter[key] = 1
    else:
        counter[OTHER] += 1


class PacketAnalyzer:
    """Capture and display authorized network traffic."""

    def __init__(self, interface=None, capture_filter=None,
                 packet_limit=DEFAULT_COUNT, duration=DEFAULT_SECONDS):
        if packet_limit < 1:
            raise ValueError("Packet count must be greater than zero")
        if not 1 <= duration <= MAX_SECONDS:
            raise ValueError(f"Duration must be 1-{MAX_SECONDS} seconds")
        if capture_filter and len(capture_filter) > 256:
            raise ValueError("Filter must be 256 characters or fewer")

        self.interface = interface
        self.capture_filter = capture_filter
        self.packet_limit = packet_limit
        self.duration = duration
        self.total = 0
        self.protocols = Counter()
        self.sources = Counter()
        self.destinations = Counter()

    @staticmethod
    def protocol(packet):
        for layer, name in (
            (ARP, "ARP"), (DNS, "DNS"), (TCP, "TCP"),
            (UDP, "UDP"), (ICMP, "ICMP"), (IP, "IP")
        ):
            if packet.haslayer(layer):
                return name
        return "OTHER"

    def show_packet(self, packet):
        self.total += 1
        protocol = self.protocol(packet)
        self.protocols[protocol] += 1
        print(f"\n[{self.total}] {datetime.now():%H:%M:%S} | {protocol} | {len(packet)} bytes")

        if packet.haslayer(Ether):
            print(f"MAC: {safe_terminal_text(packet[Ether].src)} -> "
                  f"{safe_terminal_text(packet[Ether].dst)}")

        if packet.haslayer(IP):
            src, dst = packet[IP].src, packet[IP].dst
            increment_bounded(self.sources, src, MAX_TRACKED)
            increment_bounded(self.destinations, dst, MAX_TRACKED)
            print(f"IP: {src} -> {dst} | TTL: {packet[IP].ttl}")
        elif packet.haslayer(ARP):
            src, dst = packet[ARP].psrc, packet[ARP].pdst
            increment_bounded(self.sources, src, MAX_TRACKED)
            increment_bounded(self.destinations, dst, MAX_TRACKED)
            print(f"ARP: {src} -> {dst}")

        if packet.haslayer(TCP):
            layer = packet[TCP]
            print(f"TCP: {layer.sport} -> {layer.dport} | Flags: {layer.flags}")
        elif packet.haslayer(UDP):
            layer = packet[UDP]
            print(f"UDP: {layer.sport} -> {layer.dport}")

        if packet.haslayer(ICMP):
            print(f"ICMP: type={packet[ICMP].type}, code={packet[ICMP].code}")
        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname
            if isinstance(query, bytes):
                query = query.decode("utf-8", errors="replace")
            print(f"DNS Query: {safe_terminal_text(query)}")

    def summary(self):
        print("\n" + "=" * 55)
        print(f"CAPTURE SUMMARY | Total packets: {self.total}")
        for name, count in self.protocols.most_common():
            print(f"{name:<10} {count}")
        print("Top sources:", self.sources.most_common(5))
        print("Top destinations:", self.destinations.most_common(5))
        print("=" * 55)

    def run(self):
        print("\nNETWORK PACKET ANALYZER - Python + Scapy")
        print(f"Interface: {self.interface or 'Default'}")
        print(f"Filter: {self.capture_filter or 'None'}")
        print(f"Stops at: {self.packet_limit} packets OR {self.duration} seconds")
        print("Use only authorized networks. Press Ctrl+C to stop early.\n")
        try:
            sniff(iface=self.interface, filter=self.capture_filter,
                  prn=self.show_packet, store=False,
                  count=self.packet_limit, timeout=self.duration)
            print("\nCapture completed: packet or time limit reached.")
        except KeyboardInterrupt:
            print("\nCapture stopped by user.")
        except PermissionError:
            print("\nPermission denied. Check approved capture permissions.")
        except OSError as exc:
            print(f"\nCapture error: {safe_terminal_text(exc)}")
            print("Check Npcap/libpcap and the interface name.")
        finally:
            self.summary()


def main():
    parser = argparse.ArgumentParser(description="Authorized packet analyzer")
    parser.add_argument("-i", "--interface", help="Network interface name")
    parser.add_argument("-f", "--filter", dest="capture_filter",
                        help='BPF filter, for example "tcp" or "port 53"')
    parser.add_argument("-c", "--count", type=int, default=DEFAULT_COUNT,
                        help=f"Packet limit (default {DEFAULT_COUNT})")
    parser.add_argument("--duration", type=int, default=DEFAULT_SECONDS,
                        help=f"Time limit in seconds (default {DEFAULT_SECONDS})")
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be greater than zero")
    if not 1 <= args.duration <= MAX_SECONDS:
        parser.error(f"--duration must be 1-{MAX_SECONDS} seconds")
    if args.capture_filter and len(args.capture_filter) > 256:
        parser.error("--filter must be 256 characters or fewer")
    PacketAnalyzer(args.interface, args.capture_filter,
                   args.count, args.duration).run()


if __name__ == "__main__":
    main()
