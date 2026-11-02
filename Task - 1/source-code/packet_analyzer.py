"""Short, bounded network packet analyzer using Scapy."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime

try:
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, sniff
except ImportError:
    print("Scapy missing. Install with: python -m pip install scapy")
    raise SystemExit(1)

MAX_TRACKED_ADDRESSES = 2048
MAX_DISPLAY_TEXT = 120
DEFAULT_PACKET_LIMIT = 1000
DEFAULT_CAPTURE_DURATION = 30
MAX_CAPTURE_DURATION = 3600
OTHER_ADDRESS_BUCKET = "<other addresses>"


def safe_terminal_text(value: object, limit: int = MAX_DISPLAY_TEXT) -> str:
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
        counter[OTHER_ADDRESS_BUCKET] += 1


class PacketAnalyzer:
    """Capture and display authorized network traffic."""

    def __init__(self, interface=None, capture_filter=None,
                 packet_limit=DEFAULT_PACKET_LIMIT,
                 capture_duration=DEFAULT_CAPTURE_DURATION):
        if packet_limit < 1:
            raise ValueError("packet_limit must be a positive integer")
        if not 1 <= capture_duration <= MAX_CAPTURE_DURATION:
            raise ValueError(
                f"capture_duration must be between 1 and {MAX_CAPTURE_DURATION} seconds"
            )
        if capture_filter and len(capture_filter) > 256:
            raise ValueError("Capture filter must be 256 characters or fewer")

        self.interface = interface
        self.capture_filter = capture_filter
        self.packet_limit = packet_limit
        self.capture_duration = capture_duration
        self.total_packets = 0
        self.protocols = Counter()
        self.sources = Counter()
        self.destinations = Counter()

    @staticmethod
    def protocol_name(packet):
        for layer, name in (
            (ARP, "ARP"), (DNS, "DNS"), (TCP, "TCP"),
            (UDP, "UDP"), (ICMP, "ICMP"), (IP, "IP")
        ):
            if packet.haslayer(layer):
                return name
        return "OTHER"

    def show_packet(self, packet):
        self.total_packets += 1
        protocol = self.protocol_name(packet)
        self.protocols[protocol] += 1
        stamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n[{self.total_packets}] {stamp} | {protocol} | {len(packet)} bytes")

        if packet.haslayer(Ether):
            print(f"MAC: {safe_terminal_text(packet[Ether].src)} -> "
                  f"{safe_terminal_text(packet[Ether].dst)}")

        if packet.haslayer(IP):
            src = safe_terminal_text(packet[IP].src)
            dst = safe_terminal_text(packet[IP].dst)
            increment_bounded(self.sources, src, MAX_TRACKED_ADDRESSES)
            increment_bounded(self.destinations, dst, MAX_TRACKED_ADDRESSES)
            print(f"IP: {src} -> {dst} | TTL: {packet[IP].ttl}")
        elif packet.haslayer(ARP):
            src = safe_terminal_text(packet[ARP].psrc)
            dst = safe_terminal_text(packet[ARP].pdst)
            increment_bounded(self.sources, src, MAX_TRACKED_ADDRESSES)
            increment_bounded(self.destinations, dst, MAX_TRACKED_ADDRESSES)
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

    def show_summary(self):
        print("\n" + "=" * 55)
        print(f"CAPTURE SUMMARY | Total packets: {self.total_packets}")
        for name, count in self.protocols.most_common():
            print(f"{name:<10} {count}")
        print("Top sources:", self.sources.most_common(5))
        print("Top destinations:", self.destinations.most_common(5))
        print("=" * 55)

    def run(self):
        print("\nNETWORK PACKET ANALYZER - Python + Scapy")
        print(f"Interface: {self.interface or 'Default'}")
        print(f"Filter: {self.capture_filter or 'None'}")
        print(f"Stop limit: {self.packet_limit} packets OR "
              f"{self.capture_duration} seconds")
        print("Authorized traffic only. Press Ctrl+C to stop early.\n")
        try:
            sniff(
                iface=self.interface,
                filter=self.capture_filter,
                prn=self.show_packet,
                store=False,
                count=self.packet_limit,
                timeout=self.capture_duration,
            )
            print("\nCapture completed: packet or time limit reached.")
        except KeyboardInterrupt:
            print("\nCapture stopped by user.")
        except PermissionError:
            print("\nPermission denied. Check capture permissions.")
        except OSError as exc:
            print(f"\nCapture error: {safe_terminal_text(exc)}")
            print("Check Npcap/libpcap and the interface name.")
        finally:
            self.show_summary()


def main():
    parser = argparse.ArgumentParser(description="Authorized packet analyzer")
    parser.add_argument("-i", "--interface", help="Network interface name")
    parser.add_argument("-f", "--filter", dest="capture_filter",
                        help='BPF filter, e.g. "tcp" or "port 53"')
    parser.add_argument("-c", "--count", type=int,
                        default=DEFAULT_PACKET_LIMIT,
                        help=f"Packet limit (default {DEFAULT_PACKET_LIMIT})")
    parser.add_argument("--duration", type=int,
                        default=DEFAULT_CAPTURE_DURATION,
                        help=f"Time limit in seconds (default {DEFAULT_CAPTURE_DURATION})")
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be greater than zero")
    if not 1 <= args.duration <= MAX_CAPTURE_DURATION:
        parser.error(f"--duration must be 1-{MAX_CAPTURE_DURATION} seconds")
    if args.capture_filter and len(args.capture_filter) > 256:
        parser.error("--filter must be 256 characters or fewer")

    PacketAnalyzer(args.interface, args.capture_filter,
                   args.count, args.duration).run()


if __name__ == "__main__":
    main()
