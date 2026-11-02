"""Network Packet Analyzer.

Live packet monitoring for networks you own or are authorized to inspect.

Install dependencies with: python -m pip install -r requirements.txt
On Windows, install Npcap. Use only the minimum privileges needed to capture.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime

try:
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, sniff
except ImportError:
    print(
        "Scapy is missing. Install dependencies with: "
        "python -m pip install -r requirements.txt"
    )
    raise SystemExit(1)


MAX_TRACKED_ADDRESSES = 2048
MAX_DISPLAY_TEXT = 120
DEFAULT_PACKET_LIMIT = 1000
OTHER_ADDRESS_BUCKET = "<other addresses>"


def safe_terminal_text(value: object, limit: int = MAX_DISPLAY_TEXT) -> str:
    """Make packet-derived text safe for terminal output and cap its length."""
    text = str(value)
    printable = "".join(char if char.isprintable() else "?" for char in text)
    if len(printable) > limit:
        return printable[: max(0, limit - 3)] + "..."
    return printable


def increment_bounded(counter: Counter[str], key: str, limit: int) -> None:
    """Count a value without allowing unbounded key growth."""
    if key in counter:
        counter[key] += 1
    elif len(counter) < limit:
        counter[key] = 1
    else:
        counter[OTHER_ADDRESS_BUCKET] += 1


class PacketAnalyzer:
    """Capture and summarize network packets."""

    def __init__(
        self,
        interface: str | None = None,
        capture_filter: str | None = None,
        packet_limit: int = DEFAULT_PACKET_LIMIT,
    ) -> None:
        if packet_limit < 0:
            raise ValueError("packet_limit must be zero or a positive integer")
        if capture_filter is not None and len(capture_filter) > 256:
            raise ValueError("capture filter must be 256 characters or fewer")

        self.interface = interface
        self.capture_filter = capture_filter
        self.packet_limit = packet_limit
        self.total_packets = 0
        self.protocols: Counter[str] = Counter()
        self.sources: Counter[str] = Counter()
        self.destinations: Counter[str] = Counter()

    @staticmethod
    def banner() -> None:
        print("\033[96m" + "=" * 72)
        print("                      NETWORK PACKET ANALYZER")
        print("=" * 72 + "\033[0m")
        print("  Engine       : Python + Scapy")
        print("  Purpose      : Authorized network traffic monitoring")
        print("  Privacy      : Packet metadata may be sensitive")
        print("  Stop         : Ctrl+C")
        print("=" * 72)

    @staticmethod
    def protocol_name(packet) -> str:
        if packet.haslayer(ARP):
            return "ARP"
        if packet.haslayer(DNS):
            return "DNS"
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        if packet.haslayer(IP):
            return "IP"
        return "OTHER"

    def handle_packet(self, packet) -> None:
        """Print a bounded summary of a captured packet."""
        self.total_packets += 1
        protocol = self.protocol_name(packet)
        self.protocols[protocol] += 1
        timestamp = datetime.now().strftime("%H:%M:%S")

        print("\n" + "-" * 72)
        print(f" PACKET #{self.total_packets:<6} | {timestamp} | {protocol}")
        print("-" * 72)
        print(f" Size         : {len(packet)} bytes")

        if packet.haslayer(Ether):
            print(f" Source MAC   : {safe_terminal_text(packet[Ether].src)}")
            print(f" Dest MAC     : {safe_terminal_text(packet[Ether].dst)}")

        if packet.haslayer(IP):
            src = str(packet[IP].src)
            dst = str(packet[IP].dst)
            increment_bounded(self.sources, src, MAX_TRACKED_ADDRESSES)
            increment_bounded(self.destinations, dst, MAX_TRACKED_ADDRESSES)
            print(f" Source IP    : {safe_terminal_text(src)}")
            print(f" Dest IP      : {safe_terminal_text(dst)}")
            print(f" TTL          : {int(packet[IP].ttl)}")
        elif packet.haslayer(ARP):
            src = str(packet[ARP].psrc)
            dst = str(packet[ARP].pdst)
            increment_bounded(self.sources, src, MAX_TRACKED_ADDRESSES)
            increment_bounded(self.destinations, dst, MAX_TRACKED_ADDRESSES)
            print(f" ARP Sender   : {safe_terminal_text(src)}")
            print(f" ARP Target   : {safe_terminal_text(dst)}")

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print(f" Transport    : TCP {int(tcp.sport)} -> {int(tcp.dport)}")
            print(f" TCP Flags    : {safe_terminal_text(tcp.flags, 16)}")
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print(f" Transport    : UDP {int(udp.sport)} -> {int(udp.dport)}")

        if packet.haslayer(ICMP):
            print(f" ICMP Type    : {int(packet[ICMP].type)}")
            print(f" ICMP Code    : {int(packet[ICMP].code)}")

        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname
            if isinstance(query, bytes):
                query = query.decode("utf-8", errors="replace")
            print(f" DNS Query    : {safe_terminal_text(str(query).rstrip('.'))}")

    def show_statistics(self) -> None:
        print("\n" + "=" * 72)
        print("                         CAPTURE SUMMARY")
        print("=" * 72)
        print(f" Total packets: {self.total_packets}")
        print("\n Protocol distribution:")
        if self.protocols:
            for name, count in self.protocols.most_common():
                print(f"   {name:<12} {count}")
        else:
            print("   No packets captured.")

        print("\n Top source addresses:")
        for address, count in self.sources.most_common(5):
            print(f"   {safe_terminal_text(address):<24} {count}")

        print("\n Top destination addresses:")
        for address, count in self.destinations.most_common(5):
            print(f"   {safe_terminal_text(address):<24} {count}")
        print("=" * 72)

    def run(self) -> None:
        self.banner()
        print(f" Interface    : {safe_terminal_text(self.interface or 'default')}")
        print(f" BPF filter   : {safe_terminal_text(self.capture_filter or 'none')}")
        limit_text = self.packet_limit or "unlimited (explicitly requested)"
        print(f" Packet limit : {limit_text}")
        print("\nCapture only traffic you are authorized to inspect.")
        print("Press Ctrl+C to stop.\n")

        try:
            sniff(
                iface=self.interface,
                filter=self.capture_filter,
                prn=self.handle_packet,
                store=False,
                count=self.packet_limit,
            )
        except PermissionError:
            print("\nPermission denied. Use an approved capture account or privilege.")
        except OSError as exc:
            print(f"\nCapture error: {safe_terminal_text(exc)}")
            print("Verify Npcap/libpcap, interface name, and capture permissions.")
        except KeyboardInterrupt:
            print("\nCapture stopped by user.")
        finally:
            self.show_statistics()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Monitor packets on a network you own or are authorized to inspect."
        )
    )
    parser.add_argument("-i", "--interface", help="Network interface name (optional)")
    parser.add_argument(
        "-f",
        "--filter",
        dest="capture_filter",
        help='BPF capture filter, e.g. "tcp" or "port 53" (max 256 chars)',
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=DEFAULT_PACKET_LIMIT,
        help=(
            f"Stop after this many packets (default {DEFAULT_PACKET_LIMIT}; "
            "0 means unlimited)"
        ),
    )
    args = parser.parse_args()
    if args.count < 0:
        parser.error("--count must be zero or a positive integer")
    if args.capture_filter is not None and len(args.capture_filter) > 256:
        parser.error("--filter must be 256 characters or fewer")
    return args


def main() -> None:
    args = parse_args()
    PacketAnalyzer(args.interface, args.capture_filter, args.count).run()


if __name__ == "__main__":
    main()
