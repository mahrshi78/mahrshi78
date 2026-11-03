"""Create a human-review response queue from Suricata EVE alerts."""
from __future__ import annotations

import argparse
import csv
import ipaddress
from collections import defaultdict
from pathlib import Path

from tools.eve_utils import load_alerts


def build_review_queue(alerts: list[dict]) -> list[dict]:
    """Aggregate alert sources into a manual containment-review queue."""
    grouped: dict[str, list[dict]] = defaultdict(list)

    for alert in alerts:
        source_ip = alert.get("src_ip", "")
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            continue
        grouped[source_ip].append(alert)

    rows = []
    labels = {1: "High", 2: "Medium", 3: "Low"}
    for source_ip, events in grouped.items():
        first = min(item["timestamp"] for item in events)
        last = max(item["timestamp"] for item in events)
        priorities = [item["severity"] for item in events if item["severity"] > 0]
        highest = min(priorities, default=0)
        rows.append({
            "source_ip": source_ip,
            "alert_count": len(events),
            "highest_severity": labels.get(highest, "Info"),
            "first_seen": first,
            "last_seen": last,
            "recommended_action": (
                "Review host ownership and related events; isolate or block "
                "only after analyst approval."
            ),
        })

    return sorted(rows, key=lambda item: (-item["alert_count"], item["source_ip"]))


def write_review_queue(rows: list[dict], output: str | Path) -> None:
    """Write the review queue as CSV for an operator to assess."""
    fields = [
        "source_ip", "alert_count", "highest_severity",
        "first_seen", "last_seen", "recommended_action",
    ]
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eve", default="logs/eve.json", help="Path to Suricata eve.json")
    parser.add_argument("--output", default="response_queue.csv", help="Output CSV review queue")
    args = parser.parse_args()

    alerts = load_alerts(args.eve)
    rows = build_review_queue(alerts)
    write_review_queue(rows, args.output)
    print(f"Created analyst review queue: {args.output} ({len(rows)} source IPs)")
    print("No firewall changes were made; review and approve containment manually.")


if __name__ == "__main__":
    main()
