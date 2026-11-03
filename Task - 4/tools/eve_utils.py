"""Shared helpers for reading Suricata EVE JSON alert records."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SEVERITY_LABELS = {1: "High", 2: "Medium", 3: "Low"}


def load_alerts(eve_path: str | Path) -> list[dict[str, Any]]:
    """Load valid Suricata alert events from an EVE JSON-lines file."""
    alerts: list[dict[str, Any]] = []

    with Path(eve_path).open("r", encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(event, dict) or event.get("event_type") != "alert":
                continue
            alert = event.get("alert")
            if not isinstance(alert, dict):
                continue

            try:
                severity = int(alert.get("severity", 0))
            except (TypeError, ValueError):
                severity = 0

            alerts.append({
                "timestamp": str(event.get("timestamp", "")),
                "src_ip": str(event.get("src_ip", "Unknown")),
                "src_port": event.get("src_port", ""),
                "dest_ip": str(event.get("dest_ip", "Unknown")),
                "dest_port": event.get("dest_port", ""),
                "proto": str(event.get("proto", "Unknown")),
                "signature": str(alert.get("signature", "Unnamed alert")),
                "signature_id": alert.get("signature_id", ""),
                "category": str(alert.get("category", "")),
                "severity": severity,
                "severity_label": SEVERITY_LABELS.get(severity, "Info"),
                "action": str(alert.get("action", "unknown")),
            })

    return alerts
