import json

from tools.dashboard import build_dashboard
from tools.eve_utils import load_alerts


def test_loads_only_alert_events(tmp_path):
    eve = tmp_path / "eve.json"
    events = [
        {"event_type": "flow"},
        {
            "event_type": "alert",
            "src_ip": "198.51.100.10",
            "dest_ip": "192.0.2.8",
            "proto": "TCP",
            "alert": {"signature": "Test alert", "severity": 1},
        },
    ]
    eve.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")
    alerts = load_alerts(eve)
    assert len(alerts) == 1
    assert alerts[0]["severity_label"] == "High"


def test_skips_malformed_json_lines(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text(
        "{bad json}\n"
        '{"event_type":"alert","alert":{"signature":"Valid","severity":2}}\n',
        encoding="utf-8",
    )
    assert len(load_alerts(eve)) == 1


def test_dashboard_escapes_untrusted_signature_text():
    alert = {
        "timestamp": "2026-11-03T05:00:00Z",
        "src_ip": "198.51.100.4",
        "src_port": 50000,
        "dest_ip": "192.0.2.4",
        "dest_port": 80,
        "proto": "TCP",
        "signature": "<script>alert(1)</script>",
        "severity_label": "High",
        "action": "allowed",
    }
    page = build_dashboard([alert])
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<script>alert(1)</script>" not in page


def test_dashboard_contains_filter_and_alert_summary():
    page = build_dashboard([])
    assert "Total alerts" in page
    assert 'id="severity"' in page
    assert "No Suricata alerts found" in page
