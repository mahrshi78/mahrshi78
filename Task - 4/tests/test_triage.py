from tools.triage import build_review_queue, write_review_queue


def test_groups_source_ips_and_prioritizes_alerts():
    alerts = [
        {
            "src_ip": "198.51.100.10", "timestamp": "2026-11-03T05:00:01Z",
            "severity": 2, "severity_label": "Medium",
        },
        {
            "src_ip": "198.51.100.10", "timestamp": "2026-11-03T05:00:02Z",
            "severity": 1, "severity_label": "High",
        },
        {
            "src_ip": "203.0.113.5", "timestamp": "2026-11-03T05:00:03Z",
            "severity": 3, "severity_label": "Low",
        },
    ]
    queue = build_review_queue(alerts)
    assert queue[0]["source_ip"] == "198.51.100.10"
    assert queue[0]["alert_count"] == 2
    assert queue[0]["highest_severity"] == "High"


def test_ignores_invalid_source_ip():
    rows = build_review_queue([{
        "src_ip": "not-an-ip", "timestamp": "", "severity": 1,
        "severity_label": "High",
    }])
    assert rows == []


def test_writes_csv_review_queue(tmp_path):
    output = tmp_path / "response_queue.csv"
    write_review_queue([], output)
    assert output.exists()
    assert "source_ip,alert_count" in output.read_text(encoding="utf-8")
