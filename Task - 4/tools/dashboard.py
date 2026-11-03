"""Generate a local, filterable HTML dashboard from Suricata EVE alerts."""
from __future__ import annotations

import argparse
import html
from collections import Counter
from pathlib import Path

from tools.eve_utils import load_alerts


def build_dashboard(alerts: list[dict]) -> str:
    """Build a self-contained dashboard; all event text is HTML-escaped."""
    severity_counts = Counter(item["severity_label"] for item in alerts)
    sources = {item["src_ip"] for item in alerts}
    rows = []

    for item in reversed(alerts):
        severity = item["severity_label"].lower()
        destination = item["dest_ip"]
        if item["dest_port"] != "":
            destination = f"{destination}:{item['dest_port']}"
        rows.append(
            "<tr data-severity=\\"{severity}\\">"
            "<td>{timestamp}</td><td><span class=\\"pill {severity}\\">{label}</span></td>"
            "<td>{signature}</td><td>{src}</td><td>{dst}</td><td>{proto}</td><td>{action}</td></tr>".format(
                severity=html.escape(severity, quote=True),
                timestamp=html.escape(item["timestamp"]),
                label=html.escape(item["severity_label"]),
                signature=html.escape(item["signature"]),
                src=html.escape(item["src_ip"]),
                dst=html.escape(destination),
                proto=html.escape(item["proto"]),
                action=html.escape(item["action"]),
            )
        )

    if not rows:
        rows.append('<tr><td colspan="7" class="empty">No Suricata alerts found in this EVE file.</td></tr>')

    card_data = [
        ("Total alerts", len(alerts), "total"),
        ("High", severity_counts["High"], "high"),
        ("Medium", severity_counts["Medium"], "medium"),
        ("Low", severity_counts["Low"], "low"),
        ("Source IPs", len(sources), "sources"),
    ]
    cards = "".join(
        '<article class="card {cls}"><div>{label}</div><strong>{value}</strong></article>'.format(
            cls=cls, label=html.escape(label), value=value
        )
        for label, value, cls in card_data
    )

    template = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CodSoft Task 4 | NIDS Dashboard</title>
<style>
:root{font-family:Segoe UI,Arial,sans-serif;color:#17243b;background:#f3f6fb}
body{margin:0}.wrap{max-width:1250px;margin:auto;padding:28px 22px}
header{background:#10213d;color:white;padding:25px 0}
header .wrap{padding-top:0;padding-bottom:0}h1{margin:0 0 6px;font-size:26px}
.sub{color:#c9d8ec;font-size:14px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:14px;margin:24px 0}
.card{background:white;border:1px solid #dce5f0;border-radius:13px;padding:18px;box-shadow:0 6px 22px #10213d0b}
.card div{font-size:13px;color:#65758b}.card strong{display:block;font-size:28px;margin-top:6px}
.high strong{color:#b42335}.medium strong{color:#b36b00}.low strong{color:#087a55}
.panel{background:white;border:1px solid #dce5f0;border-radius:13px;padding:18px;overflow:hidden}
.controls{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}
input,select{padding:10px 12px;border:1px solid #cbd6e4;border-radius:8px;font:inherit}
input{flex:1;min-width:210px}.table-wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:11px 9px;border-bottom:1px solid #e5ebf3;white-space:nowrap}
th{background:#f4f7fb;color:#4d5f77}.pill{font-weight:700;border-radius:999px;padding:4px 8px}
.pill.high{background:#fdebed;color:#a21d31}.pill.medium{background:#fff3d9;color:#8a5700}
.pill.low{background:#e6f6ee;color:#087a55}.pill.info{background:#eef2f7;color:#566579}
.empty{text-align:center;color:#64748b;padding:28px}
footer{color:#64748b;font-size:12px;margin-top:18px}
@media(max-width:600px){.wrap{padding:18px 12px}h1{font-size:22px}}
</style></head><body>
<header><div class="wrap"><h1>Network Intrusion Detection Dashboard</h1>
<div class="sub">CodSoft Cyber Security Internship · Task 4 · Suricata EVE alerts</div></div></header>
<main class="wrap"><section class="cards">__CARDS__</section>
<section class="panel"><h2>Detected events</h2>
<div class="controls"><input id="search" type="search" placeholder="Search signature or IP address">
<select id="severity"><option value="">All severities</option><option value="high">High</option>
<option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select></div>
<div class="table-wrap"><table id="alerts"><thead><tr><th>Timestamp</th><th>Severity</th><th>Signature</th>
<th>Source IP</th><th>Destination</th><th>Protocol</th><th>Action</th></tr></thead>
<tbody>__ROWS__</tbody></table></div></section>
<footer>Generated from Suricata EVE JSON. Alerts are indicators for analyst review, not proof of compromise.</footer>
</main><script>
const search=document.getElementById('search'),severity=document.getElementById('severity');
function filterRows(){const q=search.value.toLowerCase(),s=severity.value;
document.querySelectorAll('#alerts tbody tr').forEach(row=>{
const matchText=row.innerText.toLowerCase().includes(q);
const matchSeverity=!s||row.dataset.severity===s;
row.hidden=!(matchText&&matchSeverity);
});}
search.addEventListener('input',filterRows);severity.addEventListener('change',filterRows);
</script></body></html>"""
    return template.replace("__CARDS__", cards).replace("__ROWS__", "".join(rows))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eve", default="logs/eve.json", help="Path to Suricata eve.json")
    parser.add_argument("--output", default="dashboard.html", help="Output HTML dashboard")
    args = parser.parse_args()

    alerts = load_alerts(args.eve)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(build_dashboard(alerts), encoding="utf-8")
    print(f"Dashboard created: {output.resolve()} ({len(alerts)} alerts)")


if __name__ == "__main__":
    main()
