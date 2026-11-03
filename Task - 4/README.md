# Task - 4: Network Intrusion Detection System (NIDS)

A standalone Suricata-based Network Intrusion Detection System project for the CodSoft Cyber Security Internship. It uses custom alert-only signatures, a Python HTML dashboard for EVE JSON alerts, and a CSV analyst-review queue.

## Project structure

```text
Task - 4/
├── suricata/
│   ├── local.rules
│   └── home-net.example.yaml
├── tools/
│   ├── eve_utils.py
│   ├── dashboard.py
│   └── triage.py
├── sample-data/
│   └── eve_sample.json
├── tests/
│   ├── conftest.py
│   ├── test_dashboard.py
│   ├── test_triage.py
│   └── test_rules.py
├── reports/
│   └── SECURITY_ASSESSMENT.md
├── screenshots/
│   └── README.md
└── README.md
```

## Features

- Suricata custom rules for TCP SYN scan/burst, TCP SYN flood, ICMP echo-request burst, and high-volume SSH connection attempts.
- Alert events written to Suricata EVE JSON output.
- Local HTML dashboard with counts, severity labels, search, and filtering.
- CSV response queue grouped by source IP for analyst review.
- Automated tests for parsing, HTML escaping, severity grouping, CSV output, and signature structure.

## 1. Install Suricata

Download the current Windows 64-bit installer from the official [Suricata download page](https://suricata.io/download/). Follow the installer prompts.

Npcap is required for live packet capture on Windows. For initial offline PCAP replay this dependency can be skipped. See the official [Windows installation notes](https://docs.suricata.io/en/latest/install/windows.html).

## 2. Configure the protected network

Open the installed Suricata configuration file, usually `suricata.yaml`. In its existing `vars.address-groups` section, set `HOME_NET` to your own lab subnet. The example in `suricata/home-net.example.yaml` shows RFC1918 private ranges; narrow this to the actual network you are authorized to monitor.

Confirm that EVE JSON output is enabled and includes alert events. The output file should be named `eve.json`. See the official [EVE JSON output guide](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html).

The custom rules use SIDs 9000001–9000004 and the `alert` action only. They do not drop traffic.

## 3. Validate and run against a PCAP first

Open PowerShell in the `Task - 4` folder. Replace the sample paths below with the actual Suricata config path and an authorized PCAP path.

Validate the installed configuration and local rules:

```powershell
& "C:\Program Files\Suricata\suricata.exe" -T -c "C:\Program Files\Suricata\suricata.yaml" -S ".\suricata\local.rules"
```

Analyze an authorized PCAP:

```powershell
New-Item -ItemType Directory -Force .\logs
& "C:\Program Files\Suricata\suricata.exe" -c "C:\Program Files\Suricata\suricata.yaml" -r "C:\Path\To\authorized-capture.pcap" -S ".\suricata\local.rules" -l ".\logs"
```

The log directory should contain `eve.json` when EVE alert output is enabled. Start with offline PCAP analysis; only move to live monitoring after the rules and logs are working.

## 4. Run authorized live monitoring

After installing and verifying Npcap, run Suricata from an elevated PowerShell terminal and specify the correct capture interface ID:

```powershell
& "C:\Program Files\Suricata\suricata.exe" -c "C:\Program Files\Suricata\suricata.yaml" -i <INTERFACE_ID> -S ".\suricata\local.rules" -l ".\logs"
```

Use live capture only on your own device, lab, or a network for which you have explicit permission. Stop monitoring with Ctrl+C.

## 5. Generate and replay a safe offline test PCAP

The project includes a pure-Python PCAP generator. It writes synthetic Ethernet/IP/TCP SYN and ICMP echo-request packets using the documentation-only TEST-NET source address 198.51.100.24. It does not send traffic onto a network.

From the Task - 4 folder, create the PCAP:

```powershell
.\.venv\Scripts\python.exe -m tools.create_test_pcap --output sample-data\task4-test-traffic.pcap --dest-ip 192.168.1.10
```

The default destination 192.168.1.10 must be inside your configured HOME_NET. If you changed HOME_NET, replace --dest-ip with an IP address inside your authorized lab subnet.

Replay the generated PCAP through Suricata (offline replay only; no network packets are transmitted):

```powershell
New-Item -ItemType Directory -Force .\logs
& "C:\Program Files\Suricata\suricata.exe" -c "C:\Program Files\Suricata\suricata.yaml" -r ".\sample-data\task4-test-traffic.pcap" -S ".\suricata\local.rules" -l ".\logs"
```

Check for local SIDs in fast.log:

```powershell
Select-String -Path .\logs\fast.log -Pattern "9000001|9000002|9000003|9000004"
```

If fast.log is not enabled, inspect eve.json for event_type alert and the local signature IDs. Save genuine output screenshots in screenshots/. The replay validates detection rules against synthetic traffic, not real-world compromise.

## 6. Generate the dashboard and response queue


The supplied EVE file lets you preview the dashboard before Suricata has been installed or run.

Install the Python development tools:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Generate and open the dashboard:

```powershell
.\.venv\Scripts\python.exe -m tools.dashboard --eve sample-data\eve_sample.json --output dashboard.html
Start-Process .\dashboard.html
```

Generate the analyst response queue:

```powershell
.\.venv\Scripts\python.exe -m tools.triage --eve sample-data\eve_sample.json --output response_queue.csv
```

For actual Suricata events, change the EVE input path to `logs/eve.json`.

## 7. Run tests and code-quality checks

```powershell
.\.venv\Scripts\python.exe -m pytest tests -v
.\.venv\Scripts\python.exe -m ruff check tools tests
```

## Detection rules

| SID | Rule | Threshold |
|---|---|---|
| 9000001 | Possible TCP SYN port scan / burst | 12 inbound SYN packets from one source in 10 seconds |
| 9000002 | Possible TCP SYN flood | 100 inbound SYN packets to one destination in 5 seconds |
| 9000003 | ICMP echo-request burst | 10 requests from one source in 5 seconds |
| 9000004 | High-volume SSH connection attempts | 20 SSH SYN attempts from one source in 60 seconds |

These are heuristic thresholds. Tune them for your lab to reduce false positives. An SSH SYN burst indicates repeated connection attempts; it does not prove failed password logins.

## Basic response action

The triage utility creates `response_queue.csv` with source IP, event count, highest observed alert severity, first/last seen timestamps, and a recommended next step. It does not change Windows Firewall or block addresses automatically. Verify a source and obtain analyst approval before containment.

## Automated checks

GitHub Actions: [Task 4 NIDS Checks — successful](https://github.com/mahrshi78/mahrshi78/actions/runs/41598256365). The workflow verified 9 Python tests and Ruff linting.

## Safety and limitations

- Monitor only authorized traffic and systems.
- The included EVE data is synthetic training data using documentation/example IP ranges.
- The sample dashboard proves the reporting code works; it does not prove Suricata has captured packets.
- Suricata 8.0.7 was launched and its configuration/custom-rule load test succeeded locally on Windows. PCAP/live detection evidence is still pending; configuration load alone does not prove alert generation.
- This is a learning IDS workflow, not a replacement for a tuned production SOC deployment.

## Internship

**Organization:** CodSoft  
**Domain:** Cyber Security  
**Task:** 4 — Network Intrusion Detection System

## Local Suricata validation

On 3 November 2026, Suricata 8.0.7 successfully loaded the installed configuration and Task 4 custom rules on the Windows host. Two non-fatal warnings were displayed (missing `threshold.config` and a direction-related optimization warning for SID 9000004). Actual alert generation from an authorized PCAP or live lab traffic is still to be verified.
