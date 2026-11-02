# Task - 1: Network Packet Analyzer

A Python-based command-line network packet analyzer built with **Scapy** for authorized network monitoring and cybersecurity learning.

## Features

- Captures packets from a selected network interface.
- Identifies ARP, DNS, TCP, UDP, ICMP, and IP traffic.
- Displays source/destination IP and MAC metadata, packet size, TTL, transport ports, flags, and DNS query names when available.
- Provides a protocol distribution and top source/destination summary.
- Stops after 1,000 packets or 30 seconds by default, whichever comes first.
- Sanitizes packet-derived terminal text and bounds tracked address counters.

## Project structure

```text
Task - 1/
├── source-code/
│   └── packet_analyzer.py
├── tests/
│   ├── conftest.py
│   └── test_security_helpers.py
├── reports/
│   └── SECURITY_ASSESSMENT.md
├── screenshots/
│   └── README.md
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## Requirements

- Python 3.10 or later
- Scapy 2.6.x
- Windows: Npcap installed; Linux/macOS: approved packet-capture permissions

## Setup (Windows PowerShell)

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r "Task - 1/requirements.txt"
```

## Run

Show command-line help:

```powershell
python "Task - 1/source-code/packet_analyzer.py" --help
```

Capture up to 100 packets:

```powershell
python "Task - 1/source-code/packet_analyzer.py" --count 100 --duration 30
```

Capture TCP packets only:

```powershell
python "Task - 1/source-code/packet_analyzer.py" --filter "tcp" --count 100 --duration 20
```

Capture DNS traffic:

```powershell
python "Task - 1/source-code/packet_analyzer.py" --filter "port 53" --count 50 --duration 15
```

To select an interface:

```powershell
python "Task - 1/source-code/packet_analyzer.py" --interface "Wi-Fi" --count 100 --duration 30
```

The capture stops when either the packet limit or the time limit is reached. The default time limit is 30 seconds; use `--duration 1` through `--duration 3600` to change it. `--count 0` is rejected to prevent accidental unlimited capture. Press `Ctrl+C` to stop manually.

## Tests and static analysis

Install development tools:

```powershell
python -m pip install -r "Task - 1/requirements-dev.txt"
```

Run the checks from the repository root:

```powershell
ruff check "Task - 1/source-code/packet_analyzer.py" "Task - 1/tests/"
bandit -q -r "Task - 1/source-code/packet_analyzer.py"
python -m pytest -q "Task - 1/tests/"
```

A GitHub Actions workflow is configured at `.github/workflows/task-1-security-checks.yml` to run Ruff, Bandit, and Pytest when Task 1 files change.

## Security assessment

The assessment findings, remediation details, test scope, and limitations are documented in [reports/SECURITY_ASSESSMENT.md](./reports/SECURITY_ASSESSMENT.md).

The formatted PDF report is available in the original project repository: [Secure Code Assessment PDF](https://github.com/mahrshi78/Network-Packet-Analyzer/blob/main/Secure-Code-Assessment-Network-Packet-Analyzer.pdf).

## Important limitations and safe use

- Use this tool only on networks and devices you own or are explicitly authorized to inspect.
- Use a narrow capture filter and a finite packet count for routine use.
- IP addresses, MAC addresses, and DNS query names can be sensitive. Mask them before publishing screenshots or videos.
- Do not commit private PCAP files or captured traffic.
- Live packet capture requires Scapy, Npcap/libpcap, a real network interface, and approved capture permissions.
- The automated unit tests cover helper functions; they do **not** verify live packet capture.

## Author

Mahrshi | M.Sc. IT (Cyber Security)
