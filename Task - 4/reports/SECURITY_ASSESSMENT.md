# Task 4 — Network Intrusion Detection System Report

**Engine:** Suricata  
**Rules:** Four local alert-only signatures  
**Dashboard:** Python standard library HTML report  
**Response:** CSV analyst-review queue  
**Scope:** Authorized lab traffic and supplied EVE sample data

## 1. Objective

Configure Suricata to inspect authorized network traffic, apply custom signatures, generate alerts, and provide a readable event dashboard and basic response workflow.

## 2. Detection rules

| SID | Detection | Trigger |
|---|---|---|
| 9000001 | Possible TCP SYN port scan | 12 or more inbound SYN packets from one source within 10 seconds |
| 9000002 | Possible TCP SYN flood | 100 or more inbound SYN packets to a destination within 5 seconds |
| 9000003 | Possible ICMP echo-request burst | 10 or more inbound ICMP echo requests from one source within 5 seconds |
| 9000004 | High-volume SSH connection attempts | 20 or more inbound SSH SYN connection attempts from one source within 60 seconds |

All supplied signatures use the alert action. They generate events; they do not automatically drop packets.

## 3. Alert dashboard

The Python dashboard reads Suricata EVE JSON alert events and displays:
- Total alert count and unique source IP count.
- High, medium, and low alert counts.
- Timestamp, signature, source, destination, protocol, and Suricata action.
- Text search and severity filtering.

The page escapes values from the EVE log before rendering them.

## 4. Basic response workflow

The triage script groups alert events by source IP and creates response_queue.csv with alert count, highest observed severity, first/last seen timestamps, and a recommended investigation action.

This is a human-review queue, not an automatic firewall block. Analysts should validate the host and related traffic before containment to avoid blocking legitimate systems.

## 5. Test evidence

The Python unit tests cover:
- Filtering EVE JSON to alert events.
- Skipping malformed JSON lines.
- Mapping severity labels.
- HTML escaping of untrusted event text.
- Dashboard search/filter controls.
- Grouping source IPs and creating the response CSV.

GitHub Actions verification on 3 November 2026: [Task 4 NIDS Checks](https://github.com/mahrshi78/mahrshi78/actions/runs/41589721577) completed successfully — **9 tests passed** and Ruff reported **All checks passed**. These checks validate the Python EVE/dashboard/triage utilities and the presence/shape of the local signatures. They do not execute the Suricata engine. Do not mark Suricata packet inspection or live network monitoring as verified until the engine has been installed, its configuration/rules validated, and it has been run against an authorized PCAP or interface.

## 6. Limitations

- Detection thresholds are educational starting points and need tuning for each network.
- A SYN burst is a heuristic signal, not proof of a successful compromise or denial-of-service.
- SSH SYN counts show connection attempts only; they do not prove password failures or a brute-force login.
- The response queue does not change firewall rules.
- Live monitoring on Windows requires a supported capture driver; PCAP replay can be used first.
