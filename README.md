# Advanced Live Packet Sniffer & Network Threat Analyzer

A passive, defensive network-monitoring tool built in Python with **Scapy**. It captures live traffic on a chosen interface, parses Layer 3/4 headers in real time, and runs a heuristic engine that flags plaintext credential leakage, SYN-flood patterns, and port-scanning behavior — all displayed on a live terminal dashboard and persisted to a structured JSON audit log.

---

## Executive Summary

Unencrypted protocols (HTTP, FTP, Telnet, SMTP) still appear on internal networks far more often than security teams expect, and basic SYN floods or port scans are frequently the first visible sign of a compromised host. This project demonstrates a lightweight, dependency-minimal way to catch both classes of problem from a single vantage point, without needing a full IDS/IPS deployment.

It is built as a **passive, read-only** monitor: it never injects, modifies, retransmits, or blocks traffic. Its only output is observational — console dashboard rows and structured log lines — making it safe to run on networks you own or are authorized to audit, and straightforward to reason about from a "what does this tool actually do" standpoint.

This repository is intended as a **portfolio / educational reference implementation** showing Layer 3–7 packet parsing, sliding-window traffic heuristics, and structured security logging in clean, production-style Python.

---

## System Architecture

```
                         ┌─────────────────────────┐
                         │   Network Interface      │
                         │   (promiscuous capture)  │
                         └────────────┬─────────────┘
                                      │  scapy.sniff()
                                      ▼
                         ┌─────────────────────────┐
                         │      sniffer.py           │
                         │  ┌───────────────────┐   │
                         │  │  Packet Parser     │   │  L3/L4 header extraction
                         │  │  (IP/TCP/UDP/ICMP) │   │  (IPs, ports, length, flags)
                         │  └─────────┬─────────┘   │
                         │            ▼              │
                         │  ┌───────────────────┐   │
                         │  │ Heuristic Engine   │   │  • Plaintext leak regex scan
                         │  │                    │   │  • SYN-flood sliding window
                         │  │                    │   │  • Port-scan sliding window
                         │  └─────────┬─────────┘   │
                         │            ▼              │
                         │  ┌───────────────────┐   │
                         │  │  Rich Dashboard    │   │  Live terminal table
                         │  └───────────────────┘   │
                         └────────────┬─────────────┘
                                      │  flagged events +
                                      │  (optional) packet summaries
                                      ▼
                         ┌─────────────────────────┐
                         │       logger.py           │
                         │  SecurityEventLogger       │  Thread-safe NDJSON writer
                         └────────────┬─────────────┘
                                      ▼
                         ┌─────────────────────────┐
                         │ logs/traffic_audit.json   │  Append-only structured log
                         └─────────────────────────┘
```

**Design choices worth noting:**

- **NDJSON (newline-delimited JSON)** is used for the audit log instead of a single JSON array, so the file stays valid and appendable even if the process is killed mid-capture, and so it can be tailed live with `tail -f logs/traffic_audit.json | jq`.
- **Sliding-window counters** (per-source-IP deques, pruned by timestamp) back both the SYN-flood and port-scan heuristics, bounding memory growth regardless of session length.
- **Defensive parsing throughout**: every packet callback is wrapped so a single malformed or unusual packet layout can never crash the capture loop — it's logged as a `PARSER_ERROR` event and capture continues.

---

## Technical Features

### Packet Capture & Parsing
- Live capture via `scapy.sniff()` with configurable interface and BPF filter.
- Layer 3 (IP) and Layer 4 (TCP/UDP/ICMP) header extraction: source/destination IP, source/destination port, packet length, TCP flags (SYN/ACK/FIN/RST/PSH/URG).
- Graceful handling of non-IP and unsupported packet layouts.

### Heuristic Threat Detection
- **Plaintext data leak detection** — regex-based inspection of raw application-layer payloads for patterns like `user=`, `pass=`/`passwd=`, `token=`, `api_key=`, `secret=`, HTTP `Authorization: Basic`, and FTP `USER`/`PASS` commands.
- **SYN-flood heuristic** — a sliding time window (default 10s) tracks SYN-only packets per source IP; crossing a configurable threshold (default 50) raises a `SYN_FLOOD` alert.
- **Port-scan heuristic** — the same sliding window tracks unique destination ports contacted per source IP; crossing a configurable threshold (default 15 unique ports) raises a `PORT_SCAN` alert.
- Alert cooldown logic prevents a single sustained attack from spamming duplicate log entries every packet.

### Live Dashboard
- Real-time, auto-refreshing terminal table via `rich` (time, protocol, source, destination, length, TCP flags, status).
- Automatic plain-text fallback if `rich` is not installed, so the tool still runs with zero optional dependencies.

### Structured Logging & Reporting
- Thread-safe NDJSON writer (`logger.py`) shared safely between the capture callback thread and the dashboard render loop.
- Three record types: `security_event`, `packet_summary` (opt-in for full traffic logging), and `session_event` (start/end markers with summary stats).
- Built-in reporting mode: `python3 logger.py --report logs/traffic_audit.json` prints a breakdown of alert types and top offending source IPs from an existing log.

### Defensive Coding Standards
- Every packet-handling path is wrapped in `try/except` — parser errors, payload-decode errors, and disk-write errors all degrade gracefully instead of crashing the session.
- Thread-safe shared state (`threading.Lock`) around all sliding-window counters and the log writer.
- PEP-8-compliant, type-hinted, dataclass-based packet model.

---

## Setup Instructions

### Prerequisites

| Platform | Requirement |
|---|---|
| Linux / macOS | Root privileges (`sudo`) to open a raw socket for packet capture |
| Windows | [Npcap](https://npcap.com/#download) installed, and terminal run as Administrator |
| All platforms | Python 3.10+ |

### 1. Clone and install dependencies

```bash
git clone https://github.com/yourusername/packet-analyzer.git
cd packet-analyzer
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt`:
```
scapy>=2.5.0
rich>=13.0.0
```

> `rich` is optional — the tool automatically falls back to plain-text output if it isn't installed. `scapy` is required.

### 2. Verify interface names

```bash
# Linux/macOS
ip link show
# or
ifconfig

# Windows (run inside Python, requires scapy already installed)
python3 -c "from scapy.all import get_if_list; print(get_if_list())"
```

### 3. Run the sniffer

```bash
# Linux/macOS — root is required to open a raw capture socket
sudo python3 sniffer.py --interface eth0

# Windows — run your terminal as Administrator
python3 sniffer.py --interface "Wi-Fi"
```

---

## Usage Guide

```
usage: sniffer.py [-h] [-i INTERFACE] [-c COUNT] [-f BPF_FILTER]
                   [--log-file LOG_FILE] [--no-dashboard]

-i, --interface     Network interface to sniff on (default: Scapy auto-detect)
-c, --count         Number of packets to capture before stopping (0 = unlimited)
-f, --filter        BPF capture filter (default: "ip")
--log-file          Path to the NDJSON audit log (default: logs/traffic_audit.json)
--no-dashboard      Disable the live rich dashboard, use plain line-by-line output
```

**Examples:**

```bash
# Capture only HTTP traffic on a specific interface
sudo python3 sniffer.py -i eth0 -f "tcp port 80"

# Capture exactly 500 packets, then stop and print a session summary
sudo python3 sniffer.py -i eth0 -c 500

# Run without the rich dashboard (e.g. in a non-interactive CI log)
sudo python3 sniffer.py -i eth0 --no-dashboard

# Review a completed session's audit log
python3 logger.py --report logs/traffic_audit.json
```

**Reading the dashboard:** rows marked `OK` in green are routine traffic. Rows marked `⚠ CREDENTIAL LEAK`, `⚠ SYN FLOOD`, or `⚠ PORT SCAN` are heuristic flags — every flagged row is also written as a `security_event` record in `logs/traffic_audit.json` with full detail (matched pattern, counts, thresholds crossed) for later review.

**Tuning thresholds:** all heuristic thresholds (`WINDOW_SECONDS`, `SYN_FLOOD_THRESHOLD`, `PORT_SCAN_UNIQUE_PORT_THRESHOLD`, and the sensitive-keyword pattern list) live in the `Config` class at the top of `sniffer.py` and are safe to adjust for your environment's normal traffic baseline.

---

## Project Structure

```
packet-analyzer/
├── sniffer.py          # Core capture loop, parser, heuristic engine, dashboard
├── logger.py           # Thread-safe NDJSON structured logger + report CLI
├── requirements.txt
├── logs/
│   └── traffic_audit.json   # Created automatically on first run
└── README.md
```

---

## Disclaimer

This software is a **passive, read-only network-defense utility** provided strictly for educational purposes, personal network diagnostics, and authorized security auditing.

- **Authorized use only.** Only run this tool on networks and systems you own, or for which you have explicit written authorization to monitor (e.g. a sanctioned internal security assessment).
- **No traffic interception beyond passive observation.** This tool does not perform ARP spoofing, MITM interception, traffic injection, or any active attack technique. It observes traffic already visible to the interface it is run on.
- **Local data handling.** Any sensitive data patterns detected (e.g. plaintext credentials) are logged locally to `logs/traffic_audit.json` for defensive review. Treat this log file as sensitive data — restrict its permissions and do not commit it to version control.
- **No warranty.** This software is provided "as is", without warranty of any kind. The author assumes no liability for misuse, unauthorized deployment, or any damages arising from its use.
- **Compliance is the operator's responsibility.** Packet capture may be subject to local laws (e.g. wiretapping statutes) and organizational policy regardless of technical intent. Confirm you have the legal right to monitor the network segment in question before running this tool.

---

## License

MIT License — see `LICENSE` for details.
