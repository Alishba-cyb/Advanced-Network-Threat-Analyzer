#!/usr/bin/env python3
"""
sniffer.py — Advanced Live Packet Sniffer & Network Threat Analyzer
=====================================================================

A defensive, passive network-monitoring utility built on Scapy. It captures
live traffic on a chosen interface, parses Layer 3/4 headers, and runs a
real-time heuristic engine that flags:

  1. Plaintext credential / sensitive-data leakage in unencrypted
     application-layer payloads (HTTP, FTP, SMTP, Telnet, etc.)
  2. SYN-flood-style Denial of Service patterns (high SYN rate, single host)
  3. Port-scanning behavior (rapid unique-port connection attempts from a
     single source host within a sliding time window)

This tool is PASSIVE and READ-ONLY: it never injects, modifies, or
retransmits traffic. It is intended for use on networks and systems you own
or are explicitly authorized to monitor (home lab, your own LAN, or a
sanctioned corporate security-audit engagement).

Author: Principal Network Security Engineering reference implementation
License: MIT (see README.md)
"""

import argparse
import re
import sys
import threading
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf
except ImportError:
    print(
        "[FATAL] Scapy is not installed. Install it with:\n"
        "    pip install scapy\n"
        "On Windows you also need Npcap: https://npcap.com/#download",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from logger import SecurityEventLogger


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Config:
    """Central tunable configuration for the heuristic engine."""

    # Sliding-window duration (seconds) used for both SYN-flood and
    # port-scan detection.
    WINDOW_SECONDS = 10

    # Number of SYN packets from a single source IP within WINDOW_SECONDS
    # that triggers a DoS/SYN-flood flag.
    SYN_FLOOD_THRESHOLD = 50

    # Number of UNIQUE destination ports a single source IP must contact
    # within WINDOW_SECONDS to be flagged as a port scan.
    PORT_SCAN_UNIQUE_PORT_THRESHOLD = 15

    # How many packets/events to retain in the live dashboard view.
    DASHBOARD_MAX_ROWS = 20

    # Sensitive keyword patterns searched for in raw (plaintext) payloads.
    # Case-insensitive, word-boundary-aware where practical.
    SENSITIVE_PATTERNS = [
        re.compile(rb"user(?:name)?=", re.IGNORECASE),
        re.compile(rb"pass(?:word|wd)?=", re.IGNORECASE),
        re.compile(rb"passwd=", re.IGNORECASE),
        re.compile(rb"token=", re.IGNORECASE),
        re.compile(rb"api[_-]?key=", re.IGNORECASE),
        re.compile(rb"secret=", re.IGNORECASE),
        re.compile(rb"session[_-]?id=", re.IGNORECASE),
        re.compile(rb"\bAUTH\s+(LOGIN|PLAIN)\b", re.IGNORECASE),  # SMTP auth
        re.compile(rb"^USER\s+\S+", re.IGNORECASE | re.MULTILINE),  # FTP
        re.compile(rb"^PASS\s+\S+", re.IGNORECASE | re.MULTILINE),  # FTP
        re.compile(rb"Authorization:\s*Basic\s+", re.IGNORECASE),  # HTTP basic
    ]

    # Well-known plaintext protocol ports worth explicitly labeling.
    PLAINTEXT_PORTS = {
        21: "FTP",
        23: "Telnet",
        25: "SMTP",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        3306: "MySQL",
    }


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PacketRecord:
    """Normalized representation of a single captured packet."""

    timestamp: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    tcp_flags: Optional[str]
    status: str = "OK"
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "length": self.length,
            "tcp_flags": self.tcp_flags,
            "status": self.status,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Sliding-window tracker for DoS / port-scan heuristics
# ---------------------------------------------------------------------------

class HeuristicTracker:
    """
    Maintains per-source-IP sliding windows of recent SYN packets and
    recent (destination-port) touches, used to flag SYN floods and
    port-scanning behavior without unbounded memory growth.

    Thread-safe: a single lock guards all mutable state since Scapy's
    sniff() callback and the dashboard render loop run on different
    threads.
    """

    def __init__(self, window_seconds: int = Config.WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self._lock = threading.Lock()

        # src_ip -> deque[timestamp] of SYN packets seen
        self._syn_events: dict[str, deque] = defaultdict(deque)

        # src_ip -> deque[(timestamp, dst_port)] of connection attempts
        self._port_events: dict[str, deque] = defaultdict(deque)

        # src_ip -> set of currently "in window" ports, maintained lazily
        self._already_flagged_scan: dict[str, float] = {}
        self._already_flagged_flood: dict[str, float] = {}

        # Re-flag cooldown so a single sustained attack doesn't spam
        # identical alerts every packet.
        self._flag_cooldown = 5.0  # seconds

    def _prune(self, dq: deque, now: float) -> None:
        while dq and (now - dq[0][0] if isinstance(dq[0], tuple) else now - dq[0]) > self.window_seconds:
            dq.popleft()

    def register_syn(self, src_ip: str) -> bool:
        """
        Record a SYN packet from src_ip. Returns True if this crosses the
        SYN-flood threshold and should be flagged (respecting cooldown).
        """
        now = time.time()
        with self._lock:
            dq = self._syn_events[src_ip]
            dq.append(now)
            self._prune(dq, now)

            if len(dq) >= Config.SYN_FLOOD_THRESHOLD:
                last_flag = self._already_flagged_flood.get(src_ip, 0)
                if now - last_flag >= self._flag_cooldown:
                    self._already_flagged_flood[src_ip] = now
                    return True
        return False

    def register_connection(self, src_ip: str, dst_port: int) -> bool:
        """
        Record a connection attempt (src_ip -> dst_port). Returns True if
        the number of UNIQUE destination ports touched by src_ip within
        the window crosses the port-scan threshold (respecting cooldown).
        """
        now = time.time()
        with self._lock:
            dq = self._port_events[src_ip]
            dq.append((now, dst_port))
            self._prune(dq, now)

            unique_ports = {port for _, port in dq}
            if len(unique_ports) >= Config.PORT_SCAN_UNIQUE_PORT_THRESHOLD:
                last_flag = self._already_flagged_scan.get(src_ip, 0)
                if now - last_flag >= self._flag_cooldown:
                    self._already_flagged_scan[src_ip] = now
                    return True
        return False

    def syn_count(self, src_ip: str) -> int:
        with self._lock:
            return len(self._syn_events.get(src_ip, ()))

    def unique_port_count(self, src_ip: str) -> int:
        with self._lock:
            dq = self._port_events.get(src_ip)
            if not dq:
                return 0
            return len({port for _, port in dq})


# ---------------------------------------------------------------------------
# Payload inspection
# ---------------------------------------------------------------------------

def scan_payload_for_leaks(payload: bytes) -> list[str]:
    """
    Inspect a raw application-layer payload for plaintext sensitive-data
    patterns. Returns a list of human-readable match descriptions (may be
    empty). Designed to be defensive: never raises on malformed payloads.
    """
    findings = []
    if not payload:
        return findings

    try:
        for pattern in Config.SENSITIVE_PATTERNS:
            match = pattern.search(payload)
            if match:
                try:
                    snippet = payload[match.start():match.start() + 40].decode(
                        "utf-8", errors="replace"
                    )
                except Exception:
                    snippet = repr(payload[match.start():match.start() + 40])
                snippet = snippet.replace("\r", " ").replace("\n", " ").strip()
                findings.append(f"pattern='{pattern.pattern.decode(errors='replace')}' snippet='{snippet}'")
    except Exception as exc:  # defensive: never let payload inspection crash the sniffer
        findings.append(f"[payload-scan-error: {exc}]")

    return findings


# ---------------------------------------------------------------------------
# Dashboard rendering
# ---------------------------------------------------------------------------

class Dashboard:
    """
    Renders a live, auto-refreshing terminal table of recent packets and
    security events using `rich`. Falls back to plain stdout printing if
    `rich` is not installed.
    """

    def __init__(self, max_rows: int = Config.DASHBOARD_MAX_ROWS):
        self.max_rows = max_rows
        self.records: deque = deque(maxlen=max_rows)
        self.stats = {
            "total_packets": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "other": 0,
            "alerts": 0,
        }
        self._lock = threading.Lock()
        self.console = Console() if RICH_AVAILABLE else None

    def add_record(self, record: PacketRecord) -> None:
        with self._lock:
            self.records.append(record)
            self.stats["total_packets"] += 1
            proto_key = record.protocol.lower()
            if proto_key in self.stats:
                self.stats[proto_key] += 1
            else:
                self.stats["other"] += 1
            if record.status != "OK":
                self.stats["alerts"] += 1

    def _build_table(self) -> "Table":
        table = Table(
            title=f"Live Network Capture — {self.stats['total_packets']} packets | "
            f"{self.stats['alerts']} alert(s)",
            expand=True,
        )
        table.add_column("Time", style="dim", width=12)
        table.add_column("Proto", width=6)
        table.add_column("Source", width=21)
        table.add_column("Destination", width=21)
        table.add_column("Len", justify="right", width=6)
        table.add_column("Flags", width=8)
        table.add_column("Status", width=28)

        with self._lock:
            rows = list(self.records)

        for r in rows:
            src = f"{r.src_ip}:{r.src_port}" if r.src_port else r.src_ip
            dst = f"{r.dst_ip}:{r.dst_port}" if r.dst_port else r.dst_ip

            if r.status == "OK":
                status_text = Text("OK", style="green")
            elif r.status == "LEAK":
                status_text = Text(f"⚠ CREDENTIAL LEAK: {r.detail[:40]}", style="bold red")
            elif r.status == "SYN_FLOOD":
                status_text = Text(f"⚠ SYN FLOOD: {r.detail}", style="bold red")
            elif r.status == "PORT_SCAN":
                status_text = Text(f"⚠ PORT SCAN: {r.detail}", style="bold yellow")
            else:
                status_text = Text(r.status, style="bold magenta")

            table.add_row(
                r.timestamp.split("T")[1][:8] if "T" in r.timestamp else r.timestamp,
                r.protocol,
                src,
                dst,
                str(r.length),
                r.tcp_flags or "-",
                status_text,
            )
        return table

    def render_once_plain(self, record: PacketRecord) -> None:
        """Fallback renderer when `rich` isn't available."""
        marker = "OK" if record.status == "OK" else f"!! {record.status}"
        print(
            f"[{record.timestamp}] {record.protocol:<5} "
            f"{record.src_ip}:{record.src_port} -> {record.dst_ip}:{record.dst_port} "
            f"len={record.length} flags={record.tcp_flags} status={marker} {record.detail}"
        )


# ---------------------------------------------------------------------------
# Main analyzer engine
# ---------------------------------------------------------------------------

class ThreatAnalyzer:
    """
    Wires together packet parsing, the heuristic tracker, the event
    logger, and the dashboard. Exposes a single `handle_packet` callback
    suitable for passing directly to `scapy.sniff(prn=...)`.
    """

    def __init__(self, event_logger: SecurityEventLogger, dashboard: Dashboard):
        self.event_logger = event_logger
        self.dashboard = dashboard
        self.tracker = HeuristicTracker()
        self._packets_seen = 0
        self._start_time = time.time()

    # -- Layer parsing -----------------------------------------------------

    @staticmethod
    def _tcp_flags_to_str(flags) -> str:
        try:
            return str(flags)
        except Exception:
            return ""

    def _parse_packet(self, pkt) -> Optional[PacketRecord]:
        """
        Convert a raw Scapy packet into a normalized PacketRecord.
        Returns None for packets without an IP layer (nothing to analyze
        at L3/L4 for this tool's purposes).
        """
        if IP not in pkt:
            return None

        ip_layer = pkt[IP]
        timestamp = datetime.now().isoformat()
        length = len(pkt)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if TCP in pkt:
            tcp_layer = pkt[TCP]
            protocol = "TCP"
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            tcp_flags = self._tcp_flags_to_str(tcp_layer.flags)
        elif UDP in pkt:
            udp_layer = pkt[UDP]
            protocol = "UDP"
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
            tcp_flags = None
        elif ICMP in pkt:
            protocol = "ICMP"
            src_port = None
            dst_port = None
            tcp_flags = None
        else:
            protocol = "OTHER"
            src_port = None
            dst_port = None
            tcp_flags = None

        return PacketRecord(
            timestamp=timestamp,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            tcp_flags=tcp_flags,
        )

    # -- Heuristics ----------------------------------------------------

    def _apply_heuristics(self, pkt, record: PacketRecord) -> None:
        """
        Mutates `record.status` / `record.detail` in place based on the
        heuristic engine's findings, and forwards flagged events to the
        structured event logger.
        """
        # 1) SYN-flood / scanning heuristics (TCP only)
        if record.protocol == "TCP" and record.tcp_flags is not None:
            flags = record.tcp_flags
            is_syn_only = "S" in flags and "A" not in flags

            if is_syn_only:
                if self.tracker.register_syn(record.src_ip):
                    count = self.tracker.syn_count(record.src_ip)
                    record.status = "SYN_FLOOD"
                    record.detail = f"{count} SYNs from {record.src_ip} in {Config.WINDOW_SECONDS}s"
                    self.event_logger.log_security_event(
                        event_type="SYN_FLOOD",
                        source_ip=record.src_ip,
                        destination_ip=record.dst_ip,
                        details={
                            "syn_count": count,
                            "window_seconds": Config.WINDOW_SECONDS,
                            "threshold": Config.SYN_FLOOD_THRESHOLD,
                        },
                    )

            if record.dst_port is not None:
                if self.tracker.register_connection(record.src_ip, record.dst_port):
                    unique_ports = self.tracker.unique_port_count(record.src_ip)
                    # Only override status if not already flagged as flood,
                    # a single host can legitimately trigger both.
                    if record.status == "OK":
                        record.status = "PORT_SCAN"
                    record.detail = (record.detail + " | " if record.detail else "") + (
                        f"{unique_ports} unique ports from {record.src_ip} in {Config.WINDOW_SECONDS}s"
                    )
                    self.event_logger.log_security_event(
                        event_type="PORT_SCAN",
                        source_ip=record.src_ip,
                        destination_ip=record.dst_ip,
                        details={
                            "unique_ports_contacted": unique_ports,
                            "window_seconds": Config.WINDOW_SECONDS,
                            "threshold": Config.PORT_SCAN_UNIQUE_PORT_THRESHOLD,
                        },
                    )

        # 2) Plaintext payload leak detection (any protocol carrying Raw data)
        if Raw in pkt:
            try:
                payload_bytes = bytes(pkt[Raw].load)
            except Exception:
                payload_bytes = b""

            findings = scan_payload_for_leaks(payload_bytes)
            if findings:
                record.status = "LEAK"
                record.detail = "; ".join(findings[:2])  # keep dashboard line short
                self.event_logger.log_security_event(
                    event_type="PLAINTEXT_CREDENTIAL_LEAK",
                    source_ip=record.src_ip,
                    destination_ip=record.dst_ip,
                    details={
                        "src_port": record.src_port,
                        "dst_port": record.dst_port,
                        "protocol_guess": Config.PLAINTEXT_PORTS.get(
                            record.dst_port, Config.PLAINTEXT_PORTS.get(record.src_port, "unknown")
                        ),
                        "findings": findings,
                    },
                )

    # -- Public callback -------------------------------------------------

    def handle_packet(self, pkt) -> None:
        """
        Entry point passed to scapy.sniff(prn=...). Must never raise —
        a single malformed packet should never kill the capture loop.
        """
        try:
            record = self._parse_packet(pkt)
            if record is None:
                return

            self._apply_heuristics(pkt, record)

            self._packets_seen += 1
            self.dashboard.add_record(record)
            self.event_logger.log_packet_summary(record.to_dict())

            if not RICH_AVAILABLE:
                self.dashboard.render_once_plain(record)

        except Exception as exc:
            # Defensive catch-all: log and continue, never crash the sniffer
            # over one malformed/unusual packet layout.
            try:
                self.event_logger.log_security_event(
                    event_type="PARSER_ERROR",
                    source_ip="unknown",
                    destination_ip="unknown",
                    details={"error": str(exc)},
                )
            except Exception:
                pass  # logging itself must never crash the capture loop

    def session_summary(self) -> dict:
        elapsed = time.time() - self._start_time
        return {
            "duration_seconds": round(elapsed, 2),
            "total_packets": self._packets_seen,
            "stats": self.dashboard.stats,
        }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Advanced Live Packet Sniffer & Network Threat Analyzer "
        "(passive, defensive network monitoring tool)."
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Network interface to sniff on (e.g. eth0, en0, 'Wi-Fi'). "
        "Defaults to Scapy's auto-detected interface.",
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Number of packets to capture before stopping (0 = unlimited, Ctrl+C to stop).",
    )
    parser.add_argument(
        "-f", "--filter", default="ip", dest="bpf_filter",
        help="BPF capture filter (default: 'ip'). Example: 'tcp port 80'.",
    )
    parser.add_argument(
        "--log-file", default="logs/traffic_audit.json",
        help="Path to the structured JSON audit log (default: logs/traffic_audit.json).",
    )
    parser.add_argument(
        "--no-dashboard", action="store_true",
        help="Disable the live rich dashboard and use plain line-by-line output.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    event_logger = SecurityEventLogger(log_path=args.log_file)
    dashboard = Dashboard()
    analyzer = ThreatAnalyzer(event_logger=event_logger, dashboard=dashboard)

    use_rich_dashboard = RICH_AVAILABLE and not args.no_dashboard

    print("=" * 72)
    print(" Advanced Live Packet Sniffer & Network Threat Analyzer")
    print(" Mode: PASSIVE / READ-ONLY  |  Authorized network auditing only")
    print("=" * 72)
    print(f" Interface : {args.interface or '(auto)'}")
    print(f" BPF filter: {args.bpf_filter}")
    print(f" Log file  : {args.log_file}")
    print(f" Dashboard : {'rich (live)' if use_rich_dashboard else 'plain text'}")
    print("=" * 72)

    if not RICH_AVAILABLE:
        print(
            "[WARN] 'rich' is not installed — falling back to plain text output.\n"
            "       Install it with: pip install rich\n"
        )

    event_logger.log_session_event("SESSION_START", {
        "interface": args.interface or "auto",
        "bpf_filter": args.bpf_filter,
    })

    try:
        if use_rich_dashboard:
            console = Console()
            with Live(dashboard._build_table(), console=console, refresh_per_second=4) as live:
                def _prn(pkt):
                    analyzer.handle_packet(pkt)
                    live.update(dashboard._build_table())

                sniff(
                    iface=args.interface,
                    filter=args.bpf_filter,
                    prn=_prn,
                    count=args.count or 0,
                    store=False,
                )
        else:
            sniff(
                iface=args.interface,
                filter=args.bpf_filter,
                prn=analyzer.handle_packet,
                count=args.count or 0,
                store=False,
            )

    except PermissionError:
        print(
            "\n[FATAL] Permission denied opening the network interface.\n"
            "  Linux/macOS: re-run with 'sudo python3 sniffer.py ...'\n"
            "  Windows    : run your terminal as Administrator and ensure Npcap is installed.",
            file=sys.stderr,
        )
        sys.exit(1)
    except OSError as exc:
        print(f"\n[FATAL] OS-level capture error: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Capture stopped by user (Ctrl+C).")
    except Exception as exc:
        print(f"\n[FATAL] Unexpected error during capture: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        summary = analyzer.session_summary()
        event_logger.log_session_event("SESSION_END", summary)
        print("\n" + "=" * 72)
        print(" Session Summary")
        print("=" * 72)
        print(f" Duration        : {summary['duration_seconds']}s")
        print(f" Total packets   : {summary['total_packets']}")
        print(f" TCP / UDP / ICMP: {summary['stats']['tcp']} / "
              f"{summary['stats']['udp']} / {summary['stats']['icmp']}")
        print(f" Alerts raised   : {summary['stats']['alerts']}")
        print(f" Full audit log  : {args.log_file}")
        print("=" * 72)


if __name__ == "__main__":
    main()
