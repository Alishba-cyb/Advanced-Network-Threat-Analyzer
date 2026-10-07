#!/usr/bin/env python3
"""
logger.py — Structured Security Event & Metrics Exporter
=====================================================================

Provides `SecurityEventLogger`, a thread-safe structured JSON logging
facility used by sniffer.py to persist:

  * Flagged security events (plaintext leaks, SYN floods, port scans,
    parser errors)
  * General packet-level summaries (optional, for full-session audit
    trails)
  * Session lifecycle events (start/end, with summary statistics)

Output format: newline-delimited JSON (NDJSON) written to
`logs/traffic_audit.json`. NDJSON is used instead of a single JSON array
so the log file remains valid/appendable even if the process is
terminated mid-session, and so it can be tailed/streamed by external
tools (e.g. `tail -f logs/traffic_audit.json | jq`).

Each line is one self-contained JSON object with a `record_type` field
distinguishing "security_event", "packet_summary", and "session_event".
"""

import json
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


class SecurityEventLogger:
    """
    Thread-safe NDJSON logger. Safe to call concurrently from Scapy's
    sniff() callback thread and the main/dashboard thread.
    """

    def __init__(self, log_path: str = "logs/traffic_audit.json", also_log_packets: bool = False):
        """
        Parameters
        ----------
        log_path:
            Destination file for structured NDJSON log lines.
        also_log_packets:
            If True, every parsed packet (not just flagged events) is
            persisted via log_packet_summary(). This can grow the log
            file quickly on busy interfaces, so it defaults to False —
            flagged security events are always logged regardless.
        """
        self.log_path = Path(log_path)
        self.also_log_packets = also_log_packets
        self._lock = threading.Lock()
        self._event_count = 0

        self._ensure_log_directory()

    # -- Setup -------------------------------------------------------------

    def _ensure_log_directory(self) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            # Touch the file so it exists even before the first event,
            # and so permission problems surface immediately at startup
            # rather than silently during capture.
            if not self.log_path.exists():
                self.log_path.touch()
        except OSError as exc:
            print(f"[FATAL] Could not create/access log directory for '{self.log_path}': {exc}")
            raise

    # -- Core write path -----------------------------------------------------

    def _write_line(self, record: dict) -> None:
        """
        Append a single JSON record as one line. Wrapped in try/except so
        that a disk-full or permissions error during capture degrades to
        a printed warning rather than crashing the sniffer.
        """
        line = json.dumps(record, default=str, ensure_ascii=False)
        with self._lock:
            try:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                self._event_count += 1
            except OSError as exc:
                print(f"[WARN] Failed to write audit log entry: {exc}")

    # -- Public logging API -----------------------------------------------

    def log_security_event(
        self,
        event_type: str,
        source_ip: str,
        destination_ip: str,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Persist a flagged security/heuristic event, e.g. SYN_FLOOD,
        PORT_SCAN, PLAINTEXT_CREDENTIAL_LEAK, PARSER_ERROR.
        """
        record = {
            "record_type": "security_event",
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "details": details or {},
        }
        self._write_line(record)

    def log_packet_summary(self, packet_dict: dict[str, Any]) -> None:
        """
        Optionally persist a per-packet summary line. Only writes if
        `also_log_packets=True` was set at construction, OR if the
        packet's own status indicates it was already flagged (so flagged
        packets always get full context even if general logging is off).
        """
        if not self.also_log_packets and packet_dict.get("status", "OK") == "OK":
            return
        record = {
            "record_type": "packet_summary",
            **packet_dict,
        }
        self._write_line(record)

    def log_session_event(self, phase: str, payload: dict[str, Any]) -> None:
        """
        Persist a session lifecycle marker, e.g. SESSION_START /
        SESSION_END, with an arbitrary summary payload (interface,
        filter, duration, packet counts, etc.).
        """
        record = {
            "record_type": "session_event",
            "timestamp": datetime.now().isoformat(),
            "phase": phase,
            "payload": payload,
        }
        self._write_line(record)

    # -- Utility -------------------------------------------------------------

    @property
    def event_count(self) -> int:
        with self._lock:
            return self._event_count

    def read_all_events(self) -> list[dict]:
        """
        Convenience reader: parses the NDJSON log back into a list of
        dicts. Used by reporting/export tooling, not by the sniffer
        itself. Skips any malformed lines defensively rather than
        raising, since a log file could in principle be truncated by an
        unexpected shutdown.
        """
        events = []
        if not self.log_path.exists():
            return events
        with open(self.log_path, "r", encoding="utf-8") as fh:
            for line_number, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    print(f"[WARN] Skipping malformed log line {line_number} in {self.log_path}")
                    continue
        return events


# ---------------------------------------------------------------------------
# Standalone CLI: quick summary report over an existing audit log
# ---------------------------------------------------------------------------

def _print_summary_report(log_path: str) -> None:
    """
    Reads an existing NDJSON audit log and prints a quick human-readable
    breakdown of event types and top offending source IPs. Useful for
    post-session review: `python3 logger.py --report logs/traffic_audit.json`
    """
    logger = SecurityEventLogger(log_path=log_path)
    events = logger.read_all_events()

    security_events = [e for e in events if e.get("record_type") == "security_event"]
    session_events = [e for e in events if e.get("record_type") == "session_event"]

    print("=" * 60)
    print(f" Audit Log Report: {log_path}")
    print("=" * 60)
    print(f" Total log lines        : {len(events)}")
    print(f" Security events flagged: {len(security_events)}")
    print(f" Session markers        : {len(session_events)}")

    if security_events:
        by_type: dict[str, int] = {}
        by_source: dict[str, int] = {}
        for e in security_events:
            by_type[e["event_type"]] = by_type.get(e["event_type"], 0) + 1
            by_source[e["source_ip"]] = by_source.get(e["source_ip"], 0) + 1

        print("\n By event type:")
        for k, v in sorted(by_type.items(), key=lambda kv: -kv[1]):
            print(f"   {k:<28} {v}")

        print("\n Top source IPs:")
        for k, v in sorted(by_source.items(), key=lambda kv: -kv[1])[:10]:
            print(f"   {k:<22} {v} event(s)")
    print("=" * 60)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Audit log utility for traffic_audit.json")
    parser.add_argument(
        "--report", metavar="LOG_PATH", default="logs/traffic_audit.json",
        help="Print a summary report over an existing NDJSON audit log.",
    )
    args = parser.parse_args()
    _print_summary_report(args.report)
