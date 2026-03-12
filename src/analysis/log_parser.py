"""
Zeek log parser for GOATGuard server.

Parses Zeek's tab-separated log files (conn.log, dns.log, etc.)
into Python dictionaries. Zeek logs have a header section starting
with '#' that defines field names and types, followed by data rows
separated by tab characters.

The parser handles Zeek's special values:
    -       means "unset" (field has no value)
    (empty) means "empty string"

Requirements: Part of Sprint 3 (PCAP analysis pipeline)
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def parse_zeek_log(file_path: Path) -> list[dict]:
    """Parse a Zeek log file into a list of dictionaries.

    Each dictionary represents one row, with field names as keys.
    Zeek's unset values ('-') are converted to None.

    Args:
        file_path: Path to the Zeek log file.

    Returns:
        List of dictionaries, one per log entry.

    Example return value for conn.log:
        [
            {
                "ts": "1773178983.799704",
                "uid": "C7vRSwdXuSQb4Uaq5",
                "id.orig_h": "192.168.1.5",
                "id.orig_p": "8833",
                "id.resp_h": "20.189.172.73",
                "id.resp_p": "443",
                "proto": "tcp",
                "duration": "0.542560",
                "orig_bytes": "1149",
                "resp_bytes": "4890",
                ...
            },
            ...
        ]
    """
    entries = []
    field_names = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                # Skip empty lines
                if not line:
                    continue

                # Parse header lines
                if line.startswith("#"):
                    if line.startswith("#fields"):
                        field_names = line.split("\t")[1:]
                    continue

                # Skip if we haven't found field names yet
                if not field_names:
                    continue

                # Parse data row
                values = line.split("\t")
                entry = _build_entry(field_names, values)
                entries.append(entry)

    except OSError as e:
        logger.error(f"Cannot read log file {file_path}: {e}")

    logger.info(f"Parsed {len(entries)} entries from {file_path.name}")
    return entries

def _build_entry(field_names: list[str], values: list[str]) -> dict:
    """Convert a row of values into a dictionary using field names.

    Handles Zeek's special values:
        '-' (unset) becomes None
        '(empty)' becomes empty string ''

    Args:
        field_names: Column names from the #fields header.
        values: Tab-separated values from a data row.

    Returns:
        Dictionary mapping field names to values.
    """
    entry = {}
    for i, name in enumerate(field_names):
        if i < len(values):
            value = values[i]
            if value == "-":
                entry[name] = None
            elif value == "(empty)":
                entry[name] = ""
            else:
                entry[name] = value
        else:
            entry[name] = None
    return entry

def parse_conn_log(log_dir: Path) -> list[dict]:
    """Parse conn.log and convert numeric fields.

    Converts string values to appropriate Python types:
    timestamps to float, byte counts to int, durations to float.

    Args:
        log_dir: Directory containing Zeek log files.

    Returns:
        List of connection records with typed values.
    """
    file_path = log_dir / "conn.log"
    if not file_path.exists():
        logger.warning("conn.log not found")
        return []

    raw_entries = parse_zeek_log(file_path)
    connections = []

    for entry in raw_entries:
        conn = {
            "ts": _to_float(entry.get("ts")),
            "uid": entry.get("uid"),
            "src_ip": entry.get("id.orig_h"),
            "src_port": _to_int(entry.get("id.orig_p")),
            "dst_ip": entry.get("id.resp_h"),
            "dst_port": _to_int(entry.get("id.resp_p")),
            "proto": entry.get("proto"),
            "service": entry.get("service"),
            "duration": _to_float(entry.get("duration")),
            "orig_bytes": _to_int(entry.get("orig_bytes")),
            "resp_bytes": _to_int(entry.get("resp_bytes")),
            "conn_state": entry.get("conn_state"),
            "orig_pkts": _to_int(entry.get("orig_pkts")),
            "resp_pkts": _to_int(entry.get("resp_pkts")),
            "missed_bytes": _to_int(entry.get("missed_bytes")),
            "history": entry.get("history"),
        }
        connections.append(conn)

    logger.info(f"Parsed {len(connections)} connections from conn.log")
    return connections

def parse_dns_log(log_dir: Path) -> list[dict]:
    """Parse dns.log and extract DNS query information.

    Args:
        log_dir: Directory containing Zeek log files.

    Returns:
        List of DNS query records with typed values.
    """
    file_path = log_dir / "dns.log"
    if not file_path.exists():
        logger.warning("dns.log not found")
        return []

    raw_entries = parse_zeek_log(file_path)
    queries = []

    for entry in raw_entries:
        query = {
            "ts": _to_float(entry.get("ts")),
            "src_ip": entry.get("id.orig_h"),
            "dst_ip": entry.get("id.resp_h"),
            "proto": entry.get("proto"),
            "query": entry.get("query"),
            "qtype_name": entry.get("qtype_name"),
            "rcode_name": entry.get("rcode_name"),
            "rtt": _to_float(entry.get("rtt")),
            "answers": entry.get("answers"),
        }
        queries.append(query)

    logger.info(f"Parsed {len(queries)} DNS queries from dns.log")
    return queries


def _to_float(value) -> float:
    """Convert a string to float, returning 0.0 if None or invalid."""
    if value is None:
        return 0.0
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


def _to_int(value) -> int:
    """Convert a string to int, returning 0 if None or invalid."""
    if value is None:
        return 0
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0
    

if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    logging.basicConfig(level=logging.DEBUG)

    log_dir = Path("zeek_output")

    print("\n=== CONNECTIONS ===")
    connections = parse_conn_log(log_dir)
    for conn in connections[:5]:
        print(
            f"  {conn['src_ip']}:{conn['src_port']} -> "
            f"{conn['dst_ip']}:{conn['dst_port']} "
            f"({conn['proto']}) "
            f"bytes={conn['orig_bytes']}+{conn['resp_bytes']} "
            f"duration={conn['duration']}s "
            f"state={conn['conn_state']}"
        )

    print(f"\n  Total connections: {len(connections)}")

    print("\n=== DNS QUERIES ===")
    queries = parse_dns_log(log_dir)
    for q in queries[:5]:
        print(
            f"  {q['src_ip']} -> {q['query']} "
            f"(rtt={q['rtt']}s)"
        )

    print(f"\n  Total DNS queries: {len(queries)}")