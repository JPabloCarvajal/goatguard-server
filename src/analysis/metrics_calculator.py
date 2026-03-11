"""
Network metrics calculator for GOATGuard server.

Takes parsed Zeek connection logs and computes per-device and
per-network metrics. These metrics map directly to the database
tables: DeviceCurrentMetrics, NetworkSnapshot, and TopTalker.

Computed metrics:
    Per device:
        - bandwidth_in/out (bytes per second)
        - tcp_retransmissions (from missed_bytes)
        - failed_connections (states S0, REJ, RSTO, RSTOS0)
        - unique_destinations (distinct IPs contacted)
        - bytes_ratio (sent/received ratio)

    Per network:
        - top talkers (ranked by total consumption)
        - active_connections (total flows in the period)
        - new_connections_per_min (flow count normalized)
        - internal vs external traffic split
        - failed_connections_global (sum across all devices)

Requirements: Sprint 4 (metrics from Zeek analysis)
"""

import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

def _is_local_ip(ip: str) -> bool:
    """Check if an IP belongs to a private/local network.

    Private ranges defined in RFC 1918:
        10.0.0.0/8
        172.16.0.0/12
        192.168.0.0/16
    Plus link-local (169.254.x.x) and IPv6 local (fe80::).
    """
    if ip is None:
        return False
    return (
        ip.startswith("192.168.") or
        ip.startswith("10.") or
        ip.startswith("172.16.") or
        ip.startswith("172.17.") or
        ip.startswith("172.18.") or
        ip.startswith("172.19.") or
        ip.startswith("172.2") or
        ip.startswith("172.30.") or
        ip.startswith("172.31.") or
        ip.startswith("169.254.") or
        ip.startswith("fe80:")
    )
FAILED_STATES = {"S0", "REJ", "RSTO", "RSTOS0", "SH", "SHR", "OTH"}

def calculate_device_metrics(connections: list[dict],
                             period_seconds: float = 30.0) -> dict:
    """Calculate per-device metrics from parsed connections.

    Groups connections by source IP and computes bandwidth,
    failed connections, retransmissions, unique destinations,
    and traffic ratio for each device.

    Args:
        connections: List of parsed connection dicts from conn.log.
        period_seconds: Duration of the PCAP capture period.

    Returns:
        Dictionary mapping device IP to its computed metrics.
        Example: {
            "192.168.1.5": {
                "bandwidth_in": 15234.5,
                "bandwidth_out": 8921.3,
                "tcp_retransmissions": 3,
                "failed_connections": 1,
                "unique_destinations": 12,
                "bytes_ratio": 1.71,
                "total_bytes": 724680,
            }
        }
    """
    devices = defaultdict(lambda: {
        "bytes_in": 0,
        "bytes_out": 0,
        "retransmissions": 0,
        "failed": 0,
        "destinations": set(),
        "total_bytes": 0,
    })

    for conn in connections:
        src_ip = conn.get("src_ip")
        dst_ip = conn.get("dst_ip")

        if not src_ip:
            continue

        orig_bytes = conn.get("orig_bytes", 0)
        resp_bytes = conn.get("resp_bytes", 0)
        missed = conn.get("missed_bytes", 0)
        state = conn.get("conn_state", "")

        # Attribute traffic to the local device
        if _is_local_ip(src_ip):
            devices[src_ip]["bytes_out"] += orig_bytes
            devices[src_ip]["bytes_in"] += resp_bytes
            devices[src_ip]["total_bytes"] += orig_bytes + resp_bytes
            devices[src_ip]["destinations"].add(dst_ip)

            if missed > 0:
                devices[src_ip]["retransmissions"] += 1

            if state in FAILED_STATES:
                devices[src_ip]["failed"] += 1

        # Also track if destination is local (internal traffic)
        if _is_local_ip(dst_ip):
            devices[dst_ip]["bytes_in"] += orig_bytes
            devices[dst_ip]["bytes_out"] += resp_bytes
            devices[dst_ip]["total_bytes"] += orig_bytes + resp_bytes

    # Convert to final format with rates
    result = {}
    for ip, data in devices.items():
        bytes_in = data["bytes_in"]
        bytes_out = data["bytes_out"]

        result[ip] = {
            "bandwidth_in": bytes_in / period_seconds,
            "bandwidth_out": bytes_out / period_seconds,
            "tcp_retransmissions": data["retransmissions"],
            "failed_connections": data["failed"],
            "unique_destinations": len(data["destinations"]),
            "bytes_ratio": round(bytes_out / bytes_in, 4) if bytes_in > 0 else 0.0,
            "total_bytes": data["total_bytes"],
        }

    logger.info(f"Calculated metrics for {len(result)} devices")
    return result

def calculate_network_metrics(connections: list[dict],
                              period_seconds: float = 30.0) -> dict:
    """Calculate network-wide metrics from parsed connections.

    Args:
        connections: List of parsed connection dicts from conn.log.
        period_seconds: Duration of the PCAP capture period.

    Returns:
        Dictionary with network-level metrics.
    """
    total_failed = 0
    internal_bytes = 0
    external_bytes = 0

    for conn in connections:
        src_ip = conn.get("src_ip")
        dst_ip = conn.get("dst_ip")
        orig_bytes = conn.get("orig_bytes", 0)
        resp_bytes = conn.get("resp_bytes", 0)
        state = conn.get("conn_state", "")
        total = orig_bytes + resp_bytes

        if state in FAILED_STATES:
            total_failed += 1

        if _is_local_ip(src_ip) and _is_local_ip(dst_ip):
            internal_bytes += total
        else:
            external_bytes += total

    active = len(connections)
    connections_per_min = (active / period_seconds) * 60

    result = {
        "active_connections": active,
        "new_connections_per_min": int(connections_per_min),
        "failed_connections_global": total_failed,
        "internal_traffic_bytes": internal_bytes,
        "external_traffic_bytes": external_bytes,
    }

    logger.info(
        f"Network metrics: {active} connections, "
        f"{total_failed} failed, "
        f"internal={internal_bytes}, external={external_bytes}"
    )
    return result

def calculate_top_talkers(device_metrics: dict, top_n: int = 10) -> list[dict]:
    """Rank devices by total bandwidth consumption.

    Args:
        device_metrics: Output from calculate_device_metrics().
        top_n: How many top consumers to return.

    Returns:
        Sorted list of dicts with ip, total_consumption, rank, is_hog.
        A device is marked as 'hog' if it consumes more than 2x the
        average consumption across all devices.
    """
    if not device_metrics:
        return []

    # Sort by total bytes descending
    sorted_devices = sorted(
        device_metrics.items(),
        key=lambda item: item[1]["total_bytes"],
        reverse=True,
    )

    # Calculate average for hog detection
    total_all = sum(m["total_bytes"] for m in device_metrics.values())
    device_count = len(device_metrics)
    average = total_all / device_count if device_count > 0 else 0
    hog_threshold = average * 2

    top_talkers = []
    for rank, (ip, metrics) in enumerate(sorted_devices[:top_n], start=1):
        top_talkers.append({
            "ip": ip,
            "total_consumption": metrics["total_bytes"],
            "rank": rank,
            "is_hog": metrics["total_bytes"] > hog_threshold,
        })

    logger.info(
        f"Top talkers: {len(top_talkers)} ranked, "
        f"hog threshold={hog_threshold:.0f} bytes"
    )
    return top_talkers


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    logging.basicConfig(level=logging.DEBUG)

    from pathlib import Path
    from src.analysis.log_parser import parse_conn_log

    log_dir = Path("zeek_output")
    
    # Find first directory with conn.log
    for subdir in sorted(log_dir.iterdir()):
        if subdir.is_dir() and (subdir / "conn.log").exists():
            log_dir = subdir
            break

    connections = parse_conn_log(log_dir)

    if not connections:
        # Try root zeek_output if no subdirectories
        connections = parse_conn_log(Path("zeek_output"))

    print(f"\n=== DEVICE METRICS ===")
    device_metrics = calculate_device_metrics(connections)
    for ip, metrics in device_metrics.items():
        print(
            f"  {ip}: "
            f"in={metrics['bandwidth_in']:.1f} B/s, "
            f"out={metrics['bandwidth_out']:.1f} B/s, "
            f"retrans={metrics['tcp_retransmissions']}, "
            f"failed={metrics['failed_connections']}, "
            f"destinations={metrics['unique_destinations']}, "
            f"ratio={metrics['bytes_ratio']}"
        )

    print(f"\n=== NETWORK METRICS ===")
    net_metrics = calculate_network_metrics(connections)
    for key, value in net_metrics.items():
        print(f"  {key}: {value}")

    print(f"\n=== TOP TALKERS ===")
    top = calculate_top_talkers(device_metrics)
    for t in top:
        hog = " [HOG]" if t["is_hog"] else ""
        print(f"  #{t['rank']} {t['ip']}: {t['total_consumption']} bytes{hog}")