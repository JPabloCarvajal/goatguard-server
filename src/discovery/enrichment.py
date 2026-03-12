"""
IP and MAC enrichment for GOATGuard server.

Two enrichment capabilities:

1. OUI Lookup (Layer 2): Resolves the first 3 bytes of a MAC
   address to the hardware manufacturer using the IEEE OUI
   registry. Applied to internal devices in the inventory.
   Example: CC:28:AA → "ASUSTek COMPUTER INC."

2. Reverse DNS (Layer 7): Resolves external IP addresses to
   domain names via PTR records. Applied to destination IPs
   found in Zeek's conn.log during traffic analysis.
   Example: 140.82.113.21 → "github.com"

Results are cached in memory to avoid repeated lookups for
the same IP or MAC across analysis cycles.

Requirements: Device inventory enrichment, traffic context
"""

import logging
import socket
from typing import Optional

logger = logging.getLogger(__name__)

# Cache to avoid repeated DNS lookups (IP → hostname)
_dns_cache: dict[str, Optional[str]] = {}

# Cache for OUI lookups (MAC prefix → vendor)
_oui_cache: dict[str, Optional[str]] = {}

def lookup_oui(mac: str) -> Optional[str]:
    """Resolve a MAC address to its hardware manufacturer.

    Uses the IEEE OUI (Organizationally Unique Identifier) registry.
    The first 3 bytes of a MAC identify the manufacturer:
        CC:28:AA:09:16:04 → CC:28:AA → ASUSTek COMPUTER INC.

    Results are cached to avoid repeated lookups.

    Args:
        mac: MAC address in any common format (colon or dash separated).

    Returns:
        Manufacturer name, or None if not found.
    """
    if not mac:
        return None

    # Normalize and extract OUI prefix (first 3 bytes)
    mac_normalized = mac.replace("-", ":").upper()
    prefix = mac_normalized[:8]  # "CC:28:AA"

    if prefix in _oui_cache:
        return _oui_cache[prefix]

    try:
        from mac_vendor_lookup import MacLookup
        vendor = MacLookup().lookup(mac_normalized)
        _oui_cache[prefix] = vendor
        return vendor
    except Exception:
        _oui_cache[prefix] = None
        return None
    
def resolve_hostname(ip: str) -> Optional[str]:
    """Resolve an IP address to a hostname via reverse DNS (PTR record).

    For external IPs, this typically returns the server's domain name:
        140.82.113.21 → "lb-140-82-113-21-iad.github.com"

    The result is simplified to extract the main domain:
        "lb-140-82-113-21-iad.github.com" → "github.com"

    Results are cached to avoid repeated DNS queries.

    Args:
        ip: IPv4 address to resolve.

    Returns:
        Simplified domain name, or None if resolution fails.
    """
    if not ip:
        return None

    if ip in _dns_cache:
        return _dns_cache[ip]

    try:
        # socket.gethostbyaddr returns (hostname, aliases, addresses)
        raw_hostname = socket.gethostbyaddr(ip)[0]

        # Simplify: extract the main domain from the full hostname
        # "lb-140-82-113-21-iad.github.com" → "github.com"
        simplified = _simplify_hostname(raw_hostname)

        _dns_cache[ip] = simplified
        return simplified

    except socket.herror:
        # No PTR record for this IP
        _dns_cache[ip] = None
        return None
    except Exception:
        _dns_cache[ip] = None
        return None


def _simplify_hostname(hostname: str) -> str:
    """Extract the main domain from a full reverse DNS hostname.

    Many reverse DNS entries include load balancer prefixes or
    infrastructure identifiers that aren't useful for display:
        "lb-140-82-113-21-iad.github.com" → "github.com"
        "server-13-225-148-32.mia3.r.cloudfront.net" → "cloudfront.net"
        "edge-star-mini-shv-01-mia3.facebook.com" → "facebook.com"

    The heuristic: take the last two parts of the hostname.
    For country TLDs (co.uk, com.br), take the last three parts.

    Args:
        hostname: Full reverse DNS hostname.

    Returns:
        Simplified domain name.
    """
    parts = hostname.split(".")

    if len(parts) <= 2:
        return hostname

    # Country code TLDs that need 3 parts: co.uk, com.br, co.jp, etc.
    country_slds = {"co", "com", "org", "net", "ac", "gov"}
    if len(parts) >= 3 and parts[-2] in country_slds and len(parts[-1]) == 2:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])

def _is_local_ip(ip: str) -> bool:
    """Check if an IP is private (RFC 1918)."""
    if not ip:
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
        ip.startswith("fe80:")
    )


def enrich_connections(connections: list[dict]) -> list[dict]:
    """Add hostname information to external IPs in connection records.

    For each connection, if the destination IP is external,
    attempts to resolve it to a domain name via reverse DNS.
    Adds a 'dst_hostname' field to each connection dict.

    Only resolves external IPs — internal IPs are skipped because
    they're already in the device inventory with their own names.

    Args:
        connections: List of parsed connection dicts from conn.log.

    Returns:
        Same list with 'dst_hostname' field added to each entry.
    """
    for conn in connections:
        dst_ip = conn.get("dst_ip")

        if dst_ip and not _is_local_ip(dst_ip):
            hostname = resolve_hostname(dst_ip)
            conn["dst_hostname"] = hostname
        else:
            conn["dst_hostname"] = None

    # Count how many were resolved
    resolved = sum(1 for c in connections if c.get("dst_hostname"))
    logger.info(f"Enriched {resolved}/{len(connections)} connections with hostnames")

    return connections

def enrich_device_vendor(mac: str) -> Optional[str]:
    """Get the hardware vendor for a device's MAC address.

    Convenience wrapper around lookup_oui for use during
    device registration.

    Args:
        mac: Device MAC address.

    Returns:
        Vendor name or None.
    """
    return lookup_oui(mac)