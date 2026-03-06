"""Received header parsing and routing analysis."""

import re
from datetime import datetime, timezone
from typing import Optional

from emltriage.core.models import RoutingHop
from emltriage.utils.constants import RECEIVED_PATTERNS, RE_IPV4
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


def extract_ip_from_host(host: str) -> Optional[str]:
    """Extract IP address from host string.
    
    Args:
        host: Host string (may contain IP in brackets)
        
    Returns:
        IP address or None
    """
    # Check for IP in brackets [1.2.3.4]
    bracket_match = re.search(r'\[([0-9.]+)\]', host)
    if bracket_match:
        return bracket_match.group(1)
    
    # Check for IP at start
    match = RE_IPV4.match(host)
    if match:
        return match.group()
    
    return None


def is_private_ip(ip: str) -> bool:
    """Check if IP is private/RFC 1918.
    
    Args:
        ip: IP address
        
    Returns:
        True if private
    """
    from emltriage.utils.constants import PRIVATE_IP_RANGES
    
    try:
        parts = ip.split('.')
        if len(parts) == 4:
            ip_int = (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
            for start, end in PRIVATE_IP_RANGES:
                if start <= ip_int <= end:
                    return True
    except (ValueError, IndexError):
        pass
    
    return False


def parse_received_value(value: str) -> dict:
    """Parse a single Received header value.
    
    Args:
        value: Raw Received header value
        
    Returns:
        Dictionary with parsed components
    """
    result = {
        'from': None,
        'by': None,
        'with': None,
        'id': None,
        'for': None,
        'date_raw': None,
        'timestamp': None,
    }
    
    # Extract each component
    for key, pattern in RECEIVED_PATTERNS.items():
        match = pattern.search(value)
        if match:
            if key == 'date':
                result['date_raw'] = match.group(1).strip()
                # Try to parse timestamp
                try:
                    from email.utils import parsedate_to_datetime
                    dt = parsedate_to_datetime(result['date_raw'])
                    if dt:
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        else:
                            dt = dt.astimezone(timezone.utc)
                        result['timestamp'] = dt
                except Exception:
                    pass
            else:
                result[key] = match.group(1).strip()
    
    return result


def parse_received_headers(raw_received: list[str]) -> list[RoutingHop]:
    """Parse all Received headers into routing hops.
    
    Args:
        raw_received: List of raw Received header values (in order from newest to oldest)
        
    Returns:
        List of RoutingHop objects
    """
    hops = []
    
    for i, value in enumerate(raw_received):
        parsed = parse_received_value(value)
        
        # Extract IP from 'from' field
        from_ip = None
        is_private = False
        if parsed['from']:
            from_ip = extract_ip_from_host(parsed['from'])
            if from_ip:
                is_private = is_private_ip(from_ip)
        
        # Detect anomalies
        anomalies = []
        
        if is_private:
            anomalies.append('private_ip_in_from_field')
        
        if not parsed['timestamp'] and parsed['date_raw']:
            anomalies.append('unparseable_date')
        elif not parsed['date_raw']:
            anomalies.append('missing_date')
        
        hop = RoutingHop(
            hop_number=i,
            raw_received=value,
            from_host=parsed['from'],
            by_host=parsed['by'],
            with_proto=parsed['with'],
            id=parsed['id'],
            for_address=parsed['for'],
            date_raw=parsed['date_raw'],
            timestamp=parsed['timestamp'],
            is_private_ip=is_private,
            anomalies=anomalies,
        )
        
        hops.append(hop)
    
    # Check for non-monotonic timestamps
    if len(hops) > 1:
        timestamps = [(i, h.timestamp) for i, h in enumerate(hops) if h.timestamp]
        for i in range(len(timestamps) - 1):
            curr_idx, curr_ts = timestamps[i]
            next_idx, next_ts = timestamps[i + 1]
            
            # Timestamps should go from newer (lower index) to older (higher index)
            if curr_ts and next_ts and curr_ts < next_ts:
                hops[curr_idx].anomalies.append('non_monotonic_timestamp')
    
    return hops


def get_routing_summary(hops: list[RoutingHop]) -> dict:
    """Generate routing summary for reporting.
    
    Args:
        hops: List of routing hops
        
    Returns:
        Summary dictionary
    """
    summary = {
        'hop_count': len(hops),
        'private_ip_hops': sum(1 for h in hops if h.is_private_ip),
        'anomaly_count': sum(len(h.anomalies) for h in hops),
        'first_hop_external': None,
        'last_hop_internal': None,
    }
    
    if hops:
        # First hop (most recent) is the last MTA to receive
        first = hops[0]
        summary['first_hop_external'] = {
            'from': first.from_host,
            'by': first.by_host,
            'timestamp': first.timestamp.isoformat() if first.timestamp else None,
        }
        
        # Last hop (oldest) is the origin
        last = hops[-1]
        summary['last_hop_internal'] = {
            'from': last.from_host,
            'by': last.by_host,
            'timestamp': last.timestamp.isoformat() if last.timestamp else None,
        }
    
    return summary
