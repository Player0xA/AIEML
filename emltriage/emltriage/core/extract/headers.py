"""Header extraction utilities."""

import email
from email.header import decode_header
from email.message import EmailMessage
from typing import Any, Optional

from emltriage.core.models import HeaderEntry
from emltriage.utils.constants import IMPORTANT_HEADERS


def decode_header_value(value: str) -> tuple[Optional[str], bool]:
    """Decode RFC 2047 encoded header value.
    
    Args:
        value: Raw header value
        
    Returns:
        Tuple of (decoded_value, was_encoded)
    """
    if not value:
        return None, False
    
    try:
        decoded_parts = decode_header(value)
        result_parts = []
        was_encoded = False
        
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                was_encoded = True
                try:
                    result_parts.append(part.decode(charset or 'utf-8', errors='replace'))
                except (LookupError, UnicodeDecodeError):
                    result_parts.append(part.decode('utf-8', errors='replace'))
            else:
                result_parts.append(part)
        
        return ''.join(result_parts), was_encoded
    except Exception:
        return value, False


def parse_address_header(value: str) -> dict[str, Any]:
    """Parse From/To/Cc header into structured format.
    
    Args:
        value: Header value
        
    Returns:
        Dictionary with display_name, address, domain
    """
    try:
        # Use email.utils for robust parsing
        from email.utils import parseaddr
        
        display_name, address = parseaddr(value)
        
        if not address:
            return {
                "display_name": None,
                "address": value.strip() if value else None,
                "domain": None,
                "local_part": None,
            }
        
        parts = address.split('@')
        if len(parts) == 2:
            local_part, domain = parts
        else:
            local_part, domain = address, None
        
        return {
            "display_name": display_name if display_name else None,
            "address": address,
            "domain": domain,
            "local_part": local_part,
        }
    except Exception:
        return {
            "display_name": None,
            "address": value.strip() if value else None,
            "domain": None,
            "local_part": None,
        }


def parse_date_header(value: str) -> dict[str, Any]:
    """Parse Date header into structured format.
    
    Args:
        value: Date header value
        
    Returns:
        Dictionary with raw, timestamp, and parsed components
    """
    from email.utils import parsedate_to_datetime
    from datetime import timezone
    
    result = {
        "raw": value,
        "timestamp": None,
        "iso": None,
    }
    
    try:
        dt = parsedate_to_datetime(value)
        if dt:
            # Ensure UTC
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            result["timestamp"] = dt.isoformat()
            result["iso"] = dt.isoformat()
    except Exception:
        pass
    
    return result


def extract_headers(msg: EmailMessage) -> list[HeaderEntry]:
    """Extract all headers from email message.
    
    Args:
        msg: Email message object
        
    Returns:
        List of HeaderEntry objects
    """
    headers = []
    
    # Get all headers preserving order
    for name, value in msg.items():
        if not value:
            continue
        
        raw_value = str(value)
        decoded_value, was_encoded = decode_header_value(raw_value)
        
        # Determine if we need structured parsing
        parsed = None
        name_lower = name.lower()
        
        if name_lower in ['from', 'to', 'cc', 'bcc', 'reply-to', 'return-path', 'sender']:
            # Split multiple addresses
            from email.utils import getaddresses
            addresses = getaddresses([decoded_value or raw_value])
            parsed = {
                "addresses": [parse_address_header(f"{dn} <{addr}>" if dn else addr) 
                             for dn, addr in addresses]
            }
        elif name_lower == 'date':
            parsed = parse_date_header(decoded_value or raw_value)
        
        headers.append(HeaderEntry(
            name=name,
            raw_value=raw_value,
            decoded_value=decoded_value if was_encoded else None,
            parsed=parsed,
        ))
    
    return headers


def get_header_value(headers: list[HeaderEntry], name: str, decoded: bool = True) -> Optional[str]:
    """Get first value of a specific header.
    
    Args:
        headers: List of headers
        name: Header name (case-insensitive)
        decoded: Whether to prefer decoded value
        
    Returns:
        Header value or None
    """
    name_lower = name.lower()
    for header in headers:
        if header.name.lower() == name_lower:
            if decoded and header.decoded_value:
                return header.decoded_value
            return header.raw_value
    return None


def get_all_header_values(headers: list[HeaderEntry], name: str) -> list[str]:
    """Get all values for a specific header (for headers that can appear multiple times).
    
    Args:
        headers: List of headers
        name: Header name (case-insensitive)
        
    Returns:
        List of header values
    """
    name_lower = name.lower()
    values = []
    for header in headers:
        if header.name.lower() == name_lower:
            if header.decoded_value:
                values.append(header.decoded_value)
            else:
                values.append(header.raw_value)
    return values
