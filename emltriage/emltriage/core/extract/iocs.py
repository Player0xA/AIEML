"""IOC extraction from email components."""

import re
from typing import Optional

from emltriage.core.models import IOCEntry, IOCType, URLEntry
from emltriage.utils.constants import (
    RE_DOMAIN,
    RE_EMAIL,
    RE_HASH_MD5,
    RE_HASH_SHA1,
    RE_HASH_SHA256,
    RE_IPV4,
    RE_IPV6,
    RE_MESSAGE_ID,
)
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


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
            # IPv4
            ip_int = (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
            for start, end in PRIVATE_IP_RANGES:
                if start <= ip_int <= end:
                    return True
    except (ValueError, IndexError):
        pass
    
    return False


def extract_iocs_from_text(
    text: str,
    source: str,
    evidence_ref: str,
    seen: Optional[set[str]] = None
) -> list[IOCEntry]:
    """Extract IOCs from text.
    
    Args:
        text: Text to analyze
        source: Source type (headers, body_plain, body_html)
        evidence_ref: Evidence reference path
        seen: Set to track duplicates (optional)
        
    Returns:
        List of IOCEntry objects
    """
    if seen is None:
        seen = set()
    
    iocs = []
    
    import tldextract
    # Extract domains
    for match in RE_DOMAIN.finditer(text):
        domain = match.group().lower()
        
        # Validate domain using Public Suffix List
        ext = tldextract.extract(domain)
        if not ext.suffix:
            # Drop invalid TLDs (e.g. header.from, internal names)
            continue
            
        if domain not in seen:
            seen.add(domain)
            iocs.append(IOCEntry(
                value=domain,
                type=IOCType.DOMAIN,
                normalized=domain,
                context=text[max(0, match.start()-50):match.end()+50],
                source=source,
                evidence_ref=evidence_ref,
                first_seen_in=source,
            ))
    
    # Extract IPv4
    for match in RE_IPV4.finditer(text):
        ip = match.group()
        if ip not in seen:
            seen.add(ip)
            iocs.append(IOCEntry(
                value=ip,
                type=IOCType.IPV4,
                normalized=ip,
                context=text[max(0, match.start()-50):match.end()+50],
                source=source,
                evidence_ref=evidence_ref,
                first_seen_in=source,
            ))
    
    # Extract IPv6
    for match in RE_IPV6.finditer(text):
        ip = match.group()
        if ip not in seen:
            seen.add(ip)
            iocs.append(IOCEntry(
                value=ip,
                type=IOCType.IPV6,
                normalized=ip,
                context=text[max(0, match.start()-50):match.end()+50],
                source=source,
                evidence_ref=evidence_ref,
                first_seen_in=source,
            ))
    
    # Extract emails
    for match in RE_EMAIL.finditer(text):
        email = match.group().lower()
        if email not in seen:
            seen.add(email)
            iocs.append(IOCEntry(
                value=email,
                type=IOCType.EMAIL,
                normalized=email,
                context=text[max(0, match.start()-50):match.end()+50],
                source=source,
                evidence_ref=evidence_ref,
                first_seen_in=source,
            ))
    
    # Extract hashes
    for match in RE_HASH_SHA256.finditer(text):
        hash_val = match.group().lower()
        if hash_val not in seen:
            seen.add(hash_val)
            iocs.append(IOCEntry(
                value=hash_val,
                type=IOCType.HASH_SHA256,
                normalized=hash_val,
                context=text[max(0, match.start()-50):match.end()+50],
                source=source,
                evidence_ref=evidence_ref,
                first_seen_in=source,
            ))
    
    for match in RE_HASH_SHA1.finditer(text):
        hash_val = match.group().lower()
        if hash_val not in seen:
            seen.add(hash_val)
            iocs.append(IOCEntry(
                value=hash_val,
                type=IOCType.HASH_SHA1,
                normalized=hash_val,
                context=text[max(0, match.start()-50):match.end()+50],
                source=source,
                evidence_ref=evidence_ref,
                first_seen_in=source,
            ))
    
    for match in RE_HASH_MD5.finditer(text):
        hash_val = match.group().lower()
        if hash_val not in seen:
            seen.add(hash_val)
            iocs.append(IOCEntry(
                value=hash_val,
                type=IOCType.HASH_MD5,
                normalized=hash_val,
                context=text[max(0, match.start()-50):match.end()+50],
                source=source,
                evidence_ref=evidence_ref,
                first_seen_in=source,
            ))
    
    return iocs


def extract_iocs_from_urls(urls: list[URLEntry]) -> list[IOCEntry]:
    """Extract IOCs from URL list.
    
    Args:
        urls: List of URLEntry objects
        
    Returns:
        List of IOCEntry objects
    """
    iocs = []
    seen = set()
    
    for url_entry in urls:
        # Add URL as IOC
        if url_entry.normalized not in seen:
            seen.add(url_entry.normalized)
            iocs.append(IOCEntry(
                value=url_entry.normalized,
                type=IOCType.URL,
                normalized=url_entry.normalized,
                context=url_entry.context,
                source="urls",
                evidence_ref=url_entry.evidence_ref,
                first_seen_in="urls",
            ))
        
        # Extract domain from URL
        try:
            import tldextract
            from urllib.parse import urlparse
            parsed = urlparse(url_entry.deobfuscated)
            if parsed.netloc:
                domain = parsed.netloc.lower()
                if ':' in domain:
                    domain = domain.split(':')[0]
                    
                # Validate domain using Public Suffix List
                ext = tldextract.extract(domain)
                if not ext.suffix:
                    continue
                    
                if domain not in seen:
                    seen.add(domain)
                    iocs.append(IOCEntry(
                        value=domain,
                        type=IOCType.DOMAIN,
                        normalized=domain,
                        context=url_entry.context,
                        source="urls",
                        evidence_ref=f"urls.{url_entry.normalized}.domain",
                        first_seen_in="urls",
                    ))
        except Exception:
            pass
    
    return iocs


def extract_all_iocs(
    headers: list,
    bodies: list,
    urls: list[URLEntry],
    attachments: list,
) -> list[IOCEntry]:
    """Extract all IOCs from email components.
    
    Args:
        headers: Header entries
        bodies: Body entries
        urls: URL entries
        attachments: Attachment entries
        
    Returns:
        Combined list of IOCEntry objects
    """
    all_iocs = []
    seen = set()
    
    # Extract from headers
    for header in headers:
        text = header.decoded_value or header.raw_value
        if text:
            iocs = extract_iocs_from_text(
                text,
                source=f"header.{header.name}",
                evidence_ref=f"headers.{header.name}",
                seen=seen
            )
            all_iocs.extend(iocs)
    
    # Extract from bodies
    for i, body in enumerate(bodies):
        if body.content:
            source_type = "body_plain" if body.content_type == "text/plain" else "body_html"
            iocs = extract_iocs_from_text(
                body.content,
                source=source_type,
                evidence_ref=f"bodies.{i}",
                seen=seen
            )
            all_iocs.extend(iocs)
    
    # Extract from URLs
    url_iocs = extract_iocs_from_urls(urls)
    for ioc in url_iocs:
        if ioc.value not in seen:
            seen.add(ioc.value)
            all_iocs.append(ioc)
    
    # Extract filenames from attachments
    for i, att in enumerate(attachments):
        for filename in [att.filename_decoded, att.filename_raw]:
            if filename and filename not in seen:
                seen.add(filename)
                all_iocs.append(IOCEntry(
                    value=filename,
                    type=IOCType.FILENAME,
                    normalized=filename,
                    context=None,
                    source="attachments",
                    evidence_ref=f"attachments.{i}.filename",
                    first_seen_in="attachments",
                ))
    
    return all_iocs
