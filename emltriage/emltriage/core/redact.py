"""PII/sensitive data redaction."""

import hashlib
import re
from pathlib import Path
from typing import Optional

from emltriage.core.models import Artifacts
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


def redact_email_address(email: str, mask: str = "[REDACTED]") -> str:
    """Redact email address while preserving hash.
    
    Args:
        email: Email address
        mask: Mask string
        
    Returns:
        Redacted email with hash suffix
    """
    if not email or '@' not in email:
        return mask
    
    # Compute hash
    email_hash = hashlib.sha256(email.lower().encode()).hexdigest()[:8]
    
    return f"{mask}:{email_hash}"


def redact_ip_address(ip: str, mask: str = "[REDACTED]") -> str:
    """Redact IP address.
    
    Args:
        ip: IP address
        mask: Mask string
        
    Returns:
        Redacted IP
    """
    if not ip:
        return mask
    
    # Compute hash
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:8]
    
    return f"{mask}:{ip_hash}"


def redact_text(
    text: str,
    redact_emails: bool = True,
    redact_ips: bool = True,
) -> str:
    """Redact PII from text.
    
    Args:
        text: Input text
        redact_emails: Whether to redact emails
        redact_ips: Whether to redact IPs
        
    Returns:
        Redacted text
    """
    result = text
    
    if redact_emails:
        # Redact emails
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        for match in email_pattern.finditer(text):
            original = match.group()
            redacted = redact_email_address(original)
            result = result.replace(original, redacted)
    
    if redact_ips:
        # Redact IPv4
        ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        for match in ipv4_pattern.finditer(text):
            original = match.group()
            # Validate it's actually an IP
            parts = original.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                redacted = redact_ip_address(original)
                result = result.replace(original, redacted)
    
    return result


def redact_artifacts(
    artifacts: Artifacts,
    redact_emails: bool = True,
    redact_ips: bool = False,  # Default off as it can break analysis
) -> Artifacts:
    """Redact PII from artifacts.
    
    Args:
        artifacts: Email artifacts
        redact_emails: Whether to redact email addresses
        redact_ips: Whether to redact IP addresses
        
    Returns:
        Redacted artifacts (modified in place)
    """
    logger.info(f"Redacting artifacts: emails={redact_emails}, ips={redact_ips}")
    
    # Redact headers
    for header in artifacts.headers:
        if header.name.lower() in ['from', 'to', 'cc', 'bcc', 'reply-to', 'return-path', 'sender']:
            if header.decoded_value and redact_emails:
                header.decoded_value = redact_text(header.decoded_value, redact_emails, redact_ips)
            if header.raw_value and redact_emails:
                header.raw_value = redact_text(header.raw_value, redact_emails, redact_ips)
            if header.parsed and 'addresses' in header.parsed:
                for addr in header.parsed['addresses']:
                    if 'address' in addr and addr['address'] and redact_emails:
                        addr['address'] = redact_email_address(addr['address'])
    
    # Redact bodies
    for body in artifacts.bodies:
        if body.content:
            body.content = redact_text(body.content, redact_emails, redact_ips)
    
    # Redact IOCs (email type)
    if redact_emails:
        for ioc in artifacts.iocs:
            if ioc.type.value == 'email':
                ioc.value = redact_email_address(ioc.value)
                if ioc.normalized:
                    ioc.normalized = redact_email_address(ioc.normalized)
    
    # Update metadata
    artifacts.metadata.redact_mode = True
    
    return artifacts


def redact_file(file_path: Path, output_path: Optional[Path] = None) -> Path:
    """Redact a single file.
    
    Args:
        file_path: File to redact
        output_path: Output path (default: in-place)
        
    Returns:
        Path to redacted file
    """
    if output_path is None:
        output_path = file_path
    
    content = file_path.read_text(encoding='utf-8', errors='replace')
    redacted = redact_text(content)
    output_path.write_text(redacted, encoding='utf-8')
    
    return output_path
