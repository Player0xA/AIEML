"""IOC filtering and normalization utilities."""

from typing import Optional

from emltriage.core.models import IOCEntry, IOCType
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


# Default infrastructure whitelist - known legitimate email/CDN infrastructure
# These domains are commonly seen in email headers but are not IOCs
DEFAULT_INFRASTRUCTURE_DOMAINS = frozenset([
    # Microsoft/Office 365
    "outlook.com",
    "office365.com",
    "microsoft.com",
    "microsoftonline.com",
    "live.com",
    "hotmail.com",
    "msn.com",
    "windows.com",
    "skype.com",
    "teams.com",
    "sharepoint.com",
    "onedrive.com",
    
    # Google
    "google.com",
    "gmail.com",
    "googlemail.com",
    "googlegroups.com",
    "googleusercontent.com",
    
    # AWS/Cloud
    "amazonaws.com",
    "cloudfront.net",
    "aws.amazon.com",
    
    # Cloudflare
    "cloudflare.com",
    "cloudflare.net",
    
    # Major ESPs (Email Service Providers)
    "mailgun.net",
    "sendgrid.net",
    "mailchimp.com",
    "mandrillapp.com",
    "postmarkapp.com",
    
    # Common CDNs
    "akamai.net",
    "akamaiedge.net",
    "fastly.net",
    "edgecastcdn.net",
    
    # Social/Communication
    "facebook.com",
    "fb.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    
    # Internal/Private
    "local",
    "localhost",
    "intranet",
    "lan",
    
    # Common CSS class prefixes (not real domains)
    "msonormal",
    "wordsection",
    "section",
])


def is_noise_filename(filename: str) -> bool:
    """Check if filename is likely noise (auto-generated image names, etc).
    
    Args:
        filename: Filename to check
        
    Returns:
        True if filename is noise
    """
    import re
    
    # Common auto-generated image names from Office/Outlook
    # e.g., image001.png, image002.jpg, Picture1.jpg
    auto_image_patterns = [
        r'^image\d+\.(png|jpg|jpeg|gif|bmp)$',
        r'^picture\d+\.(png|jpg|jpeg|gif|bmp)$',
        r'^img\d+\.(png|jpg|jpeg|gif|bmp)$',
        r'^attachment\d+\.',  # Generic attachment names
    ]
    
    filename_lower = filename.lower()
    
    for pattern in auto_image_patterns:
        if re.match(pattern, filename_lower):
            return True
    
    return False


def is_infrastructure_domain(domain: str, custom_whitelist: Optional[set[str]] = None) -> bool:
    """Check if domain is known infrastructure (not an IOC).
    
    Args:
        domain: Domain to check
        custom_whitelist: Additional domains to whitelist
        
    Returns:
        True if domain is infrastructure (should be filtered)
    """
    # Normalize domain
    domain_lower = domain.lower().strip()
    
    # Remove www. prefix for checking
    if domain_lower.startswith("www."):
        domain_lower = domain_lower[4:]
    
    # Check exact match
    if domain_lower in DEFAULT_INFRASTRUCTURE_DOMAINS:
        return True
    
    # Check custom whitelist
    if custom_whitelist and domain_lower in custom_whitelist:
        return True
    
    # Check if it's a subdomain of a known infrastructure domain
    for infra_domain in DEFAULT_INFRASTRUCTURE_DOMAINS:
        if domain_lower == infra_domain:
            return True
        if domain_lower.endswith("." + infra_domain):
            return True
    
    return False


def is_infrastructure_ip(ip: str) -> bool:
    """Check if IP is known infrastructure (RFC 1918, etc).
    
    Args:
        ip: IP address to check
        
    Returns:
        True if IP is infrastructure (should potentially be filtered)
    """
    # Check for common internal/martian IPs
    internal_ips = frozenset([
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::",  # Link-local
    ])
    
    if ip in internal_ips:
        return True
    
    # Check RFC 1918 private ranges
    try:
        parts = ip.split('.')
        if len(parts) == 4:
            first = int(parts[0])
            second = int(parts[1])
            
            # 10.0.0.0/8
            if first == 10:
                return True
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True
            # 127.0.0.0/8 (loopback)
            if first == 127:
                return True
    except (ValueError, IndexError):
        pass
    
    return False


def filter_infrastructure_iocs(
    iocs: list[IOCEntry],
    custom_whitelist: Optional[set[str]] = None,
    filter_private_ips: bool = True
) -> tuple[list[IOCEntry], list[IOCEntry]]:
    """Separate IOCs into infrastructure (noise) and actual IOCs.
    
    Args:
        iocs: List of IOC entries to filter
        custom_whitelist: Additional domains to treat as infrastructure
        filter_private_ips: Whether to filter private/internal IPs
        
    Returns:
        Tuple of (actual_iocs, infrastructure_iocs)
    """
    actual_iocs = []
    infrastructure_iocs = []
    
    filtered_count = 0
    
    for ioc in iocs:
        should_filter = False
        
        if ioc.type == IOCType.DOMAIN:
            if is_infrastructure_domain(ioc.value, custom_whitelist):
                should_filter = True
                
        elif ioc.type in (IOCType.IP, IOCType.IPV4, IOCType.IPV6):
            if filter_private_ips and is_infrastructure_ip(ioc.value):
                should_filter = True
        
        elif ioc.type == IOCType.FILENAME:
            if is_noise_filename(ioc.value):
                should_filter = True
        
        if should_filter:
            infrastructure_iocs.append(ioc)
            filtered_count += 1
        else:
            actual_iocs.append(ioc)
    
    if filtered_count > 0:
        logger.info(f"Filtered {filtered_count} infrastructure items from IOCs "
                   f"({len(actual_iocs)} remaining)")
    
    return actual_iocs, infrastructure_iocs


def create_filtered_iocs_json(
    artifacts_iocs: list[IOCEntry],
    custom_whitelist: Optional[set[str]] = None,
    filter_private_ips: bool = True
) -> tuple[list[IOCEntry], list[IOCEntry]]:
    """Create filtered IOCs for export with infrastructure separated.
    
    This is used when creating iocs.json - keeps actual IOCs for CTI lookup
    while preserving infrastructure IOCs separately.
    
    Args:
        artifacts_iocs: Raw IOCs from artifacts
        custom_whitelist: Additional domains to whitelist
        filter_private_ips: Whether to filter private IPs
        
    Returns:
        Tuple of (ioc_entries_for_cti, infrastructure_entries)
    """
    return filter_infrastructure_iocs(artifacts_iocs, custom_whitelist, filter_private_ips)
