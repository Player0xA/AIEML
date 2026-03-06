"""Authentication results parsing and analysis."""

import re
from typing import Optional

from emltriage.core.models import AuthDomainResult, AuthResult, AuthenticationResults
from emltriage.utils.constants import AUTH_RESULT_PATTERN
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


def parse_authentication_results_header(value: str) -> list[AuthResult]:
    """Parse Authentication-Results header value.
    
    Args:
        value: Header value
        
    Returns:
        List of AuthResult objects
    """
    results = []
    
    # Remove the authserv-id (first word)
    # Format: authserv-id; [methodinfo]...
    parts = value.split(';', 1)
    if len(parts) < 2:
        return results
    
    method_info = parts[1]
    
    # Parse each mechanism result
    # Format: mechanism=result [reason] [...props]
    for match in AUTH_RESULT_PATTERN.finditer(method_info):
        mechanism = match.group(1).lower()
        result = match.group(2).lower()
        
        # Try to extract reason and other properties
        reason = None
        rest_start = match.end()
        
        # Look for reason in parentheses
        reason_match = re.search(r'reason="([^"]+)"', method_info[rest_start:rest_start+200])
        if not reason_match:
            # Try without quotes
            reason_match = re.search(r'reason=([^\s;]+)', method_info[rest_start:rest_start+200])
        
        if reason_match:
            reason = reason_match.group(1)
        
        results.append(AuthResult(
            mechanism=mechanism,
            result=result,
            reason=reason,
            details={},
        ))
    
    return results


def parse_dkim_signature(value: str) -> dict:
    """Parse DKIM-Signature header.
    
    Args:
        value: Header value
        
    Returns:
        Dictionary with parsed components
    """
    result = {
        'v': None,
        'a': None,
        'd': None,  # Domain
        's': None,  # Selector
        'c': None,
        'h': None,  # Headers signed
        'b': None,  # Signature
    }
    
    # Extract tag-value pairs
    for tag in ['v', 'a', 'd', 's', 'c', 'h', 'b', 't', 'x', 'l', 'q', 'i', 'z']:
        pattern = rf'{tag}=([^;]+)'
        match = re.search(pattern, value, re.IGNORECASE)
        if match:
            result[tag] = match.group(1).strip()
    
    return result


def extract_authentication_results(
    headers: list,
    perform_dkim_verify: bool = False,
    perform_dns_lookup: bool = False,
    raw_email_bytes: Optional[bytes] = None
) -> AuthenticationResults:
    """Extract and analyze authentication results.
    
    Args:
        headers: Header entries
        perform_dkim_verify: Whether to cryptographically verify DKIM
        perform_dns_lookup: Whether to query DNS for SPF/DMARC
        raw_email_bytes: Raw email bytes for DKIM verification
        
    Returns:
        AuthenticationResults object
    """
    from emltriage.core.extract.headers import get_all_header_values, get_header_value
    
    auth_results = AuthenticationResults()
    
    # Get all Authentication-Results headers
    raw_auth_results = get_all_header_values(headers, 'Authentication-Results')
    auth_results.raw_headers = raw_auth_results
    
    # Parse each header
    for header_value in raw_auth_results:
        parsed = parse_authentication_results_header(header_value)
        if parsed:
            # Group by domain if possible
            domain = None
            
            # Try to find domain in header
            header_match = re.search(r'dkim=\S+\s+header\.d=([^\s;]+)', header_value)
            if header_match:
                domain = header_match.group(1)
            
            if not domain:
                # Use From domain as fallback
                from_header = get_header_value(headers, 'From')
                if from_header:
                    from emltriage.core.extract.headers import parse_address_header
                    parsed_from = parse_address_header(from_header)
                    domain = parsed_from.get('domain')
            
            auth_results.parsed_results.append(AuthDomainResult(
                domain=domain or 'unknown',
                results=parsed,
            ))
    
    # DKIM signature parsing (not verification yet)
    dkim_sig = get_header_value(headers, 'DKIM-Signature')
    if dkim_sig:
        dkim_parsed = parse_dkim_signature(dkim_sig)
        # Could add to auth_results.parsed_results
    
    # DKIM verification (optional, requires raw bytes)
    if perform_dkim_verify and raw_email_bytes:
        try:
            import dkim
            verify_result = dkim.verify(raw_email_bytes)
            auth_results.dkim_verified = bool(verify_result)
        except Exception as e:
            auth_results.dkim_verified = False
            auth_results.dkim_verify_error = str(e)
    
    # DNS lookups (optional)
    if perform_dns_lookup:
        auth_results.dns_queried = True
        
        # Get domain from From header
        from_header = get_header_value(headers, 'From')
        if from_header:
            from emltriage.core.extract.headers import parse_address_header
            parsed_from = parse_address_header(from_header)
            domain = parsed_from.get('domain')
            
            if domain:
                try:
                    import dns.resolver
                    
                    # Query SPF
                    try:
                        answers = dns.resolver.resolve(domain, 'TXT')
                        for rdata in answers:
                            txt = str(rdata).strip('"')
                            if txt.startswith('v=spf1'):
                                auth_results.spf_dns_record = txt
                                break
                    except Exception as e:
                        logger.debug(f"SPF DNS query failed: {e}")
                    
                    # Query DMARC
                    try:
                        dmarc_domain = f"_dmarc.{domain}"
                        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
                        for rdata in answers:
                            txt = str(rdata).strip('"')
                            if txt.startswith('v=DMARC1'):
                                auth_results.dmarc_dns_record = txt
                                break
                    except Exception as e:
                        logger.debug(f"DMARC DNS query failed: {e}")
                        
                except ImportError:
                    logger.warning("dnspython not installed, skipping DNS queries")
    
    return auth_results


def get_auth_summary(auth_results: AuthenticationResults) -> dict:
    """Generate authentication summary for reporting.
    
    Args:
        auth_results: Authentication results
        
    Returns:
        Summary dictionary
    """
    summary = {
        'has_dkim': False,
        'has_spf': False,
        'has_dmarc': False,
        'dkim_pass': 0,
        'dkim_fail': 0,
        'spf_pass': 0,
        'spf_fail': 0,
        'dmarc_pass': 0,
        'dmarc_fail': 0,
    }
    
    for domain_result in auth_results.parsed_results:
        for result in domain_result.results:
            mech = result.mechanism.lower()
            res = result.result.lower()
            
            if mech == 'dkim':
                summary['has_dkim'] = True
                if res == 'pass':
                    summary['dkim_pass'] += 1
                elif res in ['fail', 'temperror', 'permerror']:
                    summary['dkim_fail'] += 1
            elif mech == 'spf':
                summary['has_spf'] = True
                if res == 'pass':
                    summary['spf_pass'] += 1
                elif res in ['fail', 'temperror', 'permerror']:
                    summary['spf_fail'] += 1
            elif mech == 'dmarc':
                summary['has_dmarc'] = True
                if res == 'pass':
                    summary['dmarc_pass'] += 1
                elif res in ['fail', 'temperror', 'permerror']:
                    summary['dmarc_fail'] += 1
    
    return summary
