"""Risk scoring calculation."""

from typing import Any, Optional

from emltriage.core.models import (
    Artifacts,
    AuthResult,
    IOCType,
    IOCEntry,
    RiskReason,
    RiskScore,
    RoutingHop,
    Severity,
    URLEntry,
)
from emltriage.utils.constants import RISK_WEIGHTS, SUSPICIOUS_PATTERNS
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


def check_header_mismatches(artifacts: Artifacts) -> list[RiskReason]:
    """Check for header mismatches that indicate spoofing.
    
    Args:
        artifacts: Email artifacts
        
    Returns:
        List of risk reasons
    """
    from emltriage.core.extract.headers import get_header_value, parse_address_header
    
    reasons = []
    
    # Get addresses
    from_header = get_header_value(artifacts.headers, 'From')
    reply_to = get_header_value(artifacts.headers, 'Reply-To')
    return_path = get_header_value(artifacts.headers, 'Return-Path')
    
    from_domain = None
    if from_header:
        parsed = parse_address_header(from_header)
        from_domain = parsed.get('domain')
    
    # From vs Reply-To mismatch
    if from_domain and reply_to:
        parsed_reply = parse_address_header(reply_to)
        reply_domain = parsed_reply.get('domain')
        if reply_domain and reply_domain.lower() != from_domain.lower():
            reasons.append(RiskReason(
                code='header_mismatch_from_reply_to',
                description=f'From domain ({from_domain}) differs from Reply-To domain ({reply_domain})',
                weight=RISK_WEIGHTS['header_mismatch_from_reply_to'],
                severity=Severity.HIGH,
                evidence_refs=['headers.From', 'headers.Reply-To'],
            ))
    
    # From vs Return-Path mismatch
    if from_domain and return_path:
        parsed_return = parse_address_header(return_path)
        return_domain = parsed_return.get('domain')
        if return_domain and return_domain.lower() != from_domain.lower():
            reasons.append(RiskReason(
                code='header_mismatch_from_return_path',
                description=f'From domain ({from_domain}) differs from Return-Path domain ({return_domain})',
                weight=RISK_WEIGHTS['header_mismatch_from_return_path'],
                severity=Severity.MEDIUM,
                evidence_refs=['headers.From', 'headers.Return-Path'],
            ))
    
    return reasons


def check_auth_failures(artifacts: Artifacts) -> list[RiskReason]:
    """Check for authentication failures.
    
    Args:
        artifacts: Email artifacts
        
    Returns:
        List of risk reasons
    """
    reasons = []
    
    for domain_result in artifacts.authentication.parsed_results:
        for result in domain_result.results:
            if result.result in ['fail', 'temperror', 'permerror']:
                mech = result.mechanism.upper()
                weight_key = f'auth_failure_{result.mechanism}'
                
                reasons.append(RiskReason(
                    code=weight_key,
                    description=f'{mech} authentication failed: {result.reason or result.result}',
                    weight=RISK_WEIGHTS.get(weight_key, 20),
                    severity=Severity.HIGH,
                    evidence_refs=['authentication.parsed_results'],
                ))
    
    # DKIM domain mismatch
    from emltriage.core.extract.headers import get_header_value, parse_address_header
    from emltriage.core.extract.auth import parse_dkim_signature
    
    dkim_sig = get_header_value(artifacts.headers, 'DKIM-Signature')
    if dkim_sig:
        dkim_parsed = parse_dkim_signature(dkim_sig)
        dkim_domain = dkim_parsed.get('d')
        
        from_header = get_header_value(artifacts.headers, 'From')
        if from_header and dkim_domain:
            parsed_from = parse_address_header(from_header)
            from_domain = parsed_from.get('domain')
            
            if from_domain and from_domain.lower() != dkim_domain.lower():
                reasons.append(RiskReason(
                    code='dkim_domain_mismatch',
                    description=f'DKIM signing domain ({dkim_domain}) differs from From domain ({from_domain})',
                    weight=RISK_WEIGHTS['dkim_domain_mismatch'],
                    severity=Severity.HIGH,
                    evidence_refs=['headers.DKIM-Signature', 'headers.From'],
                ))
    
    return reasons


def check_suspicious_urls(urls: list[URLEntry]) -> list[RiskReason]:
    """Check for suspicious URL patterns.
    
    Args:
        urls: URL entries
        
    Returns:
        List of risk reasons
    """
    reasons = []
    seen_flags = set()
    
    for i, url in enumerate(urls):
        # Punycode domains
        if SUSPICIOUS_PATTERNS['punycode_domain'].search(url.normalized):
            if 'punycode' not in seen_flags:
                seen_flags.add('punycode')
                reasons.append(RiskReason(
                    code='suspicious_url_punycode',
                    description='URL contains punycode (internationalized domain)',
                    weight=RISK_WEIGHTS['suspicious_url_punycode'],
                    severity=Severity.HIGH,
                    evidence_refs=[f'urls.{i}.normalized'],
                ))
        
        # Excessive subdomains
        if SUSPICIOUS_PATTERNS['excessive_subdomains'].search(url.normalized):
            if 'excessive_subdomains' not in seen_flags:
                seen_flags.add('excessive_subdomains')
                reasons.append(RiskReason(
                    code='suspicious_url_excessive_subdomains',
                    description='URL contains excessive number of subdomains',
                    weight=RISK_WEIGHTS['suspicious_url_excessive_subdomains'],
                    severity=Severity.LOW,
                    evidence_refs=[f'urls.{i}.normalized'],
                ))
        
        # Suspicious TLD
        if SUSPICIOUS_PATTERNS['suspicious_tld'].search(url.normalized):
            if 'suspicious_tld' not in seen_flags:
                seen_flags.add('suspicious_tld')
                reasons.append(RiskReason(
                    code='suspicious_url_tld',
                    description='URL uses suspicious top-level domain',
                    weight=15,
                    severity=Severity.MEDIUM,
                    evidence_refs=[f'urls.{i}.normalized'],
                ))
        
        # IP literal in URL
        from emltriage.utils.constants import RE_IPV4
        if RE_IPV4.search(url.normalized):
            if 'ip_literal' not in seen_flags:
                seen_flags.add('ip_literal')
                reasons.append(RiskReason(
                    code='suspicious_url_ip_literal',
                    description='URL contains IP address instead of domain',
                    weight=RISK_WEIGHTS['suspicious_url_ip_literal'],
                    severity=Severity.MEDIUM,
                    evidence_refs=[f'urls.{i}.normalized'],
                ))
    
    return reasons


def check_risky_attachments(artifacts: Artifacts) -> list[RiskReason]:
    """Check for risky attachments.
    
    Args:
        artifacts: Email artifacts
        
    Returns:
        List of risk reasons
    """
    reasons = []
    
    for i, att in enumerate(artifacts.attachments):
        if att.is_risky:
            reasons.append(RiskReason(
                code='risky_attachment',
                description=f'Risky attachment: {att.filename_decoded or att.filename_raw} ({att.magic_type})',
                weight=RISK_WEIGHTS['risky_attachment'],
                severity=Severity.HIGH,
                evidence_refs=[f'attachments.{i}'],
            ))
        
        # Check for macro indicators in deep analysis
        if att.deep_analysis:
            risk_flags = att.deep_analysis.get('risk_flags', [])
            if 'contains_vba_macros' in risk_flags:
                reasons.append(RiskReason(
                    code='attachment_macro_indicators',
                    description=f'Attachment contains VBA macros: {att.filename_decoded or att.filename_raw}',
                    weight=RISK_WEIGHTS['attachment_macro_indicators'],
                    severity=Severity.CRITICAL,
                    evidence_refs=[f'attachments.{i}.deep_analysis'],
                ))
    
    return reasons


def check_routing_anomalies(artifacts: Artifacts) -> list[RiskReason]:
    """Check for routing anomalies.
    
    Args:
        artifacts: Email artifacts
        
    Returns:
        List of risk reasons
    """
    reasons = []
    
    for i, hop in enumerate(artifacts.routing):
        # Check for anomalies flagged during parsing
        for anomaly in hop.anomalies:
            if anomaly == 'private_ip' and 'routing_private_ip' not in [r.code for r in reasons]:
                reasons.append(RiskReason(
                    code='routing_private_ip',
                    description='Private IP address in routing path',
                    weight=RISK_WEIGHTS['routing_private_ip'],
                    severity=Severity.LOW,
                    evidence_refs=[f'routing.{i}.from_host'],
                ))
            elif anomaly == 'missing_date' and 'routing_missing_date' not in [r.code for r in reasons]:
                reasons.append(RiskReason(
                    code='routing_missing_date',
                    description='Received header missing timestamp',
                    weight=RISK_WEIGHTS['routing_missing_date'],
                    severity=Severity.MEDIUM,
                    evidence_refs=[f'routing.{i}.raw_received'],
                ))
            elif anomaly == 'non_monotonic_timestamp' and 'non_monotonic' not in [r.code for r in reasons]:
                reasons.append(RiskReason(
                    code='routing_non_monotonic',
                    description='Non-monotonic timestamps in routing path',
                    weight=RISK_WEIGHTS['routing_non_monotonic'],
                    severity=Severity.MEDIUM,
                    evidence_refs=[f'routing.{i}.timestamp'],
                ))
    
    return reasons


def check_impersonation(artifacts: Artifacts) -> list[RiskReason]:
    """Check for brand/domain impersonation findings.
    
    Args:
        artifacts: Email artifacts
        
    Returns:
        List of risk reasons from impersonation detection
    """
    reasons = []
    
    if not artifacts.impersonation:
        return reasons
    
    has_impersonation = False
    high_confidence_count = 0
    
    for finding in artifacts.impersonation:
        has_impersonation = True
        if finding.score >= 0.85:
            high_confidence_count += 1
    
    # Add risk reason for impersonation detected
    if has_impersonation:
        weight = RISK_WEIGHTS['impersonation_detected']
        
        # Increase weight for high confidence findings
        if high_confidence_count > 0:
            weight = RISK_WEIGHTS['impersonation_high_confidence']
        
        reasons.append(RiskReason(
            code='impersonation_detected',
            description=f'Potential brand impersonation detected ({len(artifacts.impersonation)} findings, {high_confidence_count} high confidence)',
            weight=weight,
            severity=Severity.HIGH if high_confidence_count > 0 else Severity.MEDIUM,
            evidence_refs=[f'impersonation.{i}' for i in range(len(artifacts.impersonation))],
        ))
    
    return reasons


def calculate_risk_score(artifacts: Artifacts) -> RiskScore:
    """Calculate overall risk score.
    
    Args:
        artifacts: Email artifacts
        
    Returns:
        RiskScore object
    """
    all_reasons = []
    
    # Check various risk factors
    all_reasons.extend(check_header_mismatches(artifacts))
    all_reasons.extend(check_auth_failures(artifacts))
    all_reasons.extend(check_suspicious_urls(artifacts.urls))
    all_reasons.extend(check_risky_attachments(artifacts))
    all_reasons.extend(check_routing_anomalies(artifacts))
    all_reasons.extend(check_impersonation(artifacts))  # Add impersonation risk
    
    # Calculate total score (cap at 100)
    total_score = min(100, sum(r.weight for r in all_reasons))
    
    # Determine severity
    if total_score >= 80:
        severity = Severity.CRITICAL
    elif total_score >= 60:
        severity = Severity.HIGH
    elif total_score >= 30:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW
    
    return RiskScore(
        score=total_score,
        severity=severity,
        reasons=all_reasons,
        confidence=1.0,
    )
