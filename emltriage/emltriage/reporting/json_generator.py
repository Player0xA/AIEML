"""JSON report generator - maps artifacts to the investigation report schema."""

import re
from datetime import datetime
from typing import Any, Optional

from emltriage.core.models import Artifacts, HeaderEntry, RoutingHop
from emltriage.reporting.schemas import (
    InvestigationReport,
    Document,
    DocumentMetadata,
    RequestContext,
    EmailData,
    AuthenticationData,
    HeadersAnalysis,
    GeneralDataTable,
    HopData,
    RoutingObservations,
    SenderDomainValidation,
    ArtifactsAnalysis,
    EmailBodyIndicators,
    LandingPage,
    SuspiciousInfrastructure,
    ResolvedIP,
    ReputationData,
    IOCEntryReport,
    ReferenceEntry,
    AIInputs,
    AIOutputs,
)


def extract_domain_from_email(email_str: str) -> str:
    """Extract domain from email address."""
    if not email_str:
        return ""
    match = re.search(r'@([a-zA-Z0-9.-]+)', email_str)
    return match.group(1) if match else ""


def get_header_value(headers: list[HeaderEntry], name: str) -> str:
    """Get header value by name."""
    for header in headers:
        if header.name.lower() == name.lower():
            return header.decoded_value or header.raw_value
    return ""


def get_header_raw(headers: list[HeaderEntry], name: str) -> str:
    """Get raw header value by name."""
    for header in headers:
        if header.name.lower() == name.lower():
            return header.raw_value
    return ""


def map_routing_observations(routing: list[RoutingHop]) -> RoutingObservations:
    """Analyze routing hops for provider detection."""
    obs = RoutingObservations()
    
    routing_text = " ".join([
        hop.from_host or "" + hop.by_host or "" 
        for hop in routing
    ]).lower()
    
    if "outlook.com" in routing_text or "office.com" in routing_text:
        obs.uses_microsoft_365 = True
    if "exchange" in routing_text or "outlook" in routing_text:
        obs.uses_exchange_online = True
    
    return obs


def map_authentication(artifacts: Artifacts) -> AuthenticationData:
    """Map authentication results."""
    auth = artifacts.authentication
    result = AuthenticationData()
    
    for domain_result in auth.parsed_results:
        if domain_result.mechanism.lower() == "spf":
            result.spf_result = domain_result.results[0].result if domain_result.results else ""
            result.spf_domain = domain_result.domain
        elif domain_result.mechanism.lower() == "dkim":
            result.dkim_result = domain_result.results[0].result if domain_result.results else ""
            result.dkim_domain = domain_result.domain
        elif domain_result.mechanism.lower() == "dmarc":
            result.dmarc_result = domain_result.results[0].result if domain_result.results else ""
            result.dmarc_domain = domain_result.domain
    
    return result


def map_hops(artifacts: Artifacts) -> list[HopData]:
    """Map routing hops to HopData."""
    hops = []
    
    for i, hop in enumerate(artifacts.routing):
        hop_data = HopData(
            hop_number=i + 1,
            source=hop.from_host or "",
            source_ip="",
            destination=hop.by_host or "",
            destination_ip="",
            raw_received_line=hop.raw_received or "",
            classification="",
            ai_description=""
        )
        
        if hop.is_private_ip:
            hop_data.classification = "Internal/Private IP"
        elif hop.anomalies:
            hop_data.classification = "Anomaly: " + ", ".join(hop.anomalies)
        
        hops.append(hop_data)
    
    return hops


def map_urls_to_body_indicators(artifacts: Artifacts) -> EmailBodyIndicators:
    """Map URLs and bodies to email body indicators."""
    indicators = EmailBodyIndicators()
    
    urls = artifacts.urls
    if urls:
        indicators.urls_in_body = [url.normalized for url in urls[:20]]
        
        for url in urls:
            normalized = url.normalized.lower()
            if "login" in normalized or "signin" in normalized or "account" in normalized:
                indicators.requested_actions.append("Login/Credentials")
            if "verify" in normalized or "confirm" in normalized:
                indicators.requested_actions.append("Account Verification")
            if "update" in normalized or "payment" in normalized:
                indicators.requested_actions.append("Payment/Update")
    
    if artifacts.impersonation:
        brands = [imp.brand_candidate for imp in artifacts.impersonation]
        indicators.displayed_brand = ", ".join(set(brands))
    
    pressure_keywords = ["urgent", "immediate", "suspend", "expire", "lock", "verify now", "action required"]
    for body in artifacts.bodies:
        if body.content:
            content_lower = body.content.lower()
            for kw in pressure_keywords:
                if kw in content_lower:
                    indicators.pressure_language.append(kw)
    
    return indicators


def map_iocs(artifacts: Artifacts) -> list[IOCEntryReport]:
    """Map IOCs to report format."""
    iocs = []
    
    for ioc in artifacts.iocs:
        ioc_report = IOCEntryReport(
            indicator_type=ioc.type.value,
            value=ioc.value,
            detection_date=datetime.utcnow().isoformat(),
            vt_score="",
            source=ioc.source,
            recommendation="",
            comment=ioc.context or ""
        )
        iocs.append(ioc_report)
    
    return iocs


def extract_ai_inputs(artifacts: Artifacts, email_data: EmailData, headers_analysis: HeadersAnalysis) -> AIInputs:
    """Extract facts from artifacts for AI to process."""
    inputs = AIInputs()
    
    if email_data.sender_domain:
        inputs.sender_domain_validation_facts.append(f"Sender domain: {email_data.sender_domain}")
    
    for imp in artifacts.impersonation:
        inputs.artifact_analysis_facts.append(
            f"Impersonation detected: {imp.brand_candidate} ({imp.technique.value}) - {imp.explanation}"
        )
    
    for hop in headers_analysis.hops:
        if hop.classification:
            inputs.header_analysis_facts.append(f"Hop {hop.hop_number}: {hop.classification}")
    
    auth = headers_analysis.routing_observations
    if auth.uses_microsoft_365:
        inputs.header_analysis_facts.append("Uses Microsoft 365")
    if auth.uses_exchange_online:
        inputs.header_analysis_facts.append("Uses Exchange Online")
    
    if artifacts.risk:
        inputs.summary_facts.append(f"Risk Score: {artifacts.risk.score}/100 ({artifacts.risk.severity.value})")
        for reason in artifacts.risk.reasons:
            inputs.summary_facts.append(f"Risk: {reason.description}")
    
    return inputs


def generate_report(artifacts: Artifacts, case_id: str = "") -> InvestigationReport:
    """Generate investigation report from artifacts."""
    
    headers = artifacts.headers
    
    subject = get_header_value(headers, "subject")
    from_header = get_header_value(headers, "from")
    to = get_header_value(headers, "to")
    reply_to = get_header_value(headers, "reply-to")
    return_path = get_header_value(headers, "return-path")
    message_id = get_header_value(headers, "message-id")
    date_header = get_header_value(headers, "date")
    
    sender_domain = extract_domain_from_email(from_header)
    
    email_data = EmailData(
        subject=subject,
        from_header=from_header,
        to=to,
        sender_domain=sender_domain,
        reply_to=reply_to,
        return_path=return_path,
        message_id=message_id,
        date_header=date_header,
        authentication=map_authentication(artifacts)
    )
    
    general_data = GeneralDataTable(
        asunto=subject,
        from_header=from_header,
        to=to,
        sender_domain=sender_domain
    )
    
    routing_obs = map_routing_observations(artifacts.routing)
    hops = map_hops(artifacts)
    
    headers_analysis = HeadersAnalysis(
        raw_headers_available=len(artifacts.headers) > 0,
        general_data_table=general_data,
        hops=hops,
        routing_observations=routing_obs
    )
    
    sender_validation = SenderDomainValidation(
        domain=sender_domain,
        is_institutional=False,
        summary_facts=[]
    )
    
    body_indicators = map_urls_to_body_indicators(artifacts)
    
    artifacts_analysis = ArtifactsAnalysis(
        email_body_summary_facts=[],
        email_body_indicators=body_indicators,
        landing_page=LandingPage()
    )
    
    suspicious_infra = SuspiciousInfrastructure(
        primary_domain=sender_domain,
        related_subdomains=[],
        resolved_ips=[],
        reputation=ReputationData()
    )
    
    iocs = map_iocs(artifacts)
    
    references = [
        ReferenceEntry(type="email", value=message_id) if message_id else None,
        ReferenceEntry(type="file", value=artifacts.metadata.input_filename) if artifacts.metadata else None,
    ]
    references = [r for r in references if r and r.value]
    
    ai_inputs = extract_ai_inputs(artifacts, email_data, headers_analysis)
    ai_outputs = AIOutputs()
    
    report = InvestigationReport(
        report_type="email_investigation",
        case_id=case_id,
        document=Document(
            title="Investigación respecto a correo electrónico",
            metadata=DocumentMetadata(
                fecha=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            ),
            request_context=RequestContext()
        ),
        email=email_data,
        headers_analysis=headers_analysis,
        sender_domain_validation=sender_validation,
        artifacts_analysis=artifacts_analysis,
        suspicious_infrastructure=suspicious_infra,
        iocs=iocs,
        references=references,
        ai_inputs=ai_inputs,
        ai_outputs=ai_outputs
    )
    
    return report


def generate_report_from_dict(artifacts_dict: dict, case_id: str = "") -> InvestigationReport:
    """Generate report from artifacts dict (handles JSON serialization issues)."""
    
    def safe_get(d: dict, *keys, default=""):
        """Safely get nested dict value."""
        result = d
        for key in keys:
            if isinstance(result, dict):
                result = result.get(key, default)
            else:
                return default
        return result if result else default
    
    def safe_get_list(d: dict, *keys, default=None):
        """Safely get nested list."""
        result = d
        for key in keys:
            if isinstance(result, dict):
                result = result.get(key, default)
            else:
                return default or []
        return result if result else (default or [])
    
    headers = safe_get_list(artifacts_dict, "headers")
    routing = safe_get_list(artifacts_dict, "routing")
    iocs = safe_get_list(artifacts_dict, "iocs")
    authentication = safe_get(artifacts_dict, "authentication", default={})
    bodies = safe_get_list(artifacts_dict, "bodies")
    impersonation = safe_get_list(artifacts_dict, "impersonation")
    risk = safe_get(artifacts_dict, "risk", default={})
    metadata = safe_get(artifacts_dict, "metadata", default={})
    
    subject = ""
    from_header = ""
    to = ""
    reply_to = ""
    return_path = ""
    message_id = ""
    date_header = ""
    
    for header in headers:
        name = safe_get(header, "name", default="").lower()
        value = safe_get(header, "decoded_value", default="") or safe_get(header, "raw_value", default="")
        
        if name == "subject":
            subject = value
        elif name == "from":
            from_header = value
        elif name == "to":
            to = value
        elif name == "reply-to":
            reply_to = value
        elif name == "return-path":
            return_path = value
        elif name == "message-id":
            message_id = value
        elif name == "date":
            date_header = value
    
    sender_domain = extract_domain_from_email(from_header)
    
    spf_result = ""
    spf_domain = ""
    dkim_result = ""
    dkim_domain = ""
    dmarc_result = ""
    dmarc_domain = ""
    
    for auth_domain in safe_get_list(authentication, "parsed_results"):
        mech = safe_get(auth_domain, "mechanism", default="").lower()
        domain = safe_get(auth_domain, "domain", default="")
        results = safe_get_list(auth_domain, "results", default=[])
        result_val = safe_get(results[0], "result", default="") if results else ""
        
        if mech == "spf":
            spf_result = result_val
            spf_domain = domain
        elif mech == "dkim":
            dkim_result = result_val
            dkim_domain = domain
        elif mech == "dmarc":
            dmarc_result = result_val
            dmarc_domain = domain
    
    hops = []
    for i, hop in enumerate(routing[:10]):
        hops.append(HopData(
            hop_number=i + 1,
            source=safe_get(hop, "from_host", default=""),
            source_ip="",
            destination=safe_get(hop, "by_host", default=""),
            destination_ip="",
            raw_received_line=safe_get(hop, "raw_received", default=""),
            classification="Anomaly" if safe_get(hop, "anomalies", default=[]) else "Normal",
            ai_description=""
        ))
    
    routing_text = " ".join([hop.get("from_host", "") + hop.get("by_host", "") for hop in routing]).lower()
    uses_m365 = "outlook.com" in routing_text or "office.com" in routing_text
    uses_exchange = "exchange" in routing_text or "outlook" in routing_text
    
    general_data = GeneralDataTable(
        asunto=subject[:200],
        from_header=from_header[:200],
        to=to[:200],
        sender_domain=sender_domain
    )
    
    urls = safe_get_list(artifacts_dict, "urls")
    url_list = [safe_get(u, "normalized", default="") for u in urls[:20] if u]
    
    requested_actions = []
    pressure_lang = []
    displayed_brand = ""
    
    for url in urls[:10]:
        normalized = safe_get(url, "normalized", default="").lower()
        if "login" in normalized or "signin" in normalized:
            requested_actions.append("Login/Credentials")
        if "verify" in normalized or "confirm" in normalized:
            requested_actions.append("Account Verification")
    
    for imp in impersonation[:5]:
        displayed_brand = safe_get(imp, "brand_candidate", default="")
        break
    
    email_data = EmailData(
        subject=subject[:300],
        from_header=from_header[:300],
        to=to[:300],
        sender_domain=sender_domain,
        reply_to=reply_to[:300],
        return_path=return_path[:300],
        message_id=message_id[:300],
        date_header=date_header[:200],
        authentication=AuthenticationData(
            spf_result=spf_result,
            spf_domain=spf_domain,
            dkim_result=dkim_result,
            dkim_domain=dkim_domain,
            dmarc_result=dmarc_result,
            dmarc_domain=dmarc_domain
        )
    )
    
    headers_analysis = HeadersAnalysis(
        raw_headers_available=len(headers) > 0,
        general_data_table=general_data,
        hops=hops,
        routing_observations=RoutingObservations(
            uses_microsoft_365=uses_m365,
            uses_exchange_online=uses_exchange,
            internal_provider_route_only=False,
            authorized_sender_in_spf=(spf_result == "pass")
        )
    )
    
    sender_validation = SenderDomainValidation(
        domain=sender_domain,
        is_institutional=False,
        summary_facts=[]
    )
    
    artifacts_analysis = ArtifactsAnalysis(
        email_body_summary_facts=[],
        email_body_indicators=EmailBodyIndicators(
            theme="",
            pressure_language=list(set(pressure_lang))[:5],
            requested_actions=list(set(requested_actions))[:5],
            unusual_requests=[],
            urls_in_body=url_list[:10],
            displayed_brand=displayed_brand
        ),
        landing_page=LandingPage()
    )
    
    suspicious_infra = SuspiciousInfrastructure(
        primary_domain=sender_domain,
        related_subdomains=[],
        resolved_ips=[],
        reputation=ReputationData()
    )
    
    ioc_list = []
    for ioc in iocs[:50]:
        ioc_list.append(IOCEntryReport(
            indicator_type=safe_get(ioc, "type", default=""),
            value=safe_get(ioc, "value", default="")[:200],
            detection_date=datetime.utcnow().strftime("%Y-%m-%d"),
            vt_score="",
            source=safe_get(ioc, "source", default=""),
            recommendation="",
            comment=safe_get(ioc, "context", default="")[:200]
        ))
    
    references = []
    if message_id:
        references.append(ReferenceEntry(type="message_id", value=message_id[:200]))
    if safe_get(metadata, "input_filename"):
        references.append(ReferenceEntry(type="file", value=safe_get(metadata, "input_filename", default="")))
    
    ai_inputs = AIInputs(
        summary_facts=[f"Risk Score: {safe_get(risk, 'score', default='N/A')}/100 ({safe_get(risk, 'severity', default='unknown')})"],
        sender_domain_validation_facts=[f"Sender domain: {sender_domain}"],
        artifact_analysis_facts=[f"Brand impersonation: {displayed_brand}"] if displayed_brand else []
    )
    
    report = InvestigationReport(
        report_type="email_investigation",
        case_id=case_id,
        document=Document(
            title="Investigación respecto a correo electrónico",
            metadata=DocumentMetadata(
                fecha=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            ),
            request_context=RequestContext()
        ),
        email=email_data,
        headers_analysis=headers_analysis,
        sender_domain_validation=sender_validation,
        artifacts_analysis=artifacts_analysis,
        suspicious_infrastructure=suspicious_infra,
        iocs=ioc_list,
        references=references,
        ai_inputs=ai_inputs,
        ai_outputs=AIOutputs()
    )
    
    return report
