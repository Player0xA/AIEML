"""Report schema models matching the desired output format."""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class DocumentMetadata(BaseModel):
    tlp: str = Field(default="", description="Traffic Light Protocol")
    linea_servicio: str = Field(default="", description="Service line")
    categoria: str = Field(default="", description="Category")
    serial: str = Field(default="", description="Serial number")
    fecha: str = Field(default="", description="Date")
    ticket_interno: str = Field(default="", description="Internal ticket")


class RequestContext(BaseModel):
    tracking_id: str = Field(default="", description="Tracking ID")
    contract_reference: str = Field(default="", description="Contract reference")
    client_name: str = Field(default="", description="Client name")
    provider_name: str = Field(default="", description="Provider name")


class AuthenticationData(BaseModel):
    spf_result: str = Field(default="", description="SPF result")
    spf_domain: str = Field(default="", description="SPF domain")
    dkim_result: str = Field(default="", description="DKIM result")
    dkim_domain: str = Field(default="", description="DKIM domain")
    dmarc_result: str = Field(default="", description="DMARC result")
    dmarc_domain: str = Field(default="", description="DMARC domain")


class EmailData(BaseModel):
    subject: str = Field(default="", description="Email subject")
    from_header: str = Field(default="", description="From address")
    to: str = Field(default="", description="To address")
    sender_domain: str = Field(default="", description="Sender domain")
    reply_to: str = Field(default="", description="Reply-To address")
    return_path: str = Field(default="", description="Return-Path")
    message_id: str = Field(default="", description="Message-ID")
    date_header: str = Field(default="", description="Date header")
    authentication: AuthenticationData = Field(
        default_factory=AuthenticationData,
        description="Authentication results"
    )


class HopData(BaseModel):
    hop_number: int = Field(default=0, description="Hop number")
    source: str = Field(default="", description="Source host")
    source_ip: str = Field(default="", description="Source IP")
    destination: str = Field(default="", description="Destination host")
    destination_ip: str = Field(default="", description="Destination IP")
    raw_received_line: str = Field(default="", description="Raw Received header")
    classification: str = Field(default="", description="Hop classification")
    ai_description: str = Field(default="", description="AI description of hop")


class RoutingObservations(BaseModel):
    uses_microsoft_365: bool = Field(default=False, description="Uses Microsoft 365")
    uses_exchange_online: bool = Field(default=False, description="Uses Exchange Online")
    internal_provider_route_only: bool = Field(default=False, description="Internal provider only")
    authorized_sender_in_spf: bool = Field(default=False, description="Authorized sender in SPF")


class GeneralDataTable(BaseModel):
    asunto: str = Field(default="", description="Subject")
    from_header: str = Field(default="", description="From")
    to: str = Field(default="", description="To")
    sender_domain: str = Field(default="", description="Sender domain")


class HeadersAnalysis(BaseModel):
    raw_headers_available: bool = Field(default=True, description="Raw headers available")
    general_data_table: GeneralDataTable = Field(
        default_factory=GeneralDataTable,
        description="General data table"
    )
    hops: list[HopData] = Field(default_factory=list, description="Routing hops")
    routing_observations: RoutingObservations = Field(
        default_factory=RoutingObservations,
        description="Routing observations"
    )


class SenderDomainValidation(BaseModel):
    domain: str = Field(default="", description="Sender domain")
    is_institutional: bool = Field(default=False, description="Is institutional domain")
    registrant: str = Field(default="", description="Registrant")
    creation_year: str = Field(default="", description="Creation year")
    nameservers: list[str] = Field(default_factory=list, description="Name servers")
    provider: str = Field(default="", description="Provider")
    country: str = Field(default="", description="Country")
    summary_facts: list[str] = Field(default_factory=list, description="Summary facts")
    evidence_image_path: str = Field(default="", description="Evidence image path")
    evidence_image_caption: str = Field(default="", description="Evidence image caption")


class EmailBodyIndicators(BaseModel):
    theme: str = Field(default="", description="Email theme")
    pressure_language: list[str] = Field(default_factory=list, description="Pressure language used")
    requested_actions: list[str] = Field(default_factory=list, description="Requested actions")
    unusual_requests: list[str] = Field(default_factory=list, description="Unusual requests")
    urls_in_body: list[str] = Field(default_factory=list, description="URLs in body")
    displayed_brand: str = Field(default="", description="Displayed brand")


class EmailBodyImage(BaseModel):
    path: str = Field(default="", description="Image path")
    caption: str = Field(default="", description="Image caption")


class LandingPage(BaseModel):
    url: str = Field(default="", description="Landing page URL")
    domain: str = Field(default="", description="Landing page domain")
    subdomain: str = Field(default="", description="Subdomain")
    impersonated_brand: str = Field(default="", description="Impersonated brand")
    steps_requested: list[str] = Field(default_factory=list, description="Steps requested")
    captured_fields: list[str] = Field(default_factory=list, description="Captured fields")
    exfiltration_behavior: list[str] = Field(default_factory=list, description="Exfiltration behavior")
    anti_analysis_notes: list[str] = Field(default_factory=list, description="Anti-analysis notes")
    destination_image_path: str = Field(default="", description="Destination image path")
    destination_image_caption: str = Field(default="", description="Destination image caption")


class ArtifactsAnalysis(BaseModel):
    email_body_summary_facts: list[str] = Field(default_factory=list, description="Email body summary facts")
    email_body_indicators: EmailBodyIndicators = Field(
        default_factory=EmailBodyIndicators,
        description="Email body indicators"
    )
    email_body_image_path: str = Field(default="", description="Email body image path")
    email_body_image_caption: str = Field(default="", description="Email body image caption")
    landing_page: LandingPage = Field(default_factory=LandingPage, description="Landing page analysis")


class ResolvedIP(BaseModel):
    ip: str = Field(default="", description="IP address")
    country: str = Field(default="", description="Country")
    provider: str = Field(default="", description="Provider/ASN")


class ReputationData(BaseModel):
    source: str = Field(default="VirusTotal", description="Reputation source")
    domain_score: str = Field(default="", description="Domain score")
    subdomain_score: str = Field(default="", description="Subdomain score")
    ip_score: str = Field(default="", description="IP score")
    detections_summary: list[str] = Field(default_factory=list, description="Detections summary")
    malicious_classification: list[str] = Field(default_factory=list, description="Malicious classifications")


class SuspiciousInfrastructure(BaseModel):
    primary_domain: str = Field(default="", description="Primary domain")
    related_subdomains: list[str] = Field(default_factory=list, description="Related subdomains")
    resolved_ips: list[ResolvedIP] = Field(default_factory=list, description="Resolved IPs")
    reputation: ReputationData = Field(default_factory=ReputationData, description="Reputation data")
    infrastructure_notes: list[str] = Field(default_factory=list, description="Infrastructure notes")
    evidence_image_path: str = Field(default="", description="Evidence image path")
    evidence_image_caption: str = Field(default="", description="Evidence image caption")


class IOCEntryReport(BaseModel):
    indicator_type: str = Field(default="", description="Indicator type")
    value: str = Field(default="", description="Indicator value")
    detection_date: str = Field(default="", description="Detection date")
    vt_score: str = Field(default="", description="VirusTotal score")
    source: str = Field(default="", description="Source")
    recommendation: str = Field(default="", description="Recommendation")
    comment: str = Field(default="", description="Comment")


class ReferenceEntry(BaseModel):
    type: str = Field(default="", description="Reference type")
    value: str = Field(default="", description="Reference value")


class AIInputs(BaseModel):
    possible_impact_facts: list[str] = Field(default_factory=list, description="Possible impact facts")
    summary_facts: list[str] = Field(default_factory=list, description="Summary facts")
    header_analysis_facts: list[str] = Field(default_factory=list, description="Header analysis facts")
    sender_domain_validation_facts: list[str] = Field(default_factory=list, description="Sender domain validation facts")
    artifact_analysis_facts: list[str] = Field(default_factory=list, description="Artifact analysis facts")
    suspicious_infrastructure_facts: list[str] = Field(default_factory=list, description="Suspicious infrastructure facts")
    conclusion_facts: list[str] = Field(default_factory=list, description="Conclusion facts")
    recommendation_facts: list[str] = Field(default_factory=list, description="Recommendation facts")


class AIOutputs(BaseModel):
    posible_impacto: str = Field(default="", description="Possible impact")
    resumen_intro: str = Field(default="", description="Introduction summary")
    resumen_bullets: list[str] = Field(default_factory=list, description="Summary bullets")
    headers_intro: str = Field(default="", description="Headers introduction")
    headers_route_interpretation: str = Field(default="", description="Headers route interpretation")
    sender_domain_validation_text: str = Field(default="", description="Sender domain validation text")
    artifact_email_body_text: str = Field(default="", description="Email body analysis text")
    artifact_landing_page_text: str = Field(default="", description="Landing page analysis text")
    artifact_exfiltration_text: str = Field(default="", description="Exfiltration analysis text")
    suspicious_infrastructure_text: str = Field(default="", description="Suspicious infrastructure text")
    conclusiones: str = Field(default="", description="Conclusions")
    recomendaciones: list[str] = Field(default_factory=list, description="Recommendations")


class Document(BaseModel):
    title: str = Field(default="Investigación respecto a correo electrónico", description="Document title")
    metadata: DocumentMetadata = Field(default_factory=DocumentMetadata, description="Document metadata")
    request_context: RequestContext = Field(default_factory=RequestContext, description="Request context")


class InvestigationReport(BaseModel):
    report_type: str = Field(default="email_investigation", description="Report type")
    case_id: str = Field(default="", description="Case ID")
    document: Document = Field(default_factory=Document, description="Document")
    email: EmailData = Field(default_factory=EmailData, description="Email data")
    headers_analysis: HeadersAnalysis = Field(default_factory=HeadersAnalysis, description="Headers analysis")
    sender_domain_validation: SenderDomainValidation = Field(
        default_factory=SenderDomainValidation,
        description="Sender domain validation"
    )
    artifacts_analysis: ArtifactsAnalysis = Field(
        default_factory=ArtifactsAnalysis,
        description="Artifacts analysis"
    )
    suspicious_infrastructure: SuspiciousInfrastructure = Field(
        default_factory=SuspiciousInfrastructure,
        description="Suspicious infrastructure"
    )
    iocs: list[IOCEntryReport] = Field(default_factory=list, description="IOCs")
    references: list[ReferenceEntry] = Field(default_factory=list, description="References")
    ai_inputs: AIInputs = Field(default_factory=AIInputs, description="AI inputs")
    ai_outputs: AIOutputs = Field(default_factory=AIOutputs, description="AI outputs")
