"""Pydantic schemas for emltriage artifacts."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class ImpersonationTechnique(str, Enum):
    """Techniques used for brand/domain impersonation."""
    
    TYPOSQUAT = "typosquat"  # Levenshtein distance typo
    HOMOGLYPH = "homoglyph"  # Unicode confusable characters
    KEYWORD_MATCH = "keyword_match"  # Brand name in wrong domain
    PUNYCODE = "punycode"  # IDN homograph attack
    DISPLAY_NAME = "display_name"  # Display name doesn't match domain
    REPLY_TO_MISMATCH = "reply_to_mismatch"  # Reply-To differs from From
    SUBDOMAIN_ABUSE = "subdomain_abuse"  # Legit domain with malicious subdomain


class ImpersonationAlgorithm(str, Enum):
    """Scoring algorithms for impersonation detection."""
    
    SIMPLE = "simple"
    WEIGHTED = "weighted"
    THRESHOLD = "threshold"


class ImpersonationFinding(BaseModel):
    """Individual brand/domain impersonation finding."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    brand_candidate: str = Field(..., description="Detected brand being impersonated")
    detected_domain: str = Field(..., description="Domain detected as potential impersonation")
    technique: ImpersonationTechnique = Field(..., description="Impersonation technique used")
    score: float = Field(..., ge=0.0, le=1.0, description="Impersonation confidence score")
    severity: Severity = Field(..., description="Severity level")
    evidence_fields: list[str] = Field(
        default_factory=list,
        description="Fields where detection occurred: headers.From, body_urls, routing"
    )
    algorithm: ImpersonationAlgorithm = Field(
        default=ImpersonationAlgorithm.WEIGHTED,
        description="Scoring algorithm used"
    )
    source: str = Field(default="impersonation_detector", description="Detection source")
    query: str = Field(..., description="Detection query: normalized domain vs brand")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Detection timestamp")
    normalized_tokens: list[str] = Field(
        default_factory=list,
        description="Normalized tokens for evidence traceability"
    )
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Detection confidence")
    cost: int = Field(default=0, description="Computational cost (usually 0 for local)")
    explanation: str = Field(..., description="Human-readable explanation of why flagged")


class AnalysisMode(str, Enum):
    """Analysis depth modes."""

    TRIAGE = "triage"
    DEEP = "deep"


class Severity(str, Enum):
    """Risk severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HeaderEntry(BaseModel):
    """Single email header entry with raw and decoded values."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(..., description="Header name")
    raw_value: str = Field(..., description="Raw header value (verbatim)")
    decoded_value: Optional[str] = Field(
        None, description="Decoded value if RFC 2047 encoded"
    )
    parsed: Optional[dict[str, Any]] = Field(
        None, description="Structured parsed data (for From/To/etc)"
    )


class URLEntry(BaseModel):
    """Extracted URL with context and normalization."""

    model_config = ConfigDict(populate_by_name=True)

    raw: str = Field(..., description="Raw URL as found in source")
    normalized: str = Field(..., description="Normalized URL")
    deobfuscated: str = Field(..., description="Deobfuscated URL (hxxp->http, etc)")
    context: str = Field(..., description="Surrounding text (±100 chars)")
    source: str = Field(
        ..., description="Source type: 'plain', 'html_href', 'html_text'"
    )
    evidence_ref: str = Field(..., description="Path to source in artifacts")
    is_obfuscated: bool = Field(default=False, description="Whether URL was obfuscated")
    obfuscation_type: Optional[str] = Field(
        None, description="Type of obfuscation detected"
    )


class IOCType(str, Enum):
    """Types of indicators of compromise."""

    DOMAIN = "domain"
    IP = "ip"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EMAIL = "email"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    FILENAME = "filename"
    MESSAGE_ID = "message_id"
    CVE = "cve"


class IOCEntry(BaseModel):
    """Individual IOC entry."""

    model_config = ConfigDict(populate_by_name=True)

    value: str = Field(..., description="IOC value")
    type: IOCType = Field(..., description="IOC type")
    normalized: Optional[str] = Field(None, description="Normalized form")
    context: Optional[str] = Field(None, description="Surrounding context")
    source: str = Field(..., description="Source: headers, body_plain, body_html, attachments")
    evidence_ref: str = Field(..., description="Path to source in artifacts")
    first_seen_in: str = Field(..., description="Where first found (header name or body)")


class AttachmentHash(BaseModel):
    """Cryptographic hashes for attachment."""

    md5: str = Field(..., description="MD5 hash")
    sha1: str = Field(..., description="SHA1 hash")
    sha256: str = Field(..., description="SHA256 hash")


class AttachmentEntry(BaseModel):
    """Email attachment entry."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(..., description="Unique attachment ID")
    filename_raw: str = Field(..., description="Raw filename from MIME")
    filename_decoded: Optional[str] = Field(
        None, description="Decoded filename if RFC 2047/2231 encoded"
    )
    content_type: str = Field(..., description="MIME content type")
    content_disposition: Optional[str] = Field(None, description="Content disposition")
    size: int = Field(..., description="Size in bytes")
    hashes: AttachmentHash = Field(..., description="Cryptographic hashes")
    magic_type: str = Field(..., description="File type via libmagic")
    is_risky: bool = Field(..., description="Whether file extension is risky")
    risk_flags: list[str] = Field(default_factory=list, description="Risk indicators")
    saved_path: Optional[str] = Field(None, description="Path where attachment saved")
    deep_analysis: Optional[dict[str, Any]] = Field(
        None, description="Deep analysis results (macros, etc)"
    )


class RoutingHop(BaseModel):
    """Parsed Received header hop."""

    model_config = ConfigDict(populate_by_name=True)

    hop_number: int = Field(..., description="Hop number (0 = most recent)")
    raw_received: str = Field(..., description="Raw Received header value")
    from_host: Optional[str] = Field(None, description="From host/MTA")
    by_host: Optional[str] = Field(None, description="By host/MTA")
    with_proto: Optional[str] = Field(None, description="Protocol used")
    id: Optional[str] = Field(None, description="Message ID at this hop")
    for_address: Optional[str] = Field(None, description="Intended recipient")
    date_raw: Optional[str] = Field(None, description="Raw date string")
    timestamp: Optional[datetime] = Field(None, description="Parsed timestamp (UTC)")
    is_private_ip: bool = Field(default=False, description="Whether 'from' is private IP")
    anomalies: list[str] = Field(default_factory=list, description="Detected anomalies")


class AuthResult(BaseModel):
    """Individual authentication mechanism result."""

    mechanism: str = Field(..., description="SPF, DKIM, DMARC, etc")
    result: str = Field(..., description="pass, fail, neutral, none, temperror, permerror")
    reason: Optional[str] = Field(None, description="Failure reason if applicable")
    details: Optional[dict[str, Any]] = Field(None, description="Additional details")


class AuthDomainResult(BaseModel):
    """Authentication results for a specific domain."""

    domain: str = Field(..., description="Domain being evaluated")
    results: list[AuthResult] = Field(default_factory=list)


class AuthenticationResults(BaseModel):
    """Complete authentication analysis."""

    model_config = ConfigDict(populate_by_name=True)

    raw_headers: list[str] = Field(default_factory=list, description="Raw header values")
    parsed_results: list[AuthDomainResult] = Field(default_factory=list)
    dkim_verified: Optional[bool] = Field(
        default=None, description="Whether DKIM signature cryptographically verified"
    )
    dkim_verify_error: Optional[str] = Field(default=None, description="Error if verification failed")
    spf_dns_record: Optional[str] = Field(default=None, description="SPF record if DNS queried")
    dmarc_dns_record: Optional[str] = Field(default=None, description="DMARC record if DNS queried")
    dns_queried: bool = Field(default=False, description="Whether DNS was queried")


class RiskReason(BaseModel):
    """Individual risk scoring reason."""

    code: str = Field(..., description="Reason code")
    description: str = Field(..., description="Human-readable description")
    weight: int = Field(..., description="Risk weight (0-100)")
    severity: Severity = Field(..., description="Severity level")
    evidence_refs: list[str] = Field(
        default_factory=list, description="Evidence references"
    )


class RiskScore(BaseModel):
    """Computed risk assessment."""

    model_config = ConfigDict(populate_by_name=True)

    score: int = Field(..., ge=0, le=100, description="Risk score 0-100")
    severity: Severity = Field(..., description="Severity classification")
    reasons: list[RiskReason] = Field(default_factory=list, description="Risk reasons")
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Confidence in assessment"
    )


class BodyEntry(BaseModel):
    """Email body content."""

    model_config = ConfigDict(populate_by_name=True)

    content_type: str = Field(..., description="MIME type")
    charset: Optional[str] = Field(None, description="Character set")
    encoding: Optional[str] = Field(None, description="Transfer encoding")
    content: Optional[str] = Field(None, description="Decoded text content")
    content_hash: Optional[str] = Field(None, description="SHA256 of decoded content")
    saved_path: Optional[str] = Field(None, description="Path to saved file")
    size: int = Field(..., description="Size in bytes")


class CaseMetadata(BaseModel):
    """Case-level metadata."""

    model_config = ConfigDict(populate_by_name=True)

    run_id: str = Field(..., description="Unique run identifier")
    timestamp: datetime = Field(..., description="Analysis timestamp (UTC)")
    tool_name: str = Field(default="emltriage", description="Tool name")
    tool_version: str = Field(default="0.1.0", description="Tool version")
    input_filename: str = Field(..., description="Input filename")
    input_hash_sha256: str = Field(..., description="SHA256 of input file")
    input_size: int = Field(..., description="Input file size in bytes")
    analysis_mode: AnalysisMode = Field(..., description="Analysis mode used")
    offline_mode: bool = Field(default=True, description="Whether offline mode was used")
    redact_mode: bool = Field(default=False, description="Whether redaction was applied")


class Artifacts(BaseModel):
    """Complete extraction artifacts."""

    model_config = ConfigDict(populate_by_name=True)

    metadata: CaseMetadata = Field(..., description="Case metadata")
    headers: list[HeaderEntry] = Field(default_factory=list, description="All headers")
    routing: list[RoutingHop] = Field(default_factory=list, description="Parsed routing hops")
    authentication: AuthenticationResults = Field(
        default_factory=lambda: AuthenticationResults()
    )
    bodies: list[BodyEntry] = Field(default_factory=list, description="Body parts")
    attachments: list[AttachmentEntry] = Field(default_factory=list, description="Attachments")
    urls: list[URLEntry] = Field(default_factory=list, description="Extracted URLs")
    iocs: list[IOCEntry] = Field(default_factory=list, description="All IOCs")
    impersonation: list[ImpersonationFinding] = Field(
        default_factory=list,
        description="Brand/domain impersonation findings"
    )
    risk: Optional[RiskScore] = Field(default=None, description="Risk assessment")


class FileManifestEntry(BaseModel):
    """Single file in manifest."""

    path: str = Field(..., description="Relative path")
    sha256: str = Field(..., description="SHA256 hash")
    size: int = Field(..., description="File size in bytes")
    content_type: Optional[str] = Field(None, description="Content type if known")


class Manifest(BaseModel):
    """Complete manifest of analysis outputs."""

    model_config = ConfigDict(populate_by_name=True)

    run_id: str = Field(..., description="Run identifier (matches artifacts)")
    timestamp: datetime = Field(..., description="Manifest creation time (UTC)")
    tool_version: str = Field(..., description="Tool version")
    input_file: FileManifestEntry = Field(..., description="Input file details")
    output_files: list[FileManifestEntry] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict, description="Analysis parameters")


class IOCsExtracted(BaseModel):
    """Normalized IOC collection."""

    model_config = ConfigDict(populate_by_name=True)

    run_id: str = Field(..., description="Run identifier")
    domains: list[IOCEntry] = Field(default_factory=list)
    ips: list[IOCEntry] = Field(default_factory=list)
    emails: list[IOCEntry] = Field(default_factory=list)
    urls: list[IOCEntry] = Field(default_factory=list)
    hashes: list[IOCEntry] = Field(default_factory=list)
    filenames: list[IOCEntry] = Field(default_factory=list)
    message_ids: list[IOCEntry] = Field(default_factory=list)
    infrastructure: list[IOCEntry] = Field(
        default_factory=list,
        description="Filtered infrastructure IOCs (noise) - preserved for reference"
    )
