"""Main EML parser orchestrator."""

import hashlib
import uuid
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

from emltriage.core.analysis.risk import calculate_risk_score
from emltriage.core.analysis.impersonation import detect_impersonation
from emltriage.core.extract.attachments import extract_attachments
from emltriage.core.extract.auth import extract_authentication_results
from emltriage.core.extract.bodies import extract_bodies
from emltriage.core.extract.headers import extract_headers, get_all_header_values
from emltriage.core.extract.iocs import extract_all_iocs
from emltriage.core.extract.received import parse_received_headers
from emltriage.core.extract.urls import extract_all_urls
from emltriage.core.msg_parser import parse_msg_file
from emltriage.core.models import (
    AnalysisMode,
    Artifacts,
    CaseMetadata,
    IOCsExtracted,
    IOCEntry,
    IOCType,
)
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


def parse_eml_file(
    file_path: Path,
    output_dir: Path,
    mode: AnalysisMode = AnalysisMode.TRIAGE,
    offline: bool = True,
    redact: bool = False,
    perform_dns_lookup: bool = False,
    brand_config_path: Optional[Path] = None,
    impersonation_algorithm: str = "weighted",
    excluded_brands: Optional[list[str]] = None,
    skip_impersonation: bool = False,
) -> Artifacts:
    """Parse an email file (.eml or .msg) and extract all artifacts.
    
    Args:
        file_path: Path to .eml or .msg file
        output_dir: Directory for output files
        mode: Analysis mode (triage or deep)
        offline: Whether to run in offline mode
        redact: Whether to redact PII
        perform_dns_lookup: Whether to perform DNS lookups
        brand_config_path: Optional path to custom brand configuration
        impersonation_algorithm: Scoring algorithm for impersonation (simple, weighted, threshold)
        excluded_brands: List of brand names to exclude from impersonation detection
        skip_impersonation: Whether to skip impersonation detection entirely
        
    Returns:
        Artifacts object with all extracted data
    """
    logger.info(f"Parsing email file: {file_path}")
    
    # Route based on file extension
    is_msg = file_path.suffix.lower() == '.msg'
    
    if is_msg:
        # Check for OLE magic bytes just to be sure
        try:
            with open(file_path, "rb") as f:
                header = f.read(8)
                if not header.startswith(b"\xd0\xcf\x11\xe0"):
                    logger.warning("File has .msg extension but missing OLE magic header.")
        except IOError:
            pass
            
        return parse_msg_file(
            file_path=file_path,
            output_dir=output_dir,
            mode=mode,
            offline=offline,
            redact=redact,
            perform_dns_lookup=perform_dns_lookup,
            brand_config_path=brand_config_path,
            impersonation_algorithm=impersonation_algorithm,
            excluded_brands=excluded_brands,
            skip_impersonation=skip_impersonation
        )
        
    # Standard EML Parsing
    # Read raw bytes for hashing
    raw_bytes = file_path.read_bytes()
    input_hash = hashlib.sha256(raw_bytes).hexdigest()
    
    # Generate run_id
    run_id = str(uuid.uuid4())
    
    # Parse email
    msg = EmailMessage()
    msg = parse_email_bytes(raw_bytes)
    
    # Create output directories
    attachments_dir = output_dir / "attachments"
    attachments_dir.mkdir(parents=True, exist_ok=True)
    
    # Extract metadata
    metadata = CaseMetadata(
        run_id=run_id,
        timestamp=datetime.now(timezone.utc),
        input_filename=file_path.name,
        input_hash_sha256=input_hash,
        input_size=len(raw_bytes),
        analysis_mode=mode,
        offline_mode=offline,
        redact_mode=redact,
    )
    
    # Extract headers
    logger.debug("Extracting headers")
    headers = extract_headers(msg)
    
    # Extract bodies
    logger.debug("Extracting bodies")
    bodies = extract_bodies(msg, output_dir=output_dir)
    
    # Extract URLs
    logger.debug("Extracting URLs")
    urls = extract_all_urls(bodies)
    
    # Extract attachments
    logger.debug("Extracting attachments")
    perform_deep = mode == AnalysisMode.DEEP
    attachments = extract_attachments(
        msg,
        output_dir=attachments_dir,
        perform_deep_analysis=perform_deep
    )
    
    # Parse Received headers (routing)
    logger.debug("Parsing routing information")
    received_headers = get_all_header_values(headers, 'Received')
    routing = parse_received_headers(received_headers)
    
    # Extract authentication results
    logger.debug("Extracting authentication results")
    authentication = extract_authentication_results(
        headers,
        perform_dkim_verify=not offline and perform_deep,
        perform_dns_lookup=perform_dns_lookup and not offline,
        raw_email_bytes=raw_bytes,
    )
    
    # Extract IOCs
    logger.debug("Extracting IOCs")
    iocs = extract_all_iocs(headers, bodies, urls, attachments)
    
    # Create artifacts
    artifacts = Artifacts(
        metadata=metadata,
        headers=headers,
        routing=routing,
        authentication=authentication,
        bodies=bodies,
        attachments=attachments,
        urls=urls,
        iocs=iocs,
        impersonation=[],  # Will be populated next
        risk=None,  # Will be calculated next
    )
    
    # Detect impersonation
    if not skip_impersonation:
        logger.debug("Detecting brand/domain impersonation")
        impersonation_findings = detect_impersonation(
            artifacts=artifacts,
            brand_config_path=brand_config_path,
            algorithm=impersonation_algorithm,
            excluded_brands=excluded_brands,
        )
        artifacts.impersonation = impersonation_findings
        logger.info(f"Impersonation detection: {len(impersonation_findings)} findings")
    
    # Calculate risk score
    logger.debug("Calculating risk score")
    artifacts.risk = calculate_risk_score(artifacts)
    
    logger.info(f"Parsing complete: {len(headers)} headers, {len(bodies)} bodies, "
                f"{len(attachments)} attachments, {len(urls)} URLs, {len(iocs)} IOCs")
    
    return artifacts


def parse_email_bytes(raw_bytes: bytes) -> EmailMessage:
    """Parse email from bytes.
    
    Args:
        raw_bytes: Raw email bytes
        
    Returns:
        EmailMessage object
    """
    from email.parser import BytesParser
    
    parser = BytesParser(policy=policy.default)
    return parser.parsebytes(raw_bytes)


def create_iocs_json(artifacts: Artifacts, filter_infrastructure: bool = True) -> IOCsExtracted:
    """Create IOCs JSON from artifacts with infrastructure filtering.
    
    Args:
        artifacts: Email artifacts
        filter_infrastructure: Whether to filter out known infrastructure domains
        
    Returns:
        IOCsExtracted object with filtered IOCs and infrastructure separated
    """
    from emltriage.core.ioc_filter import create_filtered_iocs_json as filter_iocs
    
    # Get all IOCs by type
    all_domains = [ioc for ioc in artifacts.iocs if ioc.type == IOCType.DOMAIN]
    all_ips = [ioc for ioc in artifacts.iocs if ioc.type in (IOCType.IP, IOCType.IPV4, IOCType.IPV6)]
    emails = [ioc for ioc in artifacts.iocs if ioc.type == IOCType.EMAIL]
    urls_list = [ioc for ioc in artifacts.iocs if ioc.type == IOCType.URL]
    hashes = [ioc for ioc in artifacts.iocs if ioc.type in 
              (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256)]
    filenames = [ioc for ioc in artifacts.iocs if ioc.type == IOCType.FILENAME]
    message_ids = [ioc for ioc in artifacts.iocs if ioc.type == IOCType.MESSAGE_ID]
    
    infrastructure = []
    
    if filter_infrastructure:
        # Filter infrastructure from domains
        domains, infra_domains = filter_iocs(all_domains, filter_private_ips=False)
        infrastructure.extend(infra_domains)
        
        # Filter infrastructure from IPs (private IPs)
        ips, infra_ips = filter_iocs(all_ips, filter_private_ips=True)
        infrastructure.extend(infra_ips)
    else:
        domains = all_domains
        ips = all_ips
    
    return IOCsExtracted(
        run_id=artifacts.metadata.run_id,
        domains=domains,
        ips=ips,
        emails=emails,
        urls=urls_list,
        hashes=hashes,
        filenames=filenames,
        message_ids=message_ids,
        infrastructure=infrastructure,
    )
