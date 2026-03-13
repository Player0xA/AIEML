"""Native .msg format parser for emltriage."""

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import extract_msg
    HAVE_EXTRACT_MSG = True
except ImportError:
    HAVE_EXTRACT_MSG = False

from emltriage.core.analysis.risk import calculate_risk_score
from emltriage.core.analysis.impersonation import detect_impersonation
from emltriage.core.extract.auth import extract_authentication_results
from emltriage.core.extract.headers import extract_headers, get_all_header_values
from emltriage.core.extract.iocs import extract_all_iocs
from emltriage.core.extract.received import parse_received_headers
from emltriage.core.extract.urls import extract_all_urls
from emltriage.core.models import (
    AnalysisMode,
    Artifacts,
    CaseMetadata,
    BodyEntry,
    AttachmentEntry,
)
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


def extract_msg_bodies(msg_obj, output_dir: Optional[Path] = None) -> list[BodyEntry]:
    """Extract body parts directly from the OLE container.
    
    Args:
        msg_obj: extract_msg.Message object
        output_dir: Directory to save body files
        
    Returns:
        List of BodyEntry objects
    """
    bodies = []
    
    # 1. Plain Text Body
    if msg_obj.body:
        content = msg_obj.body
        try:
            content_bytes = content.encode('utf-8')
        except UnicodeEncodeError:
            content_bytes = content.encode('utf-8', errors='replace')
            
        entry = BodyEntry(
            content_type="text/plain",
            charset="utf-8",
            encoding="8bit",
            content=content,
            content_hash=hashlib.sha256(content_bytes).hexdigest(),
            saved_path=None,
            size=len(content_bytes),
        )
        if output_dir:
            filepath = output_dir / "body_plain.txt"
            try:
                filepath.write_text(content, encoding='utf-8', errors='replace')
                entry.saved_path = str(filepath)
            except Exception as e:
                logger.error(f"Failed to save MSG plain body: {e}")
        bodies.append(entry)

    # 2. HTML Body
    if msg_obj.htmlBody:
        # extract_msg might return bytes for htmlBody
        html_data = msg_obj.htmlBody
        if isinstance(html_data, bytes):
            html_content = html_data.decode('utf-8', errors='replace')
            content_bytes = html_data
        else:
            html_content = html_data
            content_bytes = html_data.encode('utf-8', errors='replace')
            
        entry = BodyEntry(
            content_type="text/html",
            charset="utf-8",
            encoding="8bit",
            content=html_content,
            content_hash=hashlib.sha256(content_bytes).hexdigest(),
            saved_path=None,
            size=len(content_bytes),
        )
        if output_dir:
            filepath = output_dir / "body_html.html"
            try:
                filepath.write_bytes(content_bytes)
                entry.saved_path = str(filepath)
            except Exception as e:
                logger.error(f"Failed to save MSG html body: {e}")
        bodies.append(entry)
        
    # 3. RTF Body
    if msg_obj.rtfBody:
        rtf_data = msg_obj.rtfBody
        entry = BodyEntry(
            content_type="text/rtf",
            charset=None,
            encoding="8bit",
            content=None,  # RTF is complex to parse into text directly here
            content_hash=hashlib.sha256(rtf_data).hexdigest(),
            saved_path=None,
            size=len(rtf_data),
        )
        if output_dir:
            filepath = output_dir / "body_rtf.rtf"
            try:
                filepath.write_bytes(rtf_data)
                entry.saved_path = str(filepath)
            except Exception as e:
                logger.error(f"Failed to save MSG rtf body: {e}")
        bodies.append(entry)

    return bodies


def extract_msg_attachments(
    msg_obj, 
    output_dir: Optional[Path] = None,
    perform_deep_analysis: bool = False
) -> list[AttachmentEntry]:
    """Extract attachments from the MSG object.
    
    Args:
        msg_obj: extract_msg.Message object
        output_dir: Directory to save attachments
        perform_deep_analysis: Whether to perform deep analysis
        
    Returns:
        List of AttachmentEntry objects
    """
    from emltriage.core.extract.attachments import (
        compute_hashes,
        identify_file_type,
        get_file_extension,
        is_risky_extension,
        perform_attachment_analysis
    )
    
    attachments = []
    
    for att in msg_obj.attachments:
        try:
            data = att.data
            if data is None:
                continue
                
            raw_filename = att.longFilename or att.shortFilename or f"attachment_{uuid.uuid4().hex[:8]}"
            content_type = getattr(att, 'mimetype', 'application/octet-stream')
            if not content_type:
               content_type = 'application/octet-stream'
                
            hashes = compute_hashes(data)
            magic_type = identify_file_type(data)
            ext = get_file_extension(raw_filename)
            is_risky, risk_flags = is_risky_extension(ext)
            
            deep_analysis = None
            if perform_deep_analysis and is_risky:
                deep_analysis = perform_attachment_analysis(data, magic_type, ext)
                if deep_analysis:
                    risk_flags.extend(deep_analysis.get('risk_flags', []))
            
            entry = AttachmentEntry(
                id=str(uuid.uuid4()),
                filename_raw=raw_filename,
                filename_decoded=raw_filename, # MSGs generally store filenames already decoded
                content_type=content_type,
                content_disposition="attachment",
                size=len(data),
                hashes=hashes,
                magic_type=magic_type,
                is_risky=is_risky or len(risk_flags) > 0,
                risk_flags=risk_flags,
                saved_path=None,
                deep_analysis=deep_analysis,
            )
            
            if output_dir:
                safe_name = raw_filename.replace('/', '_').replace('\\', '_')
                filepath = output_dir / f"{entry.id}_{safe_name}"
                try:
                    filepath.write_bytes(data)
                    entry.saved_path = str(filepath)
                except Exception as e:
                    logger.error(f"Failed to save MSG attachment: {e}")
                    
            attachments.append(entry)
            
        except Exception as e:
            logger.error(f"Failed to process MSG attachment: {e}")
            
    return attachments


def parse_msg_file(
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
    """Parse a .msg file and extract all artifacts seamlessly matching .eml pipeline.
    
    Args:
        file_path: Path to .msg file
        output_dir: Directory for output files
        mode: Analysis mode (triage or deep)
        offline: Whether to run in offline mode
        redact: Whether to redact PII
        perform_dns_lookup: Whether to perform DNS lookups
        brand_config_path: Optional path to custom brand configuration
        impersonation_algorithm: Scoring algorithm for impersonation
        excluded_brands: List of brand names to exclude from impersonation detection
        skip_impersonation: Whether to skip impersonation detection entirely
        
    Returns:
        Artifacts object with all extracted data
    """
    if not HAVE_EXTRACT_MSG:
        raise RuntimeError(
            "extract-msg library is not installed. "
            "Cannot parse .msg files. Install with: pip install extract-msg"
        )
        
    logger.info(f"Parsing MSG file using extract-msg: {file_path}")
    
    # Read raw bytes for hashing the container
    raw_bytes = file_path.read_bytes()
    input_hash = hashlib.sha256(raw_bytes).hexdigest()
    
    # Generate run_id
    run_id = str(uuid.uuid4())
    
    # Instantiate the extract_msg Message
    try:
        msg_obj = extract_msg.Message(file_path)
    except Exception as e:
        logger.error(f"Failed to parse MSG file: {e}")
        raise RuntimeError(f"Failed to parse MSG file using extract-msg: {e}") from e
    
    # We must treat the header block as an EmailMessage for our pipeline to work
    # We use `.asEmailMessage()` which extracts transport headers reliably without loss
    # (Since transport headers are the same regardless of MSG vs EML)
    email_msg = msg_obj.asEmailMessage()
    
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
    
    # Extract headers using our standard pipeline
    logger.debug("Extracting headers")
    headers = extract_headers(email_msg)
    
    # Extract bodies directly from the MSG native properties!
    logger.debug("Extracting bodies strictly from MSG properties")
    bodies = extract_msg_bodies(msg_obj, output_dir=output_dir)
    
    # Extract URLs
    logger.debug("Extracting URLs")
    urls = extract_all_urls(bodies)
    
    # Extract attachments directly from the MSG native properties!
    logger.debug("Extracting MSG attachments")
    perform_deep = mode == AnalysisMode.DEEP
    attachments = extract_msg_attachments(
        msg_obj,
        output_dir=attachments_dir,
        perform_deep_analysis=perform_deep
    )
    
    # Clean up the MAPI object
    msg_obj.close()
    
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
        impersonation=[],  
        risk=None, 
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
    
    logger.info(f"MSG Parsing complete: {len(headers)} headers, {len(bodies)} bodies, "
                f"{len(attachments)} attachments, {len(urls)} URLs, {len(iocs)} IOCs")
    
    return artifacts
