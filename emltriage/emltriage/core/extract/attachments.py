"""Attachment extraction and analysis."""

import hashlib
import uuid
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

try:
    import magic
    HAVE_MAGIC = True
except ImportError:
    HAVE_MAGIC = False

from emltriage.core.models import AttachmentEntry, AttachmentHash
from emltriage.utils.constants import RISKY_EXTENSIONS
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


def get_file_extension(filename: str) -> str:
    """Extract file extension from filename.
    
    Args:
        filename: Filename
        
    Returns:
        Extension (lowercase) or empty string
    """
    if '.' in filename:
        return filename.split('.')[-1].lower()
    return ''


def is_risky_extension(ext: str) -> tuple[bool, list[str]]:
    """Check if file extension is risky.
    
    Args:
        ext: File extension (without dot)
        
    Returns:
        Tuple of (is_risky, risk_flags)
    """
    flags = []
    is_risky = ext.lower() in RISKY_EXTENSIONS
    
    if is_risky:
        flags.append(f"risky_extension_{ext}")
    
    return is_risky, flags


def decode_filename(raw_filename: str) -> tuple[str, Optional[str]]:
    """Decode RFC 2047/2231 encoded filename.
    
    Args:
        raw_filename: Raw filename
        
    Returns:
        Tuple of (raw, decoded)
    """
    from email.header import decode_header
    
    try:
        parts = decode_header(raw_filename)
        decoded_parts = []
        was_encoded = False
        
        for part, charset in parts:
            if isinstance(part, bytes):
                was_encoded = True
                try:
                    decoded_parts.append(part.decode(charset or 'utf-8', errors='replace'))
                except (LookupError, UnicodeDecodeError):
                    decoded_parts.append(part.decode('utf-8', errors='replace'))
            else:
                decoded_parts.append(part)
        
        decoded = ''.join(decoded_parts)
        return raw_filename, decoded if was_encoded else None
    except Exception:
        return raw_filename, None


def compute_hashes(data: bytes) -> AttachmentHash:
    """Compute MD5, SHA1, SHA256 hashes.
    
    Args:
        data: Binary data
        
    Returns:
        AttachmentHash object
    """
    return AttachmentHash(
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def identify_file_type(data: bytes) -> str:
    """Identify file type using libmagic.
    
    Args:
        data: Binary data
        
    Returns:
        MIME type or magic description
    """
    if not HAVE_MAGIC:
        return "unknown (python-magic not installed)"
    
    try:
        return magic.from_buffer(data, mime=True)
    except Exception as e:
        logger.warning(f"Failed to identify file type: {e}")
        return "unknown"


def extract_attachments(
    msg: EmailMessage,
    output_dir: Optional[Path] = None,
    perform_deep_analysis: bool = False
) -> list[AttachmentEntry]:
    """Extract all attachments from email.
    
    Args:
        msg: Email message
        output_dir: Directory to save attachments
        perform_deep_analysis: Whether to perform deep analysis
        
    Returns:
        List of AttachmentEntry objects
    """
    attachments = []
    
    def process_part(part: EmailMessage, depth: int = 0) -> None:
        content_disposition = part.get_content_disposition() or ''
        content_type = part.get_content_type()
        
        # Check if this is an attachment
        is_attachment = (
            content_disposition.startswith('attachment') or
            (content_disposition.startswith('inline') and part.get_filename())
        )
        
        if not is_attachment:
            # Process multipart children
            if part.is_multipart():
                payload = part.get_payload()
                if isinstance(payload, list):
                    for subpart in payload:
                        if isinstance(subpart, EmailMessage):
                            process_part(subpart, depth + 1)
            return
        
        # Extract attachment
        raw_filename = part.get_filename() or f"attachment_{uuid.uuid4().hex[:8]}"
        raw_filename_stored, decoded_filename = decode_filename(raw_filename)
        
        # Get payload
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                logger.warning(f"Empty payload for attachment: {raw_filename}")
                return
            
            if isinstance(payload, str):
                data = payload.encode('utf-8')
            elif isinstance(payload, bytes):
                data = payload
            else:
                logger.warning(f"Unexpected payload type for attachment: {type(payload)}")
                return
        except Exception as e:
            logger.error(f"Failed to decode attachment payload: {e}")
            return
        
        # Compute hashes
        hashes = compute_hashes(data)
        
        # Identify file type
        magic_type = identify_file_type(data)
        
        # Check if risky
        ext = get_file_extension(decoded_filename or raw_filename_stored)
        is_risky, risk_flags = is_risky_extension(ext)
        
        # Deep analysis
        deep_analysis = None
        if perform_deep_analysis and is_risky:
            deep_analysis = perform_attachment_analysis(data, magic_type, ext)
            if deep_analysis:
                risk_flags.extend(deep_analysis.get('risk_flags', []))
        
        entry = AttachmentEntry(
            id=str(uuid.uuid4()),
            filename_raw=raw_filename_stored,
            filename_decoded=decoded_filename,
            content_type=content_type,
            content_disposition=content_disposition,
            size=len(data),
            hashes=hashes,
            magic_type=magic_type,
            is_risky=is_risky or len(risk_flags) > 0,
            risk_flags=risk_flags,
            saved_path=None,
            deep_analysis=deep_analysis,
        )
        
        # Save to file if output_dir provided
        if output_dir:
            # Create safe filename
            safe_name = decoded_filename or raw_filename_stored
            safe_name = safe_name.replace('/', '_').replace('\\', '_')
            filepath = output_dir / f"{entry.id}_{safe_name}"
            
            try:
                filepath.write_bytes(data)
                entry.saved_path = str(filepath)
            except Exception as e:
                logger.error(f"Failed to save attachment: {e}")
        
        attachments.append(entry)
    
    process_part(msg)
    return attachments


def perform_attachment_analysis(data: bytes, mime_type: str, ext: str) -> Optional[dict]:
    """Perform deep analysis on attachment.
    
    Args:
        data: Attachment data
        mime_type: MIME type
        ext: File extension
        
    Returns:
        Analysis results or None
    """
    analysis = {
        'risk_flags': [],
        'indicators': [],
    }
    
    # Check for Office macros
    if ext in ['docm', 'dotm', 'xlsm', 'xltm', 'pptm', 'potm', 'doc', 'xls', 'ppt']:
        try:
            from oletools.olevba import VBA_Parser
            vba_parser = VBA_Parser(filename='temp', data=data)
            if vba_parser.detect_vba_macros():
                analysis['risk_flags'].append('contains_vba_macros')
                analysis['indicators'].append({
                    'type': 'vba_macros',
                    'description': 'VBA macros detected'
                })
            vba_parser.close()
        except Exception as e:
            logger.debug(f"Failed to analyze VBA: {e}")
    
    # Check for suspicious patterns
    if mime_type == 'application/pdf':
        # Could add PDF JavaScript analysis here
        pass
    
    return analysis if analysis['risk_flags'] or analysis['indicators'] else None
