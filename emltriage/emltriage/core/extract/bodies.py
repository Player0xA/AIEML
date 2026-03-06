"""Email body extraction."""

import hashlib
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

from bs4 import BeautifulSoup

from emltriage.core.models import BodyEntry
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


def decode_payload(part: EmailMessage) -> tuple[Optional[str], Optional[bytes], str]:
    """Decode message part payload.
    
    Args:
        part: Email message part
        
    Returns:
        Tuple of (text_content, binary_content, charset)
    """
    charset = part.get_content_charset() or 'utf-8'
    
    try:
        # Try to get payload
        payload = part.get_payload(decode=True)
        if payload is None:
            return None, None, charset
        
        if isinstance(payload, list):
            # Multipart payload, not expected for bodies
            return None, None, charset
        
        if isinstance(payload, str):
            # Already decoded string
            return payload, None, charset
        
        # Binary payload
        content_type = part.get_content_type()
        
        if content_type.startswith('text/'):
            try:
                text = payload.decode(charset, errors='replace')
                return text, None, charset
            except (LookupError, UnicodeDecodeError) as e:
                logger.warning(f"Failed to decode text with charset {charset}: {e}")
                text = payload.decode('utf-8', errors='replace')
                return text, None, 'utf-8'
        else:
            return None, payload, charset
            
    except Exception as e:
        logger.error(f"Failed to decode payload: {e}")
        return None, None, charset


def extract_visible_text_from_html(html_content: str) -> str:
    """Extract visible text from HTML.
    
    Args:
        html_content: HTML content
        
    Returns:
        Visible text
    """
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
        
        # Get text
        text = soup.get_text(separator='\n', strip=True)
        
        # Clean up whitespace
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = '\n'.join(chunk for chunk in chunks if chunk)
        
        return text
    except Exception as e:
        logger.warning(f"Failed to parse HTML: {e}")
        import re
        text = re.sub(r'<[^>]+>', ' ', html_content)
        text = re.sub(r'\s+', ' ', text).strip()
        return text


def extract_bodies(msg: EmailMessage, output_dir: Optional[Path] = None) -> list[BodyEntry]:
    """Extract all body parts from email.
    
    Args:
        msg: Email message
        output_dir: Directory to save body files
        
    Returns:
        List of BodyEntry objects
    """
    bodies = []
    body_count = 0
    
    def process_part(part: EmailMessage, depth: int = 0) -> None:
        nonlocal body_count
        
        content_type = part.get_content_type()
        content_disposition = part.get_content_disposition() or ''
        
        # Skip attachments
        if content_disposition.startswith('attachment'):
            return
        
        # Check if this is a body part
        if content_type in ['text/plain', 'text/html']:
            body_count += 1
            text_content, binary_content, charset = decode_payload(part)
            
            # Calculate hash
            content_hash = None
            if text_content:
                content_hash = hashlib.sha256(text_content.encode('utf-8')).hexdigest()
            elif binary_content:
                content_hash = hashlib.sha256(binary_content).hexdigest()
            
            transfer_encoding = part.get('Content-Transfer-Encoding', '').lower()
            
            content_size = 0
            if binary_content:
                content_size = len(binary_content)
            elif text_content:
                content_size = len(text_content.encode('utf-8'))
            
            entry = BodyEntry(
                content_type=content_type,
                charset=charset,
                encoding=transfer_encoding if transfer_encoding else None,
                content=text_content,
                content_hash=content_hash,
                saved_path=None,
                size=content_size,
            )
            
            # Save to file if output_dir provided
            if output_dir:
                ext = 'txt' if content_type == 'text/plain' else 'html'
                filename = f"body_{body_count}.{ext}"
                filepath = output_dir / filename
                
                try:
                    if text_content:
                        filepath.write_text(text_content, encoding='utf-8')
                    elif binary_content:
                        filepath.write_bytes(binary_content)
                    entry.saved_path = str(filepath)
                except Exception as e:
                    logger.error(f"Failed to save body to {filepath}: {e}")
            
            bodies.append(entry)
        
        # Process multipart children
        if part.is_multipart():
            payload = part.get_payload()
            if isinstance(payload, list):
                for subpart in payload:
                    if isinstance(subpart, EmailMessage):
                        process_part(subpart, depth + 1)
    
    process_part(msg)
    return bodies


def get_body_text(bodies: list[BodyEntry], content_type: str = 'text/plain') -> Optional[str]:
    """Get body text of specific content type.
    
    Args:
        bodies: List of body entries
        content_type: Content type to retrieve
        
    Returns:
        Body text or None
    """
    for body in bodies:
        if body.content_type == content_type:
            return body.content
    return None
