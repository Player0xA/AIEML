"""URL extraction and deobfuscation."""

import re
from typing import Optional

from emltriage.core.models import URLEntry
from emltriage.utils.constants import RE_URL, URL_DEOBFS_PATTERNS
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


def deobfuscate_url(url: str) -> tuple[str, bool, Optional[str]]:
    """Deobfuscate URL by reversing common obfuscation techniques.
    
    Args:
        url: Potentially obfuscated URL
        
    Returns:
        Tuple of (deobfuscated_url, was_obfuscated, obfuscation_type)
    """
    original = url
    obfuscation_type = None
    
    for pattern, replacement, name in URL_DEOBFS_PATTERNS:
        if pattern.search(url):
            url = pattern.sub(replacement, url)
            if not obfuscation_type:
                obfuscation_type = name
    
    was_obfuscated = url != original
    return url, was_obfuscated, obfuscation_type


def normalize_url(url: str) -> str:
    """Normalize URL for comparison.
    
    Args:
        url: URL to normalize
        
    Returns:
        Normalized URL
    """
    # Convert to lowercase for protocol and domain
    url = url.lower()
    
    # Remove common tracking parameters (optional, can be extended)
    # For now, keep it simple
    
    return url


def extract_context(text: str, start: int, end: int, context_chars: int = 100) -> str:
    """Extract surrounding context for a match.
    
    Args:
        text: Full text
        start: Match start position
        end: Match end position
        context_chars: Number of context characters
        
    Returns:
        Context string
    """
    context_start = max(0, start - context_chars)
    context_end = min(len(text), end + context_chars)
    
    return text[context_start:context_end]


def extract_urls_from_text(text: str, source: str = "plain") -> list[URLEntry]:
    """Extract URLs from plain text.
    
    Args:
        text: Text to search
        source: Source type for evidence tracking
        
    Returns:
        List of URLEntry objects
    """
    urls = []
    seen = set()
    
    for match in RE_URL.finditer(text):
        raw_url = match.group()
        
        # Skip if already seen (normalized)
        normalized = normalize_url(raw_url)
        if normalized in seen:
            continue
        seen.add(normalized)
        
        # Deobfuscate
        deobf_url, was_obf, obf_type = deobfuscate_url(raw_url)
        deobf_normalized = normalize_url(deobf_url)
        
        # Extract context
        context = extract_context(text, match.start(), match.end())
        
        entry = URLEntry(
            raw=raw_url,
            normalized=normalized,
            deobfuscated=deobf_normalized,
            context=context,
            source=source,
            evidence_ref=f"bodies.{source}",
            is_obfuscated=was_obf,
            obfuscation_type=obf_type,
        )
        urls.append(entry)
    
    return urls


def extract_urls_from_html(html: str) -> list[URLEntry]:
    """Extract URLs from HTML (href attributes and visible text).
    
    Args:
        html: HTML content
        
    Returns:
        List of URLEntry objects
    """
    from bs4 import BeautifulSoup
    
    urls = []
    seen = set()
    
    try:
        soup = BeautifulSoup(html, 'lxml')
        
        # Extract from href attributes
        for tag in soup.find_all(href=True):
            raw_url = tag['href']
            normalized = normalize_url(raw_url)
            
            if normalized in seen:
                continue
            seen.add(normalized)
            
            # Deobfuscate
            deobf_url, was_obf, obf_type = deobfuscate_url(raw_url)
            deobf_normalized = normalize_url(deobf_url)
            
            # Get visible text if available
            visible_text = tag.get_text(strip=True)
            context = visible_text if visible_text else str(tag)
            
            entry = URLEntry(
                raw=raw_url,
                normalized=normalized,
                deobfuscated=deobf_normalized,
                context=context[:200],  # Limit context length
                source="html_href",
                evidence_ref=f"bodies.html.href",
                is_obfuscated=was_obf,
                obfuscation_type=obf_type,
            )
            urls.append(entry)
        
        # Also extract from visible text (same as plain text extraction)
        visible_text = soup.get_text(separator=' ', strip=True)
        text_urls = extract_urls_from_text(visible_text, source="html_text")
        
        for entry in text_urls:
            if entry.normalized not in seen:
                seen.add(entry.normalized)
                urls.append(entry)
                
    except Exception as e:
        logger.warning(f"Failed to parse HTML for URLs: {e}")
    
    return urls


def extract_all_urls(bodies: list) -> list[URLEntry]:
    """Extract URLs from all bodies.
    
    Args:
        bodies: List of BodyEntry objects
        
    Returns:
        Combined list of URLEntry objects
    """
    all_urls = []
    
    for body in bodies:
        if not body.content:
            continue
        
        if body.content_type == 'text/plain':
            urls = extract_urls_from_text(body.content, source="plain")
            all_urls.extend(urls)
        elif body.content_type == 'text/html':
            urls = extract_urls_from_html(body.content)
            all_urls.extend(urls)
    
    return all_urls
