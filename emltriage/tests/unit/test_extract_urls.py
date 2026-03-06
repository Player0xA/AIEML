"""Unit tests for URL extraction."""

import pytest

from emltriage.core.extract.urls import (
    deobfuscate_url,
    extract_context,
    extract_urls_from_text,
    normalize_url,
)


class TestDeobfuscateUrl:
    """Test URL deobfuscation."""
    
    def test_hxxp_substitution(self):
        """Test hxxp:// to http:// substitution."""
        url = "hxxp://example.com"
        deobf, was_obf, obf_type = deobfuscate_url(url)
        assert deobf == "http://example.com"
        assert was_obf
        assert "hxxp" in obf_type.lower()
    
    def test_bracket_dot_substitution(self):
        """Test [.] to . substitution."""
        url = "http://example[.]com"
        deobf, was_obf, obf_type = deobfuscate_url(url)
        assert deobf == "http://example.com"
        assert was_obf
    
    def test_no_obfuscation(self):
        """Test URL without obfuscation."""
        url = "http://example.com"
        deobf, was_obf, obf_type = deobfuscate_url(url)
        assert deobf == url
        assert not was_obf
        assert obf_type is None
    
    def test_multiple_obfuscation_techniques(self):
        """Test URL with multiple obfuscation techniques."""
        url = "hxxp[:]//example[.]com/path"
        deobf, was_obf, _ = deobfuscate_url(url)
        assert deobf == "http://example.com/path"
        assert was_obf


class TestNormalizeUrl:
    """Test URL normalization."""
    
    def test_lowercase_normalization(self):
        """Test that URLs are lowercased."""
        url = "HTTP://EXAMPLE.COM/PATH"
        normalized = normalize_url(url)
        assert normalized == "http://example.com/path"


class TestExtractContext:
    """Test context extraction."""
    
    def test_extract_context(self):
        """Test extracting surrounding context."""
        text = "This is a test sentence with a URL http://example.com in the middle"
        start = text.find("http")
        end = start + len("http://example.com")
        
        context = extract_context(text, start, end, context_chars=10)
        assert "http://example.com" in context
        assert "URL" in context or "with" in context


class TestExtractUrlsFromText:
    """Test URL extraction from text."""
    
    def test_extract_single_url(self):
        """Test extracting single URL."""
        text = "Check out http://example.com for more info"
        urls = extract_urls_from_text(text)
        
        assert len(urls) == 1
        assert urls[0].raw == "http://example.com"
        assert urls[0].source == "plain"
    
    def test_extract_multiple_urls(self):
        """Test extracting multiple URLs."""
        text = "Visit http://example.com and https://test.org"
        urls = extract_urls_from_text(text)
        
        assert len(urls) == 2
        raw_urls = [u.raw for u in urls]
        assert "http://example.com" in raw_urls
        assert "https://test.org" in raw_urls
    
    def test_extract_obfuscated_url(self):
        """Test extracting and deobfuscating URL."""
        text = "Visit hxxp://example.com for more"
        urls = extract_urls_from_text(text)
        
        assert len(urls) == 1
        assert urls[0].is_obfuscated
        assert urls[0].deobfuscated == "http://example.com"
    
    def test_no_urls_in_text(self):
        """Test text without URLs."""
        text = "This is just plain text without any URLs"
        urls = extract_urls_from_text(text)
        
        assert len(urls) == 0


class TestExtractUrlsFromHtml:
    """Test URL extraction from HTML."""
    
    def test_extract_from_href(self):
        """Test extracting URLs from href attributes."""
        from emltriage.core.extract.urls import extract_urls_from_html
        
        html = '<a href="http://example.com">Click here</a>'
        urls = extract_urls_from_html(html)
        
        assert len(urls) >= 1
        assert any(u.raw == "http://example.com" for u in urls)
    
    def test_extract_from_text(self):
        """Test extracting URLs from visible text in HTML."""
        from emltriage.core.extract.urls import extract_urls_from_html
        
        html = '<p>Visit http://example.com for more info</p>'
        urls = extract_urls_from_html(html)
        
        # Should extract from visible text
        assert any(u.raw == "http://example.com" for u in urls)
