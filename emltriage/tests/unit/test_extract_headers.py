"""Unit tests for header extraction."""

import pytest
from email.message import EmailMessage
from email.policy import default

from emltriage.core.extract.headers import (
    decode_header_value,
    extract_headers,
    get_header_value,
    parse_address_header,
)


class TestDecodeHeaderValue:
    """Test header decoding."""
    
    def test_plain_header(self):
        """Test decoding of plain header."""
        value = "Hello World"
        decoded, was_encoded = decode_header_value(value)
        assert decoded == value
        assert not was_encoded
    
    def test_rfc2047_encoded(self):
        """Test RFC 2047 encoded header."""
        value = "=?UTF-8?B?SGVsbG8gV29ybGQ=?="  # "Hello World" in base64
        decoded, was_encoded = decode_header_value(value)
        assert decoded == "Hello World"
        assert was_encoded
    
    def test_empty_header(self):
        """Test empty header value."""
        value = ""
        decoded, was_encoded = decode_header_value(value)
        assert decoded is None
        assert not was_encoded


class TestParseAddressHeader:
    """Test address parsing."""
    
    def test_simple_email(self):
        """Test simple email address."""
        result = parse_address_header("test@example.com")
        assert result["address"] == "test@example.com"
        assert result["domain"] == "example.com"
        assert result["local_part"] == "test"
    
    def test_email_with_display_name(self):
        """Test email with display name."""
        result = parse_address_header("John Doe <john@example.com>")
        assert result["address"] == "john@example.com"
        assert result["display_name"] == "John Doe"
    
    def test_invalid_email(self):
        """Test invalid email handling."""
        result = parse_address_header("not-an-email")
        assert result["address"] == "not-an-email"
        assert result["domain"] is None


class TestExtractHeaders:
    """Test header extraction."""
    
    def test_extract_basic_headers(self):
        """Test extracting basic headers from message."""
        msg = EmailMessage(policy=default)
        msg['From'] = 'sender@example.com'
        msg['To'] = 'recipient@example.com'
        msg['Subject'] = 'Test Subject'
        
        headers = extract_headers(msg)
        
        header_names = [h.name for h in headers]
        assert 'From' in header_names
        assert 'To' in header_names
        assert 'Subject' in header_names
    
    def test_extract_multiple_same_header(self):
        """Test extracting multiple headers with same name."""
        msg = EmailMessage(policy=default)
        msg.add_header('Received', 'from mail1.example.com')
        msg.add_header('Received', 'from mail2.example.com')
        
        headers = extract_headers(msg)
        
        received_headers = [h for h in headers if h.name == 'Received']
        assert len(received_headers) == 2


class TestGetHeaderValue:
    """Test header value retrieval."""
    
    def test_get_single_value(self):
        """Test getting single header value."""
        from emltriage.core.schemas import HeaderEntry
        
        headers = [
            HeaderEntry(name='Subject', raw_value='Test', decoded_value=None, parsed=None),
        ]
        
        value = get_header_value(headers, 'Subject')
        assert value == 'Test'
    
    def test_get_case_insensitive(self):
        """Test case-insensitive header lookup."""
        from emltriage.core.schemas import HeaderEntry
        
        headers = [
            HeaderEntry(name='Subject', raw_value='Test', decoded_value=None, parsed=None),
        ]
        
        value = get_header_value(headers, 'subject')
        assert value == 'Test'
    
    def test_get_missing_header(self):
        """Test getting missing header returns None."""
        from emltriage.core.schemas import HeaderEntry
        
        headers = []
        
        value = get_header_value(headers, 'Subject')
        assert value is None
