"""Utility constants and patterns for emltriage."""

import re
from typing import Final

# Risky file extensions
RISKY_EXTENSIONS: Final[frozenset[str]] = frozenset([
    # Executables
    "exe", "dll", "sys", "scr", "com", "bat", "cmd",
    # Scripts
    "js", "jse", "vbs", "vbe", "ps1", "psm1", "psd1", "wsf", "wsh",
    "hta", "html", "htm", "mht", "mhtml",
    # Office macros
    "docm", "dotm", "xlsm", "xltm", "pptm", "potm",
    "doc", "xls", "ppt",  # Legacy Office (can contain macros)
    # Archives that may contain dangerous files
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz",
    "iso", "img", "dmg", "vhd", "vhdx",
    # Shortcuts and links
    "lnk", "url", "ini",
    # Other dangerous
    "jar", "class", "py", "rb", "pl", "sh", "php", "asp", "aspx",
    "pdf",  # PDFs can contain JavaScript
    "one", "onetoc2",  # OneNote (used in malware campaigns)
])

# Regular expressions for IOC extraction
RE_DOMAIN: Final[re.Pattern] = re.compile(
    r'(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'\.[a-zA-Z]{2,})',
    re.IGNORECASE
)

RE_IPV4: Final[re.Pattern] = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

RE_IPV6: Final[re.Pattern] = re.compile(
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'
    r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|'
    r'[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|'
    r':(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|'
    r'fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
    r'::(?:ffff(?::0{1,4}){0,1}:){0,1}'
    r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
    re.IGNORECASE
)

RE_EMAIL: Final[re.Pattern] = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)

RE_URL: Final[re.Pattern] = re.compile(
    r'https?://'  # Protocol
    r'[^\s<>"{}|\\^`\[\]]+',  # URL characters (excludes problematic chars)
    re.IGNORECASE
)

RE_HASH_MD5: Final[re.Pattern] = re.compile(r'\b[a-fA-F0-9]{32}\b')
RE_HASH_SHA1: Final[re.Pattern] = re.compile(r'\b[a-fA-F0-9]{40}\b')
RE_HASH_SHA256: Final[re.Pattern] = re.compile(r'\b[a-fA-F0-9]{64}\b')

RE_MESSAGE_ID: Final[re.Pattern] = re.compile(
    r'<[^>]+@[^>]+>', re.IGNORECASE
)

# URL deobfuscation patterns
URL_DEOBFS_PATTERNS: Final[list[tuple[re.Pattern, str, str]]] = [
    (re.compile(r'hxxp', re.IGNORECASE), 'http', 'hxxp substitution'),
    (re.compile(r'\[:\]/', re.IGNORECASE), '://', 'bracket colon substitution'),
    (re.compile(r'\[\.\]', re.IGNORECASE), '.', 'bracket dot substitution'),
    (re.compile(r'\(\.\)', re.IGNORECASE), '.', 'parenthesis dot substitution'),
    (re.compile(r'\{\.\}', re.IGNORECASE), '.', 'brace dot substitution'),
    (re.compile(r'\s+dot\s+', re.IGNORECASE), '.', 'word dot substitution'),
    (re.compile(r'\s*[/\\]\s*', re.IGNORECASE), '/', 'spaced slash substitution'),
]

# RFC 1918 private IP ranges
PRIVATE_IP_RANGES: Final[list[tuple[int, int]]] = [
    (0x0A000000, 0x0AFFFFFF),    # 10.0.0.0/8
    (0xAC100000, 0xAC1FFFFF),    # 172.16.0.0/12
    (0xC0A80000, 0xC0A8FFFF),    # 192.168.0.0/16
    (0x7F000000, 0x7FFFFFFF),    # 127.0.0.0/8 (loopback)
    (0xA9FE0000, 0xA9FEFFFF),    # 169.254.0.0/16 (link-local)
]

# Headers to extract
IMPORTANT_HEADERS: Final[list[str]] = [
    "from", "to", "cc", "bcc", "reply-to", "return-path",
    "subject", "date", "message-id", "in-reply-to", "references",
    "user-agent", "x-mailer", "mime-version", "content-type",
    "authentication-results", "dkim-signature",
    "arc-seal", "arc-message-signature", "arc-authentication-results",
    "received", "received-spf", "x-originating-ip",
    "x-sender", "x-priority", "x-ms-exchange",
]

# Risk scoring weights
RISK_WEIGHTS: Final[dict[str, int]] = {
    "header_mismatch_from_reply_to": 20,
    "header_mismatch_from_return_path": 15,
    "dkim_domain_mismatch": 25,
    "auth_failure_spf": 20,
    "auth_failure_dkim": 25,
    "auth_failure_dmarc": 20,
    "suspicious_url_punycode": 20,
    "suspicious_url_at_in_path": 15,
    "suspicious_url_ip_literal": 15,
    "suspicious_url_excessive_subdomains": 10,
    "risky_attachment": 25,
    "attachment_macro_indicators": 30,
    "routing_private_ip": 10,
    "routing_missing_date": 15,
    "routing_non_monotonic": 20,
    # Impersonation detection weights
    "impersonation_detected": 30,
    "impersonation_high_confidence": 40,
}

# Received header field patterns
RECEIVED_PATTERNS: Final[dict[str, re.Pattern]] = {
    "from": re.compile(r'from\s+([^\s;]+(?:\s+\([^)]+\))?)', re.IGNORECASE),
    "by": re.compile(r'by\s+([^\s;]+)', re.IGNORECASE),
    "with": re.compile(r'with\s+([^;]+)', re.IGNORECASE),
    "id": re.compile(r'id\s+([^;]+)', re.IGNORECASE),
    "for": re.compile(r'for\s+<([^>]+)>', re.IGNORECASE),
    "date": re.compile(r';\s*(.+)$', re.IGNORECASE | re.DOTALL),
}

# Authentication result patterns
AUTH_RESULT_PATTERN: Final[re.Pattern] = re.compile(
    r'(spf|dkim|dmarc|arc)\s*=\s*(pass|fail|neutral|none|temperror|permerror|softfail)',
    re.IGNORECASE
)

# Suspicious patterns in headers and content
SUSPICIOUS_PATTERNS: Final[dict[str, re.Pattern]] = {
    "punycode_domain": re.compile(r'xn--'),
    "excessive_subdomains": re.compile(r'(?:[^.]+\.){5,}'),
    "suspicious_tld": re.compile(
        r'\.(tk|ml|ga|cf|top|xyz|click|download|work|date|party|link)$',
        re.IGNORECASE
    ),
}
