"""Robust WHOIS/RDAP lookup with multi-layer fallback strategy.

Layers:
1. HTTP RDAP (multiple servers)
2. HTTP-based WHOIS APIs
3. Web scraping fallback
"""

import re
import asyncio
import logging
from typing import Optional
from dataclasses import dataclass
from datetime import datetime

import httpx
import tldextract

logger = logging.getLogger(__name__)


@dataclass
class WhoisResult:
    domain: str
    registrar: str = "Unknown"
    creation_date: str = "Unknown"
    assessment: str = "Neutral"
    source: str = "unknown"
    raw: str = ""
    error: Optional[str] = None

    def to_dict(self):
        return {
            "registrar": self.registrar,
            "creation": self.creation_date,
            "assessment": self.assessment,
            "source": self.source,
            "raw": self.raw,
            "error": self.error
        }


class RobustWhoisLookup:
    """Multi-layer WHOIS/RDAP lookup with fallbacks."""

    RDAP_SERVERS = [
        "https://rdap.verisign.com/domain/v1/{domain}",
        "https://rdap.org/domain/{domain}",
        "https://rdap.centralregistry.com/rdap/{domain}",
        "https://rdap.publicinterestregistry.org/rdap/domain/{domain}",
    ]

    TLD_RDAP_SERVERS = {
        'com': 'https://rdap.verisign.com/domain/v1/{domain}',
        'net': 'https://rdap.verisign.com/domain/v1/{domain}',
        'org': 'https://rdap.publicinterestregistry.org/rdap/domain/{domain}',
        'info': 'https://rdap.info',
        'biz': 'https://rdap.biz',
        'io': 'https://rdap.nic.io/',
        'co': 'https://rdap.registrador.co/rdap/domain/{domain}',
        'app': 'https://rdap.nic.google/',
        'dev': 'https://rdap.nic.google/',
        'cloud': 'https://rdap.nic.cloud/',
        'online': 'https://rdap.nic.online/',
        'site': 'https://rdap.nic.site/',
        'store': 'https://rdap.nic.store/',
        'tech': 'https://rdap.nic.tech/',
        'mx': 'https://rdap.nic.mx/domain/{domain}',
        'ca': 'https://rdap.ca.fury.ca/rdap/domain/{domain}',
        'uk': 'https://rdap.nic.uk/rdap/domain/{domain}',
        'br': 'https://rdap.registro.br/rdap/domain/{domain}',
        'de': 'https://rdap.deNic.de/rdap/domain/{domain}',
        'fr': 'https://rdap.nic.fr/rdap/domain/{domain}',
        'eu': 'https://rdap.eu/rdap/domain/{domain}',
        'ru': 'https://rdap.tcinet.ru/rdap/domain/{domain}',
        'cn': 'https://rdap.cnnic.cn/rdap/domain/{domain}',
        'jp': 'https://rdap.jprs.jp/rdap/domain/{domain}',
        'kr': 'https://rdap.kr/rdap/domain/{domain}',
        'au': 'https://rdap.auda.org.au/rdap/domain/{domain}',
        'nz': 'https://rdap.nzrs.net.nz/rdap/domain/{domain}',
        'in': 'https://rdap.in/rdap/domain/{domain}',
        'sg': 'https://rdap.sgnic.sg/rdap/domain/{domain}',
    }

    WHOIS_API_ENDPOINTS = [
        "https://www.whois.com/whois/{domain}",
    ]

    INTERNAL_TLDS = {
        'local', 'lan', 'internal', 'localhost', 'test',
        'example', 'invalid', 'from', 'to', 'reply', 'macias',
        'home', 'corp', 'host'
    }

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        return self

    async def __aexit__(self, *args):
        if self.client:
            await self.client.aclose()

    async def lookup(self, domain: str) -> WhoisResult:
        """Main entry point - tries all methods until one succeeds."""
        domain = domain.strip().lower()
        
        if not domain:
            return WhoisResult(domain=domain, error="Empty domain")

        validation = self._validate_domain(domain)
        if not validation['valid']:
            return WhoisResult(domain=domain, error=validation['error'])

        extracted = tldextract.extract(domain)
        tld = extracted.suffix.lower().split('.')[-1] if extracted.suffix else None

        result = await self._try_rdap_servers(domain, tld)
        if result and not result.error:
            return result

        result = await self._try_whois_api(domain)
        if result and not result.error:
            return result

        result = await self._try_web_scraping(domain)
        if result and not result.error:
            return result

        return WhoisResult(
            domain=domain,
            error="All lookup methods failed - network may be restricted",
            assessment="Unknown (Lookup Failed)"
        )

    def _validate_domain(self, domain: str) -> dict:
        """Validate domain using tldextract for proper TLD handling."""
        try:
            extracted = tldextract.extract(domain)
            
            if not extracted.domain:
                return {'valid': False, 'error': 'Invalid domain format (no domain name)'}
            
            if not extracted.suffix:
                return {'valid': False, 'error': 'Invalid domain format (no TLD)'}
            
            tld = extracted.suffix.lower().split('.')[-1]
            if tld in self.INTERNAL_TLDS:
                return {'valid': False, 'error': 'Internal/private TLD'}
            
            if len(extracted.domain) < 1:
                return {'valid': False, 'error': 'Invalid domain format'}
            
            return {'valid': True, 'error': None}
            
        except Exception as e:
            return {'valid': False, 'error': f'Domain validation error: {str(e)}'}

    async def _try_rdap_servers(self, domain: str, tld: str = None) -> Optional[WhoisResult]:
        """Try TLD-specific RDAP server first, then fall back to generic servers."""
        servers_to_try = []
        
        if tld and tld in self.TLD_RDAP_SERVERS:
            servers_to_try.append(self.TLD_RDAP_SERVERS[tld])
        
        servers_to_try.extend(self.RDAP_SERVERS)
        
        for server_url in servers_to_try:
            try:
                url = server_url.replace("{domain}", domain)
                resp = await self.client.get(url)
                
                if resp.status_code == 200:
                    data = resp.json()
                    result = self._parse_rdap_response(domain, data)
                    if result.registrar != "Unknown" or result.creation_date != "Unknown":
                        result.source = f"rdap ({url.split('/')[2]})"
                        return result
                elif resp.status_code == 404:
                    return WhoisResult(
                        domain=domain,
                        error="Domain not found",
                        assessment="Unknown (Not Found)",
                        source="rdap"
                    )
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.debug(f"RDAP server {server_url} failed: {e}")
                continue
        
        return None

    def _parse_rdap_response(self, domain: str, data: dict) -> WhoisResult:
        """Parse RDAP JSON response."""
        registrar = "Unknown"
        creation_date = "Unknown"
        name_server = "Unknown"
        
        for entity in data.get('entities', []):
            if 'registrar' in entity.get('roles', []):
                if entity.get('vcardArray'):
                    for vcard in entity['vcardArray'][1]:
                        if vcard[0] == 'fn':
                            registrar = str(vcard[3])
                            break
            
            if 'registrant' in entity.get('roles', []):
                if entity.get('vcardArray'):
                    for vcard in entity['vcardArray'][1]:
                        if vcard[0] == 'fn':
                            registrant = str(vcard[3])
                            break

        for event in data.get('events', []):
            if event.get('eventAction') == 'registration':
                creation_date = event.get('eventDate', '').split('T')[0]
                break
            if event.get('eventAction') == 'expiration':
                expiration_date = event.get('eventDate', '').split('T')[0]

        for ns in data.get('nameservers', []):
            if ns.get('ldhName'):
                name_server = ns.get('ldhName')
                break

        raw_formatted = self._format_raw_output(
            registrar=registrar,
            creation_date=creation_date,
            name_server=name_server,
            domain=domain,
            data=data
        )
        
        return WhoisResult(
            domain=domain,
            registrar=registrar,
            creation_date=creation_date,
            raw=raw_formatted
        )

    def _format_raw_output(self, registrar: str, creation_date: str, name_server: str, domain: str, data: dict = None) -> str:
        """Format raw output to be human-readable."""
        lines = [
            f"Domain: {domain}",
            f"Registrar: {registrar}",
            f"Creation Date: {creation_date}",
            f"Name Server: {name_server}",
            "",
            "--- Additional Info ---",
        ]
        
        if data:
            if data.get('status'):
                statuses = ', '.join(data.get('status', []))
                lines.append(f"Status: {statuses}")
            
            if data.get('handle'):
                lines.append(f"Handle: {data.get('handle')}")
            
            if data.get('ldhName'):
                lines.append(f"LDH Name: {data.get('ldhName')}")
            
            lines.append("")
            lines.append("--- Raw RDAP Data (truncated) ---")
            lines.append(str(data)[:800])
        
        return '\n'.join(lines)

    async def _try_whois_api(self, domain: str) -> Optional[WhoisResult]:
        """Try HTTP-based WHOIS APIs."""
        for api_url in self.WHOIS_API_ENDPOINTS:
            try:
                url = api_url.replace("{domain}", domain)
                resp = await self.client.get(url)
                
                if resp.status_code == 200:
                    text = resp.text
                    result = self._parse_whois_text(domain, text)
                    result.source = f"whois-api ({url.split('/')[2]})"
                    return result
            except Exception as e:
                logger.debug(f"WHOIS API {api_url} failed: {e}")
                continue
        
        return None

    async def _try_web_scraping(self, domain: str) -> Optional[WhoisResult]:
        """Fallback: scrape online WHOIS pages."""
        scraping_urls = [
            f"https://who.is/whois/{domain}",
            f"https://www.whois.com/whois/{domain}",
            f"https://www.whoissearch.com/whois/{domain}",
            f"https://www.domainsponsor.com/whois/{domain}",
        ]
        
        for url in scraping_urls:
            try:
                resp = await self.client.get(url)
                
                if resp.status_code == 200:
                    text = resp.text
                    result = self._parse_whois_text(domain, text)
                    
                    if result.error and "JavaScript" in result.error:
                        logger.debug(f"Web scraping {url} returned JavaScript, trying next")
                        continue
                    
                    if result.registrar == "Unknown" and result.creation_date == "Unknown":
                        logger.debug(f"Web scraping {url} returned no useful data, trying next")
                        continue
                    
                    result.source = f"web-scraping ({url.split('/')[2]})"
                    return result
            except Exception as e:
                logger.debug(f"Web scraping {url} failed: {e}")
                continue
        
        return None

    def _parse_whois_text(self, domain: str, text: str) -> WhoisResult:
        """Parse WHOIS plain text or HTML response."""
        from bs4 import BeautifulSoup
        
        registrar = "Unknown"
        creation_date = "Unknown"
        name_server = "Unknown"
        
        try:
            soup = BeautifulSoup(text, 'html.parser')
            for script in soup(["script", "style"]):
                script.decompose()
            text_clean = soup.get_text(separator=' ', strip=True)
            text_clean = re.sub(r'\s+', ' ', text_clean)
        except Exception:
            text_clean = text
        
        text_lower = text_clean.lower()
        
        js_indicators = ['function', 'purchaseDomain', 'gtag', 'submitForm', 'toggleFold']
        js_count = sum(1 for indicator in js_indicators if indicator in text_lower)
        
        if js_count >= 2 or ('function' in text_lower and 'domain' in text_lower):
            return WhoisResult(
                domain=domain,
                error="Web scraping returned JavaScript/HTML instead of WHOIS data",
                raw="Web scraping failed - site requires JavaScript"
            )

        registrar_patterns = [
            r'registrar[:\s]+([A-Za-z0-9\s.,&-]+?)(?:\n|$|<)',
            r'registrar name[:\s]+([A-Za-z0-9\s.,&-]+?)(?:\n|$|<)',
            r'registrar of record[:\s]+([A-Za-z0-9\s.,&-]+?)(?:\n|$|<)',
            r'information registrar[:\s]+([A-Za-z0-9\s.,&-]+?)(?:,|\n|$|<)',
            r'registrar\(s\)[:\s]+([A-Za-z0-9\s.,&-]+?)(?:\n|$|<)',
        ]
        for pattern in registrar_patterns:
            match = re.search(pattern, text_clean, re.IGNORECASE)
            if match:
                registrar = match.group(1).strip()[:100]
                registrar = re.sub(r'<[^>]+>', '', registrar)
                registrar = re.sub(r'\s+', ' ', registrar)
                if registrar and len(registrar) > 2 and len(registrar) < 80:
                    if 'iana' not in registrar.lower() and 'id:' not in registrar.lower():
                        break

        date_patterns = [
            r'creation date[:\s]+(\d{4}-\d{2}-\d{2})',
            r'registered[:\s]+(\d{4}-\d{2}-\d{2})',
            r'created[:\s]+(\d{4}-\d{2}-\d{2})',
            r'registration time[:\s]+(\d{4}-\d{2}-\d{2})',
            r'created on[:\s]+(\d{4}-\d{2}-\d{2})',
            r'registration date[:\s]+(\d{4}-\d{2}-\d{2})',
        ]
        for pattern in date_patterns:
            match = re.search(pattern, text_lower)
            if match:
                creation_date = match.group(1)
                break
        
        ns_patterns = [
            r'name server[:\s]+([^\n<]{2,80})',
            r'nserver[:\s]+([^\n<]{2,80})',
            r'dns[:\s]+([^\n<]{2,80})',
        ]
        for pattern in ns_patterns:
            match = re.search(pattern, text_lower)
            if match:
                name_server = match.group(1).strip()[:100]
                name_server = re.sub(r'<[^>]+>', '', name_server)
                break
            if match:
                name_server = match.group(1).strip()[:100]
                break

        raw_formatted = self._format_whois_raw(
            domain=domain,
            registrar=registrar,
            creation_date=creation_date,
            name_server=name_server,
            raw_text=text
        )

        if 'no match for' in text_lower or 'not found' in text_lower:
            return WhoisResult(
                domain=domain,
                registrar=registrar,
                creation_date=creation_date,
                assessment="Unknown (Not Found)",
                raw=raw_formatted
            )

        return WhoisResult(
            domain=domain,
            registrar=registrar,
            creation_date=creation_date,
            raw=raw_formatted
        )

    def _format_whois_raw(self, domain: str, registrar: str, creation_date: str, name_server: str, raw_text: str) -> str:
        """Format raw WHOIS text to be more readable."""
        lines = [
            f"Domain: {domain}",
            f"Registrar: {registrar}",
            f"Creation Date: {creation_date}",
            f"Name Server: {name_server}",
            "",
            "--- Raw WHOIS (truncated) ---",
        ]
        
        text_lines = raw_text.split('\n')
        important_lines = []
        for line in text_lines[:50]:
            line = line.strip()
            if line and len(line) > 3 and not line.startswith('<'):
                important_lines.append(line[:150])
        
        lines.extend(important_lines)
        return '\n'.join(lines)


def assess_domain(registrar: str, creation_date: str, domain: str) -> str:
    """Assess domain legitimacy based on registration data."""
    assessment = "Neutral"
    
    brand_keywords = ['microsoft', 'office', 'google', 'apple', 'login', 'secure', 
                       'verify', 'update', 'account', 'admin', 'support']
    enterprise_registrars = ['markmonitor', 'csc corporate', 'amazon', 'google llc', 
                               'cloudflare', 'domain.com', 'godaddy', 'namecheap', 
                               'register.com', 'network solutions', 'enom', 'pair networks']
    
    reg_lower = registrar.lower()
    dom_lower = domain.lower()
    
    has_brand = any(kw in dom_lower for kw in brand_keywords)
    is_enterprise = any(ent in reg_lower for ent in enterprise_registrars)
    
    if has_brand and not is_enterprise and registrar != "Unknown":
        assessment = "Suspicious (Brand Impersonation)"
    elif is_enterprise:
        assessment = "Legitimate (Enterprise Registrar)"
    elif creation_date in ["Unknown", ""]:
        pass
    elif any(year in creation_date for year in ['2024', '2025', '2026']):
        assessment = "Suspicious (Newly Registered)"
    
    return assessment
