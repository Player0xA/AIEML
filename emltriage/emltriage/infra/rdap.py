"""RDAP (Registration Data Access Protocol) client.

Modern replacement for WHOIS - more structured, better for automation.
Uses IANA bootstrap files to find authoritative RDAP servers.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from emltriage.infra.models import DomainInfo, AgeClassification
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class RDAPClient:
    """RDAP client for domain registration data.
    
    RDAP is the modern replacement for WHOIS, providing structured JSON data.
    This client implements the basic RDAP protocol for domain lookups.
    
    References:
    - RFC 7482: Registration Data Access Protocol Query Format
    - RFC 7483: JSON Response Format
    - RFC 7484: Conformance with Bootstrap Files
    """
    
    # IANA bootstrap RDAP server
    BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
    
    # Common TLD servers (fallback)
    COMMON_SERVERS = {
        "com": "https://rdap.verisign.com/com/v1/",
        "net": "https://rdap.verisign.com/net/v1/",
        "org": "https://rdap.publicinterestregistry.org/rdap/",
        "io": "https://rdap.nic.io/",
        "app": "https://rdap.nic.google/",
        "dev": "https://rdap.nic.google/",
        "page": "https://rdap.nic.google/",
    }
    
    def __init__(self, timeout: int = 15, cache_bootstrap: bool = True):
        self.timeout = timeout
        self.cache_bootstrap = cache_bootstrap
        self._bootstrap_data: Optional[dict] = None
        self._server_cache: dict[str, str] = {}
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create requests session with retries."""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def _get_bootstrap_data(self) -> dict:
        """Fetch IANA RDAP bootstrap data."""
        if self._bootstrap_data is not None:
            return self._bootstrap_data
        
        try:
            response = self.session.get(self.BOOTSTRAP_URL, timeout=10)
            response.raise_for_status()
            self._bootstrap_data = response.json()
            return self._bootstrap_data
        except Exception as e:
            logger.warning(f"Failed to fetch RDAP bootstrap data: {e}")
            return {"services": []}
    
    def _find_rdap_server(self, domain: str) -> Optional[str]:
        """Find authoritative RDAP server for a domain."""
        # Check cache first
        tld = domain.split(".")[-1].lower()
        if tld in self._server_cache:
            return self._server_cache[tld]
        
        # Check common servers
        if tld in self.COMMON_SERVERS:
            server = self.COMMON_SERVERS[tld]
            self._server_cache[tld] = server
            return server
        
        # Use bootstrap data
        bootstrap = self._get_bootstrap_data()
        for service in bootstrap.get("services", []):
            tlds = service[0]
            servers = service[1]
            if tld in [t.lower() for t in tlds]:
                if servers:
                    server = servers[0]
                    if not server.endswith("/"):
                        server += "/"
                    self._server_cache[tld] = server
                    return server
        
        logger.debug(f"No RDAP server found for TLD: {tld}")
        return None
    
    def lookup_domain(self, domain: str) -> Optional[DomainInfo]:
        """Lookup domain registration data via RDAP.
        
        Args:
            domain: Domain name to lookup
            
        Returns:
            DomainInfo with registration data, or None if lookup fails
        """
        domain = domain.lower().strip()
        
        # Find RDAP server
        server = self._find_rdap_server(domain)
        if not server:
            logger.debug(f"No RDAP server for domain: {domain}")
            return None
        
        try:
            # Construct query URL
            # RDAP uses: {server}domain/{domain}
            query_url = urljoin(server, f"domain/{domain}")
            
            response = self.session.get(query_url, timeout=self.timeout)
            
            if response.status_code == 404:
                logger.debug(f"Domain not found in RDAP: {domain}")
                return None
            
            response.raise_for_status()
            data = response.json()
            
            return self._parse_rdap_response(data, domain)
        
        except requests.exceptions.RequestException as e:
            logger.debug(f"RDAP request failed for {domain}: {e}")
        except json.JSONDecodeError as e:
            logger.debug(f"RDAP JSON parse failed for {domain}: {e}")
        except Exception as e:
            logger.debug(f"RDAP lookup failed for {domain}: {e}")
        
        return None
    
    def _parse_rdap_response(self, data: dict, domain: str) -> DomainInfo:
        """Parse RDAP JSON response into DomainInfo."""
        domain_info = DomainInfo(
            domain=domain,
            source="rdap",
            query_time=datetime.utcnow(),
            raw_response=json.dumps(data, indent=2)
        )
        
        # Extract events (dates)
        events = data.get("events", [])
        for event in events:
            event_action = event.get("eventAction", "").lower()
            event_date = event.get("eventDate")
            
            if event_date:
                try:
                    # Parse ISO 8601 date
                    dt = datetime.fromisoformat(event_date.replace("Z", "+00:00"))
                    
                    if "registration" in event_action or "registration" in event_action:
                        domain_info.creation_date = dt
                    elif "expiration" in event_action or "expiration" in event_action:
                        domain_info.expiration_date = dt
                    elif "last update" in event_action or "last changed" in event_action:
                        domain_info.updated_date = dt
                except Exception:
                    pass
        
        # Calculate age
        domain_info.calculate_age()
        
        # Extract entities (registrar, contacts)
        entities = data.get("entities", [])
        for entity in entities:
            roles = entity.get("roles", [])
            
            # Look for registrar
            if "registrar" in roles:
                vcards = entity.get("vcardArray", [])
                if len(vcards) > 1:
                    for vcard in vcards[1]:
                        if isinstance(vcard, list) and len(vcard) >= 2:
                            if vcard[0] == "fn":  # Full name
                                domain_info.registrar = vcard[3] if len(vcard) > 3 else vcard[1]
                                break
            
            # Look for registrar info object
            if not domain_info.registrar:
                public_ids = entity.get("publicIds", [])
                for pid in public_ids:
                    if pid.get("type") == "IANA Registrar ID":
                        # Get the name from the entity
                        vcards = entity.get("vcardArray", [])
                        if len(vcards) > 1:
                            for vcard in vcards[1]:
                                if isinstance(vcard, list) and len(vcard) >= 2:
                                    if vcard[0] == "fn":
                                        domain_info.registrar = vcard[3] if len(vcard) > 3 else vcard[1]
                                        break
        
        # Extract name servers
        nameservers = data.get("nameservers", [])
        domain_info.name_servers = [
            ns.get("ldhName", "").lower() for ns in nameservers if ns.get("ldhName")
        ]
        
        # Extract status
        status_list = data.get("status", [])
        domain_info.status = status_list
        
        return domain_info


class WHOISFallback:
    """WHOIS client as fallback when RDAP fails."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def lookup_domain(self, domain: str) -> Optional[DomainInfo]:
        """Lookup domain using WHOIS command-line tool."""
        import subprocess
        import re
        
        try:
            result = subprocess.run(
                ["whois", domain],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                return None
            
            whois_text = result.stdout
            
            return self._parse_whois(whois_text, domain)
        
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            return None
    
    def _parse_whois(self, text: str, domain: str) -> DomainInfo:
        """Parse WHOIS text into DomainInfo."""
        domain_info = DomainInfo(
            domain=domain,
            source="whois",
            query_time=datetime.utcnow(),
            raw_response=text
        )
        
        # Common date patterns
        date_patterns = [
            r'(?:creation date|created|creation):\\\\\\*?\\s*(\\d{4}-\\d{2}-\\d{2})',
            r'(?:creation date|created|creation):\\s*(\\d{2}/\\d{2}/\\d{4})',
            r'(?:creation date|created|creation):\\s*(\\d{2}-\\w{3}-\\d{4})',
        ]
        
        registrar_patterns = [
            r'registrar:\\s*(.+?)(?:\\n|$)',
            r'registrar name:\\s*(.+?)(?:\\n|$)',
            r'sponsoring registrar:\\s*(.+?)(?:\\n|$)',
        ]
        
        text_lower = text.lower()
        
        # Extract creation date
        for pattern in date_patterns:
            match = re.search(pattern, text_lower, re.IGNORECASE)
            if match:
                date_str = match.group(1)
                try:
                    # Try various formats
                    for fmt in ["%Y-%m-%d", "%d/%m/%Y", "%d-%b-%Y"]:
                        try:
                            domain_info.creation_date = datetime.strptime(date_str, fmt)
                            break
                        except ValueError:
                            continue
                    if domain_info.creation_date:
                        break
                except Exception:
                    pass
        
        # Extract registrar
        for pattern in registrar_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                domain_info.registrar = match.group(1).strip()
                if len(domain_info.registrar) < 100:  # Sanity check
                    break
        
        # Calculate age
        domain_info.calculate_age()
        
        return domain_info


class DomainLookup:
    """Unified domain lookup with RDAP primary and WHOIS fallback."""
    
    def __init__(self, offline_mode: bool = False):
        self.offline_mode = offline_mode
        self.rdap = RDAPClient()
        self.whois = WHOISFallback()
    
    def lookup(self, domain: str) -> Optional[DomainInfo]:
        """Lookup domain registration data.
        
        Args:
            domain: Domain name
            
        Returns:
            DomainInfo or None if lookup fails
        """
        if self.offline_mode:
            logger.debug(f"Domain lookup skipped (offline mode): {domain}")
            return None
        
        # Try RDAP first
        result = self.rdap.lookup_domain(domain)
        if result:
            return result
        
        # Fallback to WHOIS
        logger.debug(f"RDAP failed for {domain}, trying WHOIS fallback")
        result = self.whois.lookup_domain(domain)
        if result:
            return result
        
        logger.warning(f"All domain lookup methods failed for {domain}")
        return None
