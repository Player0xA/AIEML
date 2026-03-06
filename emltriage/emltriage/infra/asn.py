"""ASN lookup providers (Team Cymru primary, BGPView fallback)."""

from __future__ import annotations

import socket
import re
from datetime import datetime
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from emltriage.infra.models import ASNLInfo
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class TeamCymruProvider:
    """Team Cymru DNS-based ASN lookup (free, fast, reliable).
    
    Uses the DNS interface described at:
    https://www.team-cymru.com/ip-asn-mapping
    """
    
    DNS_SERVER = "v4.whois.cymru.com"  # For IPv4 lookups
    DNS_SERVER_V6 = "v6.whois.cymru.com"  # For IPv6 lookups
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
    
    def lookup_asn(self, ip: str) -> Optional[ASNLInfo]:
        """Lookup ASN information for an IP using Team Cymru.
        
        Args:
            ip: IP address (IPv4 or IPv6)
            
        Returns:
            ASNLInfo if found, None otherwise
        """
        try:
            # Determine if IPv4 or IPv6
            if ":" in ip:
                # IPv6 - reverse and use v6 server
                reversed_ip = self._reverse_ipv6(ip)
                query = f"{reversed_ip}.origin6.asn.cymru.com"
            else:
                # IPv4 - reverse and use v4 server
                reversed_ip = self._reverse_ipv4(ip)
                query = f"{reversed_ip}.origin.asn.cymru.com"
            
            # DNS TXT lookup
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            answers = resolver.resolve(query, "TXT")
            
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                return self._parse_cymru_response(txt_record, ip)
            
        except Exception as e:
            logger.debug(f"Team Cymru lookup failed for {ip}: {e}")
        
        return None
    
    def _reverse_ipv4(self, ip: str) -> str:
        """Reverse an IPv4 address for DNS query."""
        octets = ip.split(".")
        return ".".join(reversed(octets))
    
    def _reverse_ipv6(self, ip: str) -> str:
        """Reverse an IPv6 address for DNS query."""
        # Expand IPv6 to full form
        full_ip = socket.inet_pton(socket.AF_INET6, ip)
        hex_str = full_ip.hex()
        nibbles = [hex_str[i:i+1] for i in range(len(hex_str))]
        return ".".join(reversed(nibbles))
    
    def _parse_cymru_response(self, txt: str, ip: str) -> Optional[ASNLInfo]:
        """Parse Team Cymru TXT response.
        
        Format: "ASN | IP | AS Name"
        Example: "15169 | 8.8.8.8 | GOOGLE, US"
        """
        try:
            parts = txt.split(" | ")
            if len(parts) >= 3:
                asn = int(parts[0].strip())
                org = parts[2].strip()
                
                # Parse country from org if present
                country = None
                if "," in org:
                    org_parts = org.rsplit(",", 1)
                    if len(org_parts) == 2:
                        country = org_parts[1].strip()
                        org = org_parts[0].strip()
                
                return ASNLInfo(
                    asn=asn,
                    org=org,
                    country=country,
                    registry=None,  # Not provided by Cymru
                    source="team_cymru",
                    query_time=datetime.utcnow(),
                    raw_response=txt
                )
        except Exception as e:
            logger.debug(f"Failed to parse Cymru response: {txt} - {e}")
        
        return None


class BGPViewProvider:
    """BGPView REST API provider (fallback).
    
    Free tier: 1000 requests/day
    https://bgpview.docs.apiary.io/
    """
    
    BASE_URL = "https://api.bgpview.io"
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
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
    
    def lookup_asn(self, ip: str) -> Optional[ASNLInfo]:
        """Lookup ASN for IP using BGPView API.
        
        Args:
            ip: IP address
            
        Returns:
            ASNLInfo if found, None otherwise
        """
        try:
            url = f"{self.BASE_URL}/ip/{ip}"
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get("status") == "ok" and "data" in data:
                prefix_data = data["data"]
                
                # Get ASN from prefixes
                prefixes = prefix_data.get("prefixes", [])
                if prefixes:
                    asn_data = prefixes[0].get("asn", {})
                    
                    return ASNLInfo(
                        asn=asn_data.get("asn"),
                        org=asn_data.get("name", "Unknown"),
                        country=asn_data.get("country_code"),
                        registry=asn_data.get("rir"),
                        source="bgpview",
                        query_time=datetime.utcnow(),
                        raw_response=response.text
                    )
        
        except requests.exceptions.RequestException as e:
            logger.debug(f"BGPView lookup failed for {ip}: {e}")
        except Exception as e:
            logger.debug(f"BGPView parsing failed for {ip}: {e}")
        
        return None
    
    def lookup_asn_details(self, asn: int) -> Optional[dict]:
        """Get detailed information about an ASN.
        
        Args:
            asn: AS Number
            
        Returns:
            Dict with ASN details if found
        """
        try:
            url = f"{self.BASE_URL}/asn/{asn}"
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get("status") == "ok":
                return data.get("data", {})
        
        except Exception as e:
            logger.debug(f"BGPView ASN details failed for {asn}: {e}")
        
        return None


class ASNLookup:
    """Unified ASN lookup with primary (Team Cymru) and fallback (BGPView)."""
    
    def __init__(
        self,
        primary: str = "team_cymru",
        fallback: str = "bgpview",
        offline_mode: bool = False
    ):
        self.offline_mode = offline_mode
        
        # Initialize providers
        self.cymru = TeamCymruProvider()
        self.bgpview = BGPViewProvider()
        
        self.primary = primary
        self.fallback = fallback
    
    def lookup(self, ip: str) -> Optional[ASNLInfo]:
        """Lookup ASN with automatic fallback.
        
        Args:
            ip: IP address
            
        Returns:
            ASNLInfo or None if all providers fail
        """
        if self.offline_mode:
            logger.debug(f"ASN lookup skipped (offline mode): {ip}")
            return None
        
        # Try primary first
        if self.primary == "team_cymru":
            result = self.cymru.lookup_asn(ip)
            if result:
                return result
            
            # Fallback
            if self.fallback == "bgpview":
                result = self.bgpview.lookup_asn(ip)
                if result:
                    return result
        
        elif self.primary == "bgpview":
            result = self.bgpview.lookup_asn(ip)
            if result:
                return result
            
            if self.fallback == "team_cymru":
                result = self.cymru.lookup_asn(ip)
                if result:
                    return result
        
        logger.warning(f"All ASN providers failed for {ip}")
        return None
    
    def lookup_batch(self, ips: list[str]) -> dict[str, Optional[ASNLInfo]]:
        """Lookup ASN for multiple IPs.
        
        Args:
            ips: List of IP addresses
            
        Returns:
            Dict mapping IP to ASNLInfo (or None)
        """
        results = {}
        for ip in ips:
            results[ip] = self.lookup(ip)
        return results
