"""Geolocation providers for IP addresses."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from emltriage.infra.models import GeoInfo
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class IPAPIProvider:
    """ip-api.com free geolocation provider.
    
    Free tier: 45 requests/minute (non-commercial)
    No API key required
    https://ip-api.com/
    """
    
    BASE_URL = "http://ip-api.com/json"
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create requests session."""
        session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        return session
    
    def lookup(self, ip: str) -> Optional[GeoInfo]:
        """Lookup geolocation for IP.
        
        Args:
            ip: IP address
            
        Returns:
            GeoInfo or None if lookup fails
        """
        try:
            # Build query URL with fields parameter for efficiency
            fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting"
            url = f"{self.BASE_URL}/{ip}?fields={fields}"
            
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get("status") != "success":
                logger.debug(f"ip-api lookup failed for {ip}: {data.get('message')}")
                return None
            
            return GeoInfo(
                country=data.get("countryCode"),
                country_name=data.get("country"),
                region=data.get("regionName"),
                city=data.get("city"),
                latitude=data.get("lat"),
                longitude=data.get("lon"),
                timezone=data.get("timezone"),
                isp=data.get("isp"),
                source="ip_api",
                query_time=datetime.utcnow(),
                confidence=0.8 if not data.get("proxy") and not data.get("mobile") else 0.5
            )
        
        except Exception as e:
            logger.debug(f"ip-api lookup failed for {ip}: {e}")
            return None


class IPInfoProvider:
    """ipinfo.io geolocation provider.
    
    Free tier: 50,000 requests/month
    Paid tier: Token required
    https://ipinfo.io/
    """
    
    BASE_URL = "https://ipinfo.io"
    
    def __init__(self, token: Optional[str] = None, timeout: int = 10):
        self.token = token
        self.timeout = timeout
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create requests session."""
        session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        return session
    
    def lookup(self, ip: str) -> Optional[GeoInfo]:
        """Lookup geolocation for IP.
        
        Args:
            ip: IP address
            
        Returns:
            GeoInfo or None if lookup fails
        """
        try:
            headers = {}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            
            url = f"{self.BASE_URL}/{ip}/json"
            
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            
            # Parse location (lat,lon)
            loc = data.get("loc", "").split(",")
            lat = float(loc[0]) if len(loc) > 0 and loc[0] else None
            lon = float(loc[1]) if len(loc) > 1 and loc[1] else None
            
            return GeoInfo(
                country=data.get("country"),
                region=data.get("region"),
                city=data.get("city"),
                latitude=lat,
                longitude=lon,
                timezone=data.get("timezone"),
                isp=data.get("org"),  # ipinfo uses 'org' for ISP/org
                source="ipinfo" if self.token else "ipinfo_free",
                query_time=datetime.utcnow(),
                confidence=0.85  # ipinfo is generally accurate
            )
        
        except Exception as e:
            logger.debug(f"ipinfo lookup failed for {ip}: {e}")
            return None


class GeoLookup:
    """Unified geolocation lookup with ip-api primary and ipinfo fallback."""
    
    def __init__(
        self,
        primary: str = "ip_api",
        ipinfo_token: Optional[str] = None,
        offline_mode: bool = False
    ):
        self.offline_mode = offline_mode
        self.primary = primary
        
        self.ip_api = IPAPIProvider()
        self.ipinfo = IPInfoProvider(token=ipinfo_token)
    
    def lookup(self, ip: str) -> Optional[GeoInfo]:
        """Lookup geolocation with automatic fallback.
        
        Args:
            ip: IP address
            
        Returns:
            GeoInfo or None
        """
        if self.offline_mode:
            logger.debug(f"Geo lookup skipped (offline mode): {ip}")
            return None
        
        # Try primary
        if self.primary == "ip_api":
            result = self.ip_api.lookup(ip)
            if result:
                return result
            
            # Fallback to ipinfo
            result = self.ipinfo.lookup(ip)
            if result:
                return result
        
        elif self.primary == "ipinfo":
            result = self.ipinfo.lookup(ip)
            if result:
                return result
            
            result = self.ip_api.lookup(ip)
            if result:
                return result
        
        logger.debug(f"All geo providers failed for {ip}")
        return None
    
    def lookup_batch(self, ips: list[str]) -> dict[str, Optional[GeoInfo]]:
        """Lookup geolocation for multiple IPs.
        
        Note: Be careful with rate limits when doing batch lookups.
        
        Args:
            ips: List of IP addresses
            
        Returns:
            Dict mapping IP to GeoInfo
        """
        results = {}
        for ip in ips:
            results[ip] = self.lookup(ip)
        return results
