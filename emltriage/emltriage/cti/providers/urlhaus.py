"""URLhaus provider for malicious URL checks."""

import os
from datetime import datetime, timezone
from typing import Optional

import requests

from emltriage.core.models import IOCType
from emltriage.cti.models import CTIProviderType, CTIResult, EnrichmentStatus, ProviderConfig
from emltriage.cti.providers.base import RateLimitedProvider
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class URLhausProvider(RateLimitedProvider):
    """URLhaus provider for checking malicious URLs."""
    
    # API endpoint
    BASE_URL = "https://urlhaus-api.abuse.ch/v1"
    
    # Supports URLs and domains
    SUPPORTED_TYPES = [IOCType.URL, IOCType.DOMAIN]
    
    def __init__(self, config: Optional[ProviderConfig] = None):
        """Initialize URLhaus provider.
        
        Args:
            config: Provider configuration
        """
        if config is None:
            config = ProviderConfig(
                provider_type=CTIProviderType.URLHAUS,
                api_key=os.environ.get("URLHAUS_API_KEY", ""),
                rate_limit=60,  # Rate limit for URLhaus
                timeout_seconds=30,
                cache_ttl_seconds=3600,
            )
        
        super().__init__(config)
    
    @property
    def provider_type(self) -> CTIProviderType:
        """Return provider type."""
        return CTIProviderType.URLHAUS
    
    @property
    def supported_ioc_types(self) -> list[IOCType]:
        """Return supported IOC types."""
        return self.SUPPORTED_TYPES
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> CTIResult:
        """Lookup URL in URLhaus.
        
        Args:
            ioc: The URL or domain
            ioc_type: Type of IOC
            
        Returns:
            CTIResult with enrichment data
        """
        if ioc_type not in self.SUPPORTED_TYPES:
            return self._create_unsupported_result(ioc, ioc_type)
        
        self._respect_rate_limit()
        
        try:
            if ioc_type == IOCType.URL:
                return self._lookup_url(ioc)
            else:
                return self._lookup_host(ioc)
        
        except requests.RequestException as e:
            logger.error(f"URLhaus request error: {e}")
            return self._create_error_result(ioc, ioc_type, f"Request error: {e}")
    
    def _lookup_url(self, url: str) -> CTIResult:
        """Lookup specific URL.
        
        Args:
            url: URL to lookup
            
        Returns:
            CTIResult
        """
        response = requests.post(
            f"{self.BASE_URL}/url",
            data={"url": url},
            timeout=self.config.timeout_seconds,
        )
        
        if response.status_code == 200:
            data = response.json()
            return self._parse_url_response(url, IOCType.URL, data)
        elif response.status_code == 404:
            # URL not found in database
            return self._create_success_result(
                ioc=url,
                ioc_type=IOCType.URL,
                malicious_score=0,
                confidence=1.0,
                tags=[],
                categories=["not_in_database"],
                raw_data={"query_status": "no_results"},
            )
        else:
            return self._create_error_result(url, IOCType.URL, f"API error: {response.status_code}")
    
    def _lookup_host(self, host: str) -> CTIResult:
        """Lookup host/domain.
        
        Args:
            host: Host to lookup
            
        Returns:
            CTIResult
        """
        response = requests.post(
            f"{self.BASE_URL}/host",
            data={"host": host},
            timeout=self.config.timeout_seconds,
        )
        
        if response.status_code == 200:
            data = response.json()
            return self._parse_host_response(host, IOCType.DOMAIN, data)
        elif response.status_code == 404:
            return self._create_success_result(
                ioc=host,
                ioc_type=IOCType.DOMAIN,
                malicious_score=0,
                confidence=1.0,
                tags=[],
                categories=["not_in_database"],
                raw_data={"query_status": "no_results"},
            )
        else:
            return self._create_error_result(host, IOCType.DOMAIN, f"API error: {response.status_code}")
    
    def _parse_url_response(self, ioc: str, ioc_type: IOCType, data: dict) -> CTIResult:
        """Parse URL lookup response.
        
        Args:
            ioc: The IOC
            ioc_type: Type of IOC
            data: API response
            
        Returns:
            CTIResult
        """
        try:
            query_status = data.get("query_status", "")
            
            if query_status == "no_results":
                return self._create_success_result(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    malicious_score=0,
                    confidence=1.0,
                    tags=[],
                    categories=["not_in_database"],
                    raw_data=data,
                )
            
            # URL is in database - get threat info
            threat = data.get("threat", "")
            tags = data.get("tags", [])
            
            # Parse date added
            date_added = None
            if data.get("date_added"):
                try:
                    date_added = datetime.strptime(
                        data["date_added"], "%Y-%m-%d %H:%M:%S"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
            
            # Get payload information
            payloads = data.get("payloads", [])
            payload_count = len(payloads)
            
            # Determine malicious score based on threat type and payloads
            malicious_score = 100 if threat else 50
            if payload_count > 0:
                malicious_score = 100
            
            return self._create_success_result(
                ioc=ioc,
                ioc_type=ioc_type,
                malicious_score=malicious_score,
                confidence=0.95 if threat else 0.8,
                tags=tags + ([threat] if threat else []),
                categories=[threat] if threat else ["suspicious"],
                first_seen=date_added,
                raw_data={
                    "url_status": data.get("url_status"),
                    "threat": threat,
                    "reporter": data.get("reporter"),
                    "urlhaus_reference": data.get("urlhaus_reference"),
                    "payload_count": payload_count,
                    "payloads": payloads[:5],  # Limit payloads in raw data
                },
            )
        
        except Exception as e:
            logger.error(f"Error parsing URLhaus URL response: {e}")
            return self._create_error_result(ioc, ioc_type, f"Parse error: {e}")
    
    def _parse_host_response(self, ioc: str, ioc_type: IOCType, data: dict) -> CTIResult:
        """Parse host lookup response.
        
        Args:
            ioc: The IOC
            ioc_type: Type of IOC
            data: API response
            
        Returns:
            CTIResult
        """
        try:
            query_status = data.get("query_status", "")
            
            if query_status == "no_results":
                return self._create_success_result(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    malicious_score=0,
                    confidence=1.0,
                    tags=[],
                    categories=["not_in_database"],
                    raw_data=data,
                )
            
            # Host has URLs in database
            url_count = data.get("url_count", 0)
            blacklists = data.get("blacklists", {})
            
            # Determine if blacklisted
            is_blacklisted = any(blacklists.values())
            
            # Build tags
            tags = []
            if is_blacklisted:
                tags.append("blacklisted")
            for bl, status in blacklists.items():
                if status:
                    tags.append(f"blacklist:{bl}")
            
            # Determine malicious score
            malicious_score = 0
            if is_blacklisted:
                malicious_score = 100
            elif url_count > 10:
                malicious_score = 90
            elif url_count > 0:
                malicious_score = 70
            
            # Get first URL timestamp
            first_url = None
            if data.get("urls"):
                first_url_data = data["urls"][0]
                if first_url_data.get("date_added"):
                    try:
                        first_url = datetime.strptime(
                            first_url_data["date_added"], "%Y-%m-%d %H:%M:%S"
                        ).replace(tzinfo=timezone.utc)
                    except ValueError:
                        pass
            
            return self._create_success_result(
                ioc=ioc,
                ioc_type=ioc_type,
                malicious_score=malicious_score,
                confidence=0.9 if url_count > 0 else 0.7,
                tags=tags,
                categories=["malicious_host"] if url_count > 0 else ["clean"],
                first_seen=first_url,
                raw_data={
                    "url_count": url_count,
                    "blacklists": blacklists,
                    "sample_count": data.get("sample_count", 0),
                },
            )
        
        except Exception as e:
            logger.error(f"Error parsing URLhaus host response: {e}")
            return self._create_error_result(ioc, ioc_type, f"Parse error: {e}")
