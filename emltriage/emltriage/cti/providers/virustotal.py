"""VirusTotal API provider."""

import hashlib
import os
from datetime import datetime, timezone
from typing import Optional

import requests

from emltriage.core.models import IOCType
from emltriage.cti.models import CTIProviderType, CTIResult, EnrichmentStatus, ProviderConfig
from emltriage.cti.providers.base import RateLimitedProvider
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class VirusTotalProvider(RateLimitedProvider):
    """VirusTotal API v3 provider for hashes, domains, IPs, and URLs."""
    
    # API endpoints
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    # Supported IOC types
    SUPPORTED_TYPES = [
        IOCType.DOMAIN,
        IOCType.IP,
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.URL,
        IOCType.HASH_MD5,
        IOCType.HASH_SHA1,
        IOCType.HASH_SHA256,
    ]
    
    def __init__(self, config: Optional[ProviderConfig] = None):
        """Initialize VirusTotal provider.
        
        Args:
            config: Provider configuration (API key from env if not provided)
        """
        if config is None:
            api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
            config = ProviderConfig(
                provider_type=CTIProviderType.VIRUSTOTAL,
                api_key=api_key,
                rate_limit=4,  # VT Public API: 4 requests/minute
                timeout_seconds=30,
                cache_ttl_seconds=3600,
            )
        
        super().__init__(config)
        
        if not self.config.api_key:
            logger.warning("VirusTotal API key not configured")
    
    @property
    def provider_type(self) -> CTIProviderType:
        """Return provider type."""
        return CTIProviderType.VIRUSTOTAL
    
    @property
    def supported_ioc_types(self) -> list[IOCType]:
        """Return supported IOC types."""
        return self.SUPPORTED_TYPES
    
    def _get_headers(self) -> dict:
        """Get request headers with API key.
        
        Returns:
            Headers dict
        """
        return {
            "x-apikey": self.config.api_key or "",
            "Accept": "application/json",
        }
    
    def _make_request(self, endpoint: str) -> Optional[dict]:
        """Make API request.
        
        Args:
            endpoint: API endpoint path
            
        Returns:
            Response JSON or None on error
        """
        if not self.config.api_key:
            logger.error("VirusTotal API key not configured")
            return None
        
        self._respect_rate_limit()
        
        url = f"{self.BASE_URL}/{endpoint}"
        
        try:
            response = requests.get(
                url,
                headers=self._get_headers(),
                timeout=self.config.timeout_seconds,
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                # Not found - IOC not in VT database
                return {"not_found": True}
            elif response.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded")
                return {"rate_limited": True}
            else:
                logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
                return None
        
        except requests.RequestException as e:
            logger.error(f"VirusTotal request error: {e}")
            return None
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> CTIResult:
        """Lookup IOC in VirusTotal.
        
        Args:
            ioc: The IOC to lookup
            ioc_type: Type of IOC
            
        Returns:
            CTIResult with enrichment data
        """
        if not self.config.api_key:
            return self._create_error_result(
                ioc, ioc_type, "VirusTotal API key not configured"
            )
        
        # Determine endpoint based on IOC type
        endpoint = self._get_endpoint(ioc, ioc_type)
        if not endpoint:
            return self._create_unsupported_result(ioc, ioc_type)
        
        # Make request
        data = self._make_request(endpoint)
        
        if data is None:
            return self._create_error_result(ioc, ioc_type, "API request failed")
        
        if data.get("rate_limited"):
            return CTIResult(
                ioc=ioc,
                ioc_type=ioc_type,
                lookup_timestamp=datetime.now(timezone.utc),
                provider=self.provider_type,
                status=EnrichmentStatus.RATE_LIMITED,
                error_message="Rate limit exceeded",
            )
        
        if data.get("not_found"):
            # IOC not in VT database - return empty but successful result
            return self._create_success_result(
                ioc=ioc,
                ioc_type=ioc_type,
                malicious_score=0,
                confidence=1.0,
                tags=[],
                categories=["not_in_database"],
                raw_data={"not_found": True},
            )
        
        # Parse response
        return self._parse_response(ioc, ioc_type, data)
    
    def _get_endpoint(self, ioc: str, ioc_type: IOCType) -> Optional[str]:
        """Get API endpoint for IOC type.
        
        Args:
            ioc: The IOC
            ioc_type: Type of IOC
            
        Returns:
            Endpoint path or None if unsupported
        """
        if ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]:
            return f"files/{ioc.strip()}"
        
        elif ioc_type == IOCType.DOMAIN:
            import urllib.parse
            return f"domains/{urllib.parse.quote(ioc.strip(), safe='')}"
        
        elif ioc_type in [IOCType.IP, IOCType.IPV4, IOCType.IPV6]:
            import urllib.parse
            return f"ip_addresses/{urllib.parse.quote(ioc.strip(), safe='')}"
        
        elif ioc_type == IOCType.URL:
            # URLs need to be base64 encoded
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            return f"urls/{url_id}"
        
        return None
    
    def _parse_response(self, ioc: str, ioc_type: IOCType, data: dict) -> CTIResult:
        """Parse VirusTotal API response.
        
        Args:
            ioc: The IOC
            ioc_type: Type of IOC
            data: API response data
            
        Returns:
            CTIResult
        """
        try:
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            # Calculate malicious score
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            
            malicious_score = 0
            if total > 0:
                malicious_score = int(((malicious + suspicious) / total) * 100)
            
            # Get tags and categories
            tags = attributes.get("tags", [])
            categories = attributes.get("categories", [])
            
            # Get timestamps
            first_seen = None
            last_seen = None
            
            if "first_submission_date" in attributes:
                first_seen = datetime.fromtimestamp(
                    attributes["first_submission_date"], timezone.utc
                )
            
            if "last_analysis_date" in attributes:
                last_seen = datetime.fromtimestamp(
                    attributes["last_analysis_date"], timezone.utc
                )
            
            # Get reputation
            reputation = attributes.get("reputation", 0)
            
            return self._create_success_result(
                ioc=ioc,
                ioc_type=ioc_type,
                malicious_score=malicious_score,
                confidence=0.9 if total > 10 else 0.7,
                tags=tags,
                categories=categories if isinstance(categories, list) else [str(categories)],
                first_seen=first_seen,
                last_seen=last_seen,
                raw_data={
                    "stats": stats,
                    "reputation": reputation,
                    "total_votes": attributes.get("total_votes", {}),
                },
            )
        
        except Exception as e:
            logger.error(f"Error parsing VirusTotal response: {e}")
            return self._create_error_result(ioc, ioc_type, f"Parse error: {e}")
