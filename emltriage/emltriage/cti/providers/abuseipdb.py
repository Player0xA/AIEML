"""AbuseIPDB provider for IP reputation checks."""

import os
from datetime import datetime, timezone
from typing import Optional

import requests

from emltriage.core.models import IOCType
from emltriage.cti.models import CTIProviderType, CTIResult, EnrichmentStatus, ProviderConfig
from emltriage.cti.providers.base import RateLimitedProvider
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class AbuseIPDBProvider(RateLimitedProvider):
    """AbuseIPDB provider for IP reputation and abuse reports."""
    
    # API endpoint
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    # Only supports IP addresses
    SUPPORTED_TYPES = [IOCType.IP, IOCType.IPV4, IOCType.IPV6]
    
    def __init__(self, config: Optional[ProviderConfig] = None):
        """Initialize AbuseIPDB provider.
        
        Args:
            config: Provider configuration
        """
        if config is None:
            api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
            config = ProviderConfig(
                provider_type=CTIProviderType.ABUSEIPDB,
                api_key=api_key,
                rate_limit=60,  # Free tier: 60 requests/minute
                timeout_seconds=30,
                cache_ttl_seconds=3600,
            )
        
        super().__init__(config)
        
        if not self.config.api_key:
            logger.warning("AbuseIPDB API key not configured")
    
    @property
    def provider_type(self) -> CTIProviderType:
        """Return provider type."""
        return CTIProviderType.ABUSEIPDB
    
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
            "Key": self.config.api_key or "",
            "Accept": "application/json",
        }
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> CTIResult:
        """Lookup IP in AbuseIPDB.
        
        Args:
            ioc: The IP address
            ioc_type: Type of IOC (should be IP)
            
        Returns:
            CTIResult with enrichment data
        """
        if not self.config.api_key:
            return self._create_error_result(
                ioc, ioc_type, "AbuseIPDB API key not configured"
            )
        
        if ioc_type not in self.SUPPORTED_TYPES:
            return self._create_unsupported_result(ioc, ioc_type)
        
        self._respect_rate_limit()
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/check",
                headers=self._get_headers(),
                params={
                    "ipAddress": ioc,
                    "maxAgeInDays": 90,
                    "verbose": "",
                },
                timeout=self.config.timeout_seconds,
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_response(ioc, ioc_type, data)
            
            elif response.status_code == 429:
                logger.warning("AbuseIPDB rate limit exceeded")
                return CTIResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    lookup_timestamp=datetime.now(timezone.utc),
                    provider=self.provider_type,
                    status=EnrichmentStatus.RATE_LIMITED,
                    error_message="Rate limit exceeded",
                )
            
            elif response.status_code == 422:
                # Invalid IP address
                return self._create_error_result(ioc, ioc_type, "Invalid IP address")
            
            else:
                logger.error(f"AbuseIPDB API error: {response.status_code}")
                return self._create_error_result(
                    ioc, ioc_type, f"API error: {response.status_code}"
                )
        
        except requests.RequestException as e:
            logger.error(f"AbuseIPDB request error: {e}")
            return self._create_error_result(ioc, ioc_type, f"Request error: {e}")
    
    def _parse_response(self, ioc: str, ioc_type: IOCType, data: dict) -> CTIResult:
        """Parse AbuseIPDB API response.
        
        Args:
            ioc: The IP
            ioc_type: Type of IOC
            data: API response data
            
        Returns:
            CTIResult
        """
        try:
            ip_data = data.get("data", {})
            
            # Get abuse confidence score (0-100)
            abuse_confidence = ip_data.get("abuseConfidencePercentage", 0)
            
            # Get report details
            total_reports = ip_data.get("totalReports", 0)
            num_distinct_users = ip_data.get("numDistinctUsers", 0)
            
            # Get country and ISP info
            country = ip_data.get("countryCode", "")
            isp = ip_data.get("isp", "")
            domain = ip_data.get("domain", "")
            
            # Get usage type
            usage_type = ip_data.get("usageType", "")
            
            # Build tags
            tags = []
            if country:
                tags.append(f"country:{country}")
            if usage_type:
                tags.append(f"usage:{usage_type}")
            if total_reports > 0:
                tags.append(f"reports:{total_reports}")
            
            # Build categories
            categories = []
            if ip_data.get("isWhitelisted"):
                categories.append("whitelisted")
            if ip_data.get("isTor"):
                categories.append("tor")
            
            # Get last report time
            last_reported = None
            if ip_data.get("lastReportedAt"):
                try:
                    last_reported = datetime.fromisoformat(
                        ip_data["lastReportedAt"].replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    pass
            
            return self._create_success_result(
                ioc=ioc,
                ioc_type=ioc_type,
                malicious_score=abuse_confidence,
                confidence=min(0.95, 0.5 + (total_reports / 100)),
                tags=tags,
                categories=categories,
                last_seen=last_reported,
                raw_data={
                    "abuse_confidence": abuse_confidence,
                    "total_reports": total_reports,
                    "distinct_users": num_distinct_users,
                    "country": country,
                    "isp": isp,
                    "domain": domain,
                    "usage_type": usage_type,
                    "is_whitelisted": ip_data.get("isWhitelisted", False),
                    "is_tor": ip_data.get("isTor", False),
                },
            )
        
        except Exception as e:
            logger.error(f"Error parsing AbuseIPDB response: {e}")
            return self._create_error_result(ioc, ioc_type, f"Parse error: {e}")
