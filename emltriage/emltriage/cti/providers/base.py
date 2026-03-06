"""CTI provider base class and interface."""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from emltriage.core.models import IOCType
from emltriage.cti.models import CTIProviderType, CTIResult, EnrichmentStatus, ProviderConfig
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class CTIProvider(ABC):
    """Abstract base class for CTI providers."""
    
    def __init__(self, config: ProviderConfig):
        """Initialize provider with configuration.
        
        Args:
            config: Provider configuration
        """
        self.config = config
        self.logger = get_logger(f"{__name__}.{self.provider_type.value}")
        
    @property
    @abstractmethod
    def provider_type(self) -> CTIProviderType:
        """Return the provider type identifier."""
        pass
    
    @property
    @abstractmethod
    def supported_ioc_types(self) -> list[IOCType]:
        """Return list of supported IOC types."""
        pass
    
    def is_supported(self, ioc_type: IOCType) -> bool:
        """Check if IOC type is supported by this provider.
        
        Args:
            ioc_type: Type of IOC to check
            
        Returns:
            True if supported
        """
        return ioc_type in self.supported_ioc_types
    
    @abstractmethod
    def lookup(self, ioc: str, ioc_type: IOCType) -> CTIResult:
        """Perform lookup for an IOC.
        
        Args:
            ioc: The IOC value to lookup
            ioc_type: Type of IOC
            
        Returns:
            CTIResult with enrichment data
        """
        pass
    
    def lookup_batch(self, iocs: list[tuple[str, IOCType]]) -> list[CTIResult]:
        """Perform batch lookup for multiple IOCs.
        
        Default implementation performs individual lookups.
        Override for providers that support true batch queries.
        
        Args:
            iocs: List of (ioc, ioc_type) tuples
            
        Returns:
            List of CTIResult objects
        """
        results = []
        for ioc, ioc_type in iocs:
            if self.is_supported(ioc_type):
                try:
                    result = self.lookup(ioc, ioc_type)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error looking up {ioc}: {e}")
                    results.append(self._create_error_result(ioc, ioc_type, str(e)))
            else:
                results.append(self._create_unsupported_result(ioc, ioc_type))
        return results
    
    def _create_error_result(self, ioc: str, ioc_type: IOCType, error: str) -> CTIResult:
        """Create an error result.
        
        Args:
            ioc: The IOC
            ioc_type: Type of IOC
            error: Error message
            
        Returns:
            CTIResult with error status
        """
        return CTIResult(
            ioc=ioc,
            ioc_type=ioc_type,
            lookup_timestamp=datetime.now(timezone.utc),
            provider=self.provider_type,
            status=EnrichmentStatus.ERROR,
            error_message=error,
        )
    
    def _create_unsupported_result(self, ioc: str, ioc_type: IOCType) -> CTIResult:
        """Create a result for unsupported IOC type.
        
        Args:
            ioc: The IOC
            ioc_type: Type of IOC
            
        Returns:
            CTIResult with not_supported status
        """
        return CTIResult(
            ioc=ioc,
            ioc_type=ioc_type,
            lookup_timestamp=datetime.now(timezone.utc),
            provider=self.provider_type,
            status=EnrichmentStatus.NOT_SUPPORTED,
            error_message=f"IOC type {ioc_type.value} not supported by {self.provider_type.value}",
        )
    
    def _create_success_result(
        self,
        ioc: str,
        ioc_type: IOCType,
        malicious_score: Optional[int] = None,
        confidence: Optional[float] = None,
        tags: Optional[list[str]] = None,
        categories: Optional[list[str]] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
        raw_data: Optional[dict[str, Any]] = None,
        cache_hit: bool = False,
    ) -> CTIResult:
        """Create a successful lookup result.
        
        Args:
            ioc: The IOC
            ioc_type: Type of IOC
            malicious_score: Malicious score 0-100
            confidence: Confidence 0.0-1.0
            tags: Threat tags
            categories: Categories
            first_seen: First seen timestamp
            last_seen: Last seen timestamp
            raw_data: Raw provider data
            cache_hit: Whether from cache
            
        Returns:
            CTIResult with success status
        """
        return CTIResult(
            ioc=ioc,
            ioc_type=ioc_type,
            lookup_timestamp=datetime.now(timezone.utc),
            provider=self.provider_type,
            status=EnrichmentStatus.SUCCESS,
            malicious_score=malicious_score,
            confidence=confidence,
            tags=tags or [],
            categories=categories or [],
            first_seen=first_seen,
            last_seen=last_seen,
            raw_data=raw_data or {},
            cache_hit=cache_hit,
            cache_ttl=self.config.cache_ttl_seconds if cache_hit else None,
        )


class RateLimitedProvider(CTIProvider):
    """Base class for providers with rate limiting."""
    
    def __init__(self, config: ProviderConfig):
        """Initialize with rate limiting support."""
        super().__init__(config)
        self._last_request_time: Optional[datetime] = None
        self._min_interval = timedelta(seconds=60.0 / (config.rate_limit or 60))
    
    def _respect_rate_limit(self) -> None:
        """Wait if necessary to respect rate limits."""
        if self._last_request_time is not None:
            elapsed = datetime.now(timezone.utc) - self._last_request_time
            if elapsed < self._min_interval:
                import time
                sleep_time = (self._min_interval - elapsed).total_seconds()
                logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
                time.sleep(sleep_time)
        self._last_request_time = datetime.now(timezone.utc)
