"""CTI enrichment engine."""

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from emltriage.core.io import load_iocs
from emltriage.core.models import IOCsExtracted, IOCType
from emltriage.cti.cache import CTICache
from emltriage.cti.models import (
    CTIEnrichment,
    CTIProviderType,
    CTIResult,
    CTISummary,
    LocalIntelConfig,
    ProviderConfig,
)
from emltriage.cti.providers.abuseipdb import AbuseIPDBProvider
from emltriage.cti.providers.base import CTIProvider
from emltriage.cti.providers.local import LocalIntelProvider
from emltriage.cti.providers.urlhaus import URLhausProvider
from emltriage.cti.providers.virustotal import VirusTotalProvider
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class CTIEngine:
    """Orchestrates CTI enrichment across multiple providers."""
    
    def __init__(
        self,
        cache_path: Optional[Path] = None,
        offline: bool = True,
        providers: Optional[list[CTIProviderType]] = None,
        local_intel_config: Optional[LocalIntelConfig] = None,
    ):
        """Initialize CTI engine.
        
        Args:
            cache_path: Path to SQLite cache database
            offline: Whether to run in offline mode (no online providers)
            providers: List of provider types to use (None = all available)
            local_intel_config: Configuration for local intelligence files
        """
        self.offline = offline
        self.providers: list[CTIProvider] = []
        self._provider_types: list[CTIProviderType] = []
        
        # Initialize cache
        if cache_path is None:
            cache_path = Path(".cti_cache.db")
        self.cache = CTICache(cache_path)
        
        # Initialize providers
        self._init_providers(providers, local_intel_config)
        
        logger.info(f"CTI engine initialized with {len(self.providers)} providers, offline={offline}")
    
    def _init_providers(
        self,
        providers: Optional[list[CTIProviderType]],
        local_intel_config: Optional[LocalIntelConfig],
    ) -> None:
        """Initialize configured providers.
        
        Args:
            providers: List of provider types to use
            local_intel_config: Local intel configuration
        """
        # Always add local provider if configured
        if local_intel_config and local_intel_config.enabled:
            local_provider = LocalIntelProvider(
                ProviderConfig(
                    provider_type=CTIProviderType.LOCAL,
                    enabled=True,
                    cache_ttl_seconds=86400,  # 24 hours
                ),
                local_intel_config,
            )
            self.providers.append(local_provider)
            self._provider_types.append(CTIProviderType.LOCAL)
        
        if not self.offline:
            # Add online providers
            provider_map = {
                CTIProviderType.VIRUSTOTAL: VirusTotalProvider,
                CTIProviderType.ABUSEIPDB: AbuseIPDBProvider,
                CTIProviderType.URLHAUS: URLhausProvider,
            }
            
            for provider_type in providers or list(CTIProviderType):
                if provider_type == CTIProviderType.LOCAL:
                    continue  # Already added
                
                provider_class = provider_map.get(provider_type)
                if provider_class:
                    try:
                        provider = provider_class()
                        self.providers.append(provider)
                        self._provider_types.append(provider_type)
                        logger.info(f"Initialized {provider_type.value} provider")
                    except Exception as e:
                        logger.warning(f"Failed to initialize {provider_type.value}: {e}")
    
    def enrich_iocs(
        self,
        iocs: IOCsExtracted,
        source_file: str = "",
        use_cache: bool = True,
    ) -> CTIEnrichment:
        """Enrich IOCs using configured providers.
        
        Args:
            iocs: IOCs to enrich
            source_file: Path to source file for metadata
            use_cache: Whether to use caching
            
        Returns:
            CTIEnrichment with all results
        """
        start_time = time.time()
        
        # Collect all IOCs to process
        all_iocs: list[tuple[str, IOCType]] = []
        
        for ioc_entry in iocs.domains:
            all_iocs.append((ioc_entry.value, IOCType.DOMAIN))
        
        for ioc_entry in iocs.ips:
            all_iocs.append((ioc_entry.value, ioc_entry.type))
        
        for ioc_entry in iocs.urls:
            all_iocs.append((ioc_entry.value, IOCType.URL))
        
        for ioc_entry in iocs.hashes:
            all_iocs.append((ioc_entry.value, ioc_entry.type))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_iocs = []
        for ioc, ioc_type in all_iocs:
            key = (ioc.lower(), ioc_type)
            if key not in seen:
                seen.add(key)
                unique_iocs.append((ioc, ioc_type))
        
        logger.info(f"Enriching {len(unique_iocs)} unique IOCs")
        
        # Process each IOC
        enrichments: list[CTIResult] = []
        cache_hits = 0
        error_count = 0
        
        for ioc, ioc_type in unique_iocs:
            for provider in self.providers:
                if not provider.is_supported(ioc_type):
                    continue
                
                # Check cache first
                if use_cache:
                    cached = self.cache.get(ioc, ioc_type, provider.provider_type)
                    if cached:
                        # Create result from cache
                        result = CTIResult(
                            ioc=cached.ioc,
                            ioc_type=cached.ioc_type,
                            lookup_timestamp=datetime.now(timezone.utc),
                            provider=cached.provider,
                            status="success",
                            malicious_score=cached.result.get("malicious_score"),
                            confidence=cached.result.get("confidence"),
                            tags=cached.result.get("tags", []),
                            categories=cached.result.get("categories", []),
                            raw_data=cached.result,
                            cache_hit=True,
                            cache_ttl=self.cache.default_ttl,
                        )
                        enrichments.append(result)
                        cache_hits += 1
                        continue
                
                # Perform lookup
                try:
                    result = provider.lookup(ioc, ioc_type)
                    enrichments.append(result)
                    
                    # Cache successful results
                    if use_cache and result.status.value == "success":
                        self.cache.set(
                            ioc,
                            ioc_type,
                            provider.provider_type,
                            {
                                "malicious_score": result.malicious_score,
                                "confidence": result.confidence,
                                "tags": result.tags,
                                "categories": result.categories,
                            },
                        )
                    
                    if result.status.value == "error":
                        error_count += 1
                
                except Exception as e:
                    logger.error(f"Error enriching {ioc} with {provider.provider_type.value}: {e}")
                    error_count += 1
        
        # Calculate summary
        malicious_count = sum(
            1 for e in enrichments 
            if e.malicious_score and e.malicious_score >= 70
        )
        suspicious_count = sum(
            1 for e in enrichments 
            if e.malicious_score and 30 <= e.malicious_score < 70
        )
        
        summary = CTISummary(
            total_lookups=len(enrichments),
            cache_hits=cache_hits,
            unique_iocs=len(unique_iocs),
            malicious_count=malicious_count,
            suspicious_count=suspicious_count,
            error_count=error_count,
            providers_used=self._provider_types,
            processing_time_seconds=time.time() - start_time,
        )
        
        logger.info(
            f"Enrichment complete: {summary.total_lookups} lookups, "
            f"{summary.cache_hits} cache hits, {summary.malicious_count} malicious, "
            f"{summary.error_count} errors"
        )
        
        return CTIEnrichment(
            run_id=iocs.run_id,
            timestamp=datetime.now(timezone.utc),
            source_iocs_file=source_file,
            enrichments=enrichments,
            summary=summary,
            offline_mode=self.offline,
            providers_configured=self._provider_types,
        )
    
    def enrich_from_file(
        self,
        iocs_file: Path,
        use_cache: bool = True,
    ) -> CTIEnrichment:
        """Enrich IOCs from JSON file.
        
        Args:
            iocs_file: Path to iocs.json file
            use_cache: Whether to use caching
            
        Returns:
            CTIEnrichment with all results
        """
        iocs = load_iocs(iocs_file)
        return self.enrich_iocs(iocs, str(iocs_file), use_cache)
    
    def get_cache_stats(self) -> dict:
        """Get cache statistics.
        
        Returns:
            Cache statistics
        """
        return self.cache.get_stats()
    
    def clear_cache(self) -> int:
        """Clear all cached entries.
        
        Returns:
            Number of entries cleared
        """
        return self.cache.clear_all()
    
    def clear_expired_cache(self) -> int:
        """Clear expired cache entries.
        
        Returns:
            Number of entries cleared
        """
        return self.cache.clear_expired()
