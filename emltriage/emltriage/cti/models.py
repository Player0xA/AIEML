"""CTI (Cyber Threat Intelligence) schemas for enrichment results."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from emltriage.core.models import IOCType


class CTIProviderType(str, Enum):
    """Types of CTI providers."""
    
    LOCAL = "local"
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    URLHAUS = "urlhaus"


class EnrichmentStatus(str, Enum):
    """Status of enrichment lookup."""
    
    SUCCESS = "success"
    ERROR = "error"
    CACHE_HIT = "cache_hit"
    RATE_LIMITED = "rate_limited"
    NOT_SUPPORTED = "not_supported"


class CTIResult(BaseModel):
    """Individual CTI enrichment result."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    ioc: str = Field(..., description="The IOC that was looked up")
    ioc_type: IOCType = Field(..., description="Type of IOC")
    lookup_timestamp: datetime = Field(..., description="When lookup was performed (UTC)")
    provider: CTIProviderType = Field(..., description="Provider that performed lookup")
    status: EnrichmentStatus = Field(default=EnrichmentStatus.SUCCESS)
    
    # Result data
    malicious_score: Optional[int] = Field(
        None, description="Malicious score (0-100, provider-specific)", ge=0, le=100
    )
    confidence: Optional[float] = Field(
        None, description="Confidence level (0.0-1.0)", ge=0.0, le=1.0
    )
    tags: list[str] = Field(default_factory=list, description="Threat tags/labels")
    categories: list[str] = Field(default_factory=list, description="Categories/classifications")
    
    # Timestamps
    first_seen: Optional[datetime] = Field(None, description="When IOC was first seen")
    last_seen: Optional[datetime] = Field(None, description="When IOC was last seen")
    
    # Raw result data (provider-specific)
    raw_data: dict[str, Any] = Field(
        default_factory=dict, description="Raw provider response data"
    )
    
    # Cache info
    cache_hit: bool = Field(default=False, description="Whether result came from cache")
    cache_ttl: Optional[int] = Field(None, description="Cache TTL in seconds")
    
    # Error info
    error_message: Optional[str] = Field(None, description="Error message if lookup failed")


class CTISummary(BaseModel):
    """Summary of CTI enrichment run."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    total_lookups: int = Field(..., description="Total number of lookups performed")
    cache_hits: int = Field(..., description="Number of cache hits")
    unique_iocs: int = Field(..., description="Number of unique IOCs processed")
    malicious_count: int = Field(..., description="Number of IOCs flagged as malicious")
    suspicious_count: int = Field(..., description="Number of IOCs flagged as suspicious")
    error_count: int = Field(..., description="Number of failed lookups")
    providers_used: list[CTIProviderType] = Field(default_factory=list)
    processing_time_seconds: Optional[float] = Field(None, description="Total processing time")


class CTIEnrichment(BaseModel):
    """Complete CTI enrichment output."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    run_id: str = Field(..., description="Run identifier (matches artifacts)")
    timestamp: datetime = Field(..., description="Enrichment timestamp (UTC)")
    source_iocs_file: str = Field(..., description="Path to source iocs.json")
    enrichments: list[CTIResult] = Field(default_factory=list, description="All enrichment results")
    summary: CTISummary = Field(..., description="Enrichment summary")
    
    # Metadata
    offline_mode: bool = Field(default=True, description="Whether offline mode was used")
    providers_configured: list[CTIProviderType] = Field(default_factory=list)


class CacheEntry(BaseModel):
    """Single cache entry for CTI lookups."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    ioc: str = Field(..., description="The IOC")
    ioc_type: IOCType = Field(..., description="IOC type")
    provider: CTIProviderType = Field(..., description="Provider")
    result: dict[str, Any] = Field(..., description="Cached result data")
    created_at: datetime = Field(..., description="When entry was created")
    expires_at: datetime = Field(..., description="When entry expires")
    access_count: int = Field(default=0, description="Number of times accessed")
    last_accessed: Optional[datetime] = Field(None, description="Last access time")


class LocalIntelEntry(BaseModel):
    """Single entry from local intelligence file."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    ioc: str = Field(..., description="The IOC value")
    ioc_type: IOCType = Field(..., description="Type of IOC")
    list_type: str = Field(..., description="allowlist, blocklist, or watchlist")
    source_file: str = Field(..., description="Source file path")
    description: Optional[str] = Field(None, description="Description/notes")
    tags: list[str] = Field(default_factory=list, description="Tags")
    added_date: Optional[datetime] = Field(None, description="When entry was added")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence level")
    
    
class ProviderConfig(BaseModel):
    """Configuration for a CTI provider."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    provider_type: CTIProviderType = Field(..., description="Provider type")
    enabled: bool = Field(default=True, description="Whether provider is enabled")
    api_key: Optional[str] = Field(None, description="API key if required")
    base_url: Optional[str] = Field(None, description="Base URL for API")
    rate_limit: Optional[int] = Field(None, description="Rate limit (requests per minute)")
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    cache_ttl_seconds: int = Field(default=3600, ge=0, description="Cache TTL in seconds")
    supported_ioc_types: list[IOCType] = Field(default_factory=list)
    extra_params: dict[str, Any] = Field(default_factory=dict, description="Provider-specific params")


class LocalIntelConfig(BaseModel):
    """Configuration for local intelligence files."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    enabled: bool = Field(default=True)
    watchlist_dirs: list[str] = Field(default_factory=list, description="Directories to watch")
    watchlist_files: list[str] = Field(default_factory=list, description="Specific files to load")
    auto_reload: bool = Field(default=True, description="Auto-reload on change")
    case_sensitive: bool = Field(default=False, description="Case-sensitive matching")
