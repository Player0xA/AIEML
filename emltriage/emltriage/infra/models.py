"""Infrastructure enrichment data models."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class InfrastructureType(str, Enum):
    """Type of infrastructure entity."""
    
    DOMAIN = "domain"
    IP = "ip"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    ASN = "asn"


class HostingType(str, Enum):
    """Hosting environment classification."""
    
    ENTERPRISE = "enterprise"  # Known enterprise/legitimate hosting
    VPS = "vps"  # Virtual Private Server (AWS, DigitalOcean, etc.)
    SHARED = "shared"  # Shared hosting
    BULLETPROOF = "bulletproof"  # Known bulletproof hosting
    CDN = "cdn"  # Content Delivery Network
    RESIDENTIAL = "residential"  # Residential ISP
    UNKNOWN = "unknown"


class AgeClassification(str, Enum):
    """Domain age classification."""
    
    NEW = "new"  # < 30 days
    RECENT = "recent"  # 30-90 days
    ESTABLISHED = "established"  # 90 days - 2 years
    OLD = "old"  # > 2 years
    UNKNOWN = "unknown"


class ASNLInfo(BaseModel):
    """Autonomous System Number information."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    asn: int = Field(..., description="AS Number")
    org: str = Field(..., description="Organization name")
    country: Optional[str] = Field(None, description="Country code")
    registry: Optional[str] = Field(None, description="Regional Internet Registry")
    allocation_date: Optional[datetime] = Field(None, description="When ASN was allocated")
    
    # Evidence traceability
    source: str = Field(default="team_cymru", description="Data source")
    query_time: datetime = Field(default_factory=datetime.utcnow)
    raw_response: Optional[str] = Field(None, description="Raw lookup response")


class GeoInfo(BaseModel):
    """Geolocation information for IP addresses."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    country: Optional[str] = Field(None, description="Country code (ISO 3166-1 alpha-2)")
    country_name: Optional[str] = Field(None, description="Full country name")
    region: Optional[str] = Field(None, description="Region/state")
    city: Optional[str] = Field(None, description="City name")
    latitude: Optional[float] = Field(None, ge=-90, le=90)
    longitude: Optional[float] = Field(None, ge=-180, le=180)
    timezone: Optional[str] = Field(None, description="IANA timezone")
    isp: Optional[str] = Field(None, description="ISP name")
    
    # Evidence traceability
    source: str = Field(default="ip_api", description="Geolocation provider")
    query_time: datetime = Field(default_factory=datetime.utcnow)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence score")


class DomainInfo(BaseModel):
    """Domain registration and age information."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    domain: str = Field(..., description="Domain name")
    
    # Registration info
    registrar: Optional[str] = Field(None, description="Domain registrar")
    creation_date: Optional[datetime] = Field(None, description="When domain was registered")
    expiration_date: Optional[datetime] = Field(None, description="When domain expires")
    updated_date: Optional[datetime] = Field(None, description="Last update")
    
    # Name servers
    name_servers: list[str] = Field(default_factory=list)
    
    # Status codes
    status: list[str] = Field(default_factory=list, description="Domain status codes")
    
    # Age classification
    age_days: Optional[int] = Field(None, description="Days since registration")
    age_classification: AgeClassification = Field(default=AgeClassification.UNKNOWN)
    
    # Evidence traceability
    source: str = Field(default="rdap", description="Data source (rdap/whois)")
    query_time: datetime = Field(default_factory=datetime.utcnow)
    raw_response: Optional[str] = Field(None, description="Raw RDAP/WHOIS response")
    
    def calculate_age(self) -> None:
        """Calculate age classification from creation date."""
        if not self.creation_date:
            self.age_classification = AgeClassification.UNKNOWN
            return
        
        age = (datetime.utcnow() - self.creation_date).days
        self.age_days = age
        
        if age < 30:
            self.age_classification = AgeClassification.NEW
        elif age < 90:
            self.age_classification = AgeClassification.RECENT
        elif age < 730:  # 2 years
            self.age_classification = AgeClassification.ESTABLISHED
        else:
            self.age_classification = AgeClassification.OLD


class InfrastructureEntry(BaseModel):
    """Complete infrastructure information for a domain or IP."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    # Identity
    value: str = Field(..., description="Domain or IP address")
    type: InfrastructureType = Field(..., description="Type of entity")
    
    # DNS Resolution (for domains)
    resolved_ips: list[str] = Field(default_factory=list, description="A/AAAA records")
    dns_source: str = Field(default="local", description="DNS resolver used")
    
    # ASN Information (for IPs)
    asn: Optional[ASNLInfo] = Field(None, description="AS Number information")
    
    # Geolocation (for IPs)
    geo: Optional[GeoInfo] = Field(None, description="Geolocation data")
    
    # Domain-specific info (for domains)
    domain_info: Optional[DomainInfo] = Field(None, description="Domain registration info")
    
    # Hosting classification
    hosting_type: HostingType = Field(default=HostingType.UNKNOWN)
    hosting_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    hosting_reasons: list[str] = Field(default_factory=list, description="Why this classification")
    
    # Known VPS/bulletproof indicators
    is_known_vps: bool = Field(default=False)
    is_bulletproof: bool = Field(default=False)
    bulletproof_provider: Optional[str] = Field(None, description="Known bulletproof provider if applicable")
    
    # Evidence traceability
    enrichment_time: datetime = Field(default_factory=datetime.utcnow)
    enrichment_source: str = Field(default="local", description="Enrichment provider")
    cost: int = Field(default=0, description="API cost (0 for offline)")


class InfrastructureSummary(BaseModel):
    """Aggregated infrastructure analysis summary."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    run_id: str = Field(..., description="Analysis run identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Entry counts
    total_domains: int = Field(default=0)
    total_ips: int = Field(default=0)
    total_asns: int = Field(default=0)
    
    # Age distribution
    new_domains: int = Field(default=0, description="< 30 days")
    recent_domains: int = Field(default=0, description="30-90 days")
    
    # Risk indicators
    bulletproof_count: int = Field(default=0)
    vps_count: int = Field(default=0)
    shared_hosting_count: int = Field(default=0)
    
    # Geographic distribution
    countries: dict[str, int] = Field(default_factory=dict, description="Country -> count")
    
    # Top ASNs
    top_asns: list[tuple[int, str, int]] = Field(
        default_factory=list,
        description="[(asn, org, count)] sorted by count"
    )
    
    # Entries
    domains: list[InfrastructureEntry] = Field(default_factory=list)
    ips: list[InfrastructureEntry] = Field(default_factory=list)


class InfrastructureProviderType(str, Enum):
    """Available infrastructure enrichment providers."""
    
    LOCAL = "local"  # Offline mode - use cache only
    TEAM_CYMRU = "team_cymru"  # Team Cymru DNS-based ASN lookup
    BGPVIEW = "bgpview"  # BGPView REST API (fallback)
    RDAP = "rdap"  # Registration Data Access Protocol
    WHOIS = "whois"  # Traditional WHOIS (fallback)
    IP_API = "ip_api"  # ip-api.com for geolocation
    IPINFO = "ipinfo"  # ipinfo.io (optional paid)
    
    @classmethod
    def free_providers(cls) -> list["InfrastructureProviderType"]:
        """Return list of free providers."""
        return [
            cls.TEAM_CYMRU,  # Free, DNS-based
            cls.RDAP,  # Free, standard protocol
            cls.WHOIS,  # Free, standard protocol
            cls.IP_API,  # Free tier available
        ]


class InfrastructureConfig(BaseModel):
    """Configuration for infrastructure enrichment."""
    
    offline_mode: bool = Field(default=True)
    providers: list[InfrastructureProviderType] = Field(
        default_factory=lambda: [
            InfrastructureProviderType.TEAM_CYMRU,
            InfrastructureProviderType.RDAP,
            InfrastructureProviderType.IP_API,
        ]
    )
    
    # Caching
    cache_ttl_hours: int = Field(default=24, description="Cache time-to-live")
    cache_enabled: bool = Field(default=True)
    
    # API keys (for paid providers)
    ipinfo_token: Optional[str] = Field(None)
    securitytrails_key: Optional[str] = Field(None)
    
    # Rate limiting
    rate_limit_per_minute: int = Field(default=60)
    
    # VPS/bulletproof detection
    known_vps_asns: list[int] = Field(default_factory=list)
    known_vps_orgs: list[str] = Field(default_factory=list)
    bulletproof_providers: list[str] = Field(default_factory=list)
