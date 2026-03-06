"""Infrastructure enrichment module for emltriage.

Provides infrastructure context for domains and IPs:
- DNS resolution (A/AAAA records)
- ASN lookup (Team Cymru primary, BGPView fallback)
- Domain registration (RDAP primary, WHOIS fallback)
- Geolocation (ip-api primary, ipinfo fallback)
- Hosting type detection (VPS, bulletproof, CDN, etc.)

Example:
    from emltriage.infra import InfrastructureEngine, InfrastructureConfig
    
    config = InfrastructureConfig(offline_mode=False)
    engine = InfrastructureEngine(config=config)
    
    # Enrich a single domain
    entry = engine.enrich_domain("example.com")
    print(f"ASN: {entry.asn.asn} ({entry.asn.org})")
    print(f"Hosting: {entry.hosting_type.value}")
    print(f"Domain age: {entry.domain_info.age_classification.value}")
    
    # Batch enrichment
    summary = engine.enrich_batch(
        domains=["example.com", "test.org"],
        ips=["8.8.8.8"],
        run_id="test-001"
    )
"""

from emltriage.infra.models import (
    InfrastructureEntry,
    InfrastructureSummary,
    InfrastructureType,
    InfrastructureConfig,
    InfrastructureProviderType,
    HostingType,
    AgeClassification,
    ASNLInfo,
    GeoInfo,
    DomainInfo,
)
from emltriage.infra.engine import InfrastructureEngine, enrich_infrastructure
from emltriage.infra.asn import ASNLookup, TeamCymruProvider, BGPViewProvider
from emltriage.infra.rdap import RDAPClient, DomainLookup, WHOISFallback
from emltriage.infra.geo import GeoLookup, IPAPIProvider, IPInfoProvider
from emltriage.infra.hosting import HostingDetector, VPS_ASNS, BULLETPROOF_ASNS

__all__ = [
    # Models
    "InfrastructureEntry",
    "InfrastructureSummary",
    "InfrastructureType",
    "InfrastructureConfig",
    "InfrastructureProviderType",
    "HostingType",
    "AgeClassification",
    "ASNLInfo",
    "GeoInfo",
    "DomainInfo",
    # Engine
    "InfrastructureEngine",
    "enrich_infrastructure",
    # Providers
    "ASNLookup",
    "TeamCymruProvider",
    "BGPViewProvider",
    "RDAPClient",
    "DomainLookup",
    "WHOISFallback",
    "GeoLookup",
    "IPAPIProvider",
    "IPInfoProvider",
    "HostingDetector",
    # Constants
    "VPS_ASNS",
    "BULLETPROOF_ASNS",
]
