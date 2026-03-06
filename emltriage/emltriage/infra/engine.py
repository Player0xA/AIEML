"""Main infrastructure enrichment engine.

Coordinates DNS resolution, ASN lookup, RDAP queries, geolocation,
and hosting detection into a unified enrichment pipeline.
"""

from __future__ import annotations

import socket
from datetime import datetime
from pathlib import Path
from typing import Optional

from emltriage.infra.models import (
    InfrastructureEntry,
    InfrastructureSummary,
    InfrastructureType,
    InfrastructureConfig,
    HostingType,
    AgeClassification,
    ASNLInfo,
    GeoInfo,
    DomainInfo,
)
from emltriage.infra.asn import ASNLookup
from emltriage.infra.rdap import DomainLookup
from emltriage.infra.geo import GeoLookup
from emltriage.infra.hosting import HostingDetector
from emltriage.cti.cache import CacheManager
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class InfrastructureEngine:
    """Main infrastructure enrichment engine.
    
    Coordinates multiple data sources to provide comprehensive
    infrastructure context for domains and IPs.
    """
    
    def __init__(
        self,
        config: Optional[InfrastructureConfig] = None,
        cache_manager: Optional[CacheManager] = None,
    ):
        self.config = config or InfrastructureConfig()
        self.cache = cache_manager
        
        # Initialize providers
        self.asn_lookup = ASNLookup(offline_mode=self.config.offline_mode)
        self.domain_lookup = DomainLookup(offline_mode=self.config.offline_mode)
        self.geo_lookup = GeoLookup(
            ipinfo_token=self.config.ipinfo_token,
            offline_mode=self.config.offline_mode
        )
        self.hosting_detector = HostingDetector()
    
    def enrich_domain(self, domain: str) -> InfrastructureEntry:
        """Enrich a domain with infrastructure data.
        
        Args:
            domain: Domain name to enrich
            
        Returns:
            InfrastructureEntry with all available data
        """
        entry = InfrastructureEntry(
            value=domain.lower().strip(),
            type=InfrastructureType.DOMAIN,
            enrichment_source="infrastructure_engine",
        )
        
        # Try cache first
        if self.cache:
            cached = self._get_cached_entry(domain)
            if cached:
                logger.debug(f"Cache hit for domain: {domain}")
                return cached
        
        # DNS Resolution
        entry.resolved_ips = self._resolve_domain(domain)
        entry.dns_source = "system"
        
        # Domain registration info (RDAP/WHOIS)
        if not self.config.offline_mode:
            domain_info = self.domain_lookup.lookup(domain)
            if domain_info:
                entry.domain_info = domain_info
        
        # If we have resolved IPs, enrich them too
        for ip in entry.resolved_ips:
            ip_entry = self.enrich_ip(ip)
            if ip_entry.asn:
                entry.asn = ip_entry.asn  # Use first IP's ASN for domain
                break
        
        # Hosting classification (uses domain age + hosting data)
        hosting_type, confidence, reasons = self.hosting_detector.classify_hosting(entry)
        entry.hosting_type = hosting_type
        entry.hosting_confidence = confidence
        entry.hosting_reasons = reasons
        
        # Check for suspicious indicators
        is_suspicious, suspicious_reasons = self.hosting_detector.is_suspicious_hosting(entry)
        if is_suspicious:
            if HostingType.BULLETPROOF in reasons or "bulletproof" in str(reasons).lower():
                entry.is_bulletproof = True
            entry.hosting_reasons.extend(suspicious_reasons)
        
        # Cache result
        if self.cache:
            self._cache_entry(entry)
        
        return entry
    
    def enrich_ip(self, ip: str) -> InfrastructureEntry:
        """Enrich an IP address with infrastructure data.
        
        Args:
            ip: IP address to enrich
            
        Returns:
            InfrastructureEntry with all available data
        """
        # Determine IP type
        ip_type = InfrastructureType.IPV6 if ":" in ip else InfrastructureType.IPV4
        
        entry = InfrastructureEntry(
            value=ip,
            type=ip_type,
            enrichment_source="infrastructure_engine",
        )
        
        # Try cache first
        if self.cache:
            cached = self._get_cached_entry(ip)
            if cached:
                logger.debug(f"Cache hit for IP: {ip}")
                return cached
        
        # ASN Lookup
        if not self.config.offline_mode:
            asn_info = self.asn_lookup.lookup(ip)
            if asn_info:
                entry.asn = asn_info
        
        # Geolocation
        if not self.config.offline_mode:
            geo_info = self.geo_lookup.lookup(ip)
            if geo_info:
                entry.geo = geo_info
        
        # Hosting classification
        hosting_type, confidence, reasons = self.hosting_detector.classify_hosting(entry)
        entry.hosting_type = hosting_type
        entry.hosting_confidence = confidence
        entry.hosting_reasons = reasons
        
        # Check for VPS
        if hosting_type == HostingType.VPS:
            entry.is_known_vps = True
            if entry.asn and entry.asn.asn in self.hosting_detector.KNOWN_VPS_ASNS:
                reasons.append(f"Known VPS provider: {self.hosting_detector.KNOWN_VPS_ASNS[entry.asn.asn]}")
        
        # Check for bulletproof
        is_suspicious, suspicious_reasons = self.hosting_detector.is_suspicious_hosting(entry)
        if is_suspicious:
            entry.is_bulletproof = True
            entry.bulletproof_provider = suspicious_reasons[0] if suspicious_reasons else "Unknown"
            entry.hosting_reasons.extend(suspicious_reasons)
        
        # Cache result
        if self.cache:
            self._cache_entry(entry)
        
        return entry
    
    def enrich_batch(
        self,
        domains: list[str],
        ips: list[str],
        run_id: str,
    ) -> InfrastructureSummary:
        """Enrich multiple domains and IPs.
        
        Args:
            domains: List of domain names
            ips: List of IP addresses
            run_id: Analysis run identifier
            
        Returns:
            InfrastructureSummary with all entries
        """
        summary = InfrastructureSummary(run_id=run_id)
        
        # Enrich domains
        logger.info(f"Enriching {len(domains)} domains")
        for domain in domains:
            try:
                entry = self.enrich_domain(domain)
                summary.domains.append(entry)
                
                if entry.domain_info:
                    if entry.domain_info.age_classification == AgeClassification.NEW:
                        summary.new_domains += 1
                    elif entry.domain_info.age_classification == AgeClassification.RECENT:
                        summary.recent_domains += 1
                
                if entry.is_bulletproof:
                    summary.bulletproof_count += 1
                elif entry.is_known_vps:
                    summary.vps_count += 1
                
            except Exception as e:
                logger.error(f"Failed to enrich domain {domain}: {e}")
        
        # Enrich IPs
        logger.info(f"Enriching {len(ips)} IPs")
        for ip in ips:
            try:
                entry = self.enrich_ip(ip)
                summary.ips.append(entry)
                
                # Track countries
                if entry.geo and entry.geo.country:
                    summary.countries[entry.geo.country] = summary.countries.get(entry.geo.country, 0) + 1
                
                # Track ASNs
                if entry.asn:
                    asn_key = (entry.asn.asn, entry.asn.org)
                    summary.top_asns.append((entry.asn.asn, entry.asn.org, 1))
                
                if entry.is_bulletproof:
                    summary.bulletproof_count += 1
                elif entry.is_known_vps:
                    summary.vps_count += 1
                
            except Exception as e:
                logger.error(f"Failed to enrich IP {ip}: {e}")
        
        # Calculate summary stats
        summary.total_domains = len(summary.domains)
        summary.total_ips = len(summary.ips)
        
        # Aggregate ASNs
        asn_counts = {}
        for entry in summary.ips:
            if entry.asn:
                key = (entry.asn.asn, entry.asn.org)
                asn_counts[key] = asn_counts.get(key, 0) + 1
        
        # Sort ASNs by count
        sorted_asns = sorted(asn_counts.items(), key=lambda x: x[1], reverse=True)
        summary.top_asns = [(asn, org, count) for (asn, org), count in sorted_asns[:10]]
        summary.total_asns = len(asn_counts)
        
        logger.info(
            f"Enrichment complete: {summary.total_domains} domains, "
            f"{summary.total_ips} IPs, {summary.total_asns} ASNs"
        )
        
        return summary
    
    def _resolve_domain(self, domain: str) -> list[str]:
        """Resolve domain to IP addresses."""
        ips = []
        
        try:
            # A records (IPv4)
            ipv4 = socket.getaddrinfo(domain, None, socket.AF_INET)
            for result in ipv4:
                ip = result[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            pass
        
        try:
            # AAAA records (IPv6)
            ipv6 = socket.getaddrinfo(domain, None, socket.AF_INET6)
            for result in ipv6:
                ip = result[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            pass
        
        return ips
    
    def _get_cached_entry(self, key: str) -> Optional[InfrastructureEntry]:
        """Get cached infrastructure entry."""
        if not self.cache:
            return None
        
        try:
            cache_key = f"infra:{key}"
            cached_data = self.cache.get(cache_key)
            if cached_data:
                return InfrastructureEntry(**cached_data)
        except Exception as e:
            logger.debug(f"Cache get failed for {key}: {e}")
        
        return None
    
    def _cache_entry(self, entry: InfrastructureEntry) -> None:
        """Cache infrastructure entry."""
        if not self.cache:
            return
        
        try:
            cache_key = f"infra:{entry.value}"
            ttl = self.config.cache_ttl_hours * 3600  # Convert to seconds
            self.cache.set(cache_key, entry.model_dump(mode="json"), ttl=ttl)
        except Exception as e:
            logger.debug(f"Cache set failed for {entry.value}: {e}")


def enrich_infrastructure(
    domains: list[str],
    ips: list[str],
    run_id: str,
    offline: bool = True,
    config: Optional[InfrastructureConfig] = None,
) -> InfrastructureSummary:
    """Convenience function for infrastructure enrichment.
    
    Args:
        domains: List of domains to enrich
        ips: List of IPs to enrich
        run_id: Analysis run ID
        offline: Whether to run in offline mode
        config: Optional configuration
        
    Returns:
        InfrastructureSummary with all enriched data
    """
    if config is None:
        config = InfrastructureConfig(offline_mode=offline)
    else:
        config.offline_mode = offline
    
    engine = InfrastructureEngine(config=config)
    return engine.enrich_batch(domains, ips, run_id)
