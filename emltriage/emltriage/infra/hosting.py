"""Hosting type detection heuristics.

Identifies VPS, bulletproof hosting, CDNs, and residential IPs based on:
- Known ASNs
- Organization names
- Reverse DNS patterns
- Geographic indicators
"""

from __future__ import annotations

import re
from typing import Optional

from emltriage.infra.models import (
    InfrastructureEntry,
    HostingType,
    ASNLInfo,
    GeoInfo,
    DomainInfo
)
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class HostingDetector:
    """Detect hosting type from infrastructure data."""
    
    # Known VPS/Cloud ASNs
    KNOWN_VPS_ASNS = {
        # Major Cloud Providers
        15169: "Google Cloud",
        16509: "Amazon AWS",
        8075: "Microsoft Azure",
        36351: "IBM Cloud",
        31898: "Oracle Cloud",
        
        # Popular VPS/Cloud Hosts
        14061: "DigitalOcean",
        20473: "DigitalOcean (AS20473)",
        200130: "DigitalOcean",
        63949: "Linode",
        8001: "Linode (AS8001)",
        16276: "OVH",
        12876: "OVH (AS12876)",
        57497: "Vultr",
        20473: "Vultr (AS20473)",
        25820: "Hetzner",
        24940: "Hetzner (AS24940)",
        9009: "M247",
        13335: "Cloudflare",
        209242: "Cloudflare",
        
        # Shared Hosting / Budget VPS
        46606: "Unified Layer (Bluehost)",
        19994: "Rackspace",
        33070: "Rackspace",
        26347: "DreamHost",
        14415: "HostGator",
        3344: "GoDaddy",
        20773: "GoDaddy",
        398101: "Namecheap",
        22612: "Namecheap",
        
        # Other Known VPS
        36024: "Contabo",
        51167: "Contabo (AS51167)",
        20278: "Contabo (AS20278)",
        53667: "Psychz Networks",
        40676: "Psychz Networks",
        46844: "Sharktech",
        46805: "Sharktech (AS46805)",
    }
    
    # Known VPS organization keywords
    VPS_KEYWORDS = [
        "digitalocean", "linode", "vultr", "ovh", "hetzner", "contabo",
        "aws", "amazon", "ec2", "gcp", "google cloud", "azure", "microsoft",
        "cloudflare", "fastly", "maxcdn", "keycdn", "stackpath",
        "hostgator", "bluehost", "godaddy", "dreamhost", "namecheap",
        "vps", "cloud", "hosting", "server", "data center", "datacenter",
        "sharktech", "psychz", "m247", "dedipath", "nexeon", "quadranet",
    ]
    
    # Known bulletproof hosting ASNs
    KNOWN_BULLETPROOF_ASNS = {
        9009: "M247 (watchlist)",  # Sometimes used for bulletproof
        20278: "Nexeon (watchlist)",
        53755: "Eonix (watchlist)",
        46844: "Sharktech (watchlist)",  # Sometimes bulletproof
        62904: "BlackHOST (watchlist)",
        49453: "GleSYS (watchlist)",
    }
    
    # Known bulletproof providers by name
    BULLETPROOF_KEYWORDS = [
        "bulletproof", "abuse ignored", "no abuse", "dmca ignored",
        "offshore", "offshore hosting", "privacy hosting", "anonymous",
        "cyberbunker", "atrivo", "mcbans", "nexeon", "quadranet abuse",
    ]
    
    # CDN ASNs
    CDN_ASNS = {
        13335: "Cloudflare",
        209242: "Cloudflare (EU)",
        54113: "Fastly",
        16509: "Amazon CloudFront",
        15169: "Google CDN",
        396982: "Google CDN",
        8075: "Microsoft CDN",
        22822: "Limelight",
        1299: "Telia CDN",
        32590: "Valve/Steam CDN",
        20446: "Highwinds",
        33438: "StackPath",
        13768: "Peer 5",
        137409: "G-Core Labs",
    }
    
    # Enterprise/legitimate ASNs (for context)
    ENTERPRISE_ASNS = {
        8075: "Microsoft (Enterprise)",
        15169: "Google (Enterprise)",
        16509: "Amazon (Enterprise)",
        32934: "Facebook",
        13414: "Twitter",
        54115: "GitHub",
        14618: "Amazon Corporate",
        26496: "GoDaddy Corporate",
        11427: "Time Warner",
        7922: "Comcast",
        701: "Verizon",
        7018: "AT&T",
        3356: "Level3/CenturyLink",
        2914: "NTT America",
        174: "Cogent",
        3257: "GTT",
        6939: "Hurricane Electric",
        2497: "IIJ (Japan)",
        4713: "NTT (Japan)",
        1267: "Wind Telecom (Italy)",
    }
    
    def __init__(self):
        pass
    
    def classify_hosting(
        self,
        entry: InfrastructureEntry
    ) -> tuple[HostingType, float, list[str]]:
        """Classify hosting type from infrastructure entry.
        
        Args:
            entry: Infrastructure entry with ASN/geo/domain info
            
        Returns:
            Tuple of (hosting_type, confidence, reasons)
        """
        reasons = []
        
        # Check for bulletproof first (highest priority)
        is_bp, bp_reasons = self._check_bulletproof(entry)
        if is_bp:
            return HostingType.BULLETPROOF, 0.9, bp_reasons
        
        # Check for CDN
        is_cdn, cdn_reasons = self._check_cdn(entry)
        if is_cdn:
            return HostingType.CDN, 0.95, cdn_reasons
        
        # Check for VPS
        is_vps, vps_reasons = self._check_vps(entry)
        if is_vps:
            return HostingType.VPS, 0.85, vps_reasons
        
        # Check for residential
        is_res, res_reasons = self._check_residential(entry)
        if is_res:
            return HostingType.RESIDENTIAL, 0.7, res_reasons
        
        # Check for enterprise
        is_ent, ent_reasons = self._check_enterprise(entry)
        if is_ent:
            return HostingType.ENTERPRISE, 0.8, ent_reasons
        
        # Default to unknown
        return HostingType.UNKNOWN, 0.0, ["Insufficient data for classification"]
    
    def _check_bulletproof(self, entry: InfrastructureEntry) -> tuple[bool, list[str]]:
        """Check for bulletproof hosting indicators."""
        reasons = []
        
        if not entry.asn:
            return False, reasons
        
        asn = entry.asn.asn
        org = entry.asn.org.lower() if entry.asn.org else ""
        
        # Check known bulletproof ASNs
        if asn in self.KNOWN_BULLETPROOF_ASNS:
            reasons.append(f"Known bulletproof ASN: {self.KNOWN_BULLETPROOF_ASNS[asn]}")
        
        # Check bulletproof keywords in org name
        for keyword in self.BULLETPROOF_KEYWORDS:
            if keyword in org:
                reasons.append(f"Bulletproof indicator in org name: '{keyword}'")
        
        return len(reasons) > 0, reasons
    
    def _check_cdn(self, entry: InfrastructureEntry) -> tuple[bool, list[str]]:
        """Check for CDN indicators."""
        reasons = []
        
        if not entry.asn:
            return False, reasons
        
        asn = entry.asn.asn
        
        # Check known CDN ASNs
        if asn in self.CDN_ASNS:
            reasons.append(f"Known CDN ASN: {self.CDN_ASNS[asn]}")
            return True, reasons
        
        return False, reasons
    
    def _check_vps(self, entry: InfrastructureEntry) -> tuple[bool, list[str]]:
        """Check for VPS/cloud hosting indicators."""
        reasons = []
        
        if not entry.asn:
            return False, reasons
        
        asn = entry.asn.asn
        org = entry.asn.org.lower() if entry.asn.org else ""
        
        # Check known VPS ASNs
        if asn in self.KNOWN_VPS_ASNS:
            reasons.append(f"Known VPS ASN: {self.KNOWN_VPS_ASNS[asn]}")
        
        # Check VPS keywords in org name
        for keyword in self.VPS_KEYWORDS:
            if keyword in org:
                reasons.append(f"VPS indicator in org name: '{keyword}'")
        
        # Check if it's a cloud provider
        cloud_keywords = ["cloud", "aws", "azure", "gcp", "google cloud", "amazon"]
        for keyword in cloud_keywords:
            if keyword in org:
                reasons.append(f"Cloud provider indicator: '{keyword}'")
        
        return len(reasons) > 0, reasons
    
    def _check_residential(self, entry: InfrastructureEntry) -> tuple[bool, list[str]]:
        """Check for residential ISP indicators."""
        reasons = []
        
        if not entry.asn:
            return False, reasons
        
        org = entry.asn.org.lower() if entry.asn.org else ""
        
        # Residential ISP keywords
        residential_keywords = [
            "cable", "dsl", "fiber", "broadband", "telecom", "telephone",
            "wireless", "mobile", "cellular", "residential", "home",
            "verizon", "comcast", "att", "spectrum", "cox", "xfinity",
            "bt ", "virgin", "talktalk", "sky broadband", "orange",
            "telefonica", "vodafone", " Deutsche telekom", "orange",
        ]
        
        for keyword in residential_keywords:
            if keyword in org:
                reasons.append(f"Residential ISP indicator: '{keyword}'")
        
        # Check if geo info suggests residential
        if entry.geo:
            if entry.geo.isp and "residential" in entry.geo.isp.lower():
                reasons.append("ISP flagged as residential")
        
        return len(reasons) > 0, reasons
    
    def _check_enterprise(self, entry: InfrastructureEntry) -> tuple[bool, list[str]]:
        """Check for enterprise/legitimate hosting."""
        reasons = []
        
        if not entry.asn:
            return False, reasons
        
        asn = entry.asn.asn
        
        # Check known enterprise ASNs
        if asn in self.ENTERPRISE_ASNS:
            reasons.append(f"Known enterprise ASN: {self.ENTERPRISE_ASNS[asn]}")
        
        return len(reasons) > 0, reasons
    
    def is_suspicious_hosting(self, entry: InfrastructureEntry) -> tuple[bool, list[str]]:
        """Determine if hosting is suspicious.
        
        Returns:
            Tuple of (is_suspicious, reasons)
        """
        reasons = []
        
        hosting_type, confidence, classification_reasons = self.classify_hosting(entry)
        
        # Suspicious hosting types
        if hosting_type == HostingType.BULLETPROOF:
            reasons.append("Bulletproof hosting detected")
            reasons.extend(classification_reasons)
            return True, reasons
        
        if hosting_type == HostingType.VPS:
            # VPS can be legitimate, but combined with other factors is suspicious
            if entry.domain_info:
                if entry.domain_info.age_classification.value == "new":
                    reasons.append("New domain hosted on VPS")
                    reasons.extend(classification_reasons)
                    return True, reasons
        
        return False, reasons


# VPS/bulletproof ASN lists as module-level constants for easy import
VPS_ASNS = HostingDetector.KNOWN_VPS_ASNS
BULLETPROOF_ASNS = HostingDetector.KNOWN_BULLETPROOF_ASNS
CDN_ASNS = HostingDetector.CDN_ASNS
