"""Brand and domain impersonation detection engine.

Implements F1 from OSINT Blueprint:
- Typo-squat detection (Levenshtein/Damerau distance)
- Homoglyph detection (Unicode confusables)
- Keyword-based brand matching
- Punycode/IDN abuse detection

All with evidence traceability per blueprint requirements.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml

try:
    from rapidfuzz import distance
    LEVENSHTEIN_AVAILABLE = True
except ImportError:
    LEVENSHTEIN_AVAILABLE = False

from emltriage.core.models import (
    Artifacts,
    ImpersonationFinding,
    ImpersonationTechnique,
    ImpersonationAlgorithm,
    Severity,
    IOCType,
)
from emltriage.utils.constants import RISK_WEIGHTS


class BrandConfig:
    """Loaded brand configuration from YAML."""
    
    def __init__(self, config_path: Optional[Path] = None):
        self.brands: dict[str, dict] = {}  # name -> {domains, keywords, priority}
        self.scoring = {
            "algorithm": "weighted",
            "weights": {
                "levenshtein": 0.35,
                "homoglyph": 0.30,
                "keyword_match": 0.20,
                "punycode": 0.15,
            },
            "threshold": 0.75,
            "max_distance": 3,
        }
        self.risk_integration = {
            "enabled": True,
            "weight_impersonation_detected": 30,
            "weight_high_confidence": 40,
        }
        self.homoglyph_map: dict[str, str] = {}
        self.ignored_tlds: set[str] = set()
        self.infrastructure_domains: set[str] = set()
        
        if config_path:
            self._load_config(config_path)
        else:
            self._load_default_config()
    
    def _load_default_config(self):
        """Load default brand configuration from package."""
        default_path = Path(__file__).parent.parent / "config" / "brands.yaml"
        if default_path.exists():
            self._load_config(default_path)
    
    def _load_config(self, path: Path):
        """Load configuration from YAML file."""
        with open(path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        # Load brands from all categories
        for category_name, category_data in config.get('categories', {}).items():
            for brand in category_data.get('brands', []):
                name = brand['name']
                self.brands[name] = {
                    'domains': set(brand.get('domains', [])),
                    'keywords': set(brand.get('keywords', [])),
                    'priority': brand.get('priority', 'medium'),
                }
        
        # Load scoring configuration
        if 'scoring' in config:
            self.scoring.update(config['scoring'])
        
        # Load risk integration settings
        if 'risk_integration' in config:
            self.risk_integration.update(config['risk_integration'])
        
        # Load advanced settings
        advanced = config.get('advanced', {})
        self.homoglyph_map = advanced.get('homoglyph_map', {})
        self.ignored_tlds = set(advanced.get('ignored_tlds', []))
        self.infrastructure_domains = set(advanced.get('infrastructure_domains', []))


class PrecomputedBrandCache:
    """Pre-computed fuzzy hashes for fast brand lookup."""
    
    def __init__(self, brand_config: BrandConfig):
        self.config = brand_config
        self.token_hashes: dict[str, set[str]] = {}  # token -> {brand_names}
        self.normalized_map: dict[str, str] = {}  # normalized -> original
        self._build_cache()
    
    def _build_cache(self):
        """Pre-compute all token variations for fast lookup."""
        for brand_name, brand_data in self.config.brands.items():
            # Add brand name itself
            normalized = self._normalize_token(brand_name)
            if normalized:
                self.token_hashes.setdefault(normalized, set()).add(brand_name)
                self.normalized_map[normalized] = brand_name
            
            # Add all domains
            for domain in brand_data['domains']:
                tokens = self._tokenize_domain(domain)
                for token in tokens:
                    normalized = self._normalize_token(token)
                    if normalized:
                        self.token_hashes.setdefault(normalized, set()).add(brand_name)
                        self.normalized_map[normalized] = brand_name
            
            # Add all keywords
            for keyword in brand_data['keywords']:
                normalized = self._normalize_token(keyword)
                if normalized:
                    self.token_hashes.setdefault(normalized, set()).add(brand_name)
                    self.normalized_map[normalized] = brand_name
    
    @staticmethod
    def _normalize_token(token: str) -> str:
        """Normalize a token for fuzzy matching."""
        token = token.lower().strip()
        # Remove common suffixes/prefixes
        token = re.sub(r'\.(com|org|net|gov|edu|mx)$', '', token)
        token = re.sub(r'^(www\.|mail\.|email\.|web\.)', '', token)
        return token
    
    @staticmethod
    def _tokenize_domain(domain: str) -> list[str]:
        """Tokenize domain into components."""
        # Remove protocol and path
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]
        # Split on dots and hyphens
        tokens = re.split(r'[.-]', domain)
        return [t for t in tokens if len(t) > 2]
    
    def get_candidate_brands(self, token: str) -> set[str]:
        """Get brand candidates for a token (exact match)."""
        normalized = self._normalize_token(token)
        return self.token_hashes.get(normalized, set())
    
    def fuzzy_match_brands(self, token: str, max_distance: int = 2) -> list[tuple[str, int]]:
        """Fuzzy match token against all brand tokens."""
        if not LEVENSHTEIN_AVAILABLE:
            # Fallback: exact match only
            candidates = self.get_candidate_brands(token)
            return [(c, 0) for c in candidates]
        
        normalized = self._normalize_token(token)
        if not normalized:
            return []
        
        matches = []
        for cached_token, brands in self.token_hashes.items():
            dist = distance.Levenshtein.distance(normalized, cached_token)
            if dist <= max_distance:
                for brand in brands:
                    matches.append((brand, dist))
        
        # Sort by distance
        matches.sort(key=lambda x: x[1])
        return matches


class ImpersonationDetector:
    """Main impersonation detection engine."""
    
    def __init__(
        self,
        brand_config: Optional[BrandConfig] = None,
        algorithm: ImpersonationAlgorithm = ImpersonationAlgorithm.WEIGHTED,
        excluded_brands: Optional[set[str]] = None,
    ):
        self.config = brand_config or BrandConfig()
        self.algorithm = algorithm
        self.excluded_brands = excluded_brands or set()
        self.cache = PrecomputedBrandCache(self.config)
        self.findings: list[ImpersonationFinding] = []
    
    def detect(self, artifacts: Artifacts) -> list[ImpersonationFinding]:
        """Run all impersonation detection techniques on artifacts."""
        self.findings = []
        
        # Collect all domains to check
        domains_to_check = self._extract_domains(artifacts)
        
        # Run detection on each domain
        for domain_info in domains_to_check:
            self._check_domain(
                domain=domain_info['domain'],
                source=domain_info['source'],
                evidence_ref=domain_info.get('evidence_ref', ''),
                display_name=domain_info.get('display_name'),
            )
        
        # Sort by score (highest first)
        self.findings.sort(key=lambda x: x.score, reverse=True)
        
        return self.findings
    
    def _extract_domains(self, artifacts: Artifacts) -> list[dict]:
        """Extract all domains from artifacts with their sources."""
        domains = []
        
        # From headers (From, Reply-To, Return-Path)
        for header in artifacts.headers:
            if header.name.lower() in ['from', 'reply-to', 'return-path']:
                if header.parsed and 'addresses' in header.parsed:
                    for addr in header.parsed['addresses']:
                        domain = addr.get('domain', '')
                        display = addr.get('display_name', '')
                        if domain:
                            domains.append({
                                'domain': domain,
                                'source': f"headers.{header.name}",
                                'evidence_ref': f"headers.{header.name}",
                                'display_name': display,
                            })
        
        # From URLs in bodies
        for url_entry in artifacts.urls:
            url = url_entry.deobfuscated or url_entry.normalized
            domain_match = re.search(r'https?://([^/]+)', url)
            if domain_match:
                domain = domain_match.group(1)
                if ':' in domain:
                    domain = domain.split(':')[0]
                domains.append({
                    'domain': domain,
                    'source': f"urls.{url_entry.source}",
                    'evidence_ref': url_entry.evidence_ref,
                })
        
        # From routing hops
        for hop in artifacts.routing:
            if hop.from_host:
                domains.append({
                    'domain': hop.from_host,
                    'source': 'routing.from_host',
                    'evidence_ref': f"routing.hops.{hop.hop_number}",
                })
        
        # From IOCs (domains only)
        for ioc in artifacts.iocs:
            if ioc.type == IOCType.DOMAIN:
                domains.append({
                    'domain': ioc.value,
                    'source': f"iocs.{ioc.source}",
                    'evidence_ref': ioc.evidence_ref,
                })
        
        # Deduplicate while preserving evidence
        seen = {}
        for d in domains:
            key = d['domain'].lower()
            if key not in seen:
                seen[key] = d
            else:
                # Merge evidence
                if d['source'] not in seen[key].get('sources', [seen[key]['source']]):
                    seen[key].setdefault('sources', [seen[key]['source']]).append(d['source'])
        
        return list(seen.values())
    
    def _check_domain(
        self,
        domain: str,
        source: str,
        evidence_ref: str,
        display_name: Optional[str] = None,
    ):
        """Check a single domain for impersonation."""
        # Skip infrastructure domains
        if self._is_infrastructure(domain):
            return
        
        # Skip ignored TLDs
        if self._is_ignored_tld(domain):
            return
        
        # Normalize domain
        normalized_domain = self._normalize_domain(domain)
        tokens = self.cache._tokenize_domain(normalized_domain)
        
        # Run all detection techniques
        techniques_scores = {}
        
        # 1. Levenshtein distance (typo-squats)
        lev_result = self._check_levenshtein(normalized_domain, tokens)
        if lev_result:
            techniques_scores['levenshtein'] = lev_result
        
        # 2. Homoglyph detection
        homo_result = self._check_homoglyphs(normalized_domain)
        if homo_result:
            techniques_scores['homoglyph'] = homo_result
        
        # 3. Keyword matching
        kw_result = self._check_keywords(normalized_domain, display_name, tokens)
        if kw_result:
            techniques_scores['keyword_match'] = kw_result
        
        # 4. Punycode/IDN abuse
        puny_result = self._check_punycode(domain)
        if puny_result:
            techniques_scores['punycode'] = puny_result
        
        # Calculate final score
        if techniques_scores:
            final_score, technique = self._calculate_score(techniques_scores)
            
            if final_score >= self.config.scoring['threshold']:
                # Determine severity
                severity = self._score_to_severity(final_score)
                
                # Get primary brand from highest scoring technique
                brand = techniques_scores[technique]['brand']
                
                # Create explanation
                explanation = self._create_explanation(
                    domain, brand, technique, techniques_scores
                )
                
                # Generate normalized tokens for evidence
                normalized_tokens = [
                    self.cache._normalize_token(t) for t in tokens
                ] + [normalized_domain]
                
                # Generate query string
                query = f"{domain} vs {brand}"
                
                # Create finding
                finding = ImpersonationFinding(
                    brand_candidate=brand,
                    detected_domain=domain,
                    technique=ImpersonationTechnique(technique),
                    score=final_score,
                    severity=severity,
                    evidence_fields=[source] if isinstance(source, str) else source,
                    algorithm=self.algorithm,
                    query=query,
                    normalized_tokens=normalized_tokens,
                    explanation=explanation,
                )
                
                self.findings.append(finding)
    
    def _check_levenshtein(
        self,
        domain: str,
        tokens: list[str]
    ) -> Optional[dict]:
        """Check for typo-squats using Levenshtein distance."""
        max_dist = self.config.scoring.get('max_distance', 3)
        
        best_match = None
        best_distance = max_dist + 1
        
        # Check full domain
        for brand_name, brand_data in self.config.brands.items():
            if brand_name in self.excluded_brands:
                continue
            
            for brand_domain in brand_data['domains']:
                dist = self._levenshtein_distance(domain, brand_domain)
                if dist <= max_dist and dist < best_distance:
                    best_distance = dist
                    best_match = brand_name
        
        # Check tokens
        for token in tokens:
            fuzzy_matches = self.cache.fuzzy_match_brands(token, max_distance=max_dist)
            for brand, dist in fuzzy_matches:
                if brand not in self.excluded_brands and dist < best_distance:
                    best_distance = dist
                    best_match = brand
        
        if best_match:
            # Score inversely proportional to distance
            score = max(0.0, 1.0 - (best_distance / (max_dist + 1)))
            return {
                'brand': best_match,
                'distance': best_distance,
                'score': score,
            }
        
        return None
    
    def _check_homoglyphs(self, domain: str) -> Optional[dict]:
        """Check for homoglyph attacks using Unicode confusables."""
        if not self.config.homoglyph_map:
            return None
        
        # Normalize to ASCII and check for confusables
        ascii_form = self._normalize_homoglyphs(domain)
        
        if ascii_form == domain.lower():
            return None
        
        # Check if ASCII form matches any brand
        best_match = None
        best_score = 0.0
        
        for brand_name, brand_data in self.config.brands.items():
            if brand_name in self.excluded_brands:
                continue
            
            # Check if ASCII form matches brand domain
            for brand_domain in brand_data['domains']:
                if ascii_form == brand_domain.lower() or self._levenshtein_distance(ascii_form, brand_domain) <= 1:
                    score = 0.95  # High confidence for homoglyph match
                    if score > best_score:
                        best_score = score
                        best_match = brand_name
        
        if best_match:
            return {
                'brand': best_match,
                'original': domain,
                'ascii_form': ascii_form,
                'score': best_score,
            }
        
        return None
    
    def _check_keywords(
        self,
        domain: str,
        display_name: Optional[str],
        tokens: list[str]
    ) -> Optional[dict]:
        """Check for brand keywords in wrong domains."""
        domain_lower = domain.lower()
        
        for brand_name, brand_data in self.config.brands.items():
            if brand_name in self.excluded_brands:
                continue
            
            # Check if domain contains brand keywords but isn't the brand's domain
            brand_domains = [d.lower() for d in brand_data['domains']]
            
            # Check if it's already a brand domain
            is_brand_domain = any(
                domain_lower == bd or domain_lower.endswith('.' + bd)
                for bd in brand_domains
            )
            
            if is_brand_domain:
                continue
            
            # Check keywords in domain
            for keyword in brand_data['keywords']:
                kw_lower = keyword.lower()
                if kw_lower in domain_lower:
                    # It's a keyword match - calculate score based on similarity
                    score = 0.7  # Base score for keyword match
                    
                    # Higher score if it's a suspicious variation
                    for brand_domain in brand_domains:
                        if self._levenshtein_distance(domain_lower, brand_domain) <= 3:
                            score = 0.85
                            break
                    
                    return {
                        'brand': brand_name,
                        'keyword': keyword,
                        'score': score,
                    }
            
            # Check display name
            if display_name:
                display_lower = display_name.lower()
                brand_lower = brand_name.lower()
                
                # Display name contains brand but domain doesn't match
                if brand_lower in display_lower or any(
                    kw.lower() in display_lower for kw in brand_data['keywords']
                ):
                    # Check if domain is legitimate for this brand
                    if not any(domain_lower.endswith(bd) for bd in brand_domains):
                        return {
                            'brand': brand_name,
                            'keyword': 'display_name_mismatch',
                            'score': 0.75,
                        }
        
        return None
    
    def _check_punycode(self, domain: str) -> Optional[dict]:
        """Check for punycode/IDN homograph attacks."""
        # Check for xn-- prefix (punycode)
        if 'xn--' in domain.lower():
            try:
                # Decode punycode
                decoded = domain.encode('idna').decode('idna')
                
                # Check if decoded version looks like a brand
                ascii_decoded = self._normalize_homoglyphs(decoded)
                
                for brand_name, brand_data in self.config.brands.items():
                    if brand_name in self.excluded_brands:
                        continue
                    
                    for brand_domain in brand_data['domains']:
                        if self._levenshtein_distance(ascii_decoded, brand_domain) <= 2:
                            return {
                                'brand': brand_name,
                                'punycode': domain,
                                'decoded': decoded,
                                'score': 0.90,
                            }
            except Exception:
                pass
        
        return None
    
    def _calculate_score(self, techniques: dict) -> tuple[float, str]:
        """Calculate final score based on algorithm."""
        if self.algorithm == ImpersonationAlgorithm.SIMPLE:
            # Use highest individual score
            best_technique = max(techniques, key=lambda k: techniques[k]['score'])
            return techniques[best_technique]['score'], best_technique
        
        elif self.algorithm == ImpersonationAlgorithm.WEIGHTED:
            weights = self.config.scoring.get('weights', {})
            total_score = 0.0
            total_weight = 0.0
            best_technique = None
            best_score = 0.0
            
            for technique, data in techniques.items():
                weight = weights.get(technique, 0.25)
                total_score += data['score'] * weight
                total_weight += weight
                
                if data['score'] > best_score:
                    best_score = data['score']
                    best_technique = technique
            
            final_score = total_score / total_weight if total_weight > 0 else 0.0
            return final_score, best_technique or max(techniques, key=lambda k: techniques[k]['score'])
        
        elif self.algorithm == ImpersonationAlgorithm.THRESHOLD:
            # Binary: pass if any technique passes threshold
            for technique, data in techniques.items():
                if data['score'] >= self.config.scoring['threshold']:
                    return 1.0, technique
            return 0.0, list(techniques.keys())[0]
        
        else:
            # Default to weighted
            return self._calculate_score(techniques)[0], list(techniques.keys())[0]
    
    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """Normalize domain for comparison."""
        domain = domain.lower().strip()
        # Remove protocol
        domain = re.sub(r'^https?://', '', domain)
        # Remove www prefix
        domain = re.sub(r'^www\.', '', domain)
        # Remove port
        if ':' in domain:
            domain = domain.split(':')[0]
        # Remove trailing dot
        domain = domain.rstrip('.')
        return domain
    
    @staticmethod
    def _normalize_homoglyphs(text: str) -> str:
        """Normalize homoglyphs to ASCII equivalents."""
        # NFKD normalization
        text = unicodedata.normalize('NFKD', text)
        
        # Apply homoglyph mappings
        result = []
        for char in text:
            # Check if it's a homoglyph
            if ord(char) > 127:
                # Try to find ASCII equivalent
                try:
                    # Try NFKD decomposition
                    decomposed = unicodedata.normalize('NFKD', char)
                    base = decomposed[0] if decomposed else char
                    if ord(base) < 128:
                        result.append(base)
                    else:
                        result.append(char)
                except Exception:
                    result.append(char)
            else:
                result.append(char)
        
        return ''.join(result).lower()
    
    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if LEVENSHTEIN_AVAILABLE:
            return distance.Levenshtein.distance(s1, s2)
        
        # Fallback implementation
        if len(s1) < len(s2):
            return ImpersonationDetector._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _is_infrastructure(self, domain: str) -> bool:
        """Check if domain is known infrastructure."""
        domain_lower = domain.lower()
        return any(
            domain_lower == inf or domain_lower.endswith('.' + inf)
            for inf in self.config.infrastructure_domains
        )
    
    def _is_ignored_tld(self, domain: str) -> bool:
        """Check if domain uses ignored TLD."""
        parts = domain.lower().split('.')
        if len(parts) > 0:
            return parts[-1] in self.config.ignored_tlds
        return False
    
    @staticmethod
    def _score_to_severity(score: float) -> Severity:
        """Convert score to severity level."""
        if score >= 0.85:
            return Severity.CRITICAL
        elif score >= 0.75:
            return Severity.HIGH
        elif score >= 0.60:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _create_explanation(
        self,
        domain: str,
        brand: str,
        technique: str,
        techniques: dict
    ) -> str:
        """Create human-readable explanation."""
        if technique == 'levenshtein':
            dist = techniques[technique]['distance']
            return f"Domain '{domain}' appears to be a typo-squat of '{brand}' (edit distance: {dist})"
        
        elif technique == 'homoglyph':
            original = techniques[technique].get('original', domain)
            ascii_form = techniques[technique].get('ascii_form', '')
            return f"Domain '{domain}' contains homoglyph characters resembling '{brand}' (ASCII: '{ascii_form}')"
        
        elif technique == 'keyword_match':
            keyword = techniques[technique].get('keyword', brand)
            return f"Domain '{domain}' contains '{keyword}' but is not a legitimate {brand} domain"
        
        elif technique == 'punycode':
            decoded = techniques[technique].get('decoded', '')
            return f"Punycode domain '{domain}' decodes to '{decoded}' resembling '{brand}'"
        
        else:
            return f"Potential impersonation of '{brand}' detected in '{domain}' using {technique}"


def detect_impersonation(
    artifacts: Artifacts,
    brand_config_path: Optional[Path] = None,
    algorithm: str = "weighted",
    excluded_brands: Optional[list[str]] = None,
) -> list[ImpersonationFinding]:
    """Convenience function for impersonation detection.
    
    Args:
        artifacts: Parsed email artifacts
        brand_config_path: Optional path to custom brand configuration
        algorithm: Scoring algorithm (simple, weighted, threshold)
        excluded_brands: List of brand names to exclude from detection
    
    Returns:
        List of impersonation findings
    """
    config = BrandConfig(brand_config_path) if brand_config_path else BrandConfig()
    algo = ImpersonationAlgorithm(algorithm)
    excluded = set(excluded_brands) if excluded_brands else set()
    
    detector = ImpersonationDetector(
        brand_config=config,
        algorithm=algo,
        excluded_brands=excluded,
    )
    
    return detector.detect(artifacts)
