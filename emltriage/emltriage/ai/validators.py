"""Evidence validation for AI reports."""

import json
import re
from typing import Any, Optional

from emltriage.ai.models import (
    AIAction,
    AIHypothesis,
    AIObservation,
    AIReport,
    EvidenceDiscipline,
    StorylineParagraph,
    ValidationResult,
)
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class EvidenceValidator:
    """Validates AI-generated reports for evidence discipline."""
    
    def __init__(self, artifacts: dict, auth_results: Optional[dict] = None, cti_data: Optional[dict] = None):
        """Initialize validator with source data.
        
        Args:
            artifacts: Parsed artifacts.json as dict
            auth_results: Parsed auth_results.json as dict (optional)
            cti_data: Parsed cti.json as dict (optional)
        """
        self.artifacts = artifacts
        self.auth_results = auth_results or {}
        self.cti_data = cti_data or {}
        
        # Build evidence path index
        self._valid_paths = self._build_path_index()
        
        # Extract all IOCs for hallucination detection
        self._extracted_iocs = self._extract_all_iocs()
    
    def _build_path_index(self) -> set[str]:
        """Build set of valid evidence reference paths.
        
        Returns:
            Set of valid dot-notation paths
        """
        paths = set()
        
        # Add paths from artifacts
        self._index_dict(self.artifacts, "artifacts", paths)
        
        # Add paths from auth_results
        if self.auth_results:
            self._index_dict(self.auth_results, "auth_results", paths)
        
        # Add paths from cti_data
        if self.cti_data:
            self._index_dict(self.cti_data, "cti", paths)
        
        return paths
    
    def _index_dict(self, data: Any, prefix: str, paths: set, max_depth: int = 5) -> None:
        """Recursively index dictionary paths.
        
        Args:
            data: Data to index
            prefix: Current path prefix
            paths: Set to add paths to
            max_depth: Maximum recursion depth
        """
        if max_depth <= 0:
            return
        
        paths.add(prefix)
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_prefix = f"{prefix}.{key}"
                paths.add(new_prefix)
                self._index_dict(value, new_prefix, paths, max_depth - 1)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_prefix = f"{prefix}.{i}"
                paths.add(new_prefix)
                self._index_dict(item, new_prefix, paths, max_depth - 1)
    
    def _extract_all_iocs(self) -> set[str]:
        """Extract all IOC values from artifacts for hallucination detection.
        
        Returns:
            Set of IOC values (lowercased)
        """
        iocs = set()
        
        # Extract from artifacts.iocs
        for ioc_list in ["domains", "ips", "emails", "urls", "hashes", "filenames"]:
            for ioc in self.artifacts.get("iocs", {}).get(ioc_list, []):
                if isinstance(ioc, dict):
                    value = ioc.get("value", "")
                    if value:
                        iocs.add(value.lower())
        
        # Extract from extracted domains list
        for domain in self.artifacts.get("iocs", {}).get("domains", []):
            if isinstance(domain, dict):
                value = domain.get("value", "")
                if value:
                    iocs.add(value.lower())
        
        return iocs
    
    def validate_report(self, report: AIReport) -> ValidationResult:
        """Validate AI report for evidence discipline.
        
        Args:
            report: AI-generated report
            
        Returns:
            ValidationResult with pass/fail and errors
        """
        errors = []
        warnings = []
        all_refs = []
        
        # Validate observations
        for i, obs in enumerate(report.observations):
            if not obs.evidence_refs:
                errors.append(f"Observation {i} ('{obs.finding[:50]}...') missing evidence_refs")
            else:
                all_refs.extend(obs.evidence_refs)
                for ref in obs.evidence_refs:
                    if not self._is_valid_ref(ref):
                        errors.append(f"Observation {i} has invalid ref: {ref}")
        
        # Validate inferences
        for i, inf in enumerate(report.inferences):
            if not inf.evidence_refs:
                warnings.append(f"Inference {i} missing evidence_refs (should have supporting evidence)")
            else:
                all_refs.extend(inf.evidence_refs)
                for ref in inf.evidence_refs:
                    if not self._is_valid_ref(ref):
                        errors.append(f"Inference {i} has invalid ref: {ref}")
        
        # Validate actions
        for i, action in enumerate(report.recommended_actions):
            if not action.evidence_refs:
                errors.append(f"Action {i} ('{action.action[:50]}...') missing evidence_refs")
            else:
                all_refs.extend(action.evidence_refs)
                for ref in action.evidence_refs:
                    if not self._is_valid_ref(ref):
                        errors.append(f"Action {i} has invalid ref: {ref}")
        
        # Validate storyline paragraphs
        for i, para in enumerate(report.detection_storyline):
            if not para.evidence_refs:
                warnings.append(f"Storyline paragraph {i} missing evidence_refs")
            else:
                all_refs.extend(para.evidence_refs)
                for ref in para.evidence_refs:
                    if not self._is_valid_ref(ref):
                        errors.append(f"Storyline para {i} has invalid ref: {ref}")
        
        # Check for hallucinated IOCs in report text
        hallucinated = self._detect_hallucinated_iocs(report)
        if hallucinated:
            errors.append(f"Hallucinated IOCs detected: {', '.join(hallucinated[:5])}")
        
        # Check if executive summary is reasonable length
        if len(report.executive_summary) > 500:
            warnings.append("Executive summary is very long (>500 chars)")
        
        is_valid = len(errors) == 0
        
        return ValidationResult(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            evidence_citation_count=len(all_refs),
            unique_evidence_refs=len(set(all_refs)),
        )
    
    def _is_valid_ref(self, ref: str) -> bool:
        """Check if evidence reference is valid.
        
        Args:
            ref: Evidence reference path
            
        Returns:
            True if valid
        """
        # Direct match
        if ref in self._valid_paths:
            return True
        
        # Check if it's a valid prefix to something
        for valid_path in self._valid_paths:
            if valid_path.startswith(ref + ".") or valid_path == ref:
                return True
        
        return False
    
    def _detect_hallucinated_iocs(self, report: AIReport) -> list[str]:
        """Detect IOCs in report that weren't in the original artifacts.
        
        Args:
            report: AI report
            
        Returns:
            List of hallucinated IOCs
        """
        hallucinated = []
        
        # Combine all text from report
        all_text = ""
        all_text += report.executive_summary + " "
        for para in report.detection_storyline:
            all_text += para.text + " "
        
        # Look for domain patterns
        domain_pattern = re.compile(r'\b[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.[A-Za-z]{2,}\b')
        found_domains = domain_pattern.findall(all_text)
        
        for domain in found_domains:
            # Check if domain was in extracted IOCs
            if domain.lower() not in self._extracted_iocs:
                # Also check if it's a common legitimate domain
                if not self._is_common_domain(domain):
                    hallucinated.append(domain)
        
        # Look for IP patterns
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        found_ips = ip_pattern.findall(all_text)
        
        for ip in found_ips:
            if ip not in self._extracted_iocs:
                hallucinated.append(ip)
        
        return list(set(hallucinated))  # Remove duplicates
    
    def _is_common_domain(self, domain: str) -> bool:
        """Check if domain is a common legitimate domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            True if common legitimate domain
        """
        common_domains = {
            "example.com", "test.com", "localhost", "microsoft.com",
            "google.com", "apple.com", "amazon.com", "github.com",
            "outlook.com", "office365.com", "gmail.com", "yahoo.com",
        }
        return domain.lower() in common_domains
    
    def build_evidence_discipline(self, report: AIReport, validation: ValidationResult) -> EvidenceDiscipline:
        """Build evidence discipline summary from validation.
        
        Args:
            report: AI report
            validation: Validation result
            
        Returns:
            EvidenceDiscipline object
        """
        uncited = []
        invalid_refs = []
        
        # Collect uncited claims and invalid refs from validation errors
        for error in validation.errors:
            if "missing evidence_refs" in error:
                uncited.append({"claim": error, "location": "unknown"})
            elif "invalid ref" in error:
                ref = error.split(": ")[-1] if ": " in error else ""
                invalid_refs.append({"ref": ref, "context": error})
        
        hallucinated = self._detect_hallucinated_iocs(report)
        
        return EvidenceDiscipline(
            validation_passed=validation.is_valid,
            all_claims_cited=len(uncited) == 0,
            uncited_claims=uncited,
            invalid_refs=invalid_refs,
            hallucinated_iocs=hallucinated,
            violations=validation.errors,
        )
