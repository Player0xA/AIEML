"""AI analysis engine."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from emltriage.ai.models import (
    AIAction,
    AIHypothesis,
    AIObservation,
    AIProviderType,
    AIReport,
    AIReportMetadata,
    EvidenceDiscipline,
    StorylineParagraph,
    ValidationResult,
)
from emltriage.ai.providers.anthropic import AnthropicProvider
from emltriage.ai.providers.base import AIProvider
from emltriage.ai.providers.ollama import OllamaProvider
from emltriage.ai.providers.openai import OpenAIProvider
from emltriage.ai.prompts import ANALYSIS_PROMPT_TEMPLATE, SYSTEM_PROMPT, VALIDATION_FIX_PROMPT
from emltriage.ai.validators import EvidenceValidator
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class AIEngine:
    """Orchestrates AI analysis of email artifacts."""
    
    def __init__(
        self,
        provider_type: AIProviderType = AIProviderType.OLLAMA,
        model: Optional[str] = None,
        temperature: float = 0.1,
        max_retries: int = 2,
    ):
        """Initialize AI engine.
        
        Args:
            provider_type: AI provider to use
            model: Model name (provider-specific)
            temperature: Sampling temperature (lower = more deterministic)
            max_retries: Maximum retries on validation failure
        """
        self.provider_type = provider_type
        self.model = model
        self.temperature = temperature
        self.max_retries = max_retries
        self.provider = self._init_provider()
        
        logger.info(f"AI engine initialized with {provider_type.value}:{model or 'default'}")
    
    def _init_provider(self) -> AIProvider:
        """Initialize the AI provider.
        
        Returns:
            Configured AIProvider instance
        """
        if self.provider_type == AIProviderType.OLLAMA:
            return OllamaProvider(model=self.model, temperature=self.temperature)
        elif self.provider_type == AIProviderType.OPENAI:
            return OpenAIProvider(model=self.model, temperature=self.temperature)
        elif self.provider_type == AIProviderType.ANTHROPIC:
            return AnthropicProvider(model=self.model, temperature=self.temperature)
        else:
            raise ValueError(f"Unknown provider type: {self.provider_type}")
    
    def _load_json_file(self, file_path: Path) -> dict:
        """Load and parse JSON file.
        
        Args:
            file_path: Path to JSON file
            
        Returns:
            Parsed JSON as dict
        """
        try:
            return json.loads(file_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.error(f"Failed to load {file_path}: {e}")
            return {}
    
    def analyze(
        self,
        artifacts_file: Path,
        auth_results_file: Optional[Path] = None,
        cti_file: Optional[Path] = None,
        run_id: Optional[str] = None,
    ) -> AIReport:
        """Generate AI analysis report.
        
        Args:
            artifacts_file: Path to artifacts.json
            auth_results_file: Path to auth_results.json (optional)
            cti_file: Path to cti.json (optional)
            run_id: Run identifier (from artifacts if not provided)
            
        Returns:
            AIReport with analysis
        """
        # Load source data
        artifacts = self._load_json_file(artifacts_file)
        auth_results = self._load_json_file(auth_results_file) if auth_results_file else {}
        cti_data = self._load_json_file(cti_file) if cti_file else {}
        
        # Get run_id from artifacts if not provided
        if run_id is None:
            run_id = artifacts.get("metadata", {}).get("run_id", "unknown")
        
        # Prepare prompts
        user_prompt = ANALYSIS_PROMPT_TEMPLATE.format(
            artifacts_json=json.dumps(artifacts, indent=2),
            auth_results_json=json.dumps(auth_results, indent=2),
            cti_json=json.dumps(cti_data, indent=2),
        )
        
        # Generate initial report
        logger.info("Generating AI analysis report...")
        raw_response = self.provider.generate(SYSTEM_PROMPT, user_prompt)
        
        # Parse JSON response
        try:
            report_data = json.loads(raw_response)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            # Try to extract JSON from markdown
            report_data = self._extract_json_from_markdown(raw_response)
        
        # Build AIReport from parsed data
        report = self._build_report(report_data, raw_response)
        
        # Validate report
        validator = EvidenceValidator(artifacts, auth_results, cti_data)
        validation = validator.validate_report(report)
        
        # Retry on validation failure
        retries = 0
        while not validation.is_valid and retries < self.max_retries:
            logger.warning(f"Validation failed, retrying... (attempt {retries + 1})")
            
            # Generate fix prompt
            fix_prompt = VALIDATION_FIX_PROMPT.format(
                validation_errors="\n".join(validation.errors),
                original_report=raw_response,
                artifacts_summary=self._summarize_artifacts(artifacts),
            )
            
            # Re-generate
            raw_response = self.provider.generate(SYSTEM_PROMPT, fix_prompt)
            
            try:
                report_data = json.loads(raw_response)
            except json.JSONDecodeError:
                report_data = self._extract_json_from_markdown(raw_response)
            
            report = self._build_report(report_data, raw_response)
            validation = validator.validate_report(report)
            retries += 1
        
        # Build evidence discipline summary
        evidence_discipline = validator.build_evidence_discipline(report, validation)
        
        # Build metadata
        metadata = AIReportMetadata(
            run_id=run_id,
            generated_at=datetime.now(timezone.utc),
            ai_provider=self.provider.provider_string,
            model_version=self.model or "default",
            evidence_discipline=evidence_discipline,
        )
        
        # Update report with metadata
        report.metadata = metadata
        report.raw_response = raw_response if not validation.is_valid else None
        
        if not validation.is_valid:
            logger.error(f"Report validation failed after {retries} retries: {validation.errors}")
        else:
            logger.info("AI report generated and validated successfully")
        
        return report
    
    def _build_report(self, data: dict, raw_response: str) -> AIReport:
        """Build AIReport from parsed JSON data.
        
        Args:
            data: Parsed JSON data
            raw_response: Raw AI response for debugging
            
        Returns:
            AIReport object
        """
        # Parse observations
        observations = []
        for obs_data in data.get("observations", []):
            try:
                observations.append(AIObservation(**obs_data))
            except Exception as e:
                logger.warning(f"Failed to parse observation: {e}")
        
        # Parse inferences
        inferences = []
        for inf_data in data.get("inferences", []):
            try:
                inferences.append(AIHypothesis(**inf_data))
            except Exception as e:
                logger.warning(f"Failed to parse inference: {e}")
        
        # Parse actions
        actions = []
        for action_data in data.get("recommended_actions", []):
            try:
                actions.append(AIAction(**action_data))
            except Exception as e:
                logger.warning(f"Failed to parse action: {e}")
        
        # Parse storyline
        storyline = []
        for para_data in data.get("detection_storyline", []):
            try:
                storyline.append(StorylineParagraph(**para_data))
            except Exception as e:
                logger.warning(f"Failed to parse storyline paragraph: {e}")
        
        return AIReport(
            metadata=None,  # Will be set later
            observations=observations,
            inferences=inferences,
            recommended_actions=actions,
            executive_summary=data.get("executive_summary", ""),
            detection_storyline=storyline,
            technical_analysis=data.get("technical_analysis"),
            key_indicators=data.get("key_indicators", []),
            raw_response=raw_response,
        )
    
    def _extract_json_from_markdown(self, text: str) -> dict:
        """Extract JSON from markdown code blocks.
        
        Args:
            text: Text that may contain markdown JSON
            
        Returns:
            Extracted JSON as dict
        """
        import re
        
        # Look for JSON in code blocks
        json_pattern = re.compile(r'```(?:json)?\s*(\{.*?\})\s*```', re.DOTALL)
        match = json_pattern.search(text)
        
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        
        # Look for any JSON-like structure
        try:
            # Find first { and last }
            start = text.find('{')
            end = text.rfind('}')
            if start != -1 and end != -1 and end > start:
                return json.loads(text[start:end+1])
        except json.JSONDecodeError:
            pass
        
        # Return minimal valid structure
        logger.error("Could not extract JSON from response")
        return {
            "executive_summary": "Error: Could not parse AI response",
            "observations": [],
            "inferences": [],
            "recommended_actions": [],
            "detection_storyline": [],
        }
    
    def _summarize_artifacts(self, artifacts: dict) -> str:
        """Create brief summary of artifacts for fix prompt.
        
        Args:
            artifacts: Artifacts dict
            
        Returns:
            Summary string
        """
        lines = []
        
        meta = artifacts.get("metadata", {})
        lines.append(f"Run ID: {meta.get('run_id', 'unknown')}")
        lines.append(f"Input: {meta.get('input_filename', 'unknown')}")
        
        headers = artifacts.get("headers", [])
        for h in headers:
            if h.get("name", "").lower() in ["from", "to", "subject"]:
                lines.append(f"{h.get('name')}: {h.get('raw_value', '')[:100]}")
        
        risk = artifacts.get("risk", {})
        lines.append(f"Risk Score: {risk.get('score', 'N/A')}/100 ({risk.get('severity', 'N/A')})")
        
        return "\n".join(lines)
    
    def generate_markdown(self, report: AIReport) -> str:
        """Generate Markdown report from AI analysis.
        
        Args:
            report: AIReport object
            
        Returns:
            Markdown formatted report
        """
        lines = []
        
        # Header
        lines.append("# AI-Assisted Email Analysis Report")
        lines.append("")
        lines.append("## ⚠️ DISCLAIMER")
        lines.append("")
        lines.append(report.metadata.disclaimer)
        lines.append("")
        
        # Evidence discipline
        ed = report.metadata.evidence_discipline
        lines.append("## Evidence Discipline")
        lines.append("")
        if ed.validation_passed:
            lines.append("✅ **Validation Passed**: All claims backed by evidence references")
        else:
            lines.append("⚠️ **Validation Issues Detected**")
            lines.append("")
            if ed.violations:
                lines.append("**Violations:**")
                for v in ed.violations:
                    lines.append(f"- {v}")
        lines.append("")
        
        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(report.executive_summary)
        lines.append("")
        
        # Observations
        if report.observations:
            lines.append("## Factual Observations")
            lines.append("")
            for i, obs in enumerate(report.observations):
                lines.append(f"### {i+1}. {obs.category.title()}: {obs.finding[:60]}...")
                lines.append("")
                lines.append(f"**Finding:** {obs.finding}")
                lines.append(f"**Severity:** {obs.severity}")
                lines.append(f"**Confidence:** {obs.confidence:.0%}")
                lines.append(f"**Evidence:** {', '.join(obs.evidence_refs)}")
                if obs.details:
                    lines.append(f"**Details:** {obs.details}")
                lines.append("")
        
        # Inferences
        if report.inferences:
            lines.append("## Inferences & Hypotheses")
            lines.append("")
            lines.append("*These are AI-generated hypotheses requiring human validation:*")
            lines.append("")
            
            for i, inf in enumerate(report.inferences):
                lines.append(f"### Hypothesis {i+1} (Confidence: {inf.confidence:.0%})")
                lines.append("")
                lines.append(inf.hypothesis)
                lines.append("")
                lines.append(f"**Supporting Evidence:** {', '.join(inf.evidence_refs)}")
                if inf.mitigating_factors:
                    lines.append(f"**Counter-Evidence:** {', '.join(inf.mitigating_factors)}")
                if inf.testable_predictions:
                    lines.append("**Testable Predictions:**")
                    for pred in inf.testable_predictions:
                        lines.append(f"- {pred}")
                lines.append("")
        
        # Actions
        if report.recommended_actions:
            lines.append("## Recommended Actions")
            lines.append("")
            
            # Sort by priority
            sorted_actions = sorted(report.recommended_actions, key=lambda x: x.priority)
            
            for i, action in enumerate(sorted_actions):
                lines.append(f"### Priority {action.priority}: {action.action[:50]}...")
                lines.append("")
                lines.append(f"**Action:** {action.action}")
                lines.append(f"**Rationale:** {action.rationale}")
                lines.append(f"**Category:** {action.category}")
                lines.append(f"**Evidence:** {', '.join(action.evidence_refs)}")
                if action.estimated_effort:
                    lines.append(f"**Effort:** {action.estimated_effort}")
                lines.append("")
        
        # Detection Storyline
        if report.detection_storyline:
            lines.append("## Detection Storyline")
            lines.append("")
            for para in report.detection_storyline:
                lines.append(para.text)
                lines.append("")
                lines.append(f"*Evidence: {', '.join(para.evidence_refs)}*")
                lines.append("")
        
        # Key Indicators
        if report.key_indicators:
            lines.append("## Key Indicators of Compromise")
            lines.append("")
            lines.append("| IOC | Type | Context | CTI Score |")
            lines.append("|-----|------|---------|-----------|")
            for ioc in report.key_indicators:
                score = ioc.get("cti_score", "N/A")
                lines.append(f"| {ioc.get('ioc', 'N/A')} | {ioc.get('ioc_type', 'N/A')} | "
                           f"{ioc.get('context', 'N/A')[:50]}... | {score} |")
            lines.append("")
        
        # Technical Analysis
        if report.technical_analysis:
            lines.append("## Technical Analysis")
            lines.append("")
            lines.append(report.technical_analysis)
            lines.append("")
        
        # Footer
        lines.append("---")
        lines.append("")
        lines.append(f"*Generated: {report.metadata.generated_at.isoformat()}*")
        lines.append(f"*AI Provider: {report.metadata.ai_provider}*")
        lines.append(f"*Run ID: {report.metadata.run_id}*")
        
        return "\n".join(lines)
