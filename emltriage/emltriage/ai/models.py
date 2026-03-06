"""AI module schemas and data models."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class AIProviderType(str, Enum):
    """Types of AI providers."""
    
    OLLAMA = "ollama"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class EvidenceDiscipline(BaseModel):
    """Evidence discipline validation results."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    validation_passed: bool = Field(..., description="Whether validation passed")
    all_claims_cited: bool = Field(..., description="Whether all claims have evidence refs")
    uncited_claims: list[dict[str, Any]] = Field(
        default_factory=list, description="Claims without evidence references"
    )
    invalid_refs: list[dict[str, Any]] = Field(
        default_factory=list, description="Evidence refs that don't exist in artifacts"
    )
    hallucinated_iocs: list[str] = Field(
        default_factory=list, description="IOCs in report not in extracted data"
    )
    violations: list[str] = Field(default_factory=list, description="List of violation descriptions")


class AIObservation(BaseModel):
    """Single observation from AI analysis."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    category: str = Field(..., description="Observation category (e.g., authentication, routing)")
    finding: str = Field(..., description="The observation text")
    severity: str = Field(..., description="Severity: info, low, medium, high, critical")
    evidence_refs: list[str] = Field(
        ..., description="Evidence references (paths in artifacts.json)"
    )
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in observation")
    details: Optional[str] = Field(None, description="Additional details")


class AIHypothesis(BaseModel):
    """Hypothesis/inference from AI analysis."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    hypothesis: str = Field(..., description="The hypothesis statement")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence level")
    evidence_refs: list[str] = Field(
        ..., description="Evidence supporting this hypothesis"
    )
    mitigating_factors: list[str] = Field(
        default_factory=list, description="Factors that could disprove the hypothesis"
    )
    testable_predictions: list[str] = Field(
        default_factory=list, description="Predictions that would validate this"
    )


class AIAction(BaseModel):
    """Recommended action from AI analysis."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    priority: int = Field(..., ge=1, le=5, description="Priority (1 = highest)")
    action: str = Field(..., description="The recommended action")
    rationale: str = Field(..., description="Why this action is recommended")
    evidence_refs: list[str] = Field(..., description="Evidence supporting this action")
    category: str = Field(default="general", description="Action category")
    estimated_effort: Optional[str] = Field(None, description="Estimated effort (low/medium/high)")


class StorylineParagraph(BaseModel):
    """Single paragraph in detection storyline."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    paragraph_number: int = Field(..., description="Paragraph number in sequence")
    text: str = Field(..., description="Paragraph text")
    evidence_refs: list[str] = Field(
        ..., description="Evidence references cited in this paragraph"
    )
    key_finding: Optional[str] = Field(None, description="Key finding in this paragraph")


class ValidationResult(BaseModel):
    """Result of evidence validation."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    is_valid: bool = Field(..., description="Whether the report passes validation")
    errors: list[str] = Field(default_factory=list, description="Validation errors")
    warnings: list[str] = Field(default_factory=list, description="Validation warnings")
    evidence_citation_count: int = Field(default=0, description="Total evidence citations")
    unique_evidence_refs: int = Field(default=0, description="Unique evidence references used")


class AIReportMetadata(BaseModel):
    """Metadata for AI-generated report."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    run_id: str = Field(..., description="Run identifier (matches artifacts)")
    generated_at: datetime = Field(..., description="Generation timestamp (UTC)")
    ai_provider: str = Field(..., description="AI provider used (e.g., 'ollama:llama3.1')")
    model_version: str = Field(..., description="Model version/identifier")
    prompt_version: str = Field(default="1.0", description="Prompt template version")
    evidence_discipline: EvidenceDiscipline = Field(..., description="Validation results")
    disclaimer: str = Field(
        default="This is an AI-generated report and should be used as an analytical aid only. "
                "All claims are backed by evidence references that can be verified in the artifacts. "
                "This report is NON-AUTHORITATIVE and does not replace human analysis.",
        description="AI report disclaimer"
    )


class AIReport(BaseModel):
    """Complete AI-generated narrative report."""
    
    model_config = ConfigDict(populate_by_name=True)
    
    metadata: AIReportMetadata = Field(..., description="Report metadata")
    
    # Structured analysis
    observations: list[AIObservation] = Field(
        default_factory=list, description="Factual observations from artifacts"
    )
    inferences: list[AIHypothesis] = Field(
        default_factory=list, description="Inferences and hypotheses (clearly labeled)"
    )
    recommended_actions: list[AIAction] = Field(
        default_factory=list, description="Prioritized recommended actions"
    )
    
    # Narrative
    executive_summary: str = Field(..., description="High-level executive summary")
    detection_storyline: list[StorylineParagraph] = Field(
        default_factory=list, description="Detection narrative by paragraph"
    )
    technical_analysis: Optional[str] = Field(None, description="Technical deep-dive")
    
    # Context
    key_indicators: list[dict[str, Any]] = Field(
        default_factory=list, description="Key IOCs with context"
    )
    
    # Raw for debugging
    raw_response: Optional[str] = Field(None, description="Raw AI response (for debugging)")
