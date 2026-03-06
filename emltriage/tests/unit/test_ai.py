"""Unit tests for AI module."""

import json
import pytest
from pathlib import Path
from datetime import datetime, timezone

from emltriage.ai.models import (
    AIAction,
    AIHypothesis,
    AIObservation,
    AIProviderType,
    AIReport,
    AIReportMetadata,
    EvidenceDiscipline,
    StorylineParagraph,
)
from emltriage.ai.validators import EvidenceValidator


class MockArtifacts:
    """Helper to create mock artifact data."""
    
    @staticmethod
    def create_basic_artifacts():
        return {
            "metadata": {
                "run_id": "test-123",
                "input_filename": "test.eml",
            },
            "headers": [
                {"name": "From", "raw_value": "sender@example.com"},
                {"name": "To", "raw_value": "recipient@example.com"},
                {"name": "Subject", "raw_value": "Test Email"},
            ],
            "iocs": {
                "domains": [{"value": "example.com"}, {"value": "suspicious.com"}],
                "ips": [{"value": "192.168.1.1"}],
            },
            "risk": {"score": 30, "severity": "medium"},
        }


class TestEvidenceValidator:
    """Test evidence validation."""
    
    def test_valid_observation(self):
        """Test validation with valid observation."""
        artifacts = MockArtifacts.create_basic_artifacts()
        validator = EvidenceValidator(artifacts)
        
        report = AIReport(
            metadata=AIReportMetadata(
                run_id="test-123",
                generated_at=datetime.now(timezone.utc),
                ai_provider="test",
                model_version="1.0",
                evidence_discipline=EvidenceDiscipline(
                    validation_passed=True,
                    all_claims_cited=True,
                ),
            ),
            observations=[
                AIObservation(
                    category="headers",
                    finding="From header contains example.com",
                    severity="info",
                    evidence_refs=["headers.From"],
                    confidence=1.0,
                )
            ],
            inferences=[],
            recommended_actions=[],
            executive_summary="Test",
            detection_storyline=[],
        )
        
        validation = validator.validate_report(report)
        assert validation.is_valid
        assert len(validation.errors) == 0
    
    def test_missing_evidence_ref(self):
        """Test detection of missing evidence reference."""
        artifacts = MockArtifacts.create_basic_artifacts()
        validator = EvidenceValidator(artifacts)
        
        report = AIReport(
            metadata=AIReportMetadata(
                run_id="test-123",
                generated_at=datetime.now(timezone.utc),
                ai_provider="test",
                model_version="1.0",
                evidence_discipline=EvidenceDiscipline(
                    validation_passed=False,
                    all_claims_cited=False,
                ),
            ),
            observations=[
                AIObservation(
                    category="headers",
                    finding="Missing evidence",
                    severity="info",
                    evidence_refs=[],  # Missing refs
                    confidence=1.0,
                )
            ],
            inferences=[],
            recommended_actions=[],
            executive_summary="Test",
            detection_storyline=[],
        )
        
        validation = validator.validate_report(report)
        assert not validation.is_valid
        assert any("missing evidence_refs" in e for e in validation.errors)
    
    def test_invalid_evidence_ref(self):
        """Test detection of invalid evidence reference."""
        artifacts = MockArtifacts.create_basic_artifacts()
        validator = EvidenceValidator(artifacts)
        
        report = AIReport(
            metadata=AIReportMetadata(
                run_id="test-123",
                generated_at=datetime.now(timezone.utc),
                ai_provider="test",
                model_version="1.0",
                evidence_discipline=EvidenceDiscipline(
                    validation_passed=False,
                    all_claims_cited=False,
                ),
            ),
            observations=[
                AIObservation(
                    category="headers",
                    finding="Test finding",
                    severity="info",
                    evidence_refs=["headers.NonExistent"],  # Invalid path
                    confidence=1.0,
                )
            ],
            inferences=[],
            recommended_actions=[],
            executive_summary="Test",
            detection_storyline=[],
        )
        
        validation = validator.validate_report(report)
        assert not validation.is_valid
        assert any("invalid ref" in e.lower() for e in validation.errors)
    
    def test_hallucination_detection(self):
        """Test detection of hallucinated IOCs."""
        artifacts = MockArtifacts.create_basic_artifacts()
        validator = EvidenceValidator(artifacts)
        
        report = AIReport(
            metadata=AIReportMetadata(
                run_id="test-123",
                generated_at=datetime.now(timezone.utc),
                ai_provider="test",
                model_version="1.0",
                evidence_discipline=EvidenceDiscipline(
                    validation_passed=False,
                    all_claims_cited=False,
                ),
            ),
            observations=[
                AIObservation(
                    category="iocs",
                    finding="Suspicious domain evil.com found",  # Not in artifacts
                    severity="high",
                    evidence_refs=["iocs.domains.99"],
                    confidence=0.9,
                )
            ],
            inferences=[],
            recommended_actions=[],
            executive_summary="Test with evil.com domain",  # Hallucinated
            detection_storyline=[
                StorylineParagraph(
                    paragraph_number=1,
                    text="We found evil.com which is malicious.",
                    evidence_refs=["iocs.domains.99"],
                )
            ],
        )
        
        validation = validator.validate_report(report)
        # Should detect hallucinated domain
        hallucinated = validator._detect_hallucinated_iocs(report)
        assert "evil.com" in hallucinated


class TestAIModels:
    """Test AI data models."""
    
    def test_ai_observation_creation(self):
        """Test AIObservation model."""
        obs = AIObservation(
            category="authentication",
            finding="DKIM failed",
            severity="high",
            evidence_refs=["auth_results.dkim.0.result"],
            confidence=1.0,
            details="DKIM signature verification returned fail",
        )
        
        assert obs.category == "authentication"
        assert obs.severity == "high"
        assert obs.confidence == 1.0
        assert len(obs.evidence_refs) == 1
    
    def test_ai_hypothesis_creation(self):
        """Test AIHypothesis model."""
        hyp = AIHypothesis(
            hypothesis="Email likely spoofed",
            confidence=0.85,
            evidence_refs=["headers.From", "auth_results.dkim.0.result"],
            mitigating_factors=["Valid SPF record"],
            testable_predictions=["Check envelope sender"],
        )
        
        assert hyp.confidence == 0.85
        assert len(hyp.mitigating_factors) == 1
    
    def test_ai_action_creation(self):
        """Test AIAction model."""
        action = AIAction(
            priority=1,
            action="Block sender domain",
            rationale="Domain has failed authentication",
            evidence_refs=["auth_results.spf.0.result"],
            category="containment",
            estimated_effort="low",
        )
        
        assert action.priority == 1
        assert action.category == "containment"
        assert action.estimated_effort == "low"


class TestAIReport:
    """Test AIReport model."""
    
    def test_report_serialization(self):
        """Test report JSON serialization."""
        report = AIReport(
            metadata=AIReportMetadata(
                run_id="test-123",
                generated_at=datetime.now(timezone.utc),
                ai_provider="ollama:llama3.1",
                model_version="llama3.1",
                evidence_discipline=EvidenceDiscipline(
                    validation_passed=True,
                    all_claims_cited=True,
                ),
            ),
            executive_summary="Test summary",
            observations=[],
            inferences=[],
            recommended_actions=[],
            detection_storyline=[],
        )
        
        # Should serialize to JSON
        data = report.model_dump()
        assert data["metadata"]["run_id"] == "test-123"
        assert data["executive_summary"] == "Test summary"
