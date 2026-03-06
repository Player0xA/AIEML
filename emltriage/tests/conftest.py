"""Test configuration and fixtures."""

import pytest
from pathlib import Path


@pytest.fixture
def sample_eml_path() -> Path:
    """Path to sample EML file."""
    return Path(__file__).parent / "fixtures" / "sample_emails" / "test_email.eml"


@pytest.fixture
def test_output_dir(tmp_path: Path) -> Path:
    """Temporary output directory for tests."""
    return tmp_path
