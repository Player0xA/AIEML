"""IO utilities for saving/loading artifacts."""

import json
from pathlib import Path
from typing import Any

from emltriage.core.models import (
    Artifacts,
    AuthenticationResults,
    IOCsExtracted,
)
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


def save_artifacts(artifacts: Artifacts, output_path: Path) -> None:
    """Save artifacts to JSON file.
    
    Args:
        artifacts: Artifacts to save
        output_path: Path to save to
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    data = artifacts.model_dump()
    output_path.write_text(
        json.dumps(data, indent=2, default=str),
        encoding="utf-8"
    )
    logger.info(f"Artifacts saved to: {output_path}")


def save_iocs(iocs: IOCsExtracted, output_path: Path) -> None:
    """Save IOCs to JSON file.
    
    Args:
        iocs: IOCs to save
        output_path: Path to save to
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    data = iocs.model_dump()
    output_path.write_text(
        json.dumps(data, indent=2, default=str),
        encoding="utf-8"
    )
    logger.info(f"IOCs saved to: {output_path}")


def save_auth_results(auth_results: AuthenticationResults, output_path: Path) -> None:
    """Save authentication results to JSON file.
    
    Args:
        auth_results: Authentication results to save
        output_path: Path to save to
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    data = auth_results.model_dump()
    output_path.write_text(
        json.dumps(data, indent=2, default=str),
        encoding="utf-8"
    )
    logger.info(f"Auth results saved to: {output_path}")


def load_artifacts(input_path: Path) -> Artifacts:
    """Load artifacts from JSON file.
    
    Args:
        input_path: Path to load from
        
    Returns:
        Artifacts object
    """
    data = json.loads(input_path.read_text(encoding="utf-8"))
    return Artifacts.model_validate(data)


def load_iocs(input_path: Path) -> IOCsExtracted:
    """Load IOCs from JSON file.
    
    Args:
        input_path: Path to load from
        
    Returns:
        IOCsExtracted object
    """
    data = json.loads(input_path.read_text(encoding="utf-8"))
    return IOCsExtracted.model_validate(data)


def load_json(input_path: Path) -> Any:
    """Load arbitrary JSON file.
    
    Args:
        input_path: Path to load from
        
    Returns:
        Parsed JSON data
    """
    return json.loads(input_path.read_text(encoding="utf-8"))
