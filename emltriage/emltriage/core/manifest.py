"""Manifest generation and file hashing."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from emltriage.core.models import FileManifestEntry, Manifest
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


def compute_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """Compute hash of file.
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Hex digest
    """
    if algorithm == "md5":
        hasher = hashlib.md5()
    elif algorithm == "sha1":
        hasher = hashlib.sha1()
    else:
        hasher = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    
    return hasher.hexdigest()


def get_file_info(file_path: Path, content_type: Optional[str] = None) -> FileManifestEntry:
    """Get file information for manifest.
    
    Args:
        file_path: Path to file
        content_type: Optional content type
        
    Returns:
        FileManifestEntry
    """
    return FileManifestEntry(
        path=str(file_path),
        sha256=compute_file_hash(file_path, "sha256"),
        size=file_path.stat().st_size,
        content_type=content_type,
    )


def create_manifest(
    run_id: str,
    input_file: Path,
    output_dir: Path,
    parameters: dict,
    files_to_include: Optional[list[Path]] = None,
) -> Manifest:
    """Create manifest for analysis run.
    
    Args:
        run_id: Unique run identifier
        input_file: Input EML file
        output_dir: Output directory
        parameters: Analysis parameters
        files_to_include: Additional files to include in manifest
        
    Returns:
        Manifest object
    """
    # Input file entry
    input_entry = get_file_info(input_file)
    
    # Output files
    output_entries = []
    
    # Always include core output files if they exist
    core_files = [
        output_dir / "artifacts.json",
        output_dir / "iocs.json",
        output_dir / "auth_results.json",
        output_dir / "report.md",
    ]
    
    for file_path in core_files:
        if file_path.exists():
            output_entries.append(get_file_info(file_path))
    
    # Include additional files
    if files_to_include:
        for file_path in files_to_include:
            if file_path.exists() and file_path not in core_files:
                output_entries.append(get_file_info(file_path))
    
    # Include all files in attachments directory
    attachments_dir = output_dir / "attachments"
    if attachments_dir.exists():
        for att_file in attachments_dir.iterdir():
            if att_file.is_file():
                output_entries.append(get_file_info(att_file))
    
    # Include body files
    for body_file in output_dir.glob("body_*"):
        if body_file.is_file():
            output_entries.append(get_file_info(body_file))
    
    manifest = Manifest(
        run_id=run_id,
        timestamp=datetime.now(timezone.utc),
        tool_version="0.1.0",
        input_file=input_entry,
        output_files=output_entries,
        parameters=parameters,
    )
    
    # Write manifest to file
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest.model_dump(), indent=2, default=str),
        encoding="utf-8"
    )
    
    logger.info(f"Manifest created: {manifest_path}")
    
    return manifest
