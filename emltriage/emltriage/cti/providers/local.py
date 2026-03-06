"""Local intelligence provider for CSV/JSON watchlists."""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from emltriage.core.models import IOCType
from emltriage.cti.models import (
    CTIProviderType,
    CTIResult,
    EnrichmentStatus,
    LocalIntelConfig,
    LocalIntelEntry,
    ProviderConfig,
)
from emltriage.cti.providers.base import CTIProvider
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class LocalIntelProvider(CTIProvider):
    """Provider for local intelligence files (CSV/JSON watchlists)."""
    
    # Map of supported IOC types
    SUPPORTED_TYPES = [
        IOCType.DOMAIN,
        IOCType.IP,
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.EMAIL,
        IOCType.URL,
        IOCType.HASH_MD5,
        IOCType.HASH_SHA1,
        IOCType.HASH_SHA256,
        IOCType.FILENAME,
    ]
    
    def __init__(self, config: ProviderConfig, intel_config: Optional[LocalIntelConfig] = None):
        """Initialize with provider and intel configuration.
        
        Args:
            config: Provider configuration
            intel_config: Intel file configuration
        """
        super().__init__(config)
        self.intel_config = intel_config or LocalIntelConfig()
        self._entries: list[LocalIntelEntry] = []
        self._loaded = False
        
    @property
    def provider_type(self) -> CTIProviderType:
        """Return provider type."""
        return CTIProviderType.LOCAL
    
    @property
    def supported_ioc_types(self) -> list[IOCType]:
        """Return supported IOC types."""
        return self.SUPPORTED_TYPES
    
    def _ensure_loaded(self) -> None:
        """Ensure intel files are loaded."""
        if not self._loaded and self.intel_config.enabled:
            self._load_intel_files()
            self._loaded = True
    
    def _load_intel_files(self) -> None:
        """Load all configured intel files."""
        # Load from directories
        for watch_dir in self.intel_config.watchlist_dirs:
            dir_path = Path(watch_dir)
            if dir_path.exists() and dir_path.is_dir():
                for file_path in dir_path.glob("**/*"):
                    if file_path.suffix.lower() in ['.csv', '.json', '.jsonl']:
                        self._load_file(file_path)
        
        # Load specific files
        for file_path in self.intel_config.watchlist_files:
            self._load_file(Path(file_path))
    
    def _load_file(self, file_path: Path) -> None:
        """Load a single intel file.
        
        Args:
            file_path: Path to CSV or JSON file
        """
        if not file_path.exists():
            logger.warning(f"Intel file not found: {file_path}")
            return
        
        try:
            suffix = file_path.suffix.lower()
            
            if suffix == '.csv':
                self._load_csv(file_path)
            elif suffix == '.json':
                self._load_json(file_path)
            elif suffix == '.jsonl':
                self._load_jsonl(file_path)
            else:
                logger.warning(f"Unsupported file type: {file_path}")
        
        except Exception as e:
            logger.error(f"Error loading intel file {file_path}: {e}")
    
    def _load_csv(self, file_path: Path) -> None:
        """Load CSV intel file.
        
        Expected columns: ioc, ioc_type, list_type, [description], [tags], [confidence]
        
        Args:
            file_path: Path to CSV file
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                try:
                    entry = LocalIntelEntry(
                        ioc=row['ioc'].strip(),
                        ioc_type=IOCType(row['ioc_type'].strip().lower()),
                        list_type=row['list_type'].strip().lower(),
                        source_file=str(file_path),
                        description=row.get('description'),
                        tags=row.get('tags', '').split(',') if row.get('tags') else [],
                        confidence=float(row.get('confidence', 1.0)),
                        added_date=datetime.now(timezone.utc),
                    )
                    self._entries.append(entry)
                except (KeyError, ValueError) as e:
                    logger.warning(f"Skipping invalid row in {file_path}: {e}")
        
        logger.info(f"Loaded {len(self._entries)} entries from {file_path}")
    
    def _load_json(self, file_path: Path) -> None:
        """Load JSON intel file.
        
        Args:
            file_path: Path to JSON file
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if isinstance(data, list):
            for item in data:
                try:
                    entry = LocalIntelEntry(
                        ioc=item['ioc'],
                        ioc_type=IOCType(item['ioc_type'].lower()),
                        list_type=item.get('list_type', 'watchlist').lower(),
                        source_file=str(file_path),
                        description=item.get('description'),
                        tags=item.get('tags', []),
                        confidence=item.get('confidence', 1.0),
                        added_date=datetime.now(timezone.utc),
                    )
                    self._entries.append(entry)
                except (KeyError, ValueError) as e:
                    logger.warning(f"Skipping invalid entry in {file_path}: {e}")
        
        logger.info(f"Loaded {len(self._entries)} entries from {file_path}")
    
    def _load_jsonl(self, file_path: Path) -> None:
        """Load JSONL intel file.
        
        Args:
            file_path: Path to JSONL file
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    item = json.loads(line)
                    entry = LocalIntelEntry(
                        ioc=item['ioc'],
                        ioc_type=IOCType(item['ioc_type'].lower()),
                        list_type=item.get('list_type', 'watchlist').lower(),
                        source_file=str(file_path),
                        description=item.get('description'),
                        tags=item.get('tags', []),
                        confidence=item.get('confidence', 1.0),
                        added_date=datetime.now(timezone.utc),
                    )
                    self._entries.append(entry)
                except (KeyError, ValueError, json.JSONDecodeError) as e:
                    logger.warning(f"Skipping invalid entry in {file_path}: {e}")
        
        logger.info(f"Loaded {len(self._entries)} entries from {file_path}")
    
    def lookup(self, ioc: str, ioc_type: IOCType) -> CTIResult:
        """Look up IOC in local intelligence files.
        
        Args:
            ioc: The IOC to look up
            ioc_type: Type of IOC
            
        Returns:
            CTIResult with match information if found
        """
        self._ensure_loaded()
        
        # Normalize for comparison
        lookup_value = ioc.lower() if not self.intel_config.case_sensitive else ioc
        
        # Find matching entries
        matches = []
        for entry in self._entries:
            entry_value = entry.ioc.lower() if not self.intel_config.case_sensitive else entry.ioc
            
            # Check for exact match or type-compatible match
            if entry_value == lookup_value:
                if entry.ioc_type == ioc_type or self._types_compatible(entry.ioc_type, ioc_type):
                    matches.append(entry)
        
        if matches:
            # Combine all matches into result
            all_tags = []
            all_categories = []
            min_confidence = 1.0
            descriptions = []
            
            for match in matches:
                all_tags.extend(match.tags)
                all_categories.append(match.list_type)
                min_confidence = min(min_confidence, match.confidence)
                if match.description:
                    descriptions.append(f"[{match.list_type}] {match.description}")
            
            # Determine malicious score based on list type
            malicious_score = 0
            if 'blocklist' in all_categories:
                malicious_score = 100
            elif 'watchlist' in all_categories:
                malicious_score = 50
            elif 'allowlist' in all_categories:
                malicious_score = 0
            
            return self._create_success_result(
                ioc=ioc,
                ioc_type=ioc_type,
                malicious_score=malicious_score,
                confidence=min_confidence,
                tags=list(set(all_tags)),
                categories=list(set(all_categories)),
                raw_data={
                    "match_count": len(matches),
                    "sources": [m.source_file for m in matches],
                    "descriptions": descriptions,
                },
            )
        
        # No match found
        return self._create_success_result(
            ioc=ioc,
            ioc_type=ioc_type,
            malicious_score=0,
            confidence=1.0,
            tags=[],
            categories=["no_match"],
            raw_data={"match_count": 0},
        )
    
    def _types_compatible(self, type1: IOCType, type2: IOCType) -> bool:
        """Check if two IOC types are compatible for matching.
        
        Args:
            type1: First type
            type2: Second type
            
        Returns:
            True if types are compatible
        """
        # IP types are compatible
        ip_types = {IOCType.IP, IOCType.IPV4, IOCType.IPV6}
        if type1 in ip_types and type2 in ip_types:
            return True
        
        # Hash types are compatible
        hash_types = {IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256}
        if type1 in hash_types and type2 in hash_types:
            return True
        
        return type1 == type2
    
    def get_loaded_entries_count(self) -> int:
        """Get number of loaded entries.
        
        Returns:
            Number of entries in memory
        """
        self._ensure_loaded()
        return len(self._entries)
    
    def reload(self) -> None:
        """Reload all intel files."""
        self._entries = []
        self._loaded = False
        self._ensure_loaded()
        logger.info("Reloaded local intelligence files")
