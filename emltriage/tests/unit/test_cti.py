"""Unit tests for CTI module."""

import pytest
from pathlib import Path
from datetime import datetime, timezone

from emltriage.core.models import IOCType
from emltriage.cti.models import CTIProviderType, LocalIntelConfig
from emltriage.cti.providers.local import LocalIntelProvider
from emltriage.cti.models import ProviderConfig


class TestLocalIntelProvider:
    """Test local intelligence provider."""
    
    def test_load_csv_watchlist(self, tmp_path: Path):
        """Test loading CSV watchlist file."""
        # Create test CSV
        csv_content = """ioc,ioc_type,list_type,description,tags,confidence
test.com,domain,blocklist,Test domain,malicious,1.0
good.com,domain,allowlist,Good domain,legitimate,1.0"""
        
        csv_file = tmp_path / "watchlist.csv"
        csv_file.write_text(csv_content)
        
        # Create provider
        config = ProviderConfig(
            provider_type=CTIProviderType.LOCAL,
            enabled=True,
        )
        intel_config = LocalIntelConfig(
            enabled=True,
            watchlist_files=[str(csv_file)],
        )
        
        provider = LocalIntelProvider(config, intel_config)
        
        # Check entries loaded
        assert provider.get_loaded_entries_count() == 2
    
    def test_lookup_blocklisted_domain(self, tmp_path: Path):
        """Test looking up blocklisted domain."""
        # Create test CSV
        csv_content = """ioc,ioc_type,list_type,description,tags,confidence
evil.com,domain,blocklist,Malicious domain,malware,1.0"""
        
        csv_file = tmp_path / "blocklist.csv"
        csv_file.write_text(csv_content)
        
        # Create provider
        config = ProviderConfig(provider_type=CTIProviderType.LOCAL, enabled=True)
        intel_config = LocalIntelConfig(
            enabled=True,
            watchlist_files=[str(csv_file)],
        )
        
        provider = LocalIntelProvider(config, intel_config)
        
        # Lookup blocklisted domain
        result = provider.lookup("evil.com", IOCType.DOMAIN)
        
        assert result.status.value == "success"
        assert result.malicious_score == 100
        assert "blocklist" in result.categories
    
    def test_lookup_allowlisted_domain(self, tmp_path: Path):
        """Test looking up allowlisted domain."""
        # Create test CSV
        csv_content = """ioc,ioc_type,list_type,description,tags,confidence
good.com,domain,allowlist,Good domain,legitimate,1.0"""
        
        csv_file = tmp_path / "allowlist.csv"
        csv_file.write_text(csv_content)
        
        # Create provider
        config = ProviderConfig(provider_type=CTIProviderType.LOCAL, enabled=True)
        intel_config = LocalIntelConfig(
            enabled=True,
            watchlist_files=[str(csv_file)],
        )
        
        provider = LocalIntelProvider(config, intel_config)
        
        # Lookup allowlisted domain
        result = provider.lookup("good.com", IOCType.DOMAIN)
        
        assert result.status.value == "success"
        assert result.malicious_score == 0
        assert "allowlist" in result.categories
    
    def test_lookup_unknown_domain(self, tmp_path: Path):
        """Test looking up unknown domain."""
        # Create test CSV
        csv_content = """ioc,ioc_type,list_type,description,tags,confidence
test.com,domain,blocklist,Test,malware,1.0"""
        
        csv_file = tmp_path / "watchlist.csv"
        csv_file.write_text(csv_content)
        
        # Create provider
        config = ProviderConfig(provider_type=CTIProviderType.LOCAL, enabled=True)
        intel_config = LocalIntelConfig(
            enabled=True,
            watchlist_files=[str(csv_file)],
        )
        
        provider = LocalIntelProvider(config, intel_config)
        
        # Lookup unknown domain
        result = provider.lookup("unknown.com", IOCType.DOMAIN)
        
        assert result.status.value == "success"
        assert result.malicious_score == 0
        assert "no_match" in result.categories


class TestCTICache:
    """Test CTI cache functionality."""
    
    def test_cache_set_and_get(self, tmp_path: Path):
        """Test setting and getting cache entries."""
        from emltriage.cti.cache import CTICache
        from emltriage.cti.models import CTIProviderType
        
        cache = CTICache(tmp_path / "test_cache.db")
        
        # Set entry
        cache.set(
            "example.com",
            IOCType.DOMAIN,
            CTIProviderType.LOCAL,
            {"malicious_score": 50, "tags": ["test"]},
            ttl=3600
        )
        
        # Get entry
        entry = cache.get("example.com", IOCType.DOMAIN, CTIProviderType.LOCAL)
        
        assert entry is not None
        assert entry.ioc == "example.com"
        assert entry.result["malicious_score"] == 50
    
    def test_cache_expiration(self, tmp_path: Path):
        """Test that expired entries are not returned."""
        from emltriage.cti.cache import CTICache
        from emltriage.cti.models import CTIProviderType
        
        cache = CTICache(tmp_path / "test_cache.db")
        
        # Set entry with very short TTL
        cache.set(
            "example.com",
            IOCType.DOMAIN,
            CTIProviderType.LOCAL,
            {"malicious_score": 50},
            ttl=0  # Expired immediately
        )
        
        # Get entry - should be None (expired)
        entry = cache.get("example.com", IOCType.DOMAIN, CTIProviderType.LOCAL)
        
        assert entry is None
    
    def test_cache_stats(self, tmp_path: Path):
        """Test cache statistics."""
        from emltriage.cti.cache import CTICache
        from emltriage.cti.models import CTIProviderType
        
        cache = CTICache(tmp_path / "test_cache.db")
        
        # Add some entries
        cache.set("test1.com", IOCType.DOMAIN, CTIProviderType.LOCAL, {"score": 10})
        cache.set("test2.com", IOCType.DOMAIN, CTIProviderType.LOCAL, {"score": 20})
        
        # Get stats
        stats = cache.get_stats()
        
        assert stats["total_entries"] == 2
        assert stats["valid_entries"] == 2
