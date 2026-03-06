"""SQLite caching layer for CTI lookups."""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from emltriage.core.models import IOCType
from emltriage.cti.models import CTIProviderType, CacheEntry
from emltriage.utils.logging import get_logger

logger = get_logger(__name__)


class CTICache:
    """SQLite-based cache for CTI enrichment results."""
    
    def __init__(self, db_path: Path, default_ttl: int = 3600):
        """Initialize cache.
        
        Args:
            db_path: Path to SQLite database file
            default_ttl: Default TTL in seconds
        """
        self.db_path = db_path
        self.default_ttl = default_ttl
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize database schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cti_cache (
                    ioc TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    access_count INTEGER DEFAULT 0,
                    last_accessed TIMESTAMP,
                    PRIMARY KEY (ioc, ioc_type, provider)
                )
            """)
            
            # Create index for faster lookups
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_expires 
                ON cti_cache(expires_at)
            """)
            
            conn.commit()
        
        logger.info(f"CTI cache initialized at {self.db_path}")
    
    def get(
        self,
        ioc: str,
        ioc_type: IOCType,
        provider: CTIProviderType
    ) -> Optional[CacheEntry]:
        """Get cached result if not expired.
        
        Args:
            ioc: The IOC value
            ioc_type: Type of IOC
            provider: Provider type
            
        Returns:
            CacheEntry if found and not expired, None otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                cursor = conn.execute(
                    """
                    SELECT * FROM cti_cache 
                    WHERE ioc = ? AND ioc_type = ? AND provider = ?
                    AND expires_at > ?
                    """,
                    (ioc, ioc_type.value, provider.value, datetime.now(timezone.utc))
                )
                
                row = cursor.fetchone()
                if row:
                    # Update access stats
                    conn.execute(
                        """
                        UPDATE cti_cache 
                        SET access_count = access_count + 1,
                            last_accessed = ?
                        WHERE ioc = ? AND ioc_type = ? AND provider = ?
                        """,
                        (datetime.now(timezone.utc), ioc, ioc_type.value, provider.value)
                    )
                    conn.commit()
                    
                    return CacheEntry(
                        ioc=row['ioc'],
                        ioc_type=IOCType(row['ioc_type']),
                        provider=CTIProviderType(row['provider']),
                        result=json.loads(row['result_json']),
                        created_at=datetime.fromisoformat(row['created_at']),
                        expires_at=datetime.fromisoformat(row['expires_at']),
                        access_count=row['access_count'] + 1,
                        last_accessed=datetime.now(timezone.utc),
                    )
        
        except Exception as e:
            logger.error(f"Error reading from cache: {e}")
        
        return None
    
    def set(
        self,
        ioc: str,
        ioc_type: IOCType,
        provider: CTIProviderType,
        result: dict,
        ttl: Optional[int] = None
    ) -> None:
        """Store result in cache.
        
        Args:
            ioc: The IOC value
            ioc_type: Type of IOC
            provider: Provider type
            result: Result data to cache
            ttl: TTL in seconds (uses default if not specified)
        """
        ttl = ttl or self.default_ttl
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cti_cache 
                    (ioc, ioc_type, provider, result_json, created_at, expires_at, access_count, last_accessed)
                    VALUES (?, ?, ?, ?, ?, ?, 0, NULL)
                    """,
                    (
                        ioc,
                        ioc_type.value,
                        provider.value,
                        json.dumps(result),
                        now.isoformat(),
                        expires.isoformat(),
                    )
                )
                conn.commit()
                
                logger.debug(f"Cached result for {ioc} from {provider.value}")
        
        except Exception as e:
            logger.error(f"Error writing to cache: {e}")
    
    def delete(
        self,
        ioc: str,
        ioc_type: IOCType,
        provider: CTIProviderType
    ) -> None:
        """Delete cached entry.
        
        Args:
            ioc: The IOC value
            ioc_type: Type of IOC
            provider: Provider type
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    DELETE FROM cti_cache 
                    WHERE ioc = ? AND ioc_type = ? AND provider = ?
                    """,
                    (ioc, ioc_type.value, provider.value)
                )
                conn.commit()
        
        except Exception as e:
            logger.error(f"Error deleting from cache: {e}")
    
    def clear_expired(self) -> int:
        """Remove expired entries from cache.
        
        Returns:
            Number of entries removed
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "DELETE FROM cti_cache WHERE expires_at <= ?",
                    (datetime.now(timezone.utc),)
                )
                conn.commit()
                
                count = cursor.rowcount
                if count > 0:
                    logger.info(f"Cleared {count} expired cache entries")
                return count
        
        except Exception as e:
            logger.error(f"Error clearing expired cache: {e}")
            return 0
    
    def clear_all(self) -> int:
        """Clear all cache entries.
        
        Returns:
            Number of entries removed
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("DELETE FROM cti_cache")
                conn.commit()
                
                count = cursor.rowcount
                logger.info(f"Cleared all {count} cache entries")
                return count
        
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            return 0
    
    def get_stats(self) -> dict:
        """Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM cti_cache")
                total = cursor.fetchone()[0]
                
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM cti_cache WHERE expires_at > ?",
                    (datetime.now(timezone.utc),)
                )
                valid = cursor.fetchone()[0]
                
                cursor = conn.execute(
                    "SELECT SUM(access_count) FROM cti_cache"
                )
                total_hits = cursor.fetchone()[0] or 0
                
                return {
                    "total_entries": total,
                    "valid_entries": valid,
                    "expired_entries": total - valid,
                    "total_cache_hits": total_hits,
                }
        
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {
                "total_entries": 0,
                "valid_entries": 0,
                "expired_entries": 0,
                "total_cache_hits": 0,
            }
