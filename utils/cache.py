"""
Caching mechanism for API responses and DNS results
Reduces redundant requests and improves performance
"""
import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Any
import threading

class CacheManager:
    """Thread-safe cache management"""
    
    def __init__(self, cache_dir: Path, ttl: int = 3600):
        self.cache_dir = cache_dir
        self.ttl = ttl
        self.lock = threading.Lock()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.memory_cache = {}
    
    def _get_cache_key(self, key: str) -> str:
        """Generate hash for cache key"""
        return hashlib.md5(key.encode()).hexdigest()
    
    def _get_cache_path(self, cache_key: str) -> Path:
        """Get file path for cached item"""
        return self.cache_dir / f"{cache_key}.json"
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve item from cache"""
        cache_key = self._get_cache_key(key)
        
        # Check memory cache first
        with self.lock:
            if cache_key in self.memory_cache:
                item, timestamp = self.memory_cache[cache_key]
                if datetime.now() - timestamp < timedelta(seconds=self.ttl):
                    return item
                else:
                    del self.memory_cache[cache_key]
        
        # Check disk cache
        cache_path = self._get_cache_path(cache_key)
        if cache_path.exists():
            try:
                with open(cache_path, 'r') as f:
                    data = json.load(f)
                    cached_time = datetime.fromisoformat(data['timestamp'])
                    if datetime.now() - cached_time < timedelta(seconds=self.ttl):
                        # Restore to memory cache
                        with self.lock:
                            self.memory_cache[cache_key] = (data['value'], cached_time)
                        return data['value']
            except:
                pass
        
        return None
    
    def set(self, key: str, value: Any) -> None:
        """Store item in cache"""
        cache_key = self._get_cache_key(key)
        timestamp = datetime.now()
        
        # Store in memory
        with self.lock:
            self.memory_cache[cache_key] = (value, timestamp)
        
        # Store on disk
        cache_path = self._get_cache_path(cache_key)
        try:
            with open(cache_path, 'w') as f:
                json.dump({
                    'key': key,
                    'value': value,
                    'timestamp': timestamp.isoformat()
                }, f)
        except:
            pass
    
    def clear(self) -> None:
        """Clear all cache"""
        with self.lock:
            self.memory_cache.clear()
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
