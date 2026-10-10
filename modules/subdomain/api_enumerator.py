"""
API-based subdomain enumeration with multiple sources
"""
from typing import List
import requests
from core.security import SecurityManager
from utils.ratelimiter import RateLimiter
from utils.cache import CacheManager
from config.settings import Config

class APIEnumerator:
    """Multi-API subdomain enumeration"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.security = SecurityManager()
        self.cache = CacheManager(Config.CACHE_DIR, Config.CACHE_TTL)
        self.rate_limiter = RateLimiter(Config.VT_RATE_LIMIT, 60)
    
    def fetch_subdomains(self) -> List[str]:
        """Fetch subdomains from multiple APIs"""
        all_subs = set()
        
        # Try VirusTotal if available
        if Config.VT_API_WORKING:
            vt_subs = self._fetch_from_virustotal()
            all_subs.update(vt_subs)
            print(f"[+] VirusTotal: {len(vt_subs)} subdomains")
        else:
            print(f"[!] VirusTotal: Skipped (API not configured/valid)")
        
        # Add more APIs here in the future
        # - SecurityTrails
        # - AlienVault OTX
        # - Censys
        
        return list(all_subs)
    
    def _fetch_from_virustotal(self) -> List[str]:
        """Fetch from VirusTotal API with better error handling"""
        # Check cache
        cached = self.cache.get(f"vt_{self.domain}")
        if cached is not None:
            print(f"[*] Using cached VirusTotal results")
            return cached
        
        # Rate limit check
        if not self.rate_limiter.acquire(blocking=False):
            print(f"[!] VirusTotal rate limit reached, using cached/fallback")
            return []
        
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
        headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
        
        all_subdomains = []
        next_cursor = None
        
        try:
            # Try to get multiple pages
            for page in range(3):  # Get up to 3 pages
                params = {"limit": 40}
                if next_cursor:
                    params["cursor"] = next_cursor
                
                response = requests.get(url, headers=headers, params=params, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    subs = [item['id'] for item in data.get('data', [])]
                    all_subdomains.extend(subs)
                    
                    # Check for next page
                    next_cursor = data.get('links', {}).get('next')
                    if not next_cursor:
                        break
                elif response.status_code == 401:
                    print(f"[!] VirusTotal: Invalid API key (401)")
                    Config.VT_API_WORKING = False
                    break
                elif response.status_code == 429:
                    print(f"[!] VirusTotal: Rate limit exceeded")
                    break
                else:
                    print(f"[!] VirusTotal: HTTP {response.status_code}")
                    break
            
            if all_subdomains:
                # Cache results
                self.cache.set(f"vt_{self.domain}", all_subdomains)
            
            return all_subdomains
            
        except requests.exceptions.Timeout:
            print(f"[!] VirusTotal: Request timeout")
            return []
        except Exception as e:
            print(f"[!] VirusTotal: {str(e)[:100]}")
            return []
