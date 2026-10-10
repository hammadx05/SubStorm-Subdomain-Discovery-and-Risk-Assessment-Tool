"""
Shodan API integration with better error handling and credit saving
"""
from typing import List, Dict
import requests
from core.security import SecurityManager
from utils.ratelimiter import RateLimiter
from utils.cache import CacheManager
from config.settings import Config

class ShodanClient:
    """Shodan API client with graceful degradation and credit saving"""
    
    def __init__(self):
        self.security = SecurityManager()
        self.cache = CacheManager(Config.CACHE_DIR, Config.CACHE_TTL)
        self.rate_limiter = RateLimiter(Config.SHODAN_RATE_LIMIT, 1)
    
    def lookup_ip(self, ip: str) -> Dict:
        """Query Shodan for IP information with graceful error handling"""
        # Check if Shodan is working
        if not Config.SHODAN_API_WORKING:
            return {
                'ip': ip, 
                'error': 'Shodan API not configured or invalid',
                'ports': [],
                'cves': []
            }
        
        # Check cache
        cached = self.cache.get(f"shodan_{ip}")
        if cached:
            return cached
        
        # Rate limit
        if not self.rate_limiter.acquire(blocking=False):
            return {
                'ip': ip, 
                'error': 'Rate limited - try again later',
                'ports': [],
                'cves': []
            }
        
        url = f"https://api.shodan.io/shodan/host/{ip}?key={Config.SHODAN_API_KEY}"
        
        try:
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                result = {
                    'ip': ip,
                    'ports': sorted(data.get('ports', [])),
                    'cves': list(data.get('vulns', {}).keys()),
                    'org': data.get('org', 'Unknown'),
                    'os': data.get('os', 'Unknown'),
                    'hostnames': data.get('hostnames', [])
                }
                self.cache.set(f"shodan_{ip}", result)
                return result
            elif response.status_code == 401:
                Config.SHODAN_API_WORKING = False
                return {'ip': ip, 'error': 'Invalid Shodan API key', 'ports': [], 'cves': []}
            elif response.status_code == 403:
                return {'ip': ip, 'error': 'Shodan access denied (no credits?)', 'ports': [], 'cves': []}
            elif response.status_code == 404:
                return {'ip': ip, 'error': 'IP not found in Shodan database', 'ports': [], 'cves': []}
            else:
                return {'ip': ip, 'error': f'HTTP {response.status_code}', 'ports': [], 'cves': []}
                
        except requests.exceptions.Timeout:
            return {'ip': ip, 'error': 'Shodan timeout', 'ports': [], 'cves': []}
        except Exception as e:
            return {'ip': ip, 'error': str(e)[:100], 'ports': [], 'cves': []}
    
    def lookup_multiple(self, ips: List[Dict]) -> List[Dict]:
        """Query Shodan for multiple IPs with credit saving optimization"""
        results = []
        
        # Display optimization settings
        print(f"  [ℹ]  Shodan Optimization: Max {Config.MAX_SHODAN_LOOKUPS} lookups, Unique IPs only: {Config.SHODAN_ONLY_UNIQUE_IPS}")
        
        # OPTIMIZATION 1: Only check unique IPs (saves credits)
        if Config.SHODAN_ONLY_UNIQUE_IPS:
            unique_ips = {}
            for entry in ips:
                if entry['ip'] not in unique_ips:
                    unique_ips[entry['ip']] = entry['subdomain']
                else:
                    # Multiple subdomains on same IP - only check once
                    print(f"  [*] Skipping {entry['subdomain']} - same IP as {unique_ips[entry['ip']]} (saving credit)")
            
            # Convert back to list
            ips_to_check = [{'ip': ip, 'subdomain': sub} for ip, sub in unique_ips.items()]
            saved_credits = len(ips) - len(ips_to_check)
            if saved_credits > 0:
                print(f"  [✓] {len(ips)} subdomains share {len(ips_to_check)} unique IPs")
                print(f"  [✓] Saved {saved_credits} Shodan credits!")
        else:
            ips_to_check = ips
        
        # OPTIMIZATION 2: Limit total lookups
        if Config.MAX_SHODAN_LOOKUPS and len(ips_to_check) > Config.MAX_SHODAN_LOOKUPS:
            print(f"  [!] Limiting to {Config.MAX_SHODAN_LOOKUPS} Shodan lookups (from {len(ips_to_check)})")
            print(f"  [ℹ]  Adjust MAX_SHODAN_LOOKUPS in config/settings.py to change this limit")
            ips_to_check = ips_to_check[:Config.MAX_SHODAN_LOOKUPS]
        
        total = len(ips_to_check)
        if total == 0:
            print("  [✓] No Shodan lookups needed (all IPs skipped due to optimization)")
            return results
        
        print(f"  [*] Performing {total} Shodan lookups...")
        
        for idx, entry in enumerate(ips_to_check, 1):
            print(f"   [{idx}/{total}] Querying Shodan for {entry['ip']}...", end=' ')
            result = self.lookup_ip(entry['ip'])
            result['subdomain'] = entry['subdomain']
            
            if 'error' in result:
                print(f"⚠️  {result['error']}")
            else:
                ports_count = len(result.get('ports', []))
                cves_count = len(result.get('cves', []))
                print(f"✓ {ports_count} ports, {cves_count} CVEs")
            
            results.append(result)
        
        return results
