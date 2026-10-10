"""
Configuration management with environment variable support
"""
import os
from pathlib import Path
from dotenv import load_dotenv
from colorama import Fore, Style

# Load environment variables
load_dotenv()

class Config:
    """Central configuration class"""
    
    # ============================================
    # API KEYS
    # ============================================
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '').strip()
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '').strip()
    
    # API status flags
    VT_API_WORKING = False
    SHODAN_API_WORKING = False
    
    # ============================================
    # SHODAN OPTIMIZATION (Added - Credit Saving)
    # ============================================
    MAX_SHODAN_LOOKUPS = 30          # Maximum Shodan lookups per scan (saves credits)
    SHODAN_ONLY_UNIQUE_IPS = True    # Only check unique IPs (not every subdomain)
    
    # ============================================
    # WORDLIST PRESETS
    # ============================================
    WORDLIST_PRESETS = {
        'tiny': {
            'name': 'Tiny (100 common subdomains)',
            'url': None,  # Built-in
            'size': 100,
            'description': 'Quick scan with 100 most common subdomains'
        },
        'small': {
            'name': 'Small (5,000 subdomains)',
            'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
            'size': 5000,
            'description': 'Standard scan with 5,000 common subdomains'
        },
        'medium': {
            'name': 'Medium (20,000 subdomains)',
            'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt',
            'size': 20000,
            'description': 'Extended scan with 20,000 subdomains'
        },
        'large': {
            'name': 'Large (100,000 subdomains)',
            'url': 'https://raw.githubusercontent.com/bitquark/dnspop/master/results/bitquark_subdomains_2016.txt',
            'size': 100000,
            'description': 'Deep scan with 100,000 subdomains (slower)'
        },
        'full': {
            'name': 'Full (200,000+ subdomains)',
            'url': 'https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt',
            'size': 200000,
            'description': 'Complete scan with 200,000+ subdomains (very slow)'
        }
    }
    
    # ============================================
    # THREADING CONFIGURATION
    # ============================================
    MAX_WORKERS = 100                # Number of concurrent threads
    DNS_TIMEOUT = 5                  # DNS lookup timeout (seconds)
    HTTP_TIMEOUT = 10                # HTTP request timeout (seconds)
    
    # ============================================
    # RATE LIMITING
    # ============================================
    VT_RATE_LIMIT = 4                # VirusTotal requests per minute (free tier)
    SHODAN_RATE_LIMIT = 1            # Shodan requests per second
    
    # ============================================
    # VALIDATION
    # ============================================
    REQUIRED_SUCCESS_RATE = 0.5      # 50% of validation methods must pass
    
    # ============================================
    # CACHE SETTINGS
    # ============================================
    CACHE_TTL = 3600                 # Cache time-to-live (seconds, 1 hour)
    CACHE_DIR = Path.home() / '.substorm' / 'cache'
    
    # ============================================
    # WORDLIST SETTINGS
    # ============================================
    WORDLIST_DIR = Path.home() / '.substorm' / 'wordlists'
    DEFAULT_WORDLIST_SIZE = 'small'  # Default preset (tiny/small/medium/large/full)
    
    # ============================================
    # SECURITY
    # ============================================
    DOMAIN_PATTERN = r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    # ============================================
    # METHODS
    # ============================================
    
    @classmethod
    def validate_api_keys(cls):
        """Validate API keys and test them"""
        print(f"\n[🔑] Checking API Keys...")
        
        # Validate VirusTotal
        if cls.VIRUSTOTAL_API_KEY and cls.VIRUSTOTAL_API_KEY != 'your_virustotal_key_here':
            print(f"   ✓ VirusTotal API key present (length: {len(cls.VIRUSTOTAL_API_KEY)})")
            try:
                import requests
                test_url = "https://www.virustotal.com/api/v3/domains/google.com"
                headers = {"x-apikey": cls.VIRUSTOTAL_API_KEY}
                response = requests.get(test_url, headers=headers, timeout=5)
                if response.status_code == 200:
                    cls.VT_API_WORKING = True
                    print(f"   ✓ VirusTotal API key is valid")
                elif response.status_code == 401:
                    print(f"   ✗ VirusTotal API key is INVALID (401 Unauthorized)")
                else:
                    print(f"   ⚠ VirusTotal API returned: HTTP {response.status_code}")
            except Exception as e:
                print(f"   ⚠ Could not test VirusTotal API")
        else:
            print(f"   ✗ VirusTotal API key missing")
        
        # Validate Shodan
        if cls.SHODAN_API_KEY and cls.SHODAN_API_KEY != 'your_shodan_key_here':
            print(f"   ✓ Shodan API key present (length: {len(cls.SHODAN_API_KEY)})")
            print(f"   [ℹ]  Free tier: {cls.MAX_SHODAN_LOOKUPS} lookups per scan (configurable)")
            try:
                import requests
                test_url = f"https://api.shodan.io/api-info?key={cls.SHODAN_API_KEY}"
                response = requests.get(test_url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    cls.SHODAN_API_WORKING = True
                    print(f"   ✓ Shodan API key is valid (credits: {data.get('scan_credits', 0)})")
                elif response.status_code == 401:
                    print(f"   ✗ Shodan API key is INVALID (401 Unauthorized)")
                else:
                    print(f"   ⚠ Shodan API returned: HTTP {response.status_code}")
            except Exception as e:
                print(f"   ⚠ Could not test Shodan API")
        else:
            print(f"   ✗ Shodan API key missing")
            print(f"   [ℹ]  Shodan features (ports/CVEs) will be disabled")
        
        print()
        return cls.VT_API_WORKING or cls.SHODAN_API_WORKING
    
    @classmethod
    def ensure_cache_dir(cls):
        """Create cache directory if it doesn't exist"""
        cls.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cls.WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def get_wordlist_path(cls, size_preset=None):
        """Get wordlist path for specified size preset"""
        if not size_preset:
            size_preset = cls.DEFAULT_WORDLIST_SIZE
        
        if size_preset not in cls.WORDLIST_PRESETS:
            size_preset = 'small'
        
        preset = cls.WORDLIST_PRESETS[size_preset]
        
        if size_preset == 'tiny':
            return None, preset
        
        wordlist_file = cls.WORDLIST_DIR / f"subdomains_{size_preset}.txt"
        return wordlist_file, preset
    
    @classmethod
    def show_shodan_info(cls):
        """Display Shodan optimization info"""
        if cls.SHODAN_API_WORKING:
            print(f"{Fore.CYAN}[ℹ]  Shodan Optimization:{Style.RESET_ALL}")
            print(f"     - Max lookups per scan: {cls.MAX_SHODAN_LOOKUPS}")
            print(f"     - Unique IPs only: {'Yes' if cls.SHODAN_ONLY_UNIQUE_IPS else 'No'}")
            print(f"     - Saves credits by avoiding duplicate IP checks")
