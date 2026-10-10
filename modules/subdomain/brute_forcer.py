"""
Brute force subdomain enumeration with configurable wordlist sizes
"""
from typing import List, Optional
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.validator import ResultValidator
from utils.cache import CacheManager
from utils.wordlist_manager import WordlistManager
from config.settings import Config

class BruteForcer:
    """Brute force with configurable wordlist"""
    
    def __init__(self, domain: str, wordlist_size: str = None, custom_wordlist: str = None):
        self.domain = domain
        self.wordlist_size = wordlist_size or Config.DEFAULT_WORDLIST_SIZE
        self.custom_wordlist = custom_wordlist
        self.cache = CacheManager(Config.CACHE_DIR, Config.CACHE_TTL)
        self.validator = ResultValidator()
        self.wordlist_manager = WordlistManager()
        
        # Common subdomain prefixes (always try first)
        self.common_prefixes = self.wordlist_manager._get_tiny_wordlist()[:50]
    
    def enumerate(self) -> List[str]:
        """Perform brute force enumeration"""
        found = []
        
        # Step 1: Try common prefixes first (fast win)
        print(f"\n[*] Phase 1: Checking common subdomain prefixes...")
        found_count = 0
        for prefix in self.common_prefixes[:20]:  # Try top 20 first
            sub = f"{prefix}.{self.domain}"
            if self._quick_check(sub):
                found.append(sub)
                found_count += 1
                print(f"  [{found_count}] ✓ Found: {sub}")
        
        # Step 2: Load wordlist based on user selection
        words = self._load_wordlist()
        
        if not words:
            print(f"[!] No wordlist loaded. Using common prefixes only.")
            return list(set(found))
        
        print(f"\n[*] Phase 2: Brute forcing with {len(words)} subdomains...")
        print(f"    This may take a few minutes. Press Ctrl+C to stop.\n")
        
        # Use progress counter (continue from Phase 1 count)
        checked = 0
        found_count = len(found)
        
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {executor.submit(self._check_subdomain, word): word for word in words}
            
            for future in as_completed(futures):
                checked += 1
                result = future.result()
                if result:
                    # Avoid duplicate entries
                    if result not in found:
                        found.append(result)
                        found_count += 1
                        print(f"  [{found_count}] ✓ Found: {result}")
                    else:
                        # Still show progress but not as new find
                        if checked % 500 == 0:
                            print(f"  Progress: {checked}/{len(words)} words checked ({found_count} unique found)")
                else:
                    # Show progress even when nothing found
                    if checked % 500 == 0:
                        print(f"  Progress: {checked}/{len(words)} words checked ({found_count} found)")
                
                # Show progress every 500 checks (changed from 1000 for better feedback)
                if checked % 500 == 0 and checked > 0:
                    print(f"  Progress: {checked}/{len(words)} words checked ({found_count} unique found)")
        
        unique_found = list(set(found))
        print(f"\n[✓] Brute force complete: {len(unique_found)} unique subdomains found")
        return unique_found
    
    def _quick_check(self, subdomain: str) -> bool:
        """Quick DNS check"""
        try:
            socket.gethostbyname(subdomain)
            return True
        except:
            return False
    
    def _check_subdomain(self, word: str) -> Optional[str]:
        """Check single subdomain with validation"""
        subdomain = f"{word}.{self.domain}"
        
        # Check cache
        cached = self.cache.get(f"brute_{subdomain}")
        if cached is not None:
            return subdomain if cached else None
        
        # Quick DNS check
        try:
            ip = socket.gethostbyname(subdomain)
        except:
            self.cache.set(f"brute_{subdomain}", False)
            return None
        
        # Validate
        if self.validator.validate_subdomain(subdomain, Config.REQUIRED_SUCCESS_RATE):
            self.cache.set(f"brute_{subdomain}", True)
            return subdomain
        
        self.cache.set(f"brute_{subdomain}", False)
        return None
    
    def _load_wordlist(self) -> List[str]:
        """Load wordlist based on user selection"""
        # If custom wordlist provided
        if self.custom_wordlist:
            words = self._load_custom_wordlist(self.custom_wordlist)
            if words:
                print(f"[✓] Loaded custom wordlist: {len(words)} words")
                return words
        
        # Use preset size
        if self.wordlist_size == 'tiny':
            return self.common_prefixes
        
        # Download or load preset wordlist
        success, path, words = self.wordlist_manager.download_wordlist(self.wordlist_size)
        if success and words:
            return words
        
        # Fallback to tiny
        print(f"[!] Failed to load wordlist, using tiny preset")
        return self.common_prefixes
    
    def _load_custom_wordlist(self, path: str) -> List[str]:
        """Load custom wordlist from file"""
        try:
            with open(path, 'r') as f:
                words = [line.strip().lower() for line in f if line.strip() and not line.startswith('#')]
                return list(set(words))
        except Exception as e:
            print(f"[!] Failed to load custom wordlist: {e}")
            return []
