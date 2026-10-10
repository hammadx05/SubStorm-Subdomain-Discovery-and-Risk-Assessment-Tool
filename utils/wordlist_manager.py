"""
Wordlist management with automatic downloading
"""
import os
import requests
from pathlib import Path
from typing import Tuple, List, Optional
from config.settings import Config

class WordlistManager:
    """Manage wordlist downloading and caching"""
    
    def __init__(self):
        self.wordlist_dir = Config.WORDLIST_DIR
        self.wordlist_dir.mkdir(parents=True, exist_ok=True)
    
    def download_wordlist(self, size_preset: str, force: bool = False) -> Tuple[bool, str, List[str]]:
        """
        Download wordlist for specified size preset
        Returns: (success, file_path, wordlist_content)
        """
        if size_preset not in Config.WORDLIST_PRESETS:
            print(f"[!] Invalid preset: {size_preset}")
            return False, "", []
        
        preset = Config.WORDLIST_PRESETS[size_preset]
        
        if size_preset == 'tiny':
            # Return built-in wordlist
            return True, "built-in", self._get_tiny_wordlist()
        
        wordlist_file = self.wordlist_dir / f"subdomains_{size_preset}.txt"
        
        # Check if already downloaded
        if wordlist_file.exists() and not force:
            print(f"[✓] Using cached wordlist: {preset['name']}")
            try:
                with open(wordlist_file, 'r') as f:
                    words = [line.strip() for line in f if line.strip()]
                return True, str(wordlist_file), words
            except:
                pass
        
        # Download wordlist
        print(f"[*] Downloading {preset['name']}...")
        print(f"    URL: {preset['url']}")
        
        try:
            response = requests.get(preset['url'], timeout=30, stream=True)
            response.raise_for_status()
            
            # Get total size for progress indicator
            total_size = int(response.headers.get('content-length', 0))
            
            with open(wordlist_file, 'wb') as f:
                downloaded = 0
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size:
                        progress = (downloaded / total_size) * 100
                        print(f"\r    Progress: {progress:.1f}%", end='', flush=True)
            
            print(f"\n[✓] Downloaded to: {wordlist_file}")
            
            # Read and return wordlist
            with open(wordlist_file, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
            
            print(f"    Loaded {len(words)} subdomains")
            return True, str(wordlist_file), words
            
        except requests.exceptions.RequestException as e:
            print(f"[!] Download failed: {e}")
            return False, "", []
        except Exception as e:
            print(f"[!] Error: {e}")
            return False, "", []
    
    def _get_tiny_wordlist(self) -> List[str]:
        """Return built-in tiny wordlist (100 most common subdomains)"""
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
            'web', 'media', 'email', 'images', 'img', 'download', 'dns', 'api', 'git',
            'cdn', 'stats', 'dashboard', 'portal', 'start', 'info', 'app', 'store',
            'cloud', 'server', 'backup', 'remote', 'ssh', 'exchange', 'owa', 'remote',
            'vps', 'panel', 'direct', 'cpcalendars', 'cpcontacts', 'webdisk', 'webmail',
            'whm', 'autodiscover', 'cpanel', 'host', 'server', 'ns4', 'ns5', 'mx1', 'mx2',
            'smtp2', 'pop2', 'imap2', 'test2', 'dev2', 'stage', 'staging', 'production'
        ]
    
    @staticmethod
    def list_presets():
        """Display available wordlist presets"""
        print(f"\n{'='*60}")
        print(f"📚 Available Wordlist Presets")
        print(f"{'='*60}")
        for key, preset in Config.WORDLIST_PRESETS.items():
            print(f"\n  {key.upper():8} - {preset['name']}")
            print(f"            {preset['description']}")
        print(f"\n{'='*60}")
