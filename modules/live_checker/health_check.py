"""
Multi-method live subdomain checking to reduce false positives
"""
import warnings
import urllib3
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import requests
from colorama import Fore, Style
from config.settings import Config

# Suppress SSL warnings for cleaner output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class LiveChecker:
    """
    Check if subdomains are live using multiple methods
    """
    
    @staticmethod
    def check_live(subdomain: str) -> bool:
        """Multi-method live check"""
        methods_passed = 0
        total_methods = 3
        
        # Method 1: DNS resolution
        try:
            ip = socket.gethostbyname(subdomain)
            methods_passed += 1
        except:
            pass
        
        # Method 2: HTTP/HTTPS request
        for proto in ['https', 'http']:
            try:
                response = requests.get(
                    f"{proto}://{subdomain}",
                    timeout=Config.HTTP_TIMEOUT,
                    verify=False,  # Disable SSL verification for speed
                    headers={'User-Agent': 'SubStorm/1.0'},
                    allow_redirects=True
                )
                if response.status_code < 500:
                    methods_passed += 1
                    break
            except:
                continue
        
        # Method 3: TCP port 80/443 connection
        for port in [80, 443]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(Config.DNS_TIMEOUT)
                result = sock.connect_ex((subdomain, port))
                sock.close()
                if result == 0:
                    methods_passed += 1
                    break
            except:
                continue
        
        return methods_passed >= 2
    
    @staticmethod
    def filter_live(subdomains: List[str]) -> List[str]:
        """Filter live subdomains with concurrency and visual feedback"""
        live = []
        dead = []
        
        print(f"\n{Fore.YELLOW}[*] Checking {len(subdomains)} subdomains for liveness...{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {executor.submit(LiveChecker.check_live, sub): sub for sub in subdomains}
            
            for future in as_completed(futures):
                sub = futures[future]
                if future.result():
                    live.append(sub)
                    print(f"{Fore.GREEN}[LIVE] {sub}{Style.RESET_ALL}")
                else:
                    dead.append(sub)
                    print(f"{Fore.RED}[DEAD] {sub}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}[✓] Live: {len(live)} | Dead: {len(dead)}{Style.RESET_ALL}")
        return live
