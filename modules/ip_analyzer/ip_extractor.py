"""
IP extraction and classification with CDN detection
"""
from typing import List, Dict, Tuple
import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
from core.security import SecurityManager
from config.settings import Config
from modules.ip_analyzer.cdn_detector import CDNDetector

class IPAnalyzer:
    """Extract and analyze IP addresses from subdomains with CDN detection"""
    
    def __init__(self):
        self.security = SecurityManager()
        self.cdn_detector = CDNDetector()
    
    @staticmethod
    def resolve_ip(subdomain: str) -> Tuple[str, str]:
        """Resolve subdomain to IP address"""
        try:
            ip = socket.gethostbyname(subdomain)
            return (subdomain, ip)
        except:
            return (subdomain, None)
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is private/internal"""
        private_ranges = [
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.', '127.', '169.254.',
            '::1', 'fc00:', 'fe80:'
        ]
        return any(ip.startswith(prefix) for prefix in private_ranges)
    
    def analyze_subdomains(self, subdomains: List[str]) -> Dict:
        """Analyze all subdomains and classify IPs with CDN detection"""
        results = {
            'private_ips': [],
            'public_ips': [],
            'origin_mapping': {},
            'cdn_analysis': []
        }
        
        print(f"\n{Fore.YELLOW}[*] Resolving and analyzing IP addresses for {len(subdomains)} subdomains...{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = [executor.submit(self._analyze_single, sub) for sub in subdomains]
            
            for future in futures:
                analysis = future.result()
                if analysis:
                    subdomain = analysis['subdomain']
                    ip = analysis['ip']
                    
                    results['origin_mapping'][subdomain] = ip
                    
                    if self.is_private_ip(ip):
                        analysis['type'] = 'private'
                        results['private_ips'].append(analysis)
                        print(f"{Fore.MAGENTA}[PRIVATE] {subdomain} -> {ip}{Style.RESET_ALL}")
                    else:
                        analysis['type'] = 'public'
                        results['public_ips'].append(analysis)
                        
                        # Show CDN status
                        if analysis['is_cdn']:
                            print(f"{Fore.YELLOW}[PUBLIC] {subdomain} -> {ip} [{analysis['cdn_status']}]{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.CYAN}[PUBLIC] {subdomain} -> {ip} [{analysis['cdn_status']}]{Style.RESET_ALL}")
                    
                    results['cdn_analysis'].append(analysis)
        
        # Print summary
        cdn_count = sum(1 for a in results['cdn_analysis'] if a.get('is_cdn', False))
        origin_count = len(results['public_ips']) - cdn_count
        
        print(f"\n{Fore.CYAN}[✓] Analysis Complete:{Style.RESET_ALL}")
        print(f"    Public IPs: {len(results['public_ips'])}")
        print(f"      - Behind CDN/Cloud: {cdn_count}")
        print(f"      - Likely Origin: {origin_count}")
        print(f"    Private IPs: {len(results['private_ips'])}")
        
        return results
    
    def _analyze_single(self, subdomain: str) -> Dict:
        """Analyze single subdomain with CDN detection"""
        subdomain, ip = self.resolve_ip(subdomain)
        
        if not ip:
            return None
        
        # Perform CDN detection
        cdn_result = self.cdn_detector.detect(subdomain, ip)
        
        return {
            'subdomain': subdomain,
            'ip': ip,
            'type': 'unknown',
            'is_cdn': cdn_result['is_cdn'],
            'cdn_provider': cdn_result.get('provider'),
            'cdn_confidence': cdn_result['confidence'],
            'cdn_status': self.cdn_detector.get_detailed_analysis(subdomain, ip),
            'origin_score': self.cdn_detector.calculate_origin_score(subdomain, ip),
            'evidence': cdn_result['evidence']
        }
