#!/usr/bin/env python3
"""
SubStorm - Professional Subdomain Enumeration Tool
Author: Muhammad Hammad
Version: 2.0
"""
import sys
import argparse
from pathlib import Path
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Import modules
from core.banner import display_banner
from core.security import SecurityManager
from core.validator import ResultValidator
from config.settings import Config
from modules.subdomain.brute_forcer import BruteForcer
from modules.subdomain.api_enumerator import APIEnumerator
from modules.live_checker.health_check import LiveChecker
from modules.ip_analyzer.ip_extractor import IPAnalyzer
from modules.shodan.shodan_client import ShodanClient
from reports.report_generator import ReportGenerator
from utils.wordlist_manager import WordlistManager

class SubStorm:
    """Main application class"""
    
    def __init__(self):
        self.security = SecurityManager()
        self.validator = ResultValidator()
        self.results = {
            'all_subdomains': [],
            'live_subdomains': [],
            'ip_analysis': {},
            'shodan_results': []
        }
    
    def run(self, domain: str, wordlist_size: str = None, custom_wordlist: str = None, 
            skip_brute: bool = False, skip_api: bool = False, max_subdomains: int = None):
        """Main execution flow"""
        
        # Security: Validate and sanitize input
        domain = self.security.sanitize_domain(domain)
        if not domain:
            print(f"{Fore.RED}[!] Invalid domain name{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}[✓] Target validated: {domain}{Style.RESET_ALL}")
        
        # Check for wildcard DNS
        if self.validator.is_wildcard_dns(domain, "test"):
            print(f"{Fore.YELLOW}[!] Warning: Wildcard DNS detected. Results may include false positives.{Style.RESET_ALL}")
        
        # Step 1: Subdomain Enumeration
        all_subs = set()
        
        if not skip_brute:
            brute = BruteForcer(domain, wordlist_size, custom_wordlist)
            brute_subs = brute.enumerate()
            
            # Limit if specified
            if max_subdomains and len(brute_subs) > max_subdomains:
                brute_subs = brute_subs[:max_subdomains]
                print(f"[*] Limited to {max_subdomains} subdomains as requested")
            
            all_subs.update(brute_subs)
            print(f"{Fore.CYAN}[+] Brute force found: {len(brute_subs)} subdomains{Style.RESET_ALL}")
        
        if not skip_api:
            api = APIEnumerator(domain)
            api_subs = api.fetch_subdomains()
            all_subs.update(api_subs)
            print(f"{Fore.CYAN}[+] API found: {len(api_subs)} subdomains{Style.RESET_ALL}")
        
        self.results['all_subdomains'] = list(all_subs)
        
        if not all_subs:
            print(f"{Fore.RED}[!] No subdomains found{Style.RESET_ALL}")
            return
        
        # Step 2: Live Subdomain Checking
        print(f"\n{Fore.YELLOW}[*] Checking live subdomains...{Style.RESET_ALL}")
        self.results['live_subdomains'] = LiveChecker.filter_live(list(all_subs))
        
        if not self.results['live_subdomains']:
            print(f"{Fore.RED}[!] No live subdomains found{Style.RESET_ALL}")
            return
        
        # Step 3: IP Analysis
        print(f"\n{Fore.YELLOW}[*] Analyzing IP addresses...{Style.RESET_ALL}")
        ip_analyzer = IPAnalyzer()
        self.results['ip_analysis'] = ip_analyzer.analyze_subdomains(self.results['live_subdomains'])
        
        # Step 4: Shodan Lookup
        if self.results['ip_analysis']['public_ips'] and Config.SHODAN_API_WORKING:
            print(f"\n{Fore.YELLOW}[*] Querying Shodan for {len(self.results['ip_analysis']['public_ips'])} public IPs...{Style.RESET_ALL}")
            shodan = ShodanClient()
            self.results['shodan_results'] = shodan.lookup_multiple(self.results['ip_analysis']['public_ips'])
            self._display_shodan_summary()
        
        # Step 5: Generate Reports
        print(f"\n{Fore.YELLOW}[*] Generating reports...{Style.RESET_ALL}")
        json_report = ReportGenerator.generate_json_report(domain, self.results)
        html_report = ReportGenerator.generate_html_report(domain, self.results)
        
        print(f"{Fore.GREEN}[✓] JSON Report: {json_report}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] HTML Report: {html_report}{Style.RESET_ALL}")
        
        # Step 6: Summary
        self._display_summary()
    
    def _display_summary(self):
        """Display scan summary"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✅ SCAN COMPLETED SUCCESSFULLY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"📊 Summary:")
        print(f"   • Total Subdomains: {len(self.results['all_subdomains'])}")
        print(f"   • Live Subdomains: {len(self.results['live_subdomains'])}")
        print(f"   • Public IPs: {len(self.results['ip_analysis'].get('public_ips', []))}")
        print(f"   • Private IPs: {len(self.results['ip_analysis'].get('private_ips', []))}")
        
        if self.results['shodan_results']:
            total_cves = sum(len(r.get('cves', [])) for r in self.results['shodan_results'] if 'cves' in r)
            total_ports = sum(len(r.get('ports', [])) for r in self.results['shodan_results'] if 'ports' in r)
            print(f"   • CVEs Found: {total_cves}")
            print(f"   • Open Ports: {total_ports}")
    
    def _display_shodan_summary(self):
        """Display Shodan findings summary"""
        if not self.results.get('shodan_results'):
            return
        
        print(f"\n{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}🔍 SHODAN ANALYSIS RESULTS{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
        
        for result in self.results['shodan_results']:
            if 'error' in result:
                print(f"\n{Fore.RED}⚠️  {result['ip']}: {result['error']}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.GREEN}📍 {result['ip']} ({result.get('subdomain', 'N/A')}){Style.RESET_ALL}")
                print(f"   🏢 Organization: {result.get('org', 'Unknown')}")
                print(f"   💻 OS: {result.get('os', 'Unknown')}")
                
                if result.get('ports'):
                    ports_str = ', '.join(map(str, result['ports'][:15]))
                    if len(result['ports']) > 15:
                        ports_str += f" and {len(result['ports']) - 15} more"
                    print(f"   🔌 Open Ports: {ports_str}")
                else:
                    print(f"   🔌 Open Ports: None found")
                
                if result.get('cves'):
                    print(f"   {Fore.RED}⚠️  CVEs Found: {', '.join(result['cves'][:5])}{Style.RESET_ALL}")
                    if len(result['cves']) > 5:
                        print(f"      ... and {len(result['cves']) - 5} more")
                else:
                    print(f"   {Fore.GREEN}✅ No CVEs reported{Style.RESET_ALL}")

def main():
    """Main entry point"""
    display_banner()
    
    parser = argparse.ArgumentParser(
        description="SubStorm - Advanced Subdomain Enumeration Tool",
        epilog="""
Examples:
  # Quick scan with tiny wordlist (100 subdomains)
  substorm -d example.com -s tiny
  
  # Standard scan with 20,000 subdomains
  substorm -d example.com -s medium
  
  # Deep scan with 100,000 subdomains
  substorm -d example.com -s large
  
  # Use custom wordlist
  substorm -d example.com -w /path/to/wordlist.txt
  
  # Skip API and limit to 50 subdomains
  substorm -d example.com --no-api -m 50
  
  # List available wordlist presets
  substorm --list-wordlists
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-d", "--domain", required=True, help="Target domain (example: example.com)")
    parser.add_argument("-s", "--size", choices=['tiny', 'small', 'medium', 'large', 'full'], 
                        default='small', help="Wordlist size preset (default: small)")
    parser.add_argument("-w", "--wordlist", help="Path to custom wordlist file")
    parser.add_argument("-m", "--max-subdomains", type=int, help="Maximum number of subdomains to find (limits output)")
    parser.add_argument("--no-brute", action="store_true", help="Skip brute force enumeration")
    parser.add_argument("--no-api", action="store_true", help="Skip API enumeration")
    parser.add_argument("--list-wordlists", action="store_true", help="List available wordlist presets")
    
    args = parser.parse_args()
    
    # Handle --list-wordlists
    if args.list_wordlists:
        WordlistManager.list_presets()
        sys.exit(0)
    
    # Ensure cache directory exists
    Config.ensure_cache_dir()
    
    # Validate API keys
    Config.validate_api_keys()
    
    # Check if API keys are needed but missing
    if not args.no_api and not Config.VT_API_WORKING:
        print(f"{Fore.YELLOW}[!] Warning: API enumeration disabled (no valid API keys){Style.RESET_ALL}")
        print(f"    Add API keys to .env file or use --no-api flag\n")
        response = input("Continue without API? (y/n): ").lower()
        if response != 'y':
            sys.exit(0)
    
    # Run the tool
    tool = SubStorm()
    tool.run(
        domain=args.domain,
        wordlist_size=args.size,
        custom_wordlist=args.wordlist,
        skip_brute=args.no_brute,
        skip_api=args.no_api,
        max_subdomains=args.max_subdomains
    )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)
