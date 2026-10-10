"""
ASCII Art Banner Display
"""
from colorama import Fore, Style, init

init(autoreset=True)

def display_banner():
    from config.settings import Config
    	
    """Display tool banner with author info"""
    banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ███████╗██╗   ██╗██████╗ ███████╗████████╗ ██████╗ ██████╗ ███╗   ███╗     ║
║   ██╔════╝██║   ██║██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗████╗ ████║     ║
║   ███████╗██║   ██║██████╔╝███████╗   ██║   ██║   ██║██████╔╝██╔████╔██║     ║
║   ╚════██║██║   ██║██╔══██╗╚════██║   ██║   ██║   ██║██╔══██╗██║╚██╔╝██║     ║
║   ███████║╚██████╔╝██████╔╝███████║   ██║   ╚██████╔╝██║  ██║██║ ╚═╝ ██║     ║
║   ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ║
║                                                                              ║
║                    SUBSTORM - Advanced Subdomain Tool                        ║
║                           by Muhammad Hammad                                 ║
║                              Version 2.0                                     ║
║                                                                              ║
║                  Security Hardened | Multi-threaded                          ║
║                  API Integration | Low False Positives                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
    """
    print(banner)
    
    print(f"{Fore.YELLOW}[!] Security Notice:{Style.RESET_ALL}")
    print("  - API keys loaded from environment variables")
    print("  - Input sanitization enabled")
    print("  - Rate limiting active")
    print("  - Multi-layer validation for reduced false positives")
    print("  - CloudFlare/CDN detection enabled")
    print(f"  - Parallel processing with {Config.MAX_WORKERS} threads")
    print()
