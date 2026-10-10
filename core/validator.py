"""
Input/output validation with multiple layers
"""
from typing import List, Dict, Any, Optional
import re
import dns.resolver
import dns.exception

class ResultValidator:
    """
    Multi-layer validation to reduce false positives
    Implements 3-layer validation for subdomains
    """
    
    @staticmethod
    def layer_1_dns_check(subdomain: str) -> bool:
        """
        Layer 1: Basic DNS A record check
        Fastest, but can have false positives from wildcards
        """
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            answers = resolver.resolve(subdomain, 'A')
            return len(answers) > 0
        except:
            return False
    
    @staticmethod
    def layer_2_http_check(subdomain: str, timeout: int = 5) -> bool:
        """
        Layer 2: HTTP/HTTPS connectivity
        More reliable but slower
        """
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        
        for protocol in ['https', 'http']:
            try:
                response = requests.get(
                    f"{protocol}://{subdomain}",
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0 (compatible; SubStorm/1.0)'}
                )
                # Valid HTTP response (including 4xx/5xx)
                if response.status_code > 0:
                    return True
            except requests.exceptions.Timeout:
                continue
            except:
                continue
        return False
    
    @staticmethod
    def layer_3_cname_check(subdomain: str) -> bool:
        """
        Layer 3: CNAME record validation
        Helps detect wildcard DNS
        """
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(subdomain, 'CNAME')
            return len(answers) > 0
        except:
            # No CNAME is fine, might be A record directly
            return True
    
    @classmethod
    def validate_subdomain(cls, subdomain: str, required_success_rate: float = 0.7) -> bool:
        """
        Multi-layer validation with configurable confidence threshold
        A subdomain is considered valid if required_success_rate of checks pass
        """
        checks = []
        
        # Layer 1: DNS check (always required)
        dns_valid = cls.layer_1_dns_check(subdomain)
        checks.append(dns_valid)
        
        # If DNS fails, no need to check further
        if not dns_valid:
            return False
        
        # Layer 2: HTTP check (optional but recommended)
        http_valid = cls.layer_2_http_check(subdomain)
        checks.append(http_valid)
        
        # Layer 3: CNAME check
        cname_valid = cls.layer_3_cname_check(subdomain)
        checks.append(cname_valid)
        
        # Calculate success rate
        success_count = sum(1 for check in checks if check)
        success_rate = success_count / len(checks)
        
        return success_rate >= required_success_rate
    
    @staticmethod
    def is_wildcard_dns(domain: str, test_subdomain: str) -> bool:
        """
        Detect wildcard DNS by checking random non-existent subdomain
        """
        import random
        import string
        
        random_sub = ''.join(random.choices(string.ascii_lowercase, k=10))
        test_domain = f"{random_sub}.{domain}"
        
        try:
            # Check if random subdomain resolves
            socket.gethostbyname(test_domain)
            return True  # Wildcard detected
        except:
            return False  # No wildcard
