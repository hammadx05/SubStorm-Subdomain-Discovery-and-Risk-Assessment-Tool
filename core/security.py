"""
Security mechanisms for the tool
- Input sanitization
- Rate limiting protection
- API key management
- Request validation
"""
import re
import hashlib
import hmac
from urllib.parse import urlparse
from typing import Tuple, Optional
from datetime import datetime, timedelta

class SecurityManager:
    """Handles all security-related operations"""
    
    # Security: Blocked patterns for command injection
    BLOCKED_PATTERNS = [
        r'[;&|`$]',           # Shell metacharacters
        r'\.\./',             # Path traversal
        r'[\x00-\x1f\x7f]',   # Control characters
        r'\\x[0-9a-fA-F]{2}', # Hexadecimal encoding
    ]
    
    # Security: Allowed characters for domains
    ALLOWED_DOMAIN_CHARS = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$')
    
    @classmethod
    def sanitize_domain(cls, domain: str) -> Optional[str]:
        """
        Security: Sanitize domain input to prevent injection attacks
        Returns sanitized domain or None if invalid
        """
        if not domain or len(domain) > 253:  # Max domain length
            return None
        
        # Remove whitespace
        domain = domain.strip().lower()
        
        # Check for blocked patterns
        for pattern in cls.BLOCKED_PATTERNS:
            if re.search(pattern, domain):
                return None
        
        # Validate characters
        if not cls.ALLOWED_DOMAIN_CHARS.match(domain):
            return None
        
        # Prevent DNS rebinding attacks
        if cls.is_ip_address(domain):
            return None
        
        return domain
    
    @staticmethod
    def is_ip_address(domain: str) -> bool:
        """Check if input is an IP address instead of domain"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, domain))
    
    @classmethod
    def validate_wordlist(cls, wordlist_path: str) -> Tuple[bool, str]:
        """
        Security: Validate wordlist file before reading
        Returns (is_valid, error_message)
        """
        try:
            from pathlib import Path
            path = Path(wordlist_path)
            
            # Security: Prevent path traversal
            if '..' in str(path):
                return False, "Path traversal detected"
            
            # Check if file exists
            if not path.exists():
                return False, f"File not found: {wordlist_path}"
            
            # Security: Check file size (max 100MB)
            if path.stat().st_size > 100 * 1024 * 1024:
                return False, "Wordlist too large (>100MB)"
            
            # Security: Check if readable
            if not os.access(wordlist_path, os.R_OK):
                return False, "File not readable"
            
            return True, "Valid"
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def rate_limit_protection(requests_made: int, time_window: int, limit: int) -> bool:
        """
        Security: Enforce rate limiting to prevent API abuse
        Returns True if within limit
        """
        return requests_made < limit
    
    @staticmethod
    def mask_api_key(api_key: str) -> str:
        """Security: Mask API key for logging"""
        if len(api_key) <= 8:
            return "****"
        return api_key[:4] + "****" + api_key[-4:]
    
    @staticmethod
    def validate_dns_response(response_data: dict) -> bool:
        """
        Security: Validate DNS response to prevent cache poisoning
        """
        # Check for suspicious TTL values
        if response_data.get('ttl', 0) > 86400:  # TTL > 24 hours is suspicious
            return False
        
        # Check for private IP leakage in public responses
        ip = response_data.get('ip', '')
        if ip.startswith(('10.', '172.16.', '192.168.', '127.')):
            return False
        
        return True
