"""
CDN and Cloud Service Detection
Identifies if an IP belongs to CloudFlare, AWS, Google Cloud, etc.
"""
import socket
import warnings
import urllib3
from typing import Dict, List, Tuple

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class CDNDetector:
    """Detect if IPs are behind CDN or cloud services"""
    
    # Known CDN and cloud provider IP ranges (simplified)
    CDN_PROVIDERS = {
        'CloudFlare': {
            'name': 'CloudFlare',
            'confidence': 0.95,
            'indicators': ['cloudflare', 'cf-ray'],
            'asns': [13335]
        },
        'AWS CloudFront': {
            'name': 'AWS CloudFront',
            'confidence': 0.90,
            'indicators': ['cloudfront', 'amazonaws.com'],
            'asns': [16509, 14618]
        },
        'Google Cloud CDN': {
            'name': 'Google Cloud CDN',
            'confidence': 0.85,
            'indicators': ['google', 'googleusercontent'],
            'asns': [15169, 396982]
        },
        'Fastly': {
            'name': 'Fastly',
            'confidence': 0.90,
            'indicators': ['fastly'],
            'asns': [54113]
        },
        'Akamai': {
            'name': 'Akamai',
            'confidence': 0.85,
            'indicators': ['akamai', 'akamaiedge'],
            'asns': [16625, 20940]
        },
        'Microsoft Azure': {
            'name': 'Microsoft Azure CDN',
            'confidence': 0.80,
            'indicators': ['azure', 'azureedge', 'windows.net'],
            'asns': [8075]
        }
    }
    
    def __init__(self):
        self.cache = {}
    
    def detect(self, subdomain: str, ip: str) -> Dict:
        """Detect if subdomain is behind CDN/cloud service"""
        cache_key = f"{subdomain}:{ip}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        result = {
            'is_cdn': False,
            'provider': None,
            'confidence': 0.0,
            'evidence': [],
            'is_origin_ip': True
        }
        
        # Method 1: Check reverse DNS
        rDNS_result = self._check_reverse_dns(ip)
        if rDNS_result:
            result['evidence'].append(f"Reverse DNS: {rDNS_result[:50]}")
            for provider, info in self.CDN_PROVIDERS.items():
                if any(indicator in rDNS_result.lower() for indicator in info['indicators']):
                    result['is_cdn'] = True
                    result['provider'] = provider
                    result['confidence'] = max(result['confidence'], info['confidence'])
                    result['is_origin_ip'] = False
        
        # Method 2: Check HTTP headers (if not already detected)
        if not result['is_cdn']:
            headers_result = self._check_http_headers(subdomain)
            if headers_result:
                for header, value in headers_result.items():
                    result['evidence'].append(f"HTTP Header: {header}: {value[:50]}")
                    for provider, info in self.CDN_PROVIDERS.items():
                        if any(indicator in value.lower() for indicator in info['indicators']):
                            result['is_cdn'] = True
                            result['provider'] = provider
                            result['confidence'] = max(result['confidence'], info['confidence'])
                            result['is_origin_ip'] = False
        
        # If no CDN detected, it's likely origin IP
        if not result['is_cdn']:
            result['confidence'] = 0.7
            result['evidence'].append("No CDN fingerprints detected")
        
        self.cache[cache_key] = result
        return result
    
    def _check_reverse_dns(self, ip: str) -> str:
        """Perform reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def _check_http_headers(self, subdomain: str) -> Dict:
        """Check HTTP response headers for CDN indicators"""
        try:
            import requests
            
            for proto in ['https', 'http']:
                try:
                    response = requests.get(
                        f"{proto}://{subdomain}",
                        timeout=5,
                        verify=False,
                        headers={'User-Agent': 'SubStorm-CDN-Detector/1.0'},
                        allow_redirects=True
                    )
                    
                    # Check interesting headers
                    interesting_headers = {}
                    cdn_headers = ['Server', 'CF-Ray', 'X-Cache', 'X-Amz-Cf-Id', 
                                  'X-Akamai-Transformed', 'X-Served-By', 'Via']
                    
                    for header in cdn_headers:
                        if header in response.headers:
                            interesting_headers[header] = response.headers[header]
                    
                    if 'cf-ray' in response.headers:
                        interesting_headers['CF-Ray'] = response.headers['cf-ray']
                    
                    if interesting_headers:
                        return interesting_headers
                except:
                    continue
            return {}
        except:
            return {}
    
    def get_detailed_analysis(self, subdomain: str, ip: str) -> str:
        """Get human-readable analysis"""
        result = self.detect(subdomain, ip)
        
        if result['is_cdn']:
            return f"Behind {result['provider']} (Confidence: {result['confidence']*100:.0f}%)"
        else:
            return f"Likely origin IP (Confidence: {result['confidence']*100:.0f}%)"
    
    def calculate_origin_score(self, subdomain: str, ip: str) -> int:
        """Calculate score indicating how likely this is the origin IP"""
        result = self.detect(subdomain, ip)
        
        if result['is_cdn']:
            score = int((1 - result['confidence']) * 100)
        else:
            score = int(result['confidence'] * 100)
        
        return min(100, max(0, score))
