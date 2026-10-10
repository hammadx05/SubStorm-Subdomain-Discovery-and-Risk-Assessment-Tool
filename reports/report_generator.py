"""
Generate comprehensive reports in JSON and HTML formats
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List

class ReportGenerator:
    """Generate detailed reports of scan results"""
    
    @staticmethod
    def generate_json_report(domain: str, results: Dict, output_dir: str = "reports") -> str:
        """Generate JSON report with CDN analysis"""
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        # Separate IPs by CDN status
        cdn_ips = [ip for ip in results.get('ip_analysis', {}).get('public_ips', []) if ip.get('is_cdn', False)]
        origin_ips = [ip for ip in results.get('ip_analysis', {}).get('public_ips', []) if not ip.get('is_cdn', False)]
        
        report = {
            'tool': 'SubStorm',
            'author': 'Muhammad Hammad',
            'target_domain': domain,
            'timestamp': datetime.now().isoformat(),
            'scan_summary': {
                'total_subdomains_found': len(results.get('all_subdomains', [])),
                'live_subdomains': len(results.get('live_subdomains', [])),
                'public_ips': len(results.get('ip_analysis', {}).get('public_ips', [])),
                'private_ips': len(results.get('ip_analysis', {}).get('private_ips', [])),
                'behind_cdn': len(cdn_ips),
                'origin_ips': len(origin_ips)
            },
            'subdomains': {
                'all': results.get('all_subdomains', []),
                'live': results.get('live_subdomains', [])
            },
            'ip_analysis': {
                'private': results.get('ip_analysis', {}).get('private_ips', []),
                'public': results.get('ip_analysis', {}).get('public_ips', []),
                'cdn_breakdown': {
                    'behind_cdn': cdn_ips,
                    'likely_origin': origin_ips
                }
            },
            'shodan_results': results.get('shodan_results', [])
        }
        
        filename = output_dir / f"substorm_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        return str(filename)
    
    @staticmethod
    def generate_html_report(domain: str, results: Dict, output_dir: str = "reports") -> str:
        """Generate HTML report with CDN detection"""
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        # Separate IPs by CDN status
        cdn_ips = [ip for ip in results.get('ip_analysis', {}).get('public_ips', []) if ip.get('is_cdn', False)]
        origin_ips = [ip for ip in results.get('ip_analysis', {}).get('public_ips', []) if not ip.get('is_cdn', False)]
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SubStorm Report - {domain}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 10px; }}
                h1 {{ color: #2c3e50; }}
                .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .public {{ color: #27ae60; }}
                .private {{ color: #e74c3c; }}
                .cdn {{ color: #f39c12; }}
                .origin {{ color: #3498db; }}
                .cve {{ background: #c0392b; color: white; padding: 2px 5px; border-radius: 3px; font-size: 12px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #34495e; color: white; }}
                tr:hover {{ background: #f5f5f5; }}
                .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; }}
                .badge-cdn {{ background: #f39c12; color: white; }}
                .badge-origin {{ background: #3498db; color: white; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>SubStorm Scan Report</h1>
                <p><strong>Target Domain:</strong> {domain}</p>
                <p><strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Author:</strong> Muhammad Hammad</p>
                
                <div class="summary">
                    <h2>Scan Summary</h2>
                    <ul>
                        <li>Total Subdomains Found: {len(results.get('all_subdomains', []))}</li>
                        <li>Live Subdomains: {len(results.get('live_subdomains', []))}</li>
                        <li>Public IPs: {len(results.get('ip_analysis', {}).get('public_ips', []))}</li>
                        <li>Private IPs: {len(results.get('ip_analysis', {}).get('private_ips', []))}</li>
                        <li><strong>Behind CDN/Cloud: {len(cdn_ips)}</strong></li>
                        <li><strong>Likely Origin IPs: {len(origin_ips)}</strong></li>
                    </ul>
                </div>
                
                <h2>Live Subdomains with CDN Detection</h2>
                <table>
                    <tr>
                        <th>Subdomain</th>
                        <th>IP Address</th>
                        <th>Type</th>
                        <th>CDN Status</th>
                        <th>Origin Score</th>
                    </tr>
        """
        
        # Add IP mapping to table
        for sub in results.get('live_subdomains', []):
            # Find IP info
            ip_info = None
            for item in results.get('ip_analysis', {}).get('public_ips', []):
                if item['subdomain'] == sub:
                    ip_info = item
                    break
            for item in results.get('ip_analysis', {}).get('private_ips', []):
                if item['subdomain'] == sub:
                    ip_info = item
                    break
            
            if ip_info:
                ip = ip_info['ip']
                ip_type = 'Private' if ip_info['type'] == 'private' else 'Public'
                cdn_status = ip_info.get('cdn_status', 'Unknown')
                origin_score = ip_info.get('origin_score', 0)
                cdn_badge = '<span class="badge badge-cdn">CDN</span>' if ip_info.get('is_cdn') else '<span class="badge badge-origin">Origin</span>'
                
                html += f"""
                    <tr>
                        <td>{sub}</td>
                        <td>{ip}</td>
                        <td class='{ip_type.lower()}'>{ip_type}</td>
                        <td>{cdn_badge} {cdn_status}</td>
                        <td>{origin_score}%</td>
                    </tr>
                """
        
        html += """
                </table>
                
                <h2>CDN Analysis</h2>
                <div class="summary">
                    <h3>Behind CDN/Cloud Services</h3>
                    <ul>
        """
        
        for ip in cdn_ips:
            html += f"<li>{ip['subdomain']} → {ip['ip']} - {ip.get('cdn_provider', 'Unknown CDN')} (Confidence: {ip.get('cdn_confidence', 0)*100:.0f}%)</li>"
        
        html += """
                    </ul>
                    
                    <h3>Likely Origin IPs</h3>
                    <ul>
        """
        
        for ip in origin_ips:
            html += f"<li>{ip['subdomain']} → {ip['ip']} - {ip.get('cdn_status', 'Origin IP')}</li>"
        
        html += """
                    </ul>
                </div>
                
                <h2>Shodan Results (Public IPs)</h2>
        """
        
        for shodan_result in results.get('shodan_results', []):
            if 'error' not in shodan_result:
                html += f"""
                <div style="margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px;">
                    <h3>{shodan_result.get('ip')} ({shodan_result.get('subdomain', 'N/A')})</h3>
                    <p><strong>Organization:</strong> {shodan_result.get('org', 'Unknown')}</p>
                    <p><strong>Open Ports:</strong> {', '.join(map(str, shodan_result.get('ports', []))) or 'None'}</p>
                    <p><strong>CVEs:</strong> {', '.join(f'<span class="cve">{cve}</span>' for cve in shodan_result.get('cves', [])) or 'None'}</p>
                </div>
                """
        
        html += """
            </div>
        </body>
        </html>
        """
        
        filename = output_dir / f"substorm_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w') as f:
            f.write(html)
        
        return str(filename)
