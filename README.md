# 🔍 SubStorm - Advanced Subdomain Enumeration Tool

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Compatible-blueviolet)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-2.0-red)
![Visitors](https://visitor-badge.laobi.icu/badge?page_id=hammadx05.substorm)


**by Muhammad Hammad**

</div>

---

## 📌 Overview

SubStorm is a **professional-grade subdomain enumeration tool** designed for security researchers, penetration testers, and bug bounty hunters. It combines multiple discovery methods with intelligent validation to deliver accurate results with minimal false positives.

### Why SubStorm?

- **Low False Positives** - Multi-layer validation before declaring a subdomain live
- **High Performance** - 100+ concurrent threads for blazing fast enumeration
- **Security Hardened** - Input sanitization, rate limiting, and API key protection
- **CDN Detection** - Identifies if IPs are behind CloudFlare, AWS, etc.
- **Comprehensive Reports** - JSON & HTML output with detailed analysis
- **Credit Conscious** - Optimized Shodan lookups for free tier users

---

## ✨ Features

| Category | Features |
|----------|----------|
| **Subdomain Discovery** | • Wordlist brute force (5 presets: 100 to 200k+ words)<br>• VirusTotal API integration<br>• Common prefix scanning |
| **Validation** | • 3-layer live checking (DNS, HTTP, TCP)<br>• Wildcard DNS detection<br>• Duplicate elimination |
| **IP Analysis** | • Public vs Private IP classification<br>• CDN/Cloud provider detection<br>• Origin IP scoring |
| **Vulnerability Intel** | • Shodan integration for open ports<br>• CVE vulnerability detection<br>• Organization & OS fingerprinting |
| **Reporting** | • JSON format for automation<br>• HTML format with visual styling<br>• Console color-coded output |

---

## 🚀 Quick Installation

### Kali Linux / Debian-based Systems

```bash
# Clone the repository
git clone https://github.com/hammadx05/SubStorm-Advanced-Subdomain-Enumeration-Tool.git
cd substorm

# Make installer executable and run
chmod +x setup.sh
./setup.sh

# Or install manually
pip3 install -r requirements.txt --break-system-packages
chmod +x substorm.py
```

### Manual Installation

```bash
# Install Python dependencies
pip3 install requests dnspython colorama aiohttp python-dotenv cryptography tenacity

# Download wordlists (optional)
python3 download_wordlists.py

# Create .env file for API keys (optional)
cp .env.example .env
```

---

## 🔑 API Configuration (Optional)

Create a `.env` file in the root directory:

```env
# VirusTotal API Key (Free tier: 500 requests/day)
# Get from: https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=your_key_here

# Shodan API Key (Free tier: 30 lookups/month)
# Get from: https://account.shodan.io/
SHODAN_API_KEY=your_key_here
```

> **Note:** The tool works perfectly without API keys. Only brute force enumeration will be used.

---

## 📖 Usage Guide

### Basic Commands

```bash
# Quick scan with tiny wordlist (100 subdomains)
python3 substorm.py -d example.com -s tiny

# Standard scan with 20,000 subdomains
python3 substorm.py -d example.com -s medium

# Deep scan with 100,000 subdomains
python3 substorm.py -d example.com -s large

# Limit results to 50 subdomains
python3 substorm.py -d example.com -s medium -m 50

# Use custom wordlist
python3 substorm.py -d example.com -w /path/to/wordlist.txt

# Skip API enumeration (brute force only)
python3 substorm.py -d example.com --no-api

# Skip brute force (API only)
python3 substorm.py -d example.com --no-brute
```

### Wordlist Presets

| Preset | Size | Description | Use Case |
|--------|------|-------------|----------|
| `tiny` | 100 | Built-in common prefixes | Quick reconnaissance |
| `small` | 5,000 | SecLists top 5k | Standard scanning |
| `medium` | 20,000 | SecLists top 20k | Extended enumeration |
| `large` | 100,000 | Bitquark dataset | Deep reconnaissance |
| `full` | 200,000+ | Commonspeak2 | Comprehensive audit |

### Help Menu

```bash
python3 substorm.py -h
```

```
usage: substorm.py [-h] -d DOMAIN [-s {tiny,small,medium,large,full}] 
                   [-w WORDLIST] [-m MAX_SUBDOMAINS] [--no-brute] [--no-api] 
                   [--list-wordlists]

SubStorm - Advanced Subdomain Enumeration Tool

options:
  -h, --help            Show this help message
  -d DOMAIN, --domain DOMAIN
                        Target domain (example: example.com)
  -s {tiny,small,medium,large,full}, --size {tiny,small,medium,large,full}
                        Wordlist size preset (default: small)
  -w WORDLIST, --wordlist WORDLIST
                        Path to custom wordlist file
  -m MAX_SUBDOMAINS, --max-subdomains MAX_SUBDOMAINS
                        Maximum number of subdomains to find
  --no-brute            Skip brute force enumeration
  --no-api              Skip API enumeration
  --list-wordlists      List available wordlist presets

Examples:
  substorm -d example.com -s tiny
  substorm -d example.com -s medium -m 50
  substorm -d example.com --no-api
```

---

## 🧠 Technical Deep Dive

### How Subdomain Validation Works

SubStorm uses a **3-layer validation system** to eliminate false positives:

```
Layer 1: DNS Resolution
    ↓
Layer 2: HTTP/HTTPS Connectivity
    ↓
Layer 3: TCP Port Check (80/443)
    ↓
Result: Live (if ≥2 layers pass)
```

**Why this matters:**
- **Wildcard DNS** can make non-existent subdomains appear to resolve
- **HTTP checks** verify actual web servers are responding
- **TCP checks** catch services on non-standard ports

### CDN Detection Mechanism

The tool identifies when IPs are behind Content Delivery Networks:

| Method | What it checks |
|--------|----------------|
| **Reverse DNS** | Hostname contains `cloudflare`, `fastly`, `akamai`, etc. |
| **HTTP Headers** | Presence of `CF-Ray`, `X-Cache`, `X-Amz-Cf-Id` |
| **Response Analysis** | Server headers indicating CDN services |

**Output Example:**
```
[PUBLIC] www.example.com -> 104.18.32.12 [Behind CloudFlare (Confidence: 95%)]
[PUBLIC] origin.example.com -> 192.0.2.1 [Likely origin IP (Confidence: 70%)]
```

### Shodan Credit Optimization

For free tier users (30 credits/month), SubStorm intelligently conserves credits:

```
Found: 20 subdomains → 13 live → 8 unique public IPs → 8 Shodan lookups
                                                         ↓
                                            (instead of 13, saving 5 credits)
```

**Optimizations applied:**
- Only checks LIVE subdomains (not dead ones)
- Deduplicates IP addresses (multiple subdomains on same IP = 1 lookup)
- Configurable max lookups (default: 30)

### Multi-threading Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Main Thread                       │
└─────────────────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
   ┌─────────┐     ┌─────────┐     ┌─────────┐
   │Thread 1 │     │Thread 2 │     │Thread N │  (MAX_WORKERS = 100)
   │DNS Check│     │DNS Check│     │DNS Check│
   └─────────┘     └─────────┘     └─────────┘
        │                │                │
        └────────────────┼────────────────┘
                         ▼
              Results aggregated in real-time
```

---

## 📄 Output Structure

### Console Output (Color-coded)

```
[LIVE] www.example.com          (Green - Active)
[DEAD] old.example.com          (Red - Inactive)
[PUBLIC] api.example.com -> 1.2.3.4  (Cyan - Public IP)
[PRIVATE] internal.example.com -> 10.0.0.1  (Magenta - Private IP)
```

### JSON Report

```json
{
  "target_domain": "example.com",
  "scan_summary": {
    "total_subdomains_found": 45,
    "live_subdomains": 23,
    "behind_cdn": 12,
    "origin_ips": 11
  },
  "ip_analysis": {
    "cdn_breakdown": {
      "behind_cdn": [...],
      "likely_origin": [...]
    }
  },
  "shodan_results": [...]
}
```

### HTML Report

- Visual summary cards
- Color-coded subdomain tables
- CDN detection badges
- Shodan findings section

---

## 📁 Directory Structure

```
substorm/
├── substorm.py              # Main entry point
├── setup.sh                 # Installation script
├── requirements.txt         # Python dependencies
├── .env                     # API keys (create this)
├── config/
│   ├── settings.py          # Configuration management
├── core/
│   ├── banner.py            # ASCII banner display
│   ├── security.py          # Input sanitization
│   ├── validator.py         # Multi-layer validation
├── modules/
│   ├── subdomain/           # Brute force & API enumeration
│   ├── live_checker/        # Liveness verification
│   ├── ip_analyzer/         # IP classification & CDN detection
│   └── shodan/              # Shodan API integration
├── utils/
│   ├── cache.py             # Caching mechanism
│   ├── ratelimiter.py       # Rate limiting
│   └── wordlist_manager.py  # Wordlist downloading
├── reports/                 # Generated reports
└── tests/                   # Unit tests
```

---

## 📊 Performance Benchmarks

| Operation | Threads | Time (example.com) |
|-----------|---------|--------------------|
| 5,000 DNS lookups | 100 | ~30 seconds |
| 20,000 DNS lookups | 100 | ~2 minutes |
| Live check (100 subs) | 100 | ~5 seconds |
| IP resolution (50 IPs) | 100 | ~2 seconds |

---

## ❓ Troubleshooting

| Issue | Solution |
|-------|----------|
| `externally-managed-environment` | Use `pip3 install --break-system-packages` or `--user` |
| `ModuleNotFoundError` | Run `pip3 install -r requirements.txt` |
| Shodan 401 error | API key invalid - check `.env` file |
| No subdomains found | Target may have wildcard DNS or try larger wordlist |
| Rate limiting errors | Free API tiers have limits - wait or upgrade |

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Additional API sources (SecurityTrails, AlienVault, Censys)
- Passive DNS database integration
- Screenshot capture for live subdomains
- Port scanning integration
- Slack/Discord webhook notifications

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [SecLists](https://github.com/danielmiessler/SecLists) for wordlists
- [VirusTotal](https://www.virustotal.com/) for API
- [Shodan](https://www.shodan.io/) for vulnerability data
- [dnspython](https://www.dnspython.org/) for DNS resolution

---

<div align="center">

**Built by Muhammad Hammad**

[Report Bug](https://github.com/hammadx05/SubStorm-Advanced-Subdomain-Enumeration-Tool/issues) · [Request Feature](https://github.com/hammadx05/SubStorm-Advanced-Subdomain-Enumeration-Tool/issues)

</div>