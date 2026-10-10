#!/bin/bash
# SubStorm Installation Script for Kali Linux
# Updated for Kali's externally-managed Python environment

set -e  # Stop on error

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}
╔═══════════════════════════════════╗
║         SubStorm Installer        ║
║      Subdomain Enumeration Tool   ║
╚═══════════════════════════════════╝
${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}[!] Please don't run as root. Use regular user.${NC}"
   exit 1
fi

# Create directories
echo -e "${GREEN}[*] Creating directories...${NC}"
mkdir -p ~/.substorm/cache
mkdir -p ~/.substorm/wordlists

# Make main script executable
if [ -f "substorm.py" ]; then
    chmod +x substorm.py
    echo -e "${GREEN}[✓] Made substorm.py executable${NC}"
else
    echo -e "${RED}[!] substorm.py not found in current directory${NC}"
    exit 1
fi

# Install Python dependencies using pipx or venv approach
echo -e "${GREEN}[*] Installing Python dependencies...${NC}"

# Check if dependencies are already installed
if python3 -c "import requests, dns.resolver, colorama, aiohttp, dotenv, cryptography, tenacity" 2>/dev/null; then
    echo -e "${GREEN}[✓] All dependencies already installed${NC}"
else
    echo -e "${YELLOW}[*] Installing missing dependencies...${NC}"
    
    # Try different methods for Kali
    if pip3 install --user requests dnspython colorama aiohttp python-dotenv cryptography tenacity 2>/dev/null; then
        echo -e "${GREEN}[✓] Installed with --user flag${NC}"
    else
        echo -e "${YELLOW}[!] Trying with --break-system-packages (Kali specific)...${NC}"
        pip3 install --break-system-packages requests dnspython colorama aiohttp python-dotenv cryptography tenacity
        echo -e "${GREEN}[✓] Installed with --break-system-packages${NC}"
    fi
fi

# Create wrapper script instead of alias (more reliable)
echo -e "${GREEN}[*] Creating global command...${NC}"
sudo bash -c "cat > /usr/local/bin/substorm << 'EOF'
#!/bin/bash
cd $(pwd)
python3 substorm.py \"\$@\"
EOF"

sudo chmod +x /usr/local/bin/substorm
echo -e "${GREEN}[✓] Created 'substorm' command in /usr/local/bin${NC}"

# Download wordlist to user directory (avoid sudo)
WORDLIST_PATH="$HOME/.substorm/wordlists/subdomains.txt"
if [ ! -f "$WORDLIST_PATH" ]; then
    echo -e "${GREEN}[*] Downloading subdomain wordlist...${NC}"
    wget -q --show-progress -O "$WORDLIST_PATH" \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
    echo -e "${GREEN}[✓] Wordlist saved to $WORDLIST_PATH${NC}"
else
    echo -e "${GREEN}[✓] Wordlist already exists${NC}"
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}[!] Creating .env template...${NC}"
    cat > .env << EOF
# SubStorm API Configuration
# Get your free API keys from:
# - VirusTotal: https://www.virustotal.com/gui/my-apikey
# - Shodan: https://account.shodan.io/

VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
EOF
    echo -e "${GREEN}[✓] Created .env file - Edit it to add your API keys${NC}"
else
    echo -e "${GREEN}[✓] .env file already exists${NC}"
fi

# Check if .env has actual keys (not empty)
if grep -q "VIRUSTOTAL_API_KEY=$" .env 2>/dev/null || grep -q "VIRUSTOTAL_API_KEY=\"\"" .env 2>/dev/null; then
    echo -e "${YELLOW}[!] Warning: API keys not configured in .env${NC}"
    echo -e "    Edit .env and add your VirusTotal and Shodan API keys"
fi

# Final message
echo -e "\n${GREEN}╔════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Installation Complete! 🎉      ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════╝${NC}\n"

echo -e "${BLUE}[*] Quick Start:${NC}"
echo -e "    1. ${YELLOW}nano .env${NC} (add your API keys)"
echo -e "    2. ${YELLOW}substorm -d example.com${NC} (or python3 substorm.py -d example.com)"
echo -e "\n${BLUE}[*] Examples:${NC}"
echo -e "    ${YELLOW}substorm -d example.com${NC}                    # Basic scan"
echo -e "    ${YELLOW}substorm -d example.com -w ~/.substorm/wordlists/subdomains.txt${NC}  # With wordlist"
echo -e "    ${YELLOW}python3 substorm.py -d example.com --no-brute${NC}  # Skip brute force"
echo -e "\n${BLUE}[*] Your wordlist is at:${NC}"
echo -e "    ${YELLOW}$WORDLIST_PATH${NC}"
echo -e "\n${BLUE}[*] To update bash alias (optional):${NC}"
echo -e "    ${YELLOW}echo 'alias substorm=\"python3 $(pwd)/substorm.py\"' >> ~/.bashrc${NC}"
echo -e "    ${YELLOW}source ~/.bashrc${NC}\n"
