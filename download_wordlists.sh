#!/bin/bash
# Download comprehensive wordlists for better subdomain discovery

WORDLIST_DIR="$HOME/.substorm/wordlists"
mkdir -p "$WORDLIST_DIR"

echo "[*] Downloading comprehensive wordlists..."

# Download multiple wordlists for better coverage
echo "[1/4] Downloading SecLists subdomain list (20,000 entries)..."
wget -q --show-progress -O "$WORDLIST_DIR/subdomains-seclists.txt" \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt

echo "[2/4] Downloading bitquark subdomain list (100,000 entries)..."
wget -q --show-progress -O "$WORDLIST_DIR/subdomains-bitquark.txt" \
    https://raw.githubusercontent.com/bitquark/dnspop/master/results/bitquark_subdomains_2016.txt

echo "[3/4] Downloading commonspeak2 wordlist..."
wget -q --show-progress -O "$WORDLIST_DIR/subdomains-commonspeak2.txt" \
    https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt

echo "[4/4] Creating combined wordlist (best for coverage)..."
cat "$WORDLIST_DIR"/*.txt | sort -u > "$WORDLIST_DIR/subdomains-all.txt"
wc -l "$WORDLIST_DIR/subdomains-all.txt"

echo "[✓] Wordlists downloaded to $WORDLIST_DIR"
echo "[*] Use the combined wordlist with: -w $WORDLIST_DIR/subdomains-all.txt"
