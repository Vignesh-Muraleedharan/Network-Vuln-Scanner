Network Vulnerability Scanner

A lightweight network vulnerability scanner that discovers hosts on a network, enumerates open ports/services, and correlates findings with CVE information. Designed for penetration testers, red teamers, and security hobbyists who want an automated first pass at mapping vulnerabilities in a target network.

Warning: Only scan systems you own or have explicit written permission to test. Unauthorized scanning can be illegal and unethical.

Features

Network host discovery (single IP, range, or CIDR)

Port scanning (via nmap integration)

Service identification and basic banner collection

CVE lookup and context using pycvesearch and external vulnerability databases

CSV output summarizing findings

Configurable via environment variables and .env file

Requirements

Python 3.10+ (3.8+ may work, but 3.10+ recommended)

nmap installed on the system and reachable in PATH

Internet access for CVE lookups (optional if CVE features disabled)

Python packages

The project depends on these packages (install via pip):

python-nmap (or nmap library wrapper)

requests

pycvesearch

python-dotenv

Any other packages used in the repository (check requirements.txt)

If the repo does not include requirements.txt, create it with:

python-nmap
requests
pycvesearch
python-dotenv

Installation

Clone the repository:

git clone https://github.com/Vignesh-Muraleedharan/Network-Vuln-Scanner.git
cd Network-Vuln-Scanner


(Recommended) Create and activate a virtual environment:

python -m venv venv
# Linux/macOS
source venv/bin/activate
# Windows
venv\Scripts\activate


Install Python dependencies:

pip install -r requirements.txt


If requirements.txt is missing, use:

pip install python-nmap requests pycvesearch python-dotenv


Ensure nmap is installed on your system:

Ubuntu/Debian: sudo apt install nmap

macOS (Homebrew): brew install nmap

Windows: download from the official Nmap site and add to PATH

Configuration

The scanner reads API keys and configuration from environment variables. Recommended: create a .env file in the repo root.

Example .env:

VULDB_API_KEY=your_vuldb_api_key   # optional — if used in the code
CVE_API_KEY=your_cve_api_key       # optional — if used by any CVE service
OUTPUT_DIR=./output


Change or add any other variables your code expects.

Usage

Replace scanner.py with your actual main script filename if different.

Basic scan of a single IP:

python scanner.py --target 192.168.1.10


Scan a CIDR range:

python scanner.py --target 192.168.1.0/24


Scan an IP range:

python scanner.py --target 192.168.1.1-254


Examples with options (adjust flags to match actual CLI in repo):

# Save output to a specific CSV
python scanner.py --target 10.0.0.0/24 --output results.csv

# Run a faster, light port scan
python scanner.py --target 10.0.0.5 --scan-type quick

# Enable CVE lookup (if supported)
python scanner.py --target 10.0.0.0/24 --cve-lookup


If the project is structured differently, look for an entrypoint (e.g., main.py, run.py, or scanner/) and adapt commands accordingly.

Output

Typical outputs include:

results.csv — discovered hosts, open ports, services, and associated CVE references

logs/ — runtime logs (if implemented)

output/ — any JSON or additional reports

CSV columns you can expect (example):

host,ip,port,protocol,service,banner,cve_ids,cve_summary,scan_time

How it works (high-level)

Host discovery (ping/ARP/Nmap host discovery)

Port/service scanning with nmap

Service banner grabbing and fingerprinting

CVE lookup via pycvesearch (or other configured API)

Aggregate results and write CSV/report

Troubleshooting

nmap not found: ensure nmap is installed and in your system PATH.

ModuleNotFoundError: run pip install -r requirements.txt and ensure virtualenv is activated.

CVE lookups failing: check your .env API keys, and ensure external services are reachable from your network.

Permission errors: running nmap scans may require elevated privileges for some options — check flags and avoid running as root unless necessary.

Development & Contributing

Contributions welcome. Suggested workflow:

Fork the repo

Create a feature branch (git checkout -b feature/fancy-scan)

Implement changes and add tests if applicable

Open a pull request with a clear description

Please follow standard security practices: avoid committing API keys or secrets.

Security & Legal

This tool is intended for authorized security testing and education. Scanning, probing, or attacking networks you do not own or have permission to test can be illegal. Use responsibly.