Network Vulnerability Scanner
A comprehensive network scanning tool that performs port scanning and vulnerability detection using multiple CVE databases.

Features
Multiple Scan Types
Automatic scan (ports 1-1024)
Manual scan (custom port count)
Custom scan (specific port range with custom nmap arguments)
Vulnerability Detection
VulDB API integration
CVE CIRCL API integration
pyCVESearch library support
Export Capabilities
Export open ports to CSV
Export vulnerabilities to CSV with timestamps
Clean Output
Formatted console output
Progress indicators
Structured vulnerability reports
Prerequisites
Python 3.7 or higher
Nmap installed on your system
Linux: sudo apt-get install nmap
macOS: brew install nmap
Windows: Download from nmap.org
Installation
Clone or download the project files
Install Python dependencies:
bash
pip install -r requirements.txt
Create a .env file in the project directory:
bash
cp .env .env
Edit .env and add your API keys:
VULDB_API_KEY=your_actual_vuldb_api_key
CVE_API_KEY=your_cve_api_key_if_needed
Configuration
Getting API Keys
VulDB API Key (Required for VulDB vulnerability scanning):

Visit VulDB
Create an account
Navigate to API section
Generate your API key
Add it to .env file
CVE CIRCL API (No key required):

The CVE CIRCL API is free and doesn't require authentication
Usage
Run the scanner:

bash
python network_scanner.py
Scan Options
1. Automatic Scan

Scans ports 1-1024
Quick scan for common services
2. Manual Scan

Specify number of ports to scan from port 1
Example: Entering "100" scans ports 1-100
3. Custom Scan

Specify exact port range
Add custom nmap arguments
Example: Ports 80-443 with arguments "-sS -O"
Workflow
Select scan type (1, 2, or 3)
Enter target (IP address or domain name)
Provide scan parameters (if applicable)
View scan results
Choose to save ports for vulnerability scanning
Select vulnerability scanning API (1, 2, or 3)
View vulnerability report
Export results to CSV (optional)
Output Files
open_ports_YYYYMMDD_HHMMSS.csv - List of open ports
vulnerabilities_YYYYMMDD_HHMMSS.csv - Vulnerability details
Security Notes
⚠️ Important Security Considerations:

Never commit .env file - Add it to .gitignore
Keep API keys private - Don't share or expose them
Legal compliance - Only scan systems you own or have permission to test
Ethical use - Use this tool responsibly and legally
Troubleshooting
"Nmap not found"
Ensure nmap is installed and accessible in your PATH
Run nmap --version to verify installation
"DNS lookup failed"
Check target domain/IP is correct
Verify internet connectivity
Try using IP address directly
"Invalid VulDB API key"
Verify API key is correct in .env file
Check API key hasn't expired
Ensure no extra spaces in .env file
"Permission denied" errors
Some scan types require root/administrator privileges
Run with sudo on Linux/macOS: sudo python network_scanner.py
Run as Administrator on Windows
Example Output
============================================================
   NETWORK VULNERABILITY SCANNER
============================================================

Select scan type:
  [1] Automatic scan (ports 1-1024)
  [2] Manual scan (specify port count)
  [3] Custom scan (specify port range and arguments)

Enter choice (1-3): 1

Enter target IP or website: example.com
✓ DNS resolved: example.com → 93.184.216.34

⟳ Scanning ports 1-1024 on 93.184.216.34...

────────────────────────────────────────────────────────────
  SCAN RESULTS
────────────────────────────────────────────────────────────

┌─ Host: 93.184.216.34
│  Hostname: example.com
│  State: up
└─

  Protocol: TCP
  ──────────────────────────────────────────────────
  PORT       STATE        SERVICE
  ──────────────────────────────────────────────────
  80         open         http (Apache 2.4)
  443        open         https (Apache 2.4)
Dependencies
python-nmap: Python wrapper for nmap
requests: HTTP library for API calls
pycvesearch: CVE search library
python-dotenv: Environment variable management
License
This tool is for educational and authorized security testing purposes only.

Disclaimer
This tool should only be used on systems you own or have explicit permission to test. Unauthorized scanning of networks or systems is illegal and unethical. The authors are not responsible for any misuse of this tool.

