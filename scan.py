import nmap
import json
import socket
import sys
from typing import Dict, List, Optional
from ollama import chat, generate

MODEL = "mistral:latest"

class PortScanner:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print("Error: Nmap not found.")
            sys.exit(1)
    
    def resolve_hostname(self, host: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            # Check if it's already an IP
            socket.inet_aton(host)
            return host
        except socket.error:
            # It's a hostname, resolve it
            try:
                ip = socket.gethostbyname(host)
                print(f"\n[+] Resolved {host} to {ip}")
                return ip
            except socket.gaierror:
                print(f"\n[-] Could not resolve hostname: {host}")
                return None
    
    def get_scan_type(self) -> tuple:
        """Get scan type from user"""
        print("\n" + "="*50)
        print("SELECT SCAN TYPE")
        print("="*50)
        print("1. Automatic Scan (Most common ports: 1-1024)")
        print("2. Manual Scan (Custom port range)")
        print("3. Complete Scan (All ports: 1-65535)")
        print("="*50)
        
        while True:
            choice = input("\nEnter your choice (1-3): ").strip()
            
            if choice == '1':
                return ('1-1024', 'Automatic')
            elif choice == '2':
                while True:
                    port_range = input("Enter port range (e.g., 20-80, 22,80,443): ").strip()
                    if port_range:
                        return (port_range, 'Manual')
                    print("Invalid input. Please try again.")
            elif choice == '3':
                confirm = input("Warning: Complete scan may take a long time. Continue? (y/n): ").lower()
                if confirm == 'y':
                    return ('1-65535', 'Complete')
                else:
                    continue
            else:
                print("Invalid choice. Please select 1, 2, or 3.")
    
    def scan_ports(self, target: str, port_range: str, scan_type: str) -> Dict:
        """Perform the port scan with service detection"""
        print(f"\n[*] Starting {scan_type} scan on {target}")
        print(f"[*] Scanning ports: {port_range}")
        print("[*] This may take a while...")
        
        try:
            # -sV: Service version detection
            # --version-intensity 5: More aggressive version detection
            self.nm.scan(
                hosts=target,
                ports=port_range,
                arguments='-sV --version-intensity 5'
            )
            
            return self.parse_results(target)
            
        except nmap.PortScannerError as e:
            print(f"\n[-] Scan error: {e}")
            return {}
        except Exception as e:
            print(f"\n[-] Unexpected error: {e}")
            return {}
    
    def parse_results(self, target: str) -> Dict:
        """Parse nmap results into structured format"""
        results = {
            "target": target,
            "scan_info": {},
            "open_ports": []
        }
        
        if target not in self.nm.all_hosts():
            print(f"\n[-] No results found for {target}")
            return results
        
        # Get scan info
        if 'tcp' in self.nm[target]:
            results["scan_info"] = {
                "hostname": self.nm[target].hostname(),
                "state": self.nm[target].state(),
                "protocol": "tcp"
            }
        
        # Parse each port
        for proto in self.nm[target].all_protocols():
            ports = self.nm[target][proto].keys()
            
            for port in sorted(ports):
                port_info = self.nm[target][proto][port]
                
                # Only include open ports
                if port_info['state'] == 'open':
                    port_data = {
                        "port": port,
                        "protocol": proto,
                        "state": port_info['state'],
                        "service": port_info.get('name', 'unknown'),
                        "product": port_info.get('product', ''),
                        "version": port_info.get('version', ''),
                        "extrainfo": port_info.get('extrainfo', ''),
                        "cpe": port_info.get('cpe', '')
                    }
                    
                    results["open_ports"].append(port_data)
        
        return results
    
    def print_results(self, results: Dict):
        """Print results in a formatted way"""

def analyze_vulnerabilities(results: Dict) -> str:
    """Analyze scan results for vulnerabilities using LLM"""
    print("\n" + "="*70)
    print("VULNERABILITY ANALYSIS")
    print("="*70)
    print("\n[*] Analyzing scan results with AI (Mistral)...")
    print("[*] This may take a moment...\n")
    
    system_prompt = """You are an expert cybersecurity analyst specializing in vulnerability assessment and penetration testing. 
Your task is to analyze port scan results and identify potential security vulnerabilities, misconfigurations, and risks.

For each open port and service detected, you should:
1. Identify known vulnerabilities associated with the service, product, and version
2. Assess the severity of potential vulnerabilities (Critical, High, Medium, Low)
3. Provide specific CVE numbers when applicable
4. Suggest exploitation techniques or attack vectors

Be thorough, technical, and prioritize actionable intelligence. Focus on real security concerns. Also provide the output in Bulletins for better readability."""

    # Prepare the scan data for analysis
    user_message = f"""Analyze the following port scan results for security vulnerabilities:

{json.dumps(results, indent=2)}

Provide a comprehensive vulnerability assessment including:
- Critical findings and immediate risks
- Detailed analysis for each exposed service
- Specific CVEs or known vulnerabilities
- Overall security risk rating"""

    try:
        response = chat(
            model=MODEL,
            messages=[
                {
                    'role': 'system',
                    'content': system_prompt
                },
                {
                    'role': 'user',
                    'content': user_message
                }
            ]
        )
        
        analysis = response['message']['content']
        return analysis
        
    except Exception as e:
        return f"Error during vulnerability analysis: {e}\n\nPlease ensure Ollama is running and Mistral model is installed:\n  ollama pull mistral"
        print("SCAN RESULTS")
        print("="*70)
        
        if not results.get("open_ports"):
            print("\n[-] No open ports found.")
            return
        
        print(f"\nTarget: {results['target']}")
        if results.get("scan_info"):
            print(f"Hostname: {results['scan_info'].get('hostname', 'N/A')}")
            print(f"State: {results['scan_info'].get('state', 'N/A')}")
        
        print(f"\nOpen Ports Found: {len(results['open_ports'])}")
        print("\n" + "-"*70)
        
        for port_data in results["open_ports"]:
            print(f"\nPort: {port_data['port']}/{port_data['protocol']}")
            print(f"  State: {port_data['state']}")
            print(f"  Service: {port_data['service']}")
            
            if port_data['product']:
                print(f"  Product: {port_data['product']}")
            if port_data['version']:
                print(f"  Version: {port_data['version']}")
            if port_data['extrainfo']:
                print(f"  Extra Info: {port_data['extrainfo']}")
            if port_data['cpe']:
                print(f"  CPE: {port_data['cpe']}")
        
        print("\n" + "="*70)

def main():
    print("="*70)
    print(" NETWORK PORT SCANNER WITH VULNERABILITY INFORMATION")
    print("="*70)
    print("\nNote: Run with sudo/admin privileges for better results")
    print("      (OS detection and some scans require elevated privileges)")
    
    # Get target
    target_input = input("\nEnter website URL or IP address: ").strip()
    if not target_input:
        print("[-] No target provided. Exiting.")
        sys.exit(1)
    
    # Remove protocol if present
    target_input = target_input.replace('http://', '').replace('https://', '').split('/')[0]
    
    # Initialize scanner
    scanner = PortScanner()
    
    # Resolve hostname
    target_ip = scanner.resolve_hostname(target_input)
    if not target_ip:
        sys.exit(1)
    
    # Get scan type
    port_range, scan_type = scanner.get_scan_type()
    
    # Perform scan
    results = scanner.scan_ports(target_ip, port_range, scan_type)
    
    # Display results
    scanner.print_results(results)
    
    # Analyze vulnerabilities with LLM
    vulnerability_analysis = analyze_vulnerabilities(results)
    print(vulnerability_analysis)
    
    # Add vulnerability analysis to results
    results["vulnerability_analysis"] = vulnerability_analysis
    
    # Print JSON to console
    print("\n" + "="*70)
    print("JSON OUTPUT")
    print("="*70)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Scan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)