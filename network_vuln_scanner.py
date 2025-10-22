import nmap
import socket
import requests
import json
from pycvesearch import CVESearch
import csv
import os
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables from .env file
load_dotenv()

# ==================== CONFIGURATION ====================
VULDB_API_KEY = os.getenv('VULDB_API_KEY')
CVE_API_KEY = os.getenv('CVE_API_KEY')

# ==================== UTILITY FUNCTIONS ====================
def print_banner():
    """Print application banner"""
    print("=" * 60)
    print("   NETWORK VULNERABILITY SCANNER")
    print("=" * 60)
    print()

def print_section(title):
    """Print section header"""
    print("\n" + "─" * 60)
    print(f"  {title}")
    print("─" * 60)

# ==================== DNS & SCANNING FUNCTIONS ====================
def dns_lookup(target):
    """Perform DNS lookup for target"""
    try:
        ip_address = socket.gethostbyname(target)
        print(f"✓ DNS resolved: {target} → {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f"✗ DNS lookup failed for {target}")
        return None

def scan_automatic(target):
    """Perform automatic scan on first 1024 ports"""
    ip_address = dns_lookup(target)
    if ip_address is None:
        return None
    
    print(f"\n⟳ Scanning ports 1-1024 on {ip_address}...")
    scanner = nmap.PortScanner()
    try:
        scanner.scan(ip_address, '1-1024', arguments='-v -sV')
        return scanner
    except Exception as e:
        print(f"✗ Scan failed: {e}")
        return None

def scan_manual(target, ports):
    """Perform manual scan on specified number of ports"""
    ip_address = dns_lookup(target)
    if ip_address is None:
        return None
    
    print(f"\n⟳ Scanning ports 1-{ports} on {ip_address}...")
    scanner = nmap.PortScanner()
    try:
        port_range = f"1-{ports}"
        scanner.scan(ip_address, port_range, arguments='-v -sV')
        return scanner
    except Exception as e:
        print(f"✗ Scan failed: {e}")
        return None

def scan_custom(target, port1, port2, arguments):
    """Perform custom scan with specified port range and arguments"""
    ip_address = dns_lookup(target)
    if ip_address is None:
        return None
    
    print(f"\n⟳ Scanning ports {port1}-{port2} on {ip_address}...")
    scanner = nmap.PortScanner()
    try:
        port_range = f"{port1}-{port2}"
        scanner.scan(ip_address, port_range, arguments=f'-v -sV {arguments}')
        return scanner
    except Exception as e:
        print(f"✗ Scan failed: {e}")
        return None

# ==================== RESULT DISPLAY FUNCTIONS ====================
def print_scan_results(scanner):
    """Print formatted scan results"""
    print_section("SCAN RESULTS")
    
    for host in scanner.all_hosts():
        print(f"\n┌─ Host: {host}")
        print(f"│  Hostname: {scanner[host].hostname()}")
        print(f"│  State: {scanner[host].state()}")
        print("└─")
        
        for proto in scanner[host].all_protocols():
            print(f"\n  Protocol: {proto.upper()}")
            print("  " + "─" * 50)
            print(f"  {'PORT':<10} {'STATE':<12} {'SERVICE'}")
            print("  " + "─" * 50)
            
            lport = scanner[host][proto].keys()
            for port in sorted(lport):
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port].get('name', 'unknown')
                product = scanner[host][proto][port].get('product', '')
                version = scanner[host][proto][port].get('version', '')
                
                service_info = service
                if product:
                    service_info += f" ({product}"
                    if version:
                        service_info += f" {version}"
                    service_info += ")"
                
                print(f"  {port:<10} {state:<12} {service_info}")

def save_ports(scanner):
    """Extract and save open ports from scan results"""
    ports = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            lport = scanner[host][proto].keys()
            for port in sorted(lport):
                if scanner[host][proto][port]['state'] == 'open':
                    ports.append(port)
    return ports

# ==================== VULNERABILITY CHECK FUNCTIONS ====================
def check_vuldb_vulnerabilities(ports):
    """Check vulnerabilities using VulDB API"""
    if not VULDB_API_KEY or VULDB_API_KEY == 'your_vuldb_api_key_here':
        print("✗ VulDB API key not configured in .env file")
        return []
    
    vulnerabilities = []
    headers = {
        'X-VulDB-ApiKey': VULDB_API_KEY,
        'Content-Type': 'application/json'
    }
    
    print(f"\n⟳ Checking vulnerabilities for {len(ports)} ports using VulDB...")
    
    for port in ports:
        try:
            response = requests.get(
                "https://vuldb.com/?api",
                headers=headers,
                params={'search': port},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('result', []):
                    vulnerabilities.append({
                        'port': port,
                        'vulns': data['result']
                    })
            elif response.status_code == 401:
                print("✗ Invalid VulDB API key")
                return []
        except requests.exceptions.RequestException as e:
            print(f"✗ Request error for port {port}: {e}")
    
    return vulnerabilities

def check_cve_vulnerabilities(ports):
    """Check vulnerabilities using CVE CIRCL API"""
    vulnerabilities = []
    headers = {'Content-Type': 'application/json'}
    
    print(f"\n⟳ Checking vulnerabilities for {len(ports)} ports using CVE API...")
    
    for port in ports:
        try:
            response = requests.get(
                f"https://cve.circl.lu/api/search/{port}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data:
                    vulnerabilities.append({
                        'port': port,
                        'vulns': data
                    })
        except requests.exceptions.RequestException as e:
            print(f"✗ Request error for port {port}: {e}")
    
    return vulnerabilities

def check_cve_vulnerabilities_pycvesearch(ports):
    """Check vulnerabilities using pyCVESearch"""
    vulnerabilities = []
    
    print(f"\n⟳ Checking vulnerabilities for {len(ports)} ports using pyCVESearch...")
    
    try:
        cve = CVESearch()
        for port in ports:
            try:
                results = cve.search(f"port:{port}")
                if results and 'data' in results:
                    vulnerabilities.append({
                        'port': port,
                        'vulns': results['data']
                    })
            except Exception as e:
                print(f"✗ Error searching CVE for port {port}: {e}")
    except Exception as e:
        print(f"✗ Failed to initialize CVESearch: {e}")
    
    return vulnerabilities

# ==================== VULNERABILITY DISPLAY FUNCTIONS ====================
def display_vuldb_vulnerabilities(vulnerabilities):
    """Display VulDB vulnerability results"""
    print_section("VULDB VULNERABILITY REPORT")
    
    if not vulnerabilities:
        print("\n✓ No vulnerabilities found")
        return
    
    total_vulns = sum(len(v['vulns']) for v in vulnerabilities)
    print(f"\n⚠ Found {total_vulns} vulnerabilities across {len(vulnerabilities)} ports\n")
    
    for vuln in vulnerabilities:
        print(f"\n┌─ PORT {vuln['port']}")
        for idx, cve in enumerate(vuln['vulns'], 1):
            try:
                cve_id = cve.get('cve', {}).get('CVE_data_meta', {}).get('ID', 'N/A')
                desc = cve.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', 'N/A')
                pub_date = cve.get('publishedDate', 'N/A')
                mod_date = cve.get('lastModifiedDate', 'N/A')
                
                print(f"│\n│  [{idx}] {cve_id}")
                print(f"│      Published: {pub_date}")
                print(f"│      Modified: {mod_date}")
                print(f"│      Description: {desc[:100]}...")
            except (KeyError, IndexError) as e:
                print(f"│  Error parsing vulnerability data: {e}")
        print("└─" + "─" * 58)

def display_cve_vulnerabilities(vulnerabilities):
    """Display CVE vulnerability results"""
    print_section("CVE VULNERABILITY REPORT")
    
    if not vulnerabilities:
        print("\n✓ No vulnerabilities found")
        return
    
    total_vulns = sum(len(v['vulns']) for v in vulnerabilities)
    print(f"\n⚠ Found {total_vulns} vulnerabilities across {len(vulnerabilities)} ports\n")
    
    for vuln in vulnerabilities:
        print(f"\n┌─ PORT {vuln['port']}")
        for idx, cve in enumerate(vuln['vulns'], 1):
            cve_id = cve.get('id', 'N/A')
            summary = cve.get('summary', 'N/A')
            pub_date = cve.get('Published', 'N/A')
            mod_date = cve.get('Modified', 'N/A')
            
            print(f"│\n│  [{idx}] {cve_id}")
            print(f"│      Published: {pub_date}")
            print(f"│      Modified: {mod_date}")
            print(f"│      Summary: {summary[:100]}...")
        print("└─" + "─" * 58)

# ==================== EXPORT FUNCTIONS ====================
def export_ports_to_csv(ports, filename='open_ports.csv'):
    """Export open ports to CSV file"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"open_ports_{timestamp}.csv"
        
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Port', 'Status'])
            for port in ports:
                writer.writerow([port, 'open'])
        
        print(f"\n✓ Ports exported to {filename}")
    except Exception as e:
        print(f"\n✗ Error exporting ports: {e}")

def export_vulnerabilities_to_csv(vulnerabilities, filename='vulnerabilities.csv'):
    """Export vulnerabilities to CSV file"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerabilities_{timestamp}.csv"
        
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Port', 'CVE ID', 'Summary', 'Published', 'Modified'])
            
            for vuln in vulnerabilities:
                for cve in vuln['vulns']:
                    cve_id = cve.get('id', 'N/A')
                    summary = cve.get('summary', 'N/A')
                    published = cve.get('Published', 'N/A')
                    modified = cve.get('Modified', 'N/A')
                    writer.writerow([vuln['port'], cve_id, summary, published, modified])
        
        print(f"✓ Vulnerabilities exported to {filename}")
    except Exception as e:
        print(f"✗ Error exporting vulnerabilities: {e}")

# ==================== MAIN PROGRAM ====================
def main():
    """Main program execution"""
    print_banner()
    
    # Scan type selection
    print("Select scan type:")
    print("  [1] Automatic scan (ports 1-1024)")
    print("  [2] Manual scan (specify port count)")
    print("  [3] Custom scan (specify port range and arguments)")
    print()
    
    try:
        choice = int(input("Enter choice (1-3): "))
    except ValueError:
        print("✗ Invalid input. Please enter a number.")
        return
    
    scanner = None
    
    if choice == 1:
        target = input("\nEnter target IP or website: ").strip()
        scanner = scan_automatic(target)
    
    elif choice == 2:
        target = input("\nEnter target IP or website: ").strip()
        try:
            ports = int(input("Enter number of ports to scan: "))
            scanner = scan_manual(target, ports)
        except ValueError:
            print("✗ Invalid port number")
            return
    
    elif choice == 3:
        target = input("\nEnter target IP or website: ").strip()
        try:
            port1 = int(input("Enter starting port: "))
            port2 = int(input("Enter ending port: "))
            arguments = input("Enter additional nmap arguments (optional): ").strip()
            scanner = scan_custom(target, port1, port2, arguments)
        except ValueError:
            print("✗ Invalid port numbers")
            return
    
    else:
        print("✗ Invalid choice")
        return
    
    if not scanner:
        print("\n✗ Scan failed")
        return
    
    # Display scan results
    print_scan_results(scanner)
    
    # Save ports
    print("\n" + "=" * 60)
    save_choice = input("\nSave ports for vulnerability scanning? (yes/no): ").strip().lower()
    
    if save_choice != 'yes':
        print("\n✓ Scan complete")
        return
    
    ports = save_ports(scanner)
    if not ports:
        print("\n✗ No open ports found")
        return
    
    print(f"\n✓ Found {len(ports)} open ports: {ports}")
    
    # Vulnerability scanning
    print("\nSelect vulnerability scanning API:")
    print("  [1] VulDB")
    print("  [2] CVE CIRCL")
    print("  [3] pyCVESearch")
    print()
    
    api_choice = input("Enter choice (1-3): ").strip()
    
    vulnerabilities = []
    
    if api_choice == '1':
        vulnerabilities = check_vuldb_vulnerabilities(ports)
        if vulnerabilities:
            display_vuldb_vulnerabilities(vulnerabilities)
    
    elif api_choice == '2':
        vulnerabilities = check_cve_vulnerabilities(ports)
        if vulnerabilities:
            display_cve_vulnerabilities(vulnerabilities)
    
    elif api_choice == '3':
        vulnerabilities = check_cve_vulnerabilities_pycvesearch(ports)
        if vulnerabilities:
            display_cve_vulnerabilities(vulnerabilities)
    
    else:
        print("✗ Invalid API choice")
        return
    
    # Export options
    print("\n" + "=" * 60)
    export_ports_choice = input("\nExport open ports to CSV? (yes/no): ").strip().lower()
    if export_ports_choice == 'yes':
        export_ports_to_csv(ports)
    
    if vulnerabilities:
        export_vulns_choice = input("Export vulnerabilities to CSV? (yes/no): ").strip().lower()
        if export_vulns_choice == 'yes':
            export_vulnerabilities_to_csv(vulnerabilities)
    
    print("\n✓ Scan complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()