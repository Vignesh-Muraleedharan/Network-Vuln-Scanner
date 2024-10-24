import nmap
import socket
import requests
import json
from pycvesearch import CVESearch
import csv

# Function to perform DNS lookup
def dns_lookup(target):
    try:
        # Attempt to resolve the target to an IP address
        ip_address = socket.gethostbyname(target)
        return ip_address
    except socket.gaierror:
        # Handle DNS resolution failure
        print(f"DNS lookup failed for {target}")
        return None

# Function to perform an automatic scan
def scan_automatic(target):
    ip_address = dns_lookup(target)
    if ip_address is None:
        return "Automatic scan failed due to DNS lookup failure."
    
    # Initialize the nmap scanner
    scanner = nmap.PortScanner()
    # Perform the scan on the first 1024 ports with version detection
    scanner.scan(ip_address, '1-1024', arguments='-v -sV')
    return scanner

# Function to perform a manual scan
def scan_manual(target, ports):
    ip_address = dns_lookup(target)
    if ip_address is None:
        return "Manual scan failed due to DNS lookup failure."
    
    # Initialize the nmap scanner
    scanner = nmap.PortScanner()
    # Perform the scan on the specified range of ports with version detection
    port_range = f"1-{ports}"
    scanner.scan(ip_address, port_range, arguments='-v -sV')
    return scanner

# Function to perform a custom scan
def scan_custom(target, port1, port2, arguments):
    ip_address = dns_lookup(target)
    if ip_address is None:
        return "Custom scan failed due to DNS lookup failure."
    
    # Initialize the nmap scanner
    scanner = nmap.PortScanner()
    # Perform the scan on the specified range of ports with custom arguments
    port_range = f"{port1}-{port2}"
    scanner.scan(ip_address, port_range, arguments=f'-v -sV {arguments}')
    return scanner

# Function to print scan results
def print_scan_results(scanner):
    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            lport = scanner[host][proto].keys()
            for port in sorted(lport):
                service = scanner[host][proto][port].get('name', 'unknown')
                print(f"Port: {port}\tState: {scanner[host][proto][port]['state']}\tService: {service}")

# Function to save scanned ports
def save_ports(scanner):
    ports = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            lport = scanner[host][proto].keys()
            for port in sorted(lport):
                ports.append(port)
    return ports

# Function to check vulnerabilities using CVESearch
def check_cve_vulnerabilities_pycvesearch(ports):
    vulnerabilities = []
    cve = CVESearch()
    for port in ports:
        results = cve.search(f"port:{port}")
        if results and 'data' in results:
            vulnerabilities.append({
                'port': port,
                'vulns': results['data']
            })
        else:
            print(f"No vulnerabilities found for port {port}")
    return vulnerabilities

# Function to check vulnerabilities using VulDB
def check_vuldb_vulnerabilities(ports):
    vulnerabilities = []
    api_key = '30098a7fb803136ba5b46e62c9b39a5b'  # Replace with your VulDB API key
    headers = {
        'X-VulDB-ApiKey': api_key,
        'Content-Type': 'application/json'
    }
    for port in ports:
        response = requests.get(f"https://vuldb.com/?api", headers=headers, params={'search': port})
        if response.status_code == 200:
            data = response.json()
            if data.get('result', []):
                vulnerabilities.append({
                    'port': port,
                    'vulns': data['result']
                })
            else:
                print(f"No vulnerabilities found for port {port}")
        else:
            print(f"Error {response.status_code}: Failed to fetch data for port {port}")
    return vulnerabilities

# Function to check vulnerabilities using CVE API
def check_cve_vulnerabilities(ports):
    vulnerabilities = []
    api_key = '859e1d91fdab671de59e5c466507600060f2572beyJzdWIiOjc1ODUsImlhdCI6MTcyOTc4MDI2OSwiZXhwIjoxNzMwMzgzMjAwLCJraWQiOjEsImMiOiI5emtuSHlySWdaZ1AyUWZkWjVSeEx6V0hXeHI0b3BicTRFMzNLZlRaWXQ1b0paV0lOM3FGcmdyVmRXemx6eFwveEppZEoxTEd1In0='  # Replace with your CVE API key
    headers = {
        'Content-Type': 'application/json'
    }
    for port in ports:
        response = requests.get(f"https://cve.circl.lu/api/search/{port}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data:
                vulnerabilities.append({
                    'port': port,
                    'vulns': data
                })
            else:
                print(f"No vulnerabilities found for port {port}")
        else:
            print(f"Error {response.status_code}: Failed to fetch data for port {port}")
    return vulnerabilities

# Main script logic
print("Choose 1 for automatic scan or 2 for manual scan or 3 for custom scan")
choice = int(input())
scanner = None

if choice == 1:
    target = input("Enter the target IP or website: ")
    scanner = scan_automatic(target)

elif choice == 2:
    target = input("Enter the target IP or website: ")
    ports = int(input("Enter the number of ports to scan: "))  # Ensure input is an integer
    scanner = scan_manual(target, ports)

elif choice == 3:
    target = input("Enter the target IP or website: ")
    port1 = int(input("Enter the starting port: "))  # Ensure input is an integer
    port2 = int(input("Enter the ending port: "))  # Ensure input is an integer
    arguments = input("Enter the arguments: ")
    scanner = scan_custom(target, port1, port2, arguments)

else:
    print("Invalid choice")

if scanner:
    print_scan_results(scanner)
    save_choice = input("Do you want to save the output ports for scanning using an API? (yes/no): ").strip().lower()
    if save_choice == 'yes':
        ports = save_ports(scanner)
        print(f"Ports saved: {ports}")
        api_choice = input("Choose the API to use for vulnerability check (1 for VulDB, 2 for CVE, 3 for pyCVESearch): ").strip()
    else:
        print("Ports not saved.")
        api_choice = None

    if save_choice == 'yes':
        if api_choice == '1':
            vulnerabilities = check_vuldb_vulnerabilities(ports)
            if vulnerabilities:
                for vuln in vulnerabilities:
                    print(f"Port: {vuln['port']}")
                    for cve in vuln['vulns']:
                        print(f"CVE ID: {cve['cve']['CVE_data_meta']['ID']}")
                        print(f"Description: {cve['cve']['description']['description_data'][0]['value']}")
                        print(f"Published Date: {cve['publishedDate']}")
                        print(f"Last Modified Date: {cve['lastModifiedDate']}")
                        print("-" * 40)
            else:
                print("No vulnerabilities found.")
        elif api_choice == '2':
            cve_vulnerabilities = check_cve_vulnerabilities(ports)
            if cve_vulnerabilities:
                for vuln in cve_vulnerabilities:
                    print(f"Port: {vuln['port']}")
                    for cve in vuln['vulns']:
                        print(f"CVE ID: {cve['id']}")
                        print(f"Summary: {cve['summary']}")
                        print(f"Published Date: {cve['Published']}")
                        print(f"Last Modified Date: {cve['Modified']}")
                        print("-" * 40)
            else:
                print("No CVE vulnerabilities found.")
        elif api_choice == '3':
            cve_vulnerabilities_pycvesearch = check_cve_vulnerabilities_pycvesearch(ports)
            if cve_vulnerabilities_pycvesearch:
                for vuln in cve_vulnerabilities_pycvesearch:
                    print(f"Port: {vuln['port']}")
                    for cve in vuln['vulns']:
                        print(f"CVE ID: {cve['id']}")
                        print(f"Summary: {cve['summary']}")
                        print(f"Published Date: {cve['Published']}")
                        print(f"Last Modified Date: {cve['Modified']}")
                        print("-" * 40)
            else:
                print("No CVE vulnerabilities found.")
        else:
            print("Invalid API choice.")
    else:
        print("Ports not saved.")

def export_ports_to_csv(ports, filename='open_ports.csv'):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Port'])
        for port in ports:
            writer.writerow([port])
    print(f"Ports have been exported to {filename}")

# Main script logic continuation
if save_choice == 'yes' and ports:
    export_choice = input("Do you want to export the open ports to a CSV file? (yes/no): ").strip().lower()
    if export_choice == 'yes':
        export_ports_to_csv(ports)
    else:
        print("Ports not exported.")