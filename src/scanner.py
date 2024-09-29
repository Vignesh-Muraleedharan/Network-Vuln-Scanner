import nmap
nm = nmap.PortScanner()
target = input("Enter the target IP address: ")
nm.scan(target, '1-1024')
print(nm)