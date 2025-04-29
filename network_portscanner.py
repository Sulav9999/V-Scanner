from scapy.all import ARP, Ether, srp
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import psutil
from tabulate import tabulate
import sys
import json
import os
from datetime import datetime

# Suppress Scapy warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Common service port mappings
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 115: "SFTP", 123: "NTP",
    139: "NETBIOS", 143: "IMAP", 161: "SNMP", 179: "BGP", 443: "HTTPS",
    445: "SMB", 514: "SYSLOG", 993: "IMAPS", 995: "POP3S", 3306: "MYSQL",
    3389: "RDP", 5432: "POSTGRESQL", 8080: "HTTP-PROXY", 8443: "HTTPS-ALT"
}

# Network Discovery
def get_active_ip_range():
    """
    Automatically detects the primary active network's IP range.
    Excludes virtual adapters and prioritizes internet-connected interfaces.
    """
    try:
        # First attempt to find interfaces with active connections
        for iface, addrs in psutil.net_if_addrs().items():
            # Skip virtual adapters and loopback
            if any(keyword in iface.lower() for keyword in ["vmware", "virtualbox", "vethernet", "tap", "lo", "loopback"]):
                continue
                
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4 only
                    ip = addr.address
                    netmask = addr.netmask
                    
                    # Skip link-local addresses and localhost
                    if not netmask or ip.startswith("169.254") or ip.startswith("127."):
                        continue 
                        
                    # Create network with proper subnet
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    
                    # Skip tiny or huge networks (likely not correct)
                    if network.num_addresses < 2 or network.num_addresses > 65536:
                        continue
                        
                    print(f"Active Interface: {iface}, IP Range: {network}")
                    return str(network)
                    
        # Fallback to manual input if no appropriate interface found
        print("No suitable network interface detected automatically.")
        return input("Please enter your network range manually (e.g., 192.168.1.0/24): ")
        
    except Exception as e:
        print(f"Error detecting active IP range: {e}")
        return input("Please enter your network range manually (e.g., 192.168.1.0/24): ")

def discover_devices(ip_range, timeout=3):
    """
    Scans the given IP range for active devices using ARP requests.
    Returns a list of discovered devices.
    """
    try:
        # Calculate approximate number of hosts to scan
        network = ipaddress.IPv4Network(ip_range)
        if network.num_addresses > 1024:
            confirm = input(f"Warning: You're about to scan {network.num_addresses} addresses. Continue? (y/n): ")
            if confirm.lower() != 'y':
                return []
                
        arp_request = ARP(pdst=ip_range)
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = ether_frame / arp_request
        
        print(f"Scanning network: {ip_range} (timeout: {timeout}s)...")
        answered, _ = srp(arp_request_broadcast, timeout=timeout, verbose=False)

        devices = []
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            try:
                hostname = socket.gethostbyaddr(ip)[0]  # Resolve hostname (with timeout)
            except:
                hostname = "N/A"
                
            # Add device to our results
            devices.append({'IP': ip, 'MAC': mac, 'Hostname': hostname})
            
        return devices
    except Exception as e:
        print(f"Error during network discovery: {e}")
        return []

# Port Scanning Functions
def get_service_name(port):
    """Return the service name for common ports"""
    return COMMON_PORTS.get(port, "Unknown")

def scan_port(ip, port, timeout=1):
    """
    Attempt to connect to a specific port on the target IP.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        
        if result == 0:  # If the connection is successful
            service_name = get_service_name(port)
            banner = get_service_banner(sock)
            
            if banner:
                return port, f"{service_name} - {banner}"
            else:
                return port, service_name
                
        sock.close()
        return None
    except Exception:
        return None

def get_service_banner(sock, timeout=1):
    """
    Attempt to retrieve the service banner from an already connected socket.
    """
    try:
        # Send a simple HTTP GET request for web servers
        if sock.getpeername()[1] in (80, 443, 8080, 8443):
            sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        # Or just wait for banner for other services
        
        sock.settimeout(timeout)
        banner = sock.recv(1024).decode(errors='ignore').strip()
        
        # Truncate long banners
        if len(banner) > 40:
            banner = banner[:37] + "..."
            
        return banner
    except:
        return ""
    finally:
        try:
            sock.close()
        except:
            pass

def scan_ports(ip, port_ranges=None, max_threads=100):
    """
    Scan specific ports or port ranges on the target IP using multi-threading.
    port_ranges can be a list of tuples [(start1, end1), (start2, end2), ...]
    or specific ports [80, 443, 22, ...]
    """
    if port_ranges is None:
        # Default: scan common ports instead of full range for efficiency
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                        443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    elif isinstance(port_ranges[0], tuple):
        # Expand range tuples into a flat list of ports
        ports_to_scan = []
        for start, end in port_ranges:
            ports_to_scan.extend(range(start, end + 1))
    else:
        # Use the provided list of specific ports
        ports_to_scan = port_ranges

    open_ports = []
    futures = []
    
    # Show progress indicator
    total_ports = len(ports_to_scan)
    
    print(f"Scanning {total_ports} ports on {ip}...")
    
    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all scan jobs
            for port in ports_to_scan:
                futures.append(executor.submit(scan_port, ip, port))
            
            # Process results as they complete
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 20 == 0 or completed == total_ports:
                    sys.stdout.write(f"\rProgress: {completed}/{total_ports} ports ({int(completed/total_ports*100)}%)")
                    sys.stdout.flush()
                    
                result = future.result()
                if result is not None:
                    open_ports.append(result)
            
            print()  # New line after progress indicator
    except KeyboardInterrupt:
        print("\nPort scanning interrupted.")
    
    return open_ports

def manual_scan():
    """Allow manual scanning of a specific IP or range"""
    target = input("Enter target IP or network range (e.g., 192.168.1.1 or 192.168.1.0/24): ")
    
    # Check if it's a single IP or range
    try:
        ipaddress.IPv4Address(target)
        # It's a single IP
        print(f"Scanning single IP: {target}")
        devices = [{'IP': target, 'MAC': 'N/A', 'Hostname': 'N/A'}]
    except ValueError:
        # It's a range
        try:
            ipaddress.IPv4Network(target)
            print(f"Scanning network range: {target}")
            devices = discover_devices(target)
        except ValueError:
            print("Invalid IP address or network range.")
            return
    
    # Ask for port scan type
    scan_type = input("Select port scan type:\n1. Common ports only\n2. Full scan (1-1024)\n3. Custom port range\nChoice: ")
    
    if scan_type == '1':
        port_ranges = None  # Will use default common ports
    elif scan_type == '2': 
        port_ranges = [(1, 1024)]
    elif scan_type == '3':
        try:
            custom_range = input("Enter port range (e.g., 80-445,8000-8100): ")
            port_ranges = []
            
            for part in custom_range.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    port_ranges.append((start, end))
                else:
                    port = int(part)
                    port_ranges.append((port, port))
        except:
            print("Invalid port range. Using common ports.")
            port_ranges = None
    else:
        print("Invalid choice. Using common ports.")
        port_ranges = None
    
    # Run the scans
    results = []
    scan_data = []  # For JSON export
    
    for device in devices:
        ip = device['IP']
        open_ports = scan_ports(ip, port_ranges)
        
        # Format open ports into a string for display
        if open_ports:
            ports_str = "\n".join([f"Port {port}: {banner}" for port, banner in open_ports])
        else:
            ports_str = "No open ports found."
        
        # Create structured data for JSON
        ports_data = []
        for port, banner in open_ports:
            service = get_service_name(port)
            # Split the banner from the service if combined format
            if " - " in banner and banner.startswith(service):
                banner = banner[len(service) + 3:]  # Remove "SERVICE - " prefix
            
            ports_data.append({
                "port": port,
                "service": service,
                "banner": banner if banner != service else ""
            })
            
        # Add to results for display
        results.append([device['IP'], device['MAC'], device['Hostname'], ports_str])
        
        # Add to structured data for JSON
        scan_data.append({
            "ip": device['IP'],
            "mac": device['MAC'],
            "hostname": device['Hostname'],
            "open_ports": ports_data
        })
    
    # Display results in table format
    print("\nScan Results:")
    headers = ["IP Address", "MAC Address", "Hostname", "Open Ports"]
    print(tabulate(results, headers=headers, tablefmt="grid"))
    
    # Save to JSON
    save_to_json(scan_data)

def save_to_json(scan_data):
    """Save scan results to a JSON file"""
    # Create reports directory if it doesn't exist
    if not os.path.exists("reports"):
        os.makedirs("reports")
    
    filename = "reports/portscanner.json"
    
    # Prepare the full report data
    report_data = {
        "scan_time": datetime.now().isoformat(),
        "devices": scan_data
    }
    
    # Write to file
    try:
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=4)
        print(f"\nScan results saved to {filename}")
    except Exception as e:
        print(f"\nError saving to JSON file: {e}")

# Main Function
def main():
    """
    Main function to run the automated network discovery and port scanning.
    """
    print("\n==== Advanced Network Scanner ====\n")
    
    try:
        # Offer choice between automatic and manual mode
        mode = input("Select mode:\n1. Auto-detect and scan local network\n2. Manual IP/range entry\nChoice: ")
        
        if mode == '2':
            manual_scan()
            return
            
        # Step 1: Network Discovery
        ip_range = get_active_ip_range()
        devices = discover_devices(ip_range)

        if not devices:
            print("No active devices found in this range.")
            return

        # Step 2: Port Scanning
        results = []
        scan_data = []  # For JSON export
        
        for device in devices:
            ip = device['IP']
            # Scan common ports for efficiency (instead of full 1-1024 range)
            open_ports = scan_ports(ip)

            # Format open ports into a string for display
            if open_ports:
                ports_str = "\n".join([f"Port {port}: {banner}" for port, banner in open_ports])
            else:
                ports_str = "No open ports found."
            
            # Create structured data for JSON
            ports_data = []
            for port, banner in open_ports:
                service = get_service_name(port)
                # Split the banner from the service if combined format
                if " - " in banner and banner.startswith(service):
                    banner = banner[len(service) + 3:]  # Remove "SERVICE - " prefix
                
                ports_data.append({
                    "port": port,
                    "service": service,
                    "banner": banner if banner != service else ""
                })
                
            # Add to results for display
            results.append([device['IP'], device['MAC'], device['Hostname'], ports_str])
            
            # Add to structured data for JSON
            scan_data.append({
                "ip": device['IP'],
                "mac": device['MAC'],
                "hostname": device['Hostname'],
                "open_ports": ports_data
            })

        # Step 3: Display Results in Tabulate Format
        print("\nScan Results:")
        headers = ["IP Address", "MAC Address", "Hostname", "Open Ports"]
        print(tabulate(results, headers=headers, tablefmt="grid"))
        
        # Step 4: Save results to JSON file
        save_to_json(scan_data)
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

if __name__ == "__main__":
    main()