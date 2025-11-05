import os
import time
import subprocess
import ipaddress
import socket
import platform
import threading  # Import threading module for concurrent tasks
from scapy.all import ARP, Ether, srp

# Suspicious ports that are often targeted or associated with attacks
SUSPICIOUS_PORTS = {
    4444: "Metasploit",
    23: "Telnet",
    445: "SMB (Server Message Block)",
    1433: "SQL Server",
    3389: "RDP (Remote Desktop Protocol)",
    21: "FTP",
    22: "SSH",
    3306: "MySQL",
    8080: "HTTP Proxy",
    135: "MS RPC",
    139: "NetBIOS"
}

# Function to get the local network using the local IP address
def get_local_network():
    """
    Automatically determines the local network and subnet mask.
    """
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    subnet = f"{local_ip}/24"
    print(f"Local IP: {local_ip}, Network: {subnet}")
    return subnet

# Function to ping a single host
def ping_host(ip):
    """
    Pings a single host to check if it's alive.
    """
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
    
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    return result.returncode == 0  # Return True if the host is alive

# Function to scan the network for active hosts
def scan_network(network):
    """
    Scans a network to find active hosts by pinging each IP.
    """
    print(f"\nScanning network: {network}")
    net = ipaddress.ip_network(network, strict=False)
    
    active_hosts = []
    threads = []
    
    def scan_ip(ip):
        if ping_host(ip):
            print(f"[+] Active: {ip}")
            active_hosts.append(str(ip))
    
    for ip in net.hosts():
        thread = threading.Thread(target=scan_ip, args=(ip,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()  # Wait for all threads to finish
    
    return active_hosts

# Function to scan ports on a host using Python's socket library
def scan_ports(host, ports):
    """
    Scans common ports on a given host using Python's socket library.
    """
    print(f"\nScanning ports on {host}...")
    suspicious_ports_found = []
    risk_info = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))  # Try to connect to the host and port

            if result == 0:  # If connection is successful, the port is open
                print(f"  [+] Port {port} is open on {host}")
                if port in SUSPICIOUS_PORTS:
                    suspicious_ports_found.append(port)
                    risk_info.append(f"{SUSPICIOUS_PORTS[port]} Port: {port}")
            sock.close()  # Close the socket after the scan
        except Exception as e:
            print(f"  [!] Error scanning port {port} on {host}: {e}")

    return suspicious_ports_found, risk_info

# Function to perform ARP scan for devices on the local network
def arp_scan(network):
    """
    Uses ARP requests to discover devices on the network.
    """
    print(f"\nPerforming ARP scan on network: {network}")
    arp_request = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    result = srp(packet, timeout=2, verbose=0)[0]
    devices = []
    
    for _, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    print("\nDevices found through ARP scan:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

    return [device['ip'] for device in devices]

# Function to create a Notepad file with scan results (acts as a database)
def create_notepad_file(results):
    """
    Appends scan results to a Notepad file with timestamp and space between entries.
    """
    # Get the current date and time
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Define the file path
    file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'scan_results.txt')
    
    # Open the file in append mode to add new scan data
    with open(file_path, 'a') as f:
        f.write(f"\n\n--- Scan started at {timestamp} ---\n\n")  # Add timestamp for each scan
        
        f.write("POTENTIAL RISKS AND VULNERABILITIES\n\n")
        if results:
            for result in results:
                f.write(f"{result}\n")
        else:
            f.write("No potential risks detected.\n")
        
        f.write("\n\n--- End of Scan ---\n\n")
    
    print(f"Results written to {file_path}")

    # Open the results in Notepad (Windows)
    os.startfile(file_path)

# Main function to orchestrate the scanning
def main():
    # Get the local network details
    network = get_local_network()

    # Scan for active hosts using ARP and ICMP ping
    active_hosts = arp_scan(network)
    if not active_hosts:
        active_hosts = scan_network(network)

    # Define a list of common ports to scan
    common_ports = [22, 80, 443, 21, 25, 110, 135, 139, 445, 3306, 8080, 3389]

    # Scan ports for the active hosts
    all_risk_info = []
    for host in active_hosts:
        suspicious_ports, risk_info = scan_ports(host, common_ports)
        if risk_info:
            all_risk_info.extend(risk_info)

    # Create and display the results in a Notepad file
    create_notepad_file(all_risk_info)

if __name__ == "__main__":
    main()
