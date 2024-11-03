from scapy.all import ARP, Ether, srp
import socket
import argparse
import tkinter as tk
from tkinter import ttk
from concurrent.futures import ThreadPoolExecutor, as_completed

# Dictionary for well-known ports and services
port_services = {
    20: 'FTP', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    445: 'SMB', 3389: 'RDP'
}

# Load MAC vendor information
def load_vendors():
    vendors = {}
    try:
        with open("mac_vendors.txt", "r") as file:
            for line in file:
                parts = line.strip().split(None, 1)  # Split into prefix and vendor
                if len(parts) == 2:
                    mac_prefix, vendor = parts
                    vendors[mac_prefix.replace(":", "").upper()] = vendor
    except FileNotFoundError:
        print("Warning: mac_vendors.txt file not found. Vendor information will not be available.")
    return vendors

# Get vendor from MAC address prefix
def get_vendor(mac, vendors):
    mac_prefix = mac.upper().replace(":", "")[:6]
    return vendors.get(mac_prefix, "Unknown Vendor")

# Parse 
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target Network in CIDR notation, e.g., 192.168.1.0/24')
    options = parser.parse_args()
    
    if not options.target:
        parser.error("[-] Please specify a network in CIDR notation.")
    return options

# Scan single port for IP address
def scan_single_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            service = port_services.get(port, 'Unknown')
            return (port, service)
    except Exception:
        pass
    return None

# Scan (1-1024) 
def scan_ports(ip):
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:  # Adjust max_workers as needed
        futures = [executor.submit(scan_single_port, ip, port) for port in range(1, 1025)]
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports

# Discover devices and perform port scanning
def scan_ip_mac(ip, vendors):
    print("[*] Starting ARP scan on network:", ip)
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]
    clients = []
    scanned_ips = set() 

    for sent, received in result:
        if received.psrc not in scanned_ips:  # Check if IP already been scanned
            print(f"[+] Device found: {received.psrc} - {received.hwsrc}")
            open_ports = scan_ports(received.psrc)
            vendor = get_vendor(received.hwsrc, vendors)
            print(f"[*] Open ports for {received.psrc}: {[(p[0], p[1]) for p in open_ports]}")
            clients.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'vendor': vendor,
                'open_ports': open_ports
            })
            scanned_ips.add(received.psrc)  
    return clients

# Save to HTML file
def save_results(clients):
    with open("devices.html", "w") as file:
        file.write("<html><head><title>Network Scan Results</title></head><body>")
        file.write("<h2>Network Scan Results</h2>")
        file.write("<table border='1'><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Open Ports (Service)</th></tr>")
        
        for client in clients:
            open_ports_services = ', '.join([f"{p[0]} ({p[1]})" for p in client['open_ports']])
            file.write(f"<tr><td>{client['ip']}</td><td>{client['mac']}</td><td>{client['vendor']}</td><td>{open_ports_services}</td></tr>")
        
        file.write("</table></body></html>")

# GUI tkinter
def display_results(clients):
    root = tk.Tk()
    root.title("Network Scan Results")

    tree = ttk.Treeview(root, columns=("IP", "MAC", "Vendor", "Open Ports (Service)"), show="headings")
    tree.heading("IP", text="IP")
    tree.heading("MAC", text="MAC")
    tree.heading("Vendor", text="Vendor")
    tree.heading("Open Ports (Service)", text="Open Ports (Service)")
    tree.pack(fill=tk.BOTH, expand=True)

    for client in clients:
        open_ports_services = ', '.join([f"{p[0]} ({p[1]})" for p in client['open_ports']])
        tree.insert("", "end", values=(client['ip'], client['mac'], client['vendor'], open_ports_services))
    
    root.mainloop()

# Main program 
if __name__ == "__main__":
    vendors = load_vendors()
    options = get_args()
    clients = scan_ip_mac(options.target, vendors)
    save_results(clients)  
    display_results(clients)  
    print("[*] Network scan completed. Results saved to 'devices.html'.")