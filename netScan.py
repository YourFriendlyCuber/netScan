from scapy.all import ARP, Ether, srp
import socket
import argparse

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Addresses')
    options = parser.parse_args()
    
    if not options.target:
        parser.error("[-] Please specifiy an IP Address or Adresses")
    return options

def scan_ip_mac(ip):
    
    #IP and Mac Addresses
    arp = ARP(pdst = ip)
    ether = Ether(dst = "ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []
    
    for sent, recieved in result:
        clients.append({'ip': recieved.psrc, 'mac': recieved.hwsrc})
        
    """
    print("IP" + " "*18+"MAC" + " "*18+"Open Ports")
    for client in clients:
        print("{:16}   {}".format(client['ip'], client['mac']))
    """

    return clients
    
options = get_args()
scan_ip_mac(options.target)