import scapy.all as scapy
import csv
import os
import time
import sys
import threading
import socket
import requests
import platform
import netifaces
import subprocess

start_time = time.time()
countdown_time = 60 # seconds
BLOCKED_IPS = []    
BLOCKED_ICMP_TYPES = []
BLOCKED_dPORTS = []
BLOCKED_sPORTS = []
ip_mac_dict = {}
system_platform = platform.system()
stop_event = threading.Event() 

file_url = r"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt"
response = requests.get(file_url)
if response.status_code == 200:
    file_content = response.text
    fetched_blocked_ips_list = [line.split()[0] for line in file_content.splitlines() if line and not line.startswith("#")]
    BLOCKED_IPS.extend(fetched_blocked_ips_list)
    print(f"Successfully downloaded Malicious {len(BLOCKED_IPS)} IPs list")
    
else:
    print(f"Failed to download file: Status code {response.status_code}")

print("Malicious IPs:")
for i in range(len(BLOCKED_IPS)):
        BLOCKED_IPS[i] = str(BLOCKED_IPS[i])
        print(BLOCKED_IPS[i])
print(f"Loaded {len(BLOCKED_IPS)} malicious IPs")

# create a log txt file that logs all netwrk traffic
cwd = os.getcwd()
file_path = os.path.join(cwd, "connection_log.csv")
connection_log = open(file_path, "w")
writer = csv.DictWriter(connection_log, fieldnames=["[Packet No.]","[Resource]","[URL]","[Protocol]","[Source Port]", "[Destination Port]", "[Time {dd/mm/yy | day | hh:mm:ss (GMT)}]", "[Blocked]", "[DATA]"])  
writer.writeheader()

def countdown():
    global countdown_time
    while countdown_time >= 0:
        print(f"Time remaining: {countdown_time} seconds")
        countdown_time -= 1
        time.sleep(1)
    stop_event.set()


thread = threading.Thread(target=countdown)
thread.start()
PACKET_COUNTER = 0

def stop_sniffing(packet):
    return stop_event.is_set()
    
    
def packet_sniffer(packet):
    global PACKET_COUNTER
    PACKET_COUNTER += 1

    detect_arp_spoofing(packet)

    url = "Unknown"
    if scapy.IP in packet:
        try:
            url = socket.gethostbyaddr(packet[scapy.IP].dst)[0]
        except (socket.herror, socket.gaierror, AttributeError):
            url = "Unknown"

        

    if (scapy.IP in packet and (packet[scapy.IP].src in BLOCKED_IPS or packet[scapy.IP].dst in BLOCKED_IPS)) or \
        (scapy.TCP in packet and (packet[scapy.TCP].sport in BLOCKED_sPORTS or packet[scapy.TCP].dport in BLOCKED_dPORTS)) or \
        (scapy.UDP in packet and (packet[scapy.UDP].sport in BLOCKED_sPORTS or packet[scapy.UDP].dport in BLOCKED_dPORTS)) or \
        (scapy.ICMP in packet and (packet[scapy.ICMP].type in BLOCKED_ICMP_TYPES)):

        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
            RPKT = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src) / scapy.TCP(sport=packet[scapy.TCP].dport, dport=packet[scapy.TCP].sport, flags="R")
            scapy.send(RPKT)
            ip = [packet[scapy.IP].src, packet[scapy].IP.dst]
            for ip in BLOCKED_IPS:
                if system_platform == "Linux":
                    os.system(f"iptables -A INPUT -s {ip} -j DROP")
                    os.system(f"iptables -A OUTPUT -d {ip} -j DROP")
                    print(f"Blocked IP: {ip} using iptables")
                elif system_platform == "Windows":
                    os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}")
                    os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=out action=block remoteip={ip}")
                    print(f"Blocked IP: {ip} using Windows Firewall")
                elif system_platform == "Darwin":
                    subprocess.run(["sudo", "pfctl", "-t", "blocked_ips", "-T", "add", BLOCKED_IPS], check=True)
                    subprocess.run(["sudo", "pfctl", "-f", "/etc/pf.conf"], check=True) 
                else:
                    print(f"Allowed connection from {packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'unknown'} to {packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'unknown'}")
                
        elif packet.haslayer(scapy.IP) and packet.haslayer(scapy.UDP):
            RPKT = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src)
            scapy.send(RPKT)
            print(f"Blocked connection from {packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'unknown'} to {packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'unknown'}")
        elif scapy.ICMP in packet and packet[scapy.ICMP].type in BLOCKED_ICMP_TYPES:
            RPKT = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src) / scapy.ICMP(type=3, code=3)
            scapy.send(RPKT)
            print(f"Blocked ICMP from {packet[scapy.IP].src} to {packet[scapy.IP].dst}")
        else:
            print(f"Allowed connection from {packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'unknown'} to {packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'unknown'}")

# Fallback for packets that do not match any of the above conditions
    if not packet.haslayer(scapy.IP):
        print(f"Non-IP packet detected: {packet.summary()}")



    protocol = ('TCP' if packet.haslayer(scapy.TCP)
                else 'UDP' if packet.haslayer(scapy.UDP)
                else 'ICMP' if packet.haslayer(scapy.ICMP)
                else 'Unknown')
    
    source_port = (packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) 
                   else packet[scapy.UDP].sport if packet.haslayer(scapy.UDP) 
                   else packet[scapy.ICMP].type if packet.haslayer(scapy.ICMP) 
                   else 'Unknown')
    destination_port = (packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) 
                        else packet[scapy.UDP].dport if packet.haslayer(scapy.UDP) 
                        else 'N/A' if packet.haslayer(scapy.ICMP) 
                        else 'Unknown')
    time_now = time.strftime('%d/%m/%y | %A | %H:%M:%S', time.gmtime())


    blocked = (
            "Yes(ip)" if packet.haslayer(scapy.IP) and packet[scapy.IP].src in BLOCKED_IPS else
            "Yes(dPort)" if (
                (packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport in BLOCKED_dPORTS) or
                (packet.haslayer(scapy.UDP) and packet[scapy.UDP].dport in BLOCKED_dPORTS) or
                (packet.haslayer(scapy.ICMP) and packet[scapy.ICMP].type in BLOCKED_dPORTS)
            ) else
            "Yes(sPort)" if (
                (packet.haslayer(scapy.TCP) and packet[scapy.TCP].sport in BLOCKED_sPORTS) or
                (packet.haslayer(scapy.UDP) and packet[scapy.UDP].sport in BLOCKED_sPORTS) or
                (packet.haslayer(scapy.ICMP) and packet[scapy.ICMP].type in BLOCKED_sPORTS)
            ) else
            "No")
    
    writer.writerow({
        "[Packet No.]" : f"{PACKET_COUNTER}",
        "[Resource]": f"[{packet.summary()}]",
        "[URL]": f"[{url}]",
        "[Protocol]": f"{protocol}",
        "[Source Port]": f"{source_port}",
        "[Destination Port]": f"{destination_port}",
        "[Time {dd/mm/yy | day | hh:mm:ss (GMT)}]": f"{time_now}",                
        "[Blocked]": f"{blocked}",
        "[DATA]" : f"{packet.show()}"
        })
        
    connection_log.flush()

    print(f"""
    ───────────────────────────────────────────
    Packet No:      {PACKET_COUNTER}
    Source IP:      {packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'Unknown'}
    Destination IP: {packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'Unknown'}
    Protocol:       {protocol}
    Source Port:    {source_port}
    Destination Port: {destination_port}
    URL:            {url}
    Time:           {time_now}
    Blocked:        {blocked}
    ───────────────────────────────────────────
    """, flush= True)

def detect_arp_spoofing(packet):
        try :
            if packet.haslayer(scapy.ARP):
                mac_addr = packet[scapy.ARP].hwsrc
                ip_addr = packet[scapy.ARP].psrc
                if mac_addr and ip_addr:
                    if ip_addr in ip_mac_dict:
                        current_macs = ip_mac_dict[ip_addr]
                        if mac_addr not in current_macs:
                            current_macs.append(mac_addr)
                            print(f" WARNING : Potential ARP SPOOFING DETECTED ip : {ip_addr} and mac : {mac_addr}")
                        else:
                            print(f"Network is Safe")
                    else:
                        ip_mac_dict[ip_addr] = [mac_addr]
                elif mac_addr and not ip_addr:
                    print(f"counld't get ip address for mac : {mac_addr}")
                else:
                    print(f"counld't get mac address for ip : {ip_addr}")
            else:
                print("packet does not have ARP layer")
        except Exception as e:
            print(f" Error getting ARP Packet : {e}")



def get_local_network():
    try: 
        interface = netifaces.gateways()['default'][netifaces.AF_INET][1] 
        addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        ip = addresses['addr'] 
        netmask = addresses['netmask']
        cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
        network_range = f"{ip}/{cidr}"
        return network_range, interface
    except Exception as e:
        print(f"Error getting network details {e}")

def network_scan(interface):
    network_range, _ = get_local_network()
    if not network_range or not interface:
        print("Failed to determine network range or interface")
        return []
    print(f"\nScanning Network: {network_range} on {interface}...\n")
    try:
        arp_request = scapy.ARP(pdst=network_range)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request
        answered, _ = scapy.srp(packet, iface=interface, timeout=5, verbose=False)
        devices = []
        for sent, received in answered:
            devices.append({"ip": received.psrc, "mac": received.hwsrc})
            print(f"Discovered - IP: {received.psrc}, MAC: {received.hwsrc}")
        print(f"Scan complete. Found {len(devices)} devices.")
        return devices
    except Exception as e:
        print(f"Error during network scan: {e}")
        return []

def reset_firewall():
    system_platform = platform.system()

    if system_platform == "Linux":
        os.system("sudo iptables -F && sudo iptables -X && sudo iptables -Z")
        os.system("sudo iptables -P INPUT ACCEPT && sudo iptables -P OUTPUT ACCEPT && sudo iptables -P FORWARD ACCEPT")
        print("iptables reset to default")

    elif system_platform == "Darwin" :
        os.system("sudo pfctl -F all && sudo pfctl -f /etc/pf.conf && sudo pfctl -e")
        print("PF reset to default")

    elif system_platform == "Windows":
        os.system("netsh advfirewall reset")
        print("Windows Firewall reset to default")

    else:
        print("Unsupported OS")

def filter():
    network_range, interface = get_local_network()
    if interface:
        scapy.sniff(prn=packet_sniffer, stop_filter=stop_sniffing, store=False)

def main():
    network_range, interface = get_local_network()
    if interface:
        devices = network_scan(interface)
        for device in devices:
            ip_mac_dict[device["ip"]] = [device["mac"]]
        print(f"Initial ip_mac_dict: {ip_mac_dict}")
    try:
        filterThread = threading.Thread(target=filter)
        filterThread.start()
        filterThread.join()
    
    except KeyboardInterrupt:
        print("Exiting...")
        stop_event.set()  
        reset_firewall()
        sys.exit(1)
    
    finally:
        connection_log.close()
        reset_firewall()
        print(f"Connection log saved to {file_path}")
        sys.exit(0)

if __name__ == "__main__":
    main()