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
connection_log = None
writer = None
file_path = None
PACKET_COUNTER = 0
To_spy = True

def get_malicious_ips():  
        try:
            response = requests.get(file_url)
            if response.status_code == 200:
                file_content = response.text
                fetched_blocked_ips_list = [line.split()[0] for line in file_content.splitlines() if line and not line.startswith("#")]
                BLOCKED_IPS.extend(fetched_blocked_ips_list)
                print(f"Successfully downloaded Malicious {len(BLOCKED_IPS)} IPs list")
                
            else:
                print(f"Failed to download file: Status code {response.status_code}")
        except requests.RequestException as e:
            print(f"Error fetching blocked IPs: {e}")
        
        print("Malicious IPs:")
        for i in range(len(BLOCKED_IPS)):
                BLOCKED_IPS[i] = str(BLOCKED_IPS[i])
                print(BLOCKED_IPS[i])
        print(f"Loaded {len(BLOCKED_IPS)} malicious IPs")

# create a log txt file that logs all netwrk traffic
def log_file_creation():
        global connection_log, writer, file_path
        try :
            cwd = os.path.dirname(os.path.abspath(__file__))
        except NameError:
            cwd = os.getcwd()
        filetype = "csv"
        file_path = os.path.join(cwd, f"connection_log.{filetype}")
        connection_log = open(file_path, "w")
        writer = csv.DictWriter(connection_log, fieldnames=["[Packet No.]","[Resource]","[URL/IP]","[Protocol]","[Source Port]", "[Destination Port]", "[Time {dd/mm/yy | day | hh:mm:ss (GMT)}]", "[Blocked]", "[DATA]"])  
        writer.writeheader()


def countdown():
    global countdown_time
    while countdown_time >= 0 and not stop_event.is_set():
        print(f"Time remaining: {countdown_time} seconds")
        countdown_time -= 1
        time.sleep(1)
    if countdown_time < 0:
        print("Countdown finished. Stopping sniffer...")
        stop_event.set()

def stop_sniffing(packet):
    return stop_event.is_set()
    
    
def packet_sniffer(packet):  
    global PACKET_COUNTER
    PACKET_COUNTER += 1

    detect_arp_spoofing(packet)

    ip = None
    if packet.haslayer(scapy.IP):
         ip = packet[scapy.IP].dst
    elif packet.haslayer(scapy.IPv6):
        ip = packet[scapy.IPv6].dst
    url = "Unknown"
    if ip:
        try:
            url = socket.gethostbyaddr(ip)[0]
        except (socket.herror):
            try:
                url = socket.getnameinfo((ip,0),socket.NI_NAMEREQD)[0]
            except Exception as e :
                print(f"error {e} fetching URL/IP")
                url = ip
         
    src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else packet[scapy.IPv6].src if packet.haslayer(scapy.IPv6) else "unknown"
    dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else packet[scapy.IPv6].dst if packet.haslayer(scapy.IPv6) else "unknown"
    if  (packet.haslayer(scapy.IP) and (src_ip in BLOCKED_IPS or dst_ip in BLOCKED_IPS)) or \
        (packet.haslayer(scapy.IPv6) and (src_ip in BLOCKED_IPS or dst_ip in BLOCKED_IPS)) or \
        (packet.haslayer(scapy.TCP) and (packet[scapy.TCP].sport in BLOCKED_sPORTS or packet[scapy.TCP].dport in BLOCKED_dPORTS)) or \
        (packet.haslayer(scapy.UDP) and (packet[scapy.UDP].sport in BLOCKED_sPORTS or packet[scapy.UDP].dport in BLOCKED_dPORTS)) or \
        (packet.haslayer(scapy.ICMP) and (packet[scapy.ICMP].type in BLOCKED_ICMP_TYPES)) or \
        (packet.haslayer(scapy.IPv6) and scapy.Raw in packet and packet[scapy.IPv6].nh == 58 and get_ICMPv6(packet) in BLOCKED_ICMP_TYPES):

        def block_ips(packet_ips):
         for ip in packet_ips:
                if ip in BLOCKED_IPS:
                    try:
                        if system_platform == "Linux":
                            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                            subprocess.run(["sudo","iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
                            print(f"Blocked IP: {ip} using iptables")
                        elif system_platform == "Windows":
                            subprocess.run(["netsh", "advfirewall", "firewall", "add" ,"rule", f"name=Block {ip}", "dir=in", "action=block", f"remoteip={ip}"], check=True)
                            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block {ip}", "dir=out", "action=block" ,f"remoteip={ip}"], check=True)
                            print(f"Blocked IP: {ip} using Windows Firewall")
                        elif system_platform == "Darwin":
                            subprocess.run(["sudo", "pfctl", "-t", "blocked_ips", "-T", "add", ip], check=True)
                            print(f"Blocked IP: {ip} using SkyFireWall (pfctl)")
                        else:
                            print(f"Allowed connection from {src_ip} to {dst_ip}")
                    except subprocess.CalledProcessError as se:
                        print(f"Failed to block IP {ip}: {se}")
                    except Exception  as e:
                        print(f"Failed to block IP {ip}: {e}")


        if ((packet.haslayer(scapy.IP) or packet.haslayer(scapy.IPv6)) and packet.haslayer(scapy.TCP)):
            if (packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP)):
                RPKT = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src) / scapy.TCP(sport=packet[scapy.TCP].dport, dport=packet[scapy.TCP].sport, flags="R")
                packet_ips = [packet[scapy.IP].src, packet[scapy.IP].dst]
            elif ((packet.haslayer(scapy.IPv6) and packet.haslayer(scapy.TCP))):
                RPKT = scapy.IPv6(src=packet[scapy.IPv6].dst, dst=packet[scapy.IPv6].src) / scapy.TCP(sport=packet[scapy.TCP].dport, dport=packet[scapy.TCP].sport, flags="R")
                packet_ips = [packet[scapy.IPv6].src, packet[scapy.IPv6].dst]
            scapy.send(RPKT, verbose = False)
            block_ips(packet_ips)
            if packet[scapy.TCP].sport in BLOCKED_sPORTS:
                try:
                    if system_platform == "Darwin":
                        subprocess.run(["sudo", "pfctl", "-t", "blocked_sports", "-T", "add", str(packet[scapy.TCP].sport)], check=True)
                        print(f"Blocked source port: {packet[scapy.TCP].sport} using SkyFireWall (pfctl)")
                except subprocess.CalledProcessError as se:
                            print(f"Failed to block source port {packet[scapy.TCP].sport}: {se}")
                except Exception  as e:
                            print(f"Failed to block source port {packet[scapy.TCP].sport}: {e}")

            if packet[scapy.TCP].dport in BLOCKED_dPORTS:
                try:
                    if system_platform == "Darwin":
                        subprocess.run(["sudo", "pfctl", "-t", "blocked_dports", "-T", "add", str(packet[scapy.TCP].dport)], check=True)
                        print(f"Blocked destination port: {packet[scapy.TCP].dport} using SkyFireWall (pfctl)")
                except subprocess.CalledProcessError as se:
                            print(f"Failed to block destination port {packet[scapy.TCP].dport}: {se}")
                except Exception  as e:
                            print(f"Failed to block destination port {packet[scapy.TCP].dport}: {e}")
                
        elif ((packet.haslayer(scapy.IP) or packet.haslayer(scapy.IPv6)) and packet.haslayer(scapy.UDP)):
            if((packet.haslayer(scapy.IP) and packet.haslayer(scapy.UDP))):
                 RPKT = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src) / scapy.ICMP(type=3, code =3)
                 packet_ips = [packet[scapy.IP].src, packet[scapy.IP].dst]
            elif ((packet.haslayer(scapy.IPv6) and packet.haslayer(scapy.UDP))):
                 RPKT = scapy.IPv6(src=packet[scapy.IPv6].dst, dst=packet[scapy.IPv6].src) / scapy.ICMPv6DestUnreach(code = 4)
                 packet_ips = [packet[scapy.IPv6].src, packet[scapy.IPv6].dst]
            scapy.send(RPKT, verbose = False)
            block_ips(packet_ips)
            if packet[scapy.UDP].sport in BLOCKED_sPORTS:
                try:
                    if system_platform == "Darwin":
                        subprocess.run(["sudo", "pfctl", "-t", "blocked_sports", "-T", "add", str(packet[scapy.UDP].sport)], check=True)
                        print(f"Blocked source port: {packet[scapy.UDP].sport} using SkyFireWall (pfctl)")
                except subprocess.CalledProcessError as se:
                            print(f"Failed to block source port {packet[scapy.UDP].sport}: {se}")
                except Exception  as e:
                            print(f"Failed to block source port {packet[scapy.UDP].sport}: {e}")

            if packet[scapy.UDP].dport in BLOCKED_dPORTS:
                try:
                    if system_platform == "Darwin":
                        subprocess.run(["sudo", "pfctl", "-t", "blocked_dports", "-T", "add", str(packet[scapy.UDP].dport)], check=True)
                        print(f"Blocked destination port: {packet[scapy.UDP].dport} using SkyFireWall (pfctl)")
                except subprocess.CalledProcessError as se:
                            print(f"Failed to block destination port {packet[scapy.UDP].dport}: {se}")
                except Exception  as e:
                            print(f"Failed to block destination port {packet[scapy.UDP].dport}: {e}")
            print(f"Blocked connection from {packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'unknown'} to {packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'unknown'}")

        elif (((packet.haslayer(scapy.IP) or (packet.haslayer(scapy.IPv6))) and \
             ((scapy.ICMP in packet and packet[scapy.ICMP].type) or \
             (packet[scapy.IPv6].nh == 58 and get_ICMPv6(packet))) \
             in BLOCKED_ICMP_TYPES)):
            if ((packet.haslayer(scapy.IP) and (scapy.ICMP in packet and packet[scapy.ICMP].type in BLOCKED_ICMP_TYPES))):
                RPKT = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src) / scapy.ICMP(type=3, code=3)
                packet_ips = [packet[scapy.IP].dst, packet[scapy.IP].src]
                scapy.send(RPKT, verbose = False)
                print(f"Blocked ICMP from {src_ip} to {dst_ip}")
            elif ((packet.haslayer(scapy.IPv6) and (packet[scapy.IPv6].nh == 58 and get_ICMPv6(packet)in BLOCKED_ICMP_TYPES))):
                RPKT = scapy.IPv6(src=packet[scapy.IPv6].dst, dst=packet[scapy.IPv6].src) / scapy.ICMPv6DestUnreach(code=4)
                scapy.send(RPKT, verbose = False)
                packet_ips = [packet[scapy.IPv6].dst, packet[scapy.IPv6].src]
            block_ips(packet_ips)
            print(f"Blocked ICMP from {src_ip} to {dst_ip}")
        else:
            print(f"Allowed connection from {packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'unknown'} to {packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'unknown'}")

# Fallback for packets that do not match any of the above conditions
    if not packet.haslayer(scapy.IP) and not packet.haslayer(scapy.IPv6):
        print(f"Non-IP packet detected: {packet.summary()}")

    def get_ICMPv6(packet):
         if (packet[scapy.IPv6].nh == 58 and packet.haslayer(scapy.IPv6)):
              ipv6layer = packet[scapy.IPv6].payload
              if hasattr(ipv6layer,"type"):
                   return ipv6layer.type
              elif packet.haslayer(scapy.Raw):
                   raw_data = packet[scapy.Raw].load
                   return raw_data[0] if len(raw_data) > 0 else "Unknown"
              return "Unknown"
         return "Unknown"

    protocol = ('TCP' if packet.haslayer(scapy.TCP)
                else 'UDP' if packet.haslayer(scapy.UDP)
                else 'ICMPv4' if packet.haslayer(scapy.ICMP)
                else "ICMPv6" if (packet.haslayer(scapy.IPv6) and packet[scapy.IPv6].nh == 58)
                else "ARP" if packet.haslayer(scapy.ARP)
                else 'Unknown')
    
    source_port = (packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) 
                   else packet[scapy.UDP].sport if packet.haslayer(scapy.UDP) 
                   else f"ICMP Type {packet[scapy.ICMP].type}" if packet.haslayer(scapy.ICMP) 
                   else f"ICMPv6 Type {get_ICMPv6(packet)}" if (packet.haslayer(scapy.IPv6) and packet[scapy.IPv6].nh == 58)
                   else 'Unknown')
    destination_port = (packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) 
                        else packet[scapy.UDP].dport if packet.haslayer(scapy.UDP) 
                        else f"ICMPv4 Type {packet[scapy.ICMP].type}" if packet.haslayer(scapy.ICMP)
                        else f"ICMPv6 Type {get_ICMPv6(packet)}" if (packet.haslayer(scapy.IPv6) and packet[scapy.IPv6].nh == 58)
                        else 'Unknown')
    
    time_now = time.strftime('%d/%m/%y | %A | %H:%M:%S', time.gmtime())+ f".{time.time_ns() % 1_000_000_000:09d}"


    blocked = (
            "Yes(ip)" if packet.haslayer(scapy.IP) and packet[scapy.IP].src in BLOCKED_IPS 
            else
            "Yes(dPort)" if (
                (packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport in BLOCKED_dPORTS) or
                (packet.haslayer(scapy.UDP) and packet[scapy.UDP].dport in BLOCKED_dPORTS)
            )
            else 
            "Yes(ICMP)" if (
                 (packet.haslayer(scapy.IP) and (scapy.ICMP in packet and packet[scapy.ICMP].type in BLOCKED_ICMP_TYPES)) or
                 (packet.haslayer(scapy.IPv6) and (packet[scapy.IPv6].nh == 58 and get_ICMPv6(packet) in BLOCKED_ICMP_TYPES))
            )
            else
            "Yes(sPort)" if (
                (packet.haslayer(scapy.TCP) and packet[scapy.TCP].sport in BLOCKED_sPORTS) or
                (packet.haslayer(scapy.UDP) and packet[scapy.UDP].sport in BLOCKED_sPORTS)
            )
            else
            "No"
    )
            
    
    writer.writerow({
        "[Packet No.]" : f"{PACKET_COUNTER}",
        "[Resource]": f"[{packet.summary()}]",
        "[URL/IP]": f"[{url}]",
        "[Protocol]": f"{protocol}",
        "[Source Port]": f"{source_port}",
        "[Destination Port]": f"{destination_port}",
        "[Time {dd/mm/yy | day | hh:mm:ss (GMT)}]": f"{time_now}",                
        "[Blocked]": f"{blocked}",
        "[DATA]" : f"{packet.show(dump = True)}"
        })
        
    connection_log.flush()

    print(f"""
    ───────────────────────────────────────────
    Packet No:      {PACKET_COUNTER}
    Source IP:      {src_ip}
    Destination IP: {dst_ip}
    Protocol:       {protocol}
    Source Port:    {source_port}
    Destination Port: {destination_port}
    URL/IP:            {url}
    Time:           {time_now}
    Blocked:        {blocked}
    ───────────────────────────────────────────
    """, flush= True)
       
    def spy(To_spy):
         if To_spy:
              try:
                   cwd = os.path.dirname(os.path.abspath(__file__))
              except NameError:
                   cwd = os.getcwd()
              file_type = "JSON"
              SpyPath = os.path.join(cwd,f"SpyFile.{file_type}")  
              if packet.haslayer(scapy.Raw): 
                with open(SpyPath, "w") as SpyFile:
                    writeSpy = csv.DictWriter(SpyFile, fieldnames=["Packet No.","Packet Summary","Time", "Data"])
                    writeSpy.writeheader()
                    writeSpy.writerow(
                            {
                                "Packet No." : PACKET_COUNTER,
                                "Packet Summary" : packet.summary(),
                                "Time": f"{time_now}",
                                "Data": packet[scapy.Raw].load.hex() 
                                                            if packet.haslayer(scapy.Raw)
                                                            else 
                                                                "No Raw Data"
                            }
                    )
              else:
                pass
         else:
              pass
    spy(To_spy=True)
       

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
        return None, None

def network_scan(interface):
    network_range, iface = get_local_network()
    if not network_range or not interface:
        print("Failed to determine network range or interface")
        return []
    print(f"\nScanning Network: {network_range} on {interface}...\n")
    try:
        print(f"Preparing ARP request for {network_range}...")
        arp_request = scapy.ARP(pdst=network_range)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request
        print(f"Sending ARP scan on {iface} with timeout 5s...")
        answered, unanswered = scapy.srp(packet, iface=interface, timeout=5, verbose=False, retry = 2)
        print(f"ARP scan completed. Processing responses...")
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
        subprocess.run(["sudo", "iptables", "-F"], check=False)
        subprocess.run(["sudo", "iptables", "-X"], check=False)
        subprocess.run(["sudo", "iptables", "-Z"], check=False)
        subprocess.run(["sudo", "iptables", "-P", "INPUT", "ACCEPT"], check=False)
        subprocess.run(["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"], check=False)
        subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], check=False)
        print("iptables reset to default")
    
    elif system_platform == "Darwin" :
        subprocess.run(["sudo", "pfctl", "-t","blocked_ips", "-T", "flush"], check=False)
        subprocess.run(["sudo", "pfctl", "-t","blocked_sports", "-T", "flush"], check=False)
        subprocess.run(["sudo", "pfctl", "-t","blocked_dports", "-T", "flush"], check=False)
        subprocess.run(["sudo", "pfctl", "-F", "all"], check=False)
        subprocess.run(["sudo", "pfctl", "-f", "/etc/pf.conf"], check=False)
        subprocess.run(["sudo", "pfctl", "-e"], check=False)

        print("PF reset to default")
    elif system_platform == "Windows":
        subprocess.run(["netsh", "advfirewall", "reset"], check=False)
        print("Windows Firewall reset to default")

    else:
        print("Unsupported OS")

def filter():
    network_range, interface = get_local_network()
    if interface:
        scapy.sniff(prn=packet_sniffer, stop_filter=stop_sniffing, store=False, iface = interface)

def main():
    if system_platform == "Linux" or system_platform == "Darwin":
        if os.geteuid() != 0:
            print("This script requires root privileges. Please run with sudo.")
            sys.exit(1)
    elif system_platform == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("This script requires administrator privileges. Please run as administrator.")
            sys.exit(1)
    get_malicious_ips()
    log_file_creation()
    network_range, interface = get_local_network()
    if interface:
        devices = network_scan(interface)
        for device in devices:
            ip_mac_dict[device["ip"]] = [device["mac"]]
        print(f"Initial ip_mac_dict: {ip_mac_dict}")
    countdown_thread = threading.Thread(target=countdown)
    filterThread = threading.Thread(target=filter)
    countdown_thread.start()
    filterThread.start()
    try:
        countdown_thread.join()
        filterThread.join()

    except KeyboardInterrupt:
        print("Exiting...", flush=True)
        stop_event.set()  
        time.sleep(0.1)
        reset_firewall()
        connection_log.close()
        print("OPTIMUS PRIME...", flush=True)
        sys.exit(1)
    
    finally:
        stop_event.set()  
        time.sleep(0.1)
        connection_log.close()
        reset_firewall()
        print(f"Connection log saved to {file_path}")
        sys.exit(0)

if __name__ == "__main__":
    main()
