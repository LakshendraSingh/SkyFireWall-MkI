import scapy.all as scapy
import csv
import os
import time
import sys
import threading
import requests
import platform
import netifaces
import subprocess
import dns.resolver
import dns.reversename
import shutil

 
start_time = time.time()
countdown_time = 60 # seconds
BLOCKED_IPS = []    
BLOCKED_WEBSITES = []
BLOCKED_ICMPv6_TYPES = []
BLOCKED_ICMP_TYPES = []
BLOCKED_dPORTS = []
BLOCKED_sPORTS = []
ip_mac_dict = {}
system_platform = platform.system()
stop_event = threading.Event() 
file_url = r"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt"
unique_websites = set(BLOCKED_WEBSITES)
unique_ips = set(BLOCKED_IPS)
connection_log = None
writer = None
file_path = None
PACKET_COUNTER = 0
To_spy = True
get_ips = False
to_block_tcp = False
to_block_udp = False
to_block_icmp = True
to_block_default_http_https = True
to_block_ipv6 = True
to_block_ipv4 = True
initial_contents_hosts_file = ''

def block_website():
    global BLOCKED_WEBSITES, BLOCKED_IPS
    for websites in unique_websites:
        try:
            ips_v4 = dns.resolver.resolve(f"{websites}", "A")
            for ip in ips_v4:
                unique_ips.add(ip.address)
            ips_v6 = dns.resolver.resolve(f"{websites}", "AAAA")
            for ip in ips_v6:
                unique_ips.add(ip.address)
        except Exception as e:
            print(e)
        BLOCKED_WEBSITES = list(unique_websites)
        BLOCKED_IPS = list(unique_ips)

def get_malicious_ips(get_ips): 
    if get_ips == True:
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
        finally:
            print("Malicious IPs:")
            for i in range(len(BLOCKED_IPS)):
                    BLOCKED_IPS[i] = str(BLOCKED_IPS[i])
                    print(BLOCKED_IPS[i])
            print(f"Loaded {len(BLOCKED_IPS)} malicious IPs")
    else:
        print("Malicious IPs:")
        for i in range(len(BLOCKED_IPS)):
                BLOCKED_IPS[i] = str(BLOCKED_IPS[i])
                print(BLOCKED_IPS[i])
        print(f"Loaded {len(BLOCKED_IPS)} malicious IPs")


def implement_firewall_rules():
    block_website()
    get_malicious_ips(get_ips)

    # MAC
    if system_platform == 'Darwin':
        global pf_main_local, pf_anchor_file_name, pf_anchor_file_location
        pf_main_local = "/etc/pf.conf"
        pf_anchor_file_name = "SkyFireWall"
        pf_anchor_file_location = f"/etc/pf.anchors/{pf_anchor_file_name}"
        def AnchorSetup():
                anchor_line = f'anchor {pf_anchor_file_name}\nload anchor {pf_anchor_file_name} from {pf_anchor_file_location}'
                if os.path.exists(pf_main_local):
                    with open(pf_main_local,"r") as f:
                        pf_main_contents = f.read()
                    if pf_anchor_file_name not in pf_main_contents:
                        with open(pf_main_local, "a") as f:
                            f.write(f"{anchor_line}")
                        print(f"Added anchor line {anchor_line} to {pf_main_local}")
                    else:
                        print(f"Anchor line {anchor_line} already exists in {pf_main_local}")
                else:
                    print(f"path {pf_main_local} does not exist")
                    return False
                if not os.path.exists(pf_anchor_file_location):
                    subprocess.run(rf"sudo touch {pf_anchor_file_location}")
                return True
        AnchorSetup()
        with open(pf_anchor_file_location, "w") as f:
            for ip in BLOCKED_IPS:
                is_ipv6 = ":" in ip
                #ipv4
                if not is_ipv6 and to_block_ipv4:
                    if len(BLOCKED_dPORTS) == 0 and len(BLOCKED_sPORTS) == 0:
                        f.write(f"block in quick from {ip} to any\n")
                        f.write(f"block out quick from any to {ip}\n")
                        if to_block_tcp:
                            f.write(f"block in proto tcp from {ip} to any\n")
                            f.write(f"block out proto tcp from any to {ip}\n")
                        if to_block_udp:
                            f.write(f"block in proto udp from {ip} to any\n")
                            f.write(f"block out proto udp from any to {ip}\n")
                    elif len(BLOCKED_dPORTS) == 0 and len(BLOCKED_sPORTS) != 0:
                        for sport in BLOCKED_sPORTS:
                            f.write(f"block in proto tcp from {ip} port {sport} to any\n")
                            f.write(f"block out proto tcp from any port {sport} to {ip}\n")
                            f.write(f"block in proto udp from {ip} port {sport} to any\n")
                            f.write(f"block out proto udp from any port {sport} to {ip}\n")
                    elif len(BLOCKED_dPORTS) != 0 and len(BLOCKED_sPORTS) == 0:
                        for dport in BLOCKED_dPORTS:
                            f.write(f"block in proto tcp from {ip} to any port {dport}\n")
                            f.write(f"block out proto tcp from any to {ip} port {dport}\n")
                            f.write(f"block in proto udp from {ip} to any port {dport}\n")
                            f.write(f"block out proto udp from any to {ip} port {dport}\n")
                    elif len(BLOCKED_dPORTS) != 0 and len(BLOCKED_sPORTS) != 0:
                            for dport in BLOCKED_dPORTS:
                                for sport in BLOCKED_sPORTS:
                                    f.write(f"block in proto tcp from {ip} port {sport} to any port {dport}\n")
                                    f.write(f"block out proto tcp from any port {sport} to {ip} port {dport}\n")
                                    f.write(f"block in proto udp from {ip} port {sport} to any port {dport}\n")
                                    f.write(f"block out proto udp from any port {sport} to {ip} port {dport}\n")
                    if to_block_icmp and len(BLOCKED_ICMP_TYPES) != 0:
                        for icmp_type in BLOCKED_ICMP_TYPES:
                            f.write(f"block in proto icmp from {ip} to any icmp-type {icmp_type}\n")
                            f.write(f"block out proto icmp from any to {ip} icmp-type {icmp_type}\n")
                    if to_block_icmp and len(BLOCKED_ICMP_TYPES) == 0:
                            f.write(f"block in proto icmp from {ip} to any\n")
                            f.write(f"block out proto icmp from any to {ip}\n")
                    if to_block_default_http_https:
                        f.write(f"block in proto tcp from {ip} to any port 80\n")
                        f.write(f"block out proto tcp from any to {ip} port 80\n")
                        f.write(f"block in proto tcp from {ip} to any port 443\n")
                        f.write(f"block out proto tcp from any to {ip} port 443\n")
                #ipv6
                if is_ipv6 and to_block_ipv6:
                    if len(BLOCKED_dPORTS) == 0 and len(BLOCKED_sPORTS) == 0:
                        f.write(f"block in quick from {ip} to any\n")
                        f.write(f"block out quick from any to {ip}\n")
                        if to_block_tcp:
                            f.write(f"block in proto tcp from {ip} to any\n")
                            f.write(f"block out proto tcp from any to {ip}\n")
                        if to_block_udp:
                            f.write(f"block in proto udp from {ip} to any\n")
                            f.write(f"block out proto udp from any to {ip}\n")
                    elif len(BLOCKED_dPORTS) == 0 and len(BLOCKED_sPORTS) != 0:
                        for sport in BLOCKED_sPORTS:
                            f.write(f"block in proto tcp from {ip} port {sport} to any\n")
                            f.write(f"block out proto tcp from any port {sport} to {ip}\n")
                            f.write(f"block in proto udp from {ip} port {sport} to any\n")
                            f.write(f"block out proto udp from any port {sport} to {ip}\n")
                    elif len(BLOCKED_dPORTS) != 0 and len(BLOCKED_sPORTS) == 0:
                        for dport in BLOCKED_dPORTS:
                            f.write(f"block in proto tcp from {ip} to any port {dport}\n")
                            f.write(f"block out proto tcp from any to {ip} port {dport}\n")
                            f.write(f"block in proto udp from {ip} to any port {dport}\n")
                            f.write(f"block out proto udp from any to {ip} port {dport}\n")
                    elif len(BLOCKED_dPORTS) != 0 and len(BLOCKED_sPORTS) != 0:
                            for dport in BLOCKED_dPORTS:
                                for sport in BLOCKED_sPORTS:
                                    f.write(f"block in proto tcp from {ip} port {sport} to any port {dport}\n")
                                    f.write(f"block out proto tcp from any port {sport} to {ip} port {dport}\n")
                                    f.write(f"block in proto udp from {ip} port {sport} to any port {dport}\n")
                                    f.write(f"block out proto udp from any port {sport} to {ip} port dport\n")
                    if to_block_icmp and len(BLOCKED_ICMP_TYPES) != 0:
                        for icmp_type in BLOCKED_ICMPv6_TYPES:
                            f.write(f"block in proto ipv6-icmp from {ip} to any icmp-type {icmp_type}\n")
                            f.write(f"block out proto ipv6-icmp from any to {ip} icmp-type {icmp_type}\n")
                    if to_block_icmp and len(BLOCKED_ICMPv6_TYPES) == 0:
                            f.write(f"block in proto ipv6-icmp from {ip} to any\n")
                            f.write(f"block out proto ipv6-icmp from any to {ip}\n")
                    if to_block_default_http_https:
                        f.write(f"block in proto tcp from {ip} to any port 80\n")
                        f.write(f"block out proto tcp from any to {ip} port 80\n")
                        f.write(f"block in proto tcp from {ip} to any port 443\n")
                        f.write(f"block out proto tcp from any to {ip} port 443\n")
        try:    
            pf_status = subprocess.run("sudo pfctl -s info", shell=True, capture_output=True, text = True)
            if "Status: Disabled" in pf_status.stdout:
                subprocess.run("sudo pfctl -E", check = True, shell = True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(rf"sudo pfctl -f {pf_anchor_file_location}", check = False, shell = True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as e:
            print(e)  

    elif system_platform == "Windows":
        # Clear existing rules with a specific group name to avoid duplicates
        global group_name 
        group_name = "SkyFireWall"
        subprocess.run(f'netsh advfirewall firewall delete rule name=all group="{group_name}"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        for ip in BLOCKED_IPS:
            is_ipv6 = ":" in ip
            # IPv4 rules
            if not is_ipv6 and to_block_ipv4:
                if len(BLOCKED_dPORTS) == 0 and len(BLOCKED_sPORTS) == 0:
                    # Block all traffic
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block {ip} in" group="{group_name}" dir=in action=block remoteip={ip}', shell=True)
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block {ip} out" group="{group_name}" dir=out action=block remoteip={ip}', shell=True)
                    if to_block_tcp:
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} in" group="{group_name}" dir=in action=block protocol=TCP remoteip={ip}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} out" group="{group_name}" dir=out action=block protocol=TCP remoteip={ip}', shell=True)
                    if to_block_udp:
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} in" group="{group_name}" dir=in action=block protocol=UDP remoteip={ip}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} out" group="{group_name}" dir=out action=block protocol=UDP remoteip={ip}', shell=True)
                elif len(BLOCKED_dPORTS) == 0 and len(BLOCKED_sPORTS) != 0:
                    for sport in BLOCKED_sPORTS:
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} sport {sport} in" group="{group_name}" dir=in action=block protocol=TCP remoteip={ip} localport={sport}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} sport {sport} out" group="{group_name}" dir=out action=block protocol=TCP remoteip={ip} localport={sport}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} sport {sport} in" group="{group_name}" dir=in action=block protocol=UDP remoteip={ip} localport={sport}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} sport {sport} out" group="{group_name}" dir=out action=block protocol=UDP remoteip={ip} localport={sport}', shell=True)
                elif len(BLOCKED_dPORTS) != 0 and len(BLOCKED_sPORTS) == 0:
                    for dport in BLOCKED_dPORTS:
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} dport {dport} in" group="{group_name}" dir=in action=block protocol=TCP remoteip={ip} remoteport={dport}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} dport {dport} out" group="{group_name}" dir=out action=block protocol=TCP remoteip={ip} remoteport={dport}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} dport {dport} in" group="{group_name}" dir=in action=block protocol=UDP remoteip={ip} remoteport={dport}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} dport {dport} out" group="{group_name}" dir=out action=block protocol=UDP remoteip={ip} remoteport={dport}', shell=True)
                elif len(BLOCKED_dPORTS) != 0 and len(BLOCKED_sPORTS) != 0:
                    for dport in BLOCKED_dPORTS:
                        for sport in BLOCKED_sPORTS:
                            subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} sport {sport} dport {dport} in" group="{group_name}" dir=in action=block protocol=TCP remoteip={ip} localport={sport} remoteport={dport}', shell=True)
                            subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} sport {sport} dport {dport} out" group="{group_name}" dir=out action=block protocol=TCP remoteip={ip} localport={sport} remoteport={dport}', shell=True)
                            subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} sport {sport} dport {dport} in" group="{group_name}" dir=in action=block protocol=UDP remoteip={ip} localport={sport} remoteport={dport}', shell=True)
                            subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} sport {sport} dport {dport} out" group="{group_name}" dir=out action=block protocol=UDP remoteip={ip} localport={sport} remoteport={dport}', shell=True)
                if to_block_icmp and len(BLOCKED_ICMP_TYPES) != 0:
                    for icmp_type in BLOCKED_ICMP_TYPES:
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block ICMP {ip} type {icmp_type} in" group="{group_name}" dir=in action=block protocol=ICMPv4 remoteip={ip} icmptype={icmp_type}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block ICMP {ip} type {icmp_type} out" group="{group_name}" dir=out action=block protocol=ICMPv4 remoteip={ip} icmptype={icmp_type}', shell=True)
                if to_block_icmp and len(BLOCKED_ICMP_TYPES) == 0:
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block ICMP {ip} in" group="{group_name}" dir=in action=block protocol=ICMPv4 remoteip={ip}', shell=True)
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block ICMP {ip} out" group="{group_name}" dir=out action=block protocol=ICMPv4 remoteip={ip}', shell=True)
                if to_block_default_http_https:
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block HTTP {ip} in" group="{group_name}" dir=in action=block protocol=TCP remoteip={ip} remoteport=80', shell=True)
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block HTTP {ip} out" group="{group_name}" dir=out action=block protocol=TCP remoteip={ip} remoteport=80', shell=True)
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block HTTPS {ip} in" group="{group_name}" dir=in action=block protocol=TCP remoteip={ip} remoteport=443', shell=True)
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block HTTPS {ip} out" group="{group_name}" dir=out action=block protocol=TCP remoteip={ip} remoteport=443', shell=True)
            # IPv6 rules
            if is_ipv6 and to_block_ipv6:
                if len(BLOCKED_dPORTS) == 0 and len(BLOCKED_sPORTS) == 0:
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block {ip} in" group="{group_name}" dir=in action=block remoteip={ip}', shell=True)
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block {ip} out" group="{group_name}" dir=out action=block remoteip={ip}', shell=True)
                    if to_block_tcp:
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} in" group="{group_name}" dir=in action=block protocol=TCP remoteip={ip}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} out" group="{group_name}" dir=out action=block protocol=TCP remoteip={ip}', shell=True)
                    if to_block_udp:
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} in" group="{group_name}" dir=in action=block protocol=UDP remoteip={ip}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} out" group="{group_name}" dir=out action=block protocol=UDP remoteip={ip}', shell=True)
                elif len(BLOCKED_dPORTS) == 0 and len(BLOCKED_sPORTS) != 0:
                    for sport in BLOCKED_sPORTS:
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} sport {sport} in" group="{group_name}" dir=in action=block protocol=TCP remoteip={ip} localport={sport}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} sport {sport} out" group="{group_name}" dir=out action=block protocol=TCP remoteip={ip} localport={sport}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} sport {sport} in" group="{group_name}" dir=in action=block protocol=UDP remoteip={ip} localport={sport}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} sport {sport} out" group="{group_name}" dir=out action=block protocol=UDP remoteip={ip} localport={sport}', shell=True)
                elif len(BLOCKED_dPORTS) != 0 and len(BLOCKED_sPORTS) == 0:
                    for dport in BLOCKED_dPORTS:
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} dport {dport} in" group="{group_name}" dir=in action=block protocol=TCP remoteip={ip} remoteport={dport}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} dport {dport} out" group="{group_name}" dir=out action=block protocol=TCP remoteip={ip} remoteport={dport}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} dport {dport} in" group="{group_name}" dir=in action=block protocol=UDP remoteip={ip} remoteport={dport}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} dport {dport} out" group="{group_name}" dir=out action=block protocol=UDP remoteip={ip} remoteport={dport}', shell=True)
                elif len(BLOCKED_dPORTS) != 0 and len(BLOCKED_sPORTS) != 0:
                    for dport in BLOCKED_dPORTS:
                        for sport in BLOCKED_sPORTS:
                            subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} sport {sport} dport {dport} in" group="{group_name}" dir=in action=block protocol=TCP remoteip={ip} localport={sport} remoteport={dport}', shell=True)
                            subprocess.run(f'netsh advfirewall firewall add rule name="Block TCP {ip} sport {sport} dport {dport} out" group="{group_name}" dir=out action=block protocol=TCP remoteip={ip} localport={sport} remoteport={dport}', shell=True)
                            subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} sport {sport} dport {dport} in" group="{group_name}" dir=in action=block protocol=UDP remoteip={ip} localport={sport} remoteport={dport}', shell=True)
                            subprocess.run(f'netsh advfirewall firewall add rule name="Block UDP {ip} sport {sport} dport {dport} out" group="{group_name}" dir=out action=block protocol=UDP remoteip={ip} localport={sport} remoteport={dport}', shell=True)
                if to_block_icmp and len(BLOCKED_ICMPv6_TYPES) != 0:
                    for icmp_type in BLOCKED_ICMPv6_TYPES:
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block ICMPv6 {ip} type {icmp_type} in" group="{group_name}" dir=in action=block protocol=ICMPv6 remoteip={ip} icmptype={icmp_type}', shell=True)
                        subprocess.run(f'netsh advfirewall firewall add rule name="Block ICMPv6 {ip} type {icmp_type} out" group="{group_name}" dir=out action=block protocol=ICMPv6 remoteip={ip} icmptype={icmp_type}', shell=True)
                if to_block_icmp and len(BLOCKED_ICMPv6_TYPES) == 0:
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block ICMPv6 {ip} in" group="{group_name}" dir=in action=block protocol=ICMPv6 remoteip={ip}', shell=True)
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block ICMPv6 {ip} out" group="{group_name}" dir=out action=block protocol=ICMPv6 remoteip={ip}', shell=True)
                if to_block_default_http_https:
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block HTTP {ip} in" group="{group_name}" dir=in action=block protocol=TCP remoteip={ip} remoteport=80', shell=True)
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block HTTP {ip} out" group="{group_name}" dir=out action=block protocol=TCP remoteip={ip} remoteport=80', shell=True)
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block HTTPS {ip} in" group="{group_name}" dir=in action=block protocol=TCP remoteip={ip} remoteport=443', shell=True)
                    subprocess.run(f'netsh advfirewall firewall add rule name="Block HTTPS {ip} out" group="{group_name}" dir=out action=block protocol=TCP remoteip={ip} remoteport=443', shell=True)
        print(f"Firewall rules for group {group_name} have been configured.")
        # Check if Windows Firewall is enabled
        firewall_status = subprocess.run('netsh advfirewall show allprofiles state', shell=True, capture_output=True, text=True)
        if "OFF" in firewall_status.stdout:
            print("Windows Firewall is disabled. Enabling it...")
            subprocess.run('netsh advfirewall set allprofiles state on', shell=True, check=True)

    elif system_platform == "Linux":

            for ip in BLOCKED_IPS:
                is_ipv6 = ":" in ip
                ipt_cmd = "ip6tables" if is_ipv6 else "iptables"

                # IPv4
                if not is_ipv6 and to_block_ipv4:
                    if len(BLOCKED_dPORTS) == 0 and len(BLOCKED_sPORTS) == 0:
                        subprocess.run(f"sudo {ipt_cmd} -A INPUT -s {ip} -j DROP", shell=True)
                        subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -d {ip} -j DROP", shell=True)
                        if to_block_tcp:
                            subprocess.run(f"sudo {ipt_cmd} -A INPUT -p tcp -s {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p tcp -d {ip} -j DROP", shell=True)
                        if to_block_udp:
                            subprocess.run(f"sudo {ipt_cmd} -A INPUT -p udp -s {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p udp -d {ip} -j DROP", shell=True)
                    elif len(BLOCKED_dPORTS) == 0 and len(BLOCKED_sPORTS) != 0:
                        for sport in BLOCKED_sPORTS:
                            subprocess.run(f"sudo {ipt_cmd} -A INPUT -p tcp --sport {sport} -s {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p tcp --sport {sport} -d {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A INPUT -p udp --sport {sport} -s {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p udp --sport {sport} -d {ip} -j DROP", shell=True)
                    elif len(BLOCKED_dPORTS) != 0 and len(BLOCKED_sPORTS) == 0:
                        for dport in BLOCKED_dPORTS:
                            subprocess.run(f"sudo {ipt_cmd} -A INPUT -p tcp --dport {dport} -s {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p tcp --dport {dport} -d {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A INPUT -p udp --dport {dport} -s {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p udp --dport {dport} -d {ip} -j DROP", shell=True)
                    elif len(BLOCKED_dPORTS) != 0 and len(BLOCKED_sPORTS) != 0:
                        for dport in BLOCKED_dPORTS:
                            for sport in BLOCKED_sPORTS:
                                subprocess.run(f"sudo {ipt_cmd} -A INPUT -p tcp --sport {sport} --dport {dport} -s {ip} -j DROP", shell=True)
                                subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p tcp --sport {sport} --dport {dport} -d {ip} -j DROP", shell=True)
                                subprocess.run(f"sudo {ipt_cmd} -A INPUT -p udp --sport {sport} --dport {dport} -s {ip} -j DROP", shell=True)
                                subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p udp --sport {sport} --dport {dport} -d {ip} -j DROP", shell=True)
                    if to_block_icmp and len(BLOCKED_ICMP_TYPES) != 0:
                        for icmp_type in BLOCKED_ICMP_TYPES:
                            subprocess.run(f"sudo {ipt_cmd} -A INPUT -p icmp --icmp-type {icmp_type} -s {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p icmp --icmp-type {icmp_type} -d {ip} -j DROP", shell=True)
                    if to_block_icmp and len(BLOCKED_ICMP_TYPES) == 0:
                        subprocess.run(f"sudo {ipt_cmd} -A INPUT -p icmp -s {ip} -j DROP", shell=True)
                        subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p icmp -d {ip} -j DROP", shell=True)
                    if to_block_default_http_https:
                        subprocess.run(f"sudo {ipt_cmd} -A INPUT -p tcp --dport 80 -s {ip} -j DROP", shell=True)
                        subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p tcp --dport 80 -d {ip} -j DROP", shell=True)
                        subprocess.run(f"sudo {ipt_cmd} -A INPUT -p tcp --dport 443 -s {ip} -j DROP", shell=True)
                        subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p tcp --dport 443 -d {ip} -j DROP", shell=True)

                # IPv6
                if is_ipv6 and to_block_ipv6:
                    if len(BLOCKED_dPORTS) == 0 and len(BLOCKED_sPORTS) == 0:
                        subprocess.run(f"sudo {ipt_cmd} -A INPUT -s {ip} -j DROP", shell=True)
                        subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -d {ip} -j DROP", shell=True)
                        if to_block_tcp:
                            subprocess.run(f"sudo {ipt_cmd} -A INPUT -p tcp -s {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p tcp -d {ip} -j DROP", shell=True)
                        if to_block_udp:
                            subprocess.run(f"sudo {ipt_cmd} -A INPUT -p udp -s {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p udp -d {ip} -j DROP", shell=True)
                    elif len(BLOCKED_dPORTS) == 0 and len(BLOCKED_sPORTS) != 0:
                        for sport in BLOCKED_sPORTS:
                            subprocess.run(f"sudo {ipt_cmd} -A INPUT -p tcp --sport {sport} -s {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p tcp --sport {sport} -d {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A INPUT -p udp --sport {sport} -s {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p udp --sport {sport} -d {ip} -j DROP", shell=True)
                    elif len(BLOCKED_dPORTS) != 0 and len(BLOCKED_sPORTS) == 0:
                        for dport in BLOCKED_dPORTS:
                            subprocess.run(f"sudo {ipt_cmd} -A INPUT -p tcp --dport {dport} -s {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p tcp --dport {dport} -d {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A INPUT -p udp --dport {dport} -s {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p udp --dport {dport} -d {ip} -j DROP", shell=True)
                    elif len(BLOCKED_dPORTS) != 0 and len(BLOCKED_sPORTS) != 0:
                        for dport in BLOCKED_dPORTS:
                            for sport in BLOCKED_sPORTS:
                                subprocess.run(f"sudo {ipt_cmd} -A INPUT -p tcp --sport {sport} --dport {dport} -s {ip} -j DROP", shell=True)
                                subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p tcp --sport {sport} --dport {dport} -d {ip} -j DROP", shell=True)
                                subprocess.run(f"sudo {ipt_cmd} -A INPUT -p udp --sport {sport} --dport {dport} -s {ip} -j DROP", shell=True)
                                subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p udp --sport {sport} --dport {dport} -d {ip} -j DROP", shell=True)
                    if to_block_icmp and len(BLOCKED_ICMPv6_TYPES) != 0:
                        for icmp_type in BLOCKED_ICMPv6_TYPES:
                            subprocess.run(f"sudo {ipt_cmd} -A INPUT -p ipv6-icmp --icmpv6-type {icmp_type} -s {ip} -j DROP", shell=True)
                            subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p ipv6-icmp --icmpv6-type {icmp_type} -d {ip} -j DROP", shell=True)
                    if to_block_icmp and len(BLOCKED_ICMPv6_TYPES) == 0:
                        subprocess.run(f"sudo {ipt_cmd} -A INPUT -p ipv6-icmp -s {ip} -j DROP", shell=True)
                        subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p ipv6-icmp -d {ip} -j DROP", shell=True)
                    if to_block_default_http_https:
                        subprocess.run(f"sudo {ipt_cmd} -A INPUT -p tcp --dport 80 -s {ip} -j DROP", shell=True)
                        subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p tcp --dport 80 -d {ip} -j DROP", shell=True)
                        subprocess.run(f"sudo {ipt_cmd} -A INPUT -p tcp --dport 443 -s {ip} -j DROP", shell=True)
                        subprocess.run(f"sudo {ipt_cmd} -A OUTPUT -p tcp --dport 443 -d {ip} -j DROP", shell=True)

def reroute(): 
    global initial_contents_hosts_file, hosts_path
    re_routing_ip = "127.0.0.7"
    if system_platform == "Darwin" or system_platform == "Linux":
        hosts_path = "/etc/hosts"
    elif system_platform == "Windows":
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        
    def create_backups():
        global hosts_backup
        hosts_backup = rf"{hosts_path}.bak" 
        if not os.path.exists(hosts_backup):
            try:
                shutil.copyfile(hosts_path, hosts_backup) 
            except Exception as e:
                print(f"error in backup creation of hosts file {e}")
        else:
            print("backup of hosts file exists")
    create_backups()
    try:
        with open(hosts_path, "r") as f:
            initial_contents_hosts_file = f.read()
        with open(hosts_path, "a") as f:
            f.write("\n# ############################################# #\n"
                    "#     THE FOLLOWING LINES ARE FOR SKYFIREWALL\n"
                    "# ############################################### #\n")
            for website in BLOCKED_WEBSITES:
                if website not in initial_contents_hosts_file:
                    f.write(f"{re_routing_ip} {website}\n")
    except Exception as e:
        print(e)

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
        writer = csv.DictWriter(connection_log, fieldnames=["[Packet No.]","[Resource]","[URL/IP/Arpa]","[Protocol]","[Source Port]", "[Destination Port]", "[Time {dd/mm/yy | day | hh:mm:ss (GMT)}]", "[Blocked]", "[DATA]"])  
        writer.writeheader()

def countdown():
    global countdown_time
    while countdown_time >= 0 and not stop_event.is_set():
        print(f"Time remaining: {countdown_time} seconds\n")
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
            arpa = dns.reversename.from_address(ip)
            arpa_resolved = dns.resolver.resolve(arpa, "PTR")
            url = arpa_resolved[0].to_text().rstrip('.')
        except Exception as e :
                print(f"error {e} fetching URL/IP")
                url = ip
         
        src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else packet[scapy.IPv6].src if packet.haslayer(scapy.IPv6) else "unknown"
        dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else packet[scapy.IPv6].dst if packet.haslayer(scapy.IPv6) else "unknown"
        
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
        "[URL/IP/Arpa]": f"[{url}]",
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
    URL/IP/Arpa:            {url}
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
              file_type = "csv"
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
        print(f"Sending ARP scan on {iface}")
        answered, unanswered = scapy.srp(packet, iface=interface, timeout=2, verbose=False, retry = 2)
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
    try:
        if system_platform == "Darwin":
            subprocess.run("sudo pfctl -f /etc/pf.conf", check = True, shell = True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        elif system_platform == "Windows":
            subprocess.run(f'netsh advfirewall firewall delete rule name=all group="{group_name}"',shell=True,capture_output=True,text=True)
                
        elif system_platform == "Linux":
            subprocess.run("sudo iptables -F", shell=True)
            subprocess.run("sudo iptables -X", shell=True)
            subprocess.run("sudo ip6tables -F", shell=True)
            subprocess.run("sudo ip6tables -X", shell=True)
    except Exception as e:
        print(f"fire wall reset error : {e}")

    try:
        if os.path.exists(hosts_backup):
            if os.path.exists(hosts_path):
                shutil.copyfile(hosts_backup, hosts_path)
            else:
                print(f"hosts file at path' {hosts_path} not found")
        else:
            print(f"hosts backup file at path '{hosts_backup}' not found")
    except Exception as e:
        print(f"hosts file reset error : {e}")


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
    implement_firewall_rules()
    log_file_creation()
    network_range, interface = get_local_network()
    if interface:
        devices = network_scan(interface)
        for device in devices:
            ip_mac_dict[device["ip"]] = [device["mac"]]
        print(f"Initial ip_mac_dict: {ip_mac_dict}")
    reroute_thread = threading.Thread(target = reroute)
    countdown_thread = threading.Thread(target=countdown)
    filterThread = threading.Thread(target=filter)
    reroute_thread.start()
    countdown_thread.start()
    filterThread.start()
    try:
        reroute_thread.join()
        countdown_thread.join()
        filterThread.join()

    except KeyboardInterrupt:
        print("Exiting...", flush=True)
        stop_event.set()  
        time.sleep(0.1)
        reset_firewall()
        connection_log.close()
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
