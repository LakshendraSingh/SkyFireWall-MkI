import os
import platform
import subprocess
import threading
from typing import Set, List, Optional

class FirewallPreventionManager:
    """
    Real-Time Intrusion Prevention Engine (IPS).
    Dynamically applies kernel/OS-level firewall rules to block attacking IPs
    across macOS (Darwin pfctl), Linux (iptables), and Windows (netsh).
    """
    def __init__(self, protected_ips: Optional[Set[str]] = None, dry_run: bool = False):
        self.system_platform = platform.system()
        self.lock = threading.Lock()
        self.dynamically_blocked_ips: Set[str] = set()
        self.dry_run = dry_run or not self.has_root_privileges()

        # Whitelist critical IPs that must never be blocked (loopback, local gateway, etc.)
        self.protected_ips: Set[str] = {
            '127.0.0.1', '::1', '0.0.0.0', '255.255.255.255',
            'localhost', '127.0.0.7'
        }
        if protected_ips:
            self.protected_ips.update(protected_ips)

        # macOS pf anchor config
        self.pf_anchor_name = "SkyFireWall"
        self.pf_anchor_file = f"/etc/pf.anchors/{self.pf_anchor_name}"

    @staticmethod
    def has_root_privileges() -> bool:
        """Check if process currently has root/administrator privileges."""
        try:
            if platform.system() in ['Darwin', 'Linux']:
                return os.geteuid() == 0
            elif platform.system() == 'Windows':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
        return False

    def add_protected_ip(self, ip: str):
        with self.lock:
            self.protected_ips.add(ip)

    def is_protected(self, ip: str) -> bool:
        if not ip or ip in ['unknown', 'Unknown', 'None', '']:
            return True
        return ip in self.protected_ips or ip.startswith('127.')

    def is_blocked(self, ip: str) -> bool:
        with self.lock:
            return ip in self.dynamically_blocked_ips

    def block_ip(self, ip: str, attack_info: str = "") -> bool:
        """
        Dynamically block an attacking IP in the OS firewall.
        Returns True if newly blocked, False if already blocked or protected.
        """
        if self.is_protected(ip):
            print(f"[IDPS Prevention] Skipping protected/internal IP: {ip}")
            return False

        with self.lock:
            if ip in self.dynamically_blocked_ips:
                return False  # Already blocked

            self.dynamically_blocked_ips.add(ip)

        print(f"[🚨 IDPS IPS ACTION] Dynamically blocking attacking IP: {ip} ({attack_info})")

        if self.dry_run:
            print(f"[IDPS IPS (Simulation/Non-Root)] Block rule registered for {ip}")
            return True

        is_ipv6 = ":" in ip
        success = False

        try:
            if self.system_platform == 'Darwin':
                # macOS pfctl
                if os.path.exists(self.pf_anchor_file):
                    rule_in = f"block in quick from {ip} to any\n"
                    rule_out = f"block out quick from any to {ip}\n"
                    with open(self.pf_anchor_file, "a") as f:
                        f.write(rule_in)
                        f.write(rule_out)
                    # Reload pf rules anchor
                    subprocess.run(
                        f"pfctl -a {self.pf_anchor_name} -f {self.pf_anchor_file}",
                        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
                    )
                    success = True

            elif self.system_platform == 'Linux':
                # Linux iptables
                ipt_cmd = "ip6tables" if is_ipv6 else "iptables"
                subprocess.run(f"{ipt_cmd} -I INPUT 1 -s {ip} -j DROP", shell=True, check=False)
                subprocess.run(f"{ipt_cmd} -I OUTPUT 1 -d {ip} -j DROP", shell=True, check=False)
                success = True

            elif self.system_platform == 'Windows':
                # Windows Firewall
                group_name = "SkyFireWall"
                subprocess.run(
                    f'netsh advfirewall firewall add rule name="IDPS Block {ip} in" group="{group_name}" dir=in action=block remoteip={ip}',
                    shell=True, check=False
                )
                subprocess.run(
                    f'netsh advfirewall firewall add rule name="IDPS Block {ip} out" group="{group_name}" dir=out action=block remoteip={ip}',
                    shell=True, check=False
                )
                success = True

        except Exception as e:
            print(f"[IDPS Prevention Error] Failed to enforce firewall block on {ip}: {e}")
            success = False

        return success

    def unblock_all(self):
        """Clean up all dynamically blocked IPs from firewall."""
        with self.lock:
            blocked_list = list(self.dynamically_blocked_ips)
            self.dynamically_blocked_ips.clear()

        if not blocked_list:
            return

        print(f"[IDPS Cleanup] Cleaning up {len(blocked_list)} dynamic IDPS firewall blocks...")

        if self.dry_run:
            print(f"[IDPS Cleanup (Simulation/Non-Root)] Cleared dynamic blocks for: {blocked_list}")
            return

        try:
            if self.system_platform == 'Darwin':
                if os.path.exists(self.pf_anchor_file):
                    subprocess.run(
                        f"pfctl -a {self.pf_anchor_name} -F all",
                        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
                    )

            elif self.system_platform == 'Linux':
                for ip in blocked_list:
                    ipt_cmd = "ip6tables" if ":" in ip else "iptables"
                    subprocess.run(f"{ipt_cmd} -D INPUT -s {ip} -j DROP", shell=True, check=False)
                    subprocess.run(f"{ipt_cmd} -D OUTPUT -d {ip} -j DROP", shell=True, check=False)

            elif self.system_platform == 'Windows':
                for ip in blocked_list:
                    subprocess.run(
                        f'netsh advfirewall firewall delete rule name="IDPS Block {ip} in"',
                        shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
                    subprocess.run(
                        f'netsh advfirewall firewall delete rule name="IDPS Block {ip} out"',
                        shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
        except Exception as e:
            print(f"[IDPS Cleanup Error] {e}")
