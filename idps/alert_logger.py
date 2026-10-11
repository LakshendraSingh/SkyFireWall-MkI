import os
import csv
import time
import threading
from typing import Dict, Any, Optional

class IDPSAlertLogger:
    """
    Manages IDPS alert logging to CSV and real-time console notification banners.
    """
    def __init__(self, log_filepath: Optional[str] = None):
        self.lock = threading.Lock()
        self.alert_counter = 0

        if not log_filepath:
            cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            log_filepath = os.path.join(cwd, "idps_alerts.csv")
        self.log_filepath = log_filepath

        self.fieldnames = [
            "Alert ID", "Timestamp", "Attacker IP", "Victim IP",
            "Protocol", "Service", "Attack Category", "Attack Type",
            "Confidence (%)", "Threat Level", "IPS Action", "Packet Summary"
        ]

        self._init_file()

    def _init_file(self):
        file_exists = os.path.exists(self.log_filepath)
        try:
            with open(self.log_filepath, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                if not file_exists or os.path.getsize(self.log_filepath) == 0:
                    writer.writeheader()
        except Exception as e:
            print(f"[IDPS Logger Error] Could not initialize alert CSV: {e}")

    def log_alert(self,
                  attacker_ip: str,
                  victim_ip: str,
                  protocol: str,
                  service: str,
                  category: str,
                  attack_type: str,
                  confidence: float,
                  threat_level: str,
                  ips_action: str,
                  packet_summary: str = "") -> int:
        """
        Log an intrusion alert and print a high-visibility terminal banner.
        """
        with self.lock:
            self.alert_counter += 1
            alert_id = self.alert_counter
            now_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + f".{time.time_ns() % 1_000_000_000:06d}"
            conf_str = f"{confidence * 100:.1f}%"

            record = {
                "Alert ID": alert_id,
                "Timestamp": now_str,
                "Attacker IP": attacker_ip,
                "Victim IP": victim_ip,
                "Protocol": protocol,
                "Service": service,
                "Attack Category": category,
                "Attack Type": attack_type,
                "Confidence (%)": conf_str,
                "Threat Level": threat_level,
                "IPS Action": ips_action,
                "Packet Summary": packet_summary
            }

            try:
                with open(self.log_filepath, "a", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=self.fieldnames)
                    writer.writerow(record)
            except Exception as e:
                print(f"[IDPS Logger Error] Could not write to alert file: {e}")

            # Terminal alert banner
            color_prefix = "\033[91m" if threat_level in ["CRITICAL", "HIGH"] else "\033[93m"
            color_suffix = "\033[0m"

            banner = f"""
{color_prefix}╔════════════════════════════════════════════════════════════════════════════════╗
║  🚨 [IDPS INTRUSION ALERT #{alert_id}] {threat_level.upper()} THREAT DETECTED & PREVENTED
╠════════════════════════════════════════════════════════════════════════════════╣
║  Attacker IP:       {attacker_ip:<58} ║
║  Target IP:         {victim_ip:<58} ║
║  Protocol / Port:   {protocol} ({service}){'':<48} ║
║  Attack Category:   {category:<58} ║
║  Specific Attack:   {attack_type:<58} ║
║  Model Confidence:  {conf_str:<58} ║
║  Threat Level:      {threat_level:<58} ║
║  IPS Action:        {ips_action:<58} ║
╚════════════════════════════════════════════════════════════════════════════════╝{color_suffix}
"""
            print(banner, flush=True)
            return alert_id
