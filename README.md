
# SkyFireWall-MkI
A kernel Level integrated Firewall System that blocks ports and ip addresses
in its esscence it acts as an overlayer on top of the kernal providing basic firewall support
# UNDER ACTIVE DEVELOPMENT
# Network Traffic Monitoring & Filtering Tool

## Overview
This Python script is a network monitoring and security tool that captures and logs network traffic, detects potential threats, and blocks malicious connections. It uses `Scapy` for packet sniffing and analysis and integrates firewall rules to block malicious IPs.

## Features
- **Packet Sniffing**: Captures network packets in real time.
- **Threat Detection**: Blocks traffic from known malicious IPs using an online threat database.
- **Firewall Integration**: Automatically updates system firewall rules to block threats.
- **ARP Spoofing Detection**: Identifies potential ARP spoofing attacks.
- **Network Scanning**: Detects all active devices in the local network.
- **Logging**: Records all captured packets in a CSV file.

## Prerequisites
Ensure you have the following installed:
- Python 3.x
- Required dependencies:
  ```bash
  pip install scapy requests netifaces
  ```
- Administrator/root privileges (required for firewall modifications and network sniffing)

## How It Works
1. **Fetch Malicious IPs**: The script downloads a list of malicious IPs from an online database.
2. **Scan the Local Network**: Identifies all active devices and maps their IPs to MAC addresses.
3. **Start Packet Sniffing**: Captures network packets in real time.
4. **Analyze Traffic**:
   - Checks for known malicious IPs, suspicious ports, and ARP spoofing attacks.
   - Logs each packet with details such as source/destination IP, ports, protocol, and timestamp.
5. **Firewall Enforcement**: Automatically blocks malicious IPs using system firewall rules.
6. **Countdown Timer**: Stops packet sniffing after a predefined duration (default: 60 seconds).

## Usage
Run the script with administrator/root privileges:
```bash
sudo python script.py
```

### Firewall Reset
To reset firewall rules after execution, the script automatically cleans up the applied rules before exiting.

## Supported Platforms
- **Linux**: Uses `iptables` for blocking IPs.
- **Windows**: Uses Windows Firewall rules.
- **MacOS**: Uses `pfctl` for managing firewall rules.

## Output
- **Console Logs**: Displays real-time packet details and alerts.
- **CSV Log File**: All traffic is logged in `connection_log.csv`.
- **Alerts**: Warnings for detected threats (e.g., ARP spoofing) are printed to the console.

## Security Considerations
- Ensure you have permission to monitor network traffic in your environment.
- Modify firewall rules carefully to prevent unintended disruptions.

## Disclaimer
This tool is intended for educational and research purposes only. Unauthorized network monitoring may be illegal in some jurisdictions.

## Future Improvements
- Add GUI for better user interaction.
- Implement machine learning-based anomaly detection.
- Improve efficiency in firewall rule management.

---
Special Thanks to 
https://github.com/stamparm/ipsum
for providing daily list of malicious ips
