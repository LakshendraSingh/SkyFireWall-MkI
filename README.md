
# SkyFireWall-MkI
A kernel Level integrated Firewall System that blocks ports and ip addresses
in its esscence it acts as an overlayer on top of the kernal providing basic firewall support
# UNDER ACTIVE DEVELOPMENT
# Network Traffic Monitoring & Filtering Tool

## Overview
This Python script is a network monitoring and security tool that captures and logs network traffic, detects potential threats, and blocks malicious connections. It uses `Scapy` for packet sniffing and analysis and integrates firewall rules to block malicious IPs.

## Features
- **Machine Learning IDPS (NSL-KDD)**: Integrated Intrusion Detection and Prevention System trained on the full NSL-KDD dataset (DoS, Probe, R2L, U2R, Normal).
- **Active Real-Time Prevention (IPS)**: Automatically and dynamically blocks attacking IPs at the kernel/OS firewall (`pfctl` / `iptables` / `netsh`).
- **Packet Sniffing**: Captures network packets in real time.
- **Threat Detection**: Blocks traffic from known malicious IPs using an online threat database.
- **Firewall Integration**: Automatically updates system firewall rules to block threats.
- **ARP Spoofing Detection**: Identifies potential ARP spoofing attacks.
- **Network Scanning**: Detects all active devices in the local network.
- **Logging & Alerting**: Records all captured packets in `connection_log.csv` and intrusion events in `idps_alerts.csv`.

## Prerequisites
Ensure you have the following installed:
- Python 3.x
- Required dependencies:
  ```bash
  pip install scapy requests scikit-learn pandas numpy joblib dnspython netifaces2
  ```
- Administrator/root privileges (required for firewall modifications and network sniffing)

## IDPS (Intrusion Detection and Prevention System)

SkyFireWall features a built-in Machine Learning IDPS trained on the **NSL-KDD** benchmark dataset:
- **Trained Classes**:
  - **DoS**: Neptune, Smurf, Pod, Teardrop, Land, Back, Apache2, Udpstorm, etc.
  - **Probe**: PortSweep, IPSweep, Nmap, Satan, Mscan, Saint.
  - **R2L**: Guess_Passwd, Ftp_Write, Imap, Warezclient, Spy, Phf, etc.
  - **U2R**: Buffer_Overflow, Rootkit, Loadmodule, Perl, etc.
  - **Normal**: Benign network traffic.
- **Model Bundle**: Stored in `models/idps_nsl_kdd.joblib` with high precision (~97%) to minimize false positives.
- **Dynamic IPS Action**: When malicious activity exceeds the detection threshold, the offending IP is dynamically added to the kernel firewall rules immediately, preventing subsequent packets.

### Training the IDPS Model
To train or retrain the IDPS model on the provided NSL-KDD dataset:
```bash
python3 train_idps.py
# or using SkyFireWall:
python3 SkyFireWall.py --train-idps
```
For ultra-fast quick training on the 20% subset:
```bash
python3 train_idps.py --quick
```

### Running Automated IDPS Tests
```bash
python3 test_idps.py
```

## How It Works
1. **Fetch Malicious IPs**: The script downloads known malicious IPs from an online database.
2. **Scan the Local Network**: Identifies all active devices and maps their IPs to MAC addresses.
3. **Start Packet Sniffing**: Captures network packets in real time.
4. **IDPS ML Inspection**:
   - Computes flow statistics, TCP flags, service mappings, time-window and host connection metrics.
   - Evaluates each packet and flow against the NSL-KDD trained model.
   - If an attack is detected, the attacker IP is dynamically blocked in the OS firewall and logged to `idps_alerts.csv`.
5. **Firewall Enforcement**: Automatically blocks malicious IPs using system firewall rules.
6. **Countdown Timer**: Stops packet sniffing after a predefined duration (default: 60 seconds).

## Usage
Run the script with administrator/root privileges:
```bash
sudo python3 SkyFireWall.py
```

### Optional Arguments:
- `--train-idps`: Train the IDPS machine learning model on NSL-KDD and exit.
- `--no-idps`: Disable ML IDPS intrusion detection.
- `--idps-thresh <float>`: Set anomaly confidence threshold (default: `0.65`).

### Firewall Reset
To reset firewall rules after execution, the script automatically cleans up the applied rules before exiting.

## Supported Platforms
- **Linux**: Uses `iptables` for blocking IPs.
- **Windows**: Uses Windows Firewall (`netsh`) rules.
- **macOS**: Uses `pfctl` for managing firewall rules.

## Output
- **Console Logs**: Displays real-time packet details, IDPS classification status, and intrusion alert banners.
- **CSV Log Files**:
  - `connection_log.csv`: Full network traffic log.
  - `idps_alerts.csv`: Dedicated intrusion detection & prevention alerts.
- **Alerts**: Warnings for detected threats (e.g., DoS, PortSweep, ARP spoofing) are printed to the console.

## Security Considerations
- Ensure you have permission to monitor network traffic in your environment.
- Modify firewall rules carefully to prevent unintended disruptions.

## Disclaimer
This tool is intended for educational and research purposes only. Unauthorized network monitoring may be illegal in some jurisdictions.

---
Special Thanks to 
https://github.com/stamparm/ipsum
for providing daily list of malicious ips
