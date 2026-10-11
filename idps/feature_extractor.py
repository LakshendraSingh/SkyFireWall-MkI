import time
import threading
from collections import deque, defaultdict
from typing import Dict, Any, Tuple, Optional
import scapy.all as scapy

# Standard port to NSL-KDD service mapping
PORT_SERVICE_MAP = {
    80: 'http',
    443: 'http_443',
    8080: 'http',
    8001: 'http_8001',
    2784: 'http_2784',
    21: 'ftp',
    20: 'ftp_data',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'domain_u',
    69: 'tftp_u',
    70: 'gopher',
    79: 'finger',
    109: 'pop_2',
    110: 'pop_3',
    119: 'nntp',
    123: 'ntp_u',
    143: 'imap4',
    161: 'snmp',
    162: 'snmp',
    512: 'exec',
    513: 'login',
    514: 'shell',
    515: 'printer',
    543: 'klogin',
    544: 'kshell',
    137: 'netbios_ns',
    138: 'netbios_dgm',
    139: 'netbios_ssn',
    445: 'netbios_ssn',
    389: 'ldap',
    111: 'sunrpc',
    179: 'bgp',
    113: 'auth',
    13: 'daytime',
    9: 'discard',
    7: 'echo',
    6000: 'X11',
    194: 'IRC',
    520: 'efs',
}

def resolve_service(port: int, protocol: str) -> str:
    """Map a port number and protocol to an NSL-KDD service name."""
    if protocol == 'icmp':
        return 'eco_i' if port == 8 else ('ecr_i' if port == 0 else 'tim_i')
    if port in PORT_SERVICE_MAP:
        return PORT_SERVICE_MAP[port]
    return 'private' if port > 1024 else 'other'

def map_tcp_flag(flags: int, is_syn: bool, is_ack: bool, is_fin: bool, is_rst: bool) -> str:
    """Map TCP flags to NSL-KDD connection status flags."""
    if is_syn and not is_ack:
        return 'S0'  # Connection attempt seen, no reply
    elif is_syn and is_ack:
        return 'S1'  # Established
    elif is_rst:
        return 'REJ' # Rejected
    elif is_fin:
        return 'SF'  # Normal termination
    elif is_ack:
        return 'SF'  # Normal established traffic
    return 'OTH'     # Other / Unknown

class PacketFlowTracker:
    """
    Maintains network flow state and time-window statistics to extract
    accurate NSL-KDD features from live traffic.
    """
    def __init__(self, time_window_seconds: float = 2.0, max_host_history: int = 100):
        self.window = time_window_seconds
        self.max_host_history = max_host_history
        self.lock = threading.Lock()

        # Flows: key = (src_ip, src_port, dst_ip, dst_port, protocol)
        self.active_flows: Dict[Tuple, Dict[str, Any]] = {}

        # Sliding window history of recent connections: deque of (timestamp, dst_ip, service, flag, src_port, src_ip)
        self.recent_connections = deque()

        # Destination host connection history: dst_ip -> deque of connection records
        self.host_history = defaultdict(lambda: deque(maxlen=max_host_history))

    def _cleanup_expired(self, current_time: float):
        """Purge records older than the sliding window."""
        while self.recent_connections and (current_time - self.recent_connections[0]['time'] > self.window):
            self.recent_connections.popleft()

        # Clean expired active flows inactive for > 60 seconds
        stale_flows = [
            k for k, flow in self.active_flows.items()
            if current_time - flow['last_seen'] > 60.0
        ]
        for k in stale_flows:
            del self.active_flows[k]

    def update_and_extract(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update flow statistics with incoming packet and return the 41 NSL-KDD features.
        """
        with self.lock:
            now = packet_info.get('timestamp', time.time())
            self._cleanup_expired(now)

            src_ip = packet_info.get('src_ip', '0.0.0.0')
            dst_ip = packet_info.get('dst_ip', '0.0.0.0')
            src_port = packet_info.get('src_port', 0)
            dst_port = packet_info.get('dst_port', 0)
            protocol = packet_info.get('protocol', 'tcp').lower()
            service = packet_info.get('service', 'other')
            flag = packet_info.get('flag', 'SF')
            payload_len = packet_info.get('payload_len', 0)
            wrong_fragment = packet_info.get('wrong_fragment', 0)
            urgent = packet_info.get('urgent', 0)

            # 5-tuple flow key
            forward_key = (src_ip, src_port, dst_ip, dst_port, protocol)
            reverse_key = (dst_ip, dst_port, src_ip, src_port, protocol)

            if forward_key in self.active_flows:
                flow = self.active_flows[forward_key]
                flow['src_bytes'] += payload_len
                flow['last_seen'] = now
                flow['packet_count'] += 1
                flow['flag'] = flag
            elif reverse_key in self.active_flows:
                flow = self.active_flows[reverse_key]
                flow['dst_bytes'] += payload_len
                flow['last_seen'] = now
                flow['packet_count'] += 1
            else:
                flow = {
                    'start_time': now,
                    'last_seen': now,
                    'src_bytes': payload_len,
                    'dst_bytes': 0,
                    'packet_count': 1,
                    'flag': flag
                }
                self.active_flows[forward_key] = flow

            duration = max(0.0, flow['last_seen'] - flow['start_time'])
            src_bytes = flow['src_bytes']
            dst_bytes = flow['dst_bytes']

            # Land attack condition: same source and destination IP & port
            land = 1 if (src_ip == dst_ip and src_port == dst_port and src_port != 0) else 0

            # Content flags (basic heuristics for live inspection)
            is_serror = flag in ['S0', 'S1', 'S2', 'S3']
            is_rerror = flag in ['REJ', 'RSTO', 'RSTR']

            # Record this connection
            conn_record = {
                'time': now,
                'dst_ip': dst_ip,
                'src_ip': src_ip,
                'src_port': src_port,
                'service': service,
                'flag': flag,
                'is_serror': is_serror,
                'is_rerror': is_rerror
            }
            self.recent_connections.append(conn_record)
            self.host_history[dst_ip].append(conn_record)

            # 1. Time-based features (last 2 seconds)
            same_dst_conns = [c for c in self.recent_connections if c['dst_ip'] == dst_ip]
            count = len(same_dst_conns)
            same_srv_conns = [c for c in self.recent_connections if c['service'] == service]
            srv_count = len(same_srv_conns)

            serror_count = sum(1 for c in same_dst_conns if c['is_serror'])
            rerror_count = sum(1 for c in same_dst_conns if c['is_rerror'])
            same_srv_same_dst = sum(1 for c in same_dst_conns if c['service'] == service)

            serror_rate = (serror_count / count) if count > 0 else 0.0
            rerror_rate = (rerror_count / count) if count > 0 else 0.0
            same_srv_rate = (same_srv_same_dst / count) if count > 0 else 1.0
            diff_srv_rate = 1.0 - same_srv_rate

            srv_serror_count = sum(1 for c in same_srv_conns if c['is_serror'])
            srv_rerror_count = sum(1 for c in same_srv_conns if c['is_rerror'])
            srv_diff_hosts = len(set(c['dst_ip'] for c in same_srv_conns))

            srv_serror_rate = (srv_serror_count / srv_count) if srv_count > 0 else 0.0
            srv_rerror_rate = (srv_rerror_count / srv_count) if srv_count > 0 else 0.0
            srv_diff_host_rate = (srv_diff_hosts / srv_count) if srv_count > 0 else 0.0

            # 2. Host-based features (up to 100 historical connections to dst_ip)
            h_conns = list(self.host_history[dst_ip])
            dst_host_count = min(255, len(h_conns))
            dst_host_srv_count = min(255, sum(1 for c in h_conns if c['service'] == service))

            h_serror_count = sum(1 for c in h_conns if c['is_serror'])
            h_rerror_count = sum(1 for c in h_conns if c['is_rerror'])
            h_same_src_port = sum(1 for c in h_conns if c['src_port'] == src_port)
            h_diff_hosts = len(set(c['src_ip'] for c in h_conns))

            dst_host_same_srv_rate = (dst_host_srv_count / dst_host_count) if dst_host_count > 0 else 1.0
            dst_host_diff_srv_rate = 1.0 - dst_host_same_srv_rate
            dst_host_same_src_port_rate = (h_same_src_port / dst_host_count) if dst_host_count > 0 else 0.0
            dst_host_srv_diff_host_rate = (h_diff_hosts / dst_host_count) if dst_host_count > 0 else 0.0
            dst_host_serror_rate = (h_serror_count / dst_host_count) if dst_host_count > 0 else 0.0
            dst_host_srv_serror_rate = srv_serror_rate
            dst_host_rerror_rate = (h_rerror_count / dst_host_count) if dst_host_count > 0 else 0.0
            dst_host_srv_rerror_rate = srv_rerror_rate

            return {
                'duration': float(duration),
                'protocol_type': protocol,
                'service': service,
                'flag': flag,
                'src_bytes': float(src_bytes),
                'dst_bytes': float(dst_bytes),
                'land': int(land),
                'wrong_fragment': float(wrong_fragment),
                'urgent': float(urgent),
                'hot': 0.0,
                'num_failed_logins': 0.0,
                'logged_in': 1.0 if flag == 'SF' else 0.0,
                'num_compromised': 0.0,
                'root_shell': 0.0,
                'su_attempted': 0.0,
                'num_root': 0.0,
                'num_file_creations': 0.0,
                'num_shells': 0.0,
                'num_access_files': 0.0,
                'num_outbound_cmds': 0.0,
                'is_host_login': 0.0,
                'is_guest_login': 0.0,
                'count': float(count),
                'srv_count': float(srv_count),
                'serror_rate': float(serror_rate),
                'srv_serror_rate': float(srv_serror_rate),
                'rerror_rate': float(rerror_rate),
                'srv_rerror_rate': float(srv_rerror_rate),
                'same_srv_rate': float(same_srv_rate),
                'diff_srv_rate': float(diff_srv_rate),
                'srv_diff_host_rate': float(srv_diff_host_rate),
                'dst_host_count': float(dst_host_count),
                'dst_host_srv_count': float(dst_host_srv_count),
                'dst_host_same_srv_rate': float(dst_host_same_srv_rate),
                'dst_host_diff_srv_rate': float(dst_host_diff_srv_rate),
                'dst_host_same_src_port_rate': float(dst_host_same_src_port_rate),
                'dst_host_srv_diff_host_rate': float(dst_host_srv_diff_host_rate),
                'dst_host_serror_rate': float(dst_host_serror_rate),
                'dst_host_srv_serror_rate': float(dst_host_srv_serror_rate),
                'dst_host_rerror_rate': float(dst_host_rerror_rate),
                'dst_host_srv_rerror_rate': float(dst_host_srv_rerror_rate)
            }


class LiveFeatureExtractor:
    """
    Parses a live Scapy packet and extracts complete NSL-KDD features.
    """
    def __init__(self, flow_tracker: Optional[PacketFlowTracker] = None):
        self.flow_tracker = flow_tracker or PacketFlowTracker()

    def extract_from_scapy(self, packet: scapy.packet.Packet) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Parses a Scapy packet, extracts metadata and runs flow-level feature extraction.
        Returns (features_dict, metadata_dict).
        """
        # Determine IP addresses
        src_ip = '0.0.0.0'
        dst_ip = '0.0.0.0'
        wrong_fragment = 0

        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            if packet[scapy.IP].frag != 0 or (packet[scapy.IP].flags & 1):
                wrong_fragment = 1
        elif packet.haslayer(scapy.IPv6):
            src_ip = packet[scapy.IPv6].src
            dst_ip = packet[scapy.IPv6].dst

        # Determine Protocol, Ports, Flags
        protocol = 'other'
        src_port = 0
        dst_port = 0
        flag = 'SF'
        urgent = 0
        payload_len = 0

        if packet.haslayer(scapy.TCP):
            protocol = 'tcp'
            tcp_layer = packet[scapy.TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = tcp_layer.flags
            urgent = 1 if tcp_layer.urgptr > 0 else 0

            is_syn = bool(flags & 0x02)
            is_ack = bool(flags & 0x10)
            is_fin = bool(flags & 0x01)
            is_rst = bool(flags & 0x04)
            flag = map_tcp_flag(flags, is_syn, is_ack, is_fin, is_rst)

            if packet.haslayer(scapy.Raw):
                payload_len = len(packet[scapy.Raw].load)

        elif packet.haslayer(scapy.UDP):
            protocol = 'udp'
            udp_layer = packet[scapy.UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            flag = 'SF'
            if packet.haslayer(scapy.Raw):
                payload_len = len(packet[scapy.Raw].load)

        elif packet.haslayer(scapy.ICMP):
            protocol = 'icmp'
            icmp_layer = packet[scapy.ICMP]
            src_port = icmp_layer.type
            dst_port = icmp_layer.code
            flag = 'SF'
            if packet.haslayer(scapy.Raw):
                payload_len = len(packet[scapy.Raw].load)

        elif packet.haslayer(scapy.ARP):
            protocol = 'arp'
            src_ip = packet[scapy.ARP].psrc
            dst_ip = packet[scapy.ARP].pdst
            flag = 'SF'

        # Target port determines the service
        target_port = dst_port if dst_port != 0 else src_port
        service = resolve_service(target_port, protocol)

        packet_info = {
            'timestamp': float(packet.time if hasattr(packet, 'time') and packet.time else time.time()),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'service': service,
            'flag': flag,
            'payload_len': payload_len,
            'wrong_fragment': wrong_fragment,
            'urgent': urgent
        }

        features = self.flow_tracker.update_and_extract(packet_info)

        metadata = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol.upper(),
            'service': service,
            'flag': flag,
            'payload_len': payload_len
        }

        return features, metadata
