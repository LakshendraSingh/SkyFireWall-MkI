import os
import time
from typing import Dict, Any, Optional, Set
import scapy.all as scapy

from .model import IDPSModel
from .feature_extractor import LiveFeatureExtractor, PacketFlowTracker
from .prevention import FirewallPreventionManager
from .alert_logger import IDPSAlertLogger

DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models",
    "idps_nsl_kdd.joblib"
)

class IDPSEngine:
    """
    Unified Intrusion Detection and Prevention Engine.
    Performs real-time packet inspection, anomaly & attack detection using the
    NSL-KDD trained model, and dynamic firewall prevention blocking.
    """
    def __init__(self,
                 model_path: Optional[str] = None,
                 confidence_threshold: float = 0.65,
                 auto_train_if_missing: bool = True,
                 enable_prevention: bool = True,
                 local_ips: Optional[Set[str]] = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.confidence_threshold = confidence_threshold
        self.enable_prevention = enable_prevention
        self.feature_extractor = LiveFeatureExtractor()
        self.prevention_manager = FirewallPreventionManager(protected_ips=local_ips)
        self.alert_logger = IDPSAlertLogger()

        self.model = IDPSModel()
        self._initialize_model(auto_train_if_missing)

    def _initialize_model(self, auto_train: bool):
        """Load pre-trained model or train on NSL-KDD dataset if not found."""
        if os.path.exists(self.model_path):
            print(f"[IDPS Engine] Loading NSL-KDD model from: {self.model_path}")
            self.model.load(self.model_path)
        elif auto_train:
            print("[IDPS Engine] No pre-trained model found. Initializing training on NSL-KDD dataset...")
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            train_path = os.path.join(base_dir, "NSL-KDD", "KDDTrain+.txt")
            test_path = os.path.join(base_dir, "NSL-KDD", "KDDTest+.txt")

            if not os.path.exists(train_path):
                # Fallback to 20% train if KDDTrain+.txt missing
                train_path = os.path.join(base_dir, "NSL-KDD", "KDDTrain+_20Percent.txt")

            if os.path.exists(train_path):
                self.model.train(
                    train_path=train_path,
                    test_path=test_path,
                    n_estimators=100,
                    save_path=self.model_path
                )
            else:
                raise FileNotFoundError(f"[IDPS Engine] NSL-KDD dataset not found at {train_path}")
        else:
            raise FileNotFoundError(f"[IDPS Engine] Pre-trained model not found at {self.model_path}")

    def inspect_and_enforce(self, packet: scapy.packet.Packet) -> Dict[str, Any]:
        """
        Inspect a network packet:
        1. Extract flow and packet features matching NSL-KDD schema.
        2. Predict anomaly, attack category, and specific attack type.
        3. Trigger dynamic firewall blocking if an intrusion is detected.
        """
        features, metadata = self.feature_extractor.extract_from_scapy(packet)
        prediction = self.model.predict(features, confidence_threshold=self.confidence_threshold)

        src_ip = metadata.get('src_ip', '0.0.0.0')
        dst_ip = metadata.get('dst_ip', '0.0.0.0')
        proto = metadata.get('protocol', 'OTHER')
        service = metadata.get('service', 'other')
        packet_summary = packet.summary() if hasattr(packet, 'summary') else str(packet)

        is_attack = prediction['is_attack']
        category = prediction['category']
        attack_type = prediction['attack_type']
        confidence = prediction['confidence']
        threat_level = prediction['threat_level']

        ips_action = "ALLOW"
        attacker_ip = src_ip
        victim_ip = dst_ip

        # If already blocked by IDPS
        if self.prevention_manager.is_blocked(attacker_ip):
            ips_action = "DROPPED (ALREADY BLOCKED BY IDPS)"
            is_attack = True
        elif is_attack:
            # Active Prevention
            if self.enable_prevention and not self.prevention_manager.is_protected(attacker_ip):
                blocked = self.prevention_manager.block_ip(
                    attacker_ip,
                    attack_info=f"{category}/{attack_type} ({confidence:.1%})"
                )
                ips_action = "DYNAMICALLY BLOCKED AT FIREWALL" if blocked else "BLOCKED (ACTIVE)"
            else:
                ips_action = "DETECTED (LOGGED ONLY)"

            # Log to CSV and display visual alert banner
            self.alert_logger.log_alert(
                attacker_ip=attacker_ip,
                victim_ip=victim_ip,
                protocol=proto,
                service=service,
                category=category,
                attack_type=attack_type,
                confidence=confidence,
                threat_level=threat_level,
                ips_action=ips_action,
                packet_summary=packet_summary
            )

        return {
            'is_attack': is_attack,
            'category': category,
            'attack_type': attack_type,
            'confidence': confidence,
            'threat_level': threat_level,
            'ips_action': ips_action,
            'attacker_ip': attacker_ip,
            'victim_ip': victim_ip,
            'protocol': proto,
            'service': service,
            'features': features
        }

    def shutdown(self):
        """Clean up all dynamic IDPS firewall blocks."""
        self.prevention_manager.unblock_all()
