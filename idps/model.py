import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple, Optional
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report

NSL_KDD_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']
NUMERICAL_FEATURES = [col for col in NSL_KDD_COLUMNS if col not in CATEGORICAL_FEATURES + ['label', 'difficulty']]

ATTACK_MAP = {
    'normal': 'Normal',
    # DoS (Denial of Service)
    'neptune': 'DoS', 'back': 'DoS', 'land': 'DoS', 'pod': 'DoS', 'smurf': 'DoS',
    'teardrop': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS', 'processtable': 'DoS',
    'udpstorm': 'DoS', 'worm': 'DoS',
    # Probe (Information Gathering / Port Scanning)
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',
    # R2L (Remote to Local unauthorized access)
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L',
    'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'sendmail': 'R2L', 'named': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L',
    # U2R (User to Root privilege escalation)
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
    'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R'
}

THREAT_LEVEL_MAP = {
    'Normal': 'LOW',
    'Probe': 'MEDIUM',
    'R2L': 'HIGH',
    'DoS': 'CRITICAL',
    'U2R': 'CRITICAL',
    'Unknown': 'HIGH'
}

class IDPSModel:
    """
    Intrusion Detection & Prevention System ML Model trained on NSL-KDD.
    Combines:
      - Binary anomaly detection (Normal vs Anomaly)
      - 5-class attack category classification (Normal, DoS, Probe, R2L, U2R)
      - Specific attack name classification
    """
    def __init__(self, model_bundle_path: Optional[str] = None):
        self.model_bundle_path = model_bundle_path
        self.is_trained = False
        self.binary_pipeline = None
        self.category_pipeline = None
        self.attack_pipeline = None
        self.metadata = {}

        if model_bundle_path and os.path.exists(model_bundle_path):
            self.load(model_bundle_path)

    @staticmethod
    def create_preprocessor() -> ColumnTransformer:
        return ColumnTransformer(
            transformers=[
                ('num', StandardScaler(), NUMERICAL_FEATURES),
                ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), CATEGORICAL_FEATURES)
            ]
        )

    def train(self,
              train_path: str,
              test_path: Optional[str] = None,
              n_estimators: int = 100,
              random_state: int = 42,
              save_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Train the IDPS models on NSL-KDD dataset.
        """
        print(f"[IDPS Training] Loading training dataset from: {train_path}...")
        train_df = pd.read_csv(train_path, names=NSL_KDD_COLUMNS)

        X_train = train_df.drop(columns=['label', 'difficulty'])
        y_train_label = train_df['label']
        y_train_binary = (y_train_label != 'normal').astype(int)
        y_train_category = y_train_label.map(lambda x: ATTACK_MAP.get(x, 'DoS'))

        print(f"[IDPS Training] Training set size: {len(train_df):,} samples.")
        print(f"[IDPS Training] Attack Category distribution:\n{y_train_category.value_counts().to_dict()}")

        print("[IDPS Training] Training Binary Anomaly Classifier...")
        bin_prep = self.create_preprocessor()
        bin_clf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=25,
            class_weight='balanced',
            random_state=random_state,
            n_jobs=-1
        )
        self.binary_pipeline = Pipeline([('prep', bin_prep), ('clf', bin_clf)])
        self.binary_pipeline.fit(X_train, y_train_binary)

        print("[IDPS Training] Training Multi-class Attack Category Classifier...")
        cat_prep = self.create_preprocessor()
        cat_clf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=25,
            class_weight='balanced',
            random_state=random_state,
            n_jobs=-1
        )
        self.category_pipeline = Pipeline([('prep', cat_prep), ('clf', cat_clf)])
        self.category_pipeline.fit(X_train, y_train_category)

        print("[IDPS Training] Training Granular Attack Type Classifier...")
        atk_prep = self.create_preprocessor()
        atk_clf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=25,
            random_state=random_state,
            n_jobs=-1
        )
        self.attack_pipeline = Pipeline([('prep', atk_prep), ('clf', atk_clf)])
        self.attack_pipeline.fit(X_train, y_train_label)

        self.is_trained = True

        eval_results = {}
        if test_path and os.path.exists(test_path):
            print(f"[IDPS Training] Evaluating model on test set: {test_path}...")
            test_df = pd.read_csv(test_path, names=NSL_KDD_COLUMNS)
            X_test = test_df.drop(columns=['label', 'difficulty'])
            y_test_label = test_df['label']
            y_test_binary = (y_test_label != 'normal').astype(int)
            y_test_category = y_test_label.map(lambda x: ATTACK_MAP.get(x, 'DoS'))

            # Binary metrics
            y_pred_binary = self.binary_pipeline.predict(X_test)
            bin_acc = accuracy_score(y_test_binary, y_pred_binary)
            bin_p, bin_r, bin_f1, _ = precision_recall_fscore_support(y_test_binary, y_pred_binary, average='binary')

            # Category metrics
            y_pred_category = self.category_pipeline.predict(X_test)
            cat_acc = accuracy_score(y_test_category, y_pred_category)

            eval_results = {
                'test_samples': len(test_df),
                'binary_accuracy': float(bin_acc),
                'binary_precision': float(bin_p),
                'binary_recall': float(bin_r),
                'binary_f1': float(bin_f1),
                'category_accuracy': float(cat_acc),
                'category_report': classification_report(y_test_category, y_pred_category, output_dict=True, zero_division=0)
            }

            print(f"[IDPS Evaluation] Test Binary Accuracy: {bin_acc * 100:.2f}% | Precision: {bin_p * 100:.2f}% | Recall: {bin_r * 100:.2f}% | F1: {bin_f1 * 100:.2f}%")
            print(f"[IDPS Evaluation] Attack Category Accuracy: {cat_acc * 100:.2f}%")

        self.metadata = {
            'train_dataset': train_path,
            'test_dataset': test_path,
            'train_samples': len(train_df),
            'n_estimators': n_estimators,
            'evaluation': eval_results,
            'features': NUMERICAL_FEATURES + CATEGORICAL_FEATURES,
            'attack_categories': list(set(ATTACK_MAP.values()))
        }

        if save_path:
            self.save(save_path)

        return eval_results

    def save(self, filepath: str):
        """Save the trained model bundle to disk."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        bundle = {
            'binary_pipeline': self.binary_pipeline,
            'category_pipeline': self.category_pipeline,
            'attack_pipeline': self.attack_pipeline,
            'metadata': self.metadata
        }
        joblib.dump(bundle, filepath, compress=3)
        print(f"[IDPS Model] Model bundle successfully saved to {filepath}")

        # Also write readable metadata json
        meta_path = os.path.splitext(filepath)[0] + "_metadata.json"
        try:
            with open(meta_path, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            print(f"Warning: could not save metadata json: {e}")

    def load(self, filepath: str):
        """Load the trained model bundle from disk."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"IDPS model file not found at: {filepath}")
        bundle = joblib.load(filepath)
        self.binary_pipeline = bundle['binary_pipeline']
        self.category_pipeline = bundle['category_pipeline']
        self.attack_pipeline = bundle.get('attack_pipeline')
        self.metadata = bundle.get('metadata', {})
        self.is_trained = True
        self.model_bundle_path = filepath
        print(f"[IDPS Model] Successfully loaded pre-trained model from {filepath}")

    def predict(self, feature_dict: Dict[str, Any], confidence_threshold: float = 0.65) -> Dict[str, Any]:
        """
        Run inference on a single connection/packet feature dictionary.
        Returns a rich classification dictionary:
        {
            'is_attack': bool,
            'anomaly_score': float,
            'category': str,
            'attack_type': str,
            'confidence': float,
            'threat_level': str
        }
        """
        if not self.is_trained:
            raise RuntimeError("IDPSModel is not loaded or trained yet.")

        # Ensure all expected feature columns exist
        df_row = pd.DataFrame([feature_dict])
        for col in NUMERICAL_FEATURES:
            if col not in df_row.columns:
                df_row[col] = 0.0
            else:
                df_row[col] = pd.to_numeric(df_row[col], errors='coerce').fillna(0.0)

        for col in CATEGORICAL_FEATURES:
            if col not in df_row.columns:
                df_row[col] = 'other' if col == 'service' else ('tcp' if col == 'protocol_type' else 'SF')
            else:
                df_row[col] = df_row[col].astype(str)

        # Order columns identically
        feature_order = NUMERICAL_FEATURES + CATEGORICAL_FEATURES
        df_ordered = df_row[feature_order]

        # 1. Binary prediction & anomaly probability
        bin_probs = self.binary_pipeline.predict_proba(df_ordered)[0]
        # bin_probs: [prob_normal, prob_anomaly]
        anomaly_score = float(bin_probs[1]) if len(bin_probs) > 1 else float(bin_probs[0])
        is_attack = anomaly_score >= confidence_threshold

        # 2. Multi-class Category prediction
        cat_probs = self.category_pipeline.predict_proba(df_ordered)[0]
        cat_classes = self.category_pipeline.named_steps['clf'].classes_
        cat_idx = np.argmax(cat_probs)
        predicted_category = str(cat_classes[cat_idx])
        category_confidence = float(cat_probs[cat_idx])

        # 3. Specific attack prediction
        if self.attack_pipeline is not None:
            atk_probs = self.attack_pipeline.predict_proba(df_ordered)[0]
            atk_classes = self.attack_pipeline.named_steps['clf'].classes_
            atk_idx = np.argmax(atk_probs)
            predicted_attack = str(atk_classes[atk_idx])
        else:
            predicted_attack = 'anomaly' if is_attack else 'normal'

        # If binary classifier says normal, override category to Normal unless anomaly score is high
        if not is_attack:
            category = 'Normal'
            attack_type = 'normal'
            threat_level = 'LOW'
            confidence = float(bin_probs[0])
        else:
            if predicted_category == 'Normal':
                # Anomaly detected by binary model but category predicted Normal
                category = ATTACK_MAP.get(predicted_attack, 'DoS')
                if category == 'Normal':
                    category = 'DoS'
            else:
                category = predicted_category
            attack_type = predicted_attack if predicted_attack != 'normal' else category.lower()
            threat_level = THREAT_LEVEL_MAP.get(category, 'HIGH')
            confidence = max(anomaly_score, category_confidence)

        return {
            'is_attack': is_attack,
            'anomaly_score': anomaly_score,
            'category': category,
            'attack_type': attack_type,
            'confidence': confidence,
            'threat_level': threat_level
        }
