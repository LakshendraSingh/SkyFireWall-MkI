#!/usr/bin/env python3
"""
SkyFireWall IDPS Training Pipeline
Trains Intrusion Detection and Prevention Model on NSL-KDD Dataset.
"""

import os
import sys
import argparse
import time

# Ensure project root is in python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from idps.model import IDPSModel

def parse_args():
    parser = argparse.ArgumentParser(description="Train SkyFireWall IDPS on NSL-KDD Dataset")
    parser.add_argument(
        "--train-data",
        type=str,
        default=os.path.join(BASE_DIR, "NSL-KDD", "KDDTrain+.txt"),
        help="Path to training dataset (e.g. KDDTrain+.txt or KDDTrain+_20Percent.txt)"
    )
    parser.add_argument(
        "--test-data",
        type=str,
        default=os.path.join(BASE_DIR, "NSL-KDD", "KDDTest+.txt"),
        help="Path to test dataset (e.g. KDDTest+.txt)"
    )
    parser.add_argument(
        "--save-model",
        type=str,
        default=os.path.join(BASE_DIR, "models", "idps_nsl_kdd.joblib"),
        help="Path to save trained model bundle"
    )
    parser.add_argument(
        "--estimators",
        type=int,
        default=100,
        help="Number of decision trees (default: 100)"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Use KDDTrain+_20Percent.txt for ultra-fast training (< 2 seconds)"
    )
    return parser.parse_args()

def main():
    args = parse_args()

    train_file = args.train_data
    if args.quick or not os.path.exists(train_file):
        quick_file = os.path.join(BASE_DIR, "NSL-KDD", "KDDTrain+_20Percent.txt")
        if os.path.exists(quick_file):
            train_file = quick_file
            print(f"[*] Using quick dataset: {train_file}")

    if not os.path.exists(train_file):
        print(f"[!] Error: Training file not found at {train_file}")
        sys.exit(1)

    test_file = args.test_data if os.path.exists(args.test_data) else None

    print("=" * 70)
    print("   🛡️  SKYFIREWALL IDPS: NSL-KDD MODEL TRAINING PIPELINE  🛡️")
    print("=" * 70)
    print(f"[*] Training Data: {train_file}")
    print(f"[*] Test Data:     {test_file or 'None'}")
    print(f"[*] Output Model:  {args.save_model}")
    print(f"[*] Estimators:    {args.estimators}")
    print("-" * 70)

    start_time = time.time()
    model = IDPSModel()
    metrics = model.train(
        train_path=train_file,
        test_path=test_file,
        n_estimators=args.estimators,
        save_path=args.save_model
    )
    duration = time.time() - start_time

    print("=" * 70)
    print(f"✅ Training completed successfully in {duration:.2f} seconds!")
    if metrics:
        print(f"   Binary Accuracy:   {metrics.get('binary_accuracy', 0)*100:.2f}%")
        print(f"   Binary Precision:  {metrics.get('binary_precision', 0)*100:.2f}%")
        print(f"   Binary Recall:     {metrics.get('binary_recall', 0)*100:.2f}%")
        print(f"   Binary F1 Score:   {metrics.get('binary_f1', 0)*100:.2f}%")
        print(f"   Category Accuracy: {metrics.get('category_accuracy', 0)*100:.2f}%")
    print(f"   Model Artifact:    {args.save_model}")
    print("=" * 70)

if __name__ == "__main__":
    main()
