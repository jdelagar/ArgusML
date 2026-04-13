#!/usr/bin/env python3
"""
ArgusML Continuous Learning Engine
Automatically retrains models as new threats are detected.
ArgusML gets smarter the longer it runs.
"""

import os
import sys
import json
import time
import shutil
import threading
import numpy as np
import pandas as pd
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, "/home/cerberus-s6/argusml")

DATASETS_DIR = "/home/cerberus-s6/argusml/datasets"
MODELS_DIR = "/home/cerberus-s6/argusml/models"
FUSION_DECISIONS = "/home/cerberus-s6/argusml/output/fusion_decisions.jsonl"
RETRAIN_INTERVAL = 3600   # Retrain every hour
MIN_NEW_SAMPLES = 50      # Minimum new samples before retraining
MIN_ACCURACY = 0.95       # Only deploy if accuracy meets threshold


class ContinuousLearningEngine:
    """
    Continuously retrains ArgusML models as new threats are detected.
    Runs as a background thread — never interrupts live detection.
    """

    def __init__(self, streams, fusion):
        self.streams = streams
        self.fusion = fusion
        self.last_retrain = datetime.now()
        self.retrain_count = defaultdict(int)
        self.improvement_history = []
        self.new_samples_since_retrain = defaultdict(int)
        self.is_running = False
        print("[continuous_learning] Engine initialized")

    def extract_suricata_sample(self, decision):
        """Extract Suricata features from a fusion decision."""
        confidences = decision.get("stream_confidences", {})
        if "suricata" not in confidences:
            return None

        return {
            "fl_dur": 0.0,
            "fw_pk": 0.0,
            "l_fw_pkt": 0.0,
            "l_bw_pkt": 0.0,
            "pkt_len_min": 0.0,
            "pkt_len_max": 0.0,
            "pkt_len_std": 0.0,
            "fl_byt_s": 0.0,
            "fl_iat_min": 0.0,
            "bw_iat_tot": 0.0,
            "bw_iat_min": 0.0,
            "bw_psh_flag": 0,
            "fw_urg_flag": 0,
            "bw_urg_flag": 0,
            "fw_hdr_len": 40,
            "bw_pkt_s": 0.0,
            "fin_cnt": 0,
            "syn_cnt": 0,
            "psh_cnt": 0,
            "urg_cnt": 0,
            "ece_cnt": 0,
            "down_up_ratio": 0.0,
            "fw_byt_blk_avg": 0.0,
            "fw_pkt_blk_avg": 0.0,
            "fw_blk_rate_avg": 0.0,
            "bw_byt_blk_avg": 0.0,
            "bw_pkt_blk_avg": 0.0,
            "bw_blk_rate_avg": 0.0,
            "fw_win_byt": 0,
            "bw_win_byt": 0,
            "Label": decision.get("fused_label", "normal"),
        }

    def add_detection_to_dataset(self, decision):
        """Add a confirmed detection to the training dataset."""
        label = decision.get("fused_label", "normal")
        confidence = decision.get("fused_confidence", 0)

        # Only add high confidence detections
        if confidence < 0.85:
            return

        streams_consulted = decision.get("streams_consulted", [])

        if "suricata" in streams_consulted:
            sample = self.extract_suricata_sample(decision)
            if sample:
                csv_path = os.path.join(DATASETS_DIR, "suricata.csv")
                self._append_to_csv(csv_path, sample)
                self.new_samples_since_retrain["suricata"] += 1

    def _append_to_csv(self, csv_path, sample):
        """Append a new sample to the training CSV."""
        try:
            df_new = pd.DataFrame([sample])
            if os.path.exists(csv_path):
                df_new.to_csv(csv_path, mode="a", header=False, index=False)
            else:
                df_new.to_csv(csv_path, index=False)
        except Exception as e:
            print(f"[continuous_learning] Error appending to {csv_path}: {e}")

    def should_retrain(self, stream_name):
        """Check if a stream should be retrained."""
        time_since_retrain = (datetime.now() - self.last_retrain).seconds
        new_samples = self.new_samples_since_retrain.get(stream_name, 0)

        return (
            time_since_retrain >= RETRAIN_INTERVAL and
            new_samples >= MIN_NEW_SAMPLES
        )

    def retrain_stream(self, stream_name, stream):
        """Retrain a single stream model."""
        csv_path = os.path.join(DATASETS_DIR, f"{stream_name}.csv")
        if not os.path.exists(csv_path):
            print(f"[continuous_learning] No dataset for {stream_name}")
            return False

        print(f"[continuous_learning] Retraining {stream_name} stream...")

        try:
            X, y = stream.load_training_data(csv_path)
            if X is None or len(X) < 100:
                print(f"[continuous_learning] Not enough data for {stream_name}")
                return False

            # Save old model
            old_accuracy = stream.accuracy
            old_model_path = os.path.join(MODELS_DIR, f"{stream_name}.joblib")
            backup_path = os.path.join(MODELS_DIR, f"{stream_name}_backup.joblib")
            if os.path.exists(old_model_path):
                shutil.copy(old_model_path, backup_path)

            # Train new model
            stream.train(X, y)
            new_accuracy = stream.accuracy

            # Compare
            improvement = new_accuracy - old_accuracy
            self.improvement_history.append({
                "stream": stream_name,
                "timestamp": datetime.now().isoformat(),
                "old_accuracy": old_accuracy,
                "new_accuracy": new_accuracy,
                "improvement": improvement,
                "training_samples": len(X),
            })

            if new_accuracy >= MIN_ACCURACY:
                print(f"[continuous_learning] {stream_name} retrained successfully!")
                print(f"[continuous_learning] Accuracy: {old_accuracy:.4f} → {new_accuracy:.4f} ({improvement:+.4f})")
                self.retrain_count[stream_name] += 1
                self.fusion.weights[stream_name] = max(0.5, new_accuracy * 2)
                self.new_samples_since_retrain[stream_name] = 0
                return True
            else:
                print(f"[continuous_learning] {stream_name} accuracy {new_accuracy:.4f} below threshold — restoring backup")
                if os.path.exists(backup_path):
                    shutil.copy(backup_path, old_model_path)
                    stream.load_model()
                return False

        except Exception as e:
            print(f"[continuous_learning] Retrain error for {stream_name}: {e}")
            return False

    def retrain_all(self):
        """Retrain all streams that need it."""
        print(f"[continuous_learning] Checking all streams for retraining...")
        retrained = []
        for name, stream in self.streams.items():
            if self.should_retrain(name):
                success = self.retrain_stream(name, stream)
                if success:
                    retrained.append(name)
        self.last_retrain = datetime.now()
        if retrained:
            print(f"[continuous_learning] Retrained: {retrained}")
        return retrained

    def process_decision(self, decision):
        """Process a new fusion decision for continuous learning."""
        label = decision.get("fused_label", "normal")
        if label != "normal":
            self.add_detection_to_dataset(decision)

    def get_stats(self):
        """Return continuous learning statistics."""
        return {
            "last_retrain": str(self.last_retrain),
            "retrain_counts": dict(self.retrain_count),
            "new_samples_pending": dict(self.new_samples_since_retrain),
            "improvement_history": self.improvement_history[-10:],
            "retrain_interval_seconds": RETRAIN_INTERVAL,
            "min_new_samples": MIN_NEW_SAMPLES,
        }

    def run(self):
        """Run continuous learning in background thread."""
        self.is_running = True
        print(f"[continuous_learning] Starting — retrain interval: {RETRAIN_INTERVAL}s, min samples: {MIN_NEW_SAMPLES}")

        while self.is_running:
            try:
                self.retrain_all()
            except Exception as e:
                print(f"[continuous_learning] Error: {e}")
            time.sleep(60)  # Check every minute

    def start(self):
        """Start continuous learning in background thread."""
        t = threading.Thread(target=self.run, daemon=True)
        t.start()
        print("[continuous_learning] Background thread started")
        return t

    def stop(self):
        self.is_running = False
