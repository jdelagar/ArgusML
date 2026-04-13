#!/usr/bin/env python3
"""
ArgusML
Autonomous ML-driven Intrusion Detection & Prevention System
Built by Juan Manuel De La Garza

A next-generation IDPS that combines:
- Real time network traffic analysis
- Adaptive Bayesian fusion of multiple ML streams
- Isolation Forest zero-day detection
- Local LLM autonomous rule generation
- Explainable AI — tells you WHY it flagged something
"""

import os
import sys
import time
import argparse
import json
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import (
    DATASETS_DIR,
    MODELS_DIR,
    OUTPUT_DIR,
    CONFIDENCE_THRESHOLD,
)
from streams.suricata import SuricataStream
from streams.dns import DNSStream
from streams.tls import TLSStream
from fusion.bayesian import BayesianFusion
from output.rule_generator import RuleGenerator


class ArgusML:
    """
    Main ArgusML engine.
    Coordinates all streams, fusion, and rule generation.
    """

    def __init__(self, args):
        self.args = args
        self.streams = {}
        self.fusion = BayesianFusion()
        self.rule_generator = RuleGenerator()
        self.running = False
        self.total_detections = 0
        self.start_time = None

        print("=" * 60)
        print("  ARGUS-ML — Autonomous IDPS")
        print("  Built by Juan Manuel De La Garza")
        print("=" * 60)

        self._init_streams()

    def _init_streams(self):
        """Initialize all detection streams."""
        print("\n[argus_ml] Initializing streams...")

        # Suricata stream
        suricata = SuricataStream()
        if self.args.train:
            self._train_stream(suricata)
        else:
            if not suricata.load_model():
                print("[argus_ml] No Suricata model found — training now...")
                self._train_stream(suricata)

        self.streams["suricata"] = suricata
        print(f"[argus_ml] Suricata stream ready — accuracy: {suricata.accuracy:.4f}")

        # Update fusion weights based on stream accuracy
        self.fusion.weights["suricata"] = max(0.5, suricata.accuracy * 2)

        # DNS stream
        dns = DNSStream()
        if self.args.train:
            self._train_stream(dns)
        else:
            if not dns.load_model():
                print("[argus_ml] No DNS model found — training now...")
                self._train_stream(dns)
        self.streams["dns"] = dns
        self.fusion.weights["dns"] = max(0.5, dns.accuracy * 2)
        print(f"[argus_ml] DNS stream ready — accuracy: {dns.accuracy:.4f}")

        # TLS stream
        tls = TLSStream()
        if self.args.train:
            self._train_stream(tls)
        else:
            if not tls.load_model():
                print("[argus_ml] No TLS model found — training now...")
                self._train_stream(tls)
        self.streams["tls"] = tls
        self.fusion.weights["tls"] = max(0.5, tls.accuracy * 2)
        print(f"[argus_ml] TLS stream ready — accuracy: {tls.accuracy:.4f}")

    def _train_stream(self, stream):
        """Train a stream on available data."""
        csv_path = os.path.join(DATASETS_DIR, f"{stream.get_stream_name()}.csv")

        if not os.path.exists(csv_path):
            print(f"[argus_ml] No training data found at {csv_path}")
            print(f"[argus_ml] Run with --fetch-data first to get training data")
            return

        X, y = stream.load_training_data(csv_path)
        if X is not None and y is not None:
            stream.train(X, y)
        else:
            print(f"[argus_ml] Failed to load training data for {stream.get_stream_name()}")

    def _on_detection(self, stream_results):
        """
        Callback when a stream detects something.
        Fuses results and generates rules if needed.
        """
        if not stream_results:
            return

        # Group by threat label and take highest confidence per label
        threat_groups = {}
        for result in stream_results:
            # Normalize label to lowercase with underscores
            label = result["label"].lower().replace(" ", "_")
            if not label.endswith("_activity") and label not in ("normal", "port_scan", "unknown_anomaly"):
                label = label + "_activity"
            result["label"] = label
            if label not in threat_groups or result["confidence"] > threat_groups[label]["confidence"]:
                threat_groups[label] = result

        # Fuse unique threats
        for label, best_result in threat_groups.items():
            decision = self.fusion.fuse([best_result])
            fused_label = decision["fused_label"]
            confidence = decision["fused_confidence"]

            if fused_label != "normal":
                self.total_detections += 1
                print(f"\n[DETECTION #{self.total_detections}] {datetime.now().strftime('%H:%M:%S')}")
                print(f"  Threat:     {fused_label}")
                print(f"  Confidence: {confidence:.1%}")
                print(f"  Streams:    {', '.join(decision['streams_consulted'])}")
                print(f"  Explanation: {decision['explanation']}")

                # Generate rules
                new_rules = self.rule_generator.process_decisions([decision])
                if new_rules:
                    self.rule_generator.write_rules()
                    print(f"  ✓ Generated {len(new_rules)} new Suricata rule(s)")

            # Log to output file
            self._log_decision(decision)

    def _log_decision(self, decision):
        """Log fusion decision to output file."""
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        log_path = os.path.join(OUTPUT_DIR, "fusion_decisions.jsonl")
        with open(log_path, "a") as f:
            f.write(json.dumps(decision) + "\n")

    def print_stats(self):
        """Print current system statistics."""
        uptime = datetime.now() - self.start_time if self.start_time else None
        print("\n" + "=" * 60)
        print("  ARGUS-ML STATISTICS")
        print("=" * 60)

        if uptime:
            print(f"  Uptime: {str(uptime).split('.')[0]}")

        print(f"  Total detections: {self.total_detections}")
        print()

        for name, stream in self.streams.items():
            stats = stream.get_stats()
            print(f"  Stream: {name}")
            print(f"    Accuracy:     {stats['accuracy']:.4f}")
            print(f"    F1 Score:     {stats['f1_score']:.4f}")
            print(f"    Predictions:  {stats['total_predictions']}")
            print(f"    Avg Confidence: {stats['avg_confidence']:.2%}")

        print()
        fusion_stats = self.fusion.get_stats()
        print(f"  Fusion Engine:")
        print(f"    Total fusions: {fusion_stats['total_fusions']}")
        print(f"    Stream weights: {fusion_stats['stream_weights']}")

        print()
        rule_stats = self.rule_generator.get_stats()
        print(f"  Rule Generator:")
        print(f"    Rules generated: {rule_stats['total_generated']}")
        print(f"    Rules suppressed: {rule_stats['total_suppressed']}")
        print("=" * 60)

    def run(self):
        """Start ArgusML."""
        self.running = True
        self.start_time = datetime.now()

        print(f"\n[argus_ml] Starting at {self.start_time}")
        print(f"[argus_ml] Confidence threshold: {CONFIDENCE_THRESHOLD:.0%}")
        print(f"[argus_ml] Monitoring {len(self.streams)} stream(s)")
        print(f"[argus_ml] Press Ctrl+C to stop\n")

        # Print stats every 5 minutes
        last_stats = time.time()
        STATS_INTERVAL = 300

        try:
            import threading
            threads = []
            for name, stream in self.streams.items():
                if stream.is_trained:
                    print(f"[argus_ml] Starting {name} stream...")
                    t = threading.Thread(
                        target=stream.run_live,
                        kwargs={
                            "callback": self._on_detection,
                            "poll_interval": self.args.poll_interval,
                        },
                        daemon=True
                    )
                    t.start()
                    threads.append(t)

            if not threads:
                print("[argus_ml] No trained streams available — exiting")
            else:
                print(f"[argus_ml] {len(threads)} stream(s) running...")
                for t in threads:
                    t.join()

        except KeyboardInterrupt:
            print("\n[argus_ml] Shutting down...")
            self.print_stats()


def parse_args():
    parser = argparse.ArgumentParser(
        description="ArgusML — Autonomous ML-driven IDPS"
    )
    parser.add_argument(
        "--train",
        action="store_true",
        help="Force retrain all models",
    )
    parser.add_argument(
        "--fetch-data",
        action="store_true",
        help="Fetch latest training data from R2",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print stats and exit",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=5,
        help="How often to check for new events (seconds)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    engine = ArgusML(args)

    if args.stats:
        engine.print_stats()
    else:
        engine.run()
