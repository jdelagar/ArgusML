#!/usr/bin/env python3
"""
ArgusML Suricata Stream
Reads live eve.json, extracts features, detects threats.
"""

import json
import os
import time
import numpy as np
import pandas as pd
from datetime import datetime
from core.base import BaseStream
from core.config import SURICATA_EVE_LOG


# Feature columns — consistent with our feature extractor
FEATURE_COLUMNS = [
    "fl_dur", "fl_byt_s", "fl_iat_min", "fw_pk", "l_fw_pkt",
    "l_bw_pkt", "bw_pkt_s", "pkt_len_min", "pkt_len_max", "pkt_len_std",
    "fin_cnt", "syn_cnt", "psh_cnt", "urg_cnt", "ece_cnt",
    "bw_psh_flag", "fw_urg_flag", "bw_urg_flag", "fw_win_byt", "bw_win_byt",
    "fw_byt_blk_avg", "fw_pkt_blk_avg", "fw_blk_rate_avg",
    "bw_byt_blk_avg", "bw_pkt_blk_avg", "bw_blk_rate_avg",
    "bw_iat_tot", "bw_iat_min", "fw_hdr_len", "down_up_ratio",
]

# Label mapping from Suricata signatures
LABEL_MAP = {
    "ddos": "ddos_activity",
    "flood": "ddos_activity",
    "botnet": "botnet_activity",
    "c2": "botnet_activity",
    "command and control": "botnet_activity",
    "backdoor": "backdoor_activity",
    "rat": "backdoor_activity",
    "trojan": "backdoor_activity",
    "web attack": "web_attack_activity",
    "sql injection": "web_attack_activity",
    "xss": "web_attack_activity",
    "exploit": "web_attack_activity",
    "scan": "port_scan",
    "sweep": "port_scan",
    "brute": "port_scan",
}


class SuricataStream(BaseStream):
    """
    Live Suricata network traffic detection stream.
    Reads eve.json in real time and detects threats.
    """

    def __init__(self):
        super().__init__()
        self.eve_log = SURICATA_EVE_LOG
        self.last_position = 0
        self.processed_events = 0
        self.threat_counts = {}

    def get_stream_name(self):
        return "suricata"

    def map_label(self, event):
        """Map Suricata signature to threat taxonomy label."""
        signature = event.get("alert", {}).get("signature", "").lower()
        category = event.get("alert", {}).get("category", "").lower()

        for key, label in LABEL_MAP.items():
            if key in signature or key in category:
                return label

        # Check for anomalies based on flow data
        flow = event.get("flow", {})
        pkts = float(flow.get("pkts_toserver", 0) or 0)
        bytes_to = float(flow.get("bytes_toserver", 0) or 0)

        if pkts > 10000:
            return "ddos_activity"
        if bytes_to > 10000000:
            return "unknown_anomaly"

        return "normal"

    def extract_features(self, raw_data):
        """
        Extract 30 features from Suricata eve.json events.
        raw_data can be a list of events or a single event dict.
        """
        if isinstance(raw_data, dict):
            raw_data = [raw_data]

        rows = []
        for event in raw_data:
            if event.get("event_type") not in ("alert", "flow"):
                continue
            try:
                row = self._extract_single(event)
                rows.append(row)
            except Exception as e:
                print(f"[suricata] Feature extraction error: {e}")
                continue

        if not rows:
            return pd.DataFrame()

        df = pd.DataFrame(rows)
        return df

    def _extract_single(self, event):
        """Extract features from a single eve.json event."""
        flow = event.get("flow", {})
        tcp = event.get("tcp", {})
        flags = str(tcp.get("tcp_flags", "") or "")

        bytes_to = float(flow.get("bytes_toserver", 0) or 0)
        bytes_from = float(flow.get("bytes_toclient", 0) or 0)
        pkts_to = float(flow.get("pkts_toserver", 0) or 0)
        pkts_from = float(flow.get("pkts_toclient", 0) or 0)
        age = float(flow.get("age", 0) or 0)

        return {
            "fl_dur": age,
            "fl_byt_s": bytes_to / max(age, 1),
            "fl_iat_min": 0.0,
            "fw_pk": pkts_to,
            "l_fw_pkt": pkts_to,
            "l_bw_pkt": pkts_from,
            "bw_pkt_s": bytes_from / max(age, 1),
            "pkt_len_min": 0.0,
            "pkt_len_max": 0.0,
            "pkt_len_std": 0.0,
            "fin_cnt": 1.0 if "FIN" in flags else 0.0,
            "syn_cnt": 1.0 if "SYN" in flags else 0.0,
            "psh_cnt": 1.0 if "PSH" in flags else 0.0,
            "urg_cnt": 1.0 if "URG" in flags else 0.0,
            "ece_cnt": 0.0,
            "bw_psh_flag": 0.0,
            "fw_urg_flag": 0.0,
            "bw_urg_flag": 0.0,
            "fw_win_byt": float(tcp.get("tcp_win", 0) or 0),
            "bw_win_byt": 0.0,
            "fw_byt_blk_avg": bytes_to / max(pkts_to, 1),
            "fw_pkt_blk_avg": pkts_to / max(age, 1),
            "fw_blk_rate_avg": bytes_to / max(age, 1),
            "bw_byt_blk_avg": bytes_from / max(pkts_from, 1),
            "bw_pkt_blk_avg": pkts_from / max(age, 1),
            "bw_blk_rate_avg": bytes_from / max(age, 1),
            "bw_iat_tot": 0.0,
            "bw_iat_min": 0.0,
            "fw_hdr_len": 0.0,
            "down_up_ratio": bytes_from / max(bytes_to, 1),
            "label": self.map_label(event),
        }

    def read_new_events(self):
        """
        Read new events from eve.json since last position.
        Returns list of new events.
        """
        events = []
        try:
            if not os.path.exists(self.eve_log):
                return events

            with open(self.eve_log, "r") as f:
                f.seek(self.last_position)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        events.append(event)
                    except json.JSONDecodeError:
                        continue
                self.last_position = f.tell()

        except Exception as e:
            print(f"[suricata] Error reading eve.json: {e}")

        self.processed_events += len(events)
        return events

    def load_training_data(self, csv_path):
        """Load training data from CSV file."""
        if not os.path.exists(csv_path):
            print(f"[suricata] Training data not found: {csv_path}")
            return None, None

        df = pd.read_csv(csv_path)

        # Handle both lowercase and uppercase Label column
        if "Label" in df.columns:
            df = df.rename(columns={"Label": "label"})

        if "label" not in df.columns:
            print(f"[suricata] No label column in training data")
            return None, None

        # Drop non-feature columns
        drop_cols = ["id", "label", "_src_ip", "_dest_ip", "_src_port",
                     "_dest_port", "_proto", "_timestamp", "_event_type",
                     "_signature", "_category", "_severity"]
        drop_cols = [c for c in drop_cols if c in df.columns]

        y = df["label"]
        X = df.drop(columns=drop_cols).fillna(0)
        print(f"[suricata] Loaded {len(X)} training samples, {y.nunique()} classes")
        print(f"[suricata] Features: {list(X.columns)}")
        return X, y

    def run_live(self, callback=None, poll_interval=5):
        """
        Run live detection loop using tail for efficiency.
        Calls callback(results) for each batch of detections.
        """
        import subprocess
        print(f"[suricata] Starting live detection on {self.eve_log}")

        # Use tail -f to follow the file efficiently
        process = subprocess.Popen(
            ["tail", "-F", "-n", "0", self.eve_log],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        print(f"[suricata] Monitoring live events...")
        buffer = []
        last_process_time = time.time()

        import select
        try:
            while True:
                # Read with short timeout
                ready = select.select([process.stdout], [], [], 0.5)
                if ready[0]:
                    line = process.stdout.readline()
                    if line:
                        line = line.strip()
                        if line:
                            try:
                                event = json.loads(line)
                                if event.get("event_type") in ("alert", "flow"):
                                    buffer.append(event)
                            except json.JSONDecodeError:
                                continue

                # Process buffer every poll_interval seconds regardless
                now = time.time()
                if buffer and (now - last_process_time) >= poll_interval:
                    print(f"[suricata] Processing {len(buffer)} events...")
                    results = self.predict(buffer)
                    print(f"[suricata] Got {len(results)} predictions")
                    if results and callback:
                        callback(results)
                    elif results:
                        for r in results:
                            print(f"[suricata] {r['label']} — {r['confidence']:.1%} — {r['explanation']}")
                    buffer = []
                    last_process_time = now

        except KeyboardInterrupt:
            process.terminate()
            raise


if __name__ == "__main__":
    stream = SuricataStream()
    if not stream.load_model():
        print("[suricata] No model found — train first")
    else:
        stream.run_live()
