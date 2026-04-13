#!/usr/bin/env python3
"""
ArgusML TLS/SSL Inspection Stream
Detects malicious TLS patterns using JA3/JA4 fingerprinting,
certificate anomalies, and cipher suite analysis.
"""

import os
import re
import time
import json
import hashlib
import subprocess
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
from core.base import BaseStream

# Known malicious JA3 hashes (common C2 frameworks)
MALICIOUS_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865",  # Metasploit
    "6734f37431670b3ab4292b8f60f29984",  # Cobalt Strike
    "b386946a5a44d1ddcc843bc75336dfce",  # Cobalt Strike
    "aaa6e9f9e52e607f38b25302a7b13d1d",  # TrickBot
    "72a589da586844d7f0818ce684948eea",  # Emotet
    "a0e9f5d64349fb13191bc781f81f42e1",  # Dridex
}

# Suspicious TLS versions
WEAK_TLS_VERSIONS = {"TLS 1.0", "TLS 1.1", "SSL 2.0", "SSL 3.0"}

# Known legitimate JA3S hashes
KNOWN_GOOD_JA3S = {
    "15af977ce25de452b96affa2addb1036",  # Common legitimate servers
    "b94b6e849c96f6e23b7958af3b5f6254",
}


def extract_tls_features(tls_event):
    """Extract features from a TLS event."""
    tls = tls_event.get("tls", {})
    ja3 = tls.get("ja3", {})
    ja3s = tls.get("ja3s", {})

    sni = tls.get("sni", "")
    version = tls.get("version", "")
    ja3_hash = ja3.get("hash", "")
    ja3s_hash = ja3s.get("hash", "")
    ja3_string = ja3.get("string", "")
    client_alpns = tls.get("client_alpns", [])
    subject = tls.get("subject", "")
    issuer = tls.get("issuerdn", "")
    notbefore = tls.get("notbefore", "")
    notafter = tls.get("notafter", "")
    fingerprint = tls.get("fingerprint", "")

    # JA3 cipher count
    ja3_parts = ja3_string.split(",") if ja3_string else []
    cipher_count = len(ja3_parts[1].split("-")) if len(ja3_parts) > 1 else 0
    extension_count = len(ja3_parts[2].split("-")) if len(ja3_parts) > 2 else 0
    elliptic_count = len(ja3_parts[3].split("-")) if len(ja3_parts) > 3 else 0

    # SNI features
    sni_length = len(sni)
    sni_parts = sni.split(".")
    sni_labels = len(sni_parts)
    sni_entropy = _entropy(sni.split(".")[0] if sni_parts else "")

    # Version features
    is_weak_tls = 1 if version in WEAK_TLS_VERSIONS else 0
    is_tls13 = 1 if version == "TLS 1.3" else 0
    is_tls12 = 1 if version == "TLS 1.2" else 0

    # JA3 features
    is_known_malicious_ja3 = 1 if ja3_hash in MALICIOUS_JA3 else 0
    is_known_good_ja3s = 1 if ja3s_hash in KNOWN_GOOD_JA3S else 0

    # Certificate features
    is_self_signed = 1 if (subject and issuer and subject == issuer) else 0
    has_subject = 1 if subject else 0
    has_valid_cert = 1 if notafter else 0

    # ALPN features
    has_h2 = 1 if "h2" in client_alpns else 0
    has_http11 = 1 if "http/1.1" in client_alpns else 0
    alpn_count = len(client_alpns)

    # Port
    dest_port = tls_event.get("dest_port", 443)
    is_standard_port = 1 if dest_port in (443, 8443) else 0
    is_unusual_port = 1 if dest_port not in (443, 8443, 80, 8080) else 0

    # Label based on heuristics
    label = "normal"
    if is_known_malicious_ja3:
        label = "malicious_tls"
    elif is_weak_tls:
        label = "weak_tls"
    elif is_self_signed and is_unusual_port:
        label = "c2_tls"
    elif not has_subject and not sni and is_unusual_port:
        label = "suspicious_tls"
    elif cipher_count < 3:
        label = "weak_tls"

    return {
        "sni_length": sni_length,
        "sni_labels": sni_labels,
        "sni_entropy": sni_entropy,
        "cipher_count": cipher_count,
        "extension_count": extension_count,
        "elliptic_count": elliptic_count,
        "is_weak_tls": is_weak_tls,
        "is_tls13": is_tls13,
        "is_tls12": is_tls12,
        "is_known_malicious_ja3": is_known_malicious_ja3,
        "is_known_good_ja3s": is_known_good_ja3s,
        "is_self_signed": is_self_signed,
        "has_subject": has_subject,
        "has_valid_cert": has_valid_cert,
        "has_h2": has_h2,
        "has_http11": has_http11,
        "alpn_count": alpn_count,
        "is_standard_port": is_standard_port,
        "is_unusual_port": is_unusual_port,
        "dest_port": dest_port,
        "label": label,
    }


def _entropy(s):
    if not s:
        return 0.0
    from collections import Counter
    import math
    freq = Counter(s)
    length = len(s)
    return round(-sum((c/length) * math.log2(c/length) for c in freq.values()), 4)


class TLSStream(BaseStream):
    """
    TLS/SSL inspection stream.
    Detects malicious TLS patterns using JA3/JA4 fingerprinting.
    """

    def __init__(self):
        super().__init__()
        self.ja3_counts = defaultdict(int)

    def get_stream_name(self):
        return "tls"

    def extract_features(self, raw_data):
        if isinstance(raw_data, dict):
            raw_data = [raw_data]

        rows = []
        for event in raw_data:
            if event.get("event_type") != "tls":
                continue
            try:
                row = extract_tls_features(event)
                rows.append(row)
            except Exception as e:
                print(f"[tls] Feature extraction error: {e}")
                continue

        if not rows:
            return pd.DataFrame()

        return pd.DataFrame(rows)

    def load_training_data(self, csv_path):
        if not os.path.exists(csv_path):
            print(f"[tls] Training data not found: {csv_path}")
            return None, None

        df = pd.read_csv(csv_path)
        if "Label" in df.columns:
            df = df.rename(columns={"Label": "label"})
        if "label" not in df.columns:
            print(f"[tls] No label column in training data")
            return None, None

        drop_cols = [c for c in ["id", "label"] if c in df.columns]
        y = df["label"]
        X = df.drop(columns=drop_cols).fillna(0)
        print(f"[tls] Loaded {len(X)} training samples, {y.nunique()} classes")
        return X, y

    def generate_training_data(self, eve_log, output_csv):
        """Generate TLS training data from live eve.json."""
        print(f"[tls] Generating training data from {eve_log}...")
        rows = []
        try:
            result = subprocess.run(
                ["tail", "-100000", eve_log],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "tls":
                        row = extract_tls_features(event)
                        rows.append(row)
                except:
                    continue
        except Exception as e:
            print(f"[tls] Error reading eve.json: {e}")

        if rows:
            df = pd.DataFrame(rows)

            # Add synthetic malicious samples
            synthetic = []
            for i in range(100):
                synthetic.append({
                    "sni_length": np.random.randint(0, 10),
                    "sni_labels": np.random.randint(0, 2),
                    "sni_entropy": np.random.uniform(0, 1.5),
                    "cipher_count": np.random.randint(1, 3),
                    "extension_count": np.random.randint(0, 3),
                    "elliptic_count": np.random.randint(0, 2),
                    "is_weak_tls": 1,
                    "is_tls13": 0,
                    "is_tls12": 0,
                    "is_known_malicious_ja3": 1,
                    "is_known_good_ja3s": 0,
                    "is_self_signed": 1,
                    "has_subject": 0,
                    "has_valid_cert": 0,
                    "has_h2": 0,
                    "has_http11": 0,
                    "alpn_count": 0,
                    "is_standard_port": 0,
                    "is_unusual_port": 1,
                    "dest_port": np.random.randint(1024, 65535),
                    "label": "malicious_tls"
                })

            for i in range(80):
                synthetic.append({
                    "sni_length": np.random.randint(5, 20),
                    "sni_labels": np.random.randint(1, 3),
                    "sni_entropy": np.random.uniform(2.0, 3.5),
                    "cipher_count": np.random.randint(3, 8),
                    "extension_count": np.random.randint(2, 6),
                    "elliptic_count": np.random.randint(1, 3),
                    "is_weak_tls": 0,
                    "is_tls13": 0,
                    "is_tls12": 1,
                    "is_known_malicious_ja3": 0,
                    "is_known_good_ja3s": 0,
                    "is_self_signed": 1,
                    "has_subject": 1,
                    "has_valid_cert": 0,
                    "has_h2": 0,
                    "has_http11": 1,
                    "alpn_count": 1,
                    "is_standard_port": 0,
                    "is_unusual_port": 1,
                    "dest_port": np.random.randint(1024, 65535),
                    "label": "c2_tls"
                })

            for i in range(60):
                synthetic.append({
                    "sni_length": np.random.randint(5, 15),
                    "sni_labels": np.random.randint(1, 3),
                    "sni_entropy": np.random.uniform(1.5, 3.0),
                    "cipher_count": np.random.randint(1, 4),
                    "extension_count": np.random.randint(0, 3),
                    "elliptic_count": np.random.randint(0, 2),
                    "is_weak_tls": 1,
                    "is_tls13": 0,
                    "is_tls12": 0,
                    "is_known_malicious_ja3": 0,
                    "is_known_good_ja3s": 0,
                    "is_self_signed": 0,
                    "has_subject": 1,
                    "has_valid_cert": 1,
                    "has_h2": 0,
                    "has_http11": 1,
                    "alpn_count": 1,
                    "is_standard_port": 1,
                    "is_unusual_port": 0,
                    "dest_port": 443,
                    "label": "weak_tls"
                })

            df_synthetic = pd.DataFrame(synthetic)
            df_combined = pd.concat([df, df_synthetic], ignore_index=True)
            os.makedirs(os.path.dirname(output_csv), exist_ok=True)
            df_combined.to_csv(output_csv, index=False)
            print(f"[tls] Generated {len(df_combined)} training samples")
            print(f"[tls] Label distribution: {df_combined['label'].value_counts().to_dict()}")
            return df_combined
        return None

    def run_live(self, callback=None, poll_interval=5):
        """Run live TLS detection."""
        import select
        print(f"[tls] Starting live TLS detection")

        process = subprocess.Popen(
            ["tail", "-F", "-n", "0", "/var/log/suricata/eve.json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        buffer = []
        last_process_time = time.time()

        try:
            while True:
                ready = select.select([process.stdout], [], [], 0.5)
                if ready[0]:
                    line = process.stdout.readline()
                    if line:
                        line = line.strip()
                        if line:
                            try:
                                event = json.loads(line)
                                if event.get("event_type") == "tls":
                                    buffer.append(event)
                            except json.JSONDecodeError:
                                continue

                now = time.time()
                if buffer and (now - last_process_time) >= poll_interval:
                    results = self.predict(buffer)
                    if results and callback:
                        callback(results)
                    elif results:
                        for r in results:
                            print(f"[tls] {r['label']} — {r['confidence']:.1%}")
                    buffer = []
                    last_process_time = now

        except KeyboardInterrupt:
            process.terminate()
            raise
