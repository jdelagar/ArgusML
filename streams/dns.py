#!/usr/bin/env python3
"""
ArgusML DNS Anomaly Detection Stream
Detects DNS tunneling, DGA domains, C2 beaconing via DNS.
"""

import os
import re
import math
import time
import json
import subprocess
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
from core.base import BaseStream


# Known legitimate TLDs and domains
KNOWN_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "io", "co",
    "uk", "ca", "au", "de", "fr", "jp", "cn", "ru", "br"
}

# Suspicious TLDs often used by malware
SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "site", "web", "info",
    "biz", "tk", "ml", "ga", "cf", "gq"
}

def calculate_entropy(domain):
    """Calculate Shannon entropy of a string."""
    if not domain:
        return 0.0
    freq = Counter(domain)
    length = len(domain)
    entropy = -sum((c/length) * math.log2(c/length) for c in freq.values())
    return round(entropy, 4)

def count_consonants(s):
    """Count consecutive consonants — DGA domains have many."""
    consonants = set("bcdfghjklmnpqrstvwxyz")
    return sum(1 for c in s.lower() if c in consonants)

def extract_domain_features(dns_event):
    """Extract features from a DNS event."""
    dns = dns_event.get("dns", {})
    queries = dns.get("queries", [{}])
    answers = dns.get("answers", [])

    rrname = queries[0].get("rrname", "") if queries else ""
    rrtype = queries[0].get("rrtype", "A") if queries else "A"

    # Split domain
    parts = rrname.rstrip(".").split(".")
    tld = parts[-1].lower() if parts else ""
    sld = parts[-2].lower() if len(parts) >= 2 else ""
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

    # Features
    domain_length = len(rrname)
    num_subdomains = len(parts) - 2 if len(parts) > 2 else 0
    entropy = calculate_entropy(sld)
    consonant_ratio = count_consonants(sld) / max(len(sld), 1)
    digit_ratio = sum(1 for c in sld if c.isdigit()) / max(len(sld), 1)
    hyphen_count = sld.count("-")
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    has_ip_pattern = 1 if re.search(r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}", rrname) else 0
    is_numeric_heavy = 1 if digit_ratio > 0.4 else 0
    response_count = len(answers)
    response_ips = sum(1 for a in answers if a.get("rrtype") in ("A", "AAAA"))
    ttl_values = [a.get("ttl", 0) for a in answers if "ttl" in a]
    avg_ttl = np.mean(ttl_values) if ttl_values else 0
    min_ttl = min(ttl_values) if ttl_values else 0
    is_txt_query = 1 if rrtype == "TXT" else 0
    is_mx_query = 1 if rrtype == "MX" else 0
    is_null_query = 1 if rrtype == "NULL" else 0
    query_label_count = len(parts)
    max_label_length = max(len(p) for p in parts) if parts else 0
    total_label_length = sum(len(p) for p in parts)

    # Label based on heuristics
    label = "normal"
    if domain_length > 50 and entropy > 3.5:
        label = "dns_tunneling"
    elif entropy > 4.0 and consonant_ratio > 0.7 and digit_ratio > 0.2:
        label = "dga_domain"
    elif is_txt_query and domain_length > 40:
        label = "dns_tunneling"
    elif is_suspicious_tld and entropy > 3.0:
        label = "suspicious_domain"
    elif has_ip_pattern:
        label = "dns_tunneling"
    elif min_ttl < 60 and response_count > 5:
        label = "fast_flux"

    return {
        "domain_length": domain_length,
        "num_subdomains": num_subdomains,
        "entropy": entropy,
        "consonant_ratio": consonant_ratio,
        "digit_ratio": digit_ratio,
        "hyphen_count": hyphen_count,
        "is_suspicious_tld": is_suspicious_tld,
        "has_ip_pattern": has_ip_pattern,
        "is_numeric_heavy": is_numeric_heavy,
        "response_count": response_count,
        "response_ips": response_ips,
        "avg_ttl": avg_ttl,
        "min_ttl": min_ttl,
        "is_txt_query": is_txt_query,
        "is_mx_query": is_mx_query,
        "is_null_query": is_null_query,
        "query_label_count": query_label_count,
        "max_label_length": max_label_length,
        "total_label_length": total_label_length,
        "label": label,
    }


class DNSStream(BaseStream):
    """
    DNS anomaly detection stream.
    Detects DNS tunneling, DGA domains, fast flux, C2 beaconing.
    """

    def __init__(self):
        super().__init__()
        self.query_frequency = defaultdict(list)
        self.domain_history = []

    def get_stream_name(self):
        return "dns"

    def extract_features(self, raw_data):
        if isinstance(raw_data, dict):
            raw_data = [raw_data]

        rows = []
        for event in raw_data:
            if event.get("event_type") != "dns":
                continue
            try:
                row = extract_domain_features(event)
                rows.append(row)
            except Exception as e:
                print(f"[dns] Feature extraction error: {e}")
                continue

        if not rows:
            return pd.DataFrame()

        return pd.DataFrame(rows)

    def load_training_data(self, csv_path):
        if not os.path.exists(csv_path):
            print(f"[dns] Training data not found: {csv_path}")
            return None, None

        df = pd.read_csv(csv_path)

        if "Label" in df.columns:
            df = df.rename(columns={"Label": "label"})

        if "label" not in df.columns:
            print(f"[dns] No label column in training data")
            return None, None

        drop_cols = [c for c in ["id", "label"] if c in df.columns]
        y = df["label"]
        X = df.drop(columns=drop_cols).fillna(0)
        print(f"[dns] Loaded {len(X)} training samples, {y.nunique()} classes")
        return X, y

    def generate_training_data_from_eve(self, eve_log, output_csv):
        """Generate DNS training data from live eve.json."""
        print(f"[dns] Generating training data from {eve_log}...")
        rows = []
        try:
            result = subprocess.run(
                ["tail", "-50000", eve_log],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "dns":
                        row = extract_domain_features(event)
                        rows.append(row)
                except:
                    continue
        except Exception as e:
            print(f"[dns] Error reading eve.json: {e}")

        if rows:
            df = pd.DataFrame(rows)
            os.makedirs(os.path.dirname(output_csv), exist_ok=True)
            df.to_csv(output_csv, index=False)
            print(f"[dns] Generated {len(df)} training samples")
            label_dist = df["label"].value_counts().to_dict()
            print(f"[dns] Label distribution: {label_dist}")
            return df
        return None

    def run_live(self, callback=None, poll_interval=5):
        """Run live DNS detection."""
        import select
        print(f"[dns] Starting live DNS detection")

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
                                if event.get("event_type") == "dns":
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
                            print(f"[dns] {r['label']} — {r['confidence']:.1%} — {r['explanation']}")
                    buffer = []
                    last_process_time = now

        except KeyboardInterrupt:
            process.terminate()
            raise
