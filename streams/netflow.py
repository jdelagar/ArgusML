#!/usr/bin/env python3
"""
ArgusML NetFlow Detection Stream
Detects beaconing, port scanning, lateral movement,
data exfiltration, and unusual connection patterns.
"""

import os
import time
import json
import subprocess
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
from core.base import BaseStream


def extract_flow_features(flow_event):
    """Extract features from a Suricata flow event."""
    flow = flow_event.get("flow", {})
    
    src_ip = flow_event.get("src_ip", "")
    dest_ip = flow_event.get("dest_ip", "")
    src_port = flow_event.get("src_port", 0)
    dest_port = flow_event.get("dest_port", 0)
    proto = flow_event.get("proto", "")
    app_proto = flow_event.get("app_proto", "")

    pkts_to = float(flow.get("pkts_toserver", 0) or 0)
    pkts_from = float(flow.get("pkts_toclient", 0) or 0)
    bytes_to = float(flow.get("bytes_toserver", 0) or 0)
    bytes_from = float(flow.get("bytes_toclient", 0) or 0)
    age = float(flow.get("age", 0) or 0)
    state = flow.get("state", "")
    reason = flow.get("reason", "")
    alerted = 1 if flow.get("alerted", False) else 0

    # Derived features
    total_pkts = pkts_to + pkts_from
    total_bytes = bytes_to + bytes_from
    pkt_ratio = pkts_to / max(pkts_from, 1)
    byte_ratio = bytes_to / max(bytes_from, 1)
    bytes_per_pkt = total_bytes / max(total_pkts, 1)
    flow_rate = total_bytes / max(age, 1)

    # Port features
    is_well_known_port = 1 if dest_port < 1024 else 0
    is_ephemeral_port = 1 if dest_port > 49151 else 0
    is_common_port = 1 if dest_port in (80, 443, 22, 53, 8080, 8443, 3389, 445, 139) else 0
    is_suspicious_port = 1 if dest_port in (4444, 1337, 31337, 6666, 6667, 8888, 9999) else 0

    # Protocol features
    is_tcp = 1 if proto == "TCP" else 0
    is_udp = 1 if proto == "UDP" else 0
    is_icmp = 1 if proto == "ICMP" else 0

    # IP features
    is_internal_src = 1 if src_ip.startswith(("192.168.", "10.", "172.")) else 0
    is_internal_dest = 1 if dest_ip.startswith(("192.168.", "10.", "172.")) else 0
    is_multicast = 1 if dest_ip.startswith(("224.", "239.", "255.")) else 0
    is_lateral = 1 if is_internal_src and is_internal_dest else 0

    # State features
    is_established = 1 if state == "established" else 0
    is_new = 1 if state == "new" else 0
    is_closed = 1 if state == "closed" else 0
    is_timeout = 1 if reason == "timeout" else 0

    # App protocol
    is_http = 1 if app_proto == "http" else 0
    is_tls = 1 if app_proto == "tls" else 0
    is_dns = 1 if app_proto == "dns" else 0
    is_failed = 1 if app_proto == "failed" else 0

    # Beaconing detection features
    is_small_periodic = 1 if (total_bytes < 1000 and age < 5 and pkts_to <= 3) else 0
    is_large_outbound = 1 if (bytes_to > 1000000 and byte_ratio > 10) else 0
    is_port_scan = 1 if (pkts_to == 1 and pkts_from == 0 and state == "new") else 0

    # Label based on heuristics
    label = "normal"
    if is_suspicious_port and is_established:
        label = "c2_beacon"
    elif is_port_scan and not is_multicast:
        label = "port_scan"
    elif is_lateral and total_bytes > 100000:
        label = "lateral_movement"
    elif is_large_outbound and not is_internal_dest:
        label = "data_exfiltration"
    elif is_small_periodic and not is_multicast and not is_dns:
        label = "beaconing"

    return {
        "pkts_to": pkts_to,
        "pkts_from": pkts_from,
        "bytes_to": bytes_to,
        "bytes_from": bytes_from,
        "age": age,
        "total_pkts": total_pkts,
        "total_bytes": total_bytes,
        "pkt_ratio": pkt_ratio,
        "byte_ratio": byte_ratio,
        "bytes_per_pkt": bytes_per_pkt,
        "flow_rate": flow_rate,
        "dest_port": dest_port,
        "src_port": src_port,
        "is_well_known_port": is_well_known_port,
        "is_ephemeral_port": is_ephemeral_port,
        "is_common_port": is_common_port,
        "is_suspicious_port": is_suspicious_port,
        "is_tcp": is_tcp,
        "is_udp": is_udp,
        "is_icmp": is_icmp,
        "is_internal_src": is_internal_src,
        "is_internal_dest": is_internal_dest,
        "is_multicast": is_multicast,
        "is_lateral": is_lateral,
        "is_established": is_established,
        "is_new": is_new,
        "is_closed": is_closed,
        "is_timeout": is_timeout,
        "is_http": is_http,
        "is_tls": is_tls,
        "is_dns": is_dns,
        "is_failed": is_failed,
        "alerted": alerted,
        "is_small_periodic": is_small_periodic,
        "is_large_outbound": is_large_outbound,
        "is_port_scan": is_port_scan,
        "label": label,
    }


class NetFlowStream(BaseStream):
    """
    NetFlow detection stream.
    Detects beaconing, port scanning, lateral movement,
    data exfiltration, and unusual connection patterns.
    """

    def __init__(self):
        super().__init__()
        self.connection_history = defaultdict(list)

    def get_stream_name(self):
        return "netflow"

    def extract_features(self, raw_data):
        if isinstance(raw_data, dict):
            raw_data = [raw_data]

        rows = []
        for event in raw_data:
            if event.get("event_type") != "flow":
                continue
            try:
                row = extract_flow_features(event)
                rows.append(row)
            except Exception as e:
                print(f"[netflow] Feature extraction error: {e}")
                continue

        if not rows:
            return pd.DataFrame()

        return pd.DataFrame(rows)

    def load_training_data(self, csv_path):
        if not os.path.exists(csv_path):
            print(f"[netflow] Training data not found: {csv_path}")
            return None, None

        df = pd.read_csv(csv_path)
        if "Label" in df.columns:
            df = df.rename(columns={"Label": "label"})
        if "label" not in df.columns:
            print(f"[netflow] No label column in training data")
            return None, None

        drop_cols = [c for c in ["id", "label"] if c in df.columns]
        y = df["label"]
        X = df.drop(columns=drop_cols).fillna(0)
        print(f"[netflow] Loaded {len(X)} training samples, {y.nunique()} classes")
        return X, y

    def generate_training_data(self, eve_log, output_csv):
        """Generate NetFlow training data from live eve.json."""
        print(f"[netflow] Generating training data from {eve_log}...")
        rows = []
        try:
            result = subprocess.run(
                ["tail", "-200000", eve_log],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "flow":
                        row = extract_flow_features(event)
                        rows.append(row)
                except:
                    continue
        except Exception as e:
            print(f"[netflow] Error reading eve.json: {e}")

        if rows:
            df = pd.DataFrame(rows)

            # Add synthetic malicious samples
            synthetic = []

            # Beaconing
            for i in range(200):
                synthetic.append({
                    "pkts_to": np.random.randint(1, 4),
                    "pkts_from": np.random.randint(1, 4),
                    "bytes_to": np.random.randint(100, 800),
                    "bytes_from": np.random.randint(100, 800),
                    "age": np.random.uniform(0, 5),
                    "total_pkts": np.random.randint(2, 8),
                    "total_bytes": np.random.randint(200, 1000),
                    "pkt_ratio": np.random.uniform(0.8, 1.2),
                    "byte_ratio": np.random.uniform(0.8, 1.2),
                    "bytes_per_pkt": np.random.uniform(100, 300),
                    "flow_rate": np.random.uniform(50, 300),
                    "dest_port": np.random.choice([4444, 1337, 8888, 9999, 6666]),
                    "src_port": np.random.randint(49152, 65535),
                    "is_well_known_port": 0,
                    "is_ephemeral_port": 0,
                    "is_common_port": 0,
                    "is_suspicious_port": 1,
                    "is_tcp": 1, "is_udp": 0, "is_icmp": 0,
                    "is_internal_src": 1, "is_internal_dest": 0,
                    "is_multicast": 0, "is_lateral": 0,
                    "is_established": 1, "is_new": 0, "is_closed": 0,
                    "is_timeout": 0, "is_http": 0, "is_tls": 0,
                    "is_dns": 0, "is_failed": 0, "alerted": 0,
                    "is_small_periodic": 1, "is_large_outbound": 0,
                    "is_port_scan": 0,
                    "label": "beaconing"
                })

            # Port scan
            for i in range(150):
                synthetic.append({
                    "pkts_to": 1,
                    "pkts_from": 0,
                    "bytes_to": np.random.randint(40, 80),
                    "bytes_from": 0,
                    "age": 0,
                    "total_pkts": 1,
                    "total_bytes": np.random.randint(40, 80),
                    "pkt_ratio": 1.0,
                    "byte_ratio": 1.0,
                    "bytes_per_pkt": np.random.uniform(40, 80),
                    "flow_rate": 0,
                    "dest_port": np.random.randint(1, 65535),
                    "src_port": np.random.randint(49152, 65535),
                    "is_well_known_port": np.random.randint(0, 2),
                    "is_ephemeral_port": np.random.randint(0, 2),
                    "is_common_port": np.random.randint(0, 2),
                    "is_suspicious_port": 0,
                    "is_tcp": 1, "is_udp": 0, "is_icmp": 0,
                    "is_internal_src": 1, "is_internal_dest": 1,
                    "is_multicast": 0, "is_lateral": 1,
                    "is_established": 0, "is_new": 1, "is_closed": 0,
                    "is_timeout": 1, "is_http": 0, "is_tls": 0,
                    "is_dns": 0, "is_failed": 1, "alerted": 0,
                    "is_small_periodic": 0, "is_large_outbound": 0,
                    "is_port_scan": 1,
                    "label": "port_scan"
                })

            # Data exfiltration
            for i in range(100):
                synthetic.append({
                    "pkts_to": np.random.randint(100, 1000),
                    "pkts_from": np.random.randint(1, 10),
                    "bytes_to": np.random.randint(1000000, 10000000),
                    "bytes_from": np.random.randint(100, 1000),
                    "age": np.random.uniform(10, 300),
                    "total_pkts": np.random.randint(100, 1000),
                    "total_bytes": np.random.randint(1000000, 10000000),
                    "pkt_ratio": np.random.uniform(50, 200),
                    "byte_ratio": np.random.uniform(1000, 10000),
                    "bytes_per_pkt": np.random.uniform(1000, 10000),
                    "flow_rate": np.random.uniform(10000, 100000),
                    "dest_port": np.random.choice([443, 80, 8080, 21, 22]),
                    "src_port": np.random.randint(49152, 65535),
                    "is_well_known_port": 1,
                    "is_ephemeral_port": 0,
                    "is_common_port": 1,
                    "is_suspicious_port": 0,
                    "is_tcp": 1, "is_udp": 0, "is_icmp": 0,
                    "is_internal_src": 1, "is_internal_dest": 0,
                    "is_multicast": 0, "is_lateral": 0,
                    "is_established": 1, "is_new": 0, "is_closed": 0,
                    "is_timeout": 0, "is_http": np.random.randint(0, 2),
                    "is_tls": np.random.randint(0, 2),
                    "is_dns": 0, "is_failed": 0, "alerted": 0,
                    "is_small_periodic": 0, "is_large_outbound": 1,
                    "is_port_scan": 0,
                    "label": "data_exfiltration"
                })

            # Lateral movement
            for i in range(100):
                synthetic.append({
                    "pkts_to": np.random.randint(10, 100),
                    "pkts_from": np.random.randint(5, 50),
                    "bytes_to": np.random.randint(100000, 1000000),
                    "bytes_from": np.random.randint(50000, 500000),
                    "age": np.random.uniform(5, 60),
                    "total_pkts": np.random.randint(15, 150),
                    "total_bytes": np.random.randint(150000, 1500000),
                    "pkt_ratio": np.random.uniform(1, 3),
                    "byte_ratio": np.random.uniform(1, 3),
                    "bytes_per_pkt": np.random.uniform(1000, 10000),
                    "flow_rate": np.random.uniform(1000, 50000),
                    "dest_port": np.random.choice([445, 139, 3389, 22, 5985]),
                    "src_port": np.random.randint(49152, 65535),
                    "is_well_known_port": 1,
                    "is_ephemeral_port": 0,
                    "is_common_port": 1,
                    "is_suspicious_port": 0,
                    "is_tcp": 1, "is_udp": 0, "is_icmp": 0,
                    "is_internal_src": 1, "is_internal_dest": 1,
                    "is_multicast": 0, "is_lateral": 1,
                    "is_established": 1, "is_new": 0, "is_closed": 0,
                    "is_timeout": 0, "is_http": 0, "is_tls": 0,
                    "is_dns": 0, "is_failed": 0, "alerted": 0,
                    "is_small_periodic": 0, "is_large_outbound": 0,
                    "is_port_scan": 0,
                    "label": "lateral_movement"
                })

            df_synthetic = pd.DataFrame(synthetic)
            df_combined = pd.concat([df, df_synthetic], ignore_index=True)
            os.makedirs(os.path.dirname(output_csv), exist_ok=True)
            df_combined.to_csv(output_csv, index=False)
            print(f"[netflow] Generated {len(df_combined)} training samples")
            print(f"[netflow] Label distribution: {df_combined['label'].value_counts().to_dict()}")
            return df_combined
        return None

    def run_live(self, callback=None, poll_interval=5):
        """Run live NetFlow detection."""
        import select
        print(f"[netflow] Starting live NetFlow detection")

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
                                if event.get("event_type") == "flow":
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
                            print(f"[netflow] {r['label']} — {r['confidence']:.1%}")
                    buffer = []
                    last_process_time = now

        except KeyboardInterrupt:
            process.terminate()
            raise
