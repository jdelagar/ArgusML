#!/usr/bin/env python3
"""
ArgusML Configuration
"""

import os
import yaml

# Base paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

# Suricata
SURICATA_EVE_LOG = "/var/log/suricata/eve.json"
SURICATA_RULES_FILE = "/var/lib/suricata/rules/argus_ml.rules"

# Ollama
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"

# Suricata SID range for ArgusML
SID_START = 9500001
SID_FP_START = 9600001

# Model settings
XGBOOST_PARAMS = {
    "device": "cuda",
    "tree_method": "hist",
    "n_estimators": 200,
    "max_depth": 6,
    "learning_rate": 0.1,
    "objective": "multi:softprob",
    "eval_metric": "mlogloss",
}

ISOLATION_FOREST_PARAMS = {
    "n_estimators": 200,
    "contamination": 0.05,
    "random_state": 42,
}

# Fusion settings
FUSION_WEIGHTS = {
    "suricata": 1.0,
}

# Confidence threshold to generate a rule
CONFIDENCE_THRESHOLD = 0.75

# How often to retrain (in seconds)
RETRAIN_INTERVAL = 3600  # 1 hour

# Threat taxonomy
THREAT_LABELS = [
    "normal",
    "ddos_activity",
    "botnet_activity",
    "backdoor_activity",
    "web_attack_activity",
    "port_scan",
    "dns_anomaly",
    "tls_anomaly",
    "unknown_anomaly",
]

def load_config(config_path=None):
    """Load config from yaml file if provided, otherwise use defaults."""
    if config_path and os.path.exists(config_path):
        with open(config_path, "r") as f:
            overrides = yaml.safe_load(f)
        return overrides
    return {}

