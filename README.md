# ArgusML — Autonomous ML-powered Intrusion Detection & Prevention System

**Built by Juan Manuel De La Garza**

> *"Argus Panoptes — the all-seeing giant with 100 eyes who never slept."*

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.12-green.svg)](https://python.org)
[![GPU](https://img.shields.io/badge/GPU-CUDA%2013.0-brightgreen.svg)](https://developer.nvidia.com/cuda-toolkit)
[![Accuracy](https://img.shields.io/badge/Accuracy-98.04%25-success.svg)]()

ArgusML is a fully autonomous Intrusion Detection & Prevention System (IDPS) powered by an ensemble of machine learning models. It monitors live network traffic, fuses decisions from multiple ML models using adaptive Bayesian weighting, detects known and zero-day threats, and autonomously generates and deploys Suricata detection rules — all without human intervention.

**No human writes the rules. No human analyzes the alerts. ArgusML does it all.**

---

## What ArgusML Is

ArgusML is not a single ML model. It is an **autonomous pipeline** that combines multiple independently trained ML models whose outputs are fused together into a single high-confidence threat decision:

- **XGBoost classifier** — trained from scratch on live Suricata network logs, detects known threat categories at 98.04% accuracy
- **Isolation Forest** — trained from scratch on normal traffic baselines, detects zero-day and unknown anomalies that signature based systems miss
- **Adaptive Bayesian Fusion Engine** — original architecture that combines model outputs with adaptive weighting, getting smarter over time
- **Local LLM Rule Generator** — uses Meta Llama 3 running on local GPU to autonomously write and deploy Suricata detection rules

---

## What Makes ArgusML Different

| Feature | ArgusML | Traditional IDPS | Commercial (Darktrace/Vectra) |
|---------|---------|-----------------|-------------------------------|
| Autonomous rule generation | ✅ | ❌ | ❌ |
| Adaptive Bayesian fusion | ✅ | ❌ | ❌ |
| Isolation Forest zero-day detection | ✅ | ❌ | ✅ |
| Local LLM (no cloud required) | ✅ | ❌ | ❌ |
| GPU accelerated training | ✅ | ❌ | ✅ |
| Explainable AI | ✅ | ❌ | ❌ |
| Models trained from scratch | ✅ | ❌ | ❌ |
| Open source | ✅ | ✅ | ❌ |
| Cost | Free | Free | $100K+/yr |

---

## How It Works

```
Live Network Traffic
|
Suricata 8.0+ (eve.json)
|
┌─────────────────────────┐
│     SuricataStream      │
│  XGBoost (GPU/CUDA)     │  ← Detects known threats
│  Isolation Forest       │  ← Detects zero-day anomalies
└─────────────────────────┘
|
┌─────────────────────────┐
│  Adaptive Bayesian      │
│  Fusion Engine          │  ← Combines model outputs
│  (adaptive weighting)   │  ← Gets smarter over time
└─────────────────────────┘
|
┌─────────────────────────┐
│  ArgusML Rule Generator │
│  Ollama llama3 (local)  │  ← Writes rule description
│  Suricata rule builder  │  ← Builds valid rule syntax
└─────────────────────────┘
|
argus_ml.rules → Suricata auto-reload
|
[ARGUS-ML] alerts in EveBox
```

---

## Performance

All models are trained from scratch on live data — no pre-trained weights, no borrowed models.

| Model | Training Data | Samples | Accuracy | F1 Score | Hardware |
|-------|--------------|---------|----------|----------|----------|
| XGBoost | Live Suricata logs | 9,193 | 98.04% | 97.66% | NVIDIA RTX 5070 Ti |
| Isolation Forest | Normal traffic baseline | 6,373 | Anomaly detection | — | NVIDIA RTX 5070 Ti |

---

## Key Features

### 1. Adaptive Bayesian Fusion Engine
ArgusML's original fusion architecture combines outputs from multiple ML models using Bayesian probability weighting. Unlike simple voting or stacking classifiers, the weights adapt automatically based on each model's historical accuracy. A model that starts making mistakes gets less weight. A model that becomes more accurate gets more weight. The system improves over time without retraining.

### 2. Dual-Model Threat Detection
Every piece of network traffic is evaluated by two independently trained models:
- **XGBoost** identifies the specific threat category (backdoor, DDoS, botnet, web attack) with confidence scores
- **Isolation Forest** scores how unusual the traffic is compared to the normal baseline — catching threats XGBoost has never seen before

### 3. Autonomous Rule Generation with Local LLM
When a threat is confirmed by the fusion engine, ArgusML automatically calls Meta Llama 3 running locally on GPU. The LLM generates a plain English description of the threat. ArgusML wraps it in valid Suricata rule syntax and deploys it instantly. No internet. No API calls. No data leaving the machine. Perfect for classified and air-gapped environments.

### 4. Explainable AI
Every detection includes a human readable explanation of exactly why it was flagged:
```
[DETECTION #1] 03:53:08
Threat:      backdoor_activity
Confidence:  95.5%
Streams:     suricata
Explanation: Threat detected: backdoor_activity (confidence: 95.5%) |
High byte rate (1.2M B/s) suggests data exfiltration
```

### 5. GPU Accelerated Training via CUDA DMatrix
ArgusML uses XGBoost's native CUDA DMatrix format to keep training data on the GPU throughout the entire training process. This eliminates the CPU-GPU memory transfer bottleneck and achieves full GPU utilization. Training 9,000+ samples completes in seconds.

### 6. Multi-Stream Architecture
ArgusML is designed to support multiple independent detection streams. Each stream trains its own models on its own data and contributes to the Bayesian fusion decision:
- ✅ **Suricata Stream** — Live network traffic analysis (implemented)
- 🔄 **DNS Stream** — DNS tunneling and DGA domain detection (roadmap)
- 🔄 **TLS Stream** — Certificate anomalies and cipher suite inspection (roadmap)
- 🔄 **NetFlow Stream** — Connection pattern and beaconing detection (roadmap)

---

## Installation

### Requirements
- Ubuntu 24 Linux
- Python 3.12
- NVIDIA GPU (RTX series recommended)
- CUDA 13.0+
- Suricata 8.0+
- Ollama with llama3
- Training data (Suricata eve.json logs)

### Setup
```bash
git clone https://github.com/jdelagar/ArgusML.git
cd ArgusML
python3 -m venv venv
source venv/bin/activate
pip install xgboost scikit-learn pandas numpy joblib requests pyyaml
ollama pull llama3
```

### Configure Suricata
Add to `/etc/suricata/suricata.yaml`:
```yaml
rule-files:
  - suricata.rules
  - argus_ml.rules
```

### Prepare Training Data
Place your Suricata feature dataset at:
```
datasets/suricata.csv
```
The CSV must contain 30 network flow features plus a `Label` column with threat categories.

### Train Models from Scratch
```bash
python3 argus_ml.py --train
```

### Run Live Detection
```bash
sudo python3 argus_ml.py
```

---

## Generated Rules

ArgusML autonomously generates and deploys Suricata rules tagged with `[ARGUS-ML]`:
```
alert ip any any -> any any
(msg:"[ARGUS-ML] Backdoor C2 communication detected outbound";
threshold:type threshold, track by_src, count 1, seconds 60;
metadata:cf_confidence 0.9550, cf_streams suricata,
cf_label backdoor_activity, cf_severity 1, cf_version 1.0;
classtype:misc-attack; sid:9500001; rev:1;)
```

**Rule metadata fields:**
- `cf_confidence` — fusion engine confidence score (0.0 to 1.0)
- `cf_streams` — which detection streams contributed to this rule
- `cf_label` — threat taxonomy label
- `cf_severity` — severity level (1=critical, 2=high, 3=medium, 4=low)
- `cf_version` — ArgusML version that generated the rule

---

## Project Structure

```
ArgusML/
├── argus_ml.py              # Main entry point and orchestration
├── core/
│   ├── config.py            # System configuration and constants
│   └── base.py              # Base stream class with XGBoost + Isolation Forest
├── streams/
│   └── suricata.py          # Suricata live detection stream
├── fusion/
│   └── bayesian.py          # Original Adaptive Bayesian Fusion Engine
└── output/
└── rule_generator.py    # LLM-powered autonomous rule generator
```

---

## Roadmap

- [x] DNS anomaly detection stream — tunneling, DGA, fast flux detection
- [ ] TLS/SSL inspection stream
- [ ] Network flow analysis stream
- [x] Web dashboard with live threat visualization and world map attack origins
- [x] REST API for enterprise integration
- [x] Docker container for easy deployment
- [x] Systemd services for autonomous operation
- [ ] Continuous learning — retrain on rolling window
- [ ] Post-quantum encrypted threat intelligence sharing
- [ ] Cloud deployment (AWS/GCP)
- [ ] Windows support

---

## License

Copyright 2026 Juan Manuel De La Garza

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for full details.

You are free to use, modify and distribute this software. Commercial use is permitted. You must include attribution and cannot use my name to endorse derived products without permission.

---

*ArgusML — Always watching. Never sleeping.* 👁️
