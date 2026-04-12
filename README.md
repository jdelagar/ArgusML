# ArgusML — Autonomous ML-driven Intrusion Detection System

**Built by Juan Manuel De La Garza**

> *"Argus Panoptes — the all-seeing giant with 100 eyes who never slept."*

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.12-green.svg)](https://python.org)
[![GPU](https://img.shields.io/badge/GPU-CUDA%2013.0-brightgreen.svg)](https://developer.nvidia.com/cuda-toolkit)
[![Accuracy](https://img.shields.io/badge/Accuracy-98.04%25-success.svg)]()

ArgusML is a next-generation autonomous Intrusion Detection System that combines real-time network traffic analysis, adaptive Bayesian fusion, GPU-accelerated machine learning, and AI-generated Suricata rules into a fully autonomous defense pipeline.

No human writes the rules. No human analyzes the alerts. ArgusML does it all.

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
| Open source | ✅ | ✅ | ❌ |
| Cost | Free | Free | $100K+/yr |

---

## How It Works

```
Live Network Traffic (Suricata eve.json)
|
SuricataStream
XGBoost (GPU) + Isolation Forest
|
Adaptive Bayesian Fusion Engine
weights adapt based on stream accuracy
|
ArgusML Rule Generator
Ollama llama3 running locally on GPU
|
argus_ml.rules → Suricata auto-reload
|
EveBox Dashboard [ARGUS-ML] alerts
```

---

## Performance

| Model | Dataset | Accuracy | F1 Score | Hardware |
|-------|---------|----------|----------|----------|
| XGBoost | Suricata live logs | 98.04% | 97.66% | NVIDIA RTX 5070 Ti |

---

## Key Features

### 1. Adaptive Bayesian Fusion
Unlike simple stacking classifiers ArgusML uses Bayesian fusion with adaptive weights. If a stream starts making mistakes its weight is automatically reduced. If it becomes more accurate its weight increases. The system gets smarter over time without retraining.

### 2. Isolation Forest Zero-Day Detection
ArgusML trains an Isolation Forest on normal traffic. When it sees something it has never seen before — even if XGBoost classifies it as normal — the anomaly score triggers an `unknown_anomaly` alert. This catches zero-day attacks that signature based systems miss completely.

### 3. Local LLM Rule Generation
When a threat is detected ArgusML sends the threat context to Meta Llama 3 running locally on GPU. The LLM writes a plain English description and ArgusML wraps it in valid Suricata rule syntax automatically. No internet required. No API calls. No data leaving the machine. Perfect for air-gapped environments.

### 4. Explainable AI
Every detection comes with a human readable explanation:
```
[DETECTION #1] 03:53:08
Threat:     backdoor_activity
Confidence: 95.5%
Streams:    suricata
Explanation: Threat detected: backdoor_activity (confidence: 95.5%) |
High byte rate suggests data exfiltration
```

### 5. GPU Accelerated Training
XGBoost training uses CUDA DMatrix for full GPU acceleration. Training 9,000+ samples completes in seconds on an NVIDIA RTX series GPU compared to minutes on CPU.

### 6. Multi-Stream Architecture
ArgusML is built to support multiple detection streams that fuse their outputs:
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

### Train
```bash
python3 argus_ml.py --train
```

### Run
```bash
sudo python3 argus_ml.py
```

---

## Generated Rules

ArgusML generates Suricata rules with the `[ARGUS-ML]` prefix:
```
alert ip any any -> any any
(msg:"[ARGUS-ML] Backdoor C2 communication detected outbound";
threshold:type threshold, track by_src, count 1, seconds 60;
metadata:cf_confidence 0.9550, cf_streams suricata,
cf_label backdoor_activity, cf_severity 1, cf_version 1.0;
classtype:misc-attack; sid:9500001; rev:1;)
```

---

## Project Structure

```
ArgusML/
├── argus_ml.py              # Main entry point
├── core/
│   ├── config.py            # Configuration
│   └── base.py              # Base stream class
├── streams/
│   └── suricata.py          # Suricata detection stream
├── fusion/
│   └── bayesian.py          # Adaptive Bayesian fusion engine
└── output/
└── rule_generator.py    # LLM-powered rule generator
```

---

## Roadmap

- [ ] DNS anomaly detection stream
- [ ] TLS/SSL inspection stream
- [ ] Network flow analysis stream
- [ ] Web dashboard
- [ ] REST API
- [ ] Docker container
- [ ] Continuous learning — retrain on rolling window
- [ ] Cloud deployment (AWS/GCP)
- [ ] Windows support

---

## License

Copyright 2026 Juan Manuel De La Garza

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for full details.

You are free to use, modify and distribute this software. Commercial use is permitted. You must include attribution and cannot use my name for endorsement without permission.

---

*ArgusML — Always watching. Never sleeping.* 👁️
