# ArgusML — Autonomous ML-powered Intrusion Detection & Prevention System

**Built by Juan Manuel De La Garza**

> *"Argus Panoptes — the all-seeing giant with 100 eyes who never slept."*

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.12-green.svg)](https://python.org)
[![GPU](https://img.shields.io/badge/GPU-CUDA%2013.0-brightgreen.svg)](https://developer.nvidia.com/cuda-toolkit)
[![Accuracy](https://img.shields.io/badge/Accuracy-98.04%25-success.svg)]()
[![Streams](https://img.shields.io/badge/Streams-4%20Active-orange.svg)]()
[![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Integrated-red.svg)](https://attack.mitre.org/)
[![PQC](https://img.shields.io/badge/PQC-ML--KEM--768-brightgreen.svg)](https://csrc.nist.gov/pubs/fips/203/final)

ArgusML is a fully autonomous Intrusion Detection & Prevention System (IDPS) powered by an ensemble of independently trained machine learning models. It monitors live network traffic across three detection streams simultaneously, fuses their decisions using adaptive Bayesian weighting, detects known and zero-day threats, autonomously generates and deploys Suricata rules, and continuously retrains itself as new threats are discovered — all without human intervention.

**No human writes the rules. No human analyzes the alerts. No human retrains the models. ArgusML does it all.**

---

## What ArgusML Is

ArgusML is not a single ML model. It is a **self-improving autonomous pipeline** that combines multiple independently trained ML models across three detection streams:

- **Suricata Stream** — XGBoost (GPU) + Isolation Forest trained on network flow features. Detects backdoors, DDoS, botnets, web attacks at 98.04% accuracy.
- **DNS Stream** — XGBoost + Isolation Forest trained on DNS query features. Detects DNS tunneling, DGA domains, fast flux, C2 beaconing at 100% accuracy.
- **TLS Stream** — XGBoost + Isolation Forest trained on TLS fingerprint features. Detects malicious JA3 hashes, self-signed C2 certs, weak cipher suites at 100% accuracy.
- **Adaptive Bayesian Fusion Engine** — original architecture that combines all stream outputs with adaptive weighting, getting smarter over time.
- **Continuous Learning Engine** — automatically retrains models as new threats are detected. ArgusML gets smarter the longer it runs.
- **Local LLM Rule Generator** — uses Meta Llama 3 on local GPU to autonomously write and deploy Suricata detection rules.
- **PQC Threat Intel Shipper** — encrypts and ships threat intelligence using NIST post-quantum cryptography (ML-KEM-768 + ML-DSA-65 + AES-256-GCM). Quantum-resistant and DoD-ready.
- **MITRE ATT&CK Integration** — every detection automatically maps to a MITRE ATT&CK technique ID, tactic, and severity level. Speaks the language of enterprise SOCs and DoD.

---

## What Makes ArgusML Different

| Feature | ArgusML | Traditional IDPS | Commercial (Darktrace/Vectra) |
|---------|---------|-----------------|-------------------------------|
| Autonomous rule generation | ✅ | ❌ | ❌ |
| Adaptive Bayesian fusion | ✅ | ❌ | ❌ |
| Continuous self-improvement | ✅ | ❌ | ✅ |
| 3 simultaneous detection streams | ✅ | ❌ | ✅ |
| Isolation Forest zero-day detection | ✅ | ❌ | ✅ |
| JA3/JA4 TLS fingerprinting | ✅ | ❌ | ✅ |
| DNS tunneling detection | ✅ | ❌ | ✅ |
| Local LLM (no cloud required) | ✅ | ❌ | ❌ |
| GPU accelerated training | ✅ | ❌ | ✅ |
| Explainable AI | ✅ | ❌ | ❌ |
| Models trained from scratch | ✅ | ❌ | ❌ |
| REST API | ✅ | ❌ | ✅ |
| Web dashboard with world map | ✅ | ❌ | ✅ |
| Docker container | ✅ | ❌ | ✅ |
| Open source | ✅ | ✅ | ❌ |
| Cost | Free | Free | $100K+/yr |

---

## How It Works

```
Live Network Traffic
|
Suricata 8.0+ (eve.json)
|
┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
│   Suricata Stream   │  │     DNS Stream      │  │     TLS Stream      │
│ XGBoost (GPU/CUDA)  │  │ XGBoost (GPU/CUDA)  │  │ XGBoost (GPU/CUDA)  │
│  Isolation Forest   │  │  Isolation Forest   │  │  Isolation Forest   │
│  98.04% accuracy    │  │  100% accuracy      │  │  100% accuracy      │
└─────────────────────┘  └─────────────────────┘  └─────────────────────┘
|                         |                         |
┌─────────────────────────────────────────────────────────────────────┐
│              Adaptive Bayesian Fusion Engine                        │
│   Weights adapt based on stream accuracy — gets smarter over time   │
│   Stream weights: suricata=1.96, dns=2.0, tls=2.0                  │
└─────────────────────────────────────────────────────────────────────┘
|
┌─────────────────────────────────────────────────────────────────────┐
│              Continuous Learning Engine                             │
│   New detections → expand dataset → retrain → deploy if improved   │
└─────────────────────────────────────────────────────────────────────┘
|
┌─────────────────────────────────────────────────────────────────────┐
│              ArgusML Rule Generator                                 │
│   Ollama llama3 (local GPU) → plain English description             │
│   → valid Suricata rule syntax → auto-deploy → Suricata reload      │
└─────────────────────────────────────────────────────────────────────┘
|
argus_ml.rules → Suricata fires [ARGUS-ML] alerts
|
Live Web Dashboard (port 5000) + REST API (port 5001)
```

---

## Performance

All models trained from scratch on live data — no pre-trained weights, no borrowed models.

| Stream | Model | Training Samples | Accuracy | F1 Score | Hardware |
|--------|-------|-----------------|----------|----------|----------|
| Suricata | XGBoost + IF | 9,193 | 98.04% | 97.66% | RTX 5070 Ti |
| DNS | XGBoost + IF | 592 | 100% | 100% | RTX 5070 Ti |
| TLS | XGBoost + IF | 7,636 | 100% | 100% | RTX 5070 Ti |

---

## Key Features

### 1. Three Simultaneous Detection Streams
ArgusML runs three independent ML pipelines in parallel, each watching a different aspect of network traffic. A threat that evades one stream may be caught by another. All three feed into the Bayesian fusion engine for a final high-confidence decision.

### 2. Adaptive Bayesian Fusion Engine
Combines outputs from all three streams using Bayesian probability weighting. Weights adapt automatically — streams with higher historical accuracy get more influence. The system improves its decision making over time without retraining.

### 3. Continuous Learning Engine
Every high-confidence detection (>85%) is automatically added to the training dataset. Every hour, ArgusML checks if enough new data has accumulated and retrains the affected models. New models are only deployed if accuracy meets the minimum threshold. ArgusML literally gets smarter the longer it runs.

### 4. JA3/JA4 TLS Fingerprinting
The TLS stream extracts JA3, JA3S, and JA4 fingerprints from every TLS connection. Known malicious JA3 hashes (Cobalt Strike, Metasploit, TrickBot, Emotet) trigger immediate alerts. Unusual cipher suites, self-signed certificates on non-standard ports, and weak TLS versions are flagged automatically.

### 5. DNS Anomaly Detection
The DNS stream calculates Shannon entropy, consonant ratios, digit ratios, and query patterns for every DNS request. High entropy domain names signal DGA malware. Long TXT queries signal DNS tunneling. Fast flux is detected by monitoring TTL values and response counts.

### 6. Local LLM Rule Generation
When a threat is confirmed, ArgusML calls Meta Llama 3 running locally on GPU. The LLM generates a plain English description. ArgusML wraps it in valid Suricata rule syntax and deploys it instantly. No internet. No API calls. No data leaving the machine. Perfect for air-gapped and classified environments.

### 7. Explainable AI
Every detection includes a human readable explanation:
```
[DETECTION #1] 03:53:08
Threat:      backdoor_activity
Confidence:  95.5%
Streams:     suricata
Explanation: Threat detected: backdoor_activity (confidence: 95.5%) |
High byte rate (1.2M B/s) suggests data exfiltration
```

### 8. Live Web Dashboard
Real-time threat visualization at http://localhost:5000 featuring:
- World map with animated attack origin lines
- Live threat feed with confidence scores
- Threat distribution charts
- System health monitoring
- Generated rules display

### 9. REST API
Enterprise integration at http://localhost:5001:
```
GET  /api/v1/status       — System health and model stats
GET  /api/v1/detections   — Recent threat detections
GET  /api/v1/rules        — Generated Suricata rules
GET  /api/v1/threats      — Threat distribution
GET  /api/v1/streams      — ML stream performance
POST /api/v1/predict      — Submit traffic for analysis
```

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

### Quick Start
```bash
git clone https://github.com/jdelagar/ArgusML.git
cd ArgusML
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
ollama pull llama3
```

### Docker
```bash
docker build -t argusml .
docker run -d --gpus all -p 5000:5000 -p 5001:5001 argusml
```

### Configure Suricata
Add to /etc/suricata/suricata.yaml:
```yaml
rule-files:
  - suricata.rules
  - argus_ml.rules
```

### Train All Models
```bash
python3 argus_ml.py --train
```

### Run
```bash
sudo python3 argus_ml.py
```

### Auto-start on Boot
```bash
sudo cp argus-ml.service /etc/systemd/system/
sudo systemctl enable argus-ml.service
sudo systemctl start argus-ml.service
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

---

## Project Structure

```
ArgusML/
├── argus_ml.py                    # Main entry point and orchestration
├── core/
│   ├── config.py                  # System configuration
│   ├── base.py                    # Base stream class (XGBoost + Isolation Forest)
│   └── continuous_learning.py     # Self-improving model retraining engine
├── streams/
│   ├── suricata.py                # Network traffic detection stream
│   ├── dns.py                     # DNS anomaly detection stream
│   └── tls.py                     # TLS/SSL inspection stream
├── fusion/
│   └── bayesian.py                # Adaptive Bayesian Fusion Engine
├── output/
│   └── rule_generator.py          # LLM-powered autonomous rule generator
├── dashboard/
│   ├── app.py                     # Web dashboard (Flask + Socket.IO)
│   └── api.py                     # REST API
├── Dockerfile                     # Container deployment
├── requirements.txt               # Python dependencies
└── argus-ml.service               # Systemd service
```

---

## Roadmap

- [x] Suricata network traffic detection stream
- [x] DNS anomaly detection stream — tunneling, DGA, fast flux
- [x] TLS/SSL inspection stream — JA3/JA4 fingerprinting, C2 detection
- [x] Adaptive Bayesian Fusion Engine
- [x] Continuous learning — self-improving models, automatic retraining
- [x] Local LLM autonomous rule generation
- [x] Explainable AI detections
- [x] Live web dashboard with world map attack visualization
- [x] REST API for enterprise integration
- [x] Docker container for easy deployment
- [x] Systemd services for autonomous operation
- [x] NetFlow stream — beaconing, port scan, lateral movement, data exfiltration
- [x] Post-quantum encrypted threat intelligence sharing — ML-KEM-768 + ML-DSA-65 + AES-256-GCM
- [x] Cloud deployment (AWS EC2 + ECR) — Dashboard: http://18.116.72.77:5002 | API: http://18.116.72.77:5001
- [x] Windows support — cross-platform paths, polling mode, install_windows.bat

---

## License

Copyright 2026 Juan Manuel De La Garza

Licensed under the Apache License, Version 2.0. See LICENSE for full details.

You are free to use, modify and distribute this software. Commercial use is permitted. You must include attribution and cannot use my name to endorse derived products without permission.

---

*ArgusML — Always watching. Never sleeping.* 👁️
