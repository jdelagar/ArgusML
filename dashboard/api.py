#!/usr/bin/env python3
"""ArgusML REST API"""
import os, sys, json, uuid, re, subprocess
from datetime import datetime
from functools import wraps
from collections import Counter
from flask import Flask, jsonify, request, abort

sys.path.insert(0, '/home/cerberus-s6/argusml')
app = Flask(__name__)
app.config['SECRET_KEY'] = 'argusml-api-2026'

FUSION_DECISIONS = '/home/cerberus-s6/argusml/output/fusion_decisions.jsonl'
ARGUS_RULES = '/var/lib/suricata/rules/argus_ml.rules'
API_KEYS = {'argusml-demo-key-2026': 'demo', 'argusml-admin-key-2026': 'admin'}

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not key or key not in API_KEYS:
            abort(401, description='Invalid or missing API key')
        return f(*args, **kwargs)
    return decorated

def svc_status(name):
    try:
        r = subprocess.run(['systemctl', 'is-active', name], capture_output=True, text=True)
        return r.stdout.strip()
    except:
        return 'unknown'

def get_detections(limit=100, label=None, min_confidence=0.0):
    detections = []
    if not os.path.exists(FUSION_DECISIONS):
        return detections
    try:
        with open(FUSION_DECISIONS, 'r') as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            try:
                d = json.loads(line.strip())
                d['id'] = i
                if label and d.get('fused_label') != label:
                    continue
                if d.get('fused_confidence', 0) < min_confidence:
                    continue
                if d.get('fused_label') != 'normal':
                    detections.append(d)
            except:
                continue
    except:
        pass
    return detections[-limit:]

def get_rules():
    rules = []
    if not os.path.exists(ARGUS_RULES):
        return rules
    try:
        with open(ARGUS_RULES, 'r') as f:
            for i, line in enumerate(f):
                line = line.strip()
                if line.startswith('alert') and '[ARGUS-ML]' in line:
                    msg = re.search(r'msg:\"([^\"]+)\"', line)
                    sid = re.search(r'sid:(\d+)', line)
                    conf = re.search(r'cf_confidence ([0-9.]+)', line)
                    lbl = re.search(r'cf_label (\w+)', line)
                    sev = re.search(r'cf_severity (\d+)', line)
                    rules.append({
                        'id': i, 'raw': line,
                        'message': msg.group(1) if msg else '',
                        'sid': int(sid.group(1)) if sid else 0,
                        'confidence': float(conf.group(1)) if conf else 0,
                        'label': lbl.group(1) if lbl else '',
                        'severity': int(sev.group(1)) if sev else 3,
                    })
    except:
        pass
    return rules

@app.route('/api/v1/status', methods=['GET'])
@require_api_key
def status():
    detections = get_detections(1000)
    threat_counts = Counter(d.get('fused_label') for d in detections)
    return jsonify({
        'status': 'operational', 'version': '1.0.0',
        'timestamp': datetime.now().isoformat(),
        'model': {
            'accuracy': 0.9804, 'f1_score': 0.9766,
            'algorithm': 'XGBoost + Isolation Forest',
            'fusion': 'Adaptive Bayesian',
            'hardware': 'NVIDIA RTX 5070 Ti (CUDA)',
        },
        'services': {
            'suricata': svc_status('suricata'),
            'argus_ml': svc_status('argus-ml'),
            'suricata_fusion': svc_status('suricata-fusion'),
            'evebox': svc_status('evebox'),
            'dashboard': svc_status('argus-ml-dashboard'),
        },
        'statistics': {
            'total_detections': len(detections),
            'threat_distribution': dict(threat_counts),
            'rules_generated': len(get_rules()),
        }
    })

@app.route('/api/v1/detections', methods=['GET'])
@require_api_key
def detections():
    limit = min(int(request.args.get('limit', 50)), 500)
    label = request.args.get('label')
    min_conf = float(request.args.get('min_confidence', 0.0))
    results = get_detections(limit=limit, label=label, min_confidence=min_conf)
    return jsonify({'count': len(results), 'detections': results,
        'filters': {'limit': limit, 'label': label, 'min_confidence': min_conf}})

@app.route('/api/v1/detections/<int:detection_id>', methods=['GET'])
@require_api_key
def get_detection(detection_id):
    for d in get_detections(1000):
        if d.get('id') == detection_id:
            return jsonify(d)
    abort(404, description=f'Detection {detection_id} not found')

@app.route('/api/v1/rules', methods=['GET'])
@require_api_key
def rules():
    results = get_rules()
    label = request.args.get('label')
    if label:
        results = [r for r in results if r.get('label') == label]
    return jsonify({'count': len(results), 'rules': results})

@app.route('/api/v1/threats', methods=['GET'])
@require_api_key
def threats():
    detections = get_detections(1000)
    counts = Counter(d.get('fused_label') for d in detections)
    total = sum(counts.values())
    threat_stats = []
    for lbl, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
        threat_stats.append({
            'label': lbl, 'count': count,
            'percentage': round(count / total * 100, 1) if total > 0 else 0,
            'avg_confidence': round(
                sum(d.get('fused_confidence', 0) for d in detections
                    if d.get('fused_label') == lbl) / max(count, 1), 4)
        })
    return jsonify({'total_threats': total, 'threat_types': len(counts), 'distribution': threat_stats})

@app.route('/api/v1/streams', methods=['GET'])
@require_api_key
def streams():
    return jsonify({
        'streams': [{'name': 'suricata', 'status': 'active',
            'model': 'XGBoost (GPU) + Isolation Forest',
            'accuracy': 0.9804, 'f1_score': 0.9766,
            'training_samples': 9193, 'normal_baseline_samples': 6373,
            'hardware': 'NVIDIA RTX 5070 Ti', 'features': 30}],
        'fusion': {'algorithm': 'Adaptive Bayesian',
            'active_streams': 1, 'weights': {'suricata': 1.9608}}
    })

@app.route('/api/v1/predict', methods=['POST'])
@require_api_key
def predict():
    data = request.get_json()
    if not data:
        abort(400, description='JSON body required')
    try:
        import numpy as np, joblib, xgboost as xgb
        model_path = '/home/cerberus-s6/argusml/models/suricata.joblib'
        if not os.path.exists(model_path):
            abort(503, description='Model not loaded')
        model_data = joblib.load(model_path)
        model = model_data['model']
        classes = model_data.get('classes', ['normal', 'Backdoor'])
        feature_cols = ['fl_dur','fw_pk','l_fw_pkt','l_bw_pkt','pkt_len_min',
            'pkt_len_max','pkt_len_std','fl_byt_s','fl_iat_min','bw_iat_tot',
            'bw_iat_min','bw_psh_flag','fw_urg_flag','bw_urg_flag','fw_hdr_len',
            'bw_pkt_s','fin_cnt','syn_cnt','psh_cnt','urg_cnt','ece_cnt',
            'down_up_ratio','fw_byt_blk_avg','fw_pkt_blk_avg','fw_blk_rate_avg',
            'bw_byt_blk_avg','bw_pkt_blk_avg','bw_blk_rate_avg','fw_win_byt','bw_win_byt']
        features = np.array([[float(data.get(c, 0)) for c in feature_cols]], dtype=np.float32)
        probs = model.predict(xgb.DMatrix(features))
        if probs.ndim == 1:
            confidence = float(probs[0])
            label = classes[1] if confidence > 0.5 else classes[0]
            confidence = confidence if confidence > 0.5 else 1 - confidence
        else:
            idx = probs[0].argmax()
            label = classes[idx]
            confidence = float(probs[0][idx])
        label_normalized = label.lower()
        if label_normalized != 'normal':
            label_normalized += '_activity'
        return jsonify({
            'prediction': {
                'label': label_normalized,
                'confidence': round(confidence, 4),
                'is_threat': label_normalized != 'normal',
                'severity': 1 if confidence > 0.95 else 2 if confidence > 0.85 else 3 if confidence > 0.75 else 4,
            },
            'model': 'XGBoost (GPU)',
            'timestamp': datetime.now().isoformat(),
            'request_id': str(uuid.uuid4()),
        })
    except Exception as e:
        abort(500, description=str(e))

@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(404)
@app.errorhandler(500)
@app.errorhandler(503)
def error_handler(e):
    return jsonify({'error': str(e.description), 'status': e.code}), e.code

if __name__ == '__main__':
    print('[argusml-api] Starting REST API on http://0.0.0.0:5001')
    app.run(host='0.0.0.0', port=5001, debug=False)
