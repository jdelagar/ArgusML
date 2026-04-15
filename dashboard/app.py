#!/usr/bin/env python3
"""
ArgusML Web Dashboard
Real-time threat visualization with world map attack origins.
"""

import os
import sys
import json
import time
import subprocess
import threading
from datetime import datetime
from collections import defaultdict

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import requests

sys.path.insert(0, '/home/cerberus-s6/argusml')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'argusml-dashboard-2026'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Paths
FUSION_DECISIONS = '/home/cerberus-s6/argusml/output/fusion_decisions.jsonl'
ARGUS_RULES = '/var/lib/suricata/rules/argus_ml.rules'
EVE_LOG = '/var/log/suricata/eve.json'

# Cache for geo lookups
geo_cache = {}

def geolocate_ip(ip):
    """Convert IP to lat/lon using free API."""
    if not ip or ip.startswith(('192.168.', '10.', '172.')):
        return None
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=3)
        data = response.json()
        if data.get('latitude'):
            result = {
                'lat': data['latitude'],
                'lon': data['longitude'],
                'city': data.get('city', 'Unknown'),
                'country': data.get('country_name', 'Unknown'),
                'ip': ip
            }
            geo_cache[ip] = result
            return result
    except:
        pass
    return None

def get_service_status(service):
    """Check systemd service status."""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', service],
            capture_output=True, text=True
        )
        return result.stdout.strip() == 'active'
    except:
        return False

def get_recent_detections(limit=50):
    """Read recent detections from fusion decisions log."""
    detections = []
    if not os.path.exists(FUSION_DECISIONS):
        return detections
    try:
        with open(FUSION_DECISIONS, 'r') as f:
            lines = f.readlines()
        for line in lines[-limit:]:
            try:
                d = json.loads(line.strip())
                if d.get('fused_label') != 'normal':
                    detections.append(d)
            except:
                continue
    except:
        pass
    return detections

def get_threat_stats():
    """Get threat distribution statistics."""
    stats = defaultdict(int)
    detections = get_recent_detections(500)
    for d in detections:
        label = d.get('fused_label', 'unknown')
        stats[label] += 1
    return dict(stats)

def get_generated_rules():
    """Read ArgusML generated rules."""
    rules = []
    if not os.path.exists(ARGUS_RULES):
        return rules
    try:
        with open(ARGUS_RULES, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('alert') and '[ARGUS-ML]' in line:
                    rules.append(line)
    except:
        pass
    return rules

def get_recent_alerts():
    """Get recent Suricata alerts with source IPs."""
    alerts = []
    try:
        result = subprocess.run(
            ['tail', '-100', EVE_LOG],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            try:
                event = json.loads(line)
                if event.get('event_type') == 'alert':
                    sig = event.get('alert', {}).get('signature', '')
                    if '[ARGUS-ML]' in sig or '[ML-GENERATED]' in sig:
                        alerts.append({
                            'timestamp': event.get('timestamp', ''),
                            'src_ip': event.get('src_ip', ''),
                            'dest_ip': event.get('dest_ip', ''),
                            'signature': sig,
                            'severity': event.get('alert', {}).get('severity', 3)
                        })
            except:
                continue
    except:
        pass
    return alerts[-20:]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    return jsonify({
        'threat_stats': get_threat_stats(),
        'rules': get_generated_rules(),
        'services': {
            'suricata': get_service_status('suricata'),
            'argus_ml': get_service_status('argus-ml'),
            'suricata_fusion': get_service_status('suricata-fusion'),
            'evebox': get_service_status('evebox'),
        },
        'recent_alerts': get_recent_alerts(),
        'total_detections': len(get_recent_detections(1000)),
    })

@app.route('/api/geolocate/<ip>')
def api_geolocate(ip):
    result = geolocate_ip(ip)
    if result:
        return jsonify(result)
    return jsonify({'error': 'Could not geolocate'}), 404

def watch_detections():
    """Background thread to watch for new detections and emit via socketio."""
    last_size = 0
    while True:
        try:
            if os.path.exists(FUSION_DECISIONS):
                size = os.path.getsize(FUSION_DECISIONS)
                if size > last_size:
                    with open(FUSION_DECISIONS, 'r') as f:
                        lines = f.readlines()
                    # Get new lines
                    new_lines = lines[last_size:]
                    for line in new_lines:
                        try:
                            d = json.loads(line.strip())
                            if d.get('fused_label') != 'normal':
                                # Try to get source IP from recent alerts
                                alerts = get_recent_alerts()
                                src_ip = alerts[-1]['src_ip'] if alerts else None
                                geo = geolocate_ip(src_ip) if src_ip else None
                                d['geo'] = geo
                                socketio.emit('new_detection', d)
                        except:
                            continue
                    last_size = size
        except:
            pass
        time.sleep(2)

@socketio.on('connect')
def on_connect():
    """Send initial data on connection."""
    socketio.emit('stats_update', {
        'threat_stats': get_threat_stats(),
        'rules': get_generated_rules(),
        'services': {
            'suricata': get_service_status('suricata'),
            'argus_ml': get_service_status('argus-ml'),
            'suricata_fusion': get_service_status('suricata-fusion'),
            'evebox': get_service_status('evebox'),
        },
        'recent_alerts': get_recent_alerts(),
        'total_detections': len(get_recent_detections(1000)),
    })

if __name__ == '__main__':
    # Start background watcher
    t = threading.Thread(target=watch_detections, daemon=True)
    t.start()
    print("[argusml-dashboard] Starting on http://0.0.0.0:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
