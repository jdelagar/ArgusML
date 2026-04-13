#!/usr/bin/env python3
"""
ArgusML Cloud Dashboard
Full-featured dashboard for cloud deployment using polling.
"""

import os
import sys
import json
import subprocess
from datetime import datetime
from collections import defaultdict, Counter
from flask import Flask, jsonify, Response
import requests

sys.path.insert(0, '/app')

app = Flask(__name__)

FUSION_DECISIONS = '/app/output/fusion_decisions.jsonl'
ARGUS_RULES = '/var/lib/suricata/rules/argus_ml.rules'

geo_cache = {}

def geolocate_ip(ip):
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

def get_detections(limit=100):
    detections = []
    if not os.path.exists(FUSION_DECISIONS):
        return detections
    try:
        with open(FUSION_DECISIONS, 'r') as f:
            lines = f.readlines()
        for i, line in enumerate(lines[-limit:]):
            try:
                d = json.loads(line.strip())
                if d.get('fused_label') != 'normal':
                    detections.append(d)
            except:
                continue
    except:
        pass
    return detections

def get_rules():
    rules = []
    if not os.path.exists(ARGUS_RULES):
        return rules
    try:
        with open(ARGUS_RULES, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('alert') and '[ARGUS-ML]' in line:
                    import re
                    msg = re.search(r'msg:"([^"]+)"', line)
                    sid = re.search(r'sid:(\d+)', line)
                    conf = re.search(r'cf_confidence ([0-9.]+)', line)
                    rules.append({
                        'raw': line,
                        'message': msg.group(1) if msg else '',
                        'sid': int(sid.group(1)) if sid else 0,
                        'confidence': float(conf.group(1)) if conf else 0,
                    })
    except:
        pass
    return rules

def svc_status(name):
    try:
        r = subprocess.run(['systemctl', 'is-active', name], capture_output=True, text=True)
        return r.stdout.strip() == 'active'
    except:
        return False

@app.route('/')
def index():
    return Response(DASHBOARD_HTML, mimetype='text/html')

@app.route('/api/stats')
def stats():
    detections = get_detections(1000)
    counts = Counter(d.get('fused_label') for d in detections)
    recent = get_detections(20)
    
    # Get geo for recent detections
    for d in recent:
        src_ip = d.get('src_ip')
        if src_ip:
            d['geo'] = geolocate_ip(src_ip)

    return jsonify({
        'threat_stats': dict(counts),
        'rules': get_rules(),
        'total_detections': len(detections),
        'recent_detections': recent,
        'active_threats': len([d for d in recent if d.get('fused_confidence', 0) > 0.9]),
        'services': {
            'argus_ml': svc_status('argus-ml'),
            'suricata': svc_status('suricata'),
            'suricata_fusion': svc_status('suricata-fusion'),
            'evebox': svc_status('evebox'),
        },
        'timestamp': datetime.now().isoformat(),
    })

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ArgusML — Live Threat Dashboard</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0f; color: #e0e0e0; font-family: 'Courier New', monospace; overflow-x: hidden; }
        .header { background: linear-gradient(135deg, #0d1117 0%, #161b22 100%); border-bottom: 1px solid #ff4444; padding: 15px 30px; display: flex; align-items: center; justify-content: space-between; }
        .logo { font-size: 24px; font-weight: bold; color: #ff4444; text-shadow: 0 0 20px #ff444466; letter-spacing: 2px; }
        .logo span { color: #ffffff; }
        .tagline { font-size: 11px; color: #666; letter-spacing: 1px; }
        .live-indicator { display: flex; align-items: center; gap: 8px; font-size: 12px; color: #00ff88; }
        .live-dot { width: 8px; height: 8px; background: #00ff88; border-radius: 50%; animation: pulse 1.5s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.5; transform: scale(1.3); } }
        .cloud-badge { background: #1a3a5c; border: 1px solid #4488ff; padding: 4px 10px; border-radius: 4px; font-size: 10px; color: #4488ff; }
        .stats-bar { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1px; background: #1a1a2e; border-bottom: 1px solid #222; }
        .stat-item { background: #0d1117; padding: 15px 20px; text-align: center; }
        .stat-value { font-size: 28px; font-weight: bold; color: #ff4444; text-shadow: 0 0 10px #ff444444; }
        .stat-label { font-size: 10px; color: #666; letter-spacing: 1px; margin-top: 3px; }
        .main-grid { display: grid; grid-template-columns: 1fr 350px; grid-template-rows: 450px 1fr; gap: 1px; background: #111; height: calc(100vh - 125px); }
        .panel { background: #0d1117; padding: 20px; overflow: hidden; }
        .panel-title { font-size: 11px; color: #ff4444; letter-spacing: 2px; margin-bottom: 15px; text-transform: uppercase; border-bottom: 1px solid #1a1a2e; padding-bottom: 8px; }
        #map { width: 100%; height: calc(100% - 35px); border-radius: 4px; filter: brightness(0.8) saturate(0.7); }
        .chart-panel { grid-column: 2; grid-row: 1 / 3; display: flex; flex-direction: column; gap: 1px; }
        .chart-container { background: #0d1117; padding: 20px; flex: 1; overflow: hidden; }
        .rules-panel { grid-column: 1; grid-row: 2; overflow-y: auto; }
        .threat-feed { height: calc(100% - 35px); overflow-y: auto; scrollbar-width: thin; }
        .threat-item { background: #111827; border-left: 3px solid #ff4444; padding: 10px 12px; margin-bottom: 6px; border-radius: 0 4px 4px 0; animation: slideIn 0.3s ease; }
        @keyframes slideIn { from { opacity: 0; transform: translateX(-10px); } to { opacity: 1; transform: translateX(0); } }
        .threat-label { font-size: 12px; font-weight: bold; color: #ff4444; }
        .threat-confidence { font-size: 11px; color: #00ff88; float: right; }
        .threat-time { font-size: 10px; color: #555; margin-top: 3px; }
        .threat-geo { font-size: 10px; color: #4488ff; margin-top: 3px; }
        .rule-item { background: #111827; border-left: 3px solid #4488ff; padding: 8px 12px; margin-bottom: 4px; border-radius: 0 4px 4px 0; font-size: 10px; color: #88aaff; word-break: break-all; line-height: 1.5; }
        .service-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 5px; }
        .service-dot.online { background: #00ff88; box-shadow: 0 0 6px #00ff88; }
        .service-dot.offline { background: #ff4444; box-shadow: 0 0 6px #ff4444; }
        .services-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
        .service-item { background: #111827; padding: 10px; border-radius: 4px; font-size: 11px; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: #0d1117; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 2px; }
        .attack-flash { animation: flash 0.5s ease; }
        @keyframes flash { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
    </style>
</head>
<body>
<div class="header">
    <div>
        <div class="logo">ARGUS<span>ML</span> 👁️</div>
        <div class="tagline">AUTONOMOUS ML-POWERED INTRUSION DETECTION & PREVENTION SYSTEM</div>
    </div>
    <div style="display:flex;align-items:center;gap:20px;">
        <span class="cloud-badge">☁️ AWS EC2 us-east-2</span>
        <div class="live-indicator"><div class="live-dot"></div>LIVE</div>
        <div id="clock" style="font-size:13px;color:#888;"></div>
    </div>
</div>

<div class="stats-bar">
    <div class="stat-item"><div class="stat-value" id="total-detections">0</div><div class="stat-label">TOTAL DETECTIONS</div></div>
    <div class="stat-item"><div class="stat-value" id="total-rules">0</div><div class="stat-label">RULES GENERATED</div></div>
    <div class="stat-item"><div class="stat-value" style="color:#00ff88">98.04%</div><div class="stat-label">MODEL ACCURACY</div></div>
    <div class="stat-item"><div class="stat-value" id="active-threats">0</div><div class="stat-label">ACTIVE THREATS</div></div>
    <div class="stat-item"><div class="stat-value" id="services-online" style="color:#00ff88">--</div><div class="stat-label">SERVICES ONLINE</div></div>
</div>

<div class="main-grid">
    <div class="panel">
        <div class="panel-title">🌍 LIVE ATTACK ORIGINS</div>
        <div id="map"></div>
    </div>

    <div class="chart-panel">
        <div class="chart-container">
            <div class="panel-title">📊 THREAT DISTRIBUTION</div>
            <canvas id="threatChart"></canvas>
        </div>
        <div class="chart-container">
            <div class="panel-title">⚡ SYSTEM STATUS</div>
            <div class="services-grid" id="services-grid"></div>
        </div>
        <div class="chart-container" style="flex:2;overflow:hidden;">
            <div class="panel-title">🚨 LIVE THREAT FEED</div>
            <div class="threat-feed" id="threat-feed"></div>
        </div>
    </div>

    <div class="panel rules-panel">
        <div class="panel-title">📋 ARGUS-ML GENERATED RULES</div>
        <div id="rules-list"></div>
    </div>
</div>

<script>
    setInterval(() => { document.getElementById('clock').textContent = new Date().toUTCString(); }, 1000);

    const map = L.map('map', { center: [20, 0], zoom: 2, attributionControl: false });
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map);

    const homeIcon = L.divIcon({ html: '<div style="width:12px;height:12px;background:#00ff88;border-radius:50%;box-shadow:0 0 10px #00ff88;border:2px solid #fff;"></div>', iconSize: [12,12], className: '' });
    L.marker([40.1, -104.5], {icon: homeIcon}).addTo(map).bindPopup('<b style="color:#00ff88">ArgusML Sensor</b><br>Keenesburg, CO');

    const attackMarkers = [];
    const attackLines = [];

    function addAttackToMap(geo, label, confidence) {
        if (!geo || !geo.lat || !geo.lon) return;
        const attackIcon = L.divIcon({ html: '<div style="width:10px;height:10px;background:#ff4444;border-radius:50%;box-shadow:0 0 15px #ff4444;"></div>', iconSize: [10,10], className: '' });
        const marker = L.marker([geo.lat, geo.lon], {icon: attackIcon}).addTo(map)
            .bindPopup('<b style="color:#ff4444">' + label.replace('_',' ').toUpperCase() + '</b><br>📍 ' + geo.city + ', ' + geo.country + '<br>🌐 ' + geo.ip + '<br>💯 ' + (confidence*100).toFixed(1) + '%');
        const line = L.polyline([[geo.lat, geo.lon], [40.1, -104.5]], {color: '#ff4444', weight: 1, opacity: 0.6, dashArray: '5,10'}).addTo(map);
        attackMarkers.push(marker);
        attackLines.push(line);
        if (attackMarkers.length > 20) { map.removeLayer(attackMarkers.shift()); map.removeLayer(attackLines.shift()); }
    }

    const chart = new Chart(document.getElementById('threatChart').getContext('2d'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#ff4444','#ff6600','#ffaa00','#ff00ff','#4488ff','#00ffaa'], borderWidth: 0 }] },
        options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { labels: { color: '#888', font: { size: 10 } } } } }
    });

    function updateDashboard() {
        fetch('/api/stats')
            .then(r => r.json())
            .then(data => {
                document.getElementById('total-detections').textContent = data.total_detections || 0;
                document.getElementById('total-rules').textContent = (data.rules || []).length;
                document.getElementById('active-threats').textContent = data.active_threats || 0;

                const services = data.services || {};
                const online = Object.values(services).filter(Boolean).length;
                const total = Object.keys(services).length;
                document.getElementById('services-online').textContent = online + '/' + total;

                const serviceNames = { argus_ml: 'ArgusML', suricata: 'Suricata', suricata_fusion: 'ML Fusion', evebox: 'EveBox' };
                const grid = document.getElementById('services-grid');
                grid.innerHTML = '';
                for (const [key, status] of Object.entries(services)) {
                    grid.innerHTML += '<div class="service-item"><span class="service-dot ' + (status ? 'online' : 'offline') + '"></span>' + (serviceNames[key] || key) + '</div>';
                }

                const stats = data.threat_stats || {};
                chart.data.labels = Object.keys(stats).map(k => k.replace('_activity','').replace('_',' ').toUpperCase());
                chart.data.datasets[0].data = Object.values(stats);
                chart.update();

                const feed = document.getElementById('threat-feed');
                feed.innerHTML = '';
                (data.recent_detections || []).slice().reverse().forEach(d => {
                    const label = (d.fused_label || '').replace('_activity','').replace('_',' ').toUpperCase();
                    const conf = ((d.fused_confidence || 0) * 100).toFixed(1);
                    const time = (d.timestamp || '').substring(11,19);
                    const geo = d.geo;
                    feed.innerHTML += '<div class="threat-item"><span class="threat-label">' + label + '</span><span class="threat-confidence">' + conf + '%</span><div class="threat-time">' + time + '</div>' + (geo ? '<div class="threat-geo">📍 ' + geo.city + ', ' + geo.country + '</div>' : '') + '</div>';
                    if (geo) addAttackToMap(geo, d.fused_label, d.fused_confidence);
                });

                const rulesList = document.getElementById('rules-list');
                rulesList.innerHTML = '';
                (data.rules || []).forEach(rule => {
                    rulesList.innerHTML += '<div class="rule-item"><b style="color:#88aaff">' + rule.message + '</b><br>SID: ' + rule.sid + ' | Confidence: ' + (rule.confidence * 100).toFixed(1) + '%</div>';
                });
            })
            .catch(console.error);
    }

    updateDashboard();
    setInterval(updateDashboard, 5000);
</script>
</body>
</html>"""

if __name__ == '__main__':
    print("[argusml-cloud-dashboard] Starting on http://0.0.0.0:5002")
    app.run(host='0.0.0.0', port=5002, debug=False)
