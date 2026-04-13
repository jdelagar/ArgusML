#!/usr/bin/env python3
"""
ArgusML MITRE ATT&CK Integration
Maps ArgusML detections to MITRE ATT&CK techniques automatically.
"""

# Complete mapping of ArgusML threat labels to MITRE ATT&CK techniques
ATTCK_MAPPING = {
    # Network threats (Suricata + NetFlow streams)
    "backdoor_activity": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection.",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "severity": "critical",
    },
    "botnet_activity": {
        "technique_id": "T1583.005",
        "technique_name": "Acquire Infrastructure: Botnet",
        "tactic": "Resource Development",
        "tactic_id": "TA0042",
        "description": "Adversaries may buy, lease, or rent a network of compromised systems to stage, launch, and execute operations.",
        "url": "https://attack.mitre.org/techniques/T1583/005/",
        "severity": "high",
    },
    "ddos_activity": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "description": "Adversaries may perform Network Denial of Service attacks to degrade or block the availability of targeted resources.",
        "url": "https://attack.mitre.org/techniques/T1498/",
        "severity": "high",
    },
    "web_attack_activity": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to gain initial access.",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "severity": "high",
    },
    # NetFlow threats
    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "severity": "medium",
    },
    "beaconing": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries may communicate using application layer protocols to avoid detection by blending in with existing traffic.",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "severity": "high",
    },
    "lateral_movement": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "description": "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections.",
        "url": "https://attack.mitre.org/techniques/T1021/",
        "severity": "critical",
    },
    "data_exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "severity": "critical",
    },
    # DNS threats
    "dns_tunneling": {
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries may communicate using the Domain Name System protocol to avoid detection.",
        "url": "https://attack.mitre.org/techniques/T1071/004/",
        "severity": "high",
    },
    "dga_domain": {
        "technique_id": "T1568.002",
        "technique_name": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries may make use of Domain Generation Algorithms to dynamically identify a destination for C2 traffic.",
        "url": "https://attack.mitre.org/techniques/T1568/002/",
        "severity": "high",
    },
    "fast_flux": {
        "technique_id": "T1568.001",
        "technique_name": "Dynamic Resolution: Fast Flux DNS",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries may use Fast Flux DNS to hide a command and control channel behind an array of rapidly changing IP addresses.",
        "url": "https://attack.mitre.org/techniques/T1568/001/",
        "severity": "high",
    },
    "c2_beacon": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries may communicate using application layer protocols to avoid detection.",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "severity": "critical",
    },
    # TLS threats
    "malicious_tls": {
        "technique_id": "T1573",
        "technique_name": "Encrypted Channel",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries may employ a known encryption algorithm to conceal command and control traffic.",
        "url": "https://attack.mitre.org/techniques/T1573/",
        "severity": "high",
    },
    "c2_tls": {
        "technique_id": "T1573.002",
        "technique_name": "Encrypted Channel: Asymmetric Cryptography",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries may employ a known asymmetric encryption algorithm to conceal C2 traffic.",
        "url": "https://attack.mitre.org/techniques/T1573/002/",
        "severity": "critical",
    },
    "weak_tls": {
        "technique_id": "T1040",
        "technique_name": "Network Sniffing",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may sniff network traffic to capture information about an environment.",
        "url": "https://attack.mitre.org/techniques/T1040/",
        "severity": "medium",
    },
}

# Tactic colors for dashboard visualization
TACTIC_COLORS = {
    "Initial Access": "#ff4444",
    "Execution": "#ff6600",
    "Persistence": "#ff8800",
    "Privilege Escalation": "#ffaa00",
    "Defense Evasion": "#ffcc00",
    "Credential Access": "#aaff00",
    "Discovery": "#44ff88",
    "Lateral Movement": "#00ffcc",
    "Collection": "#00ccff",
    "Command and Control": "#4488ff",
    "Exfiltration": "#aa44ff",
    "Impact": "#ff44aa",
    "Resource Development": "#ff6644",
}

def get_attck_info(threat_label):
    """Get MITRE ATT&CK information for a threat label."""
    # Try exact match first
    if threat_label in ATTCK_MAPPING:
        return ATTCK_MAPPING[threat_label]
    
    # Try partial match
    for key, value in ATTCK_MAPPING.items():
        if key in threat_label or threat_label in key:
            return value
    
    # Default unknown
    return {
        "technique_id": "T1unknown",
        "technique_name": "Unknown Technique",
        "tactic": "Unknown",
        "tactic_id": "TA0000",
        "description": "Technique not yet mapped to MITRE ATT&CK framework.",
        "url": "https://attack.mitre.org/",
        "severity": "medium",
    }

def enrich_detection(detection):
    """Enrich a detection dict with MITRE ATT&CK information."""
    label = detection.get("fused_label") or detection.get("label", "")
    attck = get_attck_info(label)
    detection["attck"] = attck
    return detection

def get_tactic_color(tactic):
    """Get color for a tactic."""
    return TACTIC_COLORS.get(tactic, "#888888")

if __name__ == "__main__":
    # Test the mapping
    test_labels = ["backdoor_activity", "port_scan", "dns_tunneling", "lateral_movement", "data_exfiltration"]
    print("ArgusML MITRE ATT&CK Mapping Test")
    print("=" * 60)
    for label in test_labels:
        info = get_attck_info(label)
        print(f"{label}")
        print(f"  Technique: {info['technique_id']} — {info['technique_name']}")
        print(f"  Tactic:    {info['tactic']} ({info['tactic_id']})")
        print(f"  Severity:  {info['severity']}")
        print(f"  URL:       {info['url']}")
        print()
    print("ATT&CK mapping module working correctly!")
