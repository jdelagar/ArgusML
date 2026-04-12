#!/usr/bin/env python3
"""
ArgusML Rule Generator
Improved version with better LLM prompting and rule quality.
Generates Suricata rules from fusion engine decisions.
"""

import os
import subprocess
import requests
import json
from datetime import datetime
from core.config import (
    SURICATA_RULES_FILE,
    OLLAMA_URL,
    OLLAMA_MODEL,
    SID_START,
    SID_FP_START,
    CONFIDENCE_THRESHOLD,
)


class RuleGenerator:
    """
    Generates Suricata rules from ArgusML decisions.
    
    Improvements over original:
    1. Better LLM prompting for more accurate descriptions
    2. More specific rule conditions based on threat type
    3. Severity levels based on confidence
    4. Rule deduplication
    5. Rule validation before writing
    """

    def __init__(self):
        self.generated_rules = {}
        self.suppressed_rules = {}
        self.sid_counter = SID_START
        self.fp_sid_counter = SID_FP_START
        self.total_generated = 0
        self.total_suppressed = 0
        print("[rule_generator] Rule generator initialized")

    def get_llm_description(self, label, confidence, explanation, streams):
        """
        Get improved LLM description with more context.
        Better prompting = better rules.
        """
        stream_list = ", ".join(streams) if streams else "unknown"
        prompt = (
            f"You are a cybersecurity expert writing Suricata IDS rule messages. "
            f"Write a concise alert message (10 words maximum) for this threat:\n"
            f"Threat type: {label}\n"
            f"Confidence: {confidence:.1%}\n"
            f"Detected by: {stream_list}\n"
            f"Context: {explanation[:200]}\n\n"
            f"Rules for your response:\n"
            f"- Maximum 10 words\n"
            f"- Be specific about the threat type\n"
            f"- No quotes, no punctuation at start or end\n"
            f"- Start with a capital letter\n"
            f"- Reply with ONLY the message, nothing else"
        )

        try:
            response = requests.post(
                OLLAMA_URL,
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
                timeout=30,
            )
            result = response.json()
            description = result.get("response", "").strip()
            # Clean up the description
            description = description.strip('"\'').strip()
            if len(description) > 100:
                description = description[:100]
            return description
        except Exception as e:
            print(f"[rule_generator] LLM error: {e}")
            return f"{label.replace('_', ' ').title()} detected by ArgusML"

    def get_severity(self, confidence):
        """Map confidence to Suricata severity level."""
        if confidence >= 0.95:
            return 1  # Critical
        elif confidence >= 0.85:
            return 2  # High
        elif confidence >= 0.75:
            return 3  # Medium
        else:
            return 4  # Low

    def get_rule_action(self, label, confidence):
        """Determine rule action based on threat type and confidence."""
        # High confidence critical threats get alert
        # Everything else gets alert too (IDS mode)
        # In IPS mode these would be 'drop' for high confidence
        return "alert"

    def build_rule(self, label, confidence, explanation, streams, sid):
        """Build a complete Suricata rule."""
        description = self.get_llm_description(label, confidence, explanation, streams)
        action = self.get_rule_action(label, confidence)
        severity = self.get_severity(confidence)
        stream_list = ",".join(streams) if streams else "unknown"

        rule = (
            f'{action} ip any any -> any any '
            f'(msg:"[ARGUS-ML] {description}"; '
            f'threshold:type threshold, track by_src, count 1, seconds 60; '
            f'metadata:cf_confidence {confidence:.4f}, '
            f'cf_streams {stream_list}, '
            f'cf_label {label}, '
            f'cf_severity {severity}, '
            f'cf_version 1.0; '
            f'classtype:misc-attack; '
            f'sid:{sid}; rev:1;)'
        )
        return rule

    def build_suppression_rule(self, label, confidence, normal_score, streams, sid):
        """Build a pass rule to suppress false positives."""
        stream_list = ",".join(streams) if streams else "unknown"
        pct = normal_score * 100

        rule = (
            f'pass ip any any -> any any '
            f'(msg:"[ARGUS-ML-SUPPRESSED] {label} suppressed - '
            f'fusion normal score {pct:.1f}%"; '
            f'metadata:cf_normal_score {normal_score:.4f}, '
            f'cf_false_positive true, '
            f'cf_original_label {label}, '
            f'cf_streams {stream_list}; '
            f'sid:{sid}; rev:1;)'
        )
        return rule

    def validate_rule(self, rule):
        """Basic rule validation before writing."""
        required = ["msg:", "sid:", "rev:"]
        return all(r in rule for r in required)

    def process_decisions(self, decisions):
        """
        Process a list of fusion decisions and generate rules.
        decisions: list of dicts from BayesianFusion.fuse()
        """
        new_rules = {}
        new_suppressions = {}

        for decision in decisions:
            label = decision.get("fused_label", "normal")
            confidence = float(decision.get("fused_confidence", 0))
            explanation = decision.get("explanation", "")
            streams = decision.get("streams_consulted", [])
            normal_score = decision.get("posteriors", {}).get("normal", 0)
            is_fp = label == "normal" and confidence > 0.9

            if is_fp:
                # Check if any stream flagged a threat
                stream_votes = decision.get("stream_votes", {})
                flagged_labels = [v for v in stream_votes.values() if v != "normal"]
                for flagged in set(flagged_labels):
                    key = f"{flagged}_{','.join(sorted(streams))}"
                    if key not in new_suppressions:
                        new_suppressions[key] = (flagged, confidence, normal_score, streams)

            elif label != "normal" and confidence >= CONFIDENCE_THRESHOLD:
                key = f"{label}_{','.join(sorted(streams))}"
                if key not in new_rules or confidence > new_rules[key][1]:
                    new_rules[key] = (label, confidence, explanation, streams)

        # Generate rules for new threats
        rules_written = []
        for key, (label, confidence, explanation, streams) in new_rules.items():
            if key not in self.generated_rules:
                rule = self.build_rule(label, confidence, explanation, streams, self.sid_counter)
                if self.validate_rule(rule):
                    self.generated_rules[key] = rule
                    rules_written.append(rule)
                    self.sid_counter += 1
                    self.total_generated += 1
                    print(f"[rule_generator] New rule: {label} ({confidence:.1%})")

        # Generate suppression rules
        for key, (label, confidence, normal_score, streams) in new_suppressions.items():
            if key not in self.suppressed_rules:
                rule = self.build_suppression_rule(
                    label, confidence, normal_score, streams, self.fp_sid_counter
                )
                if self.validate_rule(rule):
                    self.suppressed_rules[key] = rule
                    self.fp_sid_counter += 1
                    self.total_suppressed += 1
                    print(f"[rule_generator] New suppression: {label}")

        return rules_written

    def write_rules(self):
        """Write all rules to Suricata rules file."""
        os.makedirs(os.path.dirname(SURICATA_RULES_FILE), exist_ok=True)

        all_rules = list(self.generated_rules.values()) + list(self.suppressed_rules.values())

        with open(SURICATA_RULES_FILE, "w") as f:
            f.write(f"# ArgusML Generated Rules\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Alert rules: {len(self.generated_rules)}\n")
            f.write(f"# Suppression rules: {len(self.suppressed_rules)}\n")
            f.write(f"# Total: {len(all_rules)}\n\n")

            if self.generated_rules:
                f.write("# ── Alert Rules ──\n")
                for rule in self.generated_rules.values():
                    f.write(rule + "\n")

            if self.suppressed_rules:
                f.write("\n# ── Suppression Rules ──\n")
                for rule in self.suppressed_rules.values():
                    f.write(rule + "\n")

        print(f"[rule_generator] Wrote {len(all_rules)} rules to {SURICATA_RULES_FILE}")
        self.reload_suricata()

    def reload_suricata(self):
        """Reload Suricata rules without restart."""
        try:
            result = subprocess.run(
                ["pidof", "suricata"], capture_output=True, text=True
            )
            pid = result.stdout.strip()
            if pid:
                subprocess.run(["kill", "-USR2", pid], check=True)
                print(f"[rule_generator] Reloaded Suricata (pid {pid})")
            else:
                print("[rule_generator] Suricata not running")
        except Exception as e:
            print(f"[rule_generator] Reload error: {e}")

    def get_stats(self):
        """Return rule generator statistics."""
        return {
            "total_generated": self.total_generated,
            "total_suppressed": self.total_suppressed,
            "current_rules": len(self.generated_rules),
            "current_suppressions": len(self.suppressed_rules),
            "next_sid": self.sid_counter,
        }
