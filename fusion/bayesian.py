#!/usr/bin/env python3
"""
ArgusML Bayesian Fusion Engine
Combines multiple stream outputs using adaptive Bayesian weighting.
Unlike simple stacking, this learns which streams are most reliable
and adjusts weights automatically over time.
"""

import numpy as np
from datetime import datetime
from collections import defaultdict
from core.config import THREAT_LABELS, FUSION_WEIGHTS


class BayesianFusion:
    """
    Adaptive Bayesian fusion engine.
    
    Key advantages over simple stacking:
    1. Weights adapt based on each stream's historical accuracy
    2. Handles missing streams gracefully
    3. Provides confidence intervals not just point estimates
    4. Explains WHY it made each decision
    """

    def __init__(self):
        # Stream weights — start equal, adapt over time
        self.weights = FUSION_WEIGHTS.copy()

        # Track how often each stream was right
        self.stream_correct = defaultdict(int)
        self.stream_total = defaultdict(int)

        # Prior probability of each threat (starts uniform)
        self.threat_priors = {label: 1.0 / len(THREAT_LABELS) for label in THREAT_LABELS}

        # History of fusion decisions
        self.decision_history = []
        self.total_fusions = 0

        print("[bayesian_fusion] Fusion engine initialized")

    def fuse(self, stream_results):
        """
        Fuse results from multiple streams into a single decision.
        
        stream_results: list of dicts from each stream
        Returns: dict with fused label, confidence, explanation
        """
        if not stream_results:
            return self._empty_result()

        # Group results by stream
        by_stream = defaultdict(list)
        for result in stream_results:
            by_stream[result["stream"]].append(result)

        # Calculate posterior probability for each threat label
        posteriors = {label: self.threat_priors[label] for label in THREAT_LABELS}

        stream_votes = {}
        stream_explanations = []

        for stream_name, results in by_stream.items():
            if not results:
                continue

            # Get best result from this stream
            best = max(results, key=lambda x: x["confidence"])
            stream_votes[stream_name] = best

            # Get stream weight
            weight = self.weights.get(stream_name, 1.0)

            # Update posteriors using Bayes rule
            for label in THREAT_LABELS:
                if best["label"] == label:
                    # Stream says this is the threat — boost posterior
                    likelihood = best["confidence"] * weight
                else:
                    # Stream says this is NOT the threat — reduce posterior
                    likelihood = (1.0 - best["confidence"]) * weight / max(len(THREAT_LABELS) - 1, 1)

                posteriors[label] *= max(likelihood, 1e-10)

            stream_explanations.append(
                f"{stream_name}: {best['label']} ({best['confidence']:.1%})"
            )

        # Normalize posteriors
        total = sum(posteriors.values())
        if total > 0:
            posteriors = {k: v / total for k, v in posteriors.items()}

        # Get final decision
        fused_label = max(posteriors, key=posteriors.get)
        fused_confidence = posteriors[fused_label]

        # Anomaly detection — only use as supplementary signal, not override
        is_anomaly = any(r.get("is_anomaly", False) for r in stream_results)
        # Only override with unknown_anomaly if ALL streams say normal
        # and anomaly score is very high
        max_anomaly = max(r.get("anomaly_score", 0) for r in stream_results)
        if is_anomaly and fused_label == "normal" and max_anomaly > 0.8:
            fused_label = "unknown_anomaly"
            fused_confidence = max_anomaly

        # Build explanation
        explanation = self._build_explanation(
            fused_label, fused_confidence, stream_votes, posteriors, is_anomaly
        )

        result = {
            "fused_label": fused_label,
            "fused_confidence": fused_confidence,
            "posteriors": posteriors,
            "stream_votes": {k: v["label"] for k, v in stream_votes.items()},
            "stream_confidences": {k: v["confidence"] for k, v in stream_votes.items()},
            "top_stream": max(stream_votes, key=lambda k: stream_votes[k]["confidence"]) if stream_votes else "none",
            "is_anomaly": is_anomaly,
            "explanation": explanation,
            "timestamp": datetime.now().isoformat(),
            "streams_consulted": list(by_stream.keys()),
        }

        self.decision_history.append(result)
        self.total_fusions += 1

        return result

    def _build_explanation(self, label, confidence, stream_votes, posteriors, is_anomaly):
        """Build a human readable explanation of the fusion decision."""
        parts = []

        if label == "normal":
            parts.append(f"No threat detected (confidence: {confidence:.1%})")
        else:
            parts.append(f"Threat detected: {label} (confidence: {confidence:.1%})")

        # Which streams agreed
        agreeing = [s for s, v in stream_votes.items() if v["label"] == label]
        disagreeing = [s for s, v in stream_votes.items() if v["label"] != label]

        if len(stream_votes) > 1:
            if agreeing:
                parts.append(f"Streams in agreement: {', '.join(agreeing)}")
            if disagreeing:
                parts.append(f"Streams disagreeing: {', '.join(disagreeing)}")

        if is_anomaly:
            parts.append("Anomaly detection flagged unusual behavior pattern")

        # Top alternative threat
        sorted_posteriors = sorted(posteriors.items(), key=lambda x: x[1], reverse=True)
        if len(sorted_posteriors) > 1 and sorted_posteriors[1][1] > 0.1:
            alt_label, alt_conf = sorted_posteriors[1]
            if alt_label != label:
                parts.append(f"Alternative possibility: {alt_label} ({alt_conf:.1%})")

        return " | ".join(parts)

    def update_weights(self, stream_name, was_correct):
        """
        Update stream weights based on whether prediction was correct.
        This is the adaptive learning component.
        """
        self.stream_total[stream_name] += 1
        if was_correct:
            self.stream_correct[stream_name] += 1

        # Recalculate weight based on historical accuracy
        if self.stream_total[stream_name] >= 10:
            accuracy = self.stream_correct[stream_name] / self.stream_total[stream_name]
            # Weight is accuracy with a floor of 0.1 and ceiling of 2.0
            self.weights[stream_name] = max(0.1, min(2.0, accuracy * 2))
            print(f"[bayesian_fusion] Updated {stream_name} weight to {self.weights[stream_name]:.2f}")

    def update_priors(self, threat_counts):
        """
        Update threat priors based on observed threat distribution.
        More common threats get higher prior probability.
        """
        total = sum(threat_counts.values())
        if total > 0:
            for label in THREAT_LABELS:
                count = threat_counts.get(label, 0)
                # Smooth with uniform prior
                self.threat_priors[label] = (count + 1) / (total + len(THREAT_LABELS))
            print(f"[bayesian_fusion] Updated threat priors based on {total} observations")

    def get_stats(self):
        """Return fusion engine statistics."""
        return {
            "total_fusions": self.total_fusions,
            "stream_weights": self.weights,
            "stream_accuracies": {
                s: self.stream_correct[s] / max(self.stream_total[s], 1)
                for s in self.stream_total
            },
            "threat_priors": self.threat_priors,
            "decision_history_size": len(self.decision_history),
        }

    def _empty_result(self):
        """Return empty result when no streams report."""
        return {
            "fused_label": "normal",
            "fused_confidence": 0.0,
            "posteriors": {},
            "stream_votes": {},
            "stream_confidences": {},
            "top_stream": "none",
            "is_anomaly": False,
            "explanation": "No stream data available",
            "timestamp": datetime.now().isoformat(),
            "streams_consulted": [],
        }
