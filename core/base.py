#!/usr/bin/env python3
"""
ArgusML Base Stream Class
All detection streams inherit from this.
"""

import os
import time
import joblib
import numpy as np
import pandas as pd
from abc import ABC, abstractmethod
from datetime import datetime
from core.config import MODELS_DIR, CONFIDENCE_THRESHOLD, THREAT_LABELS


class BaseStream(ABC):
    """
    Base class for all ArgusML detection streams.
    Every stream must implement:
        - extract_features()
        - get_stream_name()
    """

    def __init__(self):
        self.model = None
        self.isolation_model = None
        self.label_encoder = None
        self._classes = None
        self.is_trained = False
        self.accuracy = 0.0
        self.f1_score = 0.0
        self.prediction_history = []
        self.confidence_history = []
        self.last_trained = None
        print(f"[{self.get_stream_name()}] Stream initialized")

    @abstractmethod
    def get_stream_name(self):
        """Return the name of this stream."""
        pass

    @abstractmethod
    def extract_features(self, raw_data):
        """
        Extract features from raw data.
        Must return a pandas DataFrame with consistent columns.
        """
        pass

    def predict(self, raw_data):
        """
        Run prediction on raw data.
        Returns list of dicts with label, confidence, explanation.
        """
        if not self.is_trained:
            print(f"[{self.get_stream_name()}] Model not trained yet")
            return []

        try:
            features_df = self.extract_features(raw_data)
            if features_df is None or features_df.empty:
                return []

            # Drop label column if present
            X = features_df.drop(columns=["label"], errors="ignore")
            X = X.fillna(0).astype(np.float32)

            # XGBoost prediction on GPU
            import xgboost as xgb
            X_gpu = xgb.DMatrix(X.to_numpy().astype(np.float32))
            raw_preds = self.model.predict(X_gpu)
            if raw_preds.ndim == 1:
                probs = np.column_stack([1 - raw_preds, raw_preds])
            else:
                probs = raw_preds
            labels = self._classes

            results = []
            for i, prob in enumerate(probs):
                max_idx = np.argmax(prob)
                confidence = float(prob[max_idx])
                label = labels[max_idx]

                # Isolation forest anomaly score
                anomaly_score = 0.0
                if self.isolation_model is not None:
                    anomaly_score = float(
                        -self.isolation_model.score_samples(
                            X.iloc[[i]].to_numpy()
                        )[0]
                    )

                # Only report if above threshold or anomaly detected
                if confidence >= CONFIDENCE_THRESHOLD:
                    result = {
                        "stream": self.get_stream_name(),
                        "label": label,
                        "confidence": confidence,
                        "anomaly_score": anomaly_score,
                        "explanation": self.explain(label, confidence, anomaly_score, X.iloc[i]),
                        "timestamp": datetime.now().isoformat(),
                        "is_anomaly": anomaly_score > 0.6 and label == "normal",
                    }
                    results.append(result)
                    self.prediction_history.append(result)
                    self.confidence_history.append(confidence)

            return results

        except Exception as e:
            print(f"[{self.get_stream_name()}] Prediction error: {e}")
            return []

    def explain(self, label, confidence, anomaly_score, feature_row):
        """
        Generate a human readable explanation of why this was flagged.
        This is what makes ArgusML better than theirs.
        """
        explanations = []

        if label != "normal":
            explanations.append(f"Detected {label} with {confidence:.1%} confidence")

        if anomaly_score > 0.6:
            explanations.append(f"Anomaly score {anomaly_score:.2f} indicates unusual behavior")

        # Feature based explanations
        if "syn_cnt" in feature_row.index and feature_row["syn_cnt"] > 100:
            explanations.append(f"High SYN count ({feature_row['syn_cnt']:.0f}) suggests port scan or SYN flood")

        if "fl_byt_s" in feature_row.index and feature_row["fl_byt_s"] > 1000000:
            explanations.append(f"High byte rate ({feature_row['fl_byt_s']:.0f} B/s) suggests data exfiltration or DDoS")

        if "down_up_ratio" in feature_row.index and feature_row["down_up_ratio"] > 10:
            explanations.append(f"High download/upload ratio ({feature_row['down_up_ratio']:.1f}) suggests C2 beaconing")

        return " | ".join(explanations) if explanations else f"Suspicious {label} activity detected"

    def train(self, X, y):
        """Train XGBoost and Isolation Forest models."""
        from xgboost import XGBClassifier
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import LabelEncoder
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, f1_score
        from core.config import XGBOOST_PARAMS, ISOLATION_FOREST_PARAMS

        print(f"[{self.get_stream_name()}] Training on {len(X)} samples...")

        # Encode labels
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)

        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42
        )

        # Train XGBoost on GPU using DMatrix
        import xgboost as xgb
        params = XGBOOST_PARAMS.copy()
        params["num_class"] = len(np.unique(y_encoded))
        X_train_np = X_train.to_numpy().astype(np.float32)
        X_test_np = X_test.to_numpy().astype(np.float32)
        dtrain = xgb.DMatrix(X_train_np, label=y_train)
        dtest = xgb.DMatrix(X_test_np, label=y_test)
        # Train using native API for full GPU support
        n_classes = len(np.unique(y_encoded))
        is_binary = n_classes == 2
        booster_params = {
            "device": "cuda",
            "tree_method": "hist",
            "max_depth": params.get("max_depth", 6),
            "learning_rate": params.get("learning_rate", 0.1),
            "objective": "binary:logistic" if is_binary else "multi:softprob",
            "eval_metric": "logloss" if is_binary else "mlogloss",
            "num_class": n_classes if not is_binary else None,
        }
        # Remove None values
        booster_params = {k: v for k, v in booster_params.items() if v is not None}
        booster = xgb.train(
            booster_params,
            dtrain,
            num_boost_round=params.get("n_estimators", 200),
            evals=[(dtest, "test")],
            verbose_eval=False,
        )
        self.model = booster
        self._classes = self.label_encoder.classes_
        self._classes = self.label_encoder.classes_

        # Evaluate using GPU DMatrix
        import xgboost as xgb
        dtest_eval = xgb.DMatrix(X_test.to_numpy().astype(np.float32))
        y_pred_raw = self.model.predict(dtest_eval)
        if y_pred_raw.ndim == 1:
            y_pred = (y_pred_raw > 0.5).astype(int)
        else:
            y_pred = y_pred_raw.argmax(axis=1).astype(int)
        y_test_arr = np.array(y_test).astype(int).flatten()
        self.accuracy = accuracy_score(y_test_arr, y_pred)
        self.f1_score = f1_score(y_test_arr, y_pred, average="macro", zero_division=0)

        print(f"[{self.get_stream_name()}] Accuracy: {self.accuracy:.4f} F1: {self.f1_score:.4f}")

        # Train Isolation Forest on normal data only
        normal_mask = y == "normal"
        if normal_mask.sum() > 10:
            self.isolation_model = IsolationForest(**ISOLATION_FOREST_PARAMS)
            self.isolation_model.fit(X[normal_mask].to_numpy().astype(np.float32))
            print(f"[{self.get_stream_name()}] Isolation Forest trained on {normal_mask.sum()} normal samples")

        self.is_trained = True
        self.last_trained = datetime.now()
        self.save_model()

    def save_model(self):
        """Save trained models to disk."""
        os.makedirs(MODELS_DIR, exist_ok=True)
        model_path = os.path.join(MODELS_DIR, f"{self.get_stream_name()}.joblib")
        joblib.dump({
            "model": self.model,
            "isolation_model": self.isolation_model,
            "label_encoder": self.label_encoder,
            "classes": self._classes,
            "accuracy": self.accuracy,
            "f1_score": self.f1_score,
            "last_trained": self.last_trained,
        }, model_path)
        print(f"[{self.get_stream_name()}] Model saved to {model_path}")

    def load_model(self):
        """Load trained models from disk."""
        model_path = os.path.join(MODELS_DIR, f"{self.get_stream_name()}.joblib")
        if os.path.exists(model_path):
            data = joblib.load(model_path)
            self.model = data["model"]
            self.isolation_model = data["isolation_model"]
            self.label_encoder = data["label_encoder"]
            self._classes = data.get("classes", self.label_encoder.classes_)
            self.accuracy = data["accuracy"]
            self.f1_score = data["f1_score"]
            self.last_trained = data["last_trained"]
            self.is_trained = True
            print(f"[{self.get_stream_name()}] Model loaded — accuracy: {self.accuracy:.4f}")
            return True
        return False

    def get_stats(self):
        """Return stream performance statistics."""
        return {
            "stream": self.get_stream_name(),
            "is_trained": self.is_trained,
            "accuracy": self.accuracy,
            "f1_score": self.f1_score,
            "last_trained": str(self.last_trained),
            "total_predictions": len(self.prediction_history),
            "avg_confidence": np.mean(self.confidence_history) if self.confidence_history else 0.0,
        }
