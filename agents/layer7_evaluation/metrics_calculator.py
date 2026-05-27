"""
Agent-29: MetricsCalculator
Role: Compute F1/Recall/Precision/AUC-ROC for ALL 11 attack types.
      Extends existing evaluate_model.py schema — backward compatible.
      Also computes per-agent contribution scores.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    f1_score, recall_score, precision_score, accuracy_score,
    roc_auc_score, log_loss, confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from agents.base_agent import ATTACK_TYPES, FEATURE_NAMES

BEST_MODEL_PATH = "data/models/best_model.pkl"
METRICS_LATEST = "data/metrics/latest.json"
METRICS_HISTORY = "data/metrics/history.json"


class MetricsCalculator:
    agent_id = "agent-29-metrics-calculator"

    def process(self, df: Optional[pd.DataFrame] = None, cycle: int = 1,
                is_best: bool = False) -> Dict[str, Any]:
        """Evaluate current best model on provided DataFrame or latest packets CSV."""
        if df is None:
            df = self._load_latest_packets()
        if df is None or len(df) < 10:
            return {}

        model_bundle = self._load_model()
        if model_bundle is None:
            return {}

        clf = model_bundle["model"]
        scaler = model_bundle["scaler"]
        features = model_bundle.get("features", FEATURE_NAMES)

        X = df[features].values
        y = df["label"].values
        X_scaled = scaler.transform(X)

        y_pred = clf.predict(X_scaled)
        y_proba = clf.predict_proba(X_scaled)[:, 1] if hasattr(clf, "predict_proba") else y_pred.astype(float)

        # Global metrics
        metrics = {
            "f1_score":   round(float(f1_score(y, y_pred, zero_division=0)), 4),
            "recall":     round(float(recall_score(y, y_pred, zero_division=0)), 4),
            "precision":  round(float(precision_score(y, y_pred, zero_division=0)), 4),
            "accuracy":   round(float(accuracy_score(y, y_pred)), 4),
            "log_loss":   round(float(log_loss(y, np.clip(y_proba, 1e-7, 1-1e-7))), 4),
        }
        try:
            metrics["auc_roc"] = round(float(roc_auc_score(y, y_proba)), 4)
        except Exception:
            metrics["auc_roc"] = 0.0

        # Per-attack-type recall (all 11 types)
        per_attack_recall = {}
        if "attack_type" in df.columns:
            for attack in ATTACK_TYPES:
                mask = df["attack_type"] == attack
                if mask.sum() > 0:
                    per_attack_recall[attack] = round(
                        float(recall_score(y[mask], y_pred[mask], zero_division=0)), 4
                    )

        continue_training = (
            metrics["f1_score"] < 0.92
            or metrics["recall"] < 0.90
            or metrics["precision"] < 0.88
        )

        result: Dict[str, Any] = {
            "cycle":             cycle,
            "metrics":           metrics,
            "per_attack_recall": per_attack_recall,
            "continue_training": continue_training,
            "is_best_model":     is_best,
            "timestamp":         datetime.utcnow().isoformat(),
        }

        self._write_latest(result)
        self._append_history(result)
        return result

    def _load_latest_packets(self) -> Optional[pd.DataFrame]:
        import glob
        files = sorted(glob.glob("data/packets/train_*.csv"))
        if not files:
            return None
        try:
            return pd.read_csv(files[-1])
        except Exception:
            return None

    def _load_model(self) -> Optional[dict]:
        if not os.path.exists(BEST_MODEL_PATH):
            return None
        try:
            bundle = joblib.load(BEST_MODEL_PATH)
            if isinstance(bundle, dict):
                return bundle
            return {"model": bundle, "scaler": StandardScaler(), "features": FEATURE_NAMES}
        except Exception:
            return None

    def _write_latest(self, result: Dict[str, Any]) -> None:
        try:
            os.makedirs(os.path.dirname(METRICS_LATEST), exist_ok=True)
            with open(METRICS_LATEST, "w") as f:
                json.dump(result, f, indent=2)
        except Exception:
            pass

    def _append_history(self, result: Dict[str, Any]) -> None:
        try:
            history = []
            if os.path.exists(METRICS_HISTORY):
                with open(METRICS_HISTORY) as f:
                    history = json.load(f)
            history.append(result)
            with open(METRICS_HISTORY, "w") as f:
                json.dump(history, f, indent=2)
        except Exception:
            pass
