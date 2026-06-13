"""
Agent-26: OnlineModelUpdater
Role: Retrain RandomForest from feedback data + existing training packets.
      Shadow-tests candidate model before promoting to best_model.pkl.
Runs as a background process; does NOT interrupt the detection pipeline.
"""
from __future__ import annotations

import json
import os
import threading
import time
from agents._timeutil import utcnow
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from agents.base_agent import FEATURE_NAMES

MODEL_DIR = "data/models"
CANDIDATE_PREFIX = "candidate_model"
BEST_MODEL = "data/models/best_model.pkl"
PACKETS_DIR = "data/packets"
UPDATE_INTERVAL_SECS = 21600   # 6 hours
SHADOW_PACKETS = 1000
F1_IMPROVEMENT_THRESHOLD = 0.01


class OnlineModelUpdater:
    agent_id = "agent-26-online-model-updater"

    def __init__(self):
        self._lock = threading.Lock()
        self._shadow_scores: List[float] = []
        self._production_scores: List[float] = []
        self._last_update = time.time()
        self._candidate: Optional[dict] = None

    def trigger(self, feedback_batch: List[Dict[str, Any]]) -> None:
        """Called by FeedbackCollector when a batch is ready."""
        threading.Thread(target=self._retrain, args=(feedback_batch,), daemon=True).start()

    def _retrain(self, feedback_batch: List[Dict[str, Any]]) -> None:
        with self._lock:
            print(f"[{self.agent_id}] Starting retraining with {len(feedback_batch)} feedback events")
            df_train = self._load_training_data()
            if df_train is None or len(df_train) < 100:
                return

            df_feedback = self._feedback_to_df(feedback_batch)
            if df_feedback is not None and len(df_feedback) > 0:
                df_train = pd.concat([df_train, df_feedback], ignore_index=True)

            X = df_train[FEATURE_NAMES].values
            y = df_train["label"].values

            # Determine n_estimators — increment current model's if available
            n_estimators = self._get_current_n_estimators() + 20
            n_estimators = min(n_estimators, 300)

            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            clf = RandomForestClassifier(
                n_estimators=n_estimators, max_depth=15,
                min_samples_split=5, class_weight="balanced",
                random_state=42, n_jobs=-1,
            )
            clf.fit(X_scaled, y)

            ts = utcnow().strftime("%Y%m%d_%H%M%S_%f")
            path = os.path.join(MODEL_DIR, f"{CANDIDATE_PREFIX}_{ts}.pkl")
            bundle = {"model": clf, "scaler": scaler, "features": FEATURE_NAMES}
            joblib.dump(bundle, path)

            self._candidate = {"path": path, "bundle": bundle}
            print(f"[{self.agent_id}] Candidate model saved: {path}")

    def shadow_evaluate(self, feature_vector: list, true_label: int) -> None:
        """Record shadow and production scores for comparison."""
        if self._candidate is None:
            return
        try:
            clf = self._candidate["bundle"]["model"]
            scaler = self._candidate["bundle"]["scaler"]
            X = scaler.transform([feature_vector])
            prob = clf.predict_proba(X)[0][1]
            pred = int(prob >= 0.5)
            self._shadow_scores.append(float(pred == true_label))
            if len(self._shadow_scores) >= SHADOW_PACKETS:
                self._maybe_promote()
        except Exception:
            pass

    def _maybe_promote(self) -> None:
        if not self._candidate:
            return
        shadow_acc = sum(self._shadow_scores) / len(self._shadow_scores)
        prod_acc = sum(self._production_scores) / len(self._production_scores) if self._production_scores else 0.0

        if shadow_acc > prod_acc + F1_IMPROVEMENT_THRESHOLD:
            dest = BEST_MODEL
            os.replace(self._candidate["path"], dest)
            print(f"[{self.agent_id}] Candidate promoted to {dest} (shadow_acc={shadow_acc:.4f} > prod={prod_acc:.4f})")
            self._candidate = None
            self._shadow_scores.clear()
            self._production_scores.clear()
        else:
            print(f"[{self.agent_id}] Candidate NOT promoted (shadow={shadow_acc:.4f}, prod={prod_acc:.4f})")

    def _load_training_data(self) -> Optional[pd.DataFrame]:
        try:
            files = sorted([
                os.path.join(PACKETS_DIR, f)
                for f in os.listdir(PACKETS_DIR)
                if f.endswith(".csv")
            ])
            if not files:
                return None
            dfs = [pd.read_csv(f) for f in files[-3:]]  # last 3 cycle files
            return pd.concat(dfs, ignore_index=True)
        except Exception:
            return None

    def _feedback_to_df(self, feedback: List[Dict]) -> Optional[pd.DataFrame]:
        rows = []
        for fb in feedback:
            feats = fb.get("packet_features", {})
            if not feats:
                continue
            row = {name: feats.get(name, 0.0) for name in FEATURE_NAMES}
            if fb["feedback_type"] == "false_positive":
                row["label"] = 0
            elif fb["feedback_type"] == "true_positive":
                row["label"] = 1
            else:
                continue
            rows.append(row)
        if not rows:
            return None
        return pd.DataFrame(rows)

    def _get_current_n_estimators(self) -> int:
        if not os.path.exists(BEST_MODEL):
            return 100
        try:
            bundle = joblib.load(BEST_MODEL)
            clf = bundle.get("model") if isinstance(bundle, dict) else bundle
            return clf.n_estimators
        except Exception:
            return 100
