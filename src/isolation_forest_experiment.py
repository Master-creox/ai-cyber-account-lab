"""Isolation Forest experiment (scikit-learn) — optional ML comparison.

The core lab (src/ai_anomaly.py) uses a statistical detector with no
third-party dependencies. This module experiments with scikit-learn's
IsolationForest on the *same* features and the *same* synthetic dataset,
so the two approaches can be compared fairly.

Install the extra dependency and run:

    pip install -r requirements-ml.txt
    python scripts/run_isolation_forest.py

Why Isolation Forest? It isolates observations by randomly partitioning
the feature space. Anomalies need fewer partitions to isolate, so they
score as more anomalous — a good fit for login anomaly detection, where
labelled attack data is rare and we mostly have "normal" examples.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .ai_anomaly import (FEATURE_REASONS, LoginRecord, featurize,
                         generate_synthetic_logins)

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on environment
    IsolationForest = None
    SKLEARN_AVAILABLE = False


def require_sklearn() -> None:
    if not SKLEARN_AVAILABLE:
        raise ImportError(
            "scikit-learn is not installed. Run: pip install -r requirements-ml.txt"
        )


@dataclass
class IsolationForestAssessment:
    score: float  # higher = more anomalous (negated decision function)
    is_anomalous: bool
    reasons: list[str] = field(default_factory=list)


class IsolationForestDetector:
    """Isolation Forest fitted on normal logins only, like the baseline."""

    def __init__(self, contamination: float = 0.02, n_estimators: int = 200,
                 random_state: int = 42):
        require_sklearn()
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
        )
        self._fitted = False

    def fit(self, normal_records: list[LoginRecord]) -> "IsolationForestDetector":
        if not normal_records:
            raise ValueError("Need at least one normal login to fit the model.")
        self.model.fit([featurize(r) for r in normal_records])
        self._fitted = True
        return self

    def assess(self, record: LoginRecord) -> IsolationForestAssessment:
        if not self._fitted:
            raise RuntimeError("Model is not fitted yet. Call fit() first.")
        features = featurize(record)
        # predict: 1 = normal, -1 = anomaly. decision_function: higher = more normal.
        prediction = int(self.model.predict([features])[0])
        score = float(-self.model.decision_function([features])[0])
        reasons = [reason for f, reason in zip(features, FEATURE_REASONS) if f >= 0.5]
        return IsolationForestAssessment(score=round(score, 3),
                                         is_anomalous=prediction == -1,
                                         reasons=reasons)


def _summarise(detector, labelled) -> dict:
    tp = fp = tn = fn = 0
    for record, is_bad in labelled:
        predicted = detector.assess(record).is_anomalous
        if predicted and is_bad: tp += 1
        elif predicted and not is_bad: fp += 1
        elif not predicted and not is_bad: tn += 1
        else: fn += 1
    total = tp + fp + tn + fn or 1
    detected = tp + fn or 1
    flagged = tp + fp or 1
    return {"total": total, "accuracy": round((tp + tn) / total, 3),
            "anomalies_detected": tp, "anomalies_missed": fn,
            "false_alarms": fp, "normal_correct": tn,
            "recall_on_anomalies": round(tp / detected, 3),
            "precision_on_flags": round(tp / flagged, 3)}


def run_experiment(seed: int = 42) -> dict:
    """Train both detectors on synthetic normal logins and compare them.

    The statistical detector is included so the experiment reports a fair,
    same-data comparison — not just the Isolation Forest in isolation.
    """
    require_sklearn()
    from .ai_anomaly import StatisticalAnomalyDetector

    labelled = generate_synthetic_logins(seed=seed)
    normal = [r for r, bad in labelled if not bad]

    statistical = StatisticalAnomalyDetector().fit(normal)
    forest = IsolationForestDetector().fit(normal)
    return {
        "dataset": {"total": len(labelled),
                    "normal": len(normal),
                    "anomalous": sum(1 for _, bad in labelled if bad),
                    "seed": seed},
        "statistical_detector": _summarise(statistical, labelled),
        "isolation_forest": _summarise(forest, labelled),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run_experiment(), indent=2))
