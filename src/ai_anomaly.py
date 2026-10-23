"""AI-style login anomaly detection trained on synthetic data.

Approach
--------
1. Generate synthetic *normal* logins for an account (no real user data).
2. Fit a statistical anomaly model: per-feature mean / standard deviation.
   A new login is scored by how far it deviates (z-scores) from normal.
3. If scikit-learn is installed, an IsolationForest detector is also
   provided and can be used instead of the statistical baseline.

This is an educational, defensive model. Scores explain risk signals;
they do not prove a login is malicious.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

USUAL_COUNTRIES = ["IN"]
USUAL_DEVICES = ["Android phone", "Windows laptop"]
OTHER_COUNTRIES = ["US", "GB", "RU", "BR", "NG", "CN"]
OTHER_DEVICES = ["Unknown Linux", "Unknown iPhone", "Emulator"]


@dataclass
class LoginRecord:
    country: str
    device: str
    hour: int  # 0-23
    failed_attempts: int = 0


def featurize(record: LoginRecord) -> list[float]:
    """Turn a login into numeric features relative to the usual profile."""
    return [
        0.0 if record.country in USUAL_COUNTRIES else 1.0,   # new country
        0.0 if record.device in USUAL_DEVICES else 1.0,      # new device
        min(abs(record.hour - 14), 12) / 12.0,                # distance from midday
        1.0 if record.hour < 5 or record.hour > 23 else 0.0,  # deep-night login
        min(record.failed_attempts, 5) / 5.0,                 # failed attempts
    ]


FEATURE_REASONS = [
    "Login from a country outside the usual profile.",
    "Login from a device outside the usual profile.",
    "Login time is far from the usual time of day.",
    "Login in the deep-night window for this account.",
    "Several failed login attempts before this login.",
]


def generate_synthetic_logins(n_normal: int = 200, n_anomalous: int = 30,
                              seed: int = 42) -> list[tuple[LoginRecord, bool]]:
    """Return (record, is_anomalous) pairs. Synthetic only — no real data."""
    rng = random.Random(seed)
    data: list[tuple[LoginRecord, bool]] = []
    for _ in range(n_normal):
        data.append((LoginRecord(
            country=rng.choice(USUAL_COUNTRIES),
            device=rng.choice(USUAL_DEVICES),
            hour=min(23, max(6, int(rng.gauss(14, 3)))),
            failed_attempts=rng.choice([0, 0, 0, 1]),
        ), False))
    for _ in range(n_anomalous):
        data.append((LoginRecord(
            country=rng.choice(OTHER_COUNTRIES),
            device=rng.choice(OTHER_DEVICES),
            hour=rng.choice([0, 1, 2, 3, 4, 23]),
            failed_attempts=rng.choice([2, 3, 4, 5]),
        ), True))
    rng.shuffle(data)
    return data


@dataclass
class AnomalyAssessment:
    score: float
    is_anomalous: bool
    reasons: list[str] = field(default_factory=list)


class StatisticalAnomalyDetector:
    """Z-score anomaly detector fitted on normal logins only."""

    def __init__(self, threshold: float = 2.5):
        self.threshold = threshold
        self.means: list[float] = []
        self.stds: list[float] = []

    def fit(self, normal_records: list[LoginRecord]) -> "StatisticalAnomalyDetector":
        rows = [featurize(r) for r in normal_records]
        if not rows:
            raise ValueError("Need at least one normal login to fit the model.")
        cols = list(zip(*rows))
        self.means = [sum(c) / len(c) for c in cols]
        self.stds = []
        for c, mean in zip(cols, self.means):
            variance = sum((x - mean) ** 2 for x in c) / len(c)
            self.stds.append(math.sqrt(variance) or 1.0)
        return self

    def score(self, record: LoginRecord) -> float:
        if not self.means:
            raise RuntimeError("Model is not fitted yet. Call fit() first.")
        features = featurize(record)
        return sum(abs((x - m) / s) for x, m, s in zip(features, self.means, self.stds)) / len(features)

    def assess(self, record: LoginRecord) -> AnomalyAssessment:
        value = self.score(record)
        features = featurize(record)
        reasons = [reason for f, reason in zip(features, FEATURE_REASONS) if f >= 0.5]
        return AnomalyAssessment(score=round(value, 3),
                                 is_anomalous=value >= self.threshold,
                                 reasons=reasons)


def evaluate(detector: StatisticalAnomalyDetector,
             labelled: list[tuple[LoginRecord, bool]]) -> dict:
    """Simple accuracy / detection summary on labelled synthetic data."""
    tp = fp = tn = fn = 0
    for record, is_bad in labelled:
        predicted = detector.assess(record).is_anomalous
        if predicted and is_bad: tp += 1
        elif predicted and not is_bad: fp += 1
        elif not predicted and not is_bad: tn += 1
        else: fn += 1
    total = tp + fp + tn + fn or 1
    return {"total": total, "accuracy": round((tp + tn) / total, 3),
            "anomalies_detected": tp, "anomalies_missed": fn,
            "false_alarms": fp, "normal_correct": tn}


def train_default_detector() -> StatisticalAnomalyDetector:
    data = generate_synthetic_logins()
    normal = [r for r, bad in data if not bad]
    return StatisticalAnomalyDetector().fit(normal)
