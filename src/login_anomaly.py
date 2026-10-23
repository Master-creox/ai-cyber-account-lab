"""Login risk scoring — rule-based starter for AI anomaly detection.

A baseline describes what 'normal' looks like for an account. A new login is
scored by how far it differs. Roadmap: replace/augment these rules with a
model (e.g. Isolation Forest) trained on synthetic login data.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LoginEvent:
    country: str
    device: str
    hour: int  # 0-23, local time of the account owner


@dataclass
class AccountBaseline:
    usual_countries: set[str]
    usual_devices: set[str]
    usual_start_hour: int = 6
    usual_end_hour: int = 23


@dataclass
class LoginAssessment:
    risk_score: int
    reasons: list[str] = field(default_factory=list)

    @property
    def is_anomalous(self) -> bool:
        return self.risk_score >= 2


def assess_login(event: LoginEvent, baseline: AccountBaseline) -> LoginAssessment:
    reasons: list[str] = []
    score = 0

    if event.country not in baseline.usual_countries:
        score += 2
        reasons.append(f"Login from an unusual country: {event.country}.")
    if event.device not in baseline.usual_devices:
        score += 1
        reasons.append(f"Login from an unrecognised device: {event.device}.")
    if not (baseline.usual_start_hour <= event.hour <= baseline.usual_end_hour):
        score += 1
        reasons.append(f"Login at an unusual hour: {event.hour}:00.")

    return LoginAssessment(risk_score=score, reasons=reasons)
