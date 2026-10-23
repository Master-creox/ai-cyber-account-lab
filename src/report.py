"""Unified, explainable account-security report."""
from __future__ import annotations

from .account_safety import build_checklist
from .ai_anomaly import LoginRecord, train_default_detector
from .breach_pattern import is_common_password
from .login_anomaly import AccountBaseline, LoginEvent, assess_login
from .password_strength import assess_password
from .phishing_detector import assess_url


def run_all_checks(sample_password: str, url: str, country: str,
                   device: str, hour: int, failed_attempts: int = 0) -> dict:
    """Run every lab check on *sample* inputs and return an explainable report.

    Use sample passwords only — never type a real password into a demo tool.
    """
    password_result = assess_password(sample_password)
    url_result = assess_url(url)
    baseline = AccountBaseline(usual_countries={"IN"},
                               usual_devices={"Android phone", "Windows laptop"})
    login_result = assess_login(LoginEvent(country=country, device=device, hour=hour), baseline)
    detector = train_default_detector()
    ai_result = detector.assess(LoginRecord(country=country, device=device,
                                            hour=hour, failed_attempts=failed_attempts))
    overall = "HIGH RISK" if (url_result.is_suspicious or ai_result.is_anomalous
                              or password_result.score <= 1) else \
              "REVIEW" if login_result.is_anomalous else "OK"
    return {
        "overall": overall,
        "password": {"score": password_result.score, "label": password_result.label,
                     "is_common": is_common_password(sample_password),
                     "feedback": password_result.feedback},
        "url": {"risk_score": url_result.risk_score, "is_suspicious": url_result.is_suspicious,
                "reasons": url_result.reasons},
        "login_rules": {"risk_score": login_result.risk_score,
                        "is_anomalous": login_result.is_anomalous,
                        "reasons": login_result.reasons},
        "login_ai": {"score": ai_result.score, "is_anomalous": ai_result.is_anomalous,
                     "reasons": ai_result.reasons},
        "hardening_actions": build_checklist(has_2fa=False,
                                             uses_password_manager=False,
                                             recovery_up_to_date=False),
    }


def format_report(report: dict) -> str:
    lines = [f"Overall: {report['overall']}", ""]
    p = report["password"]
    lines.append(f"Password (sample): {p['label']} ({p['score']}/4)"
                 + (" — known common password!" if p["is_common"] else ""))
    lines += [f"  - {item}" for item in p["feedback"]]
    u = report["url"]
    lines.append(f"URL: risk {u['risk_score']}" + (" — suspicious" if u["is_suspicious"] else ""))
    lines += [f"  - {item}" for item in u["reasons"]] or ["  - No risk signals found."]
    ai = report["login_ai"]
    lines.append(f"Login (AI model): score {ai['score']}" + (" — anomalous" if ai["is_anomalous"] else ""))
    lines += [f"  - {item}" for item in ai["reasons"]] or ["  - Matches the usual profile."]
    lines.append("Hardening actions:")
    lines += [f"  - {item}" for item in report["hardening_actions"]]
    return "\n".join(lines)
