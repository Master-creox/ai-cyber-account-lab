"""Command-line interface for AI Cyber Account Lab.

Examples (use sample passwords only, never a real one in a demo):
    python main.py demo
    python main.py url https://github.com/Master-creox
    python main.py login --country RU --device "Unknown Linux" --hour 2 --failed-attempts 4
    python main.py dataset --output data/sample_logins.csv
"""
from __future__ import annotations

import argparse
import csv
import getpass

from .ai_anomaly import LoginRecord, evaluate, generate_synthetic_logins, train_default_detector
from .password_strength import assess_password
from .phishing_detector import assess_url
from .report import format_report, run_all_checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ai-cyber-account-lab",
                                     description="Defensive account-security lab (educational).")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="Run all checks on built-in sample data and evaluate the AI model.")

    p_pw = sub.add_parser("password", help="Assess a sample password (prompted, not echoed).")
    p_pw.add_argument("--password", default=None,
                      help="Sample password. If omitted you will be prompted without echo.")

    p_url = sub.add_parser("url", help="Assess a URL for phishing risk signals.")
    p_url.add_argument("url")

    p_login = sub.add_parser("login", help="Score a login with the AI anomaly model.")
    p_login.add_argument("--country", required=True)
    p_login.add_argument("--device", required=True)
    p_login.add_argument("--hour", type=int, required=True)
    p_login.add_argument("--failed-attempts", type=int, default=0)

    p_data = sub.add_parser("dataset", help="Write the synthetic login dataset to CSV.")
    p_data.add_argument("--output", default="data/sample_logins.csv")
    p_data.add_argument("--normal", type=int, default=200)
    p_data.add_argument("--anomalous", type=int, default=30)

    args = parser.parse_args(argv)

    if args.command == "demo":
        report = run_all_checks("password", "http://192.168.1.10/login@secure-verify-account.example.com",
                                country="RU", device="Unknown Linux", hour=2, failed_attempts=4)
        print(format_report(report))
        data = generate_synthetic_logins()
        detector = train_default_detector()
        print("\nAI model evaluation on synthetic data:", evaluate(detector, data))
    elif args.command == "password":
        sample = args.password if args.password is not None else getpass.getpass("Sample password: ")
        result = assess_password(sample)
        print(f"{result.label} ({result.score}/4)")
        for item in result.feedback:
            print(" -", item)
    elif args.command == "url":
        result = assess_url(args.url)
        print(f"Risk score: {result.risk_score} — " + ("suspicious" if result.is_suspicious else "no strong signals"))
        for item in result.reasons:
            print(" -", item)
    elif args.command == "login":
        detector = train_default_detector()
        result = detector.assess(LoginRecord(args.country, args.device, args.hour, args.failed_attempts))
        print(f"AI anomaly score: {result.score} — " + ("ANOMALOUS" if result.is_anomalous else "normal profile"))
        for item in result.reasons:
            print(" -", item)
    elif args.command == "dataset":
        rows = generate_synthetic_logins(args.normal, args.anomalous)
        with open(args.output, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["country", "device", "hour", "failed_attempts", "is_anomalous"])
            for record, bad in rows:
                writer.writerow([record.country, record.device, record.hour,
                                 record.failed_attempts, int(bad)])
        print(f"Wrote {len(rows)} synthetic rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
