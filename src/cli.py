"""Command-line interface for AI Cyber Account Lab.

Examples (use sample passwords only, never a real one in a demo):
    python main.py demo
    python main.py url https://github.com/Master-creox
    python main.py login --country RU --device "Unknown Linux" --hour 2 --failed-attempts 4
    python main.py analyze-csv data/sample_logins.csv
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


def load_logins_csv(path: str) -> list[tuple[LoginRecord, bool | None]]:
    """Load login records from a CSV file.

    Expected columns: country, device, hour, failed_attempts.
    An optional is_anomalous column (0/1) enables an accuracy summary.
    Raises ValueError with a friendly message on malformed rows.
    """
    rows: list[tuple[LoginRecord, bool | None]] = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        required = {"country", "device", "hour", "failed_attempts"}
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise ValueError(
                "CSV needs columns: country, device, hour, failed_attempts "
                f"(found: {reader.fieldnames or 'none'})"
            )
        for lineno, row in enumerate(reader, start=2):
            try:
                record = LoginRecord(
                    country=(row["country"] or "").strip(),
                    device=(row["device"] or "").strip(),
                    hour=int(row["hour"]),
                    failed_attempts=int(row["failed_attempts"]),
                )
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Line {lineno}: bad row {row!r}") from exc
            label = None
            if "is_anomalous" in reader.fieldnames and row.get("is_anomalous") not in (None, ""):
                label = row["is_anomalous"].strip() in ("1", "true", "True")
            rows.append((record, label))
    return rows


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

    p_csv = sub.add_parser("analyze-csv",
                           help="Score every login in a CSV file with the AI anomaly model.")
    p_csv.add_argument("path", help="CSV with columns: country, device, hour, failed_attempts "
                                    "(optional: is_anomalous for an accuracy summary).")

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
    elif args.command == "analyze-csv":
        try:
            rows = load_logins_csv(args.path)
        except (OSError, ValueError) as exc:
            print(f"Could not read CSV: {exc}")
            return 1
        if not rows:
            print("No login rows found in the CSV.")
            return 1
        detector = train_default_detector()
        flagged = 0
        labelled = [(record, label) for record, label in rows if label is not None]
        for i, (record, _label) in enumerate(rows, start=1):
            result = detector.assess(record)
            if result.is_anomalous:
                flagged += 1
            verdict = "ANOMALOUS" if result.is_anomalous else "normal"
            print(f"Row {i}: {record.country} / {record.device} / hour {record.hour} / "
                  f"failed {record.failed_attempts} -> score {result.score} ({verdict})")
            for item in result.reasons:
                print("   -", item)
        print(f"\nAnalysed {len(rows)} logins: {flagged} flagged anomalous, "
              f"{len(rows) - flagged} within the normal profile.")
        if labelled:
            summary = evaluate(detector, labelled)
            print(f"Labelled rows: {len(labelled)} — accuracy vs labels: {summary['accuracy']} "
                  f"(detected {summary['anomalies_detected']}/{summary['anomalies_detected'] + summary['anomalies_missed']} "
                  f"anomalies, {summary['false_alarms']} false alarms)")
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
