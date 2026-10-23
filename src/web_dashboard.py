"""Web dashboard for AI Cyber Account Lab.

Built only on the Python standard library (WSGI), so it runs anywhere with
no extra installs:

    python dashboard.py
    # then open http://127.0.0.1:8000

Privacy & safety:
- Sample passwords are assessed in memory only and are never stored,
  logged, or echoed back in the response.
- All user input shown in HTML is escaped.
- Bind to localhost by default; do not expose this demo to the internet
  without adding real authentication, HTTPS, and rate limiting.
"""
from __future__ import annotations

import html
import json
from urllib.parse import parse_qs

from .ai_anomaly import evaluate, generate_synthetic_logins, train_default_detector
from .report import run_all_checks

CSS = """
body{font-family:system-ui,Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0}
main{max-width:860px;margin:0 auto;padding:32px 20px}
h1{font-size:28px;margin-bottom:4px}.sub{color:#8b949e}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin:16px 0}
label{display:block;margin:12px 0 6px;font-weight:600}
input,select{width:100%;padding:10px;border-radius:8px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;box-sizing:border-box}
button{background:#238636;color:#fff;border:0;padding:12px 18px;border-radius:8px;font-weight:700;cursor:pointer;margin-top:16px}
.badge{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:700}
.high{background:#da3633}.review{background:#9e6a03}.ok{background:#238636}
ul{margin:8px 0}.warn{color:#f0883e}
a{color:#58a6ff}
"""

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Cyber Account Lab — Dashboard</title><style>{css}</style></head>
<body><main>
<h1>🛡️ AI Cyber Account Lab</h1>
<p class="sub">Defensive account-security checks: password strength, phishing URL risk,
and an AI login anomaly model. Educational demo — use <b>sample</b> passwords only,
never a real one.</p>
<div class="card"><h2>Run all checks</h2>
<form method="post" action="/check">
<label>Sample password</label>
<input type="password" name="sample_password" autocomplete="off" placeholder="e.g. password (sample only)">
<label>URL to check</label>
<input type="text" name="url" placeholder="https://github.com/Master-creox">
<label>Login country (code)</label>
<input type="text" name="country" value="IN">
<label>Login device</label>
<input type="text" name="device" value="Android phone">
<label>Login hour (0–23)</label>
<input type="number" name="hour" min="0" max="23" value="11">
<label>Failed attempts before this login</label>
<input type="number" name="failed_attempts" min="0" max="20" value="0">
<button type="submit">Check security</button>
</form></div>
<div class="card"><h2>AI model</h2>
<p>Trained on synthetic logins only. Evaluation on the synthetic set:</p>
<p><b>{evaluation}</b></p>
<p><a href="/api/demo">/api/demo</a> · <a href="/health">/health</a></p>
</div>
{result}
</main></body></html>"""


def _evaluation_text() -> str:
    summary = evaluate(train_default_detector(), generate_synthetic_logins())
    return (f"Accuracy {summary['accuracy']:.1%} · "
            f"Anomalies detected {summary['anomalies_detected']} · "
            f"False alarms {summary['false_alarms']}")


def _result_html(report: dict) -> str:
    badge_class = {"HIGH RISK": "high", "REVIEW": "review", "OK": "ok"}[report["overall"]]
    def items(values):
        return "".join(f"<li>{html.escape(str(v))}</li>" for v in values) or "<li>None</li>"
    p, u, ai = report["password"], report["url"], report["login_ai"]
    return f"""<div class="card"><h2>Result: <span class="badge {badge_class}">{html.escape(report['overall'])}</span></h2>
<h3>Password (sample)</h3><p>{html.escape(p['label'])} ({p['score']}/4){" — known common password!" if p['is_common'] else ""}</p><ul>{items(p['feedback'])}</ul>
<h3>URL risk: {u['risk_score']}</h3><ul>{items(u['reasons'])}</ul>
<h3>Login — AI anomaly score: {ai['score']}</h3><ul>{items(ai['reasons'])}</ul>
<h3>Hardening actions</h3><ul>{items(report['hardening_actions'])}</ul></div>"""


def _parse_form(environ) -> dict:
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    body = environ["wsgi.input"].read(length).decode("utf-8", "replace") if length else ""
    fields = {k: v[0] for k, v in parse_qs(body).items()}
    return fields


def _int_or_default(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")

    if path == "/health":
        start_response("200 OK", [("Content-Type", "application/json")])
        return [b'{"status": "ok"}']

    if path == "/api/demo":
        report = run_all_checks("password", "http://192.168.1.10/login@secure-verify-account.example.com",
                                country="RU", device="Unknown Linux", hour=2, failed_attempts=4)
        payload = {"report": report,
                   "model_evaluation": evaluate(train_default_detector(), generate_synthetic_logins())}
        start_response("200 OK", [("Content-Type", "application/json")])
        return [json.dumps(payload, indent=2).encode("utf-8")]

    result_html = ""
    if path == "/check" and method == "POST":
        fields = _parse_form(environ)
        report = run_all_checks(
            fields.get("sample_password", ""),
            fields.get("url", ""),
            country=(fields.get("country") or "IN").upper(),
            device=fields.get("device") or "Android phone",
            hour=_int_or_default(fields.get("hour"), 11),
            failed_attempts=_int_or_default(fields.get("failed_attempts"), 0),
        )
        result_html = _result_html(report)
    elif path not in ("/", "/check"):
        start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
        return [b"Not found"]

    page = PAGE.format(css=CSS, evaluation=html.escape(_evaluation_text()), result=result_html)
    start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
    return [page.encode("utf-8")]


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    from wsgiref.simple_server import make_server
    print(f"AI Cyber Account Lab dashboard: http://{host}:{port}")
    with make_server(host, port, application) as server:
        server.serve_forever()


if __name__ == "__main__":
    run()
