import io
import json
import unittest

from src.web_dashboard import application


def call_app(path="/", method="GET", body=b""):
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    environ = {"PATH_INFO": path, "REQUEST_METHOD": method,
               "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body)}
    response = b"".join(application(environ, start_response)).decode("utf-8")
    return captured["status"], response


class TestWebDashboard(unittest.TestCase):
    def test_home_page_shows_form(self):
        status, body = call_app("/")
        self.assertEqual(status, "200 OK")
        self.assertIn("Run all checks", body)

    def test_health_endpoint(self):
        status, body = call_app("/health")
        self.assertEqual(json.loads(body)["status"], "ok")

    def test_api_demo_returns_high_risk_report(self):
        status, body = call_app("/api/demo")
        data = json.loads(body)
        self.assertEqual(data["report"]["overall"], "HIGH RISK")
        self.assertGreater(data["model_evaluation"]["accuracy"], 0.8)

    def test_post_check_does_not_echo_password_and_escapes_input(self):
        payload = (b"sample_password=Sup3rSecretSample99&url="
                   b"https%3A%2F%2Fexample.com%2F%3Cscript%3Ealert(1)%3C%2Fscript%3E"
                   b"&country=IN&device=Android+phone&hour=11&failed_attempts=0")
        status, body = call_app("/check", method="POST", body=payload)
        self.assertEqual(status, "200 OK")
        self.assertNotIn("Sup3rSecretSample99", body)
        self.assertNotIn("<script>alert(1)</script>", body)

    def test_unknown_path_is_404(self):
        status, _ = call_app("/nope")
        self.assertTrue(status.startswith("404"))


if __name__ == "__main__":
    unittest.main()
