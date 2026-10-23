# AI Cyber Account Lab

AI + Cybersecurity lab to protect account security — detecting suspicious logins, weak passwords, and phishing risks.

> Defensive, educational project. It helps users and developers protect accounts. It does not collect, store, or transmit real passwords or private account data.

## Why this project?

Most account takeovers start with simple weaknesses: reused or weak passwords, phishing links, missing two-factor authentication (2FA), and logins that do not look like the account owner. This lab combines classic cybersecurity rules with machine-learning ideas to spot those risks early.

## Features (starter)

- **Password strength analysis** — length, character variety, and common-pattern checks with clear feedback. Passwords are assessed locally and never stored.
- **Login anomaly detection** — flags unusual login time, device, or location compared with a simple baseline. Roadmap: train an anomaly model (e.g. Isolation Forest) on synthetic login data.
- **Phishing risk checks** — heuristic checks for suspicious URLs, such as look-alike domains, IP-address links, and excessive subdomains.
- **Account safety guidance** — a practical checklist for 2FA, recovery options, and session hygiene.

## Project structure

```
.
├── docs/
│   ├── account-security-checklist.md
│   └── threat-model.md
├── src/
│   ├── __init__.py
│   ├── account_safety.py
│   ├── login_anomaly.py
│   ├── password_strength.py
│   └── phishing_detector.py
├── tests/
│   ├── test_password_strength.py
│   └── test_phishing_detector.py
├── requirements.txt
└── README.md
```

## Quick start

```bash
git clone https://github.com/Master-creox/ai-cyber-account-lab.git
cd ai-cyber-account-lab
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
pytest
```

Try the password checker:

```python
from src.password_strength import assess_password

result = assess_password("Correct horse battery staple 42!")
print(result.score, result.label)
print(result.feedback)
```

## Roadmap

- [x] Starter structure, password strength, phishing heuristics, login-risk rules
- [ ] Synthetic login dataset + AI anomaly-detection model
- [ ] Password breach-pattern checks using privacy-preserving (hashed) techniques
- [ ] Simple dashboard / CLI to run all account checks together
- [ ] Reports that explain *why* a login or link was flagged

## Safety & ethics

- Use only on accounts and systems you own or have permission to test.
- Never enter real passwords into demos you do not trust — use sample passwords.
- This project is for defence and learning, not for accessing anyone else's account.

## License

MIT — see [LICENSE](LICENSE).

## Author

Akash Kumar (Master-creox) — BCA Cybersecurity student, interested in AI, cybersecurity, and real-world problem solving.
