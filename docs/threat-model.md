# Threat Model (Starter)

## Assets we protect
- Account credentials and recovery methods
- Active login sessions
- Personal data linked to an account

## Common threats
| Threat | Example | Defence in this lab |
|---|---|---|
| Weak / reused passwords | Same password on many sites | Password strength analysis |
| Phishing | Fake login page with a look-alike domain | Phishing URL heuristics |
| Credential stuffing | Automated logins with leaked passwords | Login anomaly detection + 2FA guidance |
| Unusual access | Login from a new country/device at an odd hour | Login risk scoring |
| Weak recovery setup | Old phone number on the account | Account safety checklist |

## Out of scope
- Accessing, testing, or monitoring accounts without the owner's permission
- Storing real user passwords or credentials

## Design principles
1. **Privacy first** — assess locally, store nothing sensitive.
2. **Explainable** — every flag should say why it was raised.
3. **Defence in depth** — no single check is trusted on its own.
