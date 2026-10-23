"""Account-safety guidance: build a personalised hardening checklist."""
from __future__ import annotations


def build_checklist(has_2fa: bool, uses_password_manager: bool,
                    recovery_up_to_date: bool) -> list[str]:
    actions: list[str] = []
    if not has_2fa:
        actions.append("Turn on 2FA, preferably with an authenticator app or security key.")
    if not uses_password_manager:
        actions.append("Use a password manager so every account gets a unique password.")
    if not recovery_up_to_date:
        actions.append("Update your recovery email/phone and save backup codes offline.")
    if not actions:
        actions.append("Basics are covered. Review logged-in devices and login alerts monthly.")
    return actions
