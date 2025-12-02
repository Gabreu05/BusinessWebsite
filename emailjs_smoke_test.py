#!/usr/bin/env python3
"""Standalone EmailJS smoke-test script using this project's configuration."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Tuple

import requests


EMAILJS_ENDPOINT = "https://api.emailjs.com/api/v1.0/email/send"
REQUIRED_KEYS = (
    "EMAILJS_SERVICE_ID",
    "EMAILJS_TEMPLATE_ID",
    "EMAILJS_PUBLIC_KEY",
)


def load_emailjs_config() -> Tuple[dict, list]:
    """Load EmailJS credentials from environment."""
    config = {key: os.environ.get(key) for key in REQUIRED_KEYS}
    missing = [key for key, value in config.items() if not value]
    return config, missing


def send_test_email(
    to_email: str,
    subject: str,
    message: str,
    recipient_name: str,
    config: dict,
) -> requests.Response:
    """Send a single EmailJS request using the provided configuration."""
    payload = {
        "service_id": config["EMAILJS_SERVICE_ID"],
        "template_id": config["EMAILJS_TEMPLATE_ID"],
        "user_id": config["EMAILJS_PUBLIC_KEY"],
        "template_params": {
            "to_email": "csi3@njit.edu",
            "subject": subject,
            "message": message,
            "name": recipient_name,
        },
    }
    headers = {
        "Content-Type": "application/json",
    }
    response = requests.post(
        EMAILJS_ENDPOINT,
        json=payload,
        headers=headers,
        timeout=10,
    )
    return response


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send a minimal EmailJS test message using environment configuration.",
    )
    parser.add_argument(
        "--to",
        dest="to_email",
        default="ga385@njit.edu",
        help="Recipient email address (ignored; hardcoded to ga385@njit.edu).",
    )
    parser.add_argument(
        "--name",
        dest="recipient_name",
        default="drivenbyfaith3d smoke test",
        help="Recipient name to populate the template name field (default: %(default)s).",
    )
    parser.add_argument(
        "--subject",
        default="EmailJS smoke test",
        help="Subject for the test message (default: %(default)s).",
    )
    parser.add_argument(
        "--body",
        default="This is a smoke test from emailjs_smoke_test.py.",
        help="Body for the test message (default: %(default)s).",
    )
    args = parser.parse_args()

    config, missing = load_emailjs_config()
    if missing:
        print(
            "Missing required EmailJS environment variables:",
            ", ".join(missing),
            file=sys.stderr,
        )
        return 1

    try:
        response = send_test_email(args.to_email, args.subject, args.body, args.recipient_name, config)
    except requests.RequestException as exc:
        print(f"EmailJS request error: {exc}", file=sys.stderr)
        return 2

    if response.status_code == 200:
        print("EmailJS request succeeded.")
        return 0

    print(
        f"EmailJS request failed with status {response.status_code}: "
        f"{json.dumps(response.json(), indent=2) if response.headers.get('Content-Type', '').startswith('application/json') else response.text}",
        file=sys.stderr,
    )
    return 3


if __name__ == "__main__":
    raise SystemExit(main())

