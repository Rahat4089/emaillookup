#!/usr/bin/env python3
"""Run the reversed login flow implemented in logic.js.

The network/login logic intentionally lives in logic.js. This Python file is a
small test wrapper that supplies inputs and prints the redacted JSON result.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
LOGIC_JS = ROOT / "logic.js"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Test the login API flow from logic.js")
    parser.add_argument("--origin", default=os.environ.get("LOGIN_ORIGIN", "https://cawabanga.com"))
    parser.add_argument("--api-path", default=os.environ.get("LOGIN_API_PATH", "/api/v1"))
    parser.add_argument("--transport", default=os.environ.get("LOGIN_TRANSPORT", "socket"))
    parser.add_argument("--language", default=os.environ.get("LOGIN_LANGUAGE", "en"))
    parser.add_argument("--socket-url", default=os.environ.get("LOGIN_SOCKET_URL"))
    parser.add_argument("--socket-timeout-ms", default=os.environ.get("LOGIN_SOCKET_TIMEOUT_MS", "15000"))
    parser.add_argument("--country-code", default=os.environ.get("LOGIN_COUNTRY_CODE", "BN"))
    parser.add_argument("--type", default=os.environ.get("LOGIN_TYPE", "email"))
    parser.add_argument("--email", default=os.environ.get("LOGIN_EMAIL") or os.environ.get("LOGIN_USER"))
    parser.add_argument("--password", default=os.environ.get("LOGIN_PASSWORD"))
    parser.add_argument("--fingerprint", default=os.environ.get("LOGIN_FINGERPRINT"))
    parser.add_argument("--user-agent", default=os.environ.get("LOGIN_USER_AGENT"))
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not args.email or not args.password:
        print(
            "Missing credentials. Provide --email/--password or set LOGIN_EMAIL and LOGIN_PASSWORD.",
            file=sys.stderr,
        )
        return 1

    env = os.environ.copy()
    env["LOGIN_EMAIL"] = args.email
    env["LOGIN_PASSWORD"] = args.password

    command = [
        "node",
        str(LOGIC_JS),
        "--login-test",
        "--origin",
        args.origin,
        "--api-path",
        args.api_path,
        "--transport",
        args.transport,
        "--language",
        args.language,
        "--socket-timeout-ms",
        str(args.socket_timeout_ms),
        "--country-code",
        args.country_code,
        "--type",
        args.type,
    ]
    if args.fingerprint:
        command.extend(["--fingerprint", args.fingerprint])
    if args.socket_url:
        command.extend(["--socket-url", args.socket_url])
    if args.user_agent:
        command.extend(["--user-agent", args.user_agent])

    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    output = completed.stdout.strip() or completed.stderr.strip()
    try:
        print(json.dumps(json.loads(output), indent=2, sort_keys=True))
    except json.JSONDecodeError:
        print(output)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
