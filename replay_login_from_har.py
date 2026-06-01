#!/usr/bin/env python3
"""
Replay Proton login-related requests from a HAR capture.

This script:
1) asks for email/password (unless passed via args),
2) replays login-related HAR requests in sequence,
3) prints each response (status, headers, body).

Note:
Proton login uses SRP and cryptographic proofs. A plain password is usually
not sent directly in requests. Replaying old HAR payloads may fail if tokens
or proofs are expired.
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import requests


EMAIL_REGEX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

LOGIN_HINTS = (
    "/challenge/",
    "/api/account/v1/access/incoming",
    "/api/account/v1/access/outgoing",
    "/api/auth/",
    "/api/core/v4/auth",
    "/api/core/v4/auth/info",
    "/api/core/v4/auth/cookies",
    "/authorize?app=proton-vpn-browser-extension",
)

SKIP_HINTS = (
    "/assets/static/",
    "/api/data/v1/telemetry",
    "/api/feature/v2/frontend/client/metrics",
)

BLOCKED_HEADERS = {
    "host",
    "content-length",
    "connection",
    "accept-encoding",
    "cookie",
}


def load_har(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("log", {}).get("entries", [])


def detect_first_email(entries: list[dict[str, Any]]) -> str | None:
    for entry in entries:
        request = entry.get("request", {})
        url = request.get("url", "")
        match = EMAIL_REGEX.search(url)
        if match:
            return match.group(0)
        post_data = request.get("postData", {}) or {}
        text = post_data.get("text", "") or ""
        match = EMAIL_REGEX.search(text)
        if match:
            return match.group(0)
    return None


def is_login_related(url: str) -> bool:
    if any(skip in url for skip in SKIP_HINTS):
        return False
    return any(hint in url for hint in LOGIN_HINTS)


def filter_entries(entries: list[dict[str, Any]], mode: str) -> list[dict[str, Any]]:
    if mode == "all":
        return entries
    return [entry for entry in entries if is_login_related(entry.get("request", {}).get("url", ""))]


def sanitize_headers(headers: list[dict[str, str]]) -> dict[str, str]:
    clean: dict[str, str] = {}
    for item in headers:
        name = item.get("name", "")
        value = item.get("value", "")
        if not name or name.startswith(":"):
            continue
        if name.lower() in BLOCKED_HEADERS:
            continue
        clean[name] = value
    return clean


def replace_credentials_in_string(
    value: str,
    *,
    email: str,
    password: str,
    captured_email: str | None,
    captured_password: str | None,
) -> str:
    replacement_map = {
        captured_email: email,
        quote(captured_email or ""): quote(email),
        captured_password: password,
    }
    out = value
    for old, new in replacement_map.items():
        if old:
            out = out.replace(old, new)
    return out


def replace_credentials_in_json(
    value: Any,
    *,
    email: str,
    password: str,
    captured_email: str | None,
    captured_password: str | None,
) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, sub_value in value.items():
            lower_key = key.lower()
            if lower_key in {"username", "email", "login"} and isinstance(sub_value, str):
                out[key] = email
            elif lower_key in {"password", "pass", "passwd"} and isinstance(sub_value, str):
                out[key] = password
            else:
                out[key] = replace_credentials_in_json(
                    sub_value,
                    email=email,
                    password=password,
                    captured_email=captured_email,
                    captured_password=captured_password,
                )
        return out
    if isinstance(value, list):
        return [
            replace_credentials_in_json(
                item,
                email=email,
                password=password,
                captured_email=captured_email,
                captured_password=captured_password,
            )
            for item in value
        ]
    if isinstance(value, str):
        return replace_credentials_in_string(
            value,
            email=email,
            password=password,
            captured_email=captured_email,
            captured_password=captured_password,
        )
    return value


def build_body(
    post_data: dict[str, Any],
    *,
    email: str,
    password: str,
    captured_email: str | None,
    captured_password: str | None,
) -> str | bytes | None:
    if not post_data:
        return None

    mime = (post_data.get("mimeType", "") or "").lower()
    text = post_data.get("text", "")

    if "application/json" in mime and text:
        try:
            parsed = json.loads(text)
            replaced = replace_credentials_in_json(
                parsed,
                email=email,
                password=password,
                captured_email=captured_email,
                captured_password=captured_password,
            )
            return json.dumps(replaced, separators=(",", ":"))
        except json.JSONDecodeError:
            return replace_credentials_in_string(
                text,
                email=email,
                password=password,
                captured_email=captured_email,
                captured_password=captured_password,
            )

    if "application/x-www-form-urlencoded" in mime and post_data.get("params"):
        pairs = []
        for param in post_data.get("params", []):
            name = param.get("name", "")
            value = param.get("value", "")
            value = replace_credentials_in_string(
                value,
                email=email,
                password=password,
                captured_email=captured_email,
                captured_password=captured_password,
            )
            pairs.append(f"{quote(name)}={quote(value)}")
        return "&".join(pairs)

    if text:
        return replace_credentials_in_string(
            text,
            email=email,
            password=password,
            captured_email=captured_email,
            captured_password=captured_password,
        )

    return None


def print_response(response: requests.Response) -> None:
    print(f"Status: {response.status_code} {response.reason}")
    print("Response headers:")
    for name, value in response.headers.items():
        print(f"  {name}: {value}")
    print("Response body:")

    content_type = response.headers.get("content-type", "").lower()
    text = response.text
    if "application/json" in content_type:
        try:
            parsed = response.json()
            print(json.dumps(parsed, indent=2, ensure_ascii=False))
        except json.JSONDecodeError:
            print(text)
    else:
        print(text)
    print("-" * 80)


def replay_entries(
    entries: list[dict[str, Any]],
    *,
    email: str,
    password: str,
    captured_email: str | None,
    captured_password: str | None,
    timeout: float,
    dry_run: bool,
) -> None:
    session = requests.Session()
    session.verify = True

    for index, entry in enumerate(entries, start=1):
        request = entry.get("request", {})
        method = (request.get("method", "GET") or "GET").upper()
        raw_url = request.get("url", "")
        url = replace_credentials_in_string(
            raw_url,
            email=email,
            password=password,
            captured_email=captured_email,
            captured_password=captured_password,
        )
        headers = sanitize_headers(request.get("headers", []))

        parsed = urlparse(url)
        for cookie in request.get("cookies", []):
            name = cookie.get("name")
            value = cookie.get("value")
            if name and value is not None:
                session.cookies.set(name, value, domain=parsed.hostname, path=cookie.get("path", "/"))

        post_data = request.get("postData", {}) or {}
        body = build_body(
            post_data,
            email=email,
            password=password,
            captured_email=captured_email,
            captured_password=captured_password,
        )

        print(f"[{index}/{len(entries)}] {method} {url}")
        if body is not None:
            print(f"Request body: {body}")
        else:
            print("Request body: <none>")

        if dry_run:
            print("Dry-run mode: request not sent.")
            print("-" * 80)
            continue

        try:
            response = session.request(method=method, url=url, headers=headers, data=body, timeout=timeout)
            print_response(response)
        except requests.RequestException as exc:
            print(f"Request failed: {exc}")
            print("-" * 80)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay login requests from a HAR file and print responses.")
    parser.add_argument(
        "--har",
        type=Path,
        default=Path("account-api.proton.me_2026_06_01_18_34_28.har"),
        help="Path to HAR file.",
    )
    parser.add_argument(
        "--mode",
        choices=("login", "all"),
        default="login",
        help="Replay only login-related entries (default) or all entries.",
    )
    parser.add_argument("--email", type=str, help="Email to use. If omitted, prompt interactively.")
    parser.add_argument("--password", type=str, help="Password to use. If omitted, prompt interactively.")
    parser.add_argument(
        "--captured-email",
        type=str,
        default=None,
        help="Email value that existed in the HAR. If omitted, auto-detected.",
    )
    parser.add_argument(
        "--captured-password",
        type=str,
        default=None,
        help="Password value that existed in the HAR (if any) for replacement.",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="Per-request timeout in seconds.")
    parser.add_argument("--dry-run", action="store_true", help="Print requests without sending them.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.har.exists():
        print(f"HAR file not found: {args.har}", file=sys.stderr)
        return 1

    entries = load_har(args.har)
    captured_email = args.captured_email or detect_first_email(entries)

    email = args.email or input(f"Email [{captured_email or ''}]: ").strip() or (captured_email or "")
    if not email:
        print("Email is required.", file=sys.stderr)
        return 1

    password = args.password if args.password is not None else getpass.getpass("Password: ")
    if not password:
        print("Password is required.", file=sys.stderr)
        return 1

    filtered = filter_entries(entries, args.mode)
    print(f"Loaded {len(entries)} HAR entries.")
    print(f"Replaying {len(filtered)} entries in '{args.mode}' mode.")
    if args.captured_password is None:
        print("Note: no captured password replacement provided; Proton typically uses SRP proofs, not plaintext passwords.")
    if not filtered:
        print("No entries matched selected mode.", file=sys.stderr)
        return 1

    replay_entries(
        filtered,
        email=email,
        password=password,
        captured_email=captured_email,
        captured_password=args.captured_password,
        timeout=args.timeout,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
