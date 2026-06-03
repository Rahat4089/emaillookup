#!/usr/bin/env python3
"""Perform login using a fixed endpoint and hardcoded credentials."""

from __future__ import annotations

import json
import sys
import uuid
from urllib import error, parse, request

# Hardcoded endpoint and credentials
LOGIN_ENDPOINT = "https://elon.casino/api/v1/auth/sign-in/client"
HARDCODED_EMAIL = "your_email@example.com"
HARDCODED_PASSWORD = "your_password_here"
COUNTRY_CODE = "BN"


def http_json(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    payload: dict[str, object] | None = None,
    timeout: int = 30,
) -> tuple[int, dict[str, str], str]:
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")

    req = request.Request(url=url, method=method.upper(), data=body)
    req.add_header(
        "User-Agent",
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/141.0.0.0 Safari/537.36"
        ),
    )
    req.add_header("Accept", "application/json, text/plain, */*")
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)

    try:
        with request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, dict(resp.headers.items()), raw
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return exc.code, dict(exc.headers.items()), raw


def pretty_json_or_raw(text: str) -> str:
    try:
        parsed = json.loads(text)
        return json.dumps(parsed, indent=2, ensure_ascii=True)
    except json.JSONDecodeError:
        return text


def fetch_brand_prefix(origin: str, country_code: str | None) -> str | None:
    brand_info_url = f"{origin}/api/v1/casino/brand-info"
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "x-forwarded-host": origin,
        "Referer": f"{origin}/",
        "Origin": origin,
    }
    if country_code:
        headers["x-country-code"] = country_code

    status, _, body = http_json("GET", brand_info_url, headers=headers)
    if status != 200:
        return None
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return None

    brand_prefix = payload.get("brandPrefix")
    if isinstance(brand_prefix, str) and brand_prefix:
        return brand_prefix
    return None


def run_login_flow() -> int:
    parsed = parse.urlparse(LOGIN_ENDPOINT)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    login_url = LOGIN_ENDPOINT

    if not HARDCODED_EMAIL or not HARDCODED_PASSWORD:
        print("HARDCODED_EMAIL and HARDCODED_PASSWORD must be set.", file=sys.stderr)
        return 2

    brand_prefix = fetch_brand_prefix(origin, COUNTRY_CODE)

    shared_headers: dict[str, str] = {
        "Content-Type": "application/json",
        "x-forwarded-host": origin,
        "x-fingerprint": uuid.uuid4().hex,
        "Referer": f"{origin}/",
        "Origin": origin,
    }
    if COUNTRY_CODE:
        shared_headers["x-country-code"] = COUNTRY_CODE
    if brand_prefix:
        shared_headers["x-brand-prefix"] = str(brand_prefix)

    payload = {
        "type": "email",
        "email": HARDCODED_EMAIL,
        "password": HARDCODED_PASSWORD,
    }

    print()
    print("=== Login Request ===")
    print(f"POST {login_url}")
    print("Request payload keys:", ", ".join(payload.keys()))
    status, resp_headers, resp_body = http_json(
        "POST", login_url, headers=shared_headers, payload=payload
    )
    print(f"Status: {status}")
    print("Response headers (subset):")
    for key in ("content-type", "set-cookie", "server"):
        if key in {k.lower() for k in resp_headers}:
            for hdr_key, hdr_val in resp_headers.items():
                if hdr_key.lower() == key:
                    print(f"  {hdr_key}: {hdr_val}")
    print("Response body:")
    print(pretty_json_or_raw(resp_body))

    if 200 <= status < 300:
        print("\nLogin succeeded.")
        return 0
    print("\nLogin failed.")
    return 1


def main() -> int:
    try:
        return run_login_flow()
    except KeyboardInterrupt:
        print("\nCancelled by user.")
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
