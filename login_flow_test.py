#!/usr/bin/env python3
"""Reproduce elon.casino login API call and print raw response."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import urllib.error
import urllib.request


def build_headers(
    origin: str,
    referer: str,
    brand_prefix: str,
    country_code: str,
    fingerprint: str,
) -> dict[str, str]:
    # Reversed from main.101751d4.js and working browser requests.
    return {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/126.0.0.0 Safari/537.36"
        ),
        "Origin": origin,
        "Referer": referer,
        "x-brand-prefix": brand_prefix,
        "x-forwarded-host": origin,
        "x-country-code": country_code,
        "x-fingerprint": fingerprint,
        "Authorization": "Bearer ",
        "refresh_token": "",
    }


def do_login(base_url: str, email: str, password: str, headers: dict[str, str]) -> int:
    url = f"{base_url.rstrip('/')}/auth/sign-in/client"
    payload = {
        "type": "email",
        "email": email,
        "password": password,
    }
    body = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(url=url, data=body, headers=headers, method="POST")

    print("=== REQUEST ===")
    print(f"URL: {url}")
    print("Headers:")
    print(json.dumps(headers, indent=2))
    print("Payload:")
    print(json.dumps(payload, indent=2))

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            print("\n=== RAW RESPONSE ===")
            print(f"HTTP {response.status}")
            print(dict(response.headers.items()))
            print(raw.decode("utf-8", errors="replace"))
            return response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        print("\n=== RAW RESPONSE ===")
        print(f"HTTP {exc.code}")
        print(dict(exc.headers.items()))
        print(raw.decode("utf-8", errors="replace"))
        return exc.code


def main() -> int:
    parser = argparse.ArgumentParser(description="Run raw login request against elon.casino")
    parser.add_argument("--base-url", default="https://elon.casino/api/v1")
    parser.add_argument("--origin", default="https://elon.casino")
    parser.add_argument("--referer", default="https://elon.casino/casino/")
    parser.add_argument("--brand-prefix", default="gb-ad918334")
    parser.add_argument("--country-code", default="BN")
    parser.add_argument("--email", default=os.getenv("ELON_EMAIL", ""))
    parser.add_argument("--password", default=os.getenv("ELON_PASSWORD", ""))
    parser.add_argument("--fingerprint", default=secrets.token_hex(16))

    args = parser.parse_args()

    if not args.email or not args.password:
        print("Provide credentials with --email/--password or ELON_EMAIL/ELON_PASSWORD")
        return 2

    headers = build_headers(
        origin=args.origin,
        referer=args.referer,
        brand_prefix=args.brand_prefix,
        country_code=args.country_code,
        fingerprint=args.fingerprint,
    )

    status = do_login(
        base_url=args.base_url,
        email=args.email,
        password=args.password,
        headers=headers,
    )

    return 0 if 200 <= status < 300 else 1


if __name__ == "__main__":
    sys.exit(main())
