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


def fetch_brand_info(base_url: str, origin: str) -> dict:
    url = f"{base_url.rstrip('/')}/casino/brand-info"
    headers = {
        "Content-Type": "application/json",
        "x-forwarded-host": origin,
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/126.0.0.0 Safari/537.36"
        ),
    }
    req = urllib.request.Request(url=url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def build_headers(
    origin: str,
    referer: str,
    brand_prefix: str,
    country_code: str,
    fingerprint: str,
) -> dict[str, str]:
    # Reversed from JS SDK request stack.
    headers = {
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
        "x-fingerprint": fingerprint,
        "Authorization": "Bearer ",
        "refresh_token": "",
    }
    if country_code:
        headers["x-country-code"] = country_code
    return headers


def build_payload(login_type: str, email: str, password: str, username: str, phone: str) -> dict:
    if login_type == "email":
        return {"type": "email", "email": email, "password": password}
    if login_type == "quick":
        return {"type": "quick", "username": username, "password": password}
    if login_type == "phone":
        return {"type": "phone", "phone": phone, "password": password}
    raise ValueError(f"Unsupported login type: {login_type}")


def do_login(base_url: str, payload: dict, headers: dict[str, str]) -> int:
    url = f"{base_url.rstrip('/')}/auth/sign-in/client"
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
    parser.add_argument("--country-code", default="BN")
    parser.add_argument("--brand-prefix", default="", help="Leave empty to auto-fetch from /casino/brand-info")
    parser.add_argument("--type", default="email", choices=["email", "quick", "phone"])
    parser.add_argument("--email", default=os.getenv("ELON_EMAIL", ""))
    parser.add_argument("--password", default=os.getenv("ELON_PASSWORD", ""))
    parser.add_argument("--username", default=os.getenv("ELON_USERNAME", ""))
    parser.add_argument("--phone", default=os.getenv("ELON_PHONE", ""))
    parser.add_argument("--fingerprint", default=secrets.token_hex(16))

    args = parser.parse_args()

    if not args.password:
        print("Provide password with --password or ELON_PASSWORD")
        return 2

    brand_prefix = args.brand_prefix
    if not brand_prefix:
        try:
            brand_info = fetch_brand_info(args.base_url, args.origin)
            brand_prefix = brand_info.get("brandPrefix", "")
            print("=== BRAND INFO ===")
            print(json.dumps(brand_info, indent=2))
        except Exception as error:
            print(f"Failed to fetch brand info: {error}")
            return 2

    if not brand_prefix:
        print("Brand prefix is empty; cannot continue")
        return 2

    username = args.username or args.email
    phone = args.phone or args.password

    if args.type == "email" and not args.email:
        print("Email login requires --email or ELON_EMAIL")
        return 2

    payload = build_payload(args.type, args.email, args.password, username, phone)

    headers = build_headers(
        origin=args.origin,
        referer=args.referer,
        brand_prefix=brand_prefix,
        country_code=args.country_code,
        fingerprint=args.fingerprint,
    )

    status = do_login(base_url=args.base_url, payload=payload, headers=headers)
    return 0 if 200 <= status < 300 else 1


if __name__ == "__main__":
    sys.exit(main())
