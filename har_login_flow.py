#!/usr/bin/env python3
"""Extract login endpoint from main.js and perform sign-in."""

from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
import uuid
from typing import Any
from urllib import error, parse, request


def fetch_text(url: str, timeout: int = 30) -> str:
    req = request.Request(url=url, method="GET")
    req.add_header(
        "User-Agent",
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/141.0.0.0 Safari/537.36"
        ),
    )
    req.add_header("Accept", "*/*")
    with request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def infer_api_base(js_text: str) -> str:
    candidates = re.findall(r'baseUrl:"(/api/[^"]+)"', js_text)
    for candidate in candidates:
        if candidate.startswith("/api/"):
            return candidate.rstrip("/")
    return "/api/v1"


def infer_country_code(js_text: str) -> str | None:
    match = re.search(r'countryCode:"([A-Z]{2})"', js_text)
    return match.group(1) if match else None


def infer_login_path(js_text: str) -> str:
    auth_paths = sorted(set(re.findall(r"/auth/[a-z0-9/_-]+", js_text)))
    if "/auth/sign-in/client" in auth_paths:
        return "/auth/sign-in/client"

    preferred = (
        "/auth/sign-in",
        "/auth/signin",
        "/auth/login",
    )
    for path in preferred:
        if path in auth_paths:
            return path

    for path in auth_paths:
        if "sign-in" in path or "signin" in path or "login" in path:
            return path

    raise RuntimeError("Could not infer login endpoint from main.js")


def extract_origin(js_url: str) -> str:
    parsed = parse.urlparse(js_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("Invalid JS URL. Expected full https:// URL.")
    return f"{parsed.scheme}://{parsed.netloc}"


def analyze_main_js(js_url: str) -> dict[str, Any]:
    js_text = fetch_text(js_url)
    origin = extract_origin(js_url)
    api_base = infer_api_base(js_text)
    login_path = infer_login_path(js_text)
    country_code = infer_country_code(js_text)

    return {
        "origin": origin,
        "api_base": api_base,
        "login_path": login_path,
        "country_code": country_code,
    }


def http_json(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
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


def fetch_brand_prefix(origin: str, api_base: str, country_code: str | None) -> str | None:
    brand_info_url = f"{origin}{api_base}/casino/brand-info"
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


def run_login_flow(analysis: dict[str, Any]) -> int:
    origin = analysis["origin"]
    api_base = analysis["api_base"]
    login_path = analysis["login_path"]
    country_code = analysis["country_code"]

    print("=== Login Endpoint Extraction ===")
    print(f"Origin: {origin}")
    print(f"API base: {api_base}")
    print(f"Login endpoint: {api_base}{login_path}")
    print()

    email = input("Email (or username): ").strip()
    password = getpass.getpass("Password: ")
    if not email or not password:
        print("Email and password are required.", file=sys.stderr)
        return 2

    login_url = f"{origin}{api_base}{login_path}"
    brand_prefix = fetch_brand_prefix(origin, api_base, country_code)

    shared_headers: dict[str, str] = {
        "Content-Type": "application/json",
        "x-forwarded-host": origin,
        "x-fingerprint": uuid.uuid4().hex,
        "Referer": f"{origin}/",
        "Origin": origin,
    }
    if country_code:
        shared_headers["x-country-code"] = country_code
    if brand_prefix:
        shared_headers["x-brand-prefix"] = str(brand_prefix)

    payload = {"type": "email", "email": email, "password": password}

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
    parser = argparse.ArgumentParser(
        description="Extract endpoint from main.js and perform login."
    )
    parser.add_argument(
        "--js-url",
        default="https://elon.casino/casino/static/js/main.101751d4.js",
        help=(
            "Main JS URL to analyze "
            "(default: https://elon.casino/casino/static/js/main.101751d4.js)"
        ),
    )
    args = parser.parse_args()

    try:
        analysis = analyze_main_js(args.js_url)
        return run_login_flow(analysis)
    except KeyboardInterrupt:
        print("\nCancelled by user.")
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
