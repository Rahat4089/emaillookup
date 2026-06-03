#!/usr/bin/env python3
"""Analyze a HAR file for login flow and execute login request."""

from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib import error, parse, request


def load_har(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def find_main_js_text(entries: list[dict[str, Any]]) -> str:
    for entry in entries:
        req = entry.get("request", {})
        url = req.get("url", "")
        if "/static/js/main." in url and url.endswith(".js"):
            return entry.get("response", {}).get("content", {}).get("text", "") or ""
    return ""


def infer_origin(entries: list[dict[str, Any]]) -> str:
    for entry in entries:
        url = entry.get("request", {}).get("url", "")
        parsed = parse.urlparse(url)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    raise RuntimeError("Could not infer origin from HAR entries.")


def infer_api_base(js_text: str) -> str:
    # App init call contains baseUrl, e.g. baseUrl:"/api/v1"
    candidates = re.findall(r'baseUrl:"(/api/[^"]+)"', js_text)
    for candidate in candidates:
        if candidate.startswith("/api/"):
            return candidate.rstrip("/")
    return "/api/v1"


def infer_country_code(js_text: str) -> str | None:
    match = re.search(r'countryCode:"([A-Z]{2})"', js_text)
    return match.group(1) if match else None


def find_captured_brand_prefix(entries: list[dict[str, Any]]) -> str | None:
    for entry in entries:
        url = entry.get("request", {}).get("url", "")
        if url.endswith("/api/v1/casino/brand-info"):
            text = entry.get("response", {}).get("content", {}).get("text", "")
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            brand_prefix = payload.get("brandPrefix")
            if isinstance(brand_prefix, str) and brand_prefix:
                return brand_prefix
    return None


def analyze_login_flow(har_data: dict[str, Any]) -> dict[str, Any]:
    entries = har_data.get("log", {}).get("entries", [])
    if not isinstance(entries, list) or not entries:
        raise RuntimeError("HAR has no entries.")

    main_js_text = find_main_js_text(entries)
    origin = infer_origin(entries)
    api_base = infer_api_base(main_js_text)
    country_code = infer_country_code(main_js_text)

    network_login_requests = []
    auth_keywords = ("login", "sign-in", "signin", "auth")
    for entry in entries:
        req = entry.get("request", {})
        url = req.get("url", "").lower()
        if any(keyword in url for keyword in auth_keywords):
            network_login_requests.append(
                {
                    "method": req.get("method", "GET"),
                    "url": req.get("url", ""),
                    "status": entry.get("response", {}).get("status"),
                }
            )

    js_auth_paths = sorted(set(re.findall(r"/auth/[a-z0-9/_-]+", main_js_text)))
    login_path = "/auth/sign-in/client" if "/auth/sign-in/client" in js_auth_paths else None
    token_path = "/auth/sign-in/token" if "/auth/sign-in/token" in js_auth_paths else None
    brand_prefix = find_captured_brand_prefix(entries)

    return {
        "origin": origin,
        "api_base": api_base,
        "country_code": country_code,
        "network_auth_requests": network_login_requests,
        "js_auth_paths": js_auth_paths,
        "login_path": login_path,
        "token_path": token_path,
        "captured_brand_prefix": brand_prefix,
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


def run_login_flow(analysis: dict[str, Any]) -> int:
    origin = analysis["origin"]
    api_base = analysis["api_base"]
    login_path = analysis["login_path"] or "/auth/sign-in/client"
    country_code = analysis["country_code"]

    print("=== HAR Login Flow Analysis ===")
    print(f"Origin: {origin}")
    print(f"API base: {api_base}")
    print(f"Inferred login endpoint: {api_base}{login_path}")
    if analysis["network_auth_requests"]:
        print("Auth-related requests captured in network:")
        for req in analysis["network_auth_requests"]:
            print(f"  - {req['method']} {req['url']} (status={req['status']})")
    else:
        print(
            "No direct login request captured in HAR network entries. "
            "Using login endpoint inferred from JS bundle."
        )
    print()

    email = input("Email (or username): ").strip()
    password = getpass.getpass("Password: ")
    if not email or not password:
        print("Email and password are required.", file=sys.stderr)
        return 2

    brand_info_url = f"{origin}{api_base}/casino/brand-info"
    login_url = f"{origin}{api_base}{login_path}"
    x_fingerprint = uuid.uuid4().hex

    shared_headers: dict[str, str] = {
        "Content-Type": "application/json",
        "x-forwarded-host": origin,
        "x-fingerprint": x_fingerprint,
    }
    if country_code:
        shared_headers["x-country-code"] = country_code

    print(f"Fetching brand info: {brand_info_url}")
    brand_status, _, brand_body = http_json("GET", brand_info_url, headers=shared_headers)
    brand_prefix = analysis.get("captured_brand_prefix")
    if brand_status == 200:
        try:
            brand_prefix = json.loads(brand_body).get("brandPrefix") or brand_prefix
        except json.JSONDecodeError:
            pass
    if brand_prefix:
        shared_headers["x-brand-prefix"] = str(brand_prefix)

    payload_attempts = [
        {"email": email, "password": password},
        {"login": email, "password": password},
        {"login": email, "email": email, "password": password},
    ]

    print()
    print("=== Login Attempts ===")
    for idx, payload in enumerate(payload_attempts, start=1):
        print(f"\nAttempt {idx}: POST {login_url}")
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
            print("\nLogin succeeded with this payload.")
            return 0

    print("\nAll payload attempts failed.")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze HAR login flow and attempt login by prompting email/password."
        )
    )
    parser.add_argument(
        "--har",
        default="elon.casino.har",
        help="Path to HAR file (default: elon.casino.har)",
    )
    args = parser.parse_args()

    har_path = Path(args.har)
    if not har_path.exists():
        print(f"HAR file not found: {har_path}", file=sys.stderr)
        return 2

    try:
        har_data = load_har(har_path)
        analysis = analyze_login_flow(har_data)
        return run_login_flow(analysis)
    except KeyboardInterrupt:
        print("\nCancelled by user.")
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
