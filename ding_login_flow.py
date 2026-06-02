#!/usr/bin/env python3
"""
Replay the HAR-observed Ding/Pandora email registration login flow.

The capture in this repository shows the mobile API sending the password as a
JSON field over HTTPS. It does not show a client-side password hash or request
signature for this endpoint; the generated values are UUID request identifiers.
Replace EMAIL and PASSWORD locally before running. Do not commit real
credentials.
"""

from __future__ import annotations

import json
import sys
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


BASE_URL = "https://pandora.ding.com"
USER_AGENT = "Ding/6.1"

# Hard-coded credentials, as requested. Replace these locally before running.
EMAIL = "replace-with-email@example.com"
PASSWORD = "replace-with-password"


@dataclass(frozen=True)
class RawResponse:
    status: int
    headers: dict[str, str]
    text: str

    def json(self) -> dict[str, Any]:
        return json.loads(self.text)


def make_uuid() -> str:
    """Generate the UUID fields observed as uniqueId/inAuthId in the HAR."""
    return str(uuid.uuid4())


def api_request(
    method: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    bearer_token: str | None = None,
) -> RawResponse:
    data = None
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {bearer_token}" if bearer_token else "",
        "User-Agent": USER_AGENT,
    }

    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=UTF-8"

    request = Request(
        urljoin(BASE_URL, path),
        data=data,
        headers=headers,
        method=method.upper(),
    )

    try:
        with urlopen(request, timeout=30) as response:
            return RawResponse(
                status=response.status,
                headers=dict(response.headers.items()),
                text=response.read().decode("utf-8", errors="replace"),
            )
    except HTTPError as exc:
        return RawResponse(
            status=exc.code,
            headers=dict(exc.headers.items()),
            text=exc.read().decode("utf-8", errors="replace"),
        )
    except URLError as exc:
        raise RuntimeError(f"request failed for {method.upper()} {path}: {exc}") from exc


def submit_email(email: str) -> RawResponse:
    return api_request(
        "POST",
        "/api/submitemail",
        payload={
            "email": email,
            "fType": "EmailSubmitted",
            "uniqueId": make_uuid(),
        },
    )


def register_or_login(email: str, password: str) -> RawResponse:
    return api_request(
        "POST",
        "/api/register",
        payload={
            "email": email,
            "fType": "RegistrationSubmitted",
            "inAuthId": make_uuid(),
            "password": password,
            "receiveEmails": True,
            "trackingData": [],
            "uniqueId": make_uuid(),
        },
    )


def extract_bearer_token(raw_login_response: RawResponse) -> str | None:
    try:
        body = raw_login_response.json()
    except json.JSONDecodeError:
        return None

    access = body.get("access")
    if isinstance(access, dict):
        token = access.get("bearerToken")
        if isinstance(token, str) and token:
            return token

    return None


def print_step(name: str, response: RawResponse) -> None:
    print(f"{name}: HTTP {response.status}", file=sys.stderr)


def main() -> int:
    if EMAIL == "replace-with-email@example.com" or PASSWORD == "replace-with-password":
        print(
            "Edit ding_login_flow.py and replace EMAIL/PASSWORD before running.",
            file=sys.stderr,
        )
        return 2

    bootstrap = api_request("GET", "/api/view/bootstrap")
    print_step("bootstrap", bootstrap)

    session_before = api_request("GET", "/api/session")
    print_step("anonymous session", session_before)

    email_response = submit_email(EMAIL)
    print_step("submit email", email_response)

    login_response = register_or_login(EMAIL, PASSWORD)
    print_step("register/login", login_response)

    print("\n=== RAW LOGIN RESPONSE (/api/register) ===")
    print(login_response.text)

    bearer_token = extract_bearer_token(login_response)
    if not bearer_token:
        print("\nNo bearerToken found in login response; stopping.", file=sys.stderr)
        return 1

    session_after = api_request("GET", "/api/session", bearer_token=bearer_token)
    print_step("authenticated session", session_after)

    profile = api_request("GET", "/api/profile", bearer_token=bearer_token)
    print_step("profile", profile)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
