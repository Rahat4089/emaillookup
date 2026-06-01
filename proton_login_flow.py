#!/usr/bin/env python3
"""Analyze and replay the Proton web login flow captured in the HAR file.

The HAR in this repository shows Proton's web-account login flow. The password
is never posted to Proton directly; the client performs SRP v4 locally and sends
only a public client ephemeral plus a proof.

Usage examples:

    python3 proton_login_flow.py --har account-api.proton.me_2026_06_01_18_34_28.har

    python3 proton_login_flow.py

    PROTON_USERNAME="user@example.com" PROTON_PASSWORD="..." python3 proton_login_flow.py --live-login --fetch-user

Dependencies:

    python3 -m pip install -r requirements.txt
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import secrets
import sys
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import bcrypt
import requests


DEFAULT_BASE_URL = "https://account.proton.me"
DEFAULT_APP_VERSION = "web-account@5.0.382.0"
DEFAULT_REFERER = "https://account.proton.me/vpn"
PROTON_API_ACCEPT = "application/vnd.protonmail.v1+json"
SRP_BITS = 2048
SRP_BYTES = SRP_BITS // 8
GENERATOR = 2

STD_B64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
BCRYPT_B64_ALPHABET = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
BCRYPT_B64_TRANSLATION = bytes.maketrans(STD_B64_ALPHABET, BCRYPT_B64_ALPHABET)


class ProtonLoginError(RuntimeError):
    """Raised when a Proton API step or SRP validation step fails."""


def expand_hash(data: bytes) -> bytes:
    """Proton SRP expands SHA-512 into 256 bytes using four counters."""
    return b"".join(hashlib.sha512(data + bytes([idx])).digest() for idx in range(4))


def bcrypt_base64(data: bytes) -> bytes:
    """Encode bcrypt salt bytes with Proton/go-srp's custom base64 alphabet."""
    return base64.b64encode(data).rstrip(b"=").translate(BCRYPT_B64_TRANSLATION)


def int_from_le(data: bytes) -> int:
    """Proton go-srp interprets SRP byte strings as little-endian integers."""
    return int.from_bytes(data, "little")


def int_to_le(value: int, size: int = SRP_BYTES) -> bytes:
    return value.to_bytes(size, "little")


def extract_cleartext_from_pgp_signed_message(signed_message: str) -> str:
    """Return the cleartext payload from Proton's clear-signed modulus.

    This reproduces the extraction needed for the login flow. Proton's Go
    reference implementation also verifies the PGP signature against Proton's
    SRP modulus public key. This script keeps dependencies small and does not
    perform that signature verification, so do not use it as a production
    security boundary without adding that verification step.
    """
    normalized = signed_message.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        return normalized

    lines = normalized.split("\n")
    try:
        body_start = lines.index("") + 1
        sig_start = next(
            idx
            for idx, line in enumerate(lines)
            if line.startswith("-----BEGIN PGP SIGNATURE-----")
        )
    except (ValueError, StopIteration) as exc:
        raise ProtonLoginError("Could not parse Proton clear-signed modulus") from exc

    body_lines = []
    for line in lines[body_start:sig_start]:
        # PGP cleartext signatures dash-escape body lines that start with "-".
        body_lines.append(line[2:] if line.startswith("- ") else line)
    return "\n".join(body_lines).strip()


def decode_modulus(signed_modulus: str) -> bytes:
    cleartext = extract_cleartext_from_pgp_signed_message(signed_modulus)
    try:
        return base64.b64decode(cleartext, validate=True)
    except ValueError as exc:
        raise ProtonLoginError("Could not base64-decode Proton SRP modulus") from exc


def hash_password_v4(password: str, salt_b64: str, modulus: bytes) -> bytes:
    """Derive Proton SRP v3/v4 password hash.

    Reference: ProtonMail/go-srp hashPasswordVersion3.
    """
    salt = base64.b64decode(salt_b64)
    bcrypt_salt = bcrypt_base64(salt + b"proton")
    bcrypt_hash = bcrypt.hashpw(password.encode("utf-8"), b"$2y$10$" + bcrypt_salt)
    return expand_hash(bcrypt_hash + modulus)


def validate_srp_inputs(modulus: bytes, server_ephemeral: bytes) -> None:
    modulus_int = int_from_le(modulus)
    server_ephemeral_int = int_from_le(server_ephemeral)
    if len(modulus) != SRP_BYTES or modulus_int.bit_length() != SRP_BITS:
        raise ProtonLoginError("Unexpected SRP modulus size")
    if modulus_int % 8 != 3:
        raise ProtonLoginError("SRP modulus is not congruent to 3 mod 8")
    if not 1 < server_ephemeral_int < modulus_int - 1:
        raise ProtonLoginError("SRP server ephemeral is out of bounds")
    # Proton's reference also performs stronger primality and PGP signature
    # checks. The important invariant for this educational replay is that the
    # server supplied a correctly sized modulus and bounded ephemeral.


@dataclass(frozen=True)
class SrpProofs:
    client_ephemeral_b64: str
    client_proof_b64: str
    expected_server_proof_b64: str


def generate_srp_proofs(
    username: str,
    password: str,
    version: int,
    salt_b64: str,
    signed_modulus: str,
    server_ephemeral_b64: str,
) -> SrpProofs:
    """Generate Proton SRP client proof values for /api/core/v4/auth."""
    if version not in (3, 4):
        raise ProtonLoginError(f"Unsupported Proton SRP version: {version}")

    modulus = decode_modulus(signed_modulus)
    server_ephemeral = base64.b64decode(server_ephemeral_b64)
    validate_srp_inputs(modulus, server_ephemeral)

    modulus_int = int_from_le(modulus)
    server_ephemeral_int = int_from_le(server_ephemeral)
    modulus_minus_one = modulus_int - 1
    hashed_password = hash_password_v4(password, salt_b64, modulus)
    x = int_from_le(hashed_password)

    generator_bytes = int_to_le(GENERATOR)
    k = int_from_le(expand_hash(generator_bytes + modulus)) % modulus_int
    if not 1 < k < modulus_minus_one:
        raise ProtonLoginError("SRP multiplier is out of bounds")

    while True:
        client_secret = secrets.randbelow(modulus_minus_one)
        if client_secret <= SRP_BITS * 2:
            continue

        client_ephemeral_int = pow(GENERATOR, client_secret, modulus_int)
        client_ephemeral = int_to_le(client_ephemeral_int)
        scramble = int_from_le(expand_hash(client_ephemeral + server_ephemeral))
        if scramble != 0:
            break

    base = (server_ephemeral_int - k * pow(GENERATOR, x, modulus_int)) % modulus_int
    exponent = (client_secret + scramble * x) % modulus_minus_one
    shared_secret = int_to_le(pow(base, exponent, modulus_int))

    client_proof = expand_hash(client_ephemeral + server_ephemeral + shared_secret)
    server_proof = expand_hash(client_ephemeral + client_proof + shared_secret)

    return SrpProofs(
        client_ephemeral_b64=base64.b64encode(client_ephemeral).decode("ascii"),
        client_proof_b64=base64.b64encode(client_proof).decode("ascii"),
        expected_server_proof_b64=base64.b64encode(server_proof).decode("ascii"),
    )


class ProtonWebLogin:
    """Small client for the Proton web-account flow shown in the HAR."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        app_version: str = DEFAULT_APP_VERSION,
        referer: str = DEFAULT_REFERER,
        locale: str = "en_US",
        timeout: int = 30,
        print_responses: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.app_version = app_version
        self.referer = referer
        self.timeout = timeout
        self.print_responses = print_responses
        self.session = requests.Session()
        self.session.headers.update(
            {
                "accept": PROTON_API_ACCEPT,
                "origin": self.base_url,
                "referer": referer,
                "x-pm-appversion": app_version,
                "x-pm-locale": locale,
            }
        )
        self.uid: str | None = None
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.cookies_exchanged = False

    def _headers(self, *, bearer: bool = False) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.uid:
            headers["x-pm-uid"] = self.uid
        if bearer:
            if not self.access_token:
                raise ProtonLoginError("Bearer token requested before session creation")
            headers["authorization"] = f"Bearer {self.access_token}"
        return headers

    def _print_raw_response(self, method: str, path: str, response: requests.Response) -> None:
        if not self.print_responses:
            return
        print(f"\n=== {method} {path} -> HTTP {response.status_code} ===")
        print("--- response headers ---")
        for name, value in response.headers.items():
            print(f"{name}: {value}")
        print("--- raw response body ---")
        print(response.text)

    def _api(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        bearer: bool = False,
    ) -> dict[str, Any]:
        response = self.session.request(
            method,
            f"{self.base_url}{path}",
            json=json_body,
            headers=self._headers(bearer=bearer),
            timeout=self.timeout,
        )

        self._print_raw_response(method, path, response)

        try:
            payload = response.json()
        except ValueError as exc:
            raise ProtonLoginError(
                f"{method} {path} returned non-JSON status {response.status_code}"
            ) from exc

        if response.status_code >= 400 or payload.get("Code") not in (None, 1000):
            message = payload.get("Error") or payload.get("ErrorDescription") or payload
            raise ProtonLoginError(f"{method} {path} failed: {message}")
        return payload

    def create_web_session(self) -> None:
        """Create the anonymous auth session seen at HAR entry 006."""
        payload = self._api("POST", "/api/auth/v4/sessions")
        self.uid = payload["UID"]
        self.access_token = payload["AccessToken"]
        self.refresh_token = payload["RefreshToken"]

    def auth_info(self, username: str, intent: str = "Proton") -> dict[str, Any]:
        """Fetch SRP salt, modulus, server ephemeral, and SRP session id."""
        if not self.uid:
            self.create_web_session()
        if not self.cookies_exchanged:
            self.exchange_auth_cookies()
        return self._api(
            "POST",
            "/api/core/v4/auth/info",
            json_body={"Username": username, "Intent": intent},
        )

    def authenticate(
        self,
        username: str,
        password: str,
        *,
        totp: str | None = None,
        persistent_cookies: bool = True,
    ) -> dict[str, Any]:
        """Perform the SRP password proof and verify Proton's server proof."""
        info = self.auth_info(username)
        proofs = generate_srp_proofs(
            username=username,
            password=password,
            version=int(info["Version"]),
            salt_b64=info["Salt"],
            signed_modulus=info["Modulus"],
            server_ephemeral_b64=info["ServerEphemeral"],
        )

        auth_body: dict[str, Any] = {
            "Username": username,
            "ClientProof": proofs.client_proof_b64,
            "ClientEphemeral": proofs.client_ephemeral_b64,
            "SRPSession": info["SRPSession"],
            "PersistentCookies": 1 if persistent_cookies else 0,
        }
        if totp:
            auth_body["TwoFactorCode"] = totp

        auth_payload = self._api("POST", "/api/core/v4/auth", json_body=auth_body)
        if auth_payload.get("ServerProof") != proofs.expected_server_proof_b64:
            raise ProtonLoginError("ServerProof did not match the local SRP expectation")

        if auth_payload.get("2FA", {}).get("Enabled") and not totp:
            raise ProtonLoginError("Password proof succeeded, but this account requires 2FA")

        return auth_payload

    def exchange_auth_cookies(self, *, persistent: bool = False) -> dict[str, Any]:
        """Exchange the bootstrap refresh token for web auth cookies.

        HAR entry 021 performs this right after session creation. The same
        browser session is then upgraded by the SRP auth call. requests.Session
        stores the Set-Cookie response headers automatically.
        """
        if not (self.uid and self.refresh_token):
            raise ProtonLoginError("Cookie exchange requires an initialized session")
        state = secrets.token_urlsafe(18)
        payload = self._api(
            "POST",
            "/api/core/v4/auth/cookies",
            json_body={
                "UID": self.uid,
                "ResponseType": "token",
                "GrantType": "refresh_token",
                "RefreshToken": self.refresh_token,
                "RedirectURI": "https://protonmail.com",
                "Persistent": 1 if persistent else 0,
                "State": state,
            },
            bearer=True,
        )
        self.cookies_exchanged = True
        return payload

    def fetch_user(self) -> dict[str, Any]:
        return self._api("GET", "/api/core/v4/users")


def describe_endpoint(method: str, path: str) -> str:
    lower = path.lower()
    if lower.endswith("/api/auth/refresh"):
        return "old refresh-token attempt; failed in the capture"
    if "/api/auth/sessions/forks/" in lower:
        return "consumes a fork selector and returns a session"
    if lower.endswith("/api/auth/v4/sessions"):
        return "creates the anonymous web auth session"
    if lower.endswith("/api/auth/v4/sessions/forks"):
        return "creates a child-session fork selector"
    if lower.endswith("/api/auth/v4/sessions/local/key"):
        return "stores or retrieves the browser-local payload encryption key"
    if lower.endswith("/api/auth/v4/sessions/payload"):
        return "stores opaque encrypted local-session payload"
    if lower.endswith("/api/core/v4/auth/info"):
        return "returns SRP salt, modulus, server ephemeral, and SRP session"
    if lower.endswith("/api/core/v4/auth"):
        return "submits SRP client proof and receives server proof"
    if lower.endswith("/api/core/v4/auth/cookies"):
        return "exchanges refresh token for AUTH-* web cookies"
    if lower.endswith("/api/core/v4/users"):
        return "fetches authenticated user profile"
    if lower.endswith("/api/core/v4/keys/salts"):
        return "fetches per-key salts for decrypting account keys"
    if lower.endswith("/api/core/v4/settings/recovery/secret"):
        return "uploads encrypted recovery secret"
    if path.startswith("/authorize"):
        return "OAuth-style browser authorization page"
    return "supporting request"


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        if len(value) > 12:
            return f"<redacted string len={len(value)}>"
        return value
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value[:5]]
    return value


def load_json_text(entry: dict[str, Any], section: str) -> dict[str, Any] | None:
    if section == "request":
        text = (entry.get("request", {}).get("postData") or {}).get("text")
    else:
        text = (entry.get("response", {}).get("content") or {}).get("text")
    if not text:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def analyze_har(path: str) -> None:
    with open(path, "r", encoding="utf-8") as handle:
        har = json.load(handle)

    entries = list(enumerate(har.get("log", {}).get("entries", [])))
    entries.sort(key=lambda item: item[1].get("startedDateTime", ""))
    print(f"HAR entries: {len(entries)}")
    print("Relevant login/encryption flow, sorted by startedDateTime:")
    for idx, entry in entries:
        request = entry["request"]
        response = entry["response"]
        url = urlsplit(request["url"])
        endpoint = url.path
        if url.query:
            endpoint += "?..."

        description = describe_endpoint(request["method"], endpoint)
        if description == "supporting request" and request["method"] == "GET":
            continue

        request_json = load_json_text(entry, "request")
        response_json = load_json_text(entry, "response")
        request_keys = sorted(request_json.keys()) if request_json else []
        response_keys = sorted(response_json.keys()) if response_json else []
        print(
            f"{idx:03d} {request['method']:<6} {response['status']:<3} "
            f"{url.netloc}{endpoint} - {description}"
        )
        if request_keys:
            print(f"     request keys: {request_keys}")
        if response_keys:
            print(f"     response keys: {response_keys}")


def get_credentials(args: argparse.Namespace) -> tuple[str, str, str | None]:
    username = args.username or os.getenv("PROTON_USERNAME")
    password = args.password or os.getenv("PROTON_PASSWORD")
    totp = args.totp or os.getenv("PROTON_TOTP")

    if not username:
        username = input("Proton username/email: ").strip()
    if not password:
        password = getpass.getpass("Proton password: ")
    return username, password, totp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--har", help="Path to a HAR file to summarize safely")
    parser.add_argument("--live-login", action="store_true", help="Run the live Proton login flow")
    parser.add_argument("--fetch-user", action="store_true", help="Fetch /api/core/v4/users after login")
    parser.add_argument(
        "--no-print-responses",
        action="store_true",
        help="Do not print raw API responses during live login",
    )
    parser.add_argument("--username", help="Proton username/email; prefer PROTON_USERNAME")
    parser.add_argument("--password", help="Proton password; prefer PROTON_PASSWORD or prompt")
    parser.add_argument("--totp", help="Optional TOTP code; prefer PROTON_TOTP")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--app-version", default=DEFAULT_APP_VERSION)
    args = parser.parse_args(argv)
    default_interactive_login = not args.har and not args.live_login
    if default_interactive_login:
        args.live_login = True
        args.fetch_user = True

    if args.har:
        analyze_har(args.har)

    if not args.live_login:
        if not args.har:
            parser.print_help()
        return 0

    username, password, totp = get_credentials(args)
    print_responses = not args.no_print_responses
    if print_responses:
        print("Raw API responses will be printed below. They may contain session tokens; keep this output private.")
    client = ProtonWebLogin(
        base_url=args.base_url,
        app_version=args.app_version,
        print_responses=print_responses,
    )
    auth_payload = client.authenticate(username, password, totp=totp)

    print("SRP login succeeded.")
    print(f"UID: {client.uid}")
    print(f"UserID: {auth_payload.get('UserID')}")
    print(f"2FA enabled: {bool(auth_payload.get('2FA', {}).get('Enabled'))}")

    if args.fetch_user:
        user_payload = client.fetch_user()
        user = user_payload.get("User", {})
        print("Fetched user profile:")
        print(json.dumps(redact_value({
            "ID": user.get("ID"),
            "Email": user.get("Email"),
            "Name": user.get("Name"),
            "DisplayName": user.get("DisplayName"),
            "Keys": f"{len(user.get('Keys', []))} keys",
        }), indent=2, sort_keys=True))

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProtonLoginError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
