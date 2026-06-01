#!/usr/bin/env python3
"""
Reverse and execute Proton's full login flow (SRP-based), printing all responses.

This script asks for email/password, performs the live auth flow, and prints each
request/response pair so the full login process is observable.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import secrets
import string
import sys
from dataclasses import dataclass
from typing import Any

import bcrypt
import requests


ACCOUNT_BASE = "https://account.proton.me"
CHALLENGE_BASE = "https://account-api.proton.me"
APP_VERSION = "web-account@5.0.382.0"
ACCEPT = "application/vnd.protonmail.v1+json"
LOCALE = "en_US"
BCRYPT_PREFIX = b"$2y$10$"
BCRYPT_ALPHABET = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


@dataclass
class SessionTokens:
    access_token: str
    refresh_token: str
    uid: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Execute Proton full login flow and print all responses."
    )
    parser.add_argument("--email", type=str, help="Account email (if omitted, prompt)")
    parser.add_argument("--password", type=str, help="Account password (if omitted, prompt)")
    parser.add_argument("--intent", choices=("Auto", "Proton"), default="Proton")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--skip-challenge",
        action="store_true",
        help="Skip initial challenge/access preflight endpoints.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print step plan only; do not send network requests.",
    )
    parser.add_argument(
        "--human-verification-token",
        type=str,
        default=None,
        help="Optional Proton human verification token (if CAPTCHA is required).",
    )
    parser.add_argument(
        "--human-verification-method",
        type=str,
        default="captcha",
        help="Method for the human verification token header (default: captcha).",
    )
    return parser.parse_args()


def prompt_credentials(args: argparse.Namespace) -> tuple[str, str]:
    email = (args.email or input("Email: ").strip()).strip()
    if not email:
        raise ValueError("Email is required.")
    password = args.password if args.password is not None else getpass.getpass("Password: ")
    if not password:
        raise ValueError("Password is required.")
    return email, password


def json_or_text(response: requests.Response) -> str:
    content_type = response.headers.get("content-type", "").lower()
    body = response.text
    if "application/json" in content_type:
        try:
            return json.dumps(response.json(), indent=2, ensure_ascii=False)
        except json.JSONDecodeError:
            return body
    return body


def print_response_only(name: str, response: requests.Response | None) -> None:
    if response is None:
        return
    print("-" * 100)
    print(f"STEP RESULT: {name}")
    print(f"RESPONSE STATUS: {response.status_code} {response.reason}")
    print("RESPONSE HEADERS:")
    for key, value in response.headers.items():
        print(f"  {key}: {value}")
    print("RESPONSE BODY:")
    print(json_or_text(response))


def do_request(
    session: requests.Session,
    *,
    name: str,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    json_body: Any = None,
    timeout: float = 30.0,
    dry_run: bool = False,
) -> requests.Response | None:
    print("=" * 100)
    print(f"STEP: {name}")
    print(f"REQUEST: {method.upper()} {url}")
    print("REQUEST HEADERS:")
    for key, value in (headers or {}).items():
        print(f"  {key}: {value}")
    if json_body is None:
        print("REQUEST BODY: <none>")
    else:
        print("REQUEST BODY:")
        print(json.dumps(json_body, indent=2, ensure_ascii=False))

    if dry_run:
        print("DRY-RUN: request not sent")
        return None

    response = session.request(
        method=method,
        url=url,
        headers=headers,
        json=json_body,
        timeout=timeout,
    )
    print_response_only(name, response)
    return response


def default_headers(
    *,
    uid: str | None = None,
    include_auth: str | None = None,
    human_verification_token: str | None = None,
    human_verification_method: str | None = None,
) -> dict[str, str]:
    headers = {
        "accept": ACCEPT,
        "x-pm-appversion": APP_VERSION,
        "x-pm-locale": LOCALE,
        "content-type": "application/json",
        "origin": ACCOUNT_BASE,
        "referer": f"{ACCOUNT_BASE}/",
    }
    if uid:
        headers["x-pm-uid"] = uid
    if include_auth:
        headers["authorization"] = f"Bearer {include_auth}"
    if human_verification_token:
        headers["x-pm-human-verification-token"] = human_verification_token
    if human_verification_method:
        headers["x-pm-human-verification-token-type"] = human_verification_method
    return headers


def extract_signed_modulus_b64(signed_modulus: str) -> str:
    marker_start = "-----BEGIN PGP SIGNED MESSAGE-----"
    marker_sig = "-----BEGIN PGP SIGNATURE-----"
    if marker_start not in signed_modulus or marker_sig not in signed_modulus:
        raise ValueError("Invalid signed modulus format")
    body = signed_modulus.split("\n\n", 1)[1]
    base64_part = body.split(marker_sig, 1)[0].strip()
    if not base64_part:
        raise ValueError("No modulus payload found in signed modulus")
    return base64_part


def concat_bytes(parts: list[bytes]) -> bytes:
    return b"".join(parts)


def sha512_expand(seed: bytes) -> bytes:
    # Same as Proton web: concat SHA512(seed + counter) for counter 0..3.
    blocks = []
    for counter in range(4):
        blocks.append(hashlib.sha512(seed + bytes([counter])).digest())
    return b"".join(blocks)


def normalize_username(value: str) -> str:
    return value.replace(".", "").replace("-", "").replace("_", "").lower()


def bcrypt_base64_encode(data: bytes, length: int) -> str:
    if length <= 0:
        raise ValueError("Illegal length for bcrypt base64 encoding")
    if length > len(data):
        raise ValueError("Requested length exceeds input size")

    output = []
    offset = 0
    while offset < length:
        c1 = data[offset]
        offset += 1
        output.append(BCRYPT_ALPHABET[(c1 >> 2) & 0x3F])
        c1 = (c1 & 0x03) << 4
        if offset >= length:
            output.append(BCRYPT_ALPHABET[c1 & 0x3F])
            break

        c2 = data[offset]
        offset += 1
        c1 |= (c2 >> 4) & 0x0F
        output.append(BCRYPT_ALPHABET[c1 & 0x3F])
        c1 = (c2 & 0x0F) << 2
        if offset >= length:
            output.append(BCRYPT_ALPHABET[c1 & 0x3F])
            break

        c2 = data[offset]
        offset += 1
        c1 |= (c2 >> 6) & 0x03
        output.append(BCRYPT_ALPHABET[c1 & 0x3F])
        output.append(BCRYPT_ALPHABET[c2 & 0x3F])
    return bytes(output).decode("ascii")


def to_bigint_be(raw: bytes) -> int:
    if not raw:
        return 0
    return int.from_bytes(raw, byteorder="big", signed=False)


def to_bigint_le(raw: bytes) -> int:
    return to_bigint_be(raw[::-1])


def to_bytes(value: int, *, order: str = "be", size: int | None = None) -> bytes:
    if value < 0:
        raise ValueError("Negative values are not supported")
    length = max(1, (value.bit_length() + 7) // 8)
    out = value.to_bytes(length, byteorder="big", signed=False)
    if size is not None:
        out = out.rjust(size, b"\x00")
    if order == "le":
        out = out[::-1]
    elif order != "be":
        raise ValueError("order must be 'be' or 'le'")
    return out


def mod(value: int, modulus: int) -> int:
    result = value % modulus
    if result < 0:
        result += modulus
    return result


def srp_password_hash(
    *,
    version: int,
    password: str,
    salt_b64: str | None,
    username: str | None,
    modulus_bytes: bytes,
) -> bytes:
    def t_hash(password_value: str, bcrypt_salt_suffix: str) -> bytes:
        salt = BCRYPT_PREFIX + bcrypt_salt_suffix.encode("ascii")
        hashed = bcrypt.hashpw(password_value.encode("utf-8"), salt)
        return sha512_expand(hashed + modulus_bytes)

    if version in (3, 4):
        if not salt_b64:
            raise ValueError("Missing SRP salt for auth version >=3")
        salt_bytes = base64.b64decode(salt_b64)
        seed = salt_bytes + b"proton"
        if len(seed) != 16:
            raise ValueError("Invalid salt seed length for Proton bcrypt derivation")
        salt_suffix = bcrypt_base64_encode(seed, 16)
        return t_hash(password, salt_suffix)

    if version == 2:
        if not username:
            raise ValueError("Missing username for auth version 2")
        md5_source = normalize_username(username).lower().encode("utf-8")
        suffix = hashlib.md5(md5_source).hexdigest()
        return t_hash(password, suffix)

    if version == 1:
        if not username:
            raise ValueError("Missing username for auth version 1")
        suffix = hashlib.md5(username.lower().encode("utf-8")).hexdigest()
        return t_hash(password, suffix)

    if version == 0:
        if not username:
            raise ValueError("Missing username for auth version 0")
        mix = (username.lower() + password).encode("utf-8")
        legacy = base64.b64encode(hashlib.sha512(mix).digest()).decode("ascii")
        suffix = hashlib.md5(username.lower().encode("utf-8")).hexdigest()
        return t_hash(legacy, suffix)

    raise ValueError(f"Unsupported auth version: {version}")


def generate_safe_client_values(byte_length: int, modulus: int, server_ephemeral: bytes) -> tuple[int, int, int]:
    generator = 2
    for _ in range(1000):
        client_secret = to_bigint_le(secrets.token_bytes(byte_length))
        client_ephemeral = pow(generator, client_secret, modulus)
        client_ephemeral_le = to_bytes(client_ephemeral, order="le", size=byte_length)
        scrambling_param = to_bigint_le(sha512_expand(client_ephemeral_le + server_ephemeral))
        if scrambling_param != 0 and client_ephemeral != 0:
            return client_secret, client_ephemeral, scrambling_param
    raise RuntimeError("Could not generate safe SRP client parameters")


def compute_srp_proofs(auth_info: dict[str, Any], *, username: str, password: str) -> tuple[str, str, str]:
    version = int(auth_info["Version"])
    signed_modulus = auth_info["Modulus"]
    server_ephemeral_b64 = auth_info["ServerEphemeral"]
    srp_session = auth_info["SRPSession"]

    signed_username = auth_info.get("Username")
    if version <= 2 and signed_username and username.lower() != signed_username.lower():
        raise ValueError("Username mismatch with server-provided auth info")

    modulus_payload_b64 = extract_signed_modulus_b64(signed_modulus)
    modulus_bytes = base64.b64decode(modulus_payload_b64)
    server_ephemeral = base64.b64decode(server_ephemeral_b64)
    hashed_password = srp_password_hash(
        version=version,
        password=password,
        salt_b64=auth_info.get("Salt"),
        username=signed_username if version < 3 else None,
        modulus_bytes=modulus_bytes,
    )

    byte_length = 256
    modulus = to_bigint_le(modulus_bytes)
    if len(to_bytes(modulus, order="be")) != byte_length:
        raise ValueError("SRP modulus has incorrect size")

    generator = 2
    multiplier_hash = sha512_expand(to_bytes(generator, order="le", size=byte_length) + modulus_bytes)
    multiplier = to_bigint_le(multiplier_hash)
    server_ephemeral_int = to_bigint_le(server_ephemeral)
    password_int = to_bigint_le(hashed_password)
    modulus_minus_one = modulus - 1
    k_mod = mod(multiplier, modulus)
    if server_ephemeral_int == 0:
        raise ValueError("SRP server ephemeral is out of bounds")

    client_secret, client_ephemeral, scrambling = generate_safe_client_values(
        byte_length, modulus, server_ephemeral
    )
    gx = mod(pow(generator, password_int, modulus) * k_mod, modulus)
    exponent = mod(scrambling * password_int + client_secret, modulus_minus_one)
    base = mod(server_ephemeral_int - gx, modulus)
    shared_session_int = pow(base, exponent, modulus)

    client_ephemeral_bytes = to_bytes(client_ephemeral, order="le", size=byte_length)
    shared_session_bytes = to_bytes(shared_session_int, order="le", size=byte_length)
    client_proof = sha512_expand(client_ephemeral_bytes + server_ephemeral + shared_session_bytes)
    expected_server_proof = sha512_expand(client_ephemeral_bytes + client_proof + shared_session_bytes)

    return (
        base64.b64encode(client_ephemeral_bytes).decode("ascii"),
        base64.b64encode(client_proof).decode("ascii"),
        base64.b64encode(expected_server_proof).decode("ascii"),
    )


def require_json(response: requests.Response, step: str) -> dict[str, Any]:
    try:
        data = response.json()
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{step}: response is not valid JSON") from exc
    return data


def require_success_code(payload: dict[str, Any], step: str) -> None:
    code = payload.get("Code")
    if code != 1000:
        raise RuntimeError(f"{step}: unexpected API code {code} payload={json.dumps(payload)}")


def run_flow(
    email: str,
    password: str,
    *,
    intent: str,
    timeout: float,
    skip_challenge: bool,
    dry_run: bool,
    human_verification_token: str | None,
    human_verification_method: str | None,
) -> int:
    session = requests.Session()
    session.headers.update(
        {
            "accept": ACCEPT,
            "x-pm-appversion": APP_VERSION,
            "x-pm-locale": LOCALE,
            "user-agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
            ),
        }
    )

    if not skip_challenge:
        do_request(
            session,
            name="Challenge login page",
            method="GET",
            url=f"{CHALLENGE_BASE}/challenge/v4/html?Type=0&Name=login&Lang=en-US&Dir=ltr",
            timeout=timeout,
            dry_run=dry_run,
        )
        do_request(
            session,
            name="Challenge unauth page",
            method="GET",
            url=f"{CHALLENGE_BASE}/challenge/v4/html?Type=0&Name=unauth&Lang=en-US&Dir=ltr",
            timeout=timeout,
            dry_run=dry_run,
        )
        do_request(
            session,
            name="Access incoming preflight",
            method="GET",
            url=f"{ACCOUNT_BASE}/api/account/v1/access/incoming",
            timeout=timeout,
            dry_run=dry_run,
        )
        do_request(
            session,
            name="Access outgoing preflight",
            method="GET",
            url=f"{ACCOUNT_BASE}/api/account/v1/access/outgoing",
            timeout=timeout,
            dry_run=dry_run,
        )

    session_headers = {"x-enforce-unauthsession": "true"}
    create_session_resp = do_request(
        session,
        name="Create unauth session",
        method="POST",
        url=f"{ACCOUNT_BASE}/api/auth/v4/sessions",
        headers=session_headers,
        timeout=timeout,
        dry_run=dry_run,
    )

    if dry_run:
        print("Dry-run complete: full flow steps printed.")
        return 0

    create_session_json = require_json(create_session_resp, "Create unauth session")
    require_success_code(create_session_json, "Create unauth session")
    tokens = SessionTokens(
        access_token=create_session_json["AccessToken"],
        refresh_token=create_session_json["RefreshToken"],
        uid=create_session_json["UID"],
    )

    info_headers = default_headers(uid=tokens.uid, include_auth=tokens.access_token)
    auth_info_resp = do_request(
        session,
        name="Get auth info",
        method="POST",
        url=f"{ACCOUNT_BASE}/api/core/v4/auth/info",
        headers=info_headers,
        json_body={"Username": email, "Intent": intent},
        timeout=timeout,
    )
    auth_info = require_json(auth_info_resp, "Get auth info")
    require_success_code(auth_info, "Get auth info")

    client_ephemeral_b64, client_proof_b64, expected_server_proof = compute_srp_proofs(
        auth_info, username=email, password=password
    )

    auth_headers = default_headers(
        uid=tokens.uid,
        include_auth=tokens.access_token,
        human_verification_token=human_verification_token,
        human_verification_method=human_verification_method if human_verification_token else None,
    )
    auth_resp = do_request(
        session,
        name="Submit SRP auth",
        method="POST",
        url=f"{ACCOUNT_BASE}/api/core/v4/auth",
        headers=auth_headers,
        json_body={
            "ClientProof": client_proof_b64,
            "ClientEphemeral": client_ephemeral_b64,
            "SRPSession": auth_info["SRPSession"],
            "Username": email,
            "PersistentCookies": 1,
        },
        timeout=timeout,
    )
    auth_json = require_json(auth_resp, "Submit SRP auth")
    if auth_json.get("Code") == 9001:
        details = auth_json.get("Details", {})
        print("=" * 100)
        print("Human verification required by Proton.")
        print(f"Token: {details.get('HumanVerificationToken')}")
        print(f"Methods: {details.get('HumanVerificationMethods')}")
        print(f"Web URL: {details.get('WebUrl')}")
        print(
            "Re-run with --human-verification-token '<token>' "
            "--human-verification-method captcha after completing verification."
        )
        return 2
    require_success_code(auth_json, "Submit SRP auth")
    server_proof = auth_json.get("ServerProof")
    if server_proof and server_proof != expected_server_proof:
        raise RuntimeError("Server proof mismatch: login response could not be verified.")

    authenticated_tokens = SessionTokens(
        access_token=auth_json.get("AccessToken", tokens.access_token),
        refresh_token=auth_json.get("RefreshToken", tokens.refresh_token),
        uid=auth_json.get("UID", tokens.uid),
    )

    state_token = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24))
    cookie_headers = default_headers(
        uid=authenticated_tokens.uid,
        include_auth=authenticated_tokens.access_token,
    )
    cookie_resp = do_request(
        session,
        name="Exchange refresh token for cookies",
        method="POST",
        url=f"{ACCOUNT_BASE}/api/core/v4/auth/cookies",
        headers=cookie_headers,
        json_body={
            "UID": authenticated_tokens.uid,
            "ResponseType": "token",
            "GrantType": "refresh_token",
            "RefreshToken": authenticated_tokens.refresh_token,
            "RedirectURI": "https://protonmail.com",
            "Persistent": 1,
            "State": state_token,
        },
        timeout=timeout,
    )
    cookie_json = require_json(cookie_resp, "Exchange refresh token for cookies")
    require_success_code(cookie_json, "Exchange refresh token for cookies")

    print("=" * 100)
    print("Login flow completed.")
    print(f"UID: {authenticated_tokens.uid}")
    print(f"SRP Session: {auth_info['SRPSession']}")
    return 0


def main() -> int:
    args = parse_args()
    try:
        email, password = prompt_credentials(args)
        return run_flow(
            email,
            password,
            intent=args.intent,
            timeout=args.timeout,
            skip_challenge=args.skip_challenge,
            dry_run=args.dry_run,
            human_verification_token=args.human_verification_token,
            human_verification_method=args.human_verification_method,
        )
    except Exception as exc:  # pragma: no cover
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
