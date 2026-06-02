#!/usr/bin/env python3
"""Reverse-engineered FashionGo login payload runner.

This script reproduces the browser-side login flow captured in the HAR:
1) Fetch RSA key metadata from /crypto/key
2) AES-encrypt the plaintext password
3) RSA-encrypt the AES passphrase, then base64-encode that RSA hex output
4) POST the login payload to id.fashiongo.net

It prompts for email/password and prints the raw HTTP response.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys
from getpass import getpass
from typing import Any

import requests
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY_ENDPOINT = "https://www.fashiongo.net/crypto/key"
LOGIN_ENDPOINT = "https://id.fashiongo.net/api/auth/login"


def generate_hex_string(length: int = 32) -> str:
    """Generate a lowercase hex string with exactly the requested length."""
    if length <= 0:
        raise ValueError("length must be positive")
    token = secrets.token_hex((length + 1) // 2)
    return token[:length]


def aes_encrypt_password(password: str, passphrase: str) -> str:
    """Mirror CryptoJS AES.encrypt(plain, key, {iv}) behavior from login JS."""
    key = passphrase.encode("latin1")
    iv = passphrase[:16].encode("latin1")
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(password.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode("ascii")


def rsa_encrypt_passphrase(passphrase: str, modulus_hex: str, exponent_hex: str) -> str:
    """Replicate js rsa.encrypt() + btoa(hexCiphertext) format."""
    n = int(modulus_hex, 16)
    e = int(exponent_hex, 16)
    public_key = rsa.RSAPublicNumbers(e, n).public_key()
    encrypted_bytes = public_key.encrypt(passphrase.encode("utf-8"), asym_padding.PKCS1v15())

    # JS path returns ciphertext as hex text (possibly without full-length leading zeros),
    # then applies btoa() to that hex string.
    encrypted_hex = format(int.from_bytes(encrypted_bytes, byteorder="big"), "x")
    if len(encrypted_hex) % 2 != 0:
        encrypted_hex = "0" + encrypted_hex

    return base64.b64encode(encrypted_hex.encode("ascii")).decode("ascii")


def fetch_crypto_key(session: requests.Session, is_default: bool) -> dict[str, Any]:
    """Fetch keyId/modulus/exponent from the same endpoint used by browser JS."""
    headers = {
        "accept": "application/json, text/javascript, */*; q=0.01",
        "referer": "https://www.fashiongo.net/login?returnUrl=/",
        "x-requested-with": "XMLHttpRequest",
        "user-agent": "Mozilla/5.0",
    }
    params = {
        "default": str(is_default).lower(),
        "type": "GET",
        "dataType": "json",
        "contentType": "application/json",
        "mimeType": "application/json",
    }
    response = session.get(KEY_ENDPOINT, headers=headers, params=params, timeout=30)
    response.raise_for_status()
    body = response.json()
    if not body.get("success"):
        raise RuntimeError(f"Key endpoint returned unsuccessful response: {body}")
    data = body.get("data") or {}
    required = ("keyId", "modulus", "exponent")
    if not all(data.get(k) for k in required):
        raise RuntimeError(f"Missing expected key fields. Received: {body}")
    return data


def build_login_payload(
    session: requests.Session, email: str, password: str, is_default: bool
) -> dict[str, str]:
    """Create the exact payload shape expected by /api/auth/login."""
    key_data = fetch_crypto_key(session, is_default=is_default)
    passphrase = generate_hex_string(32)
    encrypted_password = aes_encrypt_password(password, passphrase)
    encrypted_passphrase = rsa_encrypt_passphrase(
        passphrase=passphrase,
        modulus_hex=key_data["modulus"],
        exponent_hex=key_data["exponent"],
    )
    return {
        "userName": email,
        "password": encrypted_password,
        "secureKey": key_data["keyId"],
        "passphrase": encrypted_passphrase,
    }


def do_login(
    session: requests.Session, payload: dict[str, str], return_url: str
) -> requests.Response:
    """Send login request with browser-like headers and query params."""
    headers = {
        "accept": "application/json, text/javascript, */*; q=0.01",
        "content-type": "application/json; charset=UTF-8",
        "origin": "https://www.fashiongo.net",
        "referer": "https://www.fashiongo.net/",
        "referer-application-type": "FgWeb",
        "user-agent": "Mozilla/5.0",
    }
    params = {"returnUrl": return_url}
    return session.post(LOGIN_ENDPOINT, headers=headers, params=params, json=payload, timeout=30)


def extract_result_message(response: requests.Response) -> str | None:
    """Safely read header.resultMessage from JSON response."""
    try:
        body = response.json()
    except ValueError:
        return None
    header = body.get("header") if isinstance(body, dict) else None
    if isinstance(header, dict):
        msg = header.get("resultMessage")
        if isinstance(msg, str):
            return msg
    return None


def print_raw_response(response: requests.Response) -> None:
    """Print status line, headers, and unmodified response body text."""
    print("\n=== RAW RESPONSE ===")
    print(f"HTTP {response.status_code} {response.reason}")
    print("\n--- Headers ---")
    for k, v in response.headers.items():
        print(f"{k}: {v}")
    print("\n--- Body ---")
    print(response.text)


def prompt_non_empty(label: str, secret: bool = False) -> str:
    """Prompt until a non-empty value is provided."""
    while True:
        value = getpass(f"{label}: ") if secret else input(f"{label}: ")
        if value.strip():
            return value.strip() if not secret else value
        print(f"{label} cannot be empty. Please try again.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prompt for credentials, build reversed login payload, and print raw response."
    )
    parser.add_argument("--email", help="Email/username (if omitted, script will prompt).")
    parser.add_argument("--password", help="Password (if omitted, script will prompt securely).")
    parser.add_argument(
        "--return-url",
        default="/",
        help="returnUrl query value to pass to the login API (default: /).",
    )
    parser.add_argument(
        "--no-retry-default-key",
        action="store_true",
        help="Disable fallback retry with default=true key when decryption fails.",
    )
    args = parser.parse_args()

    email = args.email.strip() if args.email else prompt_non_empty("Email")
    password = args.password if args.password else prompt_non_empty("Password", secret=True)

    session = requests.Session()

    try:
        payload = build_login_payload(session, email, password, is_default=False)
        print("\n=== LOGIN PAYLOAD (default=false) ===")
        print(json.dumps(payload, indent=2))
        response = do_login(session, payload, args.return_url)
        print_raw_response(response)

        if not args.no_retry_default_key:
            result_message = extract_result_message(response)
            if result_message == "Password decryption failed. Please try again!":
                print("\nPassword decryption failed with default=false key. Retrying with default=true...")
                payload = build_login_payload(session, email, password, is_default=True)
                print("\n=== LOGIN PAYLOAD (default=true retry) ===")
                print(json.dumps(payload, indent=2))
                response = do_login(session, payload, args.return_url)
                print_raw_response(response)

    except requests.RequestException as exc:
        print(f"Network/HTTP error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
