#!/usr/bin/env python3
"""Login/register client reconstructed from the supplied Ding HAR capture.

The HAR shows these generated fields:

* ``inAuthId`` and ``uniqueId`` are random 16-byte values formatted with UUID
  hyphens. They do not consistently set RFC UUID version bits.
* ``deviceid`` is the same random UUID-shaped value reused by the device.
* ``apinonce`` is ``android.`` followed by the same UUID-shaped random value.
* ``apihash`` is a 128-character hexadecimal digest, consistent with SHA-512.

The capture proves the field shapes, but it does not contain the client-side
secret/canonicalization needed to reproduce ``apihash`` conclusively. This
client therefore makes the signer configurable through a SHA-512 template or
HMAC-SHA512 template.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping


BASE_URL = "https://pandora.ding.com"
CLIENT_VERSION = "6.1"
CLIENT_CULTURE = "en"
USER_AGENT = f"Ding/{CLIENT_VERSION}"
DEFAULT_DEVICE_ID_PATH = Path.home() / ".ding_deviceid"
SENSITIVE_KEYS = {
    "bearerToken",
    "originalBearerToken",
    "refreshToken",
    "token",
    "password",
}


class DingApiError(RuntimeError):
    """Raised when the Ding API returns an HTTP error."""

    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"Ding API returned HTTP {status}: {body[:500]}")


def random_uuid_like() -> str:
    """Return a random 128-bit value formatted like the IDs in the HAR."""

    value = secrets.token_hex(16)
    return (
        f"{value[:8]}-{value[8:12]}-{value[12:16]}-"
        f"{value[16:20]}-{value[20:]}"
    )


def make_api_nonce() -> str:
    """Return the HAR-observed nonce format: android.<uuid-like-random>."""

    return f"android.{random_uuid_like()}"


def load_or_create_device_id(path: Path) -> str:
    """Persist a stable per-client device ID, matching the captured behavior."""

    if path.exists():
        device_id = path.read_text(encoding="utf-8").strip()
        if device_id:
            return device_id

    device_id = random_uuid_like()
    path.write_text(device_id + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return device_id


def compact_json(data: Mapping[str, Any]) -> str:
    """Serialize request JSON in the compact Android/OkHttp style."""

    return json.dumps(data, separators=(",", ":"), ensure_ascii=False)


def render_template(template: str, values: Mapping[str, str]) -> str:
    """Render a hash template with a small, explicit value set."""

    try:
        return template.format(**values)
    except KeyError as exc:
        available = ", ".join(sorted(values))
        raise ValueError(
            f"Unknown hash template field {exc.args[0]!r}; available: {available}"
        ) from exc


def make_api_hash(
    *,
    method: str,
    path: str,
    body: str,
    nonce: str,
    device_id: str,
    secret: str,
    hash_template: str,
    hmac_template: str | None,
    bearer_token: str,
) -> str:
    """Create the apihash value using the configured SHA-512 signer."""

    values = {
        "method": method.upper(),
        "path": path,
        "body": body,
        "nonce": nonce,
        "deviceid": device_id,
        "secret": secret,
        "bearer": bearer_token,
        "clientversion": CLIENT_VERSION,
        "clientculture": CLIENT_CULTURE,
    }

    if hmac_template is not None:
        message = render_template(hmac_template, values)
        return hmac.new(
            secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha512
        ).hexdigest()

    message = render_template(hash_template, values)
    return hashlib.sha512(message.encode("utf-8")).hexdigest()


def redact(value: Any) -> Any:
    """Return a copy of JSON-like data with token/password values hidden."""

    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if key in SENSITIVE_KEYS:
                redacted[key] = f"<redacted len={len(str(item))}>"
            else:
                redacted[key] = redact(item)
        return redacted
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class DingClient:
    """Small client for the login/registration flow visible in the HAR."""

    def __init__(
        self,
        *,
        base_url: str,
        device_id: str,
        api_secret: str,
        hash_template: str,
        hmac_template: str | None,
        dry_run: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.device_id = device_id
        self.api_secret = api_secret
        self.hash_template = hash_template
        self.hmac_template = hmac_template
        self.dry_run = dry_run

    def register(
        self,
        *,
        email: str,
        password: str,
        receive_emails: bool,
        bearer_token: str = "",
    ) -> Mapping[str, Any]:
        """POST /api/register and return the parsed JSON response."""

        payload = {
            "email": email,
            "fType": "RegistrationSubmitted",
            "inAuthId": random_uuid_like(),
            "password": password,
            "receiveEmails": receive_emails,
            "trackingData": [],
            "uniqueId": random_uuid_like(),
        }
        return self.request(
            "POST", "/api/register", payload=payload, bearer_token=bearer_token
        )

    def session(self, bearer_token: str) -> Mapping[str, Any]:
        """GET /api/session with a bearer token from the register response."""

        return self.request("GET", "/api/session", bearer_token=bearer_token)

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        bearer_token: str = "",
    ) -> Mapping[str, Any]:
        """Send a signed request to the Ding API."""

        body = compact_json(payload) if payload is not None else ""
        nonce = make_api_nonce()
        api_hash = make_api_hash(
            method=method,
            path=path,
            body=body,
            nonce=nonce,
            device_id=self.device_id,
            secret=self.api_secret,
            hash_template=self.hash_template,
            hmac_template=self.hmac_template,
            bearer_token=bearer_token,
        )

        headers = {
            "clientculture": CLIENT_CULTURE,
            "clientversion": CLIENT_VERSION,
            "authorization": f"Bearer {bearer_token}" if bearer_token else "",
            "apinonce": nonce,
            "apihash": api_hash,
            "deviceid": self.device_id,
            "user-agent": USER_AGENT,
            "accept-encoding": "gzip",
        }
        data = None
        if body:
            data = body.encode("utf-8")
            headers["content-type"] = "application/json; charset=UTF-8"

        if self.dry_run:
            preview = {
                "method": method.upper(),
                "url": self.base_url + path,
                "headers": {
                    **headers,
                    "authorization": "<redacted>" if bearer_token else "",
                    "apihash": f"<sha512 hex len={len(api_hash)}>",
                    "deviceid": f"<redacted len={len(self.device_id)}>",
                    "apinonce": f"<redacted len={len(nonce)}>",
                },
                "json": redact(payload or {}),
            }
            print(json.dumps(preview, indent=2, sort_keys=True))
            return {"dryRun": True}

        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method=method.upper(),
        )

        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                response_body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            raise DingApiError(exc.code, error_body) from exc

        if not response_body:
            return {}
        return json.loads(response_body)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Perform the Ding /api/register auth flow reconstructed from HAR."
    )
    parser.add_argument("--email", default=os.getenv("DING_EMAIL"))
    parser.add_argument("--password", default=os.getenv("DING_PASSWORD"))
    parser.add_argument("--base-url", default=os.getenv("DING_BASE_URL", BASE_URL))
    parser.add_argument(
        "--device-id",
        default=os.getenv("DING_DEVICE_ID"),
        help="Stable deviceid. If omitted, one is persisted locally.",
    )
    parser.add_argument(
        "--device-id-file",
        type=Path,
        default=Path(os.getenv("DING_DEVICE_ID_FILE", DEFAULT_DEVICE_ID_PATH)),
        help=f"Path used to persist generated deviceid (default: {DEFAULT_DEVICE_ID_PATH}).",
    )
    parser.add_argument(
        "--api-secret",
        default=os.getenv("DING_API_SECRET", ""),
        help="Client-side signing secret, if the apihash recipe requires one.",
    )
    parser.add_argument(
        "--hash-template",
        default=os.getenv("DING_HASH_TEMPLATE", "{secret}{nonce}{body}"),
        help=(
            "Plain SHA-512 input template. Available fields: method, path, body, "
            "nonce, deviceid, secret, bearer, clientversion, clientculture."
        ),
    )
    parser.add_argument(
        "--hmac-template",
        default=os.getenv("DING_HMAC_TEMPLATE"),
        help=(
            "If set, use HMAC-SHA512 with --api-secret as key and this template "
            "as the message instead of plain SHA-512."
        ),
    )
    parser.add_argument(
        "--bearer-token",
        default=os.getenv("DING_BEARER_TOKEN", ""),
        help="Optional existing bearer token to include on the register request.",
    )
    parser.add_argument(
        "--no-marketing",
        action="store_true",
        help="Send receiveEmails=false in the registration payload.",
    )
    parser.add_argument(
        "--session",
        action="store_true",
        help="After register succeeds, call /api/session using access.bearerToken.",
    )
    parser.add_argument(
        "--show-token",
        action="store_true",
        help="Print tokens in responses. By default tokens and passwords are redacted.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the redacted request instead of sending it.",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    email = args.email or input("Email: ").strip()
    password = args.password or getpass.getpass("Password: ")
    device_id = args.device_id or load_or_create_device_id(args.device_id_file)

    client = DingClient(
        base_url=args.base_url,
        device_id=device_id,
        api_secret=args.api_secret,
        hash_template=args.hash_template,
        hmac_template=args.hmac_template,
        dry_run=args.dry_run,
    )

    try:
        result = client.register(
            email=email,
            password=password,
            receive_emails=not args.no_marketing,
            bearer_token=args.bearer_token,
        )
        output: dict[str, Any] = {"register": result}

        token = (
            result.get("access", {}).get("bearerToken")
            if isinstance(result.get("access"), dict)
            else None
        )
        if args.session and token:
            output["session"] = client.session(str(token))

        printable = output if args.show_token else redact(output)
        print(json.dumps(printable, indent=2, sort_keys=True))
    except DingApiError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
