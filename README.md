# emaillookup

## Proton full login reverse script

`replay_login_from_har.py` executes Proton's real SRP-based login flow and prints
all request/response steps.

The script now uses only required endpoints for login plus account-info capture:
- `POST /api/auth/v4/sessions`
- `POST /api/core/v4/auth/info`
- `POST /api/core/v4/auth`
- `POST /api/core/v4/auth/cookies`
- `GET /api/core/v4/users`
- `GET /api/core/v4/settings`
- `GET /api/core/v4/addresses?Page=0&PageSize=50`

All requests are sent with TLS verification disabled (`verify=False`).

### Usage

```bash
python3 replay_login_from_har.py
```

Optional flags:

- `--email <email>` and `--password <password>`: non-interactive credentials
- `--intent Auto|Proton`: auth intent (default: `Proton`)
- `--dry-run`: print all planned login steps without sending requests
- `--human-verification-token <token>`: optional CAPTCHA verification token
- `--human-verification-method <method>`: token method header (default: `captcha`)

Example:

```bash
python3 replay_login_from_har.py \
  --email "you@example.com" \
  --password "your-password" \
  --dry-run
```

Dependency:

```bash
python3 -m pip install bcrypt
```