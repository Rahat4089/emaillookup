# emaillookup

## Proton full login reverse script

`replay_login_from_har.py` executes Proton's real SRP-based login flow and prints
all request/response steps.

Note:
- `access/incoming` and `access/outgoing` preflight calls can return `401` before
  auth; this is expected and does not block login.

### Usage

```bash
python3 replay_login_from_har.py
```

Optional flags:

- `--email <email>` and `--password <password>`: non-interactive credentials
- `--intent Auto|Proton`: auth intent (default: `Proton`)
- `--skip-challenge`: skip pre-login challenge/access calls
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