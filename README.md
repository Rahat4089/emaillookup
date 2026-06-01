# emaillookup

## Proton full login reverse script

`replay_login_from_har.py` executes Proton's real SRP-based login flow and prints
all request/response steps.

### Usage

```bash
python3 replay_login_from_har.py
```

Optional flags:

- `--email <email>` and `--password <password>`: non-interactive credentials
- `--intent Auto|Proton`: auth intent (default: `Proton`)
- `--skip-challenge`: skip pre-login challenge/access calls
- `--dry-run`: print all planned login steps without sending requests

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