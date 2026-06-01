# emaillookup

## HAR login replay script

`replay_login_from_har.py` replays login-related HTTP requests captured in a HAR
file and prints each response.

### Usage

```bash
python3 replay_login_from_har.py
```

Optional flags:

- `--har <path>`: HAR file path
- `--mode login|all`: replay only login requests (default: `login`) or all
  requests from the HAR
- `--email <email>` and `--password <password>`: non-interactive credentials
- `--dry-run`: print requests without sending them

Example:

```bash
python3 replay_login_from_har.py \
  --har account-api.proton.me_2026_06_01_18_34_28.har \
  --mode login \
  --dry-run
```