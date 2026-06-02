# emaillookup

## Ding HAR login notes

The supplied HAR contains the Ding mobile API flow against
`https://pandora.ding.com`. The credential-bearing request in the capture is
`POST /api/register`; its response contains `access.bearerToken`, which is then
used as the bearer token for requests such as `GET /api/session`.

Reversed field shapes from the HAR:

- `inAuthId`: random 16-byte UUID-shaped value.
- `uniqueId`: random 16-byte UUID-shaped value.
- `deviceid`: stable UUID-shaped device value reused across requests.
- `apinonce`: `android.` plus a random UUID-shaped value.
- `apihash`: 128 lowercase hex characters, consistent with SHA-512 or
  HMAC-SHA512. The HAR proves the output shape, but not the hidden client-side
  secret/canonicalization required to reproduce it.

`ding_login.py` implements this flow without embedding captured credentials,
tokens, or hashes. It generates fresh IDs/nonces and lets you configure the
`apihash` signer.

```bash
python3 ding_login.py \
  --email user@example.com \
  --password 'your-password' \
  --api-secret 'client-signing-secret' \
  --hash-template '{secret}{nonce}{body}' \
  --session
```

For HMAC-SHA512 signing, pass `--hmac-template` instead of relying on the plain
SHA-512 template:

```bash
python3 ding_login.py \
  --email user@example.com \
  --password 'your-password' \
  --api-secret 'client-signing-secret' \
  --hmac-template '{method}{path}{body}{nonce}' \
  --session
```

Use `--dry-run` to print a redacted request without sending it. By default the
script redacts tokens and passwords in output; use `--show-token` only when you
need to inspect the raw API token locally.