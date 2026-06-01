# Proton login flow from the HAR

The capture is for `account.proton.me` and shows Proton's web-account login.
The account password is not sent to Proton. Instead, the browser performs SRP
(Secure Remote Password) v4 locally and submits proof values that let Proton
verify the password without receiving it.

## High-level sequence

1. **Session bootstrap**
   - `POST /api/auth/v4/sessions`
   - Returns a temporary `UID`, `AccessToken`, and `RefreshToken` for the web
     auth session.

2. **Optional child/local browser session setup**
   - `POST /api/auth/v4/sessions/forks`
   - `GET|PUT /api/auth/v4/sessions/local/key`
   - `POST /api/auth/v4/sessions/payload`
   - These requests are web-client state management. The `Key` is a
     client-generated browser-local key and `Payload` is opaque encrypted
     session state. This is separate from the password proof.

3. **Cookie exchange**
   - `POST /api/core/v4/auth/cookies`
   - The HAR does this right after the anonymous session is created, using the
     bootstrap refresh token. The browser receives `AUTH-*` web cookies, then
     the same session is upgraded by the SRP proof.

4. **SRP challenge lookup**
   - `POST /api/core/v4/auth/info`
   - Request body includes `Username` and `Intent`.
   - Response includes:
     - `Version`: SRP version, `4` in this HAR.
     - `Salt`: password-hash salt.
     - `Modulus`: PGP clear-signed SRP modulus.
     - `ServerEphemeral`: SRP server public value.
     - `SRPSession`: challenge/session identifier.

5. **Client-side password proof**
   - The client derives a password hash:
     - decode `Salt`
     - append the ASCII string `proton`
     - bcrypt the UTF-8 password with cost `10` and Proton's bcrypt base64
       alphabet
     - SHA-512 expand the bcrypt output plus SRP modulus
   - The client generates a random SRP secret, computes `ClientEphemeral`, the
     shared SRP secret, `ClientProof`, and expected `ServerProof`.

6. **SRP authentication**
   - `POST /api/core/v4/auth`
   - Request body includes `Username`, `ClientProof`, `ClientEphemeral`,
     `SRPSession`, and `PersistentCookies`.
   - Response includes `ServerProof`. The client must compare it with the
     locally computed expected server proof.

7. **Authenticated account requests**
   - `GET /api/core/v4/users`
   - `GET /api/core/v4/keys/salts`
   - These happen after authentication. The key salts are used later when the
     web client decrypts Proton account keys locally.

## Script

`proton_login_flow.py` implements the SRP portion and the web cookie exchange.
It intentionally reads credentials from environment variables or prompts:

```bash
python3 -m pip install -r requirements.txt

python3 proton_login_flow.py \
  --har account-api.proton.me_2026_06_01_18_34_28.har

PROTON_USERNAME="user@example.com" PROTON_PASSWORD="..." \
  python3 proton_login_flow.py --live-login --fetch-user
```

The script does not hardcode or print access tokens, refresh tokens, cookies, or
passwords.
