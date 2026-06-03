# Elon Casino login flow (reversed from `main.101751d4.js`)

## Initialization flow

1. App bootstrap (`index.tsx`) calls SDK init with:
   - `baseUrl: /api/v1`
   - `countryCode: BN`
2. API client builds auth headers and sends JSON requests.
3. Fingerprint is initialized (`FingerprintJS`) and placed into `x-fingerprint` header.

## Login endpoint

- Method: `POST`
- URL: `https://elon.casino/api/v1/auth/sign-in/client`
- Payload shape (email login):

```json
{
  "type": "email",
  "email": "<email>",
  "password": "<password>"
}
```

## Headers used by JS flow

- `Content-Type: application/json`
- `x-brand-prefix: <brand-prefix>`
- `x-forwarded-host: https://elon.casino`
- `x-country-code: BN`
- `x-fingerprint: <fingerprint id>`
- `Authorization: Bearer <access-token>` (empty on first sign-in)
- `refresh_token: <refresh-token>` (empty on first sign-in)

## Token flow (from JS)

- Sign-in success returns `accessToken` + `refreshToken`.
- App stores tokens and sets auth header to `Authorization: Bearer <accessToken>`.
- Session restore endpoint: `GET /auth/sign-in/token`
- Refresh endpoint: `POST /auth/sign-in/refresh-token` with body:

```json
{
  "refreshToken": "<refresh-token>"
}
```

## Live test with provided credentials

Credential tested:
- `madigitalstudio2018@gmail.com:01770921730`

Result from endpoint (raw API):
- `HTTP 401`
- Body: `{"message":"bad request","error":"Unauthorized","statusCode":401}`

