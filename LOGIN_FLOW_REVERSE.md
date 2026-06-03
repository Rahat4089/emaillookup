# Elon Casino login flow (reversed from `main.101751d4.js`)

## Initialization flow

1. App bootstrap (`index.tsx`) calls SDK init with:
   - `baseUrl: /api/v1`
   - `countryCode: BN`
2. SDK resolves brand settings from:
   - `GET /casino/brand-info`
3. API client builds auth headers and sends JSON requests.
4. Fingerprint is initialized (`FingerprintJS`) and placed into `x-fingerprint` header.

## Login endpoint

- Method: `POST`
- URL: `https://elon.casino/api/v1/auth/sign-in/client`

### Payload variants accepted by validator

`type` must be one of: `email | phone | quick | token | oauth`

Email login payload:

```json
{
  "type": "email",
  "email": "<email>",
  "password": "<password>"
}
```

Quick login payload:

```json
{
  "type": "quick",
  "username": "<username>",
  "password": "<password>"
}
```

Phone login payload:

```json
{
  "type": "phone",
  "phone": "+<country-code><number>",
  "password": "<password>"
}
```

## Headers used by JS flow

- `Content-Type: application/json`
- `Accept: application/json, text/plain, */*`
- `Origin: https://elon.casino`
- `Referer: https://elon.casino/casino/`
- `x-brand-prefix: <brand-prefix>` (fetched from `/casino/brand-info`)
- `x-forwarded-host: https://elon.casino`
- `x-country-code: BN` (from app init)
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

## Live tests with provided credential

Credential tested:
- `madigitalstudio2018@gmail.com:01770921730`

Observed responses:
- `type=email` -> `HTTP 401 Unauthorized`
- `type=quick` (username=email and username=madigitalstudio2018) -> `HTTP 401 Unauthorized`
- `type=phone` (`+8801770921730`) -> `HTTP 401 Unauthorized`

Raw body for unauthorized responses:

```json
{"message":"bad request","error":"Unauthorized","statusCode":401}
```

