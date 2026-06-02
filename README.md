# emaillookup

## Ding/Pandora login flow replay

`ding_login_flow.py` replays the HAR-observed mobile API flow:

1. `GET /api/view/bootstrap`
2. `GET /api/session`
3. `POST /api/submitemail`
4. `POST /api/register`
5. authenticated `GET /api/session`
6. authenticated `GET /api/profile`

Edit the hard-coded `EMAIL` and `PASSWORD` constants in the script before
running it:

```bash
python3 ding_login_flow.py
```

The HAR in this repository does not show a client-side password hash or request
signature for `/api/register`; the script generates the UUID `uniqueId` and
`inAuthId` values observed in the request and prints the raw `/api/register`
response.
