# eblannft-sync

Small profile-state sync API for exteraGram/eblanNFT-style local cosmetics.

## API

- `GET /health`
- `GET /v1/profile/{telegram_id}`
- `PUT /v1/profile/me` with `Authorization: Bearer <token>`
- `POST /v1/admin/issue-token` with `X-Admin-Key: <ADMIN_SECRET>`

## Required variables

- `DATABASE_URL` — PostgreSQL URL on Railway
- `ADMIN_SECRET` — private server admin key used only to issue/rotate account tokens
- `TOKEN_PEPPER` — random server-side string mixed into stored token hashes

The server stores only SHA-256 hashes of client tokens, not the plaintext tokens.
