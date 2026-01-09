# Mock Users API — Temporary DELETE (TTL)

Adds **temporary delete** support without changing existing functionality:
- `DELETE /deleteUser/:id` — temporarily hides a **base user** for the TTL window (default **10 minutes**).
- `DELETE /deleteUser` — same as above but accepts `{ id }` in JSON body.
- `GET /users` and `GET /getUser` immediately reflect the deletion (list shows **9** base users; plus any temp-created users).
- After TTL expires, the user **reappears** automatically.
- Existing permanent delete for temp-created users remains: `DELETE /users/:id` → **204 No Content** (base users are forbidden).

## Quick Start
```bash
npm install
cp .env.example .env
npm start
# http://localhost:3000
```

## Environment Variables
```
PORT=3000
API_KEY=dev-key-123
STRICT_PARAMS=false
TTL_MINUTES=10
```

## cURL Examples
> Replace API key if you changed `.env`.

### Temporary delete by route param
```bash
curl -X DELETE http://localhost:3000/deleteUser/2   -H "x-api-key: dev-key-123"
```
Response (200):
```json
{ "status": 200, "message": "User temporarily deleted", "ttlMinutes": 10, "expiresAt": 1736050000000, "data": { "id": 2 } }
```

### Temporary delete by body
```bash
curl -X DELETE http://localhost:3000/deleteUser   -H "Content-Type: application/json" -H "x-api-key: dev-key-123"   -d '{"id":2}'
```

### Verify deletion reflected
```bash
curl http://localhost:3000/users
curl -H "x-api-key: dev-key-123" http://localhost:3000/getUser
```

### After TTL — user reappears
> For quick testing set `TTL_MINUTES=1` and restart.
```bash
curl http://localhost:3000/users   # user 2 hidden
sleep 60
curl http://localhost:3000/users   # user 2 visible again
```

### Permanent delete (temp-created user only)
```bash
# Suppose you created id 11 via POST /createUser
curl -X DELETE http://localhost:3000/users/11 -H "x-api-key: dev-key-123"  # -> 204
```

## Validations & Status Codes
- `401` if missing/invalid `x-api-key` (for delete endpoints)
- `400` if `id` invalid (non-integer or ≤ 0)
- `404` if trying to temporarily delete a non-base user
- `200` on successful temporary delete with `{ ttlMinutes, expiresAt, data: { id } }`
- `204` on permanent delete of temp-created users
- `403` when attempting permanent delete of base users via `DELETE /users/:id`

## Notes
- Storage is in-memory. All temporary deletions/overrides/users clear on restart.
- ETag caching remains active on GETs; if the list changes due to temp delete, you’ll get **200** (new ETag) rather than **304**.
- No existing functionality was changed; new endpoints are additive.
