# E2E OIDC Dummy Provider

This project is a **configurable OpenID Connect (OIDC) provider simulator** written in Python using Flask.

---

## Purpose

- Provide a JSON-driven **mock OIDC IdP** to test the Questel cascade (or any custom client).
- Enable **end-to-end testing** of the `authorization_code` flow described in `MANUAL_TESTING_GUIDE.md`.
- Offer a reference implementation for the `/authorize → /token → /userinfo` exchanges.

This service is strictly for **testing** and must not be used in production.

---

## Features

- **OIDC Discovery**: `/.well-known/openid-configuration`
- **JWKS endpoint**: `/jwks.json` (HS256 symmetric key exposed for testing)
- **Authorization Code Flow**:
  - `/authorize` → auto-approves by default (no form) but you can enforce the form with `prompt=login`
  - `/login` → generates a short-lived authorization code
  - `/token` → authenticates the client (Basic Auth or form) and returns:
    - `access_token` (server-side session token)
    - `id_token` signed with HS256 (Questel-aligned claims)
    - `userinfo` payload mirroring the `/userinfo` endpoint
  - `/userinfo` → returns claims for a given access token
- **Callback helper**: `/callback` for quick manual inspection
- **Healthcheck**: `/selfTest`
- **Dynamic configuration**:
  - via `OIDC_CLIENTS_JSON` or `OIDC_CLIENTS_FILE`
  - per-client email domains, redirect URIs, services, rights, default claims
- **Always-positive mode**: by default the mock is lenient and keeps responding with success even if inputs are invalid; set `OIDC_STRICT_VALIDATION=true` to enforce hard failures.

---

## Requirements

- Python 3.9+
- Flask & PyJWT (installed via the requirements file)

Install dependencies (virtualenv recommended):

```bash
pip install -r requirements.txt
```

---

## Run

```bash
python main.py
# or
FLASK_ENV=development OIDC_CLIENTS_FILE=clients.json python main.py
```

The server listens on **http://0.0.0.0:5000** by default (override with `PORT`).

---

## Configuration

Define OIDC clients through an environment variable or JSON file:

```json
{
  "test-questel-client": {
    "client_secret": "test-questel-secret",
    "redirect_uris": [
      "http://localhost:8080/oidc/external/callback"
    ],
    "allowed_email_domains": ["questel.com"],
    "display_name": "Questel Mock IdP",
    "default_account_name": "Questel Test Account",
    "default_services": ["EQCORPORATEPLUS"],
    "default_rights": ["read", "write"],
    "scopes": ["openid", "profile", "email", "account", "services", "rights"]
  }
}
```

- `OIDC_CLIENTS_JSON`: inline JSON payload.
- `OIDC_CLIENTS_FILE`: path to a JSON file (takes precedence).
- `OIDC_SIGNING_KEY`: HS256 symmetric key used for `id_token` signing.
- `OIDC_ISSUER`: issuer URL (default `http://localhost:5000`).
- `OIDC_CODE_TTL`, `OIDC_ACCESS_TOKEN_TTL`: TTL in seconds.
- `OIDC_STRICT_VALIDATION`: set to `true` to enable strict error handling. Default is `false`, meaning the mock stays positive and auto-corrects invalid inputs whenever possible.
- `OIDC_AUTO_APPROVE`: set to `false` to re-enable the manual login form. Default is `true`, which auto-issues a code using the default (or query-provided) email.

> Without custom configuration, the built-in `test-questel-client` (redirect URI `http://localhost:8080/oidc/external/callback`) is ready to use and aligned with the manual testing guide.

## Endpoints Documentation

### 1. Discovery Document
```
GET /.well-known/openid-configuration
```
Returns OIDC metadata including endpoints and supported claims.

### 2. JWKS
```
GET /jwks.json
```
Returns a dummy JWKS key set (for testing only).

### 3. Authorize
```
GET /authorize?client_id=test-questel-client&redirect_uri=http://localhost:8080/oidc/external/callback&scope=openid%20profile%20email&state=12345&nonce=abc
```
- Auto-approves and redirects immediately with an authorization code (uses the default email unless you pass `&email=<user@questel.com>`).
- Add `prompt=login` to force the HTML form for manual testing.
- Validates the redirect URI against the client configuration (or falls back in lenient mode).

### 4. Login
```
POST /login
```
- Processes the form, verifies the email domain (or auto-fixes it), then redirects back with `code` + `state`.

### 5. Token
```
POST /token
```
Expected fields:
- `grant_type=authorization_code`
- `code`
- Optional `redirect_uri`
- Client authentication:
  - `Authorization: Basic base64(client_id:client_secret)` **or**
  - `client_id` + `client_secret` form params.

Response:
- `access_token` stored server-side (later consumed by `/userinfo`)
- `id_token` signed with HS256
- `userinfo` inline payload

### 6. Userinfo
```
GET /userinfo
Authorization: Bearer <access_token>
```
Returns claims derived from the client defaults and requested scopes.

### 7. Callback
```
GET /callback?code=...&state=...
```
Utility endpoint to quickly inspect callback parameters.

---

## Example Flow (aligned with `MANUAL_TESTING_GUIDE.md`)

1. **Provision on the SSO side**
   - Create (or reuse) an `UM_ACCOUNT` with `auth_mode=OIDC` and an `UM_USER` entry matching the email you will use in the mock IdP
   - Insert an `UM_OIDCCONFIG` pointing to this mock (`issuer=http://localhost:5000`, `authorization_endpoint=http://localhost:5000/authorize`, etc.)
   - Ensure the OAuth client `test-oidc-cascade-client` has `redirect_uri=http://localhost:8079/callback`
2. **External authentication**
   - Browse to the `/authorize` URL generated by the SSO (the mock immediately returns with a code).
   - Need a manual step? Append `prompt=login` to display the form instead.
3. **Callback back to SSO**
   - Redirection to `http://localhost:8080/oidc/external/callback?code=...&state=...`.
4. **Code exchange**
   ```bash
   curl -u test-questel-client:test-questel-secret \
     -d "grant_type=authorization_code" \
     -d "code=<code>" \
     -d "redirect_uri=http://localhost:8080/oidc/external/callback" \
     http://localhost:5000/token
   ```
5. **Userinfo**
   ```bash
   curl -H "Authorization: Bearer <access_token>" http://localhost:5000/userinfo
   ```

---

## Security & Limitations

- Redirect URI and email validation are configurable; lenient mode keeps answers positive by falling back to defaults whenever possible.
- `id_token` uses HS256 with the shared key exposed via JWKS (test only).
- Access tokens/codes live purely in memory with configurable TTLs.
- No refresh tokens, user consent, MFA, or real persistence → testing only.

---

## Notes

- Local use only.
- You can extend it to other signing algorithms if needed (`SIGNING_ALG` + matching key material).
- Works seamlessly with `docker-compose up` (port 5000 exposed).

---

## User catalog

- The file `users.json` (same directory) centralizes the mock identities.
- Each entry exposes `id`, `email`, `firstname`, `lastname`, `account`, `services`, `rights`, `notes`.
- The catalog is served at `GET /users.json` so other tools (mock-client-rp, scripts) can consume it live.
- Configure an alternate catalog via `MOCK_IDP_USER_CATALOG=/path/to/users.json`.
- Set `MOCK_IDP_USER_CATALOG_AUTO_RELOAD=true` to reload the catalog automatically on each request (useful when editing the JSON while the container is running).
- `notes` highlights whether the identity already exists in UMv2 or must be auto-provisioned by `ExternalOIDCProvisioningService`.
