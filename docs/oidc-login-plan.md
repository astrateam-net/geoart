# Native OIDC login with server-side sessions (Plan)

## Why this exists

`DEKART_REQUIRE_OIDC` trusts a JWT that a reverse proxy puts in `X-Forwarded-Access-Token`. The
header plan kept login out of Dekart on purpose ("Don't implement OIDC login redirects inside
Dekart"). Device tokens arrived a month later and changed the trade-off:

- `dekart init`, `dekart tools` and the GeoSQL MCP server send `Authorization: Bearer <device token>`.
  Header mode never reads `Authorization`, so they get 401 (Amazon mode had the same gap, fixed in #346).
- The proxy in front refuses every request without its cookie, including `POST /api/v1/device`, so
  the CLI cannot even start the device flow. Making it work means routing exceptions per path in
  the proxy, and every new non-browser endpoint repeats that.
- Snapshots load `/reports/{id}/snapshot?snapshot_token=…` in a headless browser with no cookie; the
  proxy redirects it to the IdP.

When Dekart owns login, nothing sits in front of it, and every client is checked in one place.

## Goal

Add an auth mode where Dekart performs the OIDC authorization code flow itself and keeps a
server-side session, the way Grafana (`pkg/services/authn`, `user_auth_token`) and Coder
(`coderd/httpmw/apikey.go`, `api_keys`) do:

- Any OIDC provider through discovery (`<issuer>/.well-known/openid-configuration`): Keycloak,
  Authentik, Okta, Entra, Auth0.
- PKCE (S256), `state` and `nonce` on every login.
- The browser holds only an opaque, HttpOnly session cookie. IdP tokens never reach the browser.
- Session lifetime is Dekart's own, independent of the IdP access token lifetime.
- The IdP refresh token is stored encrypted and used server-side; a failed refresh ends the session,
  so disabling a user in the IdP reaches Dekart.
- Device tokens and snapshot tokens keep working unchanged.

## Non-goals

- Role or group mapping from IdP claims. Membership stays in Dekart's UI.
- Changing `DEKART_REQUIRE_OIDC` (header mode). It keeps working as today.
- Redis or any session store besides the metadata database.
- Cross-origin UI hosting with cookies (`VITE_API_HOST` on another origin). Production serves UI and
  API from one origin.

## Environment variables

| Name | Required | Description |
| --- | --- | --- |
| `DEKART_REQUIRE_OIDC_LOGIN` | yes | `1` enables the mode. Mutually exclusive with the other `DEKART_REQUIRE_*` modes. Requires the SSO license key. |
| `DEKART_OIDC_ISSUER` | yes | Issuer URL. Endpoints and JWKS come from discovery. Already used by header mode. |
| `DEKART_OIDC_CLIENT_ID` | yes | OAuth client ID. Also the expected ID token audience. |
| `DEKART_OIDC_CLIENT_SECRET` | no | Confidential clients only. Public clients rely on PKCE. |
| `DEKART_OIDC_SCOPES` | no | Default `openid email profile offline_access`. `offline_access` asks for a refresh token. |
| `DEKART_OIDC_TOKEN_KEY` | yes | Base64 32-byte key, AES-256-GCM encryption of stored refresh tokens. |

Redirect URI to register at the provider: `<DEKART_APP_URL>/api/v1/oidc/callback`.

Lifetimes are constants, matching Grafana's defaults: session expires after 7 days without use and
30 days after login; `last_used_at` is written at most once an hour.

## Data model

One migration, in `migrations/` and `sqlite/migrations/`:

```sql
CREATE TABLE IF NOT EXISTS oidc_sessions (
    id TEXT PRIMARY KEY,               -- sha256 of the cookie value; the raw value is never stored
    email TEXT NOT NULL,
    subject TEXT NOT NULL,             -- ID token `sub`
    refresh_token TEXT,                -- AES-256-GCM, base64; NULL when the provider issued none
    id_token TEXT,                     -- AES-256-GCM; sent as id_token_hint on logout (migration 000058)
    idp_expires_at TIMESTAMP NOT NULL, -- expiry of the IdP access token from the last exchange
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_sessions_expires_at ON oidc_sessions (expires_at);
```

## Request flow

```text
GET  /api/v1/oidc/login?redirect=/reports/…
     → short-lived HttpOnly cookie with state, nonce, PKCE verifier, redirect path
     → 302 to the provider's authorization endpoint
GET  /api/v1/oidc/callback?code=…&state=…
     → state matches cookie; exchange code with verifier
     → verify ID token: signature (JWKS), iss, aud = client ID, exp, nonce; read `email`
     → upsert `users`, insert `oidc_sessions`, set `dekart_session` cookie
       (HttpOnly, Secure when DEKART_APP_URL is https, SameSite=Lax, Path=/)
     → 302 to the stored redirect path (relative paths only)
POST /api/v1/oidc/logout
     → delete the session row, clear the cookie, return the provider's end_session_endpoint with
       id_token_hint and post_logout_redirect_uri (the provider requires both together)
```

`ClaimsCheck.GetContext` in this mode, in order:

1. `Authorization: Bearer` present: snapshot token, then device token (`validateSnapshotToken`,
   `validateDeviceAuthToken`, `validateSnapshotReport`). A bearer never falls through to the cookie.
2. `dekart_session` cookie: look up `sha256(value)`; reject when expired.
   When `idp_expires_at` has passed, refresh with the stored refresh token (one refresh per session at
   a time). Store the rotated refresh token. Refresh rejected, or no refresh token: delete the session.
3. Nothing valid: `nil`, the request gets 401.

The UI stops holding a token in this mode. On 401 it navigates to `/api/v1/oidc/login?redirect=<path>`.
gRPC-web and fetch calls are same-origin, so the cookie travels without client changes.

## Steps

1. Config: read the variables in `app.go`, add the mode to the `b2i` exclusion and `validateConfig`,
   add it to `enabledSSOEnvVars()`.
2. `src/server/user/oidclogin.go`: discovery, login, callback, logout, session lookup and refresh.
   Reuse `oidcJWTVerifier` for ID token signatures and `golang.org/x/oauth2` for the exchange and PKCE.
3. `src/server/user/oidcsession.go`: session table access and refresh token encryption.
4. Register the three routes in `app.go` when the mode is on.
5. Proto: `TYPE_REQUIRE_OIDC_LOGIN` in `GetEnvResponse.Variable.Type`; expose it in both `GetEnv`
   branches of `server.go`; `make proto`.
6. Client: `oidcLoginEnabled` in the env reducer and `authConfigured`; 401 redirect in `AppRedirect`;
   login and logout in `Header.jsx`; `DeviceAuthorizePage.jsx` gated like Google OAuth.
7. `.env.example`: a block below the header-mode OIDC block.
8. Docs: environment variables table and the SSO method list.

## Tests

- `TestGetContextOIDCLogin`, a table test like `TestGetContextAmazonOIDC`: valid session, expired
  session, unknown cookie, IdP expiry with refresh success, refresh rejected, no refresh token,
  device token, revoked device, snapshot token, snapshot for another report, bearer and cookie together.
- Callback tests against `httptest` discovery, token and JWKS servers: state mismatch, nonce mismatch,
  wrong audience, wrong issuer, missing email, unsafe redirect path.
- Encryption round trip and tamper detection for stored refresh tokens.
- No outbound network: the existing blocking RoundTripper.

## Acceptance

- Browser login against Authentik and Keycloak with no proxy in front; page reload keeps the session.
- An idle tab still works after the IdP access token expired (server-side refresh).
- Disabling the user in the IdP ends the Dekart session at the next refresh.
- `dekart init`, `dekart tools`, `dekart snapshot` and `dekart mcp serve` work against the same instance.
- Logout removes the session row; the old cookie value gets 401.
