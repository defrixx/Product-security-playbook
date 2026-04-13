# OIDC + OAuth 2.0 Security Playbook

## 1. Scope and Objective

This playbook describes secure integration of OIDC (authentication) and OAuth 2.0 (authorization) with Keycloak.

---

## 2. OIDC and OAuth 2.0: How They Work Together

- **OIDC** handles user login and issues `id_token` (who authenticated, how, and when)
- **OAuth 2.0** issues `access_token` and `refresh_token` for API access
- In Authorization Code flow, OIDC and OAuth are typically used together

Core rule:
- Use `id_token` for login/session context in the client (RP), not as API bearer
- Use `access_token` for API authorization

---

## 3. Recommended Architecture Patterns

### 3.1 Web Backend (server-rendered)

- Confidential client
- Authorization Code flow
- PKCE enabled (recommended even for confidential clients)
- Tokens stored on backend
- Browser receives only session cookie

### 3.2 SPA + BFF (recommended for browser)

- SPA does not keep refresh token
- BFF performs code exchange and stores refresh token server-side
- SPA communicates with BFF through secure cookie-based session
- BFF calls APIs on behalf of user

### 3.3 Mobile

- Public client
- Authorization Code + PKCE (S256)
- System browser only (ASWebAuthenticationSession / Custom Tabs)
- Refresh token stored only in OS secure storage

### 3.4 Service-to-service

- OAuth Client Credentials
- Separate machine clients and scopes/roles
- Do not mix user tokens and service tokens

---

## 4. Token Sets and Token Purpose

### 4.1 Token sets by flow

1. `authorization_code` (with OIDC scope):
- `id_token` + `access_token` + often `refresh_token`

2. `authorization_code` (without OIDC scope):
- `access_token` + often `refresh_token`, no `id_token`

3. `client_credentials`:
- `access_token` only (usually no refresh token)

4. `token exchange` (RFC 8693, Keycloak V2):
- input token -> new `access_token` (different audience/scope)

5. `offline_access` (scope, not a flow):
- `offline_access` is an OAuth scope that changes refresh token semantics
- when requested and allowed, an offline token is issued with long-lived or non-session-bound behavior
- does not represent a separate grant flow, but modifies token behavior within existing flows (e.g., authorization_code)

### 4.2 Purpose of each token

- `id_token`: user authentication result for client session context
- `access_token`: bearer presented to resource server for authorization
- `refresh_token`: obtain new access tokens without full re-login
- `offline token`: obtain new tokens without active browser session
- `userinfo` response: optional source of additional profile claims, not a replacement for `id_token` validation

Identity rule:
- Use `sub` as the primary stable user identifier in your application
- Do not use `email` as primary identity key

### 4.3 Critical security rules

- Never use `id_token` as API bearer
- Keep `aud` and `scope` narrow
- Use explicit token/session timing limits (see numeric baseline below), not "short/long" wording
- PKCE mandatory for public clients

---

## 5. Baseline Secure Profile (Recommended)

Use as default for most systems.

1. Flow:
- Authorization Code + PKCE (`S256`)

2. Client model:
- Browser: SPA + BFF or server-side web
- Mobile: public client + PKCE + system browser
- Service: confidential + client credentials

3. Token controls:
- Access token TTL: `5-15m` (default recommendation: `10m`)
- ID token TTL: `<=5m`
- Browser/BFF refresh token absolute max lifetime: `<=24h`
- Mobile refresh token absolute max lifetime: `<=30d` only with secure enclave/keystore storage and device trust controls
- Refresh token reuse grace window for retry races: `<=30s` (reject older token use outside this window)
- `Revoke Refresh Token` enabled (rotation)
- Limited scopes
- Explicit audience

4. Token validation:
- Validate `iss`, `aud`, `exp`, `nbf`, `iat`, signature (`kid`/JWKS)
- Enforce JWT `alg` allowlist and reject unexpected algorithms
- Validate `nonce` for front-channel user login flows
- Validate `azp` when present (especially with multiple audiences)
- Validate `auth_time`/`acr`/`amr` when policy requires specific authentication strength
- Validate authorization scopes + roles + policy

5. Callback integrity checks:
- `state` is mandatory and must match request->callback exactly
- `nonce` is mandatory for OIDC login and must match the original authorization request value

6. Logout:
- RP-Initiated Logout
- Local application session logout
- Back-channel/logout notifications where needed

7. Cookies:
- `HttpOnly`, `Secure`, `SameSite=Lax` (or `None; Secure` for cross-site SSO)
- Narrow `Domain` and `Path`
- Session ID rotation after login

8. Baseline timing and replay controls:
- User session idle timeout (browser): `15m`
- User session max age (browser): `8h`
- High-risk operations require a fresh authentication event within `<=15m` (`max_age`)
- JWT validation clock skew tolerance: `<=60s` (hard limit: `<=120s`)
- Token endpoint rate limit baseline:
  - Per client + source IP: `60 req/min` sustained
  - Burst: `120 req/min` for `<=1m`
  - Login/token brute-force lockout signal after `10` failed attempts in `5m`

---

## 6. Maximum Security Profile

Use for high-risk and regulated environments.

1. Everything from Recommended profile plus:
- Sender-constrained tokens (DPoP and/or mTLS)
- PAR (RFC 9126)
- JAR (RFC 9101)
- Strict Keycloak client policies
- Mandatory MFA/step-up for critical operations

2. DPoP in Keycloak 26.4+:
- Enable `Require DPoP bound tokens` for selected clients
- For public clients, at minimum bind refresh token (prefer refresh + access)
- Verify adapter/runtime compatibility for holder-of-key validation

3. mTLS (where applicable):
- Certificate-based client auth
- Certificate-bound tokens (RFC 8705) when required

4. Additional controls:
- Strict CORS
- Block deprecated grants (implicit, password)
- Anti-automation and rate limiting on auth/token endpoints

---

## 7. Certificates, Keys, JWKS, and Signatures

### 7.1 What resource server must validate

- JWT signature against JWKS keys (`/protocol/openid-connect/certs`)
- `kid` in JWT header must resolve to active JWKS key
- Trust only the expected issuer and its JWKS location from trusted discovery metadata
- Never accept JWKS from untrusted or user-controlled URLs

### 7.2 Key rotation in Keycloak (realm keys)

- Planned rotation is mandatory
- Introduce new key in advance (active/passive approach)
- Remove old key only after compatibility window
- In compromise case: issue new key immediately and invalidate sessions/tokens
- Baseline cadence:
  - Signing key rotation every `90d` (or faster for regulated profiles)
  - Compatibility overlap window: `24-72h`
  - Emergency compromise rotation target: complete key switch in `<=1h`

### 7.3 TLS certificates

- HTTPS only
- mTLS for trusted internal channels where threat model requires it
- Control trusted CA set and certificate lifetime

### 7.4 Client auth at token endpoint

- Prefer `private_key_jwt` or mTLS for confidential clients
- `client_secret` is acceptable only with mandatory rotation
- Enforce client secret rotation policy in Keycloak

---

## 8. Sessions and Session Storage

### 8.1 Where to store

- Browser: session cookie only
- Application server: session state (Redis/DB/in-memory with replication)
- Refresh/offline tokens: server-side storage or OS secure storage on mobile

### 8.2 What must not be kept in browser

- Refresh token in `localStorage`/`sessionStorage` is prohibited
- Access token in JS runtime only when unavoidable and with short TTL

### 8.3 Session timeout model

Align Keycloak and application settings:
- SSO Session Idle
- SSO Session Max
- Client Session Idle/Max
- Access Token Lifespan
- Refresh token rotation policy
Otherwise app session and upstream token validity can drift out of sync.

Baseline defaults:
- SSO Session Idle: `15m`
- SSO Session Max: `8h`
- Client Session Idle: `15m`
- Client Session Max: `8h`
- Access Token Lifespan: `10m`
- Client clock skew tolerance: `<=60s`

### 8.4 BFF session security controls (mandatory)

- CSRF protection is mandatory for all state-changing BFF endpoints (`POST/PUT/PATCH/DELETE`):
  - Synchronizer token or double-submit cookie pattern
  - Validate `Origin` (primary) and `Referer` (fallback) for browser requests
  - Reject requests without valid CSRF token even if session cookie is present
- Same-origin policy for session-bound endpoints:
  - Do not allow cross-origin CORS for BFF session endpoints
  - Allow only exact frontend origin(s) for non-session API CORS where explicitly required
  - Enforce `Sec-Fetch-Site` checks and reject cross-site requests for session operations
- Authorization code replay detection in login callback:
  - Store `state` and `nonce` server-side with single-use semantics and TTL `<=10m`
  - Reject callback if `state` is missing, expired, or already consumed
  - Record and alert on replay attempts (reused `state`, repeated callback correlation ID)
- Rotate local session ID after successful login callback and privilege elevation events.

---

## 9. Logout, Session Revocation, Token Revocation

### 9.1 Typical secure logout flow

1. Destroy local app session
2. Call OIDC RP-Initiated Logout (`end_session_endpoint`)
3. Return to strictly registered `post_logout_redirect_uri`

### 9.2 Global emergency revocation

In Keycloak:

- `Sign out all active sessions` invalidates SSO cookies
- `Revocation` / `Not Before` invalidates previously issued tokens in bulk
- Some adapters support push not-before propagation

Important: sign-out alone does not instantly invalidate already-issued access tokens until `exp`; use short TTL and introspection/revocation strategy where required.

### 9.3 Token revocation endpoint

- Use `/protocol/openid-connect/revoke` (RFC 7009)
- Revoke refresh token on logout
- With rotation enabled, keep only the latest refresh token server-side

### 9.4 Back-channel/front-channel logout

- Configure back-channel/front-channel logout for multi-RP ecosystems
- Always design fallback: local app logout must remain correct under partial federation/logout channel failure

### 9.5 Token replay after logout: mandatory control

- For sensitive APIs (money movement, privilege changes, PII export, admin actions), introspection is mandatory by default even for JWT tokens.
- Enforce token revocation checks for `<=15m` after user logout, global `Not Before` updates, or incident-driven revocation.
- Deny tokens that are:
  - inactive in introspection
  - issued before current realm/client `Not Before`
  - outside allowed session binding context (when sender-constrained tokens are enabled)

---

## 10. Authorization and Token Liveness Checks

### 10.1 Authorization checks

Resource server must validate:
- `scope` (operation rights)
- `realm/client roles`
- `aud` (token issued for this API)
- Context conditions (tenant, resource ownership, ABAC/RBAC policy)

### 10.2 Token liveness model

Two models:

1. Local JWT validation (fast, low cost):
- Validate signature and claims (`exp`, `nbf`, `iss`, `aud`)
- Good for high-throughput APIs

2. Introspection (RFC 7662):
- Validate `active` and server-side token state
- Required for high-risk operations or near-real-time revocation

Production pattern:
- Local validation by default
- Introspection is mandatory for high-risk operations, suspicious tokens, and post-incident periods

### 10.3 Introspection resiliency model (mandatory)

Define and enforce explicit behavior for IdP/introspection degradation:

- Timeout budget (per introspection call):
  - Connect timeout: `<=100ms`
  - Response timeout: `<=300ms`
  - Total request budget: `<=500ms`
- Result caching (bounded and revocation-aware):
  - Positive cache TTL: `<=30s` and never beyond token `exp` / current `Not Before`
  - Negative/inactive cache TTL: `<=5s`
  - Flush cache on revocation incidents and `Not Before` updates
- Endpoint-class policy (no implicit behavior):
  - Class A (money movement, admin, privilege changes, PII export): `fail-closed`
  - Class B (state-changing business operations): `fail-closed`
  - Class C (low-risk read-only endpoints): explicit decision required; `fail-open` allowed only by approved exception with max degraded window `<=120s`
- Degraded-mode controls:
  - Trigger alert on introspection error rate/SLA breach
  - Enable circuit breaker and backoff to prevent IdP overload
  - Auto-return to normal policy after introspection recovery is verified

---

## 11. Step-by-Step Integration with Keycloak

### Step 1. Realm and cryptography baseline

- Configure realm keys and rotation plan
- Enable admin/user event audit
- Verify HTTPS and proxy header handling

### Step 2. Create client types

- `web-bff` (confidential)
- `spa-frontend` (if separate public client is needed)
- `mobile-app` (public + PKCE)
- `service-api-client` (confidential + client_credentials)

### Step 3. Lock redirect/logout URIs

- Exact match only
- Separate URI set per environment
- Configure `Valid Post Logout Redirect URIs`

### Step 4. Enable secure capabilities

- Standard Flow: ON
- Implicit: OFF
- Direct Access Grants: OFF (unless strong business need)
- PKCE method: `S256`
- Revoke Refresh Token: ON (usually)
- Enforce minimum client policies (PKCE, secure redirects)

### Step 5. Configure scopes/roles/audience

- Minimal client scopes
- Separate API client roles
- Audience mapping to exact resource servers

### Step 6. Integrate application

- Use `.well-known/openid-configuration` as endpoint source
- Pin trust to expected `issuer` and use only that issuer's `jwks_uri`
- Authorization Code + PKCE
- Keep browser session cookie, not bearer tokens in browser storage
- On callback, strictly validate `state` and `nonce` before creating local session

### Step 7. Build resource server middleware

- Centralize JWT/introspection validation
- Enforce `iss/aud/exp/nbf` and scope/role checks
- Keep deny-by-default authorization

### Step 8. Implement logout/revocation/invalidation

- RP-initiated logout
- Refresh token revocation path
- Incident runbook for mass `Not Before`

### Step 9. Monitoring and detection

- Metrics: token endpoint errors, refresh failures, invalid signature, invalid audience
- Alerts: anomalies in refresh/token-exchange/DPoP failures
- SIEM correlation between auth and API denial events

---

## 12. Threat-Driven Checks (Mandatory in Review)

- Authorization code interception -> PKCE + exact redirect URI
- Bearer token theft -> short TTL + DPoP/mTLS
- Refresh token reuse -> rotation + reuse detection
- Open redirect -> strict allowlist
- Mix-up attacks -> `iss` validation + strict client/issuer config
- Privilege escalation -> strict audience/scope/role separation
- Session fixation -> regenerate session ID after login
- Token leakage in logs -> redaction and explicit no-token logging policy

---

## 13. Anti-patterns

- `id_token` used as API bearer
- PKCE `plain` instead of `S256`
- Wildcard redirect URI
- Refresh token stored in browser storage
- Long access token TTL (hours/days)
- Single client for user login and machine-to-machine traffic without segregation
- No key rotation and key-compromise response procedure

---

## 14. Exception Governance (Mandatory)

Any exception to this profile (TTL, rotation, session limits, introspection scope, redirect strictness, token storage) must include:
- Named owner (team + accountable person)
- Tracking ticket
- Explicit business justification
- Compensating controls
- Expiry date (default max `30d`, hard max `90d`)
- Closure criteria (what must be changed to remove the exception)

Release gate rule:
- Expired exceptions block release until renewed with security approval or removed.