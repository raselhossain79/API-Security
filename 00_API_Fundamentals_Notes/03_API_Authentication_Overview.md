# API Authentication — Overview & Mechanisms

> This file is mechanism-first — understanding HOW API authentication works before
> studying how to attack it. The attack notes (JWT attacks, OAuth, API key security,
> Broken Authentication) assume this foundation is already in place.

---

## 1. Bearer Tokens

The most common API authentication pattern. The client sends a token in the
`Authorization` header with every request:

```http
GET /api/users/123 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Breaking this down:
- `Authorization` — the standard HTTP header for credentials
- `Bearer` — the authentication scheme type, telling the server "this is a bearer
  token — whoever holds it is authenticated"
- `eyJhbGci...` — the actual token value (usually a JWT, but not always)

**The security model:** Anyone who has the token can use it. There's no per-device
binding (unlike TLS client certificates). Theft = full impersonation.

---

## 2. JWT (JSON Web Tokens) — Structure

JWTs are the most common bearer token format. Three base64url-encoded parts separated
by dots:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
       │                                        │                                   │
    header (base64url)                    payload (base64url)              signature (base64url)
```

**Decoded header:**
```json
{"alg": "HS256", "typ": "JWT"}
```
- `alg` — the signing algorithm used (HS256, RS256, ES256, or "none")
- `typ` — token type

**Decoded payload (the claims):**
```json
{"sub": "123", "role": "user", "exp": 1735689600, "iat": 1735603200}
```
- `sub` — subject (usually user ID)
- `role` — custom claim, not standard — apps use this for authorization
- `exp` — expiry timestamp (Unix time)
- `iat` — issued-at timestamp

**Signature:** The server uses the algorithm + secret key to sign header+payload.
Without the secret, you can't forge a valid signature. The JWT attack notes cover
exactly the ways this signature validation gets bypassed.

---

## 3. API Keys

Simpler than JWT — just a static secret string sent in a header, query parameter,
or request body:

```http
# In a header (most secure)
GET /api/data HTTP/1.1
X-API-Key: sk_live_abc123xyz789

# In a query parameter (least secure — logged in URL logs)
GET /api/data?api_key=sk_live_abc123xyz789

# In Authorization header
Authorization: ApiKey sk_live_abc123xyz789
```

**Key differences from JWT:**
- No expiry by default (unless the platform rotates them)
- No built-in claims/roles — the server looks up what the key is allowed to do
  in its own database
- Simpler to implement, simpler to mishandle (exposed in git repos, JS bundles,
  logs, error messages)

---

## 4. OAuth 2.0 — High-Level Flow

OAuth is an *authorization framework* — it lets a user grant an application access
to their data on another service without giving the app their password. The classic
"Login with Google/GitHub" pattern.

**Authorization Code Flow (the most common and most secure variant):**

```
User → clicks "Login with Google" on example.com

example.com → redirects user to Google:
  https://accounts.google.com/oauth/authorize
    ?client_id=example_app_id
    ?redirect_uri=https://example.com/callback
    ?response_type=code
    ?scope=email profile
    ?state=random_csrf_value

User → approves access on Google

Google → redirects back to example.com:
  https://example.com/callback
    ?code=AUTHORIZATION_CODE
    ?state=random_csrf_value

example.com backend → exchanges the code for tokens:
  POST https://accounts.google.com/oauth/token
  {code, client_id, client_secret, redirect_uri}

Google → returns:
  {access_token, refresh_token, id_token}

example.com → uses access_token to call Google APIs on behalf of the user
```

**Why this matters for attack notes:**
- `redirect_uri` — the OAuth attack notes cover manipulating this to steal the
  authorization code
- `state` — missing or predictable state = CSRF on the OAuth flow
- The `code` exchange — interception attacks happen here

---

## 5. Session Cookies vs Tokens in API Context

| | Session Cookie | Bearer Token (JWT/OAuth) |
|---|---|---|
| Where stored | Browser cookie jar | localStorage, memory, or mobile app storage |
| Sent automatically | Yes, browser sends with every request | No, app must explicitly add to Authorization header |
| CSRF risk | High (browser sends cookies automatically) | Low (JS must explicitly add the header) |
| XSS risk | Lower (if HttpOnly) | Higher (localStorage is readable by JS) |
| Common in | Traditional web apps, some APIs | Modern REST APIs, mobile backends |

**Pentest implication:** APIs using Bearer tokens are less vulnerable to CSRF than
cookie-based apps — but if the token is stored in localStorage, XSS becomes more
impactful because it can directly steal the token.

Continue to → `04_Reading_API_Documentation.md`
