# OAuth 2.0 Fundamentals and Flows

## Purpose of This File

Every attack in this series depends on understanding what OAuth is actually supposed to do before it's misused. This file covers the mechanism only — no attacks yet. If you already know OAuth cold, skim the "why the server trusts what it trusts" callouts in each flow, since those are the exact assumptions later files break.

---

## 1. What OAuth 2.0 Actually Is

OAuth 2.0 is an **authorization** framework, not an authentication protocol. It was designed to solve one specific problem: how does a user grant a third-party application limited access to their data on another service, without handing over their password to that third party?

This distinction matters for security work because a huge number of real-world OAuth vulnerabilities exist precisely because OAuth gets used for **authentication** ("Log in with Google") when it was built for **authorization** ("Let this app read my calendar"). OAuth alone tells a client application "this user approved this access." It does not, by itself, verify who the user is in a way that's safe to treat as a login. That gap is filled by OpenID Connect (OIDC), a thin identity layer built on top of OAuth — but a huge number of production systems implement "Sign in with X" using raw OAuth without OIDC, and that's where a lot of the vulnerabilities in this series live.

### The Three (or Four) Parties

- **Resource Owner** — the user. The person who owns the data and can grant or deny access to it.
- **Client Application** — the website or app that wants access to the user's data (or wants to use the OAuth provider to authenticate the user). Sometimes called the "relying party" in OIDC terminology.
- **Authorization Server** — issues tokens after the resource owner authenticates and consents. This is the endpoint that receives `client_id`, `redirect_uri`, `scope`, etc.
- **Resource Server** — hosts the protected data (e.g. a `/userinfo` or `/api/profile` endpoint) and accepts access tokens as proof of authorization.

In many real deployments the authorization server and resource server are the same service (e.g. Google, GitHub, an internal identity provider). PortSwigger's labs model them as separate hosts — an `oauth-server.net` host issuing tokens, and the lab's own host acting as the client application — which is a useful mental model to keep because it mirrors how third-party identity providers work in production.

### Client Registration

Before any OAuth flow can run, the client application registers with the authorization server and receives:
- A `client_id` — public, non-secret identifier for the application.
- A `client_secret` — used by confidential clients (e.g. server-side web apps) to authenticate themselves when exchanging a code for a token. Public clients (SPAs, mobile apps, CLI tools) typically don't get a secret because they can't keep it confidential.
- One or more **registered redirect URIs** — the exact callback URLs the authorization server is allowed to send the response to. This whitelist is the single most important security control in the whole framework, and File 2 of this series is dedicated to how it gets bypassed.

---

## 2. The Authorization Code Grant

This is the flow you'll encounter most often in real-world web applications, and the one most of this series focuses on.

### When it's used

Server-side (confidential) web applications where the backend can securely store a `client_secret`. It's the recommended flow for anything with a backend component, and — with PKCE added — is now also the recommended flow for public clients like SPAs and mobile apps (replacing the old Implicit flow).

### Step-by-step mechanism

**Step 1 — Authorization Request**

The client redirects the user's browser to the authorization server:

```
GET /auth?client_id=a1b2c3&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile%20email&state=xyz789 HTTP/1.1
Host: oauth-authorization-server.com
```

Breaking down every parameter:

| Parameter | Meaning | Why the server trusts it |
|---|---|---|
| `client_id` | Identifies which registered application is requesting access | Public value, not a secret — trust comes from matching it against the registered redirect URI list, not from the value itself |
| `redirect_uri` | Where to send the user back with the result | The server is supposed to validate this against the client's pre-registered whitelist — File 2 covers what happens when it doesn't |
| `response_type=code` | Tells the server which grant type to use — here, "give me a code, not a token directly" | Server-controlled logic branches on this value |
| `scope` | Space-separated list of permissions being requested | The user consents to exactly this list — later files cover what happens when the server doesn't re-validate scope at the token exchange step |
| `state` | An opaque, unguessable value the client generates and expects to get back unchanged | This is the client's CSRF token for the OAuth flow itself — File 3 is entirely about what happens when this is missing, predictable, or not actually checked |

**Step 2 — User Authenticates and Consents**

The user logs into the authorization server (if not already logged in) and is shown a consent screen listing the requested scopes. This step happens entirely on the authorization server's own origin — the client application never sees the user's credentials for that provider. This is the core security property OAuth was built to preserve.

**Step 3 — Authorization Response**

The authorization server redirects the browser back to the registered `redirect_uri` with a short-lived, single-use authorization code:

```
HTTP/1.1 302 Found
Location: https://client-app.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz789
```

The `code` here is deliberately short-lived (often 30–60 seconds) and single-use. It's not the access token — it's a voucher that has to be redeemed server-to-server. This indirection exists specifically so that a code intercepted in the browser (via history, Referer leakage, or a malicious redirect) is far less useful than a raw access token would be — assuming, critically, that the redemption step properly validates who's redeeming it. That assumption is exactly what redirect_uri and PKCE attacks target.

**Step 4 — Token Exchange (server-to-server, back-channel)**

The client's backend — not the browser — sends the code directly to the authorization server's token endpoint, along with its `client_secret`:

```
POST /token HTTP/1.1
Host: oauth-authorization-server.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https://client-app.com/callback&client_id=a1b2c3&client_secret=SECRET
```

Notice `redirect_uri` is sent again here. A well-implemented authorization server checks that this matches the `redirect_uri` from Step 1 exactly. Because this exchange happens server-to-server over a channel the attacker cannot touch, this second check is what actually stops most authorization-code-interception attacks — not `state`, and not the browser-visible `redirect_uri` validation alone. This is a critical mechanism to understand before File 2, because a lot of write-ups conflate "redirect_uri was validated once" with "the flow is secure," when the back-channel re-check is what really closes the hole.

**Step 5 — Token Response**

```json
{
  "access_token": "2YotnFZFEjr1zCsicMWpAA",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email"
}
```

The access token is now used by the client's backend to call the resource server (e.g. `GET /userinfo` with `Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA`) to fetch identity data, which it then uses to log the user in — typically by issuing its own session cookie.

**Why this flow is comparatively strong:** the access token itself never touches the browser. Everything sensitive after the initial redirect happens server-to-server. This is exactly why File 2 through File 6 spend so much time on the *code*, not the token — the code is the only sensitive artifact that's exposed to browser-based interception in a correctly implemented Authorization Code flow.

---

## 3. The Implicit Grant

### When it's used (and why it's mostly deprecated)

Originally designed for browser-based apps (SPAs) that have no backend to keep a `client_secret` confidential. Because there's no secure place to exchange a code for a token, the Implicit flow skips the code entirely and returns the access token directly to the browser. Current OAuth security best practice (OAuth 2.0 Security Best Current Practice, and OAuth 2.1) explicitly recommends against it in favor of Authorization Code + PKCE — but it's still common in older or poorly maintained systems, which is exactly why PortSwigger built a whole lab around it.

### Mechanism

**Step 1 — Authorization Request**

```
GET /auth?client_id=a1b2c3&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489 HTTP/1.1
Host: oauth-authorization-server.com
```

The only difference from Authorization Code so far is `response_type=token` instead of `response_type=code`.

**Step 2 — Token Delivered via URL Fragment**

```
HTTP/1.1 302 Found
Location: https://client-app.com/callback#access_token=2YotnFZFEjr1zCsicMWpAA&token_type=Bearer&expires_in=3600&state=ae13d489
```

Notice the token is appended after a `#`, not as a query parameter. This is a deliberate design choice: URL fragments are never sent to the server in the HTTP request line, and browsers don't include them in the `Referer` header on a normal navigation. In theory this limits exposure — the fragment only exists client-side, readable by JavaScript on the page via `window.location.hash`.

**Why the server "trusts" this token:** it doesn't verify much at delivery time — the token is simply handed to whatever JavaScript is running at the registered redirect URI. All the trust is pushed downstream to how the client application's JavaScript handles that fragment.

**Step 3 — Client-Side Handling and the Root of the Vulnerability**

The client-side JavaScript reads the token from the fragment and, because a page reload would lose that in-memory token, the application often needs to persist the session. The common (and dangerous) pattern:

```
POST /authenticate HTTP/1.1
Host: client-app.com
Content-Type: application/json

{"email": "wiener@normal-user.net", "access_token": "2YotnFZFEjr1zCsicMWpAA"}
```

The client's backend receives this and is expected to verify the access token actually belongs to that email — normally by calling the resource server's `/userinfo` endpoint itself with the token, server-to-server, and comparing the result. **The vulnerability PortSwigger's "Authentication bypass via OAuth implicit flow" lab demonstrates is what happens when the backend skips that verification and just trusts the email field the browser sent.** Since this `POST /authenticate` request is fully visible and editable in the browser (it's not a secure back-channel call — the client controls it entirely), an attacker can simply change the `email` field to a victim's address and get logged in as them, because the server has no secret to check it against.

This is the mechanism-level reason Implicit flow is risky: it moves a trust decision that should happen server-to-server into a request the attacker fully controls.

---

## 4. The Client Credentials Grant

### When it's used

Machine-to-machine authorization with no resource owner involved — a backend service authenticating directly as itself to call an API, not on behalf of a user. Common in API security contexts: a microservice calling another microservice, a CI/CD pipeline calling a deployment API, a backend job pulling data from a partner API.

### Mechanism

```
POST /token HTTP/1.1
Host: oauth-authorization-server.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=a1b2c3&client_secret=SECRET&scope=api:read
```

Single request, single response. No browser redirect, no user consent screen, no authorization code — the client authenticates directly with its own credentials and gets a token back:

```json
{
  "access_token": "z0y9x8w7v6",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api:read"
}
```

**Why the server trusts it:** purely on `client_id` + `client_secret`, treated like a username/password pair for the application itself. There's no user identity in this flow at all — the resulting token represents the *application*, not a person. In API security assessments this flow matters because a leaked `client_secret` (in a mobile app binary, a public GitHub repo, a misconfigured CI variable) is functionally equivalent to a leaked API master key — this is a very common real-world finding in bug bounty programs involving mobile apps and third-party integrations, and worth actively hunting for when reviewing decompiled APKs or exposed `.env` files during recon.

---

## 5. Device Authorization Grant (Device Flow)

### When it's used

Devices with limited input capability or no browser — smart TVs, CLI tools, IoT devices. Think of logging into a streaming app on a TV by visiting a URL on your phone and entering a short code.

### Mechanism

**Step 1 — Device Requests a Code**

```
POST /device_authorization HTTP/1.1
Host: oauth-authorization-server.com

client_id=a1b2c3&scope=openid profile
```

Response:

```json
{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://oauth-authorization-server.com/device",
  "expires_in": 1800,
  "interval": 5
}
```

**Step 2 — User Authorizes on a Secondary Device**

The user visits `verification_uri` on their phone or laptop, enters the short `user_code`, logs in if needed, and approves.

**Step 3 — The Original Device Polls**

```
POST /token HTTP/1.1
Host: oauth-authorization-server.com

grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS&client_id=a1b2c3
```

The device repeats this request every `interval` seconds until the authorization server responds with either a token (approved) or `authorization_pending` / `expired_token` / `access_denied`.

**Why the server trusts it:** the `device_code` is a long, high-entropy, unguessable value tied server-side to the short `user_code`. The short code is what's human-typeable, but it's never usable on its own to obtain a token — only the polling device holding the long `device_code` can redeem it, and only after the *user_code* has been approved out-of-band. The realistic attack surface here is less about the protocol mechanics and more about **user_code phishing**: an attacker tricks a victim into visiting the real `verification_uri` and entering a *code the attacker generated*, which silently authorizes the attacker's polling device with the victim's session. This is a known real-world phishing pattern against device flow implementations (sometimes called "device code phishing") and worth being aware of even though PortSwigger doesn't currently have a dedicated lab for it.

---

## 6. Grant Type Comparison Table

| Flow | Token exposed to browser? | Needs client_secret? | Typical use case | Primary attack surface (covered in this series) |
|---|---|---|---|---|
| Authorization Code | No (only a short-lived code is) | Yes (confidential client) | Server-side web apps, and SPAs when paired with PKCE | redirect_uri manipulation, state/CSRF, scope upgrade at token exchange |
| Implicit | Yes, directly | No | Legacy SPAs (deprecated in OAuth 2.1) | Token leakage via fragment mishandling, unverified client-side trust in POST /authenticate |
| Client Credentials | No (server-to-server only) | Yes | Machine-to-machine / service accounts | Leaked client_secret in binaries, repos, CI config |
| Device Flow | No | Depends on client type | TVs, CLIs, IoT | user_code phishing, insufficient device_code entropy |

---

## 7. Identifying OAuth in the Wild During Recon

Before you can attack any of this, you need to spot it. Practical recon checklist:

- Look for "Log in with [Provider]" buttons — the strongest visual signal.
- Proxy the login flow through Burp and watch for a request to a path containing `/authorize`, `/authorization`, `/oauth`, or similar, carrying `client_id`, `redirect_uri`, and `response_type` query parameters.
- Once you've identified the authorization server's host, always probe:
  - `GET /.well-known/oauth-authorization-server`
  - `GET /.well-known/openid-configuration`

  These are standardized discovery endpoints (RFC 8414 and OpenID Connect Discovery respectively) that frequently return a JSON document listing every supported endpoint, grant type, and feature — including things not documented anywhere public, like whether dynamic client registration is enabled. This single request is often the fastest way to widen your understanding of the attack surface before you've touched a single attack technique.
- Check whether the identity provider is a known third party (Google, GitHub, Facebook, Auth0, Okta) or an in-house authorization server. In-house implementations are, in practice, far more likely to contain the client-side and validation-logic bugs this series covers, because the well-known providers have had this exact attack surface hardened for over a decade.

---

## Real-World Industry Note

OAuth misconfiguration bug reports are consistently among the higher-payout categories on HackerOne and Bugcrowd precisely because the impact is so often full account takeover, not just data disclosure. The pattern worth internalizing from this file alone: **almost every serious OAuth vulnerability comes from one party trusting a value it should have independently verified** — the client trusting an unverified email from the browser (Implicit flow), the authorization server trusting a redirect_uri it didn't strictly whitelist, or the token endpoint trusting a scope it didn't re-validate. Every subsequent file in this series is a variation on that same theme applied to a different parameter.

---

## What's Next

File 2 goes deep on the single most productive attack surface in real-world OAuth testing: `redirect_uri` manipulation, including open redirect chaining and subdomain takeover chaining.
