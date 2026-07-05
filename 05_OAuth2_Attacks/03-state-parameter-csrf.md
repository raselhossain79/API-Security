# State Parameter Bypass and CSRF on OAuth Flows

## What the state Parameter Actually Protects Against

This is worth being precise about, because it's commonly misunderstood even by developers who implement it: `state` is **not** primarily about preventing token theft. Its job is narrower and specific — it protects the **client application's callback endpoint** from Cross-Site Request Forgery.

Recall the shape of the callback request from file 1:

```
GET /callback?code=SplxlOBeZQQYbYS6WxSbIA&state=af0ifjsldkj HTTP/1.1
Host: client-app.com
```

This is a plain, unauthenticated `GET` request to the client application. Nothing about it is cryptographically tied to a specific browser session unless the client itself ties it there. Without `state`, there is no way for `client-app.com` to know whether this `code` arrived as the natural result of *this browser's own* OAuth flow, or whether an attacker simply crafted this URL themselves and tricked the victim's browser into visiting it.

**The correct mechanism:**
1. Before redirecting the user to the authorization server (file 1, Step 1), the client generates a random, unguessable value and stores it server-side, tied to the user's current session (e.g., in a session-bound cookie or server-side session store).
2. That value is sent as `state` in the authorization request.
3. When the browser returns to `/callback`, the client compares the `state` in the query string against the value it stored for *this specific browser session*.
4. If they don't match — or if no `state` was stored for this session at all — the client must reject the callback outright, not just log a warning.

## What state Does NOT Protect Against

Be precise here, because this distinction matters for how you write up findings:

- `state` does **not** protect against a stolen authorization code or token being redeemed by an attacker who already has a valid session with the OAuth provider — an attacker generating their *own* `state` value from their *own* browser sails through this check trivially, because they're not forging anyone else's session, they're using their own. This is why file 2's redirect_uri attacks work regardless of whether `state` is present: the attacker isn't trying to forge the victim's `state`, they're trying to get the victim's *code* delivered to the attacker's own endpoint.
- `state` does not protect the authorization server itself from anything — it's entirely a client-side (relying party) protection.

## Detecting Missing or Weak state — Manual Testing Method

1. **Capture a full, successful OAuth flow** through Burp (or any intercepting proxy) and identify the initial authorization request — file 1 tells you exactly what to look for: `GET /auth?...client_id=...&redirect_uri=...&response_type=...`.
2. **Check whether a `state` parameter is present at all.** If it's simply absent from the request, that's the most severe case — flawed CSRF protection by omission.
3. **If present, replay the entire flow a second time** (log out, start fresh) and compare the `state` value across the two runs.
   - Identical value both times → the client isn't generating anything session-specific; it may be a static string hardcoded into the client's request-building code. Trivially guessable/reusable by an attacker.
   - Sequential or low-entropy values (e.g., incrementing integers, timestamps, short numeric strings) → predictable enough to potentially brute-force or guess within a live attack window.
4. **Test whether the client actually validates it**, independent of whether it *generates* it well: capture a legitimate callback URL (`/callback?code=...&state=...`), then replay it in a **fresh browser session with no prior OAuth flow initiated** (e.g., a different browser profile, or after clearing cookies). If the client still accepts the code and logs the visiting browser in, it's not actually checking `state` against anything stored — it's just accepting whatever value shows up.
5. **Try dropping the `state` parameter entirely** from an otherwise legitimate callback URL and resending it. If the client still processes the request successfully, validation is not enforced server-side even if the client dutifully generates a strong value on the way out.

## CSRF on OAuth: Login CSRF

**Scenario:** A client application that lets users log in *exclusively* via OAuth (no separate password-based account system).

**Impact of missing state here:** an attacker can force a victim to log in to the *attacker's* account on the client application, without the victim realizing their session has changed. This sounds low-impact at first, but it's a classic setup for data-leakage attacks — the victim, believing they're still using their own account, may enter sensitive data (payment details, personal information, search history) into what is actually the attacker's account, which the attacker can later view.

**Attack construction:**
1. Attacker begins their own OAuth flow with the target client application, gets redirected to the authorization server, and logs in with **their own** OAuth account, but stops right before the final redirect back to `/callback` — i.e., they capture the URL `https://client-app.com/callback?code=ATTACKER_CODE&state=ATTACKER_STATE` without letting their own browser visit it.

   How this capture typically happens in practice: intercept the request in a proxy at the point the authorization server issues the `302` to `/callback`, copy the `Location` header value, then drop the request so the code is never consumed by the attacker's own browser and remains valid.

2. Attacker hosts this captured URL on a page the victim will visit, e.g. via an auto-submitting `<img>` tag, a hidden `<iframe>`, or a meta-refresh:
```html
<iframe src="https://client-app.com/callback?code=ATTACKER_CODE&state=ATTACKER_STATE"></iframe>
```
3. When the victim's browser loads this page, it sends the `GET /callback?code=ATTACKER_CODE&state=ATTACKER_STATE` request as if it were completing its own OAuth flow.
4. If the client application does not validate `state` against a value tied to the victim's own session (because it never generated one, or never checks it), the client happily exchanges `ATTACKER_CODE` for a token belonging to the **attacker's** OAuth identity, and logs the victim's browser in — as the attacker.
5. The victim, unaware their session changed, continues using the site normally, potentially entering sensitive information that the attacker can retrieve later by logging into their own account.

## CSRF on OAuth: Forced Account Linking

**Scenario:** A client application that supports *both* a classic password login and an option to "link" a social/OAuth account to an existing password-based account, so the user can later log in either way.

This is the higher-impact variant, and it's the one directly demonstrated by PortSwigger's forced OAuth profile linking lab (mapped in file 7). The linking endpoint typically looks like:

```
GET /oauth-linking?code=CODE HTTP/1.1
Host: client-app.com
```

**Why this endpoint is dangerous without state:** if it accepts any valid `code` and links whichever OAuth identity that code redeems to **whatever account the requesting browser currently has an active session with** — with no `state` check tying the linking request back to the specific user who initiated it — an attacker can hijack this exact mechanism to attach *their own* OAuth identity to the *victim's* password account.

**Attack construction:**
1. Attacker logs into the client application using the classic username/password form (an ordinary account they control legitimately).
2. Attacker starts the "link my social account" flow, gets redirected through the OAuth provider, authenticates with **their own** OAuth identity, and — exactly as in the login-CSRF case — intercepts and drops the request at the point the authorization server redirects back to `/oauth-linking?code=...`, capturing that code without letting it be consumed.
3. Attacker builds a page:
```html
<iframe src="https://client-app.com/oauth-linking?code=STOLEN_CODE"></iframe>
```
4. Attacker delivers this to the victim while the **victim has an active session on the client application** (this is the key precondition — the linking endpoint operates on "whoever's currently logged in," so the victim must already be logged into their own password-based account in their browser).
5. Victim's browser loads the iframe, sends `GET /oauth-linking?code=STOLEN_CODE`, and the client application — trusting that this browser's active session is the account to link to, with no `state` cross-check — attaches the attacker's OAuth identity to the **victim's account**.
6. The attacker now goes to the client application and selects "log in with social media," authenticating with their own OAuth credentials as normal. Because that OAuth identity is now linked to the victim's account, the attacker is logged in — as the victim, with full access to the victim's account and data.

**Why this is worse than login CSRF:** the attacker doesn't just get a fleeting session — they get a **durable, repeatable login path** into the victim's actual account, usable at any time in the future, and the victim's original password still works too, so there's often no visible sign anything happened unless the victim reviews linked-account settings.

## The "Doesn't Necessarily Prevent" Caveat

Even a correctly implemented `state` parameter does not stop the redirect_uri and code-interception attacks from file 2. An attacker performing those attacks generates their **own valid `state`** from their **own browser** when initiating the malicious flow — they're not trying to forge the victim's session token, they're diverting the victim's authorization *response* to an attacker-controlled endpoint. `state` validates that *a* legitimate flow initiated it; it does not validate *where* the response is allowed to go — that's `redirect_uri`'s job. This is why both parameters need to be tested independently, and why a target can be fully vulnerable to code interception while appearing to have "proper" `state` handling.

## Remediation Notes (for context when writing reports)

- `state` must be generated with a cryptographically secure random source, be unique per authorization request, tied server-side to the initiating session, single-use, and validated on every callback with no fallback path that skips the check.
- For public clients (SPAs, mobile apps) that can't easily maintain server-side session state before the redirect, PKCE (file 6) provides overlapping but distinct protection and should be used in addition to, not instead of, `state`.
- Account-linking endpoints specifically should require the user to be re-authenticated (e.g., re-enter password) immediately before linking, not rely on `state` and an existing session alone, given how high-impact the forced-linking attack is.

## What Comes Next

File 4 moves from CSRF-style flow manipulation to two different problems: getting an OAuth token to carry *more* permission than it should (scope elevation), and getting a legitimately issued code or token to leak somewhere it shouldn't (Referer headers, browser history, logs, error messages).
