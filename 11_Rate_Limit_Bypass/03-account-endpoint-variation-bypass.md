# 03 — Account-Level and Endpoint Variation Rate Limit Bypass

## Prerequisite

Read `01-how-api-rate-limiting-works.md` and `02-header-based-ip-spoofing-bypass.md` first. This file covers what to do when the identity key **isn't IP-based** (account/session keyed) or when the counter itself is keyed on the **request path string** rather than a normalized endpoint identity.

## PortSwigger Lab Mapping (Honest Disclosure)

- **"Rate limit bypass via multi-endpoint request distribution"** (Business logic vulnerabilities topic) is the direct official lab for the endpoint-variation half of this file — work through it after reading section 2 below.
- There is no official Academy lab for multi-account distribution bypass specifically. The closest conceptually related lab is **"Broken brute-force protection, multiple credentials per request"**, which teaches a related but distinct technique (batching credentials into one request rather than spreading requests across many accounts). Section 1 below is sourced from real-world API abuse patterns (freemium tier abuse, review-bombing, credential stuffing infrastructure) rather than a single Academy lab.

## 1. Account-Level Rate Limit Bypass — Distributing Across Identities

### 1.1 Why This Identity Key Exists

Once a target has hardened against IP-based bypass (file 02) — e.g., by rate limiting on authenticated session or account ID instead of IP — the rate limiter's key becomes "who is logged in," not "where are they connecting from." This is a **stronger** control than IP-based limiting because account creation usually has more friction than sending a spoofed header. The strength of this control is entirely a function of how much friction stands between an attacker and a fresh, valid account.

### 1.2 The Trust Assumption Being Exploited

The rate limiter assumes: **"one account == one distinct actor, and actors are hard to create in bulk."** This assumption breaks down piece by piece depending on the target's signup flow:

| Signup friction | Attacker cost per new identity | Practical impact |
|---|---|---|
| Email verification only, disposable email accepted | Near-zero (automatable with disposable email APIs) | Account-based limiting provides almost no real protection |
| Email verification, disposable domains blocklisted | Low (requires a small pool of real or aged mailbox providers) | Meaningfully raises cost but rarely stops a motivated attacker |
| Phone/SMS verification | Moderate (SMS-receiving services, though many are now blocklisted by providers) | Substantially raises cost — often enough to deter casual abuse |
| Manual/paid onboarding, KYC | High | Account-based limiting is genuinely strong here |
| OAuth via third-party (Google/GitHub login only) | Depends entirely on the friction of creating *those* accounts, which is usually also low | Rate limiter inherits the weakest link in the chain |

**The piece-by-piece exploit:** the rate limiter correctly counts requests per account — that part isn't broken. What's broken is the **assumption that the account itself is a costly, scarce resource**. If it isn't, the attacker simply creates N accounts and divides their total request volume by N, keeping every individual account's count under threshold while the aggregate throughput is N times the intended limit.

### 1.3 Practical Distribution Pattern

```
Target limit: 10 requests / account / minute
Attacker goal: 100 requests / minute total

Attacker provisions 10 accounts (A1-A10)
Requests are round-robined:
  req 1  -> A1
  req 2  -> A2
  ...
  req 10 -> A10
  req 11 -> A1  (A1 is now at count 2, well under its individual limit of 10)
  ...
```

The key implementation detail: **stagger account creation and warm-up too.** A defensive system watching for abuse often flags a burst of brand-new accounts all immediately hitting the same endpoint at high frequency as a correlated signal independent of any single account's rate — this is a detection method that operates *above* the per-account rate limiter, and is covered from the defender's side in file 05 (behavioral analysis). To evade it: age accounts before use where feasible, and avoid perfectly synchronized round-robin timing (see file 04 for timing jitter).

### 1.4 Real-World Note

This exact pattern is the basis of most "freemium tier abuse" bug bounty reports — e.g., an AI API or SaaS product that rate-limits free-tier usage per account, where account creation only requires an email. Programs vary widely on whether they consider this in-scope (many treat it as "intended business risk" rather than a security vulnerability, since it's arguably a business/fraud problem, not an authentication bypass) — **check the program's scope and past disclosed reports before spending significant time here**, since it is one of the more frequently N/A'd or "informative only" finding categories in bug bounty triage.

## 2. Endpoint Variation Bypass — Attacking the Counter's Key Normalization

### 2.1 Why This Works — The Normalization Gap

A rate limiter that keys on the literal request path string (`/api/v1/login`) rather than a *normalized, routed* endpoint identity is trusting that "the same logical endpoint is always requested with the exact same string." Web frameworks and routers, however, are usually far more permissive about what strings map to the same handler than the rate limiter is about what strings map to the same counter key. This is a **mismatch between the routing layer's leniency and the rate limiter's strictness** — and it's exploitable precisely because these are frequently two entirely separate pieces of middleware that don't share a normalization function.

### 2.2 Variation Techniques, Piece by Piece

**Case variation:**
```
/api/v1/login
/api/v1/Login
/api/v1/LOGIN
```
Why it works: HTTP path matching is case-sensitive in the URL spec, but many web frameworks (and virtually all Windows-hosted IIS/.NET stacks by default) route case-insensitively at the handler level, while a rate limiter implemented as separate middleware — especially one bolted on via a WAF rule or CDN rule using exact string match — often is not. The handler executes identically; the counter key differs.

**Trailing slash variation:**
```
/api/v1/login
/api/v1/login/
```
Why it works: most routers treat these as equivalent by default (some frameworks even issue an automatic redirect between them), but a naive rate-limit key built directly from `request.path` treats them as two distinct strings.

**Path parameter / extra segment injection:**
```
/api/v1/login
/api/v1/login;
/api/v1/login%2F
/api/v1/login/./
/api/v1/./login
/api/v1//login
```
Why it works: these exploit path normalization differences between the rate limiter and the router even more aggressively — double slashes, dot-segments, and encoded slashes are collapsed to the canonical path by most routers (per RFC 3986 normalization) but not necessarily by whatever component computes the rate-limit key, especially if that component runs *before* the framework's own path normalization step (e.g., a WAF or reverse-proxy rule).

**Query string variation:**
```
/api/v1/login
/api/v1/login?x=1
/api/v1/login?cachebust=<random>
```
Why it works: this specifically targets rate limiters (or, more often, caching layers mistaken for rate limiters) that key on the full URL including query string rather than just the path — appending an arbitrarily changing query parameter that the handler ignores produces a fresh key on every request while hitting the identical logical endpoint.

**API version prefix variation:**
```
/api/v1/login
/api/v2/login   (if v2 exists and proxies to the same underlying logic)
/api/login      (unversioned alias, if one exists)
```
Why it works: this isn't a normalization trick so much as a **coverage gap** — if a rate limit rule was written for one specific versioned path and the same business logic is reachable through a second path (a newer API version, an internal alias, a mobile-specific endpoint), the rule simply doesn't apply to the second path at all. This is extremely common after API version migrations where old rules aren't ported forward to new route definitions.

### 2.3 How to Systematically Discover Which Variations Bypass the Counter

1. Establish baseline: trigger the rate limit on the canonical path, note the exact response (429 status, custom block page, `Retry-After` header value).
2. For each variation technique above, reset to a fresh window (or fresh IP/account if needed) and send the same request count using the variation. If the block does not trigger, the counter key does not normalize that variation.
3. **Critically, verify the request still reaches the intended handler and produces the intended business logic effect** (e.g., an actual login attempt, not a 404). A bypass that returns 404 is not a bypass — it just means you found an unreachable path.
4. Chain variations with header spoofing (file 02) — a target with both an IP-based front-line rate limiter and a path-string-based counter behind it will need both bypasses combined to fully evade end-to-end.

### 2.4 Real-World Note

Endpoint variation bypass is disproportionately effective against rate limiting implemented as **WAF rules or CDN page rules** (string/regex match on URL) rather than application-code rate limiting (which usually goes through the framework's router first and inherits its normalization). When testing, prioritize targets you suspect are using edge/WAF-layer rate limiting — response header fingerprints like `cf-ray`, `x-sucuri-id`, or vendor-specific block pages are good indicators to look for before investing time in variation testing.

## Next File

`04-timing-window-distribution-bypass.md` — exploiting window boundaries and refill timing once you've identified the algorithm type from file 01.
