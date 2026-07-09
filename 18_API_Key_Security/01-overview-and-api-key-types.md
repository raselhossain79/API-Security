# API Key Security Testing — Overview and Key Types

## 1. What an API Key Actually Is

An API key is a static bearer credential. Unlike a session token (short-lived,
tied to a login event) or a JWT (structured, often self-describing, frequently
short-lived with a refresh cycle), an API key is usually:

- **Long-lived** — issued once, often valid indefinitely until manually revoked.
- **Opaque** — the server holds the meaning; the key itself is normally just a
  random-looking string with no embedded claims (contrast with a JWT, where the
  payload is inspectable — see the JWT Attacks series for that case).
- **Bearer-based** — whoever holds the string gets whatever access is bound to
  it. There is no proof-of-possession step in most implementations. This is the
  single most important fact driving this entire series: **if a key leaks, it is
  compromised, full stop, until it is rotated.**

This matters for testing methodology. With a JWT you might attack the signature
or the algorithm. With an API key there is nothing to attack cryptographically in
the key itself (assuming it's generated correctly) — the attack surface is almost
entirely: (1) how the key leaks, (2) whether the key was generated predictably,
and (3) whether the server-side authorization tied to the key is correct. This
series is structured around exactly those three surfaces.

## 2. Common API Key Formats You'll Encounter

Recognizing a key by its shape is the first skill in this series — it's what lets
you eyeball a JS bundle, a git diff, or a Burp history entry and immediately know
"that's a credential" before you've even confirmed it against the provider.

| Provider / Type | Typical Prefix | Typical Length | Notes |
|---|---|---|---|
| AWS Access Key ID | `AKIA`, `ASIA` | 20 chars, base32-like | `ASIA` = temporary (STS), `AKIA` = long-lived IAM user key |
| AWS Secret Access Key | none (paired with above) | 40 chars, base64 charset | Never appears alone in the wild without the Access Key ID nearby — search for both together |
| Google API Key | `AIza` | 39 chars | Common in Android/JS apps (Maps, Firebase) |
| Stripe Secret Key | `sk_live_`, `sk_test_` | ~24-107 chars after prefix depending on version | `sk_live_` is the one that matters; `sk_test_` still worth reporting but lower severity |
| Stripe Publishable Key | `pk_live_`, `pk_test_` | similar | Meant to be public — not a finding by itself, but confirms live vs test environment |
| GitHub Personal Access Token | `ghp_`, `github_pat_` | 40 / variable | Fine-grained PATs (`github_pat_`) carry explicit scopes — worth decoding what repos/orgs it touches |
| GitHub OAuth Token | `gho_` | 40 | |
| Slack Token | `xox[a-z]-` | variable | `xoxb` (bot), `xoxp` (user), `xoxs` (workspace) — different blast radius per prefix |
| Twilio | `SK`, `AC` prefix pairs | 34 chars | Account SID + Auth Token pair, same "search for the pair" logic as AWS |
| SendGrid | `SG.` | ~69 chars | |
| Mailgun | `key-` | 32 hex chars after prefix | |
| Firebase | often embedded as part of a JSON config, `AIza` prefix for the web API key | | Firebase web API keys are *meant* to be client-exposed in many configs — the real finding is usually a misconfigured Firebase Security Rules set, not the key itself. Don't over-report these without checking the rules. |
| Generic/custom keys | none — vendor-specific | typically 24–64 chars, hex or base64 | Requires entropy analysis rather than pattern matching (covered in File 3) |

**Why this table matters practically:** truffleHog, gitleaks, and nuclei all ship
with regex/entropy detectors built from tables like this one. Knowing the shapes
yourself means you can (a) sanity-check tool output instead of trusting it blindly,
and (b) manually spot custom/in-house key formats that no public detector rule will
catch — which is common in internal or early-stage APIs, and is exactly the kind
of finding that separates a manual tester from someone who just ran a scanner.

## 3. Where API Keys Fit in the Request

Three transmission patterns, each with different discoverability and different
testing implications:

1. **Header-based** (most common, most defensible): `X-API-Key: <key>` or
   `Authorization: Bearer <key>` / `Authorization: Apikey <key>`. Not logged by
   most default web server access logs, not visible in browser history, not
   auto-included in referrer headers. This is the pattern you *want* to see as a
   defender and the pattern that makes your job harder as a tester — leakage has
   to happen somewhere else (client-side code, git, etc.), because the wire
   traffic itself is comparatively clean.
2. **Query string-based**: `GET /v1/data?api_key=<key>`. This is the
   worst-practice pattern and the one most useful to you as a tester, because
   query strings land in: server access logs, browser history, the `Referer`
   header sent to third-party resources loaded on the same page, proxy logs,
   and browser DevTools Network tab trivially. A single screenshot of a URL bar
   can leak a key under this pattern.
3. **Body-based** (POST/PUT payload field): Less common for pure "API key as
   auth" but common where the key is one field among several (e.g., a webhook
   registration payload). Harder to leak via logs, but easy to leak via
   client-side JS if the app constructs the request in the browser.

When you find a key, always ask: *which of the three did the app use to transmit
it, and does that explain how it leaked?* This connects directly into File 2.

## 4. Threat Model for This Series

We are testing for four independent failure modes. A given target may have zero,
one, or all four:

1. **Leakage** — the key exists somewhere it shouldn't (client code, git history,
   a public Postman collection, an error message). Covered in File 2.
2. **Predictability** — the key was generated with insufficient entropy, such
   that an attacker could guess a *different* valid key without ever finding a
   leaked one. Covered in File 3.
3. **Over-scoping** — the key, once obtained (whether leaked or issued
   legitimately to a low-privilege consumer), grants more access than its stated
   purpose. Covered in File 3.
4. **Revocation/rotation failure** — a key that was supposedly rotated or revoked
   still authenticates. Covered in File 3.

Each of these is a separate root cause and a separate finding in a report — do
not lump "found a leaked key" and "the leaked key still had admin scope" into one
bug. The first is an information disclosure / secrets management finding; the
second is a broken access control finding on top of it. Report them as chained
but distinct issues, the same way you would in the exploitation-chaining
capstone notes.

## 5. Why WAF / API Gateway Bypass Is Mostly Not Applicable Here

This is worth stating explicitly rather than silently omitting, per the standing
convention of this library.

WAFs and API gateways defend against *attack patterns in requests* — SQLi
payloads, XSS payloads, oversized bodies, malformed content types, abnormal
request rates. Almost nothing in this series involves crafting a malicious
request pattern that a WAF signature would recognize:

- **Discovering a leaked key** (File 2) happens almost entirely *off the wire* —
  in a JS file you downloaded normally, in a git repository, in a Postman
  collection someone published. There is no "attack request" for a WAF to
  inspect. A WAF sitting in front of the API has nothing to do with whether the
  key leaked in a GitHub commit six months ago.
- **Testing entropy/predictability** (File 3) is a passive/analytical exercise
  performed on keys you already have. Generating candidate keys and testing them
  *does* eventually touch the API and could theoretically trigger rate-limiting
  or anomaly detection — see the crossover note below.
- **Testing scope** (File 3) is a small number of authenticated requests using a
  key you already possess, sent to endpoints the key is or isn't supposed to
  reach. These are well-formed, legitimate-looking requests. A WAF has no
  syntactic reason to flag `GET /v1/admin/users` authenticated with a
  read-only key as malicious — that's an authorization decision the *application*
  has to get right, not something a gateway signature can catch.
- **Testing rotation gaps** (File 3) is a single request with an old credential.
  Same reasoning — nothing pattern-matchable.

**The one genuine crossover point:** if your predictability testing in File 3
involves brute-forcing or spraying a large number of candidate keys against a
live endpoint, you *will* run into rate limiting and bot protection — but at
that point you are no longer testing "API key security," you are executing a
credential-stuffing-style attack and should reference the dedicated **API
Rate Limit / Bot Protection Bypass** series for the WAF/gateway detection and
bypass content (request rate fingerprinting, IP rotation, header rotation,
timing jitter, CAPTCHA/challenge handling). This series will flag that
crossover point again in File 3 rather than duplicating that content here.

## 6. PortSwigger Coverage — Honest Assessment

PortSwigger Web Security Academy does not have a dedicated "API Key Security"
topic category. This is a genuine gap, not an oversight in this note series.
The closest relevant labs live under **Authentication**, **Information
Disclosure**, and **Web Cache Poisoning / Business Logic**, and are referenced
by exact fit in Files 2 and 3 rather than listed here in bulk. Where PortSwigger
has no equivalent lab at all — which is most of File 2's git-leakage and
Postman-leakage content, and most of File 3's entropy content — this series
points to HackTheBox API-focused challenges and real disclosed HackerOne reports
instead, and says so explicitly rather than stretching a loosely-related
PortSwigger lab to fit.

## 7. Cross-References

- **API Reconnaissance** — for enumerating where an API even transmits keys
  before you start hunting for leaks.
- **Broken Authentication (API2)** — for auth mechanisms that aren't static keys
  (session tokens, OTP, credential stuffing).
- **JWT Attacks** — for structured, self-describing tokens; contrast with the
  opaque-string model this series covers.
- **OAuth 2.0** — for delegated-access tokens, which share some scope-testing
  logic with File 3 of this series but have their own flow-level attack surface.
- **API Rate Limit / Bot Protection Bypass** — for the WAF/gateway content that
  applies only if your predictability testing escalates to bulk key guessing.
