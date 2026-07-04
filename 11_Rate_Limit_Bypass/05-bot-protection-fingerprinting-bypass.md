# 05 — API-Specific Bot Protection and Fingerprinting Bypass

## Scope Note

This file explicitly excludes image/audio CAPTCHA solving — that's a separate (and largely automation-service-driven, not technique-driven) problem outside this series' scope. This file covers the detection layers that operate on **API traffic characteristics** rather than presenting an interactive human-verification challenge: TLS fingerprinting, header consistency analysis, and request behavioral/cadence analysis.

## PortSwigger Lab Mapping (Honest Disclosure)

**There is no PortSwigger Academy lab covering this content.** TLS/JA3 fingerprinting and behavioral bot detection are not part of the Academy curriculum as of this writing — they sit closer to the WAF/bot-management vendor space (Cloudflare Bot Management, Akamai Bot Manager, DataDome, PerimeterX/HUMAN) than to the classic web-app vuln classes Academy focuses on. This entire file is sourced from vendor documentation (published to explain their own detection methodology, often in the context of selling the product), public bot-management bypass research, and observed patterns in bug bounty writeups. Flagging this clearly: treat this file as the least lab-verifiable of the series, and expect vendor-specific behavior to vary and change over time.

## 1. TLS Fingerprinting (JA3 / JA4)

### 1.1 What's Being Measured

When a client initiates a TLS handshake, the `ClientHello` message contains a specific, ordered set of fields: TLS version, cipher suite list (and their order), extensions list (and their order), elliptic curve list, and elliptic curve point formats. **JA3** is an MD5 hash of a normalized string built from these fields. **JA4** is a newer, more detailed successor format from the same research lineage.

### 1.2 Why This Is Trusted As a Bot Signal

The insight bot-management vendors rely on: **different TLS libraries produce different, highly consistent ClientHello fingerprints.** A request claiming (via its `User-Agent` header) to be Chrome on Windows, but whose TLS handshake fingerprint matches Python's `requests` library or `curl`, is an internally inconsistent request — the HTTP-layer identity claim doesn't match the TLS-layer behavioral fact. This inconsistency is a strong bot signal because it's very hard to fake by accident: most HTTP client libraries use whatever their language's default TLS stack produces, and don't touch it, because doing so requires TLS-library-level configuration most developers never need.

### 1.3 The Exploit, Piece by Piece

The defense assumes an attacker's tooling will use its default TLS stack. The bypass is to **make the TLS handshake match what a real browser produces**, independent of what HTTP library issues the actual request:

- Tools like `curl-impersonate` and TLS-client libraries in Go/Python that specifically re-implement Chrome's or Firefox's exact cipher suite ordering and extension list exist precisely to close this HTTP/TLS-layer mismatch — this is a "reduce your own inconsistency" bypass rather than a flaw in the target's logic.
- The `User-Agent` header and the TLS fingerprint must match a **plausible, currently-real** browser/version combination — using a JA3 fingerprint for Chrome 90 alongside a `User-Agent` claiming Chrome 125 reintroduces a different flavor of the same inconsistency signal (an implausible version pairing), so both need to be kept internally coherent and current.
- **Why this matters specifically for rate limiting, not just generic bot blocking:** several CDN/bot-management platforms use TLS fingerprint as an *additional* identity key layered on top of IP, specifically because it survives IP rotation (file 02) — if you're rotating source IPs or spoofed headers but every request shares the identical (default HTTP library) TLS fingerprint, the platform can still cluster and rate-limit you by fingerprint even though your IP-layer identity looks fresh on every request.

## 2. Header Consistency and Ordering Fingerprinting

### 2.1 What's Being Measured

Beyond individual header *values*, real browsers send headers in a **consistent, predictable order** and always include a specific *set* of headers together (e.g., real Chrome requests reliably include `sec-ch-ua`, `sec-fetch-site`, `sec-fetch-mode`, `sec-fetch-dest` in a consistent combination and order, alongside `Accept-Language` formatted in a specific way).

### 2.2 Why This Is Trusted

Most HTTP client libraries (Python `requests`, Node `axios`, Go `net/http`) set only the headers the developer explicitly specifies, in the order they were added programmatically, with a much smaller default set than a real browser sends. This produces a **detectably sparse and unusually-ordered** header set compared to genuine browser traffic — again, an internal-consistency signal, this time entirely at the HTTP layer with no TLS involvement needed to detect it.

### 2.3 The Exploit, Piece by Piece

- Capture a full, real header set (order included) from an actual browser session against the target (via browser dev tools' "copy as cURL" or a proxy like Burp) and replicate that **exact set, in that exact order**, on every automated request — most HTTP libraries allow explicit header ordering via `OrderedDict`-style structures or raw request construction rather than relying on default insertion order.
- Include the modern `sec-ch-ua*` Client Hints headers with values consistent with the claimed `User-Agent` — omitting them entirely, on a request claiming to be a recent Chrome version, is itself a red flag, since real recent Chrome always sends them.
- Match `Accept-Language`, `Accept-Encoding`, and `Accept` header values to genuinely common real-world browser defaults rather than a library's minimal default (e.g., a bare `Accept: */*` is a common giveaway of scripted traffic).

## 3. Behavioral and Cadence Analysis

### 3.1 What's Being Measured

This layer looks at **patterns across a sequence of requests** rather than any single request in isolation: inter-request timing distribution, mouse-movement/JS-execution telemetry (for browser-rendered flows), sequence of endpoints hit (does the client request a page's HTML, then its CSS/JS/images in the pattern a real browser would, or does it go straight to the API endpoint with none of the supporting asset requests a real page load would generate), and consistency of behavior across a session.

### 3.2 Why This Is Trusted

A real human using a real browser generates a rich, noisy, and *incidentally consistent* pattern of surrounding traffic and timing variance that is expensive and easy to overlook replicating. Pure API-level automation typically only issues the exact calls needed for the attacker's goal, skipping every incidental request a real page load would trigger, and does so with far more regular timing than genuine human input produces.

### 3.3 The Exploit, Piece by Piece

- **Timing jitter** (also covered in file 04, section 4): avoid perfectly regular intervals; sample delays from a distribution that resembles human reaction/reading time rather than a fixed sleep value.
- **Replicate incidental request patterns** where the detection is known/suspected to check for them: if targeting an API that backs a web UI, consider whether requesting the associated static assets (or at minimum, presenting a `Referer` header consistent with having navigated from the actual page) reduces the "API-only, no page context" signal.
- **Session consistency:** if a session/cookie is involved, don't rotate identity keys (file 02/03) *mid-session* in a way that produces impossible patterns (e.g., the same session cookie suddenly presenting a completely different IP geolocation, TLS fingerprint, and User-Agent string within the same short session) — this kind of intra-session inconsistency is one of the highest-confidence bot signals available to a defender because it requires no baseline of "normal" to detect; the inconsistency is self-evident from a single session's data alone.
- **For genuinely JS-driven behavioral telemetry** (mouse movement, keystroke dynamics, canvas/WebGL fingerprinting collected client-side and sent to a bot-management vendor's endpoint): this moves outside pure API testing into browser automation territory (tools like Playwright/Puppeteer with stealth plugins that patch the automation-detectable properties `navigator.webdriver`, headless-mode artifacts, etc.) — flagged here as a boundary of this series' scope, since it's a browser-automation-detection problem distinct from direct API request crafting.

## 4. Real-World Notes

- Bot-management vendors explicitly market **layered** detection (TLS + header + behavioral + IP reputation combined into a single risk score) precisely because each individual signal is bypassable in isolation, as shown above — successfully evading all layers simultaneously requires combining every technique in this file consistently, not picking one.
- From a defensive/reporting perspective: if you achieve a rate-limit or bot-protection bypass using these techniques during authorized testing, the strongest report includes **which specific layer(s) failed to catch you** (e.g., "TLS fingerprint matched real Chrome, so the platform's fingerprint-based detection did not trigger, but the request cadence was still robotic — the target's cadence-analysis layer either doesn't exist or has a threshold high enough to be practically ineffective") — this level of piece-by-piece attribution is far more actionable for the client than a generic "bot protection was bypassed" statement.
- Many of these vendor products (Cloudflare Bot Management, DataDome, PerimeterX/HUMAN, Akamai Bot Manager) publish their own detection philosophy in marketing/technical blog content — reading the vendor's own explanation of what they detect is often the fastest way to reverse-engineer what a specific deployment is likely checking, before spending testing time trial-and-error probing blind.

## Next File

`06-cheatsheet.md` — condensed quick-reference for all techniques in this series.
