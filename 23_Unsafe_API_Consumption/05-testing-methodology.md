# 05 — Testing Methodology: Black-Box vs Grey-Box vs White-Box

## 1. Honest framing first

API10 is the hardest category in the entire OWASP API Security Top 10 to
find in pure black-box testing, and it's worth understanding exactly why
before diving into technique, so you don't waste engagement time expecting
black-box results this category usually can't give you.

The vulnerability lives in code you, as an external tester, cannot see: the
line where your target's backend processes a response from *its* upstream
vendor. In black-box testing you typically have no visibility into:

- Which third-party APIs the target even integrates with
- What that third party actually returned for any given request
- Whether the processing of that response is safe or unsafe

This is fundamentally different from, say, BOLA (API1) or Mass Assignment
(API3), where you can directly manipulate the request and observe the
response — the entire attack surface is visible to you as an external
party. For API10, the attack surface (the vendor response) is usually
invisible unless you can either control it, intercept it, or read the code
that processes it.

## 2. Black-box approach — what's actually achievable

You cannot test unsafe consumption of a vendor's API you don't control. But
you *can* test it in the specific, common case where **the target lets you
configure what the "third party" is** — because at that point, you become
the third party, and the response is entirely under your control.

**Look for these features specifically:**

- Custom webhook URL configuration ("notify us at this URL when X happens" — but inverted: "we'll POST to your URL," or less commonly, a URL *you* provide that the app later fetches/expands)
- "Connect your own API key / endpoint" integrations (custom CRM URL, custom analytics endpoint, self-hosted service integrations)
- URL/link preview or unfurling features (paste a link, app fetches metadata)
- File import via URL ("import from URL" instead of direct upload)
- Any "bring your own service" SSO/OAuth provider configuration
- Payment gateway sandbox/test mode where you can point the app at a controlled mock endpoint

**Practical black-box technique once you find such a feature:**

1. Stand up a small HTTP server you control (a simple Python/Node script or
   a service like `ngrok`/`requestbin` for quick iteration) that you can
   configure to return arbitrary response bodies.
2. Register your server as the "third party" (webhook target, import URL,
   custom API endpoint — whatever the feature allows).
3. Trigger the app to call your server, and iterate on the response:
   - Return injection payloads in string fields (`'; DROP TABLE...`, `{{7*7}}`) to test file 02's scenarios.
   - Return internal URLs (`http://169.254.169.254/...`, `http://localhost:PORT/`) in any URL-typed field to test file 03's scenarios.
   - Return wrong types (string where a number is expected, `null`, missing fields, empty arrays) to test file 04's scenarios.
   - Return an HTTP 500, a timeout (don't respond at all), or a non-JSON body to specifically probe fail-open logic (file 04, Scenario 3).
4. Observe application behavior: error messages, timing differences,
   out-of-band callbacks to a listener you control (for blind SSRF —
   use a unique subdomain per test to correlate DNS/HTTP callbacks), and
   any state changes (was a transaction allowed that should have been
   blocked?).

This technique converts what would otherwise be an untestable black-box
category into a fully testable one, wherever the "custom endpoint" feature
exists. Where it doesn't exist, be honest in your report: this category is
out of scope for meaningful black-box coverage on this specific target, and
recommend a grey-box or source-assisted follow-up.

## 3. Grey-box approach

With partial access (a low-privilege account, some documentation, or the
ability to see server-side error messages/stack traces), grey-box testing
adds:

- **Error message analysis**: forcing third-party call failures (e.g., by
  submitting inputs likely to cause a vendor-side error — invalid formats,
  edge-case values) and reading resulting stack traces, which often reveal
  which library/vendor is being called and how the response is parsed.
- **Response headers/timing**: server response time differences that
  suggest a third-party call happened synchronously in the request path
  (useful for identifying *which* endpoints even have this attack surface
  before you can test them further).
- **Any legitimate access to configure a real (not mocked) third-party
  integration** — if you have a low-privilege account that lets you connect
  a real but attacker-influenceable third-party service (e.g., you can
  register your own account with a supported OAuth provider and control
  fields in your own OAuth profile), you can plant payloads in fields that
  flow back through the legitimate integration.

## 4. White-box approach (source code review) — where this category is actually reliably found

If you have source access, this is by far the most productive way to assess
this category:

1. **Grep for outbound HTTP client usage**: `requests.get`, `fetch(`,
   `axios.`, `HttpClient`, `curl_exec`, `urllib`, gRPC client stubs, etc.
   Build a list of every outbound integration point.
2. **For each one, trace the response variable forward**: does it get
   deserialized into a typed model/schema (good), or used as a loose
   dict/object with no validation (bad)?
3. **Check for these specific anti-patterns**:
   - String concatenation of any response field into a SQL query, shell
     command, template string, or `eval`/`exec`-like construct (file 02).
   - Any response field typed or documented as a URL that is passed to an
     HTTP client call without a destination allowlist check (file 03).
   - Absence of schema/type validation library usage (Pydantic, JSON
     Schema, Zod, class-validator, protobuf-generated types, etc.) around
     deserialization of the response (file 04).
   - `try/except`/`try/catch` blocks around a third-party call whose
     `except`/`catch` branch defaults to an *allow* or *success* state
     (file 04, Scenario 3 — the fail-open pattern; this is the single
     highest-value grep target in this entire category).
   - Generic recursive merge/deep-extend calls applied to third-party
     response data without key filtering (file 04, Scenario 5 /
     Prototype Pollution cross-reference).

## 5. PortSwigger Web Security Academy lab mapping — stated honestly

**There is no dedicated API10 / Unsafe Consumption of APIs lab track on
PortSwigger Web Security Academy at the time of writing, and there is no
clean Apprentice → Practitioner → Expert progression specific to this
category.** This should be stated plainly rather than forcing an artificial
mapping — the Academy's API-specific labs concentrate on API1 (BOLA),
API3 (Mass Assignment), and general REST/GraphQL testing methodology, not
on the "your server unsafely trusts an upstream response" pattern.

What *is* genuinely useful, because the exploitation mechanics transfer
directly even though the trigger point (third-party response vs. direct
user input) differs:

- **For the SSRF sub-risk (file 03)** — work through the Academy's SSRF lab
  track in order; the destination-fetching logic you're bypassing is
  mechanically identical once you're the one supplying the malicious URL
  (which, per the black-box technique in section 2, you often will be):
  - *Apprentice*: "Basic SSRF against the local server" and "Basic SSRF
    against another back-end system"
  - *Practitioner*: "SSRF with blacklist-based input filter",
    "SSRF with whitelist-based input filter", "SSRF with filter bypass via
    open redirection vulnerability"
  - *Expert*: "Blind SSRF with out-of-band detection", "Blind SSRF with
    Shellshock exploitation"
- **For the injection sub-risk (file 02)** — the SQL Injection, SSTI, and
  OS Command Injection lab tracks (see those series for full lab lists)
  teach the exact payload construction; the only adaptation needed for
  API10 is delivering the payload via a response field you control (per
  section 2's technique) instead of a request parameter.
- **For the data-integrity sub-risk (file 04)** — there is no close
  PortSwigger analog; this is best practiced via source review of small
  intentionally-vulnerable sample apps (see crAPI note below) or by writing
  your own minimal test harness that consumes a mock third-party API you
  control.

## 6. Supplementary practice — grey-box CTF and HackTheBox

Because PortSwigger coverage is minimal, supplementary practice for this
category leans more on grey-box/source-available environments than on
black-box web labs:

- **crAPI (Completely Ridiculous API)**: doesn't have a challenge
  purpose-built for "unsafe consumption of a third-party API," but its
  source is available, and it does integrate with supporting services
  (e.g., a mail-catcher service, a coupon/community service) in its
  docker-compose stack. Reading how crAPI's own services consume each
  other's responses (treating crAPI's internal services as "third
  parties" to each other) is a reasonable low-effort way to practice the
  white-box review technique from section 4 against real, if intentionally
  vulnerable, code.
- **HackTheBox**: rather than pointing at specific named boxes (box
  availability and content rotate, and misremembering a box's actual
  vulnerability chain would be worse than not citing one), search HTB's
  active machine list and filtering tags for **SSRF** and **webhook**
  tagged boxes — a good number of HTB machines chain an SSRF against an
  internal service discovered *through* a legitimate integration/webhook
  feature as one step in a larger exploitation path, which is exactly the
  pattern in file 03. Treat any box in that category as practice for
  "finding an SSRF that's reachable only because the vulnerable app trusts
  a URL sourced from another service," even when the box's own writeup
  doesn't use OWASP API10 terminology for it.
- **Build your own mock third-party**: given how much of this category
  depends on controlling a response, the single most effective practice
  setup is writing a tiny local API (Flask/Express, a dozen lines) that a
  toy consuming app calls, and then deliberately making the consuming app
  vulnerable to each of the four sub-risks in this series, one at a time,
  so you can observe exploitation end-to-end with full visibility on both
  sides. This mirrors the white-box review workflow you'll use on real
  engagements far more closely than any pre-built lab can.

Continue to `06-final-checklist.md`.
