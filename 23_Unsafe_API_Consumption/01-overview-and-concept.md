# 01 — Overview and Concept: Unsafe Consumption of APIs (API10:2023)

## 1. What this category actually is

Every other category in the API Security Top 10 (API1–API9) assumes your
application is the **server**: something outside sends it a request, and the
risk is that your server trusts that request too much.

API10 flips the role. Your application is the **client**. It calls a
third-party API — a payment gateway, a geolocation lookup, a currency
converter, a social login provider, an internal microservice owned by a
different team, a SaaS integration, a webhook delivery — and it receives a
response. The vulnerability is that developers who are careful about
validating *inbound* requests from users are often completely uncareful about
validating *inbound* responses from services they integrate with.

The mental model:

```
User → [Your API] → Third-Party API
                          |
                          v
                   Third-party response
                          |
                          v
              [Your API trusts this blindly]
                          |
                          v
              Injection / SSRF / logic bypass
```

The third-party response is treated as "internal" data because it didn't come
from a browser or a public endpoint. But from a trust perspective, it is
exactly as external as user input — arguably more dangerous, because
developers rarely apply the same sanitization discipline to it.

## 2. Why this happens (the root cause)

Three assumptions developers make, all of them wrong in different ways:

1. **"We control the integration, so the data is safe."** You control *when*
   you call the API. You do not control *what it returns*. If the third
   party is compromised, has a bug, gets DNS-hijacked, or is itself vulnerable
   to injection from someone else's input that eventually flows into the
   response it hands back to you, you inherit that risk.
2. **"It's just a partner/vendor, not an attacker."** Supply-chain
   compromises (of package registries, SaaS platforms, CDN providers) are a
   well-established pattern. A legitimate vendor today can be a compromised
   distribution point tomorrow, and your application will have no idea,
   because nothing about the request changed — only the response.
3. **"We validated the response is 200 OK / valid JSON, so it's fine."**
   Syntactic validity (valid JSON, valid XML) says nothing about semantic
   safety. A perfectly well-formed JSON string can still contain a SQL
   injection payload in a field value.

## 3. Attack surface: where this shows up in real applications

Any outbound integration is a candidate:

- Geolocation / IP-lookup APIs (city, region, ISP name fields)
- Currency conversion / pricing APIs
- Payment gateways and their webhook/callback payloads
- Social login / OAuth userinfo endpoints
- Third-party file/malware scanning APIs (returning a "clean filename" or verdict)
- Shipping/logistics APIs (address normalization services)
- Weather, translation, and other "trusted utility" APIs
- Internal microservice-to-microservice calls (a compromised internal service is functionally a malicious third party to the service consuming it)
- Webhook subscriptions where the "third party" sends *you* data on its own schedule

## 4. The four sub-risks this series covers

| Sub-risk | Summary | File |
|---|---|---|
| Injection | Response field is concatenated into a query/template/command | `02-injection-via-third-party-response.md` |
| SSRF | Response field contains a URL your server fetches without validation | `03-ssrf-via-third-party-response.md` |
| Data integrity | Response schema/type is not validated, causing type confusion, null dereference, or fail-open logic bypass | `04-data-integrity-issues.md` |
| (Testing) | How to actually find these in black-box vs grey-box engagements | `05-testing-methodology.md` |

## 5. WAF / API Gateway relevance — read this before the other files

This is called out explicitly, as requested, rather than silently skipped.

**For the injection (file 02) and data-integrity (file 04) sub-risks, WAF and
API Gateway defenses are largely not applicable, and here is why:**

- A WAF sits in front of your API and inspects **inbound** HTTP traffic from
  clients calling *you*. It has no visibility into the outbound HTTP call your
  backend makes to a third party, nor the response that comes back on that
  connection. That traffic never crosses the WAF.
- An API Gateway in the conventional sense (the one fronting your own API for
  your own consumers) has the same blind spot. It is not positioned to
  inspect server-to-server egress calls unless it is specifically deployed as
  a **forward/egress proxy**, which is architecturally a different
  deployment than the typical "gateway in front of my API" setup.
- Because the exploit payload arrives via a response body on a connection
  your own backend initiated, there is no "attacker request" for a signature-
  based WAF rule to match against in the first place. The dangerous action is
  a local processing step (string concatenation into a query, for example),
  not a network-observable request pattern.

**Where gateway/proxy-level defense *does* become relevant: the SSRF
sub-risk (file 03).** If your application fetches a URL that came from a
third-party response, an **egress-filtering proxy or gateway that enforces a
destination allowlist** can meaningfully reduce risk, because at that point
there genuinely is an outbound network request that a control point can
intercept and evaluate. File 03 has a dedicated section on this, including
realistic bypass considerations (DNS rebinding, redirect chains, allowlisted-
domain open redirects).

**Bottom line:** treat API10 primarily as an **application-layer trust and
validation problem**, not a network perimeter problem. The fix lives in your
code (schema validation, output encoding, parameterization, URL allowlisting
at the point of use) far more than it lives in a WAF rule set.

## 6. Real-world note

A pattern worth internalizing: the highest-impact real-world instances of
this category are rarely "attacker directly controls a big-name API."
They're usually one of:

- A **feature that lets your own users configure a third-party endpoint**
  (custom webhook URL, custom API base URL, "bring your own integration"),
  where the "third party" is trivially attacker-controlled — this is the
  single most exploitable and most commonly reported real-world variant, and
  it's the basis for most of the practical testing technique in file 05.
- A **shared/open-source dependency or SaaS platform compromise** that
  affects many downstream consumers at once (the supply-chain angle).
- **Fail-open logic on third-party errors or timeouts** — covered in depth in
  file 04 — where a malformed or unreachable third party causes the
  application to default to an insecure state (e.g., treating a failed fraud
  check as "not fraud").

Continue to `02-injection-via-third-party-response.md`.
