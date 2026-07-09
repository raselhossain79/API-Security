# API SSRF — Overview and Context

## Scope of This Series

This series covers Server-Side Request Forgery (SSRF) as it appears specifically in
API contexts. It assumes familiarity with the core SSRF mechanism (a server-side
component makes an HTTP request to a URL that is influenced or fully controlled by the
attacker) and does **not** re-explain the general technique. For the mechanism itself,
and for the full catalogue of filter bypass methods (blacklist bypass, whitelist
bypass, IP encoding tricks, DNS rebinding, redirect chaining, protocol smuggling via
`gopher://`, `file://`, `dict://`), see the Web Application Security — SSRF series.
Those bypass techniques apply unchanged once you have located an API parameter that
triggers a server-side request — this series is about finding that parameter, the
API-specific patterns it appears in, and what to do once SSRF is confirmed in an API.

## What Differs From Web Application SSRF

Web application SSRF is usually discovered through a browsable UI feature — an "import
from URL" button, an avatar upload widget, a PDF export tool. The request that
triggers the outbound fetch is visible because you interact with a page and watch the
network tab.

API SSRF is different in three structural ways:

**1. The trigger is a JSON/XML field, not a UI action.**
There is frequently no visible UI at all. The vulnerable parameter is a field inside a
REST request body (`"webhookUrl": "..."`), a GraphQL mutation argument, or a form field
in a multipart upload endpoint. You will not find it by clicking around — you find it
by reading API documentation, OpenAPI/Swagger specs, or by systematically reviewing
every endpoint that accepts a body for any field whose name or value shape suggests a
URL. Recon methodology for this is covered in file 2.

**2. The consumer of the URL is often not the API server itself, but a downstream
service the API calls on your behalf.**
A "create webhook subscription" endpoint doesn't fetch your URL immediately — it
stores it, and a separate worker process, notification service, or third-party
integration (Slack, Stripe, an internal message queue) makes the request later,
asynchronously, when an event fires. This means:
  - The response you see from the API call is not the response of the SSRF request.
    Confirmation is often blind (see file 4).
  - The request may originate from a different host/IP than the one you sent the API
    call to — commonly a worker node with different network reach, which is exactly
    why this pattern is valuable for internal pivoting (file 5).
  - Timing is decoupled: the outbound request might fire seconds, minutes, or only
    "on next event" after your API call.

**3. APIs are far more likely to be running inside cloud-native, containerized
infrastructure with instance metadata services reachable from the request path.**
Web apps SSRF often targets `localhost` services. API backends — especially
microservice architectures on AWS/GCP/Azure — are far more likely to have direct,
unauthenticated network access to a cloud metadata endpoint, and the credentials
returned there are usually scoped to that specific service's IAM role, making the
payoff proportionally larger. File 3 covers this in depth.

## API SSRF Delivery Surface (What to Expect)

Across REST, GraphQL, and webhook-style integrations, SSRF-capable parameters cluster
into a small number of recurring categories:

| Category | Typical field names | Why it exists |
|---|---|---|
| Webhook/callback registration | `webhookUrl`, `callbackUrl`, `notifyUrl`, `redirectUri` | Product needs to push events to a customer-controlled endpoint |
| Avatar/image import | `avatarUrl`, `imageUrl`, `logoUrl` | Lets users set a profile image "by URL" instead of uploading a file |
| Document/file import | `importUrl`, `sourceUrl`, `fileUrl`, `documentUrl` | Bulk import, "import from Google Drive/Dropbox link", PDF generation from URL |
| Federated/SSO metadata fetch | `metadataUrl`, `oidcDiscoveryUrl`, `jwksUri` | SSO configuration commonly fetches a remote JSON/XML metadata document |
| Payment/invoice integration | `returnUrl`, `cancelUrl`, `ipnUrl` | Third-party payment providers call back to a merchant-supplied URL |
| Link preview / unfurling | `url` in a "preview" or "og-data" endpoint | Chat apps and note tools fetch a URL server-side to render a rich preview |
| PDF/screenshot rendering | `targetUrl`, `pageUrl` | Server-side headless browser renders a given URL to PDF/PNG |

This table is a starting point for recon, not an exhaustive list — file 2 covers how
to find fields that don't match an obvious naming convention.

## WAF / API Gateway Relevance for This Vulnerability Class

Unlike some vulnerability classes in this note library (SQLi, XSS) where WAF signature
matching and bypass is a large, standalone topic, WAF/API Gateway defenses are
**meaningfully relevant to API SSRF, but in a narrower and more mixed way** than for
those classes. This is worth stating explicitly:

- Generic WAFs (ModSecurity-style, cloud WAFs at the edge) largely **cannot** detect
  SSRF from the inbound request alone, because a JSON field containing
  `"webhookUrl": "http://169.254.169.254/..."` is syntactically indistinguishable from
  a legitimate webhook URL. There is no injection syntax to pattern-match, unlike SQLi
  or XSS payloads. WAF vendors instead rely on **egress-side controls** (blocking the
  outbound request itself) rather than **ingress-side detection** — this is why the
  meaningful defense for SSRF lives at a different layer than for injection classes.
- API Gateways (Kong, AWS API Gateway + Lambda authorizers, Apigee) sometimes apply
  **outbound allowlisting** at the service layer — restricting what hosts a given
  microservice is permitted to call. This is the actual effective control for SSRF and
  is covered where it applies in files 2, 3, and 5, rather than as a single dedicated
  bypass section, because the bypass considerations differ by context (metadata
  endpoint blocking vs. internal CIDR blocking vs. DNS-based allowlist bypass).
  Because this control is architecturally different per context, each file covers its
  own WAF/Gateway-relevant subsection instead of one generic treatment here.
- Where a generic input-filter WAF *does* attempt SSRF detection (blacklisting
  `169.254.169.254`, `localhost`, `127.0.0.1`, private CIDR ranges as string patterns
  in body fields), the bypass techniques for that filter are pure SSRF bypass
  technique — identical whether the field lives in a web form or a JSON API body. That
  content is intentionally **not duplicated here**; see the Web Application Security —
  SSRF series for blacklist/whitelist bypass methods. What this series adds is
  API-specific delivery and chaining context, not a second copy of the bypass catalogue.

## How This Series Chains With Other API Vulnerability Series

- **API4 (Unrestricted Resource Consumption):** repeatedly triggering an SSRF-capable
  import/webhook endpoint against a slow or large target can be used as a
  resource-exhaustion vector against the API's own worker pool.
- **API6 (Unrestricted Access to Sensitive Business Flows):** business flows that
  accept a URL (bulk import, invoice generation) are frequently the same endpoints
  vulnerable to SSRF — recon for one often surfaces the other.
- **BOLA/BFLA:** SSRF-to-internal-pivot (file 5) frequently lands on an internal
  admin API that itself has BOLA/BFLA issues, compounding the impact.
- **JWT/OAuth series:** metadata/JWKS URL fields (`jwksUri`, `oidcDiscoveryUrl`) are
  both an SSRF vector and, if you can point them at attacker-controlled infrastructure,
  a JWT signature validation bypass vector — that overlap is noted in file 2 but the
  JWT validation mechanics themselves live in the JWT attacks series.

## Real-World Note

In bug bounty and client engagements, the highest-value API SSRF findings are almost
never the "obvious" `url` parameter — they are the second-order ones: a CSV import
field, an SSO metadata URL configured once during tenant onboarding, or a webhook
retry mechanism that re-fetches a URL on a fixed schedule and therefore gives you a
reliable, repeatable OOB signal even when the initial request is blind. Treat every
endpoint that stores a URL for later use as a candidate, not just ones that fetch
immediately.
