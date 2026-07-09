# SSRF via Webhook and Callback URL Parameters

## Mechanism

A large fraction of modern APIs let the client register a URL that the server will
call later: "send a POST to this URL when order status changes," "notify this endpoint
when the export finishes," "fetch this file and attach it to the record." The server
treats the client-supplied URL as fully trusted destination data. If the server does
not validate that the URL points to a host the API operator actually intends to talk
to (their own infrastructure, or a customer's registered domain), an attacker can
supply a URL pointing at internal infrastructure, cloud metadata services, or another
tenant's private endpoint, and the server will make that request on the attacker's
behalf, from the server's network position.

This is functionally identical SSRF to the web-app case — the difference covered in
this file is entirely about **where these parameters live in an API surface and how to
find them**, since there is usually no UI to click through.

## Recon: Finding URL-Accepting Parameters

### 1. Read the API specification first

If an OpenAPI/Swagger/GraphQL schema is available (`/swagger.json`, `/openapi.yaml`,
`/graphql` introspection), search it programmatically for field names and types:

```
grep -iE '"(webhook|callback|notify|redirect|return|cancel|ipn|import|source|avatar|logo|image|document|file|metadata|jwks|oidc)[a-z]*url' openapi.json
```

Piece-by-piece: this searches the spec text for any field name containing one of the
common URL-purpose prefixes (`webhook`, `callback`, `notify`, etc.) followed by `url`
or `Url`, case-insensitively (`-i`), using extended regex syntax (`-E`) so the
alternation (`|`) works without escaping. This catches `webhookUrl`, `callback_url`,
`notifyURL`, etc. in one pass instead of reading every field by hand.

Also check the schema's `type: string, format: uri` annotations — some specs mark URL
fields explicitly even when the name doesn't follow a convention.

### 2. Enumerate every endpoint that accepts a request body

For endpoints without documented schemas, systematically send a request with every
optional field populated (or fetch a full "create" payload example if the API returns
one on a 400 validation error — many APIs helpfully list all accepted fields when
validation fails) and look for any field whose accepted value is validated as URL-shaped
(rejects `not-a-url`, accepts `http://example.com`).

### 3. Check integration/settings endpoints specifically

Look for endpoints under paths like `/settings/integrations`, `/webhooks`, `/sso`,
`/notifications/config`. These are purpose-built to store outbound-calling URLs and are
disproportionately likely to be SSRF-vulnerable because they are configured once by an
admin and rarely re-validated.

### 4. Check "retry" and "test" actions on webhook endpoints

Many webhook management APIs expose a `POST /webhooks/{id}/test` action that
immediately fires a request to the stored URL — this converts a normally-async,
blind vector into a synchronous one you can iterate on quickly during testing (still
confirm impact carefully; firing repeated test requests against a target is itself
traffic you're generating).

## Example Payload — Webhook Registration SSRF

Request:

```http
POST /api/v2/webhooks HTTP/1.1
Host: target-api.example.com
Authorization: Bearer <token>
Content-Type: application/json

{
  "event": "order.completed",
  "webhookUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  "active": true
}
```

Piece-by-piece breakdown of the payload:

- `"event": "order.completed"` — a legitimate, required field so the request passes
  basic validation and isn't rejected for being incomplete. Including realistic
  surrounding fields is important: many validation layers reject the whole request
  if any *other* field is malformed, which would mask whether the URL field itself
  is the vulnerable one.
- `"webhookUrl": "http://169.254.169.254/..."` — the attacker-controlled field. The
  value is a full HTTP URL pointing at the AWS instance metadata IP
  (`169.254.169.254`, covered in depth in file 3) rather than a real customer
  endpoint. The path `/latest/meta-data/iam/security-credentials/` is the metadata
  path that lists IAM role names attached to the instance — the actual credential
  extraction (a second request) is covered in file 3, this example only shows the
  registration step.
- `"active": true` — ensures the webhook is enabled so it will actually fire on the
  next matching event, rather than being registered but dormant.

What the server-side request retrieves: when `order.completed` next fires, the
server's notification worker sends an HTTP GET (or POST, depending on the platform's
webhook convention) to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
Because this IP is only reachable from inside the cloud instance itself, and the
worker process is running there, the request succeeds where an external attacker's
direct request to that IP would simply time out. The response body — a list of IAM
role names — is not returned to you directly (this is the blind/async problem
described in file 1). Confirming this and retrieving the response requires either:
  - An endpoint that echoes back the webhook delivery result/response body (some
    platforms show delivery logs with response snippets — check
    `/webhooks/{id}/deliveries` or similar), or
  - Out-of-band confirmation via Collaborator first (file 4), followed by chaining
    into a response-disclosing endpoint if one exists, or
  - If the platform supports it, redirecting the webhook to attacker infrastructure
    is not applicable here since the target IS the destination — instead look for a
    "resend/replay" feature that might surface the stored response.

## Avatar / Document / Import URL SSRF

The same mechanism applies to "set avatar by URL," "import document from URL," and
bulk import endpoints, with one practical difference: these often fetch **synchronously**
and return **some** signal about the fetch (success/failure, sometimes even the fetched
content itself, e.g., an avatar endpoint that resizes and returns the processed image).
This makes them valuable even when a webhook-style field on the same API is blind,
because a synchronous import endpoint can be used to indirectly confirm reachability
before pivoting to the async webhook fields.

Example:

```http
POST /api/v2/users/me/avatar HTTP/1.1
Host: target-api.example.com
Authorization: Bearer <token>
Content-Type: application/json

{"avatarUrl": "http://internal-admin.corp.local:8080/health"}
```

Piece-by-piece: `avatarUrl` is fetched immediately by the server to download and
process an image. Pointing it at an internal hostname (`internal-admin.corp.local`)
rather than an IP tests both SSRF *and* whether internal DNS resolves from the API
server's network position — a positive sign the server sits inside the corporate
network rather than in an isolated DMZ. The `:8080/health` path targets a common
internal service health-check endpoint; a distinguishable error (e.g., "unsupported
content type: application/json" instead of a generic connection-refused/timeout)
confirms the request reached a live service, even though the image-processing step
will fail and no image will be set.

## SSRF via Third-Party API Integrations

Distinct from the above, this pattern is where the API itself — not a
attacker-supplied field — makes an outbound call to a third-party service as part of
normal operation, and an attacker can influence the *destination* of that call
indirectly. Common cases:

- **OAuth/SSO "discovery URL" fields** (`oidcDiscoveryUrl`, `metadataUrl`): the API
  fetches `.well-known/openid-configuration`-style JSON from an attacker-supplied
  origin during SSO setup. Because this is typically an admin/tenant-configuration
  flow, exploitation usually requires attacker access to an admin panel or a
  multi-tenant misconfiguration allowing cross-tenant field injection — note this as
  a lower base-likelihood but high-impact vector (it can lead to authentication
  bypass, covered in the JWT/OAuth series, in addition to SSRF impact).
- **Payment provider callback fields** (`returnUrl`, `ipnUrl` for services like
  PayPal IPN-style integrations): the API relays these to the payment provider, which
  in turn calls back — this is a two-hop SSRF and the actual outbound request from the
  *target* server may never happen; instead you're causing the *payment provider* to
  make the request, which is a different (and usually much lower severity) trust
  boundary. Distinguish this clearly from same-origin webhook SSRF in your reporting —
  conflating them is a common reporting error that overstates severity.
- **Link unfurl/preview services**: chat, ticketing, and note-taking APIs that render
  "rich previews" of links pasted into a message body. The message content itself
  (not a dedicated URL field) is the injection point — test by pasting a URL into any
  free-text field that later gets rendered with a preview.

## WAF / API Gateway Considerations for This Pattern

As stated in the overview, generic ingress WAFs cannot distinguish a malicious webhook
URL from a legitimate one at the syntax level. Where API Gateways add value here is
**egress allowlisting on the worker service that performs the fetch** — e.g., a Kong
plugin or a Lambda execution role restricted via VPC/security group so the webhook
delivery worker can only reach `0.0.0.0/0` on port 443 and is explicitly denied RFC1918
ranges and `169.254.0.0/16`. When present, this control is bypassed the same way any
network-layer SSRF filter is bypassed (DNS rebinding to a domain that resolves to an
internal IP only after the gateway's initial check, or via an open-redirect hop — see
the general SSRF series for those techniques). The API-specific consideration is: check
whether the *registration* endpoint and the *delivery* worker enforce the same
allowlist — it is common for the registration endpoint to validate the URL string
strictly while the async delivery worker, written by a different team, performs no
validation at all. Testing both independently is worthwhile.

## Real-World Note

Webhook and import URL fields are consistently under-tested in bug bounty programs
because they require patience (waiting for an async event) rather than instant
feedback. Programs that have already had their obvious synchronous SSRF points fixed
frequently still have live webhook-delivery SSRF, because it wasn't caught by the same
automated scanning that flags immediate-response endpoints. Prioritize accordingly when
scope allows.

## Cross-References

- General SSRF mechanism and filter bypass techniques: Web Application Security —
  SSRF series.
- Metadata endpoint exploitation once reachability is confirmed: file 3.
- Confirming reachability when the fetch is asynchronous: file 4 (Blind SSRF).
- JWKS/OIDC discovery URL abuse for auth bypass: JWT attacks / OAuth 2.0 series.
- Business-flow-adjacent import endpoints: API6 (Unrestricted Access to Sensitive
  Business Flows) series.
