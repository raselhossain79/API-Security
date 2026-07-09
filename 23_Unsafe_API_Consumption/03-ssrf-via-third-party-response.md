# 03 — SSRF via Third-Party API Responses

This file assumes you already understand baseline SSRF mechanics (cloud
metadata endpoints, internal port scanning, blacklist/whitelist bypass
techniques). If not, read the general SSRF series first — this file focuses
only on what's different when the URL your server fetches comes from a
**third-party API response** rather than direct user input.

## 1. The mechanism

```
Third-party API response contains a URL field
        |
        v
Your backend fetches that URL server-side, no validation
        |
        v
URL points to an internal service / cloud metadata endpoint / localhost
        |
        v
Internal response leaks back to attacker via app behavior
```

The key structural difference from "classic" SSRF (API7-style, user submits
a URL directly): here the URL is **one hop removed** from the attacker. The
attacker doesn't type the malicious URL into your app directly — they get it
planted inside a response your backend consumes and then blindly acts on.
This one extra hop is exactly why developers under-defend it: it doesn't
*feel* like user input, so it often skips the URL-validation logic that
"direct" user-submitted URL fields get.

## 2. Scenario 1: URL preview / expansion via a compromised or malicious third-party service

**Setup:** Your application integrates with a "link unshortening" or
"URL metadata preview" service — you send it a short URL, it resolves and
returns metadata including a `resolved_url` field, which your backend then
fetches itself to generate a thumbnail/preview.

**Step by step:**

1. Your backend calls the third-party service:
   `GET https://url-service.example/expand?url=https://bit.ly/xyz`
2. Third party responds:
   ```json
   { "original": "https://bit.ly/xyz", "resolved_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
   ```
   This happens either because the third-party service itself is compromised,
   or because the *original* short link the attacker submitted already
   redirected to the metadata IP and the "expansion" service faithfully
   reports the final hop without itself blocking internal ranges.
3. Your backend, trusting the vendor's `resolved_url` field completely,
   fetches it server-side to build a preview:
   ```
   preview_html = fetch(response.resolved_url)
   ```
4. **Why this is unsafe:** the request now originates from *your* backend's
   network position — inside your VPC, with access to your cloud metadata
   service. The response (IAM credentials, instance metadata) gets rendered
   into whatever "preview" the app builds, leaking it to the attacker who
   originally submitted the short link.
5. This is a two-hop SSRF: attacker → third-party service → your backend.
   Standard user-input SSRF filters on *your* app never see the malicious
   URL directly — they see a clean-looking vendor API call, and the danger
   only appears one JSON field deep in the response.

## 3. Scenario 2: Webhook subscription "delivery/retry URL" set by a compromised partner

**Setup:** Your application subscribes to a partner platform's events. The
partner's subscription-confirmation response includes a `retry_callback_url`
your backend is supposed to call if a delivery needs to be retried later.

**Step by step:**

1. Partner platform responds to your subscription request:
   ```json
   { "subscription_id": "sub_123", "retry_callback_url": "http://internal-admin.corp.local:8080/debug/execute" }
   ```
2. Later, your backend's retry logic fetches `retry_callback_url` without
   validating it's still pointed at the expected partner domain.
3. **Why this is unsafe:** the URL is not hardcoded/pinned to the partner's
   known domain at the point your app first receives it — it's accepted as
   "whatever the partner says it should be," which is exactly the trust
   assumption this entire category warns against. If that partner account is
   compromised (weak partner-side auth, insider threat, or supply-chain
   compromise of the partner's own backend), the attacker fully controls
   where your server sends requests, on an ongoing basis.

## 4. Scenario 3: Blind pagination-link following

**Setup:** Your backend paginates through a third-party API by following
the `next` link the API provides in each response page, rather than
constructing the next-page URL itself from a known base.

**Step by step:**

1. Legitimate first page: `{"data": [...], "next": "https://api.partner.com/items?page=2"}`
2. On a later page (or if the partner API is compromised / a MITM occurs on
   a non-pinned TLS connection), the `next` field becomes:
   `{"data": [...], "next": "http://localhost:6379/"}`
3. Your backend's pagination loop, written generically as "keep fetching
   `response.next` until it's null," fetches an internal Redis instance
   instead of the next results page.
4. **Why this is unsafe:** the developer wrote a *generic* "follow the link
   the API gives me" loop for convenience, trusting the API to always return
   URLs on its own domain. There's no allowlist check per iteration.

## 5. What's structurally different from classic (API7 / direct) SSRF

| | Classic SSRF | API10 SSRF |
|---|---|---|
| Attacker submits URL | Directly, via a form/param | Indirectly, via a compromised/manipulated third-party response field |
| Developer's mental model | "This is user input, I should validate it" | "This came from our trusted vendor, why would I validate it?" |
| Where the filter usually lives (if any) | On the direct user-facing input field | Often nowhere — the vendor call is assumed safe by design |
| Detection difficulty | Moderate (you control the malicious URL directly) | Higher — you often need to get a URL *planted inside* a third-party response, which usually requires you to control or influence the third party |

## 6. WAF / API Gateway relevance — this is the one sub-risk where it matters

Unlike injection and data-integrity issues, this sub-risk involves a genuine
**outbound network request** at the point of exploitation (your server
fetching the malicious `resolved_url`/`retry_callback_url`/`next` link).
That means a control point positioned to intercept egress traffic can
meaningfully help.

**Realistic defenses at the gateway/proxy layer:**

- **Egress allowlisting**: force all outbound calls from application
  services through a forward proxy or API gateway that only permits
  connections to an explicit allowlist of destination domains/IPs. Applied
  correctly, this stops the metadata-endpoint and internal-service scenarios
  above cold, because `169.254.169.254` and `internal-admin.corp.local`
  simply aren't on the allowlist.
- **Redirect suppression**: configure the HTTP client/gateway to not follow
  redirects automatically, or to re-validate the destination after each hop.
- **DNS pinning / resolved-IP validation**: validate the *resolved* IP
  address against a private-range blocklist at request time, not just the
  hostname string, to prevent DNS rebinding.

**Realistic bypass considerations (be honest about these in a report or when advising on defense):**

- **DNS rebinding**: attacker's domain resolves to an allowlisted-looking
  value during any validation step, then to an internal IP at actual
  connection time (TOCTOU between check and fetch). Defeats hostname-only
  allowlisting; requires re-resolving and re-validating IP at connection
  time, ideally pinning the resolved IP for the whole request lifecycle.
- **Redirect chains through an allowlisted domain**: if `partner.com` is
  allowlisted and the app *does* follow redirects, an open redirect on
  `partner.com` itself (`https://partner.com/redirect?to=http://169.254.169.254/`)
  bypasses a domain-only allowlist entirely.
- **IP address encoding tricks**: decimal (`2130706433`), octal
  (`0177.0.0.1`), IPv6-mapped (`::ffff:127.0.0.1`), and shorthand forms can
  bypass naive string-matching blocklists that only check for literal
  `127.0.0.1` / `localhost` strings.
- **Allowlist scope too broad**: allowlisting an entire cloud provider's IP
  range (common for "just allow AWS IPs" shortcuts) still permits requests
  to other tenants' infrastructure, including metadata endpoints on shared
  ranges.

## 7. Real-world note

The most exploitable real-world variant of this is a **feature that lets
your own users register a custom webhook or callback URL for a third-party
integration you built** (e.g., "connect your CRM," "set your Slack
notification URL," "configure your payment gateway sandbox endpoint"). In
that case *your users are the third party* from your backend's perspective,
and the barrier to exploitation is zero — no compromise of an external
vendor required, just registering `http://169.254.169.254/` as your own
webhook target. This is also the most practical entry point for black-box
testing — see file 05.

Continue to `04-data-integrity-issues.md`.
