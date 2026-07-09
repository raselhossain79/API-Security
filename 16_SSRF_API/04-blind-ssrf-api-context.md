# Blind SSRF in API Context — Burp Collaborator Workflow

## Why Blindness Is the Default in API SSRF

As covered in file 1, API SSRF frequently fires from an asynchronous worker process,
not the request handler that returned your HTTP response. You get a `200 OK` /
`{"id": "wh_123", "status": "registered"}` immediately, and the actual outbound
request — the one that matters — happens later, on a different service, and its
result is never surfaced back to you through any API response. This makes
out-of-band (OOB) detection the default confirmation method for this vulnerability
class, not a fallback for edge cases.

## Burp Collaborator — What It Actually Does

Collaborator is a service Burp Suite Professional operates that gives you a unique,
disposable subdomain (and, incidentally, an email address and a few other protocol
listeners) and logs **every** DNS lookup and network connection made to it, along with
full request/response details for HTTP(S). The core idea: if you plant a Collaborator
subdomain inside a payload the target server will resolve/fetch, and it later shows up
in the Collaborator log, you have independent, out-of-band proof that the server made
that request — proof that exists even though the API itself told you nothing.

## Step-by-Step Workflow for an API Webhook Field

**Step 1 — Generate a payload.**
In Burp: Burp menu → Collaborator → "Copy to clipboard" generates a unique subdomain,
e.g. `a1b2c3d4e5f6.oastify.com` (format varies by Collaborator server config, but it
is always a random, single-use subdomain under a domain Burp controls).

Piece-by-piece: the random label (`a1b2c3d4e5f6`) is generated fresh per payload and
is what makes the technique reliable for attribution — if you send five different
payloads to five different fields, each gets its own unique subdomain, so an incoming
Collaborator interaction tells you exactly *which* payload fired, not just that *some*
payload fired.

**Step 2 — Insert it into the target field.**

```http
POST /api/v2/webhooks HTTP/1.1
Host: target-api.example.com
Authorization: Bearer <token>
Content-Type: application/json

{
  "event": "order.completed",
  "webhookUrl": "http://a1b2c3d4e5f6.oastify.com/probe",
  "active": true
}
```

Piece-by-piece: `http://` (not `https://`) is used deliberately for the first probe —
plain HTTP guarantees you get both a DNS lookup *and* a subsequent TCP/HTTP
connection attempt logged, giving two independent confirmation signals instead of
one. The `/probe` path is arbitrary and only useful for your own log-reading
convenience (to distinguish this specific test from others if you're running many
probes against the same Collaborator client window) — the server won't route on it.

**Step 3 — Trigger the async flow.**
Fire whatever event causes the webhook to actually deliver — create the order,
complete the workflow, or use the `/webhooks/{id}/test` endpoint if the API in
question:

- If a test-fire action, this converts the async workflow into a synchronous
  one for the purposes of *timing*, but the response still won't leak fetch results —
  Collaborator confirmation is still required, the test action just removes the wait.

**Step 4 — Poll Collaborator.**
Burp menu → Collaborator → "Poll now," or leave the client window open — it polls
automatically. A successful interaction shows:

```
Interaction type: HTTP
Received: <timestamp>
Client IP: 10.42.6.19          <- the SSRF-vulnerable server's real internal IP
DNS query: A a1b2c3d4e5f6.oastify.com
HTTP request: GET /probe HTTP/1.1
              User-Agent: Go-http-client/1.1
```

Piece-by-piece interpretation:
- **DNS query logged, HTTP not** → the resolver looked up the hostname but no
  connection followed. This can mean an egress firewall blocked the outbound
  connection *after* DNS resolution (common when an API Gateway/service mesh enforces
  network-layer egress rules, as discussed in files 2 and 3) — DNS-only is still
  useful signal, but weaker: it proves the hostname was resolved server-side, not that
  a request reached an attacker-controlled listener.
- **Both DNS and HTTP logged** → full confirmation; the server made a genuine
  outbound HTTP request to attacker infrastructure. This is unambiguous SSRF.
- **Client IP field** → often the single most valuable piece of incidental
  information in the whole workflow. This is the real, non-NATed (or
  NAT-translated-but-still-informative) source IP of whichever server actually issued
  the request — frequently *not* the same host that served your original API
  response, confirming the "different worker node" pattern from file 1, and giving you
  a real internal IP to pivot from in file 5.
- **User-Agent header** → identifies the library/framework making the request
  (`Go-http-client`, `python-requests`, `axios/1.x`, `okhttp`), which tells you the
  tech stack of the async worker — useful for guessing what other SSRF-relevant
  behavior it might have (e.g., `python-requests` follows redirects by default and
  historically has had its own SSRF-relevant redirect/scheme quirks).

## What to Do After Confirming Blind SSRF

Confirmation alone (an OOB hit) is evidence the vulnerability exists but is rarely
sufficient for a strong-severity finding on its own — the next steps determine real
impact:

**1. Escalate to metadata endpoint targeting, still via Collaborator for the DNS-only case.**
Rather than pointing the webhook URL directly at `169.254.169.254` and hoping for a
directly-visible result (you won't get one — see file 3, responses aren't returned),
combine: send the metadata payload, then separately confirm reachability of *internal
IP ranges generally* by testing whether the server resolves/connects to a Collaborator
listener when it's pointed at an internal-looking hostname you control via a wildcard
DNS record resolving to say `10.0.0.5` — this confirms internal network reachability
as a category, informing whether metadata targeting is even architecturally possible
before you spend time on it.

**2. Check for any partial data leak channel.**
Look for: webhook delivery logs/history endpoints (`GET /webhooks/{id}/deliveries`)
that might store and later expose response status codes, response headers, or even
truncated response bodies from the actual SSRF request — this can turn a blind
finding into a data-exfiltration one. Also check error messages returned by the
*original* API call — some implementations perform enough synchronous validation
(e.g., an HTTP HEAD to check the URL is reachable before accepting the webhook
registration) to leak a `200`/`404`/`connection refused` distinction even though the
full response body stays server-side. This distinction alone can confirm internal port
states (see file 5).

**3. Use response-time as a fallback oracle if Collaborator access is unavailable.**
If working in an environment without external network egress from the target
(fully air-gapped internal test, or a Collaborator-blocking network), a coarse
port-scan-via-timing approach still works: request timeouts differ measurably between
"connection refused" (fast) and "connection accepted but no response" or "filtered"
(slow, until timeout) — much less precise than OOB confirmation, but usable when OOB
isn't reachable. This is a fallback, not a preferred method — always prefer
Collaborator or a self-hosted OOB listener when available.

**4. Confirm scope and document the async worker distinctly from the front-end API.**
In your report, be explicit that the vulnerable component is the async delivery
worker, not the request-handling API server — this affects both the fix
recommendation (validation needs to happen at delivery time / at the point of the
actual fetch, not just at registration time, since a URL can be legitimate at
registration and later re-point via DNS change — a form of TOCTOU relevant to
webhook SSRF specifically) and helps the target's engineering team locate the right
code path faster.

## Self-Hosted OOB Alternative

Where Collaborator isn't available (Burp Community, or a client engagement barring use
of Burp's cloud infrastructure), the same workflow applies using a self-hosted
alternative — `interactsh` (open-source, self-hostable OOB interaction server) or a
domain you control with logging enabled on its authoritative DNS server plus a plain
HTTP listener (`python3 -m http.server` behind a public IP, with access logs). The
workflow and the interpretation of DNS-only vs DNS+HTTP results are identical; only
the tooling for generating/polling differs.

## WAF / API Gateway Considerations

Detection of OOB SSRF attempts at the WAF/Gateway layer is limited to two realistic
mechanisms: (1) DNS-based egress filtering that blocks resolution of
non-allowlisted external domains from the worker's network namespace entirely (in
which case you'd see zero Collaborator interaction at all, not a blocked-but-logged
one — indistinguishable from "not vulnerable" without further testing), and (2)
outbound proxy logging/alerting on connections to known OOB-service domains
(`*.oastify.com`, `*.burpcollaborator.net`, `*.interact.sh` are sometimes
denylisted by security-conscious environments specifically because they're
associated with testing tools). If you suspect denylisting of known OOB domains
specifically (rather than a general egress block), self-hosting on an unlisted domain
is the direct workaround — this is a legitimate testing consideration, not a
bypass technique targeting a production security control, since the denylist in this
case exists to block testing tool signatures rather than to prevent real attacker
SSRF (a real attacker would use their own unlisted infrastructure regardless).

## Real-World Note

The `Client IP` field in a Collaborator interaction log is easy to skim past because
the DNS/HTTP confirmation is what you were looking for, but in an internal API
environment that field routinely reveals the internal service mesh topology (e.g., IPs
in a `10.244.x.x` range indicating Kubernetes pod networking) faster than any explicit
recon step would. Always record it, even on a routine confirmation.

## Cross-References

- Delivery mechanisms and fields to test: file 2.
- What to target once internal reachability is confirmed: file 3 (metadata) and
  file 5 (internal pivot).
- General SSRF OOB technique fundamentals (non-API-specific): Web Application
  Security — SSRF series.
