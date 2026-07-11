# Service Impersonation and Lateral Movement

## 1. Overview

This file covers the two techniques that most directly weaponize the trust
assumptions from File 1:

1. **Service impersonation** — reaching an internal service and having it treat you
   as if you were a legitimate calling service, because it never actually checks
   who's calling
2. **Lateral movement via internal APIs** — using access gained to one internal
   service as a pivot point to enumerate and access others

The centerpiece of this file is a full, step-by-step SSRF-to-internal-service-
impersonation walkthrough, since this is the most common real-world path from
"externally exploitable bug" to "full internal service compromise."

---

## 2. Service Impersonation: Core Concept

Service impersonation testing asks one question of every internal endpoint you can
reach: **does this endpoint verify who is calling it, or does it assume that mere
reachability implies legitimacy?**

This directly targets Trust Assumption 4.1 and 4.4 from File 1: "only internal
services can reach this" and "network membership implies authorization." An endpoint
vulnerable to service impersonation performs the action requested by *any* caller
that can reach it over the network, with no additional identity check.

### 2.1 What to look for

When you reach an internal service endpoint (via legitimate whitebox access, or via
a pivot as shown in Section 3 below), check for each of the following, in order of
how commonly they're missing:

1. **No authentication header/token check at all** — the endpoint just processes the
   request body.
2. **A token check exists but accepts any well-formed token** — e.g., checks
   "does the `X-Internal-Service` header exist and equal any non-empty string" rather
   than validating a real credential.
3. **A token/cert check exists and is genuinely validated (see File 2) but no
   authorization check follows** — the endpoint confirms *a* legitimate service is
   calling, but not *which* service, and performs the action regardless (this is the
   File 2 Section 3.3 identity-confusion issue manifesting at the application layer).
4. **IP allowlisting only** — the endpoint checks the source IP is within the internal
   CIDR range, which is trivially satisfied by anything on the internal network,
   including an attacker who has pivoted there.

---

## 3. Step-by-Step Walkthrough: SSRF to Internal Service Impersonation

This walkthrough uses a realistic scenario: an externally-facing `order-service`
exposes a feature that fetches a user-supplied URL (e.g., "import your avatar from a
URL" or "fetch a product image from this link" — classic SSRF-prone functionality).
Internally, there is an `inventory-service` that exposes a `/internal/adjust-stock`
endpoint with no additional authentication, because it was designed under the
assumption that only `order-service` (its intended caller) can reach it on the
internal network.

### Step 1 — Identify the SSRF entry point

```
POST /api/orders/import-image HTTP/1.1
Host: shop.example.com
Content-Type: application/json

{"imageUrl": "https://cdn.example.com/product123.jpg"}
```

Confirm classic SSRF by substituting an internal/loopback address and observing a
different response (timing difference, error message difference, or successful
fetch of internal content):

```json
{"imageUrl": "http://169.254.169.254/latest/meta-data/"}
```

If this returns cloud metadata content (or a distinguishable response confirming the
request was made), SSRF is confirmed. *(For full SSRF payload technique and filter
bypass detail, see the existing SSRF series — this walkthrough focuses on what comes
next, which is microservices-specific.)*

### Step 2 — Enumerate internal service DNS/hostnames

Cloud-native and Kubernetes environments use predictable internal DNS naming. Common
patterns to try via the SSRF:

```
http://inventory-service/
http://inventory-service.default.svc.cluster.local/
http://inventory-service.internal/
http://payment-service:8080/
http://10.0.1.0/  (and sweep the internal CIDR if hostnames fail)
```

**Why this works:** Kubernetes Services get automatic DNS entries
(`<service>.<namespace>.svc.cluster.local`), and the SSRF-vulnerable service (making
the request from *inside* the cluster/VPC) can resolve these names even though you,
the external attacker, cannot resolve them yourself. This is the key mechanic that
makes SSRF so much more dangerous in a microservices context than in a monolith: the
vulnerable service's network position becomes your network position for the duration
of the request.

```
POST /api/orders/import-image HTTP/1.1
Host: shop.example.com
Content-Type: application/json

{"imageUrl": "http://inventory-service/"}
```

A response containing an application banner, API documentation, or an error page
distinct from the internet-facing app confirms you've reached an internal-only
service.

### Step 3 — Discover internal endpoints

Since you likely can't browse an internal Swagger/OpenAPI UI interactively (the SSRF
gives you one request/response at a time, not a full session), use the SSRF to probe
for common internal API documentation and health-check paths, one at a time:

```
http://inventory-service/swagger.json
http://inventory-service/openapi.json
http://inventory-service/actuator/mappings   (Spring Boot Actuator — very common)
http://inventory-service/_internal/routes
```

**Real-world note:** Spring Boot Actuator endpoints (`/actuator/mappings`,
`/actuator/env`, `/actuator/beans`) left exposed on internal services (because "it's
internal, who cares") are one of the single most common and highest-value findings in
microservices assessments — `/actuator/mappings` alone often hands you a complete
internal API map.

If documentation isn't available, fall back to a wordlist-based path guess through
the SSRF (slower — one guess per request unless you can chain the SSRF through a tool
that supports it, e.g., some blind-SSRF-to-internal-scan setups use time/response-size
oracles to accelerate this).

### Step 4 — Identify an unauthenticated state-changing endpoint

Suppose Step 3 reveals `/internal/adjust-stock`. Test whether it requires
authentication:

```
POST /api/orders/import-image HTTP/1.1
Host: shop.example.com
Content-Type: application/json

{"imageUrl": "http://inventory-service/internal/adjust-stock?sku=PROD123&delta=-100"}
```

Two challenges arise here that are specific to SSRF-mediated impersonation (as
opposed to direct access):

1. **The SSRF vector likely only supports GET-style URL fetches**, but the target
   internal endpoint expects a POST with a JSON body. If the SSRF-vulnerable
   functionality only performs GET requests to the supplied URL, you're initially
   limited to GET-compatible internal endpoints or internal endpoints that accept
   parameters via query string (a common secondary weakness — internal APIs often
   accept both GET-with-query-params and POST-with-body for convenience, precisely
   because internal API design gets less rigor, per File 1 Section 4.6).
2. **You often get no response body back** (blind SSRF) — you'll need an out-of-band
   or side-channel confirmation (e.g., checking the storefront's displayed stock
   count before and after, or using a controlled internal endpoint if one exists, to
   confirm the request landed).

### Step 5 — Confirm impersonation, not just reachability

The critical distinction: reaching the endpoint proves an attack surface exists;
getting it to *act* proves impersonation. Confirm the state change actually
happened — in this example, check the product's displayed stock level before and
after the request. A change confirms `inventory-service` executed the write
operation believing the SSRF-vulnerable `order-service` was a legitimate internal
caller, because no additional identity verification stood in the way.

### Step 6 — Document the trust assumption exploited

For the report: `inventory-service`'s `/internal/adjust-stock` endpoint assumed that
network reachability from within the cluster implied the caller was the legitimate
`order-service`. In reality, any component capable of making a server-side HTTP
request that lands inside the cluster network — including an external attacker via
an unrelated SSRF vulnerability in a completely different service — satisfies that
same "network reachability" bar. The endpoint conflated *location* with *identity*
(File 1, Section 4.1 and 4.4).

---

## 4. Lateral Movement via Internal APIs

Once you have one working pivot point (the SSRF above, a compromised container, a
leaked credential), the goal shifts from "exploit this one endpoint" to
"systematically enumerate and access the broader internal service landscape."

### 4.1 Step 1 — Build an internal service inventory

Use your pivot to sweep for other internal services. If your pivot is a full SSRF
that supports arbitrary hostnames (not just a fixed one you discovered), enumerate
systematically:

```
http://auth-service/
http://user-service/
http://payment-service/
http://notification-service/
http://pricing-service/
http://admin-service/
http://logging-service/
http://config-service/
```

Also try common Kubernetes namespace variations if the environment uses
multi-namespace segmentation:

```
http://payment-service.payments.svc.cluster.local/
http://payment-service.prod.svc.cluster.local/
```

### 4.2 Step 2 — Prioritize by data/action sensitivity

Not all internal services are equally valuable. Prioritize in this rough order,
consistent with typical microservices architectures:

1. `payment-service` / `billing-service` — financial data and transaction control
2. `auth-service` / `identity-service` — could yield credentials for further pivoting,
   including into services that *do* have proper authentication
3. `admin-service` / internal-only admin panels — often have weaker auth than the
   customer-facing product because "no external customer will ever see this"
4. `config-service` — internal configuration services (e.g., Spring Cloud Config
   servers) frequently expose secrets, database credentials, and other services'
   API keys in plaintext
5. `user-service` — PII exposure
6. `notification-service`, `logging-service` — lower direct impact but often reveal
   internal architecture details (service names, internal hostnames, sometimes
   forwarded tokens in logs) that aid further pivoting

### 4.3 Step 3 — Use each newly-accessed service to find the next one

This is genuinely lateral movement, not just repeated direct pivoting from the
original SSRF: a `config-service` compromised in Step 2 might hand you a database
connection string or an API key for `payment-service`, letting you authenticate
properly rather than relying on impersonation. Similarly, `logging-service` often
contains request/response logs from *other* services that leak internal API paths,
parameter names, or (in poorly configured logging) full auth tokens that were
supposed to be redacted.

**Trust assumption exploited at this stage:** the assumption that a compromise is
"contained" to the service that was originally vulnerable. Microservices
architectures without genuine service-to-service authorization (File 2) have no
internal blast-radius containment — compromising the least-sensitive service (e.g.,
`notification-service`) is architecturally equivalent to compromising the most
sensitive one, because the network doesn't distinguish between them.

### 4.4 Step 4 — Confirm whether network segmentation exists at all

A well-architected environment implements **Kubernetes NetworkPolicies** (or
equivalent VPC security groups / Calico rules) restricting which services can talk to
which. Test for this directly: if `order-service` (your pivot point) is only
*supposed* to talk to `inventory-service` and `payment-service`, but your SSRF
successfully reaches `user-service` and `logging-service` too, network segmentation
is either absent or misconfigured (commonly, a default-allow policy, or a
network policy that exists but was never actually applied to the relevant
namespace).

---

## 5. WAF / API Gateway Relevance for This Topic

This is one of the two files in this series (alongside File 4) where WAF/gateway
defenses are directly relevant, because the *entry point* into this entire chain
(Section 3, Step 1) is SSRF — a well-known WAF/gateway detection category.

### 5.1 Common detection methods

- **Payload pattern matching** — WAFs commonly flag URLs containing
  `169.254.169.254`, `localhost`, `127.0.0.1`, RFC1918 ranges
  (`10.x`, `172.16-31.x`, `192.168.x`), and `.internal`/`.local`/
  `.cluster.local` suffixes in any parameter that appears to accept a URL.
- **DNS rebinding protection** — some gateways/application-layer SSRF protections
  resolve the hostname at validation time and again at request time, rejecting
  mismatches, specifically to counter DNS-rebinding-based SSRF filter bypass.
- **Egress monitoring / anomaly detection** — API gateways and service meshes with
  observability tooling (e.g., Istio + Prometheus/Grafana, or a cloud provider's
  VPC flow log analysis) can flag a service suddenly making requests to internal
  hostnames it has never contacted before — this is a behavioral detection rather
  than a payload-pattern one, and is significantly harder to evade.
- **Outbound allowlisting at the application layer** — the most robust defense:
  the SSRF-prone functionality is restricted to an explicit allowlist of permitted
  external domains, making internal-hostname payloads rejected regardless of
  obfuscation.

### 5.2 Realistic bypass considerations

- **Blacklist-based filters** (matching literal strings like `169.254.169.254`) are
  routinely bypassed with alternate IP representations: decimal (`2852039166`),
  octal, hex (`0xA9FEA9FE`), IPv6-mapped (`::ffff:169.254.169.254`), or
  URL-embedded credentials tricks (`http://expected-host@169.254.169.254/`).
- **DNS rebinding** defeats naive "resolve once, check, then trust the hostname"
  filters by returning a safe IP at validation time and the internal IP at actual
  connection time — relevant when the SSRF-vulnerable service performs its own DNS
  resolution separately from any upstream validation step.
- **Redirect-based bypass** — if the vulnerable service follows HTTP redirects, a URL
  pointing to an attacker-controlled server that responds with a `302` to the
  internal target bypasses filters that only inspect the initially-supplied URL and
  never re-validate after a redirect (this is exactly the PortSwigger "SSRF with
  filter bypass via open redirection" lab referenced in File 1, Section 6).
- **Internal hostname enumeration is inherently hard to signature-match** — unlike
  the well-known `169.254.169.254` metadata IP, internal service names
  (`inventory-service`, `payment-service.prod.svc.cluster.local`) are
  environment-specific and not part of any generic WAF ruleset, meaning payload-
  pattern-matching WAFs provide essentially no protection against the internal
  service enumeration technique in Section 3, Step 2–3, even when they successfully
  block metadata-endpoint SSRF. This asymmetry is worth highlighting explicitly in
  reports: metadata-service SSRF is well-defended almost everywhere now; internal
  service-name SSRF is not.

---

## 6. PortSwigger Web Security Academy Mapping

**Apprentice:**
- *Basic SSRF against the local server*
- *Basic SSRF against another back-end system*

**Practitioner:**
- *SSRF with blacklist-based input filter*
- *SSRF with whitelist-based input filter*
- *Blind SSRF with out-of-band detection*
- *SSRF with filter bypass via open redirection vulnerability*

**Expert:**
- No Expert-tier lab directly extends this into multi-service lateral movement;
  PortSwigger's labs stop at "reach one internal system." The lateral movement
  methodology in Section 4 above (chaining access across multiple internal services)
  has no PortSwigger equivalent — this gap is exactly why Section 7's supplementary
  resources matter for this specific file more than almost any other in your library.

---

## 7. Supplementary Practice

- **crAPI** — has a genuine multi-container backend; practice using one compromised
  container/service's access to reach sibling containers on the shared Docker
  network, directly modeling Section 4's methodology.
- **HTB Pro Labs (RastaLabs, Offshore, APTLabs, Cybernetics)** — full internal
  networks; practice the "one foothold → systematic internal enumeration →
  prioritized targeting → repeat from new position" loop in Section 4 against a real
  multi-host environment.
- **TryHackMe "Internal"** — purpose-built for exactly this pivot-and-enumerate
  pattern, with a manageable scope for a first attempt at this methodology.
- **TryHackMe "Wreath"** — proxychains/pivoting-focused, good for the mechanical
  skill of routing tooling (e.g., Burp) through a pivot when your only path to an
  internal service is via an already-compromised host, rather than direct SSRF.

---

## 8. Real-World Notes

- SSRF-to-internal-service-impersonation is consistently one of the highest-severity
  findings in microservices assessments precisely because it converts a
  medium-severity-looking bug (SSRF, often initially scoped as "can read cloud
  metadata") into full internal write access once the internal service landscape is
  mapped. Always push past the initial SSRF confirmation into internal service
  enumeration before scoping severity.
- The `/actuator/mappings` and Spring Cloud Config server findings mentioned in
  Section 3, Step 3 and Section 4.2 respectively are disproportionately common in
  real assessments relative to how much attention they get in training material —
  actively check for both on every internal-facing pivot.
- Blind SSRF (no response body) is the norm, not the exception, once you're past the
  initial confirmation stage — budget testing time for building out-of-band
  confirmation methods (timing, observable side effects, DNS interaction logging via
  a controlled domain) rather than expecting reflected responses throughout.

---

## 9. Cross-References

- See **File 1, Section 4** for the trust assumptions this entire file exploits.
- See **File 2** for what a properly-implemented defense against this attack looks
  like (mTLS + validated service identity would have stopped Step 4/5 of the
  walkthrough above).
- See **File 4** for the related but distinct technique of bypassing the gateway
  entirely rather than pivoting via SSRF.
- See the existing **SSRF series** for full payload/filter-bypass technique detail —
  this file assumes that grounding and focuses on what's unique once the SSRF lands
  inside a microservices network.
