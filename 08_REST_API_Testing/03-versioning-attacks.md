# REST API Testing Methodology — 03: API Versioning Attacks

## Mechanism: why old versions stay dangerous

API versioning exists so consumers (mobile apps, third-party integrations, internal services) don't break when the API evolves. The practical consequence is that **organizations keep old versions running far longer than they intend to**, because deprecating a version means coordinating with every consumer still calling it — which is organizationally slow even when it's technically trivial. This creates a predictable security gap:

- Security fixes (a patched authorization check, a newly added rate limit, an input validation improvement) are applied to the **current** version during active development, but are not always backported to older versions still running in production, because backporting requires deliberate engineering effort that deprecation timelines don't always prioritize.
- Older versions are frequently **excluded from newer defensive layers** entirely — a WAF rule or API gateway policy added specifically for `/v3/` may never have been retroactively applied to `/v1/`, because whoever configured the new policy was reasoning about current traffic patterns, not legacy paths.
- Monitoring and alerting are commonly tuned around current-version traffic; anomalous activity against a legacy version generates far less signal to defenders, making it a quieter avenue for testing (and for genuine attackers).

PortSwigger's own API testing guidance makes this point directly: "use protective measures on all versions of your API, not just the current production version" is listed as a specific prevention recommendation — which is itself confirmation that this gap is common enough to warrant an explicit line item.

## Step-by-step version enumeration

**Step 1 — Extract every version reference already visible in your File 01 recon.**

Before probing anything new, mine what you already have:
- URL path segments: `/v1/`, `/v2/`, `/api/2023-01-01/` (date-based versioning), `/api/beta/`
- Header-based versioning: `Accept: application/vnd.company.v2+json`, `X-Api-Version: 2`, `Api-Version: 2023-06-01`
- Query-string versioning: `?version=1`, `?api-version=2.0`
- The `servers` field in any OpenAPI spec you found in File 01 — specs sometimes list multiple version-specific base URLs even if only the latest is documented in detail
- Response headers on any request you've already sent (`X-Api-Version`, `X-Powered-By` combined with changelog dates) — these often leak the *current* version number, which tells you what to count downward from

**Step 2 — Enumerate downward and upward from every known version.**

If you've confirmed `/api/v3/users` exists, systematically test:
```
GET /api/v1/users HTTP/1.1
GET /api/v2/users HTTP/1.1
GET /api/v4/users HTTP/1.1
```

What each request specifically tests:
- `/v1/`, `/v2/` (downward) — whether deprecated versions remain live and reachable at all. A `200` response here is the finding itself before you've even tested for weaker controls.
- `/v4/` (upward) — whether an unreleased or beta version is reachable ahead of public documentation, which sometimes exposes features or fewer validation checks not yet hardened for production traffic.

**Step 3 — For header-based and content-negotiation versioning, vary the header rather than the path.**

```
GET /api/users HTTP/1.1
Accept: application/vnd.company.v1+json
```
vs.
```
GET /api/users HTTP/1.1
Accept: application/vnd.company.v3+json
```

What this tests: many APIs use a *single URL* with version selection entirely inside the `Accept` header or a custom version header. If you only enumerate the path, you'll completely miss this versioning scheme. Confirm which scheme(s) the target actually uses in Step 1 before deciding which enumeration approach to run.

**Step 4 — Systematically diff behavior between versions once you've confirmed multiple are reachable.**

For every version you can reach, replay the exact same authenticated request and compare:
- **Authorization enforcement**: does `/v1/admin/users` enforce the same role check as `/v3/admin/users`? Test with a low-privilege token against both.
- **Rate limiting**: send a burst against `/v1/` and the same burst against `/v3/` — a legacy version that doesn't throttle where the current one does is a distinct, reportable weakness even without a further exploitable bug behind it.
- **Input validation strictness**: send a payload known to be rejected by the current version's validation (oversized input, an injection-style payload used purely as a probe, unexpected data types) against each version and compare rejection behavior.
- **Response field disclosure**: compare the JSON response shape across versions — legacy versions sometimes return additional internal fields that were later stripped from the response schema in newer versions, but the underlying data is still being returned by the old code path.

**Step 5 — Check whether legacy versions still trust deprecated authentication mechanisms.**

Older API versions sometimes retain support for authentication schemes that have since been deprecated for the current version (e.g., a legacy Basic Auth fallback, an older JWT signing algorithm, an API key format that newer versions reject). Confirm this by attempting to authenticate to the old version using credentials/tokens/formats that the current version explicitly rejects.

## Version enumeration techniques, consolidated

- **Sequential numeric enumeration**: `/v1/` through current+1, both path-based and header-based.
- **Date-based enumeration**: for APIs versioned by release date (`/api/2023-01-15/`), check the changelog (if public) for prior date strings, and try adjacent dates even without a changelog, since APIs adopting this scheme are often internally consistent about format.
- **Wordlist-driven Intruder sweep**: for less predictable version naming (`alpha`, `beta`, `legacy`, `deprecated`, `internal`, `staging`), run a targeted wordlist against the version-segment position rather than assuming purely numeric sequencing.
- **Subdomain/host-based version discovery**: some organizations run old versions on entirely separate hosts (`api-v1.target.com` vs `api.target.com`) rather than path/header schemes — cross-reference this against subdomain recon work from your existing recon/subdomain-takeover series rather than treating it as unrelated.
- **Archived documentation and changelogs**: public changelogs, GitHub release notes, or archived Swagger docs (even via the Wayback Machine for genuinely public, non-authentication-gated documentation) frequently name deprecated versions explicitly.

## WAF / API Gateway relevance — dedicated section

Versioning is one of the areas where gateway configuration drift is the *entire* vulnerability, making this section central rather than supplementary.

### How WAFs/gateways typically detect this attack pattern

- **Path-based routing rules scoped only to current-version paths**: many API gateways apply WAF rulesets, rate-limiting policies, and bot-detection rules via path-prefix matching (`/v3/*`). A rule written this way silently does not apply to `/v1/*` unless someone deliberately mirrored the rule — detection of version-enumeration *attempts* themselves is therefore often weaker on legacy paths precisely because the same gateway policies that would flag suspicious behavior on the current version were never extended backward.
- **Anomaly detection tuned to current-version traffic volume**: legacy versions typically carry a small fraction of current traffic, so per-endpoint traffic-volume-based anomaly detection (a common WAF/gateway feature) has a much lower baseline to compare against — meaning a burst of testing traffic against `/v1/` can look proportionally larger and more anomalous than the same absolute request count against high-traffic `/v3/`, even though the intent is identical. This can cut either way: it may trigger *faster* alerting on legacy paths in some configurations, so don't assume legacy always means unmonitored — verify by testing cautiously rather than assuming.

### Realistic bypass considerations

- **Testing whether gateway-level protections (auth enforcement, rate limiting, input validation at the edge) are applied per-version or globally** is itself the primary "bypass" technique here — there's no separate payload-obfuscation step needed if the gateway configuration itself only covers the current version.
- **Header-based version negotiation can sometimes route around path-based gateway rules entirely**: if a gateway's WAF rule matches on URL path prefix but the application also honors an `Accept`/`X-Api-Version` header to select version-specific logic behind a single path, sending the current (allowed) path with an old-version header can reach old-version code while sailing past a path-based gateway rule that only inspected the URL. Confirm this distinction explicitly — it's a genuinely different bypass mechanism from simply hitting an old path directly.
- **Origin-direct access**: as in File 02, if the origin server (rather than the gateway) is directly reachable, gateway-enforced version deprecation/blocking can be bypassed entirely by skipping the gateway. Always check for this during recon rather than treating gateway-level blocks as final.

---

## PortSwigger lab mapping

**Honest gap disclosure — read this before searching for a lab:** PortSwigger's Web Security Academy does **not** currently have a lab dedicated specifically to API version enumeration or cross-version authorization/rate-limit differentials. This is a genuine coverage gap in the Academy's API testing topic, not an oversight in this note series. The closest adjacent labs teach transferable skills:

| Lab | Difficulty | Transferable skill |
|---|---|---|
| Exploiting an API endpoint using documentation | Apprentice | Base-path investigation technique (Step 1) directly transfers to discovering version-prefixed base paths |
| Finding and exploiting an unused API endpoint | Practitioner | The general discipline of testing paths/methods the front-end never calls directly transfers to testing version paths the current front-end never references |

### crAPI supplementary practice — this is where the gap is filled

crAPI is the stronger environment for this specific topic because it ships **multiple real microservices with independent versioning behavior**, unlike a single-purpose PortSwigger lab:

- crAPI's **community and workshop services** expose endpoints where older, less-validated logic paths remain reachable alongside current ones — a direct, hands-on analogue to the version-differential testing in Steps 4–5 above.
- Because crAPI is a full deployable application (via Docker Compose) rather than an ephemeral lab instance, it's also the better environment to practice **subdomain/host-based version discovery** techniques against a realistic multi-service topology, since you control the full environment and can inspect actual routing configuration to verify what you found through black-box testing.

---

## What's next

File 04 shifts from surface/version enumeration to manipulating the `Content-Type` header itself — testing how the same endpoint behaves when you feed it JSON, XML, and plain text, and what that reveals.
