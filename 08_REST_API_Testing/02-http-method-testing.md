# REST API Testing Methodology — 02: HTTP Method Testing

## Mechanism: why method abuse works at all

REST APIs assign semantic meaning to HTTP methods (`GET` reads, `POST` creates, `PUT`/`PATCH` update, `DELETE` removes) but **the HTTP protocol does not enforce this — it's a convention the application layer chooses to implement, or not.** Every method sent to every endpoint reaches the same route handler unless the framework, application code, or an intermediary (WAF/gateway) explicitly restricts which methods that handler accepts.

This creates two independent failure modes you're testing for:

1. **Unintended method allowance**: a method the spec never documented for an endpoint actually works, because the underlying framework routes it there anyway (e.g., a framework that maps *any* method to a handler unless told otherwise) or because a second, forgotten handler exists for that path.
2. **Inconsistent authorization per method**: the endpoint correctly requires authentication/authorization for `GET`, but a developer wrote the `DELETE` or `PATCH` handler later, forgot to apply the same authorization middleware, and that method now bypasses controls that clearly exist elsewhere on the same path.

The second failure mode is far more common in real applications than the first, and it's why method testing has to happen on **every** endpoint, not just ones you suspect are risky — a low-risk-looking `GET /api/products/1` endpoint might sit right next to a completely unprotected `DELETE /api/products/1`.

## The core testing loop

For every endpoint in your File 01 inventory, regardless of what the spec says is supported:

```
GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE, CONNECT*
```

\*`TRACE`/`CONNECT` are rarely relevant to application-layer REST APIs (they're more transport/proxy-level) but cost nothing to include in an automated sweep.

### Step-by-step, piece by piece

**Step 1 — Send the baseline `OPTIONS` request first.**

```
OPTIONS /api/users/123 HTTP/1.1
Host: api.target.com
Authorization: Bearer <valid-token>
```

What this tests: `OPTIONS` is *supposed* to return an `Allow` header listing every method the server considers valid for that resource. This is your fastest signal of what to test next — **but treat it as a hint, not ground truth.** Many frameworks generate the `Allow` header from route registration and can either over-report (listing a method that's registered but actually rejected deeper in application logic) or under-report (a method handled by a catch-all route that never updates `Allow`). Always follow up by actually sending every method rather than trusting `Allow` alone.

What each part of the response tells you:
- `Allow: GET, HEAD, OPTIONS` → server-declared supported methods. Cross-check every one listed here, and every one *not* listed here, against real requests.
- Status `204 No Content` vs `200 OK` with a body → framework fingerprint; some frameworks (e.g. certain Express/Rails configurations) return extra debug info in `OPTIONS` bodies.
- Missing `Allow` header entirely → the endpoint doesn't implement `OPTIONS` handling at the application layer; this is itself worth noting, since it means CORS preflight behavior (if relevant) is likely being handled by a different layer (gateway/CDN) than the actual route logic — a mismatch you can sometimes exploit (see File 04 CORS interplay).

**Step 2 — Send the documented method as your control.**

Confirm the endpoint behaves exactly as your File 01 baseline recorded. If it doesn't, stop and re-baseline before continuing — you can't detect an anomaly against a baseline that's already wrong.

**Step 3 — Systematically send every undocumented method, targeting low-priority objects.**

```
DELETE /api/users/123 HTTP/1.1
Host: api.target.com
Authorization: Bearer <low-privilege-token>
```

What this specifically tests: whether the `DELETE` handler for this path exists **and** whether it independently enforces the same authorization the `GET`/`PUT` handlers enforce. A `200`/`204` response here, using a token that has no documented delete permission, is the core finding this step exists to catch.

**Important safety note (carried over from your standing conventions and directly from PortSwigger's own guidance):** when testing state-changing methods (`PUT`, `PATCH`, `DELETE`, `POST`) against real or shared lab objects, always target low-priority, disposable objects — a throwaway test record, not a shared account or the only instance of a critical resource. This applies doubly hard to authorized client engagements: confirm with the client which objects/environments are safe to mutate before running method sweeps in anything beyond an isolated lab.

**Step 4 — Vary the method on the *same* URL with different content-type/body combinations.**

Some frameworks route method dispatch differently depending on whether a body is present at all:

```
PATCH /api/users/123 HTTP/1.1
Content-Type: application/json
Content-Length: 0

```
vs.
```
PATCH /api/users/123 HTTP/1.1
Content-Type: application/json

{"role":"admin"}
```

What this tests: whether an empty-body `PATCH` is silently accepted (revealing the endpoint exists and is reachable) even where a populated body would normally be rejected for schema validation reasons — useful for confirming an endpoint's existence and method support independently of getting a fully valid payload right on the first attempt.

**Step 5 — Method override headers.**

Many frameworks and API gateways honor a header that lets a client *claim* a different method than the one actually sent, originally intended to work around client/proxy limitations on `PUT`/`DELETE`:

```
POST /api/users/123 HTTP/1.1
X-HTTP-Method-Override: DELETE
Authorization: Bearer <low-privilege-token>
```

What this specifically tests: whether a gateway-level or WAF-level method restriction (which typically inspects the literal HTTP method of the request line) can be bypassed by sending an *allowed* method (`POST`) on the wire while the application layer honors the override header and treats it as `DELETE`. This is a distinct, gateway-focused bypass from Step 3's direct method test — test both, since a target can block direct `DELETE` while still honoring the override header. Common headers to try: `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`.

**Step 6 — Use Burp Intruder's built-in HTTP verbs list for scale.**

Once you've manually validated the mechanism on one or two endpoints, use Intruder's **HTTP verbs** payload list (built in) against the method position of every endpoint in your inventory, to cover the full surface without manually repeating Steps 1–5 per endpoint. Manually re-verify any hit before reporting it — automated sweeps produce false positives from generic error pages that return `200` regardless of method.

## What each unintended method typically exposes

| Method found unexpectedly enabled | Typical exposure |
|---|---|
| `DELETE` on a resource that should only support `GET` | Unauthorized resource deletion, often bypassing UI-layer confirmation dialogs and any authorization check tied only to the `GET`/`POST` handlers |
| `PUT`/`PATCH` on a read-only-looking resource | Unauthorized modification — frequently reveals additional writable fields via mass assignment (cross-reference File 06) |
| `TRACE` enabled | Can enable Cross-Site Tracing (XST) in specific legacy browser/proxy configurations — rare in modern REST APIs but trivial to check and worth ruling out explicitly |
| `OPTIONS` returning verbose `Allow` + framework version in headers | Information disclosure aiding further recon (framework fingerprinting) |
| Alternate method reaching a *different* handler than expected (e.g., `POST` to a path documented as `GET`-only routes to an internal admin action) | Access to hidden functionality never exposed in any documented method for that path — this is the scenario PortSwigger's "unused API endpoint" lab is built around |

## WAF / API Gateway relevance — dedicated section

Method-based restrictions are one of the areas where WAFs and API gateways are most commonly configured, making this section directly relevant.

### How WAFs/gateways typically detect this attack pattern

- **Allowlist enforcement per route**: modern API gateways (Kong, Apigee, AWS API Gateway, Azure APIM) are commonly configured with an explicit allowlist of methods per route, rejecting anything else at the gateway before it reaches application code — this is exactly the mitigation PortSwigger recommends ("apply an allowlist of permitted HTTP methods").
- **Signature-based detection on method + path combinations**: some WAFs flag high volumes of varied-method requests against the same path in a short window as a scanning signature, since this pattern is unusual in legitimate client traffic (browsers/legitimate API clients rarely probe every method against the same resource).
- **Method-override header inspection**: security-aware gateways specifically strip or ignore `X-HTTP-Method-Override`-style headers rather than honoring them, precisely because of the Step 5 bypass above — but this is inconsistently implemented, which is why the header is still worth testing on every engagement rather than assumed useless.

### Realistic bypass considerations

- **Gateway vs. application-layer mismatch**: if the gateway blocks `DELETE` at the edge but the origin server is directly reachable (misconfigured DNS, exposed origin IP, missing IP allowlisting on the origin), sending the same request directly to the origin bypasses the gateway's method restriction entirely. Always check for direct-origin reachability as part of recon (File 01) before concluding a method is blocked.
- **Case and whitespace variation**: some less rigorous method-filtering implementations match methods as an exact-case string comparison; trying lowercase or mixed-case methods (`delete`, `Delete`) occasionally slips past naive allowlists, though most modern frameworks normalize method casing before comparison — treat this as a low-probability check, not a primary technique.
- **Method-override headers remain a legitimate first bypass attempt** even against gateway-level blocks, precisely because many gateways only inspect the request-line method and pass the override header through unmodified to the application, which then honors it (Step 5).
- **Rate-limited scanning detection**: if a target's WAF flags rapid multi-method probing, throttle your Intruder sweep (add delay between requests, reduce thread count) and/or spread testing across a longer session rather than a single burst, consistent with a careful, deliberate authorized-testing pace rather than a noisy automated scan signature.

---

## PortSwigger lab mapping

| Lab | Difficulty | Maps to |
|---|---|---|
| Finding and exploiting an unused API endpoint | Practitioner | Steps 3 and 6 above — the lab specifically requires discovering that an endpoint supports an undocumented method exposing hidden functionality (price manipulation via an undocumented `PATCH`) |

**Honest gap disclosure:** PortSwigger has no lab dedicated purely to the `X-HTTP-Method-Override` gateway-bypass technique (Step 5) or to `TRACE`/XST testing — these are lower-frequency findings in modern stacks and PortSwigger's single Practitioner-level method-abuse lab focuses on direct undocumented-method discovery rather than override-header bypass. Treat Step 5 as an established real-world technique validated by gateway vendor documentation and public bug bounty writeups, not something you can currently drill on PortSwigger.

### crAPI supplementary practice

- crAPI's **workshop/community endpoints** expose several routes where methods beyond the documented ones are enabled, making it a good secondary environment to practice the full Step 1–6 loop against a multi-endpoint surface rather than a single isolated lab instance.

---

## What's next

File 03 moves from method-level surface abuse to version-level surface abuse: testing whether older API versions remain reachable with weaker enforcement than the current one.
