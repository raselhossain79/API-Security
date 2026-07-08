# 7. Final Cheatsheet and Lab Mapping

## 7.1 Honest scope disclosure

PortSwigger Web Security Academy's dedicated Race Conditions topic does not contain
labs explicitly labeled as "API" race conditions — all six labs in that topic are
built around a browser-facing e-commerce/login flow, not a bearer-token API or a
GraphQL endpoint. This is an honest gap: there is no PortSwigger lab that lets you
practice GraphQL aliased batching, idempotency key abuse, or a genuine microservice
check/use split exactly as described in Files 1-4 of this series.

What the labs below **do** give you is the core mechanism practice — TOCTOU windows,
limit overruns, multi-endpoint alignment, partial construction — using the same
underlying logic flaws that this series' API-specific files build on. Each lab is
mapped below with an honest note on how directly (or how loosely) it translates to
the API-specific technique in this series, rather than overstating the overlap.

## 7.2 PortSwigger Race Conditions labs, in difficulty progression order

### Apprentice

**1. Limit overrun race conditions**
- Core lesson: classic TOCTOU limit overrun on a discount-code endpoint, solved via
  the single-packet attack.
- API translation: **direct** — this is architecturally identical to the coupon
  redemption race in File 5, section 5.2, REST path. The only adaptation needed for
  a real API target is swapping cookie-session auth for bearer-token auth (File 1,
  section 1.1), which if anything removes a defense rather than adding complexity.

### Practitioner

**2. Bypassing rate limits via race conditions**
- Core lesson: exploiting a race condition to bypass a per-username brute-force rate
  limit on a login endpoint.
- API translation: **partial** — the underlying TOCTOU mechanism (racing a counter
  increment) is the same mechanism relevant to File 1, section 1.4's discussion of
  gateway-level rate limiting, but the lab itself doesn't involve an API gateway or
  a distributed rate-limit store (like Redis) the way a real production API would.
  Useful for the core concept; not a substitute for testing an actual gateway-backed
  rate limiter.

**3. Multi-endpoint race conditions**
- Core lesson: racing a `POST /cart` and `POST /cart/checkout` pair to add items
  after order validation but before confirmation.
- API translation: **direct** — this is the exact conceptual ancestor of File 2's
  check/use and reserve/confirm patterns. The lab's two-endpoint structure maps
  cleanly onto the reserve/confirm ticketing scenario in File 5, section 5.4,
  including the same "align the race windows across two different endpoints"
  challenge and the connection-warming solution.

**4. Single-endpoint race conditions**
- Core lesson: racing parallel requests to a single password-reset endpoint with
  different usernames to cause a session-state collision.
- API translation: **loose** — this lab's exploit depends on server-side session
  variables, which don't exist in a stateless bearer-token API (File 1, section
  1.1). The underlying "single endpoint, different input values, shared mutable
  state" concept is still relevant to some API scenarios (e.g. a shared cache key
  collision), but the specific session-variable mechanism doesn't transfer directly.

**5. Exploiting time-sensitive vulnerabilities**
- Core lesson: racing two password reset requests timed to generate the same
  timestamp-derived token.
- API translation: **loose** — relevant background if an API generates
  security-critical tokens (idempotency keys, reset tokens, API keys) from
  insufficiently random sources, which connects conceptually to File 4, section 4.5's
  note on predictable idempotency key generation, but the lab itself isn't an API
  race condition in the sense this series covers.

### Expert

**6. Partial construction race conditions**
- Core lesson: exploiting a race window during multi-step object creation (a new
  user account created before its API key is initialized) using PHP array-parameter
  syntax to match an uninitialized `null`/empty value.
- API translation: **direct, and worth calling out specifically** — this lab's
  underlying flaw (an object exists mid-construction with an exploitable
  uninitialized field) is directly relevant to API account/resource creation
  endpoints, and the "partial construction" concept generalizes well to the
  reserve/confirm and check/use patterns in File 2, where a resource can exist in an
  incomplete or pending state that a parallel request can exploit before the
  resource is fully finalized.

## 7.3 crAPI supplementary practice mapping

crAPI (Completely Ridiculous API) is referenced throughout this series as
supplementary practice specifically because, unlike the PortSwigger labs above, it
is an actual API target (REST, not browser-form-driven), which fills the gap noted
in 7.1. Relevant areas to test using crAPI, mapped to this series:

- **Coupon/voucher redemption endpoints** — map to File 5, section 5.2, and are a
  direct hands-on complement to PortSwigger's Apprentice limit-overrun lab, but
  against a real bearer-token API rather than a cookie-session web app.
- **Vehicle/mechanic request workflows involving multi-step state transitions** — map
  to File 2's multi-step chain race concept; useful for practicing the "predict
  potential collisions across the chain" methodology against endpoint pairs that
  aren't labeled as obviously as PortSwigger's `POST /cart` / `POST /cart/checkout`
  pair.
- **Community/forum post and contact-mechanic endpoints with resource ownership
  checks** — while primarily a BOLA/IDOR target (see the Broken Access Control
  series), worth retesting for race conditions where object creation and ownership
  assignment happen as separate steps, connecting to the partial-construction concept
  from PortSwigger's Expert lab.

**Honest gap:** crAPI does not include a GraphQL endpoint, so it provides no direct
practice for File 3's aliased batching technique. For that, practice against a
GraphQL-specific vulnerable target (see the GraphQL notes series for target
recommendations) rather than crAPI.

## 7.4 Master cheatsheet

### Detection priority order (repeated from File 5, section 5.5, for quick reference)

1. Batch/array duplicate-element test — no tooling required.
2. GraphQL aliased batch test — no network timing tooling required.
3. Idempotency key parallel-replay test — highest severity when found.
4. Multi-step chain race test (reserve/confirm, check/use pairs).
5. Classic single-endpoint limit-overrun race via single-packet attack — reserve for
   last, highest tooling precision required.

### Quick reference: technique vs. required conditions

| Technique | Requires HTTP/2 | Requires precise timing | File |
|---|---|---|---|
| Batch/array duplicate test | No | No | 1, 6 |
| GraphQL aliased batching | No | No | 3 |
| Idempotency key parallel replay | No (helps, not required) | Somewhat | 4, 6 |
| Multi-step chain race | No | Low-to-moderate (window often wide) | 2 |
| Single-packet attack (classic) | Yes | Yes | 6, general series |

### Quick reference: where to look for the underlying architectural cause

| Symptom | Likely cause | File |
|---|---|---|
| Same-account parallel requests process with no serialization at all | Stateless bearer-token auth, no session lock | 1.1 |
| Race window is wide (hundreds of ms, not single-digit ms) | Distributed microservice check/use split | 1.2 |
| Single request with array/batch overruns a limit | Validate-once, apply-many loop | 1.3 |
| Intermittent success only on first request of a burst | Gateway-level rate limiting/throttling | 1.4 |
| Duplicate idempotency key produces >1 distinct transaction ID | Non-atomic idempotency key check-and-mark | 4.2 |
| Reserve succeeds many times but confirm should have failed | Reserve/confirm split with no re-validation at confirm | 2.2(B) |

### WAF/gateway defense-awareness quick check

Before concluding a race attempt failed, rule out each of the following gateway-level
interferences, in this order:

1. Protocol mismatch — confirm HTTP/2 support if using the single-packet attack.
2. Gateway-level rate limiting — check for `429`s partway through a burst.
3. Gateway-level idempotency deduplication — check for suspiciously uniform/fast
   "duplicate" response latency and any gateway-specific cache/dedup header.
3. Per-key concurrency limits — retest with multiple valid tokens for the same
   resource if in scope.
5. Persisted-query enforcement (GraphQL only) — check for a `PersistedQueryNotFound`
   error blocking ad-hoc batched mutations.

## 7.5 Reporting checklist for API race condition findings

- State the specific architectural cause (from the table in 7.4), not just "race
  condition found" — this determines remediation guidance and severity.
- Quantify the overrun ratio (e.g. "X of Y parallel requests succeeded") rather than
  reporting a binary pass/fail.
- Note whether a WAF/gateway-level control partially mitigated the issue (e.g. rate
  limiting made exploitation harder but did not eliminate it) — this affects severity
  scoring and should be stated explicitly rather than omitted.
- For idempotency key findings, distinguish clearly between "idempotency key not
  enforced" (4.2), "underlying operation racy independent of idempotency keys" (4.3),
  and "idempotency key body-mismatch not validated" (4.4) — these are different root
  causes requiring different fixes.
