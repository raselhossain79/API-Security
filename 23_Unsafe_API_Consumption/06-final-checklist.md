# 06 — Final Checklist: Unsafe Consumption of APIs (API10:2023)

## 1. Design / architecture checklist

- [ ] Every outbound third-party/microservice integration has been
      inventoried (no "we forgot we call that vendor" gaps)
- [ ] Every integration has an explicit **response schema/contract**
      defined (JSON Schema, OpenAPI response spec, protobuf, or equivalent
      typed model) — not just "we parse the JSON and hope"
- [ ] Failure handling for every third-party call is explicitly
      **fail-closed** for any security-relevant decision (fraud checks,
      auth/entitlement checks, content moderation, KYC/identity verification)
- [ ] Any feature that lets a user configure a third-party endpoint (custom
      webhook, custom API URL, "bring your own integration") has a
      documented, enforced destination allowlist or is treated as
      full SSRF attack surface in threat modeling
- [ ] Egress network policy exists (or is explicitly deferred with a
      documented reason) — can application services reach arbitrary
      external/internal hosts, or is there a forward-proxy/gateway
      enforcing an allowlist?
- [ ] TLS certificate validation is enabled (not disabled "temporarily") on
      every outbound client used for third-party calls

## 2. Code review checklist (white-box)

- [ ] No third-party response field is concatenated directly into a SQL
      query, ORM raw-query call, shell command, or template string —
      parameterized queries / argument-array process calls / safe template
      auto-escaping used throughout
- [ ] Every response field typed or documented as a URL is validated
      against an allowlist (scheme + domain, ideally + resolved IP) before
      being used in any further outbound request
- [ ] Redirect-following is disabled by default on internal HTTP clients
      used for consuming third-party responses, or redirects are
      re-validated against the same allowlist at each hop
- [ ] Deserialization uses a typed/validated model (Pydantic, Zod,
      class-validator, generated protobuf/OpenAPI types) rather than loose
      untyped dict/object access
- [ ] Every `try/except` / `try/catch` around a third-party call has been
      reviewed specifically for what the failure branch does — confirm it
      does not silently default to an allow/success state for anything
      security-relevant
- [ ] Recursive merge/deep-extend of third-party response data into
      internal objects filters or blocks `__proto__`, `constructor`, and
      `prototype` keys (or uses `Object.create(null)` / equivalent safe
      merge utility)
- [ ] Response data written to logs is treated as untrusted (newline/
      control-character stripping or structured logging instead of raw
      string interpolation) before being written or rendered in any
      log-viewing UI
- [ ] Shared/common "API client wrapper" modules used across services have
      been reviewed once, centrally — since a fix there fixes every caller
      (see file 02, section 7)

## 3. Testing checklist (black-box / grey-box)

- [ ] Inventoried every feature that lets you configure a third-party
      endpoint (custom webhook, custom API URL, URL/link preview,
      "import from URL," custom OAuth/SSO provider, sandbox/test payment
      endpoint)
- [ ] For each such feature: stood up a controlled mock server and
      confirmed what response bodies/status codes/timeouts it can be made
      to return
- [ ] Tested injection payloads (SQLi, SSTI, command injection markers) in
      every string-typed field of a mock response, observing for
      execution/error signatures per file 02
- [ ] Tested internal/metadata URLs (`169.254.169.254`, `localhost`,
      internal hostnames/ports) in every URL-typed field of a mock
      response, using out-of-band callback detection for blind cases, per
      file 03
- [ ] Tested type confusion (wrong type, `null`, missing field, empty
      array/object) in every field, specifically checking security-decision
      fields (fraud/verdict/entitlement booleans) for fail-open behavior
      per file 04
- [ ] Tested non-responses (timeout, connection refused, HTTP 500,
      non-JSON body) against the same security-decision endpoints
- [ ] Where no user-configurable third-party endpoint exists, documented
      this category as requiring grey-box/white-box follow-up rather than
      claiming black-box coverage that wasn't actually achievable

## 4. Reporting notes

- Always state the **trust assumption being violated** explicitly in a
  finding for this category — reviewers unfamiliar with API10 often
  initially read these findings as "not exploitable" because the payload
  doesn't come directly from the reporter's own request in the PoC. Make
  the two-hop chain (attacker → configurable third-party endpoint →
  vulnerable processing) explicit in the write-up, ideally with a sequence
  diagram.
- For fail-open findings (file 04, Scenario 3), quantify business impact
  in terms of the security control being bypassed (e.g., "fraud checks can
  be reliably bypassed by inducing a timeout"), not just "the app crashes."
- Cross-reference the specific injection/SSRF technique series (SQLi, SSTI,
  command injection, SSRF) for exploitation depth rather than duplicating
  that detail in an API10-specific report — this keeps the finding focused
  on the trust-boundary issue that makes it an API10 finding in the first
  place.

---

This completes the Unsafe Consumption of APIs (API10:2023) note series.
Return to `README.md` for the full file index.
