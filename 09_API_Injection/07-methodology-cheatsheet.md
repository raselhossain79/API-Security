# API Injection Testing — Methodology Cheatsheet

Quick-reference consolidation of files 1–6. Use this as the working checklist during
engagements; refer back to the individual files for full explanation of any step.

## Phase 1 — Recon & Body Mapping

- [ ] Capture all API requests in Burp Proxy; confirm `Content-Type` for each endpoint.
- [ ] Walk the full JSON tree of every request body — flag every leaf string, number, and
      array element as a candidate injection point (file 1).
- [ ] Use Param Miner to surface hidden/undocumented parameters not visible in captured
      traffic.
- [ ] Test alternate Content-Type values against each endpoint (`application/xml`,
      `text/xml`, `application/x-www-form-urlencoded`, `multipart/form-data`) — note which
      are accepted without a 415, even if undocumented (files 1, 5B, 6).
- [ ] Note which endpoints are read-only (search/filter/GET-style behavior via POST) vs
      write/state-changing — prioritize caution and authorization scope on the latter,
      especially before using `--risk=2` or higher sqlmap settings.

## Phase 2 — Vulnerability-Class Testing Order

Recommended order (roughly ascending setup complexity, not necessarily likelihood):

1. **SQLi** (file 2) — test JSON string values with quote-breaking payloads; confirm
   with Burp Repeater before automating with sqlmap.
2. **NoSQLi** (file 3) — test scalar fields (especially auth-related: password, token,
   role) with `$ne`/`$gt`/`$regex` object substitution; check for full-body `$where`
   acceptance as a schema-validation-strength probe.
3. **Command Injection** (file 4) — target functional patterns (diagnostics, file
   conversion, export/backup); confirm via OOB first (most reliable in API/gateway
   contexts), time-delay second.
4. **SSTI** (file 5A) — target "generate/personalize" style features; confirm with
   `{{7*7}}`-style arithmetic probes, check both synchronous response and any secondary
   output channel (email, generated file, webhook).
5. **XXE** (file 5B) — Content-Type-switch to XML first; confirm parser acceptance
   before attempting entity payloads; check secondary output channels same as SSTI.

## Phase 3 — Encoding & Escaping Quick Reference

| Delivery context | Encoding needed |
|---|---|
| JSON string value (SQLi, NoSQLi, cmd injection, SSTI) | JSON escaping: `\"`, `\\`, `\u00XX` |
| XML body (XXE) | XML entity encoding: `&lt;`, `&amp;`, `&quot;` |
| Query string on API endpoint (any body type) | URL-encoding, independent of body format |
| NoSQL operator key (`$ne`, `$gt`, `$where`) | No string-escaping — it's a JSON key/structure, not a string value |

## Phase 4 — WAF/Gateway Bypass Checklist (file 6)

- [ ] Baseline test: does the same payload succeed form-encoded but fail JSON (or vice
      versa) on an endpoint accepting both? — fastest signal for inspection-path gaps.
- [ ] Try Unicode-escaping (`\u00XX`) individual payload characters if a raw payload is
      blocked.
- [ ] If the target schema has genuine nested structure, test placing the payload at the
      deepest genuinely-supported nesting level.
- [ ] Test Content-Type switching as an evasion path, not just an application-layer XXE
      technique.
- [ ] Test malformed-but-plausibly-tolerated JSON (duplicate keys) if other techniques
      fail and engagement time allows for this more speculative technique.
- [ ] Remember: NoSQLi may be blocked by **type-schema validation** rather than signature
      matching — a `$ne` object substitution failing doesn't necessarily mean WAF
      signature detection; it may mean the Gateway enforces field types structurally, in
      which case none of the JSON-escaping bypass techniques apply.

## sqlmap Quick Command (JSON Body)

```bash
sqlmap -r request.txt --level=3 --risk=2 --technique=BT --batch --threads=2 -p <param>
```

Adjust `--threads` down to 1 first against rate-limited APIs; raise `--risk` only with
explicit authorization given the destructive-payload implications on write endpoints
(see file 2 for full flag rationale).

## Full PortSwigger Lab Progression Reference (API-Adapted, Consolidated)

| Vulnerability | Apprentice | Practitioner | Expert |
|---|---|---|---|
| SQLi | Login bypass; WHERE clause hidden data | Blind conditional responses; blind time delays | Filter bypass via XML encoding (closest analog to JSON-encoding bypass) |
| NoSQLi | *No Academy lab — use crAPI* | *No Academy lab — use crAPI* | *No Academy lab — use crAPI* |
| Command Injection | Simple case | Time delays; output redirection; OOB interaction; OOB exfiltration | *No Expert lab currently* |
| SSTI | — | Info disclosure via documentation; unknown language w/ documented exploit | Info disclosure via user-supplied objects (closest nested-JSON analog); sandboxed environment / sandbox escape |
| XXE | External entities file retrieval; SSRF via XXE | Blind XXE OOB; blind XXE OOB via parameter entities; blind exfiltration via malicious DTD | XInclude file retrieval |

**Gaps requiring alternative environments**: NoSQL injection (no Academy category at all
— use crAPI); deep, JSON-native practice generally for all classes (Academy labs are
form/query-string-native and require manual conversion, as noted throughout) — crAPI
remains the primary supplementary environment for genuinely JSON-first vulnerable
targets across this whole series.

## Reporting Note

When writing up findings from this methodology, always document:

- The exact JSON body sent (with payload highlighted), not just the vulnerable parameter
  name — reviewers unfamiliar with the specific nesting depth need to see the full
  request to reproduce.
- Which Content-Type was used, especially for any Content-Type-switch-based finding —
  this is easy to omit and makes reproduction impossible without it.
- Whether detection relied on response reflection, timing, or OOB interaction — timing-
  and OOB-based findings should include the Collaborator interaction log or timing data
  as evidence, since these aren't self-evident from the request/response pair alone.
