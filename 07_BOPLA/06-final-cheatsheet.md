# BOPLA — Broken Object Property Level Authorization
### File 6 of 6: Final Cheatsheet

Quick-reference for live engagements. Full mechanism explanations are in files 1–5 —
this file is deliberately terse.

---

## 1. Core Definitions

| Term | Definition |
|---|---|
| **BOPLA** | OWASP API3:2023 — authorization failure at the individual **property/field** level (merges 2019's API3 Excessive Data Exposure + API6 Mass Assignment) |
| **Excessive Data Exposure** | API **response** contains fields the caller shouldn't see, regardless of what the UI renders |
| **Mass Assignment** | API **request** binds attacker-supplied fields onto internal object properties the caller shouldn't be able to set |
| **CSV/Formula Injection** | Related export-boundary issue (CWE-1236): unsanitized object properties written into CSV/XLS trigger spreadsheet formula execution when opened |

Distinguish from siblings: **BOLA** = wrong object, **BFLA** = wrong function/endpoint,
**BOPLA** = wrong property on an otherwise-authorized object/endpoint.

---

## 2. Excessive Data Exposure — Quick Test Checklist

- [ ] Capture raw JSON response in Burp — never trust the rendered page.
- [ ] List every field in the response; list every field rendered in the UI.
- [ ] Flag anything in response-not-UI matching: `*_hash`, `*_token`, `*_secret`,
      `*_key`, `internal_*`, `is_*`, `*_admin`, `*_role`, `*_score`, `*_ip`, `ssn`, `dob`,
      raw sequential `id`.
- [ ] Repeat for **list/array endpoints** — nested objects often leak more than the
      single-object endpoint.
- [ ] Compare same object ID across roles (user vs admin/support endpoint) — same
      response shape returned to a lower role = finding.
- [ ] Check search/autocomplete/pagination endpoints — often reuse the over-exposed
      serializer.

---

## 3. Mass Assignment — Quick Test Checklist

- [ ] Baseline the documented request for every `POST`/`PUT`/`PATCH`.
- [ ] Build candidate field list from: prior Excessive Data Exposure findings, JS/mobile
      source, common guesses (`isAdmin`, `role`, `balance`, `verified`, `status`,
      `user_id`/`owner_id`).
- [ ] Inject **one field at a time**, alongside legitimate fields.
- [ ] Never trust the write response — always `GET` the object back to confirm state
      change.
- [ ] Repeat per-endpoint, not per-object-type (sibling endpoints on the same model are
      independently vulnerable/safe).
- [ ] Compare role-gated writes: does a low-priv user's payload produce the same state
      change an admin's identical payload produces?

---

## 4. Mass Assignment Filter Bypass — Quick Reference

| Technique | What to try | Why it works |
|---|---|---|
| Alternate names/casing | `IsAdmin`, `is_Admin`, `admin_flag`, `userRole` | Blocklist matches one exact string; binder may be case-insensitive or alias-aware |
| Nested object injection | `{"profile":{"is_admin":true}}`, `{"account":{"settings":{"role":"admin"}}}` | Shallow filters don't recurse; permissive nested-write ORMs do |
| Array/bulk wrapping | `{"users":[{"id":X,"is_admin":true}]}` | Bulk endpoints may be more permissive than single-object endpoints |
| Content-type switching | Same fields via `application/x-www-form-urlencoded`, multipart, or legacy XML instead of JSON | Validation often built for one content type; framework accepts several via separate parsers into the same binder |
| JSON key duplication | `{"role":"user","role":"admin"}` | Filter checks first occurrence; parser keeps last (or vice versa) |

**WAF/Gateway note:** true schema whitelisting (`additionalProperties: false`) at the
gateway is NOT bypassable by the above — look for endpoints where the schema itself is
missing/looser instead.

---

## 5. CSV/Formula Injection — Quick Reference

- **Trigger characters**: `=`, `+`, `-`, `@`, tab (`0x09`), carriage return (`0x0D`) as
  the **first character** of a cell.
- **Safe test payloads**: `=1+1`, `=SUM(1,1)` — never use `cmd|`, PowerShell, or
  `WEBSERVICE()`/`HYPERLINK()` payloads against a file another real person might open.
- **Sweep every field** that is (a) user-writable and (b) later appears in any CSV/XLS
  export, admin dashboard, or scheduled report.
- **2025 real-world confirmations**: CVE-2025-11279/12249 (Axosoft ticket title →
  CSV export), CVE-2025-62417 (Bagisto product field → CSV export), CVE-2025-55745
  (UnoPim quick-export → PowerShell reverse shell).
- **Mitigation to recommend**: neutralize at write time AND export time (defense in
  depth) — not a single WAF rule, which produces false positives on legitimate data
  starting with `-` or `@`.

---

## 6. WAF / API Gateway Relevance Summary

| Sub-type | Gateway-relevant? | Why |
|---|---|---|
| Excessive Data Exposure | **No** (mostly) | Benign, legitimate-looking request; requires response-schema-aware allow-listing, not pattern matching — different control category entirely |
| Mass Assignment | **Yes** | Request-side field injection; gateway JSON-schema whitelisting is the one control that isn't easily bypassed by the techniques in file 4 |
| CSV/Formula Injection | **Partially** | Detectable via leading-character inspection, but high false-positive rate makes application-layer (export-time) mitigation the recommended fix, not a gateway rule |

---

## 7. PortSwigger Lab Map — Full Series, Correct Progression Order

| # | Difficulty | Lab | Topic file |
|---|---|---|---|
| 1 | Apprentice | Exploiting an API endpoint using documentation | Files 2 & 3 (recon baseline) |
| 2 | Practitioner | Finding and exploiting an unused API endpoint | File 2 (response inspection) |
| 3 | Practitioner | **Exploiting a mass assignment vulnerability** | File 3 (primary dedicated lab) |
| 4 | Practitioner | Exploiting server-side parameter pollution in a query string | File 4 (parameter pollution parallel) |
| 5 | Expert | Exploiting server-side parameter pollution in a REST URL | File 4 (advanced bypass mindset) |

**Honest gaps**: No PortSwigger lab exists for Excessive Data Exposure specifically, and
none exists for CSV/Formula Injection at all. Use crAPI (dashboard/vehicle endpoints for
exposure, profile/coupon endpoints for mass assignment) and the public 2025 CVE
write-ups (section 5) to fill these gaps.

---

## 8. Report-Writing Reminders

- For Excessive Data Exposure findings: always show the raw JSON, not a screenshot of the
  UI — the UI is irrelevant to the finding.
- For Mass Assignment findings: always include the `GET` read-back proving server-side
  state change, not just the write request/response.
- For CSV/Formula Injection: use only diagnostic payloads (`=1+1`) in the report unless
  you have explicit written authorization and a fully isolated environment for a
  code-execution PoC; state clearly if full impact could not be directly demonstrated due
  to scope.
- Always name which sub-type (Excessive Data Exposure vs Mass Assignment vs
  Formula Injection) each finding belongs to — they have different root causes and
  different fixes, even when reported under the same "BOPLA" umbrella.
