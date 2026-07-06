# API Injection Testing Notes

A focused note series on how SQL injection, NoSQL injection, OS command injection, SSTI,
and XXE apply specifically through **API endpoints** — JSON/XML body delivery, nested and
array parameters, testing methodology adapted for the API context, and WAF/API Gateway
bypass techniques specific to structured-body inspection.

## Scope

This series does **not** re-teach the underlying mechanics of each vulnerability class.
It assumes that knowledge is already covered in the corresponding web-application
injection note series, and builds only the **API-delivery-specific layer** on top:
JSON/XML body structure, encoding requirements, sqlmap-for-JSON workflow, MongoDB
operator injection, blind detection in async/gateway-fronted architectures, and
JSON-context WAF bypass technique.

## Files

| File | Contents |
|---|---|
| `01-overview-api-injection-context.md` | Why API injection differs from web-app injection: JSON delivery, nested objects, arrays, encoding, WAF behavior split |
| `02-sqli-via-api.md` | SQLi through JSON body values, Burp workflow, full sqlmap flag breakdown for JSON bodies |
| `03-nosql-injection-via-api.md` | MongoDB operator injection (`$ne`, `$gt`, `$regex`, `$where`) via JSON bodies |
| `04-command-injection-via-api.md` | Shell-out parameters in REST bodies; blind detection via time delay and OOB |
| `05-ssti-xxe-via-api.md` | Template expression injection via API strings; Content-Type switching for XXE |
| `06-waf-bypass-api-injection.md` | Dedicated WAF/Gateway detection & bypass for JSON-context injection (Unicode escaping, nested JSON, Content-Type switching, parser discrepancy) |
| `07-methodology-cheatsheet.md` | Consolidated testing checklist, encoding reference, sqlmap quick command, full PortSwigger lab progression table |

## Relationship to the Web-App Injection Series

Read the relevant web-app series file first for underlying vulnerability theory, then
read the corresponding file here for the API-delivery adaptation. Cross-references are
called out inline throughout.

## Practice Environment

- **Primary**: PortSwigger Web Security Academy — labs are form/query-string-native, so
  each file includes an explicit Apprentice → Practitioner → Expert mapping with notes on
  how to convert the lab's request into a JSON body for API-context practice.
- **Gap coverage**: **crAPI** is used throughout wherever PortSwigger has no equivalent
  lab (most notably: NoSQL injection has no Academy category at all). Gaps are disclosed
  explicitly in each file rather than omitted silently.

## Tooling

- Burp Suite (Repeater, Intruder, Collaborator) — primary manual testing tool throughout.
- Param Miner — hidden/nested parameter discovery.
- sqlmap — JSON-body SQLi automation (full flag breakdown in file 2).
- crAPI — supplementary JSON-native vulnerable target for gap coverage.

## Conventions

- Full English only, all files.
- Every payload and command broken down piece by piece — no unexplained payloads.
- WAF/Gateway relevance addressed explicitly in every file (dedicated note per
  vulnerability class, full technique detail centralized in file 6).
- Real-world framing included in every file.
- Honest gap disclosure where PortSwigger Academy coverage doesn't exist.
