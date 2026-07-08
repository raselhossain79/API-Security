# Final Cheatsheet and Lab Mapping

File 9 of 9 — the closing reference for the GraphQL Security Testing
series. Two parts: a consolidated quick-reference cheatsheet, and a full
mapping of every PortSwigger Web Security Academy GraphQL lab to the file
in this series that covers the underlying technique, in official
difficulty-progression order, with honest gap disclosure.

---

## Part A — Quick-reference cheatsheet

### A1. Recon and confirmation

```graphql
query { __typename }
```
Universal GraphQL confirmation probe. Try against `/graphql`, `/api`,
`/api/graphql`, `/graphql/api`, `/graphql/v1`, `/v1/graphql`, with GET and
form-encoded fallbacks if POST/JSON yields nothing. (File 2)

### A2. Introspection

```graphql
{__schema{queryType{name}}}
```
Cheap introspection-enabled probe before running the full query. (File 2)

If blocked: try whitespace insertion (`__schema\n{`), alternate transport
(GET/form-encoded), or fall back to field-suggestion leakage — send a
guessed field name and read the "Did you mean...?" error, recursively.
(File 2)

### A3. Batching / alias rate-limit bypass

```graphql
mutation {
  guess0: verifyOtp(code: "0000") { success }
  guess1: verifyOtp(code: "0001") { success }
}
```
Convert `variables`-based single calls to inline-argument aliased calls;
delete stale `variables`/`operationName`; generate the alias set
programmatically; grep response for the success indicator. (File 3)

### A4. Depth / complexity DoS

```graphql
query { comments { replies { replies { replies { body } } } } }
```
Nest through self-referential or cyclic type relationships; test
incrementally to find the actual rejection threshold; also test large
pagination arguments combined with moderate nesting to probe for
cost-scoring vs. depth-only limiting. (File 4)

### A5. Authorization (BOLA/BFLA)

- Substitute ID arguments with a second test account's IDs — direct and
  nested/indirect access paths both.
- Call every introspected mutation never observed in normal UI traffic
  directly as a low-privilege account.
- Request full field sets on returned types, not just UI-selected fields,
  to catch field-level exposure gaps.
(File 5)

### A6. Injection

- Test `String`-typed (and unstructured/`JSON`-typed) arguments with
  classic SQLi payloads via `variables` first, then inline arguments.
- Test NoSQL targets by sending JSON objects (`{"$ne": null}`) in place of
  expected scalar values, even against typed arguments.
- Test nested input-object fields, not just top-level scalar arguments.
(File 6)

### A7. WAF evasion

- Whitespace/token insertion, field/argument reordering, renaming
  attacker-controlled identifiers (aliases, operation names, fragment
  names) — cheap first-pass evasion against signature-based detection.
- Fragment restructuring to relocate sensitive selections away from
  shallow top-level scanning.
- Against AST/complexity-aware defenses: distribute cost/payload volume
  across multiple individually-unremarkable requests rather than varying
  one request's syntax.
(File 7)

### A8. Tooling one-liners

```bash
# graphql-cop — fast first-pass scan, JSON output with cURL reproduction
python3 graphql-cop.py -t https://target/graphql -o json

# InQL standalone — full schema dump + HTML docs + query templates
inql -t https://target/graphql --generate-html --generate-queries -o ./inql-output
```
(File 8)

---

## Part B — PortSwigger GraphQL lab mapping

### Honest gap disclosure, stated up front

PortSwigger's GraphQL topic has a **smaller dedicated lab set than most
other topics in this series' companion library** — five labs total, one
Apprentice and four Practitioner, with **no Expert-tier GraphQL labs
currently published**. This is stated plainly rather than padding the
mapping with unrelated labs from other topics to appear more comprehensive.
If PortSwigger adds further GraphQL labs (including any future Expert-tier
labs) after this file was written, re-check
`https://portswigger.net/web-security/graphql` before relying on this list
as exhaustive.

Additionally: **one of the five labs (CSRF over GraphQL) touches a topic
this series does not have a dedicated file for.** CSRF fundamentals
(same-site cookie behavior, missing anti-CSRF tokens, GET-based
state-changing requests) are assumed prerequisite knowledge from this
series' companion REST-focused CSRF notes, not re-taught here — this file
maps the lab to the relevant sections of files 2 and 6 that explain the
GraphQL-specific mechanics involved (why a GET-based GraphQL query is
CSRF-exploitable, and how a state-changing mutation reaches the resolver
the same way regardless of transport), but does not attempt to substitute
for dedicated CSRF methodology content.

### The mapping, in official difficulty progression

| # | Lab name | Difficulty | Core technique | Covered in |
|---|---|---|---|---|
| 1 | Accessing private GraphQL posts | Apprentice | Use introspection to discover a query that returns data not exposed through the normal UI, then call it directly | File 2 (§4–5): full introspection query, reading `Query` fields not surfaced in the app |
| 2 | Finding a hidden GraphQL endpoint | Practitioner | The GraphQL endpoint itself isn't at a common/obvious path and must be discovered before any other technique applies | File 2 (§2): universal `__typename` probe against a path list, plus checking app JS/traffic for the real endpoint path |
| 3 | Accidental exposure of private GraphQL fields | Practitioner | A type has a field (e.g. a password or internal field) that isn't selected by the UI but is fully queryable once you request it directly | File 2 (§4–5) for finding it via introspection, and File 5 (§4) for the field-level-authorization framing of why this is a distinct bug class from BOLA/BFLA |
| 4 | Bypassing GraphQL brute force protections | Practitioner | Use aliasing to pack many login/credential-check attempts into one HTTP request, defeating a per-request rate limiter | File 3 in full — this lab's scenario is essentially the OTP/login walkthrough in File 3 §4, adapted to whatever credential check the lab presents |
| 5 | Performing CSRF exploits over GraphQL | Practitioner | Deliver a state-changing GraphQL mutation cross-site, exploiting GET-based query support or missing CSRF protections on the GraphQL endpoint | GraphQL-specific mechanics covered in File 2 §6b (alternate-transport/GET support) and File 6 §2 (why transport choice doesn't change what the resolver executes); general CSRF exploitation methodology is assumed prerequisite from this series' companion CSRF notes, not re-taught here |

### Suggested working order

Work the table top to bottom — it already matches PortSwigger's own
Apprentice → Practitioner ordering, and each lab's prerequisite knowledge
builds cleanly on the previous one: you need comfortable introspection
usage (labs 1–2) before field-exposure hunting becomes fast (lab 3), and
you need to be fluent with aliasing as a mechanic (file 1/file 3) before
lab 4's brute-force bypass stops feeling like a scripting exercise and
starts feeling like an obvious next move once you see a rate limiter in
front of a login mutation.

### crAPI supplementary practice

Per this series' standard convention, crAPI (Completely Ridiculous API) is
noted here as supplementary hands-on practice alongside the PortSwigger
labs. **Caveat specific to this file:** crAPI's core intentionally
vulnerable surface is REST-based; its GraphQL-specific coverage is
comparatively thin relative to the REST-focused companion series in this
note library. Treat crAPI as useful for practicing the general
API-recon-and-authorization mindset that transfers directly to GraphQL
(file 5's methodology in particular), rather than as a source of
GraphQL-specific lab scenarios comparable in depth to the PortSwigger
GraphQL set above. Damn Vulnerable GraphQL Application (DVGA) is a stronger
GraphQL-specific supplementary target if deeper hands-on practice beyond
PortSwigger's five labs is wanted — it covers DoS, information disclosure,
injection, and broken authorization scenarios that map directly onto files
3, 4, 5, and 6 respectively, with more room to practice than PortSwigger's
smaller lab count allows.

---

## Part C — Series recap

| File | Title | Core takeaway |
|---|---|---|
| 1 | GraphQL Fundamentals for Pentesters | The schema is not an access-control boundary; the resolver is |
| 2 | Introspection and Schema Extraction | Full schema dump reveals mutations never exposed in any UI; field-suggestion leakage survives introspection being disabled |
| 3 | Batching and Alias Attacks | One HTTP request can contain many operations; rate limiters counting requests, not operations, are trivially bypassed |
| 4 | Depth, Complexity, and DoS Attacks | Nested selections multiply resolver calls; small requests can carry exponential backend cost |
| 5 | Authorization Testing (BOLA/BFLA) | Every field is its own authorization decision; test the whole schema graph, not just obvious direct-access endpoints |
| 6 | Injection Testing | GraphQL's type system validates shape, not safety; classic injection classes resurface unchanged once past the resolver |
| 7 | WAF Bypass for GraphQL | Detection layers range from naive string-matching to true AST parsing; match your evasion technique to the actual layer present |
| 8 | Tooling (InQL + graphql-cop) | graphql-cop for fast automated first-pass signal, InQL for interactive schema exploration and template generation |
| 9 | Final Cheatsheet and Lab Mapping | This file |

This closes the GraphQL Security Testing series.
