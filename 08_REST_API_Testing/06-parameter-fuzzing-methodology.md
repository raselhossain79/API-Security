# REST API Testing Methodology — 06: Parameter Fuzzing Methodology for APIs

## Mechanism: why API fuzzing needs a different approach than web-form fuzzing

Traditional web application fuzzing targets a flat, known parameter list — query-string keys or form fields you can enumerate directly from the rendered HTML. REST APIs break this model in three ways that this file's methodology is built specifically to address:

1. **Structure is nested and often deeply so.** A single request body might be `{"user": {"profile": {"address": {"zip": "..."}}}}` — four levels of nesting before you reach a fuzzable leaf value. Flat parameter wordlists don't address structural position at all.
2. **Arrays introduce a dimension flat fuzzing has no concept of.** `"items": [{"id": 1}, {"id": 2}]` can be fuzzed at the array level (add/remove elements) independently of fuzzing values within a single element.
3. **Hidden parameters in APIs are frequently *not* absent from the wire at all** — they're absent from the *documented* schema but still processed if present, because backend deserialization into an object typically ignores unrecognized fields silently rather than rejecting the whole request (this is the direct mechanical cause of mass assignment vulnerabilities).

## Step-by-step, piece by piece

### A. JSON body structure fuzzing

**Step 1 — Map the full documented schema before fuzzing anything.**

Pull the full request body schema from your File 01 spec extraction. For every field, note: type, whether required, whether it has an `enum` constraint, and its nesting depth. This is your fuzzing target list before you look for anything undocumented.

**Step 2 — Fuzz each leaf value against its declared type, one field at a time.**

```json
{"quantity": 1}
```
→
```json
{"quantity": "1"}
```
```json
{"quantity": -1}
```
```json
{"quantity": 0}
```
```json
{"quantity": 999999999999999}
```
```json
{"quantity": null}
```

What each variant specifically tests:
- String-for-number (`"1"`) — type coercion behavior, and whether downstream business logic assumes strict typing that a loosely-typed language silently doesn't enforce.
- Negative value (`-1`) — business logic validation gaps; a negative quantity reaching a pricing/inventory calculation can produce a negative total, effectively a refund-to-attacker scenario.
- Zero — edge-of-range boundary testing, frequently mishandled differently from both positive and negative values.
- Extreme magnitude — integer overflow behavior in the backend language/runtime, or unbounded resource consumption if the value drives a loop or allocation size downstream.
- `null` — whether the field is truly required server-side or only required by client-side/schema validation that the actual processing logic doesn't re-check.

**Step 3 — Fuzz structural type, not just value, at each field position.**

```json
{"quantity": [1, 2]}
```
```json
{"quantity": {"amount": 1}}
```

What this tests: sending an array or object where a scalar is expected probes whether the deserialization layer performs strict type validation or silently attempts to coerce/unwrap the structure — a common source of unexpected behavior in dynamically-typed backend frameworks, and occasionally a path to prototype-pollution-style issues (cross-reference your prototype pollution series for exploitation depth if you find a backend that merges nested objects unsafely).

### B. Nested object fuzzing

**Step 1 — Fuzz at every nesting level independently, not just the leaves.**

Given:
```json
{"user": {"profile": {"role": "customer"}}}
```

Test modifications at each level:
- Leaf level: `"role": "admin"` — the most obvious mass-assignment-style probe.
- Mid level: replace the entire `profile` object with an empty object `{}` or with `null` — tests whether the handler assumes the nested object always has a specific shape and crashes/misbehaves when it doesn't, sometimes revealing verbose stack traces (information disclosure) or fallback-to-default behavior that itself has security implications (e.g., falling back to a default role that's more privileged than intended).
- Top level: send `"user": []` (array instead of object) — tests deserialization strictness at the outermost structural boundary.

**Step 2 — Duplicate keys within nested structures.**

```json
{"user": {"role": "customer", "role": "admin"}}
```

What this tests: JSON technically permits duplicate keys, and different parsers resolve this differently — some take the first occurrence, some the last, some concatenate/error. If any component in the request path (WAF, gateway, application parser) resolves duplicates differently from another component in the same chain, this is a parameter-pollution-style desync usable to smuggle a value past a validating layer while a different value reaches the actual business logic. This is the JSON-body analogue of the query-string server-side parameter pollution technique PortSwigger's dedicated labs cover (see Lab Mapping below).

### C. Array injection

**Step 1 — Convert a scalar parameter into an array.**

```
GET /api/products?category=shoes
```
→
```
GET /api/products?category[]=shoes
GET /api/products?category=shoes&category=boots
```

What this tests: whether the backend framework's query-string parser has array-handling conventions (`param[]=`, repeated `param=`) enabled by default, even where the endpoint was designed for a single scalar value — this can reveal a secondary parsing path with different validation than the documented scalar-only usage, and in some frameworks, sending an unexpected array where a scalar is expected causes a type error that leaks framework/stack information.

**Step 2 — Inject unexpected object structures inside a JSON array.**

```json
{"items": [{"id": 1, "quantity": 2}]}
```
→
```json
{"items": [{"id": 1, "quantity": 2}, {"id": 1, "quantity": -2}]}
```

What this tests: business logic that correctly validates a *single* item's quantity might sum or aggregate the array without re-validating each element individually — a negative-quantity element paired with a positive one can be used to test whether the aggregate total is what gets validated, or each line item independently, revealing an inconsistency in how the array is processed as a whole vs. element-by-element.

**Step 3 — Array length/size extremes.**

Send an array with an unusually large number of elements (hundreds to low thousands, scaled responsibly to the target's evident capacity — this is a resource-consumption probe, not a denial-of-service attempt, so keep volume proportionate and stop at the first sign of server strain) to test whether the endpoint enforces any array-size limit at all. Unbounded array acceptance is a direct API4 (Unrestricted Resource Consumption) finding — cross-reference your dedicated API4 series for the full resource-exhaustion exploitation angle; this step here is purely about confirming the absence of a size limit as the initial discovery step.

### D. Hidden parameter discovery

**Step 1 — Use Param Miner for automated discovery before manual guessing.**

Param Miner (introduced in File 01 setup) actively guesses hidden parameters by sending a large wordlist of candidate parameter names and comparing responses for behavioral differences — this is differential analysis (File 05) applied specifically to parameter *names* rather than values. Run it against both query-string and JSON body positions; the JSON-body mode requires explicitly enabling it in Param Miner's settings since it doesn't default to body-parameter guessing the same way it does query-string guessing.

**Step 2 — Derive candidate hidden parameter names from your File 01 recon, not just generic wordlists.**

- Response field names that appear in a *related* endpoint's output but are missing from the request schema of the endpoint you're testing — a `GET` response containing an `isVerified` field is a strong candidate for a hidden, writable parameter on the corresponding `PATCH`/`PUT` endpoint for the same resource, even if it's absent from that endpoint's documented request schema.
- Frontend JavaScript variable names and object keys referenced anywhere near the API call construction, even ones that appear to be dead code or commented out — developers frequently leave references to fields that used to be client-settable and were only removed from the UI, not from backend acceptance.
- Naming-convention guessing based on confirmed parameters: if `is_verified` exists, systematically try `is_admin`, `is_staff`, `is_active`, `is_locked` — API naming conventions are usually internally consistent across a single codebase, making pattern-based guessing higher-yield than a purely generic wordlist.

**Step 3 — Confirm a discovered hidden parameter is genuinely processed, not merely tolerated.**

Finding that an unexpected parameter doesn't cause a `400` error is necessary but not sufficient — confirm the parameter actually changes server-side state or returned data (send it with a value that should produce an observable difference, then verify that difference via a follow-up `GET`) before treating it as a confirmed finding. An accepted-but-ignored parameter is not itself a vulnerability.

## WAF / API Gateway relevance — dedicated section

### How WAFs/gateways typically detect this attack pattern

- **Schema validation at the gateway layer**: API gateways with schema-enforcement features (validating incoming requests against the OpenAPI spec before forwarding to the application) will reject requests containing parameters not defined in the schema, or with type mismatches — this is the most direct and increasingly common defense against exactly the fuzzing described in Sections A–D.
- **Payload size and depth limits**: gateways commonly enforce maximum JSON nesting depth and maximum array length as a generic anti-abuse control (also relevant to resource-exhaustion attacks generally), which directly limits Section C.3's array-size probing and Section B's deep-nesting tests.
- **Duplicate-key normalization at the gateway**: security-conscious gateways normalize or reject duplicate JSON keys before forwarding the request, specifically to prevent the parser-disagreement class of attack described in Section B, Step 2.

### Realistic bypass considerations

- **Schema validation gaps for optional/loosely-typed fields**: even where a gateway enforces schema validation, fields marked as loosely typed (e.g., a generic `object` or `any` type in the OpenAPI spec, common for metadata/extension fields) frequently bypass strict validation entirely — target these fields first when a target is known to have gateway-level schema enforcement, since they're the schema's own escape hatch.
- **Nested-field validation is inconsistently enforced even when top-level validation is strict**: many gateway schema validators check top-level required fields and types rigorously but validate nested object contents more loosely (or not at all, if the spec itself under-specifies nested schemas) — this is precisely why Section B's level-by-level approach (not just leaf-level fuzzing) matters, since a gateway that blocks a malformed top-level request may pass a malformed nested object through untouched.
- **Parser-disagreement (duplicate key) bypasses remain viable specifically where the gateway's own parser and the backend application's parser are different implementations/languages** — this is a structural condition worth confirming during recon (differing `Server` headers, differing error message formats between what looks like edge vs. origin responses) rather than assumed present by default.
- **Pace and shape of the fuzzing traffic**: Param Miner's automated sweeps and Section C.3's array-size tests both generate distinctive, high-volume traffic; throttle both when testing behind an active WAF, consistent with the pacing guidance repeated throughout this series (Files 02, 04, 05).

---

## PortSwigger lab mapping

| Lab | Difficulty | Maps to |
|---|---|---|
| Finding hidden parameters | Apprentice | Direct precedent for Section D — Param Miner-driven parameter discovery |
| Exploiting a mass assignment vulnerability | Practitioner | Direct precedent for Section D's confirmation step and the broader hidden-writable-field discovery pattern |
| Exploiting server-side parameter pollution in a query string | Practitioner | Direct precedent for the duplicate/conflicting-parameter mechanism in Section B, Step 2, applied to query strings rather than JSON bodies |
| Exploiting server-side parameter pollution in a REST URL | Expert | Extends the same parameter-pollution mechanism into path-segment/URL-structure manipulation — the correct next step after the Practitioner-level query-string lab, and the appropriate top of this file's difficulty progression |

**Honest gap disclosure:** none of PortSwigger's labs specifically target JSON array-injection (Section C) or multi-level nested-object fuzzing (Section B, Step 1) as their core mechanic — the Academy's parameter-pollution labs focus on query-string and URL-path pollution rather than JSON body structure. This is a genuine gap in lab-based practice for the JSON-specific techniques in this file.

### crAPI supplementary practice — fills the JSON-structure gap directly

- crAPI's **shop and community services** accept nested JSON bodies (order objects containing nested address/payment sub-objects) and are a strong hands-on substitute for Sections A and B specifically, since PortSwigger's labs don't cover nested JSON body fuzzing directly.
- crAPI's **coupon/discount endpoints** are commonly used in community writeups to practice array-injection-style testing (Section C) against a realistic multi-item order structure, again filling a gap PortSwigger's lab set doesn't currently address.

---

## What's next

File 07 compresses every technique across all six files into a single sequential checklist and quick-reference cheatsheet you can run against any new REST API target without re-reading the full methodology each time.
