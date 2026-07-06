# WAF Bypass for API Injection (JSON-Context Techniques)

This file consolidates the WAF/Gateway detection-and-bypass discussion referenced across
files 2–5. Rather than repeating full technique breakdowns per vulnerability class, this
file explains the underlying mechanism once and cross-references which vulnerability
files it applies to.

## Why JSON Bodies Get Inspected Differently Than Form-Encoded Bodies

### How a Generic WAF Typically Inspects Form-Encoded / Query-String Data

Most legacy WAF rule sets were written when the dominant traffic pattern was:

```
username=admin&password=' OR '1'='1
```

The WAF's inspection pipeline for this format is comparatively simple: URL-decode the
body, split on `&` and `=`, and run signature regexes against each decoded value. This is
a well-understood, decades-old inspection pattern (mod_security core rule set and similar
products were built around exactly this).

### How JSON Body Inspection Differs

A JSON body requires the WAF to:

1. Parse the JSON structure itself (which can fail or be interpreted inconsistently if
   the JSON is malformed, deeply nested, or uses unusual-but-valid syntax).
2. Walk the resulting object tree to find string/number leaf values.
3. Apply the same signature regexes against each leaf value — but now those leaf values
   may contain **JSON-escaped characters** (`\u0027`, `\"`, `\\`) that need to be
   *decoded* before signature matching will catch anything, similar to how URL-decoding
   is required for the form-encoded case.

**The bypass opportunity exists specifically where step 3's decoding is incomplete,
skipped, or inconsistent with how the actual backend application parses the same JSON.**
Not every WAF product has this gap — modern, API-aware WAFs (built specifically for JSON/
REST/GraphQL traffic) generally do proper JSON-aware normalization. The gap is most
commonly found in:

- Generic/legacy WAF products retrofitted to "also handle JSON" rather than built
  JSON-native from the start.
- WAFs configured with form-encoded rule sets left enabled by default while JSON-specific
  rules were bolted on separately, creating inconsistent coverage between the two rule
  paths.
- API Gateways where the gateway's own schema validation checks *declared* fields only,
  while a WAF sitting behind or beside it inspects the raw body with generic signatures
  that may not normalize JSON escaping the same way the backend's JSON parser does.

## Technique 1: Unicode Escaping in JSON Strings

JSON strings support `\u00XX` Unicode escape sequences for any character, including
ordinary ASCII characters that don't strictly need escaping. A payload like:

```json
{"username": "admin' OR '1'='1"}
```

can be rewritten, character by character, as:

```json
{"username": "admin\u0027 OR \u00271\u0027=\u00271"}
```

Breakdown:

- `\u0027` is the Unicode escape for the single-quote character (`'`, code point
  `U+0027`). To any component that reads this as a raw text string looking for a literal
  `'` character via simple string-matching signatures (rather than first decoding
  `\u00XX` sequences into their actual characters), the payload does not contain the
  substring `'` at all — it contains the substring `\u0027`, which won't match a
  signature written to detect `'`.
- The actual backend application's JSON parser, however, **always** decodes `\u0027` into
  a literal `'` character as a normal, required part of correct JSON parsing — this isn't
  an edge case or malformed input, it's fully valid JSON that every compliant JSON parser
  handles identically. This is exactly why the gap exists: the backend *must* decode it
  correctly to function at all, while the WAF's signature engine *may or may not* decode
  it before pattern-matching, depending on implementation.
- This technique can be applied to any character in the payload, not just quotes — SQL
  keywords like `OR`, `UNION`, `SELECT` can be partially or fully Unicode-escaped
  character-by-character if the WAF's keyword-matching doesn't normalize first. Applies
  directly to the SQLi file (file 2) and, for shell metacharacters, the command injection
  file (file 4) and SSTI delimiter characters (file 5, Part A).

## Technique 2: Nested JSON to Bypass Keyword Detection

Some WAF products apply signature scanning only to a limited nesting depth, or apply
different rule strictness at different depths (a common performance/config trade-off,
since fully recursive deep-tree scanning is more expensive). A payload placed at an
unusually deep nesting level:

```json
{
  "data": {
    "meta": {
      "context": {
        "filter": {
          "value": "admin' OR '1'='1"
        }
      }
    }
  }
}
```

Breakdown:

- The actual injectable field (`value`) is buried five levels deep. If the backend
  application code specifically extracts and uses `data.meta.context.filter.value` (i.e.
  this nesting reflects genuine application logic, not just an arbitrary wrapper you
  invented), then the backend will process this exactly as if it were a top-level field.
- If the WAF's JSON-inspection logic has a configured or hard-coded depth limit (common
  in some products for performance reasons) shallower than 5 levels, the payload at this
  depth is never evaluated against the signature rules at all — it's structurally
  invisible to the WAF while remaining fully functional to the backend.
- **Important caveat**: this technique only works where the application genuinely
  supports/expects nested input at that depth — you can't arbitrarily nest a payload
  inside a wrapper the backend doesn't parse; the nesting has to correspond to real
  application structure (a nested filter object, a metadata wrapper, etc.), which means
  this technique requires first understanding the target's actual JSON schema (via
  legitimate requests, API documentation, or client-side JS/mobile-app reverse
  engineering) rather than being universally applicable to every endpoint.
- Applies to all vulnerability classes in this series wherever the target application's
  own schema has genuine nesting depth to exploit — most naturally relevant to SQLi
  (file 2) and NoSQLi (file 3), where nested "filter" or "query" objects are common
  legitimate API patterns.

## Technique 3: Content-Type Switching to Evade JSON-Specific WAF Rules

Covered in depth in file 5 (XXE section) as both an application-layer technique (reaching
an XML parser) and a WAF-layer technique. Restated here as the general principle: if a
WAF or Gateway's inspection ruleset is **configured per Content-Type** (a common
performance optimization — no point running JSON-specific normalization logic against a
body declared as something else), then submitting a body in a format the WAF doesn't
apply its strictest ruleset to — while the backend still happens to accept and parse that
format — creates a coverage gap. Concretely:

- A WAF might apply thorough JSON-aware SQLi/NoSQLi signature matching to
  `Content-Type: application/json` requests, but apply only generic/no inspection to
  `Content-Type: application/xml` or `multipart/form-data` requests to the same endpoint,
  if the endpoint happens to accept multiple content types (common in frameworks with
  automatic content negotiation).
- Testing whether an endpoint accepts an alternate Content-Type at all (as shown in the
  XXE file's Step 1) is therefore a bypass-reconnaissance step in its own right, useful
  even for vulnerability classes other than XXE — e.g. discovering that a login endpoint
  also accepts `application/x-www-form-urlencoded` in addition to its documented JSON
  format could let you deliver a SQLi payload through the less-scrutinized form-encoded
  path even though the "primary" JSON path is properly protected.

## Technique 4: Malformed-but-Tolerated JSON (Parser Discrepancy)

A more advanced and less universally applicable technique: some backend JSON parsers
(particularly permissive/lenient ones, or those built on frameworks with non-standard
parsing extensions) tolerate JSON that isn't strictly valid per spec — trailing commas,
single-quoted keys, unquoted keys, duplicate keys (using the last occurrence). If the WAF
uses a **strict** JSON parser that rejects or mis-parses this input (potentially failing
"closed" and blocking it, or "open" and skipping inspection because it couldn't parse the
body as JSON at all), while the backend's lenient parser still processes it correctly, a
parser-discrepancy gap opens up. Example — duplicate keys:

```json
{"role": "user", "role": "admin"}
```

Breakdown:

- Strict JSON spec doesn't define behavior for duplicate keys, and different parsers
  handle this differently — some take the first occurrence, some take the last, some
  error out entirely.
- If the WAF's parser inspects (and matches signatures against) the **first** `role`
  value (`"user"` — benign, passes inspection) while the backend's parser uses the
  **last** `role` value (`"admin"` — the actual value used in application logic), a
  payload hidden in the second occurrence would never be seen by the WAF's inspection
  logic at all.
- This technique requires knowing (or testing for) the specific parser discrepancy
  between the WAF and backend, which is more engagement-specific and harder to predict
  than techniques 1–3 — treat it as a technique to test for, not one to assume will work
  universally.

## Summary Table: Technique Applicability by Vulnerability Class

| Technique | SQLi (file 2) | NoSQLi (file 3) | Cmd Injection (file 4) | SSTI (file 5A) | XXE (file 5B) |
|---|---|---|---|---|---|
| Unicode escaping | Yes | Limited* | Yes | Yes | N/A (XML entity encoding used instead) |
| Nested JSON depth | Yes | Yes (very natural fit) | Limited* | Limited* | N/A |
| Content-Type switching | Sometimes | Sometimes | Sometimes | Sometimes | Primary technique |
| Parser discrepancy (malformed JSON) | Yes | Yes | Yes | Yes | N/A (different discrepancy class: XML parser quirks, covered in web-app XXE series) |

\* *Limited: NoSQLi payloads are structural (JSON operators as keys, e.g. `$ne`), so
Unicode-escaping individual characters inside an operator name like `$ne` is unusual and
may break MongoDB's own operator parsing rather than just evading the WAF — test
carefully rather than assuming it transfers cleanly. Command injection and SSTI payloads
are typically too short/structurally simple to benefit much from deep-nesting bypass
specifically, though it doesn't hurt to test.*

## Detection Methods: How WAFs/Gateways Typically Identify This Attack Pattern (Baseline, Pre-Bypass)

For completeness — before applying any bypass, understand what's typically being
detected in the first place:

- **Signature/regex matching** against decoded string values for known keywords (`UNION`,
  `SELECT`, `$where`, shell metacharacters, template delimiters).
- **Schema/type validation** at the API Gateway layer — rejecting requests where a field
  declared as `string` in the OpenAPI/Swagger spec receives a JSON object instead (this
  is actually one of the more effective baseline defenses against NoSQLi operator
  injection specifically, since `{"$ne": null}` is trivially rejected by a gateway
  enforcing "this field must be a string" — the bypass techniques above don't help
  against a hard type-schema rejection, since the issue isn't detection evasion but a
  fundamental type mismatch the gateway catches structurally).
- **Rate-based/behavioral detection** — flagging unusual request volume or timing
  patterns (relevant to the blind/time-based techniques in files 2 and 4 specifically;
  many rapid sequential requests with varying payloads is itself a detectable pattern
  independent of payload content).
- **Anomaly scoring** (e.g. mod_security-style cumulative scoring) rather than single-rule
  blocking — meaning a payload that individually evades several rules via the techniques
  above might still get blocked if enough partial-match signals accumulate past a
  threshold; combining multiple bypass techniques simultaneously (e.g. Unicode-escaping
  plus nesting) increases evasion likelihood but isn't guaranteed against anomaly-scoring
  WAFs.

## Real-World Note

In practice, the most reliable initial signal for whether a target's WAF/Gateway has a
JSON-normalization gap is simply **comparing response behavior between an equivalent
payload sent form-encoded vs sent as JSON** against the same underlying parameter (where
the endpoint happens to accept both) — a payload blocked in one format but successful in
the other is direct proof of an inspection-path inconsistency, and is far faster to
establish empirically than reasoning about the WAF vendor's internal architecture from
documentation alone, which is rarely detailed enough to predict this behavior in advance.
