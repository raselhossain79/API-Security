# REST API Testing Methodology — Part 6: Parameter Fuzzing Methodology (JSON-Specific)

## Series Position

This file assumes Parts 1–5 are complete. This file covers parameter fuzzing **specifically as it applies to structured JSON API bodies** — nested objects, arrays, and type confusion — which is methodologically distinct from web-form fuzzing (flat key-value pairs) covered elsewhere in the web application vulnerability series. If you have only ever fuzzed traditional web form parameters, treat this entire file as covering new ground, not a variation on familiar technique.

---

## Why JSON Fuzzing Requires a Different Methodology Than Form Fuzzing

Traditional web-form fuzzing operates on a flat structure: `param1=value1&param2=value2`. Every parameter is a string, at the same nesting level, and fuzzing means substituting the value side of one key at a time.

JSON API bodies break this model in three fundamental ways that traditional fuzzing wordlists and traditional Burp Intruder "sniper" positioning don't natively account for:

1. **Nesting** — a field you want to fuzz might be three levels deep inside nested objects (`user.address.postalCode`), and the fuzzing payload has to preserve valid JSON structure around it or the entire request fails to parse before your payload is even evaluated.
2. **Type** — a JSON value isn't just a string; it has an explicit type (string, number, boolean, null, object, array). Fuzzing includes deliberately sending the *wrong type* for a field, which has no equivalent in flat form fuzzing where everything is inherently a string.
3. **Arrays** — a field might expect a single value or an array of values, and testing what happens when you send an array where a single value is expected (or vice versa) is a distinct, JSON-specific technique with no form-fuzzing analogue.

**Real-world framing:** JSON deserialization libraries (Jackson for Java, System.Text.Json/Newtonsoft for .NET, Pydantic for Python, etc.) each have their own default behavior for type coercion, unknown-field handling, and null handling — and these defaults are frequently more permissive than developers assume, because developers test against the shape their own client sends and never see what the underlying library actually tolerates from a client that doesn't play by the documented rules.

---

## Step 1: Type Confusion Fuzzing

For every field identified in your Part 1 spec extraction, systematically substitute a value of the **wrong type** and observe how the server handles it.

### 1.1 — The Type Substitution Matrix

Given a documented field `"age": 25` (expected type: number), test:

```json
{"age": "25"}          // string instead of number
{"age": true}           // boolean instead of number
{"age": null}           // null instead of number
{"age": []}             // empty array instead of number
{"age": {}}             // empty object instead of number
{"age": 25.5}           // float where integer expected
{"age": -1}             // negative where positive expected
{"age": 999999999999999999999}   // integer overflow — exceeds typical language integer bounds
```

**What each specifically tests:**
- **String-for-number** — some languages/frameworks perform automatic type coercion (`"25"` silently becomes `25`), which can be entirely benign, but in weakly-typed comparison contexts downstream (e.g., an `age >= 18` check implemented with a loose comparison operator) can produce logic errors if the coercion doesn't happen consistently across every code path the value touches.
- **Boolean-for-number** — tests whether the deserializer coerces `true`/`false` to `1`/`0` (common in some dynamically-typed backend languages) which can have unexpected downstream effects if that coerced value flows into a calculation or a database column with different constraints than the application layer expects.
- **Null** — tests whether the field is truly optional at the deserialization layer even if documented as required, and whether downstream code has a null-check before using the value (a very common source of `500` errors that leak stack traces, per Part 4 Step 2.2's error-verbosity technique) or, worse, silently proceeds with a null value where business logic assumed a value must be present (e.g., `null` age bypassing an age-gate check entirely because the comparison against `null` evaluates unexpectedly).
- **Empty array/object where scalar expected** — tests deserializer strictness; a permissive deserializer that accepts this without error suggests the underlying type system is very loosely enforced across the board, which should raise your prior for how likely *other* type-confusion techniques in this file are to succeed against the same target.
- **Integer overflow** — tests for the exact same class of bug relevant to any language with fixed-width integer types: does an oversized number wrap, get silently truncated, throw a clean validation error, or throw an unhandled exception? This is worth testing on any numeric field that flows into calculations (pricing, quantities, balances) specifically, since a wraparound on a quantity or balance field has direct business-logic impact (e.g., a negative-wrapped quantity value that, combined with a multiplication elsewhere in the code, produces a negative total price).

### 1.2 — Object-for-String Confusion (a JSON-Specific Deserialization Bug Class)

Given a documented field `"name": "John Doe"` (expected type: string), test:

```json
{"name": {"$ne": null}}
{"name": {"toString": "admin"}}
{"name": ["admin", "user"]}
```

**What this specifically tests:** this is the JSON-body equivalent of a NoSQL injection probe (`{"$ne": null}` is a MongoDB query operator) — if the field value is passed relatively unchanged into a NoSQL query builder rather than being strictly validated as a plain string first, sending an object instead of a string can inject query operators directly. This overlaps with, but is distinct from, the dedicated NoSQL Injection series' methodology — this file's job is confirming *that unexpected object structures survive deserialization into a downstream query* at all, which is the prerequisite condition the full NoSQL injection technique then exploits. If you get anything other than a clean type-validation rejection, escalate to the full NoSQL injection methodology on that specific field.

---

## Step 2: Nested Object Fuzzing

### 2.1 — Adding Undocumented Nested Fields (Mass Assignment via Nesting)

Given a documented body:

```json
{
  "username": "testuser",
  "profile": {
    "bio": "hello"
  }
}
```

Test adding undocumented fields **at every nesting level**, not just the top level:

```json
{
  "username": "testuser",
  "role": "admin",
  "profile": {
    "bio": "hello",
    "verified": true,
    "internalNotes": "test"
  }
}
```

**What this specifically tests:** mass assignment vulnerabilities are usually tested at the top level of a JSON body (adding `"role": "admin"` alongside documented top-level fields), but validation/allowlisting logic is sometimes only applied to the top-level object and not recursively applied to nested objects — a developer might carefully strip disallowed top-level fields before passing the body to an update function, but pass the entire `profile` sub-object through unchecked because "that's just the user's own profile data." Testing undocumented field injection at **every** nesting level, not just the top, is the specific extension this file adds beyond basic mass-assignment testing (full technique covered in the dedicated Mass Assignment series).

### 2.2 — Depth Fuzzing (Excessive Nesting)

```json
{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a": "..." }}}}}}}}}}
```

Programmatically generate nesting far beyond any realistic legitimate use (hundreds or thousands of levels deep).

**What this specifically tests:** many JSON parsers have a default or configurable maximum nesting depth, and exceeding it can cause an unhandled exception (information disclosure per Part 4's error-verbosity technique) or, in parsers without a depth limit at all, a stack-overflow-based denial of service, since recursive-descent parsers naturally consume one stack frame per nesting level. This is a genuine, realistic DoS vector distinct from payload-size-based DoS, and costs very little to test — generate the payload programmatically rather than by hand.

### 2.3 — Null and Missing Intermediate Objects

```json
{"profile": null}                    // entire nested object is null instead of an object
{"profile": {"bio": null}}           // nested field within the object is null
{}                                     // entire nested object omitted
```

**What this specifically tests:** whether code that accesses nested fields does so safely (`profile?.bio` or equivalent null-safe access) or assumes the nested object always exists because "the frontend always sends it" — a very common source of `500` errors on APIs where the backend was only ever exercised through the documented client's request shape, and never through a client that deliberately omits or nulls intermediate structure.

---

## Step 3: Array Injection and Manipulation

### 3.1 — Single-Value-to-Array Substitution

Given a documented field `"email": "test@test.com"` (expected: single string), test:

```json
{"email": ["test@test.com"]}
{"email": ["test@test.com", "attacker@evil.com"]}
{"email": []}
```

**What this specifically tests:** whether a field the application logic treats as singular is actually deserialized permissively into a list-capable type internally. Sending `["test@test.com", "attacker@evil.com"]` on a field like email is specifically valuable on password-reset or notification-related endpoints — if the backend's "send confirmation to `email`" logic iterates over what it assumes is a single value but actually received an array, a confirmation or reset link could be sent to a second, attacker-controlled address alongside the legitimate one, without any error being raised.

### 3.2 — Array-to-Single-Value Substitution

Given a documented field `"tags": ["a", "b", "c"]` (expected: array), test:

```json
{"tags": "a"}
{"tags": {"0": "a", "1": "b"}}
```

**What this specifically tests:** the inverse of 3.1 — whether array-handling code (e.g., a `.map()` or `.forEach()` call) throws an unhandled exception when it unexpectedly receives a non-array, again feeding into error-verbosity/DoS concerns, and whether an object with numeric string keys (`{"0": "a", "1": "b"}`) gets coerced into array-like behavior by a permissive deserializer in ways that bypass array-length validation checks that were written assuming genuine array input.

### 3.3 — Array Index and Sparse Array Testing

```json
{"items": [{"id": 1}, {"id": 2}]}
```

Test:

```json
{"items": []}                                    // empty array where population expected
{"items": [{"id": 1}, null, {"id": 3}]}          // null element within array
{"items": [{"id": 1}, {"id": 1}, {"id": 1}]}     // duplicate entries — does business logic assume uniqueness?
```

**What this specifically tests:** empty-array submission tests for the same "no filter applied = process nothing, or process everything" ambiguity covered under Part 5's parameter differential axis, but specifically for bulk/batch endpoints (e.g., a bulk-delete or bulk-update endpoint that expects a list of target IDs — does an empty array mean "operate on nothing," or does a poorly-written implementation interpret it as "no filter, operate on everything"?). Null elements within an otherwise valid array test per-element null-safety in loop logic. Duplicate entries test whether business logic that should be idempotent (e.g., "add these items to cart") is exploitable via duplication to bypass a quantity limit or trigger unintended side effects if each array element triggers a discrete action (e.g., a discount-code array field applied additively rather than being deduplicated).

### 3.4 — Array-Based Mass Assignment (Bulk Endpoint Specific)

For any endpoint accepting an array of objects for batch creation/update:

```json
{
  "items": [
    {"name": "item1", "price": 10},
    {"name": "item2", "price": 10, "discountOverride": true}
  ]
}
```

**What this specifically tests:** whether allowlist/validation logic applied to a bulk endpoint's schema is applied consistently to **every element** in the array, or only validated against the first element / a shared schema check that doesn't actually iterate per-element in practice. Bulk endpoints are validated less rigorously than single-object endpoints in practice fairly often, because they're typically added later in an API's lifecycle as a convenience feature layered on top of existing single-object logic, and the validation layer doesn't always get equally reworked for the batch case.

---

## Step 4: Building and Running the Fuzzing Set Systematically

### 4.1 — Structuring Payloads for Burp Intruder on Nested JSON

Burp Intruder's payload-position markers (`§...§`) work naturally inside a JSON body — place markers around the specific value you're fuzzing, regardless of nesting depth:

```
{"username":"testuser","profile":{"bio":"§FUZZ§","verified":false}}
```

Payload list: your Step 1 type-confusion matrix values, formatted appropriately (note: for testing structural type confusion — like substituting a string for an entire object — you cannot use a simple value-substitution payload marker positioned *inside* quotes, since the marker approach only works for value-level fuzzing; structural changes to the JSON itself require either multiple pre-built full-body payloads sent as distinct requests, or Intruder's "Extension-generated payloads" using a small script that emits full alternate JSON bodies).

### 4.2 — Why Automated JSON-Aware Fuzzers Are Worth Adding Beyond Burp Intruder

Standard Intruder is value-substitution-oriented and becomes cumbersome for deep structural mutation (Step 1.2's object-for-string swaps, Step 2's depth fuzzing, Step 3's array/scalar swaps) because each of those requires the JSON *structure itself* to change, not just a value within a fixed structure. For structural fuzzing at scale, a purpose-built JSON fuzzing script (even a short one that takes your baselined body, applies a library of structural mutations, and fires each as a discrete request while logging status/body/timing) is more reliable and more thorough than hand-building dozens of Repeater tabs. Reserve manual Repeater work for investigating specific promising results the automated pass surfaces, not for the initial broad sweep.

---

## PortSwigger Web Security Academy Mapping

Correct difficulty-progression order for the concepts most directly exercised in this file:

1. **API testing → "Exploiting a mass assignment vulnerability"** — direct practice of Step 2.1's nested-field-injection technique, though the lab itself demonstrates it at a single nesting level.
2. **NoSQL injection → "Detecting NoSQL injection"** and **"Exploiting NoSQL operator injection to bypass authentication"** — direct practice of Step 1.2's object-for-string operator injection technique, in a full end-to-end exploitation context.

**Honest gap disclosure:** PortSwigger's academy does not have labs specifically modeling deep-nesting type confusion (Step 1), depth-based DoS fuzzing (Step 2.2), or array/scalar substitution (Step 3) as isolated, dedicated scenarios — these techniques are drawn from real deserialization-library behavior across frameworks rather than from a lab designed to teach them individually. **crAPI** is the best available practice target for Step 3's array-manipulation techniques specifically, since it includes several array-accepting endpoints (multi-item vehicle/order data) with realistic validation gaps; for depth-fuzzing DoS practice, a locally-run test API with a known JSON parser (e.g., a small Express or Flask app you configure yourself) is more instructive than any public lab, since the point is observing a *specific parser's* depth-limit behavior, which varies by library and version.

---

## Summary — Parameter Fuzzing Checklist Per Endpoint

- [ ] Type confusion matrix run against every documented field (string/number/boolean/null/array/object substitutions)
- [ ] Object-for-string substitution tested on every string field for downstream query-operator injection
- [ ] Undocumented field injection tested at **every** nesting level, not just top level
- [ ] Excessive nesting depth tested for parser DoS behavior
- [ ] Null/missing intermediate nested objects tested for unsafe null access
- [ ] Single-value-to-array and array-to-single-value substitution tested on every applicable field
- [ ] Empty array and duplicate-entry array submissions tested on bulk/batch endpoints specifically
- [ ] Bulk endpoint per-element validation confirmed consistent (not just first-element-checked)
- [ ] Structural mutations tested via automated script, not exclusively manual Repeater work

Proceed to **Part 7: Methodology Checklist** for the consolidated end-to-end engagement workflow tying all six preceding files together.
