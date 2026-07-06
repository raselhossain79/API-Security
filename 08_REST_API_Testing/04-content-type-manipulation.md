# REST API Testing Methodology — 04: Content-Type Manipulation

## Mechanism: why switching content-type changes behavior

An API endpoint's business logic (validation rules, injection defenses, output encoding) is frequently written **once**, against the content-type the developer assumed would always be used — usually `application/json`. The parsing/deserialization layer that converts the raw request body into an internal object, however, is often a shared, generic library capable of handling several content-types (JSON, XML, form-encoded, plain text) with **different underlying parsing code paths per type**.

This produces a specific, exploitable mismatch: **security controls applied at the JSON-parsing layer do not automatically apply to the XML-parsing layer**, even though both ultimately populate the same internal object that reaches the same business logic. PortSwigger states this directly: an API "may be secure when handling JSON data but susceptible to injection attacks when dealing with XML." The content-type header is, in effect, a routing signal that can select an entirely different, less-hardened code path through the same endpoint.

## Step-by-step, piece by piece

**Step 1 — Establish which content-types the endpoint claims to accept.**

Check your File 01 spec extraction for `requestBody.content` — this lists documented content-types. Also send an intentionally malformed request and read the error:

```
POST /api/orders HTTP/1.1
Content-Type: application/json

not valid json
```

What this tests: the error response often names the expected format explicitly (`"Expected valid JSON"`) or, more usefully, sometimes reveals a parser library name/version in a stack trace — direct fingerprinting information for choosing which XML/deserialization vulnerabilities are even plausible against this stack (cross-reference your XXE and insecure-deserialization series here).

**Step 2 — Send the exact same logical request across every plausible content-type, one header change at a time.**

Baseline (JSON — matches documented behavior):
```
POST /api/orders HTTP/1.1
Content-Type: application/json

{"item_id": 42, "quantity": 1}
```

Switch 1 — XML, same logical data:
```
POST /api/orders HTTP/1.1
Content-Type: application/xml

<order><item_id>42</item_id><quantity>1</quantity></order>
```

What this specifically tests: whether the server even accepts an undocumented content-type at all. A `415 Unsupported Media Type` means the endpoint explicitly enforces an allowlist — a `200`/`201`, or any response other than `415`, means the parser silently accepted a format nobody documented, and you should now assume there is a second, likely less-scrutinized code path handling this request.

Switch 2 — plain text:
```
POST /api/orders HTTP/1.1
Content-Type: text/plain

{"item_id": 42, "quantity": 1}
```

What this specifically tests: some frameworks skip strict content-type-based parser selection entirely and instead attempt to auto-detect/parse the body regardless of the declared `Content-Type` — meaning a JSON payload sent with a `text/plain` header can sometimes bypass content-type-based input validation or WAF rules that only inspect requests explicitly declared as JSON/XML, while the parser underneath still happily deserializes it as JSON.

Switch 3 — form-urlencoded:
```
POST /api/orders HTTP/1.1
Content-Type: application/x-www-form-urlencoded

item_id=42&quantity=1
```

What this specifically tests: whether a REST-style JSON endpoint also has legacy form-encoded parsing wired up (common in frameworks that enable multiple body parsers globally by default) — this occasionally exposes a much older code path with weaker validation than the JSON-specific handler that was more recently hardened.

**Step 3 — Once you find an accepted alternate content-type, actively probe it for injection differences, not just acceptance.**

If XML is accepted, this is your signal to pivot into full XXE testing (your dedicated XXE series covers exploitation depth — this step is specifically about *discovering* that the pivot point exists):

```
POST /api/orders HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE order [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<order><item_id>&xxe;</item_id><quantity>1</quantity></order>
```

What this tests: whether the XML parser wired up for this endpoint resolves external entities — a check that is entirely irrelevant to the JSON code path and would never surface if you only tested the documented content-type.

**Step 4 — Use the Content Type Converter BApp to automate the JSON⇄XML translation at scale**, once you've manually validated the mechanism on a couple of endpoints. Feed it your full endpoint inventory from File 01 rather than manually rewriting every request body by hand.

**Step 5 — Compare error verbosity across content-types, not just success/failure.**

Even where an alternate content-type is ultimately rejected, compare *how* it's rejected against your File 01 baseline error format. A generic JSON validation error might be a clean, generic `400`, while an XML parsing failure on the same endpoint might leak a full stack trace including internal class names or file paths — itself an information-disclosure finding, and useful fingerprinting for further attacks.

## Injection opportunities via content-type switching, consolidated

| Alternate content-type accepted | What it opens up |
|---|---|
| `application/xml` | XXE (external entity injection, SSRF via entity resolution, potential blind data exfiltration) — full exploitation covered in your XXE series |
| `text/plain` parsed as JSON anyway | Bypass of content-type-scoped WAF/validation rules that only inspect declared JSON/XML requests |
| `application/x-www-form-urlencoded` on a JSON endpoint | Access to a legacy/secondary parsing code path, sometimes with weaker type coercion (e.g., array/object injection via bracket notation `item[]=1&item[]=2` reaching a handler that expects a scalar) |
| Nested content-type inside a multipart body (`multipart/form-data` with an embedded JSON part) | Some frameworks apply different validation to the outer multipart wrapper vs. the inner JSON part — worth testing on any endpoint that also accepts file uploads alongside structured data |

## WAF / API Gateway relevance — dedicated section

### How WAFs/gateways typically detect this attack pattern

- **Content-Type allowlisting at the gateway edge**: security-aware API gateways reject requests whose `Content-Type` doesn't match the documented spec for that operation, before the request ever reaches application code — this is precisely the mitigation PortSwigger recommends ("validate that the content type is expected for each request or response").
- **Payload inspection tuned per declared content-type**: many WAFs select which inspection rules to apply (JSON-injection signatures vs. XML-entity signatures vs. generic signatures) based on the declared `Content-Type` header. This is exactly the assumption Switch 2 above exploits — a payload sent under a content-type the WAF doesn't associate with structured-data attacks may receive weaker or no inspection, even if the application parses it as structured data anyway.
- **XML-specific entity-expansion and DOCTYPE detection**: WAFs with XML awareness commonly flag `<!DOCTYPE` and `<!ENTITY` declarations outright as a known XXE signature — a blanket block on these tokens is a common, relatively blunt detection rule.

### Realistic bypass considerations

- **Mismatched declared vs. actual content-type** (Switch 2/3 above) is the primary, most broadly applicable bypass: if the WAF's inspection ruleset is selected by the `Content-Type` header rather than by sniffing the actual body structure, declaring a content-type the WAF treats as "safe" while sending a body the application will still parse as structured data routes around content-type-scoped inspection entirely.
- **For XML/XXE specifically**, where a naive WAF rule blocks the literal string `<!DOCTYPE`, parameter entities and external DTD references can sometimes achieve the same effect through indirection (referencing an external DTD file that itself contains the entity declaration, rather than declaring it inline) — this is a well-documented XXE-WAF-bypass pattern; full exploitation mechanics belong in your dedicated XXE series, but the discovery step (does this endpoint even parse XML) belongs here.
- **Case and whitespace variation in the `Content-Type` header value itself** (`Application/JSON`, extra parameters like `application/json; charset=utf-8; boundary=x`) occasionally bypasses a naive exact-string content-type allowlist at the gateway while still being accepted by a more lenient application-layer parser — low-probability but essentially free to test alongside Step 2.
- **Rate/volume of content-type-switching attempts**: sending every content-type variant against every endpoint in rapid succession is itself an unusual traffic pattern; pace this testing (as with method sweeps in File 02) if the target has visible rate-limiting or bot-detection responses during earlier baseline testing.

---

## PortSwigger lab mapping

**Honest gap disclosure:** PortSwigger's API testing topic does not include a lab built specifically and solely around content-type switching as the core mechanic — the concept is taught in the topic's written material (see the "Identifying supported content types" section referenced in your Overview file) but isn't the central mechanic of a dedicated Practitioner/Expert lab. The relevant labs teach adjacent, transferable skills:

| Lab | Difficulty | Transferable skill |
|---|---|---|
| Exploiting an API endpoint using documentation | Apprentice | Practicing the discipline of testing an endpoint's actual accepted request format against what's documented, directly transferable to content-type discovery |
| Finding and exploiting an unused API endpoint | Practitioner | Reinforces the general "test what's plausible, not just what's documented" mindset this file applies specifically to content-type |

Your dedicated **XXE series** and **insecure deserialization series** are the correct place to look for labs covering the *exploitation depth* once an alternate content-type is confirmed accepted — this file's PortSwigger coverage is intentionally limited to the discovery mechanic, not exploitation, and cross-referencing those series here avoids duplicating lab mappings you've already documented elsewhere.

### crAPI supplementary practice

- crAPI's endpoints are predominantly JSON, but several accept multipart uploads alongside JSON metadata fields — useful for practicing the nested-content-type check described in the consolidated table above, which has no direct PortSwigger lab equivalent at all.

---

## What's next

File 05 builds directly on the content-type, method, and version variations covered so far — turning each of those into one half of a systematic differential comparison to surface authorization and information-leakage differences.
