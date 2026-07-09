# 04 — Data Integrity Issues: Missing Schema and Type Validation

## 1. The mechanism

This sub-risk doesn't require the third party to be malicious at all — it
surfaces from ordinary **unexpected** responses: an error page instead of
JSON, a field that's sometimes a string and sometimes an array, a field
that's missing entirely during an outage, a numeric field returned as a
string due to a vendor-side bug or API version change. The consuming
application never checked that the response actually matches the shape it
assumes, so it fails in ways the developer never designed for.

```
Application assumes: { "price": 19.99, "in_stock": true }
Third party actually returns (bug/outage/compromise/version change):
        { "price": "19.99 USD" }      <- type confusion (string vs number)
        { }                            <- null / missing field dereference
        { "in_stock": null }           <- logic bypass on falsy/undefined handling
        [ ]                            <- array where object expected
```

## 2. Scenario 1: Type confusion in price comparison

**Setup:** An e-commerce app calls a pricing/promotions API to check if a
discount applies, comparing the returned price against a threshold.

**Step by step:**

1. Expected response: `{"price": 45.00}`. App logic:
   `if (response.price < 50) { applyFreeShipping(); }`
2. Due to a vendor-side bug (or an attacker who controls a compromised
   upstream feeding this pricing service), the response becomes:
   `{"price": "45.00 USD"}` — a string, not a number.
3. In a loosely-typed language, `"45.00 USD" < 50` may evaluate
   unpredictably (type coercion rules vary — in JavaScript this comparison
   coerces the string to `NaN`, and any comparison with `NaN` is `false`;
   in other cases coercion could go the other way). The point is not the
   exact coercion outcome — it's that **the developer never decided what
   should happen here**, so the actual behavior is whatever the language's
   coercion rules happen to produce, which is rarely the intended business
   logic.
4. **Why this is unsafe:** no explicit type check (`typeof response.price
   === "number"`) or schema validation exists before the value is used in a
   business-logic comparison. The vulnerability isn't the coercion rule
   itself — it's the total absence of a guard before trusting the type.

## 3. Scenario 2: Null dereference causing denial of service

**Setup:** An app calls a third-party address-validation API and
immediately accesses a nested field on the response.

**Step by step:**

1. Expected: `{"validated_address": {"street": "...", "geo": {"lat": 23.8, "lng": 90.4}}}`
2. Third party, during a partial outage or for an unresolvable address,
   returns: `{"validated_address": null}`.
3. App code: `const lat = response.validated_address.geo.lat;` throws an
   unhandled exception (null/undefined property access) because
   `validated_address` is `null`, not an object.
4. **Why this is unsafe:** if this endpoint isn't wrapped in adequate
   error handling, a single third-party outage or a single crafted response
   (if the attacker can influence when the address API returns null — e.g.
   by submitting an address string designed to be unresolvable) becomes a
   denial-of-service vector against your own checkout flow. At scale, an
   attacker who can trigger this condition reliably and cheaply can hit it
   repeatedly to degrade availability.

## 4. Scenario 3: Fail-open logic bypass — the highest-impact real pattern in this category

**Setup:** A fraud-detection or KYC (identity verification) third-party API
returns a verdict field the app uses to gate a sensitive action.

**Step by step:**

1. Expected: `{"is_fraud": true}` or `{"is_fraud": false}`.
2. App code:
   ```
   response = call_fraud_api(transaction)
   if response.is_fraud == true:
       block_transaction()
   else:
       allow_transaction()
   ```
3. Now consider any of: the third party times out, returns a malformed
   response, returns `{"is_fraud": null}`, returns an HTTP 500 with an HTML
   error page instead of JSON, or the field is renamed in a vendor API
   version bump nobody updated the integration for.
4. In every one of those cases, `response.is_fraud == true` evaluates to
   `false` (missing field, parse failure defaulting to an empty/None object,
   null not strictly equal to true) — and the code takes the `else` branch:
   **it allows the transaction.**
5. **Why this is unsafe:** the control flow defaults to the *permissive*
   outcome whenever the third party doesn't behave exactly as expected. This
   is a **fail-open** design, and it is exploitable actively: if an attacker
   can cause the fraud API call to fail or time out on demand (e.g., by
   sending an unusually large/malformed request that the fraud API itself
   mishandles, or simply by racing/flooding to induce timeouts), they can
   reliably force the "allowed" branch for their own fraudulent transaction.
   The correct default for any security-relevant gate is **fail-closed**:
   any non-explicit-safe response should result in blocking, not allowing.

## 5. Scenario 4: Prototype pollution via unchecked object merge

**Setup:** An app merges a third-party API's configuration response
directly into an internal settings object using a generic deep-merge
utility, without validating keys.

**Step by step:**

1. Expected: `{"theme": "dark", "locale": "en"}`.
2. Malicious/compromised response includes a polluting key:
   `{"theme": "dark", "__proto__": {"isAdmin": true}}`.
3. A naive recursive merge implementation (common in hand-rolled "merge
   config" helpers, and historically in some versions of popular merge/
   deep-extend libraries) walks into `__proto__` and writes `isAdmin: true`
   onto `Object.prototype`, affecting every object in the running process
   that doesn't already define its own `isAdmin` property — potentially
   including access-control checks elsewhere in the application that
   naively check `user.isAdmin`.
4. **Why this is unsafe:** this is the exact mechanism covered in depth in
   the Prototype Pollution series — the only thing specific to API10 here
   is that the source of the polluting object is a third-party API response
   rather than a JSON request body. Cross-reference that series for full
   gadget-chain exploitation detail; the takeaway for this series is that
   **any unchecked recursive merge of a third-party response into an
   internal object is a candidate for this class of bug**, not just merges
   of user-submitted request bodies.

## 6. WAF / API Gateway relevance

Same conclusion as file 02, and for the same reason: the unsafe processing
happens locally, after the response has already been received on a
connection your backend initiated — there's no inbound request for a WAF to
inspect. The narrow exception noted in file 02 (a gateway-level response
schema validator on an internal service mesh) applies here too, and would
actually be somewhat more effective against this specific sub-risk than
against injection, since **type confusion is exactly what schema validation
is designed to catch** (a strict JSON Schema with `"type": "number"` on the
`price` field would reject the string variant outright). If your
organization already runs a service mesh or gateway with response-schema
enforcement on internal/third-party calls, that is a genuinely strong and
appropriate mitigation for this sub-risk specifically — worth calling out as
a positive finding in a grey-box/white-box assessment where present.

## 7. Real-world note

The fail-open pattern in Scenario 3 is, in practical experience across many
real applications, the single most consequential instance of this entire
API10 category — more so than injection or SSRF in terms of direct business
impact, because it targets security *decisions* (fraud checks, KYC/identity
verification, entitlement/licensing checks, content moderation APIs) rather
than just data plumbing. When reviewing or testing any integration with a
third-party "decision" API (anything returning an allow/deny, verified/
unverified, or safe/unsafe verdict), always specifically test: what does the
application do if that API times out, returns malformed data, or is
unreachable? That single question uncovers a disproportionate share of
real, high-severity API10 findings.

Continue to `05-testing-methodology.md`.
