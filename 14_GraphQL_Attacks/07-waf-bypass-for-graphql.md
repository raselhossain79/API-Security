# WAF Bypass for GraphQL

File 7 of 9. This file consolidates the WAF/API-gateway detection-and-bypass
sections scattered through files 2–6 into a single dedicated reference, plus
covers two additional cross-cutting evasion techniques — query obfuscation
and alias obfuscation — that apply across multiple attack categories rather
than to any one specific vulnerability class.

**Scope note:** this file is a consolidated reference, not a duplicate of
files 2–6. Each earlier file's WAF section is specific to that file's
vulnerability class and should still be read in context. This file exists
so you have one place to look when planning WAF evasion for an engagement,
without hunting through six files.

---

## 1. How GraphQL-aware WAFs and gateways actually detect attacks

Before evasion, understand the detection layers you're up against. They
generally operate at one or more of these levels, in roughly increasing
order of sophistication:

1. **Generic HTTP/body inspection** — the WAF doesn't understand GraphQL at
   all; it applies the same signature rules it would to any POST body
   (SQLi patterns, XSS patterns, known malicious strings). Weakest layer,
   easiest to evade, but still commonly the *only* layer in front of many
   GraphQL endpoints, since GraphQL-specific WAF tooling is a smaller,
   newer market than generic WAF products.
2. **String/substring matching on GraphQL-specific keywords** — rules
   keyed on literal strings like `__schema`, `__type`, known introspection
   fragment names, or known attack-tool user-agents/payload signatures.
3. **Query parsing and AST-level analysis** — the gateway actually parses
   the GraphQL query into its abstract syntax tree and can therefore count
   real nesting depth, real number of aliased fields, and apply
   complexity/cost scoring based on the true structure rather than
   surface-level text patterns. This is the most robust layer and the
   hardest to evade with syntactic tricks, because it reasons about the
   query the same way the GraphQL server itself does.
4. **Behavioral/anomaly detection** — flags requests based on
   response-time outliers, unusual field-access patterns, or aggregate
   request volume/shape across a session, rather than any single request in
   isolation.

**The practical implication:** evasion techniques that work great against
layer 1–2 (string obfuscation, whitespace tricks) do essentially nothing
against layer 3, because a real parser normalizes away exactly the
surface-level variation those tricks rely on. Always try to determine which
layer you're actually facing (send an obviously-malicious payload and an
equivalent semantically-identical-but-differently-formatted payload and
compare behavior) before investing time in syntactic evasion that a proper
parser will see straight through.

---

## 2. Consolidated detection-and-bypass reference by attack category

| Category | Typical detection | Bypass angle | Detail |
|---|---|---|---|
| Introspection | Substring match on `__schema`/`__type`; known fragment names (`FullType`, `InputValue`, `TypeRef`) | Whitespace insertion around `__schema`; alternate transport (GET/form-encoded); rename fragments; split into smaller queries; field-suggestion leakage avoids these meta-fields entirely | File 2, §6–8 |
| Batching/aliasing | Alias-count / total-field-count limits; query-cost scoring | Split alias set across more/smaller requests; vary alias naming and field order; mix in decoy aliased fields | File 3, §7 |
| Depth/complexity | Static depth counting on parsed AST; gateway-level cost scoring; response-time anomaly detection | Fragment-based payload compression; large pagination args to raise real cost while staying under depth-only thresholds; distribute cost across several "reasonable" requests | File 4, §6 |
| Authorization (BOLA/BFLA) | **Not meaningfully addressable by a WAF** — requires business context the gateway doesn't have | N/A — except genuine declarative field/mutation-level authorization policy at the gateway, which is a real access-control mechanism, not a WAF signature | File 5, §6 |
| Injection (SQL/NoSQL/OS command) | Payload signature matching on `query`/`variables`; JSON-structure/type-mismatch anomaly detection for NoSQL | Split payload across query string vs. variables inconsistently; class-appropriate payload obfuscation (same as REST); nest payload inside input-object fields to dodge shallow JSON inspection | File 6, §6 |

---

## 3. Query obfuscation techniques (cross-cutting)

These apply across almost any attack category above, wherever the detection
layer is string/substring-based (layers 1–2 in section 1) rather than a
true parser (layer 3).

### 3a. Whitespace and insignificant-token insertion

GraphQL's lexer treats spaces, tabs, newlines, and commas as insignificant
between tokens. A signature keyed on an exact contiguous substring like
`__schema{queryType` breaks the moment any of these are inserted at a token
boundary, while the query remains 100% valid to a real GraphQL parser:

```graphql
query{
__schema
,
{
queryType{name}
}
}
```

This is the same mechanism as file 2's whitespace-insertion introspection
bypass, generalized: it works anywhere a detection rule is matching literal
adjacent-character sequences rather than parsing tokens.

### 3b. Field/argument reordering

Where a signature is tuned to a specific, commonly-copy-pasted payload
shape (e.g. the canonical introspection query from file 2, or a known
public brute-force-alias script), reordering fields or arguments produces a
semantically identical but textually different request:

```graphql
mutation {
  login(password: "123456", username: "carlos") { success token }
}
```
vs.
```graphql
mutation {
  login(username: "carlos", password: "123456") { token success }
}
```

Both execute identically. If detection is keyed on the exact published
payload text from a common tool or writeup (more common than it should be,
since defenders sometimes build rules directly from public PoCs), this
alone is enough to evade it.

### 3c. Case and naming variation on user-controlled identifiers

Aliases, operation names, and fragment names are entirely
attacker-chosen strings with no semantic meaning to the server — rename
them freely (`guess0001` → `x1a`, `IntrospectionQuery` → `Q1`) to defeat any
rule matching on these specific literal names, which several real-world
signatures do since they're copied from well-known public tooling/queries
rather than derived from the underlying attack mechanism.

---

## 4. Fragment abuse as an evasion technique (beyond depth compression)

File 4 covered fragments for payload *compression* in depth attacks.
Fragments also function as general-purpose obfuscation across other
categories, because they let you **relocate the sensitive part of a query
away from the top-level structure a shallow rule might be scanning**:

```graphql
query {
  user(id: 4) {
    ...Sensitive
  }
}

fragment Sensitive on User {
  email
  billingAddress
}
```

A rule scanning only the top-level selection set text for sensitive field
names (`email`, `billingAddress`) directly adjacent to a suspicious
argument (`id: 4`) may miss them entirely when they're declared in a
separately-named fragment referenced only via `...Sensitive`, particularly
if the rule doesn't fully resolve fragment spreads before matching — a
meaningfully more sophisticated (and more expensive) piece of parsing than
matching the literal selection set.

---

## 5. Alias obfuscation as its own technique

Beyond the rate-limit-bypass use in file 3, aliasing is independently
useful as a **detection-evasion primitive** in its own right, because it
lets you rename any field reference to something innocuous while the
underlying operation is unchanged:

```graphql
query {
  totallyNormalLookingField: user(id: 4) {
    x1: email
    x2: billingAddress
  }
}
```

If a detection rule is naively matching on real field names in the request
text (e.g. flagging any request that mentions both `user` and
`billingAddress` in close proximity as a probable BOLA probe), the response
still comes back correctly keyed and readable to you (`x1`, `x2` in the
JSON response), but the request itself no longer contains the literal
strings the rule was watching for in that configuration — the field names
`email` and `billingAddress` still appear once, as the actual field being
selected, but not paired with an alias/label that makes the intent to
extract them look obviously sensitive to a shallow text scan. This is a
narrower, more situational bypass than sections 3–4 and works only against
comparatively unsophisticated pattern matching, but it costs nothing to try
alongside other evasion, and it composes directly with the alias-based
batching technique from file 3 — the same aliases doing rate-limit-bypass
duty there can simultaneously serve this obfuscation purpose.

---

## 6. Practical testing workflow for this file

1. **Fingerprint the defense layer first** (section 1) before choosing
   evasion techniques — send a baseline malicious payload and a
   syntactically-varied equivalent, compare outcomes.
2. **Start with the cheapest techniques**: whitespace insertion,
   reordering, renaming attacker-controlled identifiers (sections 3, 5) —
   these cost nothing and defeat a surprising amount of real-world
   detection, since much GraphQL WAF tooling is still comparatively
   immature relative to REST-focused WAF products.
3. **Escalate to fragment-based restructuring** (section 4, and file 4 for
   the depth-specific variant) if simple textual variation doesn't work —
   this targets shallow-parsing defenses specifically.
4. **If AST-level/complexity-scoring defenses are confirmed present**
   (layer 3/4 in section 1), recognize that syntactic evasion alone likely
   won't succeed — pivot toward the distribution/splitting strategies noted
   in each category's row in section 2's table (spreading cost or payload
   volume across multiple individually-unremarkable requests) rather than
   continuing to vary the shape of a single request.
5. **Always retest the underlying vulnerability without any WAF-evasion
   layer first**, directly against the origin if you have any way to reach
   it (e.g. via a staging environment, or if the WAF is confirmed
   bypassable and you just want to confirm root-cause impact) — this keeps
   your report's core finding (the actual vulnerability) cleanly separated
   from the secondary finding (the WAF is bypassable), since these are two
   distinct, individually valuable things to report.

---

## 7. Summary checklist for this file

- [ ] Determine which detection layer (section 1) the target is actually
      running before selecting evasion techniques.
- [ ] Apply whitespace/token, reordering, and identifier-renaming
      obfuscation as first-pass, low-cost attempts.
- [ ] Use fragment restructuring to relocate sensitive selections away from
      shallow top-level text scanning.
- [ ] Use aliasing both for its file-3 rate-limit purpose and as an
      independent naming-obfuscation layer.
- [ ] Recognize when a defense is AST/complexity-based and pivot to
      distribution/splitting strategies instead of continued syntactic
      variation.
- [ ] Report WAF-bypass findings separately from the underlying
      vulnerability finding.

**Next: file 8 — Tooling (InQL + graphql-cop)**, covering full setup and
flag-by-flag usage of the two dedicated GraphQL security tools referenced
throughout this series.
