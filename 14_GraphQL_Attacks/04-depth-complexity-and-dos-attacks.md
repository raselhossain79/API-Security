# Depth, Complexity, and DoS Attacks

File 4 of 9. Assumes file 1 (resolvers, fragments) and file 3 (the "one
request, many resolver calls" theme, applied there via aliasing/batching).
This file covers the other major way that same mismatch gets abused:
**nesting depth and query complexity**, rather than operation count.

---

## 1. The mechanism: nested selections map to nested resolver calls

Recall from file 1, section 10: a resolver runs once per field, per object
instance in the result. This is trivial to picture for a flat query, but
becomes important once fields return lists of objects that themselves have
list fields.

Take a schema like:

```graphql
type Product {
  id: ID!
  name: String!
  reviews: [Review!]!
}

type Review {
  id: ID!
  body: String!
  author: User!
}

type User {
  id: ID!
  name: String!
  reviews: [Review!]!
}
```

Notice `User.reviews` returns `[Review!]!`, and `Review.author` returns a
`User`. This creates a **cycle** in the type graph: `Product → Review →
User → Review → User → ...` indefinitely. Nothing in the type system
prevents you from writing a query that walks this cycle as many times as
you like:

```graphql
query {
  products {
    reviews {
      author {
        reviews {
          author {
            reviews {
              author {
                name
              }
            }
          }
        }
      }
    }
  }
}
```

Each level of nesting here is not a cosmetic increase in JSON size — it is
a **multiplicative increase in resolver executions**. If each product has
20 reviews, and each review's author has 20 more reviews, the resolver call
count roughly multiplies by 20 at every additional level of `reviews →
author → reviews`. Six levels deep, as above, on data with a fan-out of
even 10 per level is already on the order of a million resolver
invocations from a single, syntactically modest-looking query — and each of
those resolver invocations is plausibly a separate database query, unless
the server has batching/caching (e.g. DataLoader) specifically implemented
to prevent this. **This is the entire mechanism behind GraphQL nested-query
DoS: small request, exponential backend cost.**

---

## 2. Why this is GraphQL-specific and doesn't exist the same way in REST

A REST API's endpoint-per-resource design means the server, not the client,
decides how much to fan out in a single response — `/products/3/reviews`
returns reviews, and if you want each review's author you make separate
requests. The fan-out is bounded by however many round-trips the client is
willing to make, and each of those round-trips individually hits the
existing per-request rate limiting and monitoring.

GraphQL deliberately removes that friction — that's the entire value
proposition of the technology (fewer round-trips, client-specified shape).
The cost of removing that friction is that nothing structurally stops a
client from asking the server to do, in one request, the resolver-execution
equivalent of a very large number of REST calls chained together. Depth
attacks and the alias/batching attacks in file 3 are two different ways of
exploiting the same underlying tradeoff — file 3 multiplies width
(operation count), this file multiplies depth (nesting), and in practice
attackers combine both when possible for maximum effect.

---

## 3. Building a depth-attack payload manually

You rarely need the schema to have an actual authorial cycle like the
example above — even a straightforwardly nested, non-cyclic structure can
be nested arbitrarily if the type system allows it and no server-side depth
limit exists. The general recipe:

1. From the introspected schema (file 2), find any field that returns an
   object type which itself has a field returning back to a type reachable
   from the original — directly cyclic (`Review.author.reviews`) or
   indirectly (`Category.subcategories: [Category]`, a self-referential
   type, is an even simpler and extremely common real-world case, since
   category/comment/organizational-hierarchy trees are almost always
   modeled this way).
2. Nest the query as deep as the server allows, requesting a real leaf
   scalar field (like `name` or `id`) at the bottom so the query is valid
   syntax and the server can't shortcut evaluation.
3. Send and observe response time and server resource behavior. Start
   moderate (10–15 levels) and increase; you're looking for a
   disproportionate jump in response time relative to nesting depth
   increase, which confirms the multiplicative-cost mechanism rather than
   linear cost.

Self-referential example, using a comment tree:

```graphql
query {
  post(id: 1) {
    comments {
      replies {
        replies {
          replies {
            replies {
              replies {
                replies {
                  replies {
                    body
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

Breakdown: `comments` returns a list; each item's `replies` field returns
another list of the same shape, so each additional `replies` level
multiplies total node count by however many replies exist per comment at
that level. If replies average even 5 per comment, 8 levels deep is already
`5^8` ≈ 390,000 leaf-node resolver calls from one request that is not
visually alarming on the wire.

### Using fragments to compress deep payloads (and evade naive detection)

Instead of writing out every nesting level inline, a self-referencing
fragment produces the same effective depth far more compactly and can dodge
detection tuned to spot long, obviously-nested brace structures:

```graphql
query {
  post(id: 1) {
    comments {
      ...ReplyChain
    }
  }
}

fragment ReplyChain on Comment {
  body
  replies {
    ...ReplyChain
  }
}
```

Most servers will actually reject a truly self-referencing fragment at
parse/validation time (GraphQL disallows fragment cycles specifically to
prevent unbounded expansion — this is one defense the spec itself provides,
see section 5). But **chained, non-cyclic fragments repeated many times**
still meaningfully shrinks payload size for a fixed depth versus writing
every brace by hand, and is worth knowing for the WAF-evasion angle covered
in file 7, where request size/shape is part of what gets fingerprinted.

---

## 4. Complexity attacks: width without depth

Depth isn't the only lever. **Complexity** (sometimes called "query cost")
attacks achieve the same resource-exhaustion goal through breadth at a
single or shallow level, rather than deep nesting:

```graphql
query {
  a: products(first: 1000) { id reviews { id } }
  b: products(first: 1000) { id reviews { id } }
  c: products(first: 1000) { id reviews { id } }
  ... (many more aliased, large-pagination calls)
}
```

This is deliberately similar to file 3's alias technique, but the goal here
is raw resolver-execution volume/data volume rather than defeating a rate
limiter specifically — requesting very large page sizes (`first: 1000`)
combined with nested sub-selections, repeated via aliasing, multiplies cost
along both the width and depth axes simultaneously. In practice, real-world
DoS-oriented testing almost always combines some depth with some width,
since defenses (section 5) frequently only cap one dimension.

---

## 5. Server-side defenses you should test the target against

Before assuming an application is vulnerable, actively test whether these
common mitigations are present — your report should state which specific
defenses are missing, not just "no depth limiting":

- **Maximum query depth.** A hard ceiling (e.g. reject anything over 10–15
  levels) enforced during query validation, before execution begins. Test
  by sending payloads of increasing depth and finding the exact rejection
  threshold, or confirming there isn't one.
- **Query complexity/cost analysis.** Assigns a numeric cost per field
  (often configurable, sometimes multiplied by requested list size via
  pagination arguments) and rejects documents whose total exceeds a budget
  — this is the more robust defense since it accounts for width and depth
  together, and for pagination arguments that depth-limiting alone would
  miss (a query 3 levels deep requesting `first: 10000` at each level has
  low depth but enormous actual cost).
- **Fragment cycle detection.** Spec-mandated in compliant GraphQL server
  implementations — a directly self-referencing fragment (as attempted in
  section 3) should be rejected at validation time regardless of other
  defenses. If a target *doesn't* reject this, that's itself a notable
  finding, since it means even the baseline spec-level protection is
  missing or misconfigured.
- **Timeouts.** A blunt but real backstop — if the resolver execution takes
  too long, the server aborts. Useful to note in a report as a mitigating
  factor even if depth/complexity limits are absent, since it caps
  worst-case impact even though it doesn't prevent resource waste up to
  that timeout.
- **Aliased-field / total-field count limits.** Overlaps directly with file
  3's defenses — some gateways cap total field count per document
  regardless of whether that count comes from depth or width.

Absence of the first two in particular is the actual vulnerability worth
reporting; "the server took 40 seconds to respond to a deeply nested query"
is the symptom, "no depth or complexity limiting exists" is the root cause
your report should name explicitly.

---

## 6. WAF / API gateway relevance for this specific vulnerability

Detection methods commonly seen:

- **Static depth counting** on the parsed query AST before execution — the
  gateway counts brace nesting depth independent of the backend GraphQL
  server's own limits, giving a defense layer even if the application code
  itself has none.
- **Cost-scoring at the gateway layer**, mirroring the complexity-analysis
  defense in section 5 but implemented in infrastructure rather than
  application code — common in managed API gateway products marketed
  specifically for GraphQL.
- **Response-time/resource-usage anomaly detection** — flags requests whose
  execution time or backend resource consumption is a statistical outlier
  relative to the endpoint's baseline, catching depth/complexity attacks
  indirectly via their effect rather than by parsing the query shape.

Realistic evasion angles:
- **Fragment-based compression** (section 3) to keep the literal request
  small and reduce the chance of tripping size- or shape-based heuristics,
  while still producing high actual execution cost — this specifically
  targets gateways that fingerprint request *shape* rather than fully
  resolving fragment expansion before scoring cost.
- **Staying just under a known or discovered depth/complexity threshold**
  while relying on **large pagination arguments** at each level to still
  achieve high real cost — this targets defenses that implement depth
  limiting but not true complexity/cost scoring (section 5's distinction
  between the two matters directly here).
- **Distributing cost across several separate, individually
  "reasonable-looking" requests** sent in quick succession rather than one
  outlier request, if the defense is purely per-request cost scoring rather
  than aggregate/session-level.

A consolidated treatment of GraphQL WAF evasion across every technique in
this series is file 7.

---

## 7. Summary checklist for this file

- [ ] Identify self-referential or cyclic type relationships from the
      introspected schema.
- [ ] Test increasing nesting depth incrementally; find the actual
      rejection threshold (if any) rather than assuming one exists.
- [ ] Test large pagination arguments combined with moderate nesting to
      probe for complexity-scoring vs. depth-only limiting.
- [ ] Confirm whether fragment-cycle detection is enforced (spec baseline).
- [ ] Distinguish, in your findings, "no depth limit" from "no complexity
      scoring" from "no timeout" — these are three separate, individually
      reportable gaps, not one finding.
- [ ] Measure and record actual response-time/resource impact as evidence,
      not just that a large query was accepted.

**Next: file 5 — Authorization Testing in GraphQL (BOLA/BFLA on
resolvers)**, where the same "resolver, not schema, is the access-control
boundary" idea from file 1 becomes the primary attack methodology.
