# Injection Testing via gRPC Fields

## 1. How this maps to your existing series

The vulnerability classes here — SQL injection, OS command injection, SSTI — are the same ones covered in depth in your web application injection series. This file doesn't re-explain those vulnerability classes from scratch; it covers what's specific to **delivering them through a decoded gRPC/protobuf field** rather than a JSON body or URL parameter, and what changes about detection once the payload is traveling over a binary transport instead of plaintext.

---

## 2. Why the delivery mechanism matters here

Once a protobuf message is decoded (file 3), a string field is just a string field — from the application's perspective, by the time your payload reaches business logic, a `search_query` field populated via gRPC and a `search_query` JSON key populated via REST are indistinguishable. The vulnerable code path — string concatenation into a SQL query, unsanitized input passed to a shell, unsanitized input rendered into a template — doesn't care what serialization format carried the value in. **What's different is everything upstream of that point**: how you find the field, how you deliver the payload, and how likely it is to be inspected en route.

---

## 3. Finding injectable fields

Use the schema map you already built in file 2 (reflection) or the `.proto` file if you have one. Prioritize string fields that are plausibly used in one of these ways downstream:

- **Fields that look like they build queries or filters** — `search_query`, `filter`, `sort_by`, `order_by` — classic SQLi surface, same as REST/GraphQL.
- **Fields that look like they're passed to system operations** — `filename`, `path`, `export_format`, `report_type`, anything that suggests server-side file handling or shelling out to an external tool (image conversion, PDF generation, archive extraction) — command injection surface.
- **Fields that populate user-facing templated output** — `display_name`, `email_subject`, `notification_template`, anything that ends up rendered back to a user (confirmation emails, generated documents, dashboard widgets) — SSTI surface.

This triage step is identical in spirit to how you'd approach a REST or GraphQL body — the only gRPC-specific addition is that reflection (file 2) gives you the **complete** field list for every message type up front, including fields the client UI never actually populates (file 3, section 7). Test those too — an unused-by-the-UI field that still reaches vulnerable server logic is a common and easily missed finding.

---

## 4. Delivering payloads through the Burp workflow

This directly reuses the edit-and-send loop from file 3, section 5:

1. Capture a legitimate call to the target method, send to Repeater.
2. In the decoded protobuf tab, locate the target string field.
3. Replace its value with your test payload.
4. Send, and inspect both the decoded response body and the `grpc-status`/`grpc-message` trailers (file 1, section 5) — error-based detection on gRPC often shows up in `grpc-message` text rather than in a rendered HTML error page, so read that field carefully, not just the response body.

### 4.1 SQL injection

Standard detection techniques apply directly — the payload just needs to land in the decoded string field instead of a JSON value:

```
' OR '1'='1
'; WAITFOR DELAY '0:0:5'--
' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--
```

Time-based blind detection works exactly as it does over REST — measure response latency after sending a delay payload through the field, same methodology, same caveats about network jitter and needing a clean baseline first. Error-based detection needs one gRPC-specific adjustment: check `grpc-message` for leaked database error text (e.g., a raw driver exception string), since that's frequently where a backend surfaces an unhandled exception when gRPC error handling wraps it, rather than in a response body field.

### 4.2 OS command injection

```
; id
| whoami
$(whoami)
`whoami`
& ping -c 4 127.0.0.1 &
```

Same detection logic as REST/web command injection testing — out-of-band callback techniques (DNS/HTTP interaction via a collaborator-style listener) remain your most reliable confirmation method, since they don't depend on the response channel reflecting anything back to you at all, and work identically regardless of what serialization format delivered the payload.

### 4.3 Server-Side Template Injection (SSTI)

```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
```

Deliver through fields likely to reach templated output (section 3). Confirmation is the same as always — look for the evaluated result (`49`) reflected back somewhere the raw string should have appeared instead, whether that's in the immediate gRPC response, or asynchronously in an email/document/notification generated from the field later. The asynchronous case is worth emphasizing for gRPC specifically: a field delivered via one RPC method (e.g., `UpdateProfile`) may not render until a completely different, later process consumes it (e.g., a scheduled email job) — track where a field's value resurfaces across the whole application, not just in the immediate response to the call that set it.

---

## 5. Field-type-specific considerations

- **Numeric and enum fields validated client-side by the plugin** (file 3, section 6) — schema-mode editors often refuse to let you type a non-numeric string into an `int32` field. If you specifically want to test type confusion (sending injection-style text where a number is expected, to see how the server's deserializer handles a type mismatch), switch to raw/blackbox editing for that field, since strict schema-mode editing works against you here by design.
- **Repeated string fields** — test injection payloads in each position of a repeated field independently, and also test an unusually large number of repeated entries, since some backend implementations concatenate repeated values into a single query or command without the same care given to singular fields.
- **Nested message fields** — don't stop at the top-level message; injectable strings are just as likely two or three levels deep in a nested structure (e.g., `CreateOrderRequest.shipping_address.city`), and it's easy to only test the outermost fields out of habit carried over from flatter REST JSON bodies.

---

## 6. WAF and API Gateway relevance for gRPC injection — detection and bypass

This section exists because injection is exactly the case flagged in file 1, section 9 where WAF/gateway defenses are substantially relevant, and the mechanics differ meaningfully from REST/JSON injection testing.

### 6.1 Why gRPC changes detection

Most WAF and API gateway injection-detection rulesets were built primarily around inspecting **text-based** payloads — JSON bodies, URL parameters, form data — using regex/signature matching against readable strings (`' OR 1=1`, `UNION SELECT`, `; cat /etc/passwd`, etc.). A gRPC request body is binary protobuf wrapped in a 5-byte framing header (file 1, section 7). Your injection payload's actual ASCII/UTF-8 bytes (`' OR '1'='1`) are still present in the length-delimited string field's raw bytes — protobuf doesn't obfuscate string content, it just surrounds it with binary tag/length metadata that a naive text-pattern scanner never accounts for.

This produces two distinct outcomes depending on how sophisticated the inspecting device is:

- A WAF/gateway that does **not** parse protobuf structure and only pattern-matches against the raw body will frequently **miss** injection payloads it would catch instantly in a JSON body — not because the payload is disguised, but because the binary framing bytes surrounding your string break up naive regex matching, and because many rulesets simply aren't applied to `application/grpc*` content types at all, since gRPC traffic is comparatively rare in most WAF vendors' default rule coverage.
- A WAF/gateway that **does** understand gRPC/protobuf (increasingly common on modern API gateway products marketed specifically for gRPC/microservices traffic) can decode the message the same way your Burp plugin does (file 3) and apply the same signature matching it would to JSON — in which case detection parity with REST is restored, and standard evasion techniques (case variation, encoding tricks, comment injection, alternate syntax) are your realistic options, same as they would be against any signature-based WAF.

### 6.2 Practical detection-method checklist

When you encounter a gateway or WAF in front of a gRPC target, establish which category above you're dealing with before you invest time in evasion:

1. Send an obviously loud, unambiguous payload (`' OR '1'='1` or `; id`) through a string field via the Burp workflow (section 4) and observe whether it's blocked (typically visible as a `grpc-status` other than what your baseline returned, sometimes `grpc-status: 3` `INVALID_ARGUMENT` from the gateway itself rather than the backend, or occasionally the connection is reset entirely at the transport level — a different signature from an application-level rejection).
2. If blocked, send the exact same payload through a REST or JSON endpoint on the same target/organization if one exists, to establish whether this WAF vendor's ruleset catches the payload at all when it's in a format the WAF clearly parses. This tells you whether the block came from protobuf-aware inspection or from something else (rate limiting, an unrelated validation rule) triggering coincidentally.
3. If unblocked on gRPC but blocked on REST for the identical logical payload, you've established the gateway is not meaningfully inspecting gRPC payload content — worth reporting as a detection-coverage gap independent of whatever the underlying injection finding turns out to be, since it means the WAF is providing a false sense of coverage for this transport.

### 6.3 Bypass considerations when protobuf-aware inspection is confirmed

If testing under section 6.2 confirms the gateway does inspect decoded gRPC field content, treat it the same as WAF bypass testing on any other transport — standard techniques still apply once your payload's text is genuinely visible to the inspecting device:

- Case and whitespace variation (`Or`, `oR`, extra whitespace/tabs, inline comments in SQL: `/**/OR/**/`)
- Encoding-based smuggling appropriate to the injection class (e.g., alternate SQL function names for filter/keyword-based rules, alternate command substitution syntax for command injection)
- Splitting a payload across multiple message fields if the target concatenates several protobuf fields into one downstream query/command — a gRPC-specific angle worth trying, since a WAF inspecting each field independently may not catch a payload assembled from otherwise-benign-looking fragments spread across two or three separate fields in the same message.

None of this is gRPC-exclusive technique — it's standard WAF bypass methodology applied once you've confirmed (via section 6.2) that inspection is actually happening on this transport, rather than assumed.

---

## 7. Real-world notes

- In practice, the most common outcome when testing injection on a gRPC backend that sits behind a WAF or API gateway is that the gateway simply isn't inspecting the gRPC traffic at all — many organizations deploy their WAF ruleset primarily tuned for their REST/GraphQL surface and either exempt gRPC listeners or never got around to extending coverage to them, precisely because gRPC is newer and less common in most WAF vendors' out-of-box rule libraries. Don't assume protection exists just because you see a gateway/load balancer in front of the target — verify per section 6.2 before concluding either way.
- Because reflection (file 2) exposes internal/admin methods with the same visibility as customer-facing ones, injection testing on those internal methods deserves equal attention — an internal reporting or admin method that builds a raw query from a filter string is just as exploitable as a customer-facing one, and is sometimes even less carefully input-validated on the (often false) assumption that only trusted internal callers can reach it.
- Streaming methods (file 1, section 4; file 4, section 3.4) are easy to overlook during injection testing because the request/response shape looks different from a simple unary call in Burp's history list — make sure your injection sweep covers server-streaming and client-streaming methods, not just unary ones, since the underlying field-level vulnerability logic is identical regardless of call type.
- Track where a field's value is consumed **after** the immediate RPC response, not just within it (section 4.3) — gRPC backends are common in microservices architectures specifically because they pass data between multiple internal services, meaning a single injected field can reach several different downstream consumers, each a separate potential trigger point for the payload to actually execute or render.

---

## 8. Where this series goes next

- **File 6** — full flag-by-flag reference for delivering these payloads via `grpcurl` directly, without Burp, useful for scripting repeatable injection sweeps across many methods.
- **File 7** — consolidated cheatsheet covering payload lists and detection checkpoints from this file alongside the rest of the series.
