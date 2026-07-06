# SSTI and XXE via API Endpoints

Combined file per delivery-context focus: SSTI and XXE are mechanically unrelated
vulnerability classes, but both are grouped here because their API-specific delivery
story is short and similar in structure — refer to your web-app SSTI and XXE series
respectively for full engine/parser-specific exploitation mechanics.

---

## Part A: SSTI via API

### Template Expression Injection Through API String Parameters

SSTI vulnerabilities arise when user input is passed into a server-side template engine
(Jinja2, Twig, FreeMarker, Handlebars, etc.) and rendered rather than treated as inert
data. In an API context, the injectable parameter is, again, a JSON string value —
structurally identical to the SQLi delivery pattern in file 2, but the payload syntax is
template-engine expression syntax instead of SQL.

Example vulnerable JSON body (a "generate personalized message" API feature):

```json
{
  "templateName": "welcome_email",
  "userDisplayName": "Alice"
}
```

If `userDisplayName` is inserted into a Jinja2 template string and rendered server-side,
test payload:

```json
{
  "templateName": "welcome_email",
  "userDisplayName": "{{7*7}}"
}
```

Breakdown:

- `{{7*7}}` — Jinja2 expression-delimiter syntax. `{{` and `}}` tell the Jinja2 engine
  "evaluate what's between these as a template expression," not literal text.
- `7*7` — a simple arithmetic expression used purely as a detection probe. If the
  rendered output (wherever it's returned — in the API response body, or in an email
  actually sent by the "welcome_email" feature) contains `49` instead of the literal
  string `{{7*7}}`, that confirms the input is being evaluated by the template engine,
  not just inserted as plain text — the core SSTI confirmation step.
- **Why JSON delivery matters here**: no JSON-escaping is required for `{{7*7}}` itself
  since curly braces and asterisks are valid unescaped characters in a JSON string. The
  delivery-specific consideration is instead about **where the rendered output surfaces**
  — API SSTI often renders into a side effect (an email, a generated PDF, a downstream
  webhook payload) rather than directly into the synchronous HTTP response, meaning
  detection sometimes requires checking a secondary output channel rather than the
  immediate API response, similar in spirit to the async-job-queue consideration
  discussed in the command injection file.

### Escalation Payload Example (Jinja2 → RCE)

Once basic evaluation is confirmed with `{{7*7}}`, escalation follows the same engine-
specific RCE chains covered in your web-app SSTI series (e.g. Jinja2's
`{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`
pattern). The only API-specific addition: if the confirmed injection point is deeply
nested in the JSON body (e.g. `user.preferences.greetingTemplate`), make sure your
escalation payload — which is often long and contains many special characters — is still
valid as a JSON string value. Long Jinja2/Python-chain payloads can contain double-quotes
internally (e.g. within the `popen('id')` call, depending on quote choice); consistently
use single quotes inside the payload itself so you don't need to escape anything when
embedding it in the JSON double-quoted string.

### WAF/Gateway Note for SSTI via API

Relevant, though less commonly targeted by generic WAF signatures than SQLi. Template
delimiter syntax (`{{`, `${`, `<%`) is somewhat distinctive and some WAFs do include
generic template-injection signatures, but JSON-nesting and Unicode-escaping the
delimiter characters (covered in file 6) can still evade poorly-normalized rule sets in
the same way described for the other vulnerability classes.

### PortSwigger Lab Mapping (Adapted for API Context)

- **Practitioner**: "Server-side template injection with information disclosure via
  documentation" — convert the vulnerable form parameter to a JSON body field to practice
  the delivery-context conversion; the detection-via-error-message logic transfers
  directly.
- **Practitioner**: "Server-side template injection in an unknown language with a
  documented exploit" — same conversion approach; useful for practicing engine
  fingerprinting when you only control a JSON string value rather than a full request.
- **Expert**: "Server-side template injection with information disclosure via
  user-supplied objects" — the most relevant Expert lab; the "user-supplied object"
  concept in this lab maps conceptually well onto nested JSON object parameters
  specifically, since both scenarios involve the application passing a structured,
  attacker-influenced object into template context rather than a flat string.
- **Expert**: "Server-side template injection in a sandboxed environment" (and the
  sandbox-escape variants) — useful for the RCE-escalation stage described above; delivery
  conversion to JSON is a minor step once the sandbox-escape chain itself is understood
  from your web-app series.

---

## Part B: XXE via API

### Switching Content-Type to XML on Endpoints That Accept It

Most modern APIs are JSON-first, but many still retain **XML support** for legacy
compatibility, SOAP-based internal integrations, or specific endpoints (file upload,
report generation, EDI/B2B integrations) that were built or documented before the
JSON-first convention took hold. XXE testing against an API is fundamentally a
**Content-Type discovery and switching exercise** before it's an XML-parsing exercise.

### Step 1: Confirm the Endpoint Accepts XML At All

Take a normal JSON request:

```http
POST /api/v1/reports/generate HTTP/1.1
Content-Type: application/json

{"reportType": "summary", "format": "pdf"}
```

Convert to XML with equivalent structure and swap the header:

```http
POST /api/v1/reports/generate HTTP/1.1
Content-Type: application/xml

<request>
  <reportType>summary</reportType>
  <format>pdf</format>
</request>
```

Breakdown:

- `Content-Type: application/xml` — this header change is the entire technique at this
  stage. Many API frameworks (especially those built on older Java/.NET stacks, or using
  content-negotiation middleware) will auto-detect the body format based on this header
  and route the request to an XML deserializer instead of the JSON one, **even if the
  API's public documentation only describes JSON usage** — undocumented format support is
  extremely common because the underlying framework supports both by default and no one
  explicitly disabled XML.
- If the response is a normal 200 (not a 415 Unsupported Media Type or 400), that's
  confirmation the endpoint parses XML — proceed to XXE payload testing. If you get a 415,
  try common alternate values before concluding XML isn't supported at all:
  `Content-Type: text/xml`, `application/soap+xml` (if the API has any SOAP heritage), and
  check whether the endpoint has a separate URL path variant (e.g. `/api/v1/reports/xml/generate`)
  documented in older API versions or found via directory/endpoint discovery.

### Step 2: XXE Payload Once XML Is Confirmed Accepted

```xml
<?xml version="1.0"?>
<!DOCTYPE request [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<request>
  <reportType>&xxe;</reportType>
  <format>pdf</format>
</request>
```

Breakdown (delivery-context framing; full XXE entity mechanics are in your web-app XXE
series):

- `<!DOCTYPE request [...]>` — declares a Document Type Definition inline, which is where
  the external entity is defined. This must be present for the entity declaration to be
  valid XML.
- `<!ENTITY xxe SYSTEM "file:///etc/passwd">` — declares an external general entity named
  `xxe` that resolves to the contents of a local file on the server.
- `&xxe;` — the entity reference, placed inside a field the API actually processes and
  likely reflects back in some form (here, `reportType`, assuming the generated report
  echoes the report type somewhere in its output) — the file contents get substituted in
  at parse time, and if that value flows into the generated PDF/report output, you have a
  read primitive.
- **API-specific consideration**: whether the file contents are ever visible to you
  depends heavily on whether the field you're injecting into is reflected in a
  retrievable output (the generated report, an error message, a webhook payload) — the
  same "check secondary output channels" principle from the SSTI section applies. If
  nothing is reflected anywhere, pivot to blind XXE via OOB (out-of-band entity
  resolution to a domain you control), same OOB principle used in the command injection
  file.

### WAF/Gateway Note for XXE via API

Highly relevant, and worth emphasizing specifically: **many API Gateways and WAFs apply
inspection rules keyed to `Content-Type`** — a JSON-specific WAF ruleset may simply not
run its inspection logic at all against a request whose `Content-Type` claims
`application/xml`, if the ruleset wasn't configured to also cover XML bodies. This means
Content-Type switching isn't just a technique for reaching an XML parser at the
application layer — it can also be a WAF/Gateway-layer bypass in its own right, if the
gateway's inspection rules are JSON-scoped rather than universally applied to all body
types. This overlap between "reaching the vulnerable code path" and "evading inspection"
is unique to XXE in this series and is called out explicitly in
`06-waf-bypass-api-injection.md` as well.

### PortSwigger Lab Mapping (Adapted for API Context)

- **Apprentice**: "Exploiting XXE using external entities to retrieve files" — direct
  conversion practice: take the lab's vulnerable XML-consuming form and practice the
  Content-Type-switching discovery step described above against a JSON-first API mindset
  (i.e., practice as if you didn't know upfront that XML was accepted).
- **Apprentice**: "Exploiting XXE to perform SSRF attacks" — the SSRF-via-external-entity
  technique transfers directly; useful for practicing against internal API endpoints
  specifically, since SSRF-via-XXE against an API gateway's internal network is a
  realistic escalation path in microservice environments.
- **Practitioner**: "Blind XXE with out-of-band interaction" and "Blind XXE with
  out-of-band interaction via XML parameter entities" — both map directly to the "pivot
  to OOB when nothing is reflected" consideration above.
- **Practitioner**: "Exploiting blind XXE to exfiltrate data using a malicious external
  DTD" — directly applicable once OOB is confirmed; practice hosting the malicious DTD
  externally and referencing it from the API-delivered XML body.
- **Expert**: "Exploiting XInclude to retrieve files" — relevant specifically for API
  endpoints where you don't control the full outer XML document (e.g. your input is
  embedded inside a larger SOAP envelope or wrapper you don't control) — XInclude lets
  you inject a file-read primitive without needing to define your own DOCTYPE, since the
  DOCTYPE-based approach in the first payload above requires control over the document's
  top-level structure.

## Real-World Note

Content-Type-based XXE discovery against nominally "JSON-only" APIs is one of the more
consistently underestimated findings in bug bounty programs — testers frequently skip XML
testing entirely against APIs whose documentation only shows JSON examples, when in
practice the underlying framework (Spring, Jackson/JAX-RS-based Java stacks especially)
often accepts both by default unless explicitly restricted, making the Content-Type
switch step a high-value, low-effort check worth including in every API assessment
regardless of what the documentation claims.
