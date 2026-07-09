# 02 — Injection via Third-Party API Responses

## 1. The mechanism

This is structurally identical to classic injection (SQLi, SSTI, command
injection — see those series for baseline theory). The only thing that
changes is the **source of the tainted data**: instead of a form field or
URL parameter, the payload arrives inside a field of a JSON/XML response
from a service your backend called.

Generic flow:

```
Attacker compromises/controls third-party response
        |
        v
Third party returns: { "city": "Dhaka'; DROP TABLE users;--" }
        |
        v
Your backend: query = "SELECT * FROM cities WHERE name = '" + response.city + "'"
        |
        v
Query executes with injected SQL — because the string was concatenated,
not parameterized, the database has no way to know "city" was attacker data.
```

The database, template engine, or shell has no concept of "this string came
from a trusted vendor." It only sees a string. If that string is built into
an executable context unsafely, it is exploited exactly the same way as if
a user had typed it into a form.

## 2. Scenario 1: SQL Injection via a geolocation/IP-lookup API

**Setup:** Your application looks up the visitor's IP address against a
third-party geolocation API to log analytics data, keyed by city name.

**Step by step:**

1. Your backend calls `GET https://geo-provider.example/lookup?ip=1.2.3.4`.
2. The third-party API responds:
   ```json
   { "ip": "1.2.3.4", "city": "Dhaka' OR '1'='1", "country": "BD" }
   ```
3. Your backend builds the query:
   ```sql
   SELECT * FROM analytics_cities WHERE city_name = 'Dhaka' OR '1'='1'
   ```
4. **Why this is unsafe:** the developer never expected `city` to be
   attacker-influenced because it "comes from our geolocation vendor, not
   from the user." That assumption is the entire vulnerability. Two realistic
   paths for the attacker to actually control this field:
   - The geolocation vendor itself is compromised (supply chain).
   - The vendor's data is sourced from crowdsourced or user-submittable data
     (many "city name" and "ISP name" geolocation fields are registered by
     ISPs or updated via public submission forms) — an attacker registers a
     malicious string as their own ISP/network name, then makes a request
     from that IP, and the field flows straight through the geolocation
     provider back into your query.
5. **The fix** is unchanged from any other SQLi case: parameterized queries /
   prepared statements. The field being "from a vendor" changes nothing about
   the required defense.

## 3. Scenario 2: Server-Side Template Injection (SSTI) via a webhook payload

**Setup:** A payment provider sends a webhook on successful payment. Your
application renders a confirmation email using a template engine, inserting
the customer name field from the webhook payload.

**Step by step:**

1. Payment provider (or an attacker who has compromised the merchant account
   / spoofed the webhook — see the Webhook Security series for signature
   verification bypass) sends:
   ```json
   { "event": "payment.succeeded", "customer_name": "{{7*7}}", "amount": 4200 }
   ```
2. Your backend renders:
   ```
   template.render("Hello " + payload.customer_name + ", your payment succeeded!")
   ```
   using a template engine (Jinja2, Twig, FreeMarker, etc.) that evaluates
   `{{ }}` expressions in the string it's given.
3. Output: `Hello 49, your payment succeeded!` — confirming template
   evaluation occurred, i.e., SSTI. A production payload here would move to
   RCE gadget chains (see the SSTI series for engine-specific RCE payloads).
4. **Why this is unsafe:** the developer trusted `customer_name` because it
   arrived via an authenticated webhook from a known payment provider. The
   authentication of the *channel* (webhook signature, TLS, source IP) says
   nothing about the safety of the *content* of an individual field, which in
   most payment integrations is still ultimately attacker-influenced — the
   customer name is data the buyer typed into a checkout form on the
   payment provider's hosted page.

## 4. Scenario 3: OS command injection via a file-scanning API

**Setup:** Your application uploads user files to a third-party
malware-scanning API. On a "clean" verdict, it moves the file using the
filename the scanning API echoes back in its response (some scanning APIs
normalize/return the filename alongside the verdict).

**Step by step:**

1. Third-party scanner responds:
   ```json
   { "verdict": "clean", "filename": "report.pdf; rm -rf /data/*" }
   ```
2. Your backend runs:
   ```
   os.system("mv /tmp/upload " + response.filename)
   ```
3. **Why this is unsafe:** two compounding mistakes: (a) building a shell
   command via string concatenation at all — always use an argument-array
   API (e.g., `subprocess.run([...])` without `shell=True`) instead of a
   shell string; (b) trusting a filename field from a response as if it were
   already sanitized, simply because it passed through a security-branded
   third-party service. "Security product" does not mean "output-safe for
   your specific downstream use."

## 5. Scenario 4: Log injection / log forging

**Setup:** Your backend logs third-party API responses for debugging,
writing raw field values into a log file consumed by a web-based log viewer.

**Step by step:**

1. Third party returns a field containing embedded newlines and a fake log
   line: `"status": "ok\n[ADMIN] User escalated to superuser"`.
2. Your backend writes: `logger.info("Third-party status: " + response.status)`
3. The forged line appears indistinguishable from a real log entry to anyone
   reviewing logs, enabling log forging. If the log viewer renders log
   content as HTML without escaping, an embedded `<script>` payload in the
   same field becomes stored XSS against whoever views the logs (typically
   an internal admin — high-value target).
4. **Why this is unsafe:** logging is treated as a "safe sink" by most
   developers, so response data going into logs gets none of the
   sanitization that goes into, say, a database write. It is not a safe sink.

## 6. WAF / API Gateway relevance for this specific sub-risk

As covered in file 01: **largely not applicable.** The injection payload
travels on the outbound connection your backend initiates to the third
party, and the exploitation happens purely in your backend's local
processing of the response body — there is no attacker-originated request
for an inbound WAF to inspect.

The one narrow exception: if your API Gateway or service mesh has a
**response-validation plugin** that enforces a strict JSON Schema on
responses from specific upstreams (some gateways, e.g. Kong, Apigee, and
some service meshes, support this for internal service-to-service calls),
malformed or unexpectedly-typed/patterned fields could be rejected before
reaching your application code. This is uncommon in practice for outbound
third-party integrations specifically (it's more commonly used for internal
microservice contracts), and even where present, a **realistic bypass** is
straightforward: craft the payload to satisfy the schema's type and length
constraints exactly (e.g., a `string` field with no format/regex constraint
happily accepts `'; DROP TABLE users;--` since it's still a syntactically
valid string) — schema validation checks *shape*, not *content safety*.

## 7. Real-world note

The most damaging real-world pattern in this category is not a single
compromised vendor call — it's a **shared library or SDK wrapping a
third-party API** that is used across many services in an organization. If
that shared wrapper doesn't sanitize/parameterize on the way out, every
service using it inherits the vulnerability simultaneously, turning one
weak integration point into an organization-wide injection vector. When
reviewing code for this category (see file 05, white-box approach), always
check for these shared "API client" wrapper modules first — fixing the
wrapper once fixes every caller.

Continue to `03-ssrf-via-third-party-response.md`.
