# JSON & Data Formats

> Every API test involves reading and manipulating data in some format — JSON for
> REST/GraphQL, XML for SOAP, Protobuf for gRPC. You need to be fast and confident
> with JSON specifically since it's in almost every modern API.

---

## 1. JSON (JavaScript Object Notation)

The default data format for REST and GraphQL APIs. Burp Repeater shows it directly.

### Basic Structure

```json
{
  "id": 123,
  "username": "rasel",
  "email": "rasel@example.com",
  "role": "user",
  "active": true,
  "score": 9.5,
  "address": null
}
```

**Data types, broken down:**
- `"id": 123` — number (no quotes around the value)
- `"username": "rasel"` — string (quotes around the value)
- `"active": true` — boolean (true/false, no quotes)
- `"score": 9.5` — float
- `"address": null` — null (absence of value)

### Nested Objects

```json
{
  "user": {
    "id": 123,
    "profile": {
      "name": "Rasel",
      "avatar": "http://example.com/img.png"
    }
  }
}
```

**Pentest relevance:** SSRF can live inside nested URL fields like `"avatar"`.
Mass assignment exploits work by adding extra keys at any nesting level.

### Arrays

```json
{
  "users": [
    {"id": 1, "username": "admin"},
    {"id": 2, "username": "rasel"}
  ],
  "tags": ["pentest", "api", "bug-bounty"]
}
```

**Pentest relevance:** Array-based injection — some APIs process array values
differently than single values, enabling bypass of input validation.

### Why JSON Structure Matters for Pentesting

```json
POST /api/register
{
  "username": "rasel",
  "email": "rasel@example.com",
  "password": "test123"
}
```

If you add an extra field:
```json
{
  "username": "rasel",
  "email": "rasel@example.com",
  "password": "test123",
  "role": "admin",
  "isAdmin": true,
  "balance": 99999
}
```

If the API binds all incoming JSON fields to a model without whitelisting,
those extra fields get written to the database — this is **Mass Assignment (BOPLA)**.
Understanding JSON structure is why you can spot this opportunity.

---

## 2. XML (Used in SOAP APIs and XXE)

XML is structured with tags, like HTML but for data:

```xml
<?xml version="1.0" encoding="utf-8"?>
<user>
  <id>123</id>
  <username>rasel</username>
  <email>rasel@example.com</email>
</user>
```

**External Entity definition (the XXE payload mechanism):**
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <username>&xxe;</username>
</user>
```

Breaking this down:
- `<!DOCTYPE foo [...]>` — defines a document type with custom entities
- `<!ENTITY xxe SYSTEM "file:///etc/passwd">` — defines an entity named `xxe` whose
  value is the contents of `/etc/passwd`, fetched from the filesystem
- `&xxe;` — the entity reference; the XML parser replaces this with the file contents
- The username field then contains the file contents, which gets returned in the response

---

## 3. Protocol Buffers (Protobuf — Used in gRPC)

Binary format — not human-readable. You need the `.proto` schema file to understand
what fields exist:

```proto
// Example .proto file
message User {
  int32 id = 1;
  string username = 2;
  string email = 3;
  string role = 4;
}
```

In Burp, gRPC protobuf traffic looks like garbled binary without a plugin.
With the Burp gRPC plugin, it decodes to readable field=value format.

**Pentest relevance:** Once decoded, protobuf fields are injection points just like
JSON fields — the delivery mechanism is different but SQLi, command injection, and
BOLA testing work the same way on the decoded values.

---

## 4. Content-Type Switching — A Key API Testing Technique

Many APIs accept multiple content types but only sanitize input for one of them:

```http
# Normal request
POST /api/user/update
Content-Type: application/json
{"username": "rasel<script>alert(1)</script>"}

# Switch to XML — might bypass JSON-specific sanitization
POST /api/user/update
Content-Type: application/xml
<username>rasel<script>alert(1)</script></username>

# Switch to plain text — might cause parsing errors revealing internals
POST /api/user/update
Content-Type: text/plain
username=rasel'--
```

This single technique (content-type switching) is one of the most productive things
to try early in any API engagement — many APIs have sanitization only on the
content-type they primarily use.

Continue to → `03_API_Authentication_Overview.md`
