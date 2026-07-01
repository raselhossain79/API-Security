# API Types & Structures

> Understanding which API type you're dealing with is the first thing you figure out
> during recon — because REST, GraphQL, SOAP, gRPC, and WebSocket all look different
> in Burp, require different testing approaches, and have different vulnerability
> distributions.

---

## 1. REST (Representational State Transfer)

The most common API type. Uses standard HTTP methods, resources accessed via URLs,
responses usually in JSON.

```
GET    /api/v1/users/123          → retrieve user 123
POST   /api/v1/users              → create a new user
PUT    /api/v1/users/123          → replace user 123 entirely
PATCH  /api/v1/users/123          → partially update user 123
DELETE /api/v1/users/123          → delete user 123
```

**What a typical REST request looks like in Burp:**
```http
GET /api/v1/users/123 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
Content-Type: application/json
Accept: application/json
```

**Key pentest characteristics:**
- Predictable URL structure makes BOLA trivial to test (just change the ID)
- HTTP method abuse is common (DELETE/PUT not tested by devs, left open)
- Versioning (/v1/ vs /v2/) creates improper inventory management opportunities
- Every parameter in the URL, query string, and body is a potential injection point

---

## 2. GraphQL

A single endpoint (`/graphql`) that accepts structured queries. Instead of many URLs,
you send a query describing exactly what data you want.

**What a GraphQL request looks like in Burp:**
```http
POST /graphql HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJ...
Content-Type: application/json

{
  "query": "{ user(id: 123) { username email role } }"
}
```

**Mutation (write operation):**
```http
{
  "query": "mutation { updateUser(id: 123, role: \"admin\") { id role } }"
}
```

**Key pentest characteristics:**
- Single endpoint — you can't map attack surface from URLs alone
- Introspection query (`__schema`) reveals the full schema if enabled
- Batching/aliases allow multiple operations in one request → rate limit bypass
- Authorization must be checked at the resolver level, not just the endpoint —
  BFLA is extremely common because devs often forget to check auth on each resolver
- Field suggestions in error messages leak schema even when introspection is disabled

---

## 3. SOAP (Simple Object Access Protocol)

XML-based, uses WSDL files for service description, typically accessed via POST to a
single endpoint. Common in enterprise/legacy environments.

**What a SOAP request looks like in Burp:**
```http
POST /service HTTP/1.1
Host: api.example.com
Content-Type: text/xml; charset=utf-8
SOAPAction: "getUserDetails"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUserDetails>
      <userId>123</userId>
    </getUserDetails>
  </soap:Body>
</soap:Envelope>
```

**Key pentest characteristics:**
- XML body = XXE injection opportunity
- WSDL file (if exposed) describes all methods/parameters — same as Swagger for REST
- SQLi, command injection via XML parameter values
- WS-Security headers handle authentication — often misconfigured
- Rare in modern public bug bounty but common in enterprise client engagements

---

## 4. gRPC (Google Remote Procedure Call)

Uses Protocol Buffers (protobuf) for serialization — binary format, not human-readable
like JSON. Built on HTTP/2. Common in internal microservices.

**What gRPC traffic looks like:** Binary, not readable as plain text in Burp without
a plugin. You need the `.proto` service definition file to understand the structure.

**Key pentest characteristics:**
- Service reflection (if enabled) exposes all available RPC methods —
  equivalent of introspection for GraphQL or WSDL for SOAP
- Protobuf messages must be decoded to test — Burp needs configuration
- Authorization flaws same as REST (BOLA/BFLA) but harder to spot without tooling
- `grpcurl` is the primary CLI tool for interacting with gRPC services
- Mainly relevant for internal/whitebox engagements — rarely in external bug bounty

---

## 5. WebSocket

Persistent, bidirectional connection. Starts as an HTTP request (the "upgrade
handshake") then switches to a different protocol for the ongoing connection.

**What the WebSocket handshake looks like in Burp:**
```http
GET /ws HTTP/1.1
Host: api.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://example.com
```

**After the handshake:** messages flow both ways as frames, not as HTTP
request-response pairs. Burp shows these in the WebSocket history tab.

**Key pentest characteristics:**
- Origin header on the handshake is the only CSRF-equivalent protection — often missing
- Messages carry JSON payloads — injection possible through WebSocket message content
- Authentication token usually sent in the first message after connection —
  test what happens when it's missing or invalid
- No HTTP method to restrict — authorization must be enforced per-message

---

## 6. Quick Identification Guide (During Recon)

| Signal | Likely API type |
|---|---|
| Multiple URL endpoints with IDs (`/api/users/123`) | REST |
| Single `/graphql` endpoint, JSON with `"query":` key | GraphQL |
| XML body, `SOAPAction` header, `.asmx` or `/service` endpoint | SOAP |
| Binary traffic, HTTP/2, `content-type: application/grpc` | gRPC |
| `Upgrade: websocket` header in initial request | WebSocket |
| `.proto` files or gRPC reflection available | gRPC |
| `/swagger`, `/api-docs`, `/openapi.json` accessible | REST (documented) |

Continue to → `02_JSON_and_Data_Formats.md`
