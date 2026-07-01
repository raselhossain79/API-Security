# Burp Suite for API Testing

> Web_Fundamentals_Notes/07 covers Burp basics (Proxy, Repeater, Intruder, Decoder).
> This file covers what's different when using Burp specifically for API testing —
> configuration, extensions, and workflows that don't apply to traditional web app
> testing.

---

## 1. What's Different About API Traffic in Burp

**Traditional web app:** Browser makes requests, Burp intercepts automatically via
the browser proxy configuration.

**API testing:** Traffic often comes from:
- Mobile apps (need to route device traffic through Burp)
- CLI tools (curl, Postman, kiterunner)
- Non-browser clients that may not respect proxy settings

For mobile traffic specifically, you need to:
1. Set Burp to listen on your machine's LAN IP (not just 127.0.0.1)
2. Configure the mobile device to use your machine's IP as proxy
3. Install Burp's CA certificate on the mobile device (Settings → Security →
   Install Certificate) to intercept HTTPS

---

## 2. Handling JSON in Burp Repeater

By default, Burp Repeater shows JSON as a single line. Enable pretty-printing:
- In Repeater, click the `\n` button or use the "Pretty" view toggle to format JSON
  into readable indented structure

When editing JSON in Repeater:
- Make sure JSON stays syntactically valid — a missing `}` or extra `,` will cause
  the server to return a 400 parse error, not the vulnerability response you're looking
  for, and you'll waste time thinking the endpoint is protected
- Use Burp's built-in JSON pretty-printer before sending to catch syntax errors

---

## 3. Key Burp Extensions for API Testing

Install from Extender → BApp Store:

**InQL (GraphQL):**
- Sends introspection queries automatically and maps the entire schema visually
- Generates Repeater tabs for every query and mutation found
- Essential for any GraphQL engagement — manually building introspection queries is slow

**Autorize:**
- Automatically replays every request you make with a lower-privileged token
  (configured by you) and flags responses that look the same — primary tool for BOLA
  and BFLA detection
- Setup: paste a regular user's token into Autorize's config; browse as admin; Autorize
  replays every admin request as the regular user and highlights any that succeed

**JWT Editor:**
- Modifies JWT tokens directly in Burp (decodes, lets you edit claims, re-signs or
  strips signature)
- Essential for JWT attack notes — manually base64-decoding and re-encoding is error-prone

**HTTP Request Smuggler:**
- Scans for CL.TE/TE.CL/TE.TE smuggling vulnerabilities automatically
- Relevant for API endpoints that go through a proxy/load balancer

**Param Miner:**
- Discovers hidden/unkeyed parameters and headers
- Useful for Web Cache Poisoning and finding undocumented API parameters

---

## 4. Configuring Burp for Non-Browser API Clients

When using curl or Postman through Burp:

**curl through Burp:**
```bash
curl -x http://127.0.0.1:8080 https://api.example.com/users/123 \
  -H "Authorization: Bearer eyJ..." \
  --insecure
```
Breaking this down:
- `-x http://127.0.0.1:8080` — route traffic through Burp Proxy on port 8080
- `--insecure` — ignore TLS certificate errors caused by Burp's CA (only use in
  a controlled test environment)

**Postman through Burp:**
- Postman Settings → Proxy → Manual Proxy Configuration → `127.0.0.1:8080`
- Disable "Use System Proxy" in Postman
- This routes all Postman requests through Burp so you can see and modify them

---

## 5. Burp Intruder for API Parameter Fuzzing

Intruder works the same way for APIs as for web forms, but the payload position
is inside the JSON body:

```http
POST /api/users/§123§ HTTP/1.1
Authorization: Bearer eyJ...
Content-Type: application/json

{"action": "view"}
```

The `§123§` marks where Intruder will insert each payload from your list — in this
case, sequential user IDs to test BOLA.

**For JSON body fuzzing:**
```http
POST /api/register HTTP/1.1
Content-Type: application/json

{"username": "test", "email": "test@test.com", "§role§": "§user§"}
```
Cluster bomb mode here tests all combinations of field names and values —
useful for mass assignment discovery.

---

## 6. Burp's WebSocket History Tab

Unlike HTTP requests (which are one-shot), WebSocket messages appear in
Proxy → WebSocket history as an ongoing stream. Each message (sent or received)
is listed separately. Right-click any message to send it to Repeater for
modification and replay.

Continue to → `06_Postman_Basics_for_Pentesters.md`
