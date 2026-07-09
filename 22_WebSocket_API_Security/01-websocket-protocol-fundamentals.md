# WebSocket Protocol Fundamentals for Pentesters

## Purpose of This File

Before you can attack a WebSocket implementation, you need to understand what makes it structurally different from a normal HTTP request/response cycle. Every subsequent file in this series (message manipulation, auth testing, CSWSH, SSE) assumes you understand the mechanics covered here. This file is mechanism-first: no payloads yet, just how the protocol actually works and how it shows up in Burp.

Cross-reference: this file sits underneath the CSWSH concepts summarized in `04-origin-bypass-summary-cswsh.md` and the full CSWSH technique note in the web application security series.

---

## 1. Why WebSockets Exist

Regular HTTP is a request/response protocol: the client asks, the server answers, the connection (logically) ends. If the server wants to push new data to the client — a chat message, a live price update, a notification — HTTP alone can't do that without the client repeatedly polling.

WebSockets solve this by establishing a single long-lived TCP connection that both the client and server can write to at any time, independently of each other. This is called **full-duplex** communication.

**Real-world note:** Applications that use WebSockets include live chat widgets, trading dashboards, collaborative editors, multiplayer game state sync, and live notification systems. If you see a chat bubble or a live-updating dashboard, check Burp's WebSockets history tab before assuming it's polling-based.

---

## 2. The HTTP Upgrade Handshake

A WebSocket connection always starts life as a normal HTTP request. This matters for testing: the handshake is an HTTP request, which means every HTTP-layer attack surface (headers, cookies, auth tokens, CSRF) is present at the moment the connection is established — even though the traffic that follows is not HTTP.

### 2.1 Client request headers

```
GET /chat HTTP/1.1
Host: vulnerable-app.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://vulnerable-app.com
Cookie: session=abc123
```

Breakdown of each header and why it exists:

- **`GET /chat HTTP/1.1`** — The handshake must be a `GET` request. This is the endpoint the application has designated for the WebSocket upgrade. It's a normal routable path, so normal access-control logic on the server should (but often doesn't) apply to it.
- **`Host`** — Same purpose as in any HTTP request: identifies the target virtual host. Relevant to Host header injection testing if the server trusts this value when constructing the WebSocket URL to hand back to the client, or when generating password reset / redirect logic tied to the same session.
- **`Upgrade: websocket`** — Tells the server "I want to switch protocols from HTTP to WebSocket on this same TCP connection." Without this header (and `Connection: Upgrade`), the server treats it as an ordinary HTTP request.
- **`Connection: Upgrade`** — Required alongside the `Upgrade` header. This is a hop-by-hop signal telling any intermediary (proxy, load balancer) that this specific connection is being upgraded, not just this one request.
- **`Sec-WebSocket-Key`** — A randomly generated, base64-encoded 16-byte value. Its only purpose is to prove to the client that the server actually understood and processed this specific handshake (see 2.2 for how the server uses it). **It is not a security token, not a CSRF token, and not a secret.** It provides zero protection against cross-site WebSocket hijacking — this is a common misconception worth correcting explicitly when writing up findings, because developers sometimes assume it does provide CSRF protection.
- **`Sec-WebSocket-Version: 13`** — The WebSocket protocol version being used (RFC 6455 defined version 13, which is what's in universal use today). If the server doesn't support the requested version, it will respond with an error and list supported versions.
- **`Origin`** — Sent automatically by browsers, identifying the origin (scheme + host + port) of the page that opened the WebSocket connection. **This is the header the server must validate to prevent cross-site WebSocket hijacking.** Full technique covered in `04-origin-bypass-summary-cswsh.md` and the dedicated CSWSH note in the web app series.
- **`Cookie`** — If the application uses cookie-based sessions, the browser automatically attaches the session cookie to the handshake request, exactly as it would with any other same-origin HTTP request. This is precisely what makes CSWSH possible: the browser will send valid session cookies to a WebSocket handshake initiated by a malicious cross-origin page, because from the browser's perspective it's just another request to that origin.

### 2.2 Server response

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

- **`101 Switching Protocols`** — The status code confirming the upgrade succeeded. From this point forward, this TCP connection no longer speaks HTTP; it speaks the WebSocket framing protocol.
- **`Sec-WebSocket-Accept`** — Computed by the server by taking the client's `Sec-WebSocket-Key`, appending a fixed GUID (`258EAFA5-E914-47DA-95CA-C5AB0DC85B11`), SHA-1 hashing the result, and base64-encoding it. The client verifies this value matches what it independently computes, confirming the response came from a server that understood the WebSocket handshake (and, weakly, that no naive HTTP cache or proxy blindly replayed a canned response). Again — this is a handshake integrity check, not an authentication or CSRF mechanism.

**Testing implication:** Because authorization is decided at the point of the handshake (via the session cookie or auth header sent at that moment), everything that happens over the WebSocket connection afterward inherits whatever session context the handshake established — for as long as the connection stays open. This is why testing session/token expiry over WebSockets is different from testing it over HTTP (covered in `03-authentication-and-authorization-testing.md`).

---

## 3. WebSocket Frame Structure

Once upgraded, data is exchanged as discrete **frames**, not raw streams. You don't need to hand-parse frames when using Burp (it does this for you), but understanding frame structure explains *why* certain behaviors happen — e.g., why a message can be marked text vs. binary, and why fragmented messages exist.

Each frame contains:

- **FIN bit** — Indicates whether this is the final fragment of a message. A single logical message can be split across multiple frames (fragmentation), useful for streaming large payloads without buffering the whole thing first.
- **Opcode** — Identifies the frame type: `0x1` = text frame, `0x2` = binary frame, `0x8` = connection close, `0x9`/`0xA` = ping/pong (keepalive). Text frames are UTF-8 and are what you'll see rendered in Burp's WebSocket history. Binary frames carry raw bytes (e.g., Protobuf, msgpack) and won't render as readable text without additional parsing — worth flagging in scope notes if a target uses a binary WebSocket subprotocol.
- **MASK bit + masking key** — Every frame sent from client to server **must** be masked (XORed with a random 4-byte key sent in the frame). Frames from server to client are never masked. This masking exists purely to prevent cache-poisoning attacks against intermediary proxies that don't understand WebSocket framing — it is **not encryption** and provides no confidentiality. Burp handles unmasking transparently; you'll never need to do this by hand.
- **Payload length + payload data** — The actual message content. For text frames using JSON-based application protocols (extremely common — most chat, trading, and notification apps send JSON over WebSockets), this is where your injection testing happens (`02-message-manipulation-and-injection-testing.md`).

**Real-world note:** You don't need to manually construct frames for testing — Burp's Repeater and Proxy handle framing/masking/unmasking automatically. The frame structure matters for two practical reasons: (1) recognizing when an app is sending binary/subprotocol data that needs extra decoding before you can fuzz it, and (2) understanding that ping/pong frames exist, so you don't mistake keepalive traffic for application data when reading WebSocket history.

---

## 4. ws:// vs wss://

- **`ws://`** — Unencrypted WebSocket, riding over a plain TCP connection. Equivalent security posture to `http://`: anyone on the network path can read and tamper with every message.
- **`wss://`** — WebSocket over TLS, equivalent to `https://`. This is the only variant that should appear in a production application. The TLS handshake happens first, then the WebSocket upgrade handshake happens inside the encrypted channel.

**Testing implication:** If you find `ws://` in a production app (check page source, JS bundles, and Burp's WebSockets history for the scheme used), that's a finding on its own — session tokens and application data are traveling in cleartext. Also check for **protocol downgrade** scenarios: does the app fall back to `ws://` if `wss://` fails to connect? Does a proxy/load balancer terminate TLS and speak `ws://` internally in a way that's testable from an internal vantage point?

---

## 5. Full-Duplex Model — Why It Changes Your Testing Approach

In HTTP, request and response are tightly coupled: you send a request, you get exactly one response, testing is inherently synchronous. Over a WebSocket connection:

- Either side can send a message at any time, unprompted.
- There is no guaranteed 1:1 mapping between "a message you sent" and "a message you receive." The server might push three unrelated messages before responding to what you sent.
- The connection persists across many logical "requests" — meaning a single handshake's authorization decision can apply to potentially hundreds of subsequent messages, unlike HTTP where authorization is (in a well-built app) re-evaluated on every request.

This has direct consequences for authorization testing (`03-authentication-and-authorization-testing.md`): a broken access control check performed only at handshake time, and never re-validated per-message, is a very common real-world flaw.

---

## 6. How WebSocket Traffic Appears in Burp Suite

- **Proxy > WebSockets history tab** — This is where all WebSocket traffic lives, completely separate from the normal HTTP history tab. The handshake request itself still appears in HTTP history (since it's technically an HTTP request/response with a `101` status), but every message sent after the upgrade appears only in the WebSockets history tab.
- Each row shows direction (client→server or server→client), the frame's text content, and a timestamp. Binary frames show as raw bytes or a "binary data" placeholder depending on Burp version.
- **Intercepting messages** — With Proxy intercept on, individual WebSocket messages can be intercepted and modified before forwarding, exactly like HTTP requests. Interception rules (client-to-server / server-to-client) are configurable in Proxy settings, since intercepting every server push can be noisy on chatty applications.
- **Sending to Repeater** — Right-click any message in WebSockets history → "Send to Repeater" opens a WebSocket-aware Repeater tab where you can edit and resend individual messages, or attach/clone/reconnect the underlying WebSocket connection itself (useful when a connection drops after a malformed payload, or when a token embedded in the handshake needs refreshing). This is the primary workflow used throughout `02-message-manipulation-and-injection-testing.md`.

**Real-world note:** If you don't see anything in WebSockets history despite the app clearly having a live-updating feature, check whether it's using **Server-Sent Events** instead — a different, one-way real-time mechanism that shows up in ordinary HTTP history as a long-held response, not in WebSockets history at all. Covered in `05-server-sent-events-security-testing.md`.

---

## 7. Summary Table

| Concept | HTTP | WebSocket |
|---|---|---|
| Connection lifetime | Per-request (or short-lived keep-alive) | Long-lived, persists until explicitly closed |
| Direction | Client requests, server responds | Either side sends at any time (full-duplex) |
| Where it shows in Burp | Proxy > HTTP history | Proxy > WebSockets history |
| Encryption variant | `http://` vs `https://` | `ws://` vs `wss://` |
| Where auth is decided | Re-evaluated per request (ideally) | Typically decided once, at handshake |
| CSRF-equivalent risk | Standard CSRF | Cross-site WebSocket hijacking (CSWSH) |

---

## Next File

`02-message-manipulation-and-injection-testing.md` — how to actually intercept, replay, and fuzz WebSocket messages in Burp, and how classic injection vulnerabilities manifest through this delivery channel.
