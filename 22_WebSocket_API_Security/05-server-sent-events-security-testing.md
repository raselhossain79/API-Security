# Server-Sent Events (SSE) Security Testing

## Purpose of This File

Server-Sent Events (SSE) is a second common pattern for real-time server-to-client data delivery, frequently confused with WebSockets because both power "live updating" features. Architecturally and from a testing perspective they are quite different. This file covers what SSE is, how it differs mechanically from WebSockets, how to test its authentication, and the information-disclosure risk that is specific to its long-lived-connection-over-plain-HTTP design.

---

## 1. Mechanism: How SSE Differs from WebSockets

The core distinction, stated precisely: **SSE is a one-way, server-to-client stream delivered over a single, long-held, ordinary HTTP response — there is no protocol upgrade, no separate framing protocol, and no client-to-server message channel over the same connection.**

Breaking that down:

- **One-way only.** The server pushes data to the client. The client cannot send messages back over the same SSE connection — if the application needs to send client-to-server data (e.g., a chat message a user types), it does so via a completely separate, ordinary HTTP request (a normal `POST`), while the SSE connection is used purely to receive the resulting pushes. This is a fundamentally different model from a WebSocket's full-duplex single connection (file 01, section 5).
- **Plain HTTP, not a protocol upgrade.** An SSE connection is a standard `GET` request where the server simply never closes the response, and instead keeps writing to it over time. There is no `101 Switching Protocols`, no `Upgrade`/`Connection` handshake headers, and no `Sec-WebSocket-*` headers. The response uses `Content-Type: text/event-stream`, and the connection is kept open by the server continuing to flush data on the same HTTP response body indefinitely.
- **Simpler message format.** Where WebSocket frames have a binary structure (file 01, section 3), SSE messages are plain UTF-8 text, formatted as newline-delimited `field: value` pairs, most commonly:
```
data: {"price": 104.22}

data: {"price": 104.35}

```
Each `data:` line (or block of lines, for multi-line payloads) followed by a blank line constitutes one event. Optional fields include `event:` (a named event type, letting client-side JS listen for specific event types via `addEventListener`) and `id:` (used for automatic reconnection resume, described below).
- **Where it shows up in Burp:** SSE does **not** appear in the WebSockets history tab. It appears in ordinary **Proxy > HTTP history** as a single request whose response never fully completes/closes while the connection is active — Burp will show the response streaming in over time rather than arriving as one discrete payload. If you're looking for real-time traffic and WebSockets history is empty, check HTTP history for a long-held `GET` request with `Content-Type: text/event-stream`.
- **Built-in reconnection.** The browser's native `EventSource` API automatically reconnects if the connection drops, and can send the `Last-Event-ID` header (populated from the most recent `id:` field received) on reconnect, allowing the server to resume the stream from where it left off. This reconnection/resume behavior is itself worth testing — see section 3.

---

## 2. Authentication Testing for SSE Endpoints

Because there's no handshake-with-custom-headers step the way there is with WebSockets, and because the native browser `EventSource` API **cannot set custom request headers at all** (a real and commonly-hit limitation for developers), SSE authentication tends to rely on one of a smaller set of patterns — each with its own testing angle:

### 2.1 Cookie-based auth (most common)
Since `EventSource` can't attach custom headers, cookie-based session auth is the path of least resistance for developers, and the browser attaches cookies automatically to the SSE `GET` request exactly as with any other same-origin request.

**Test:**
- Strip the session cookie in Repeater and re-request the SSE endpoint directly — does the stream still open and deliver data, or is it correctly rejected?
- This cookie-based pattern also creates a **CORS/cross-origin risk** that is the SSE analog of CSWSH (file 04): if the SSE endpoint doesn't correctly restrict cross-origin reads (via proper CORS headers — `Access-Control-Allow-Origin` must NOT reflect arbitrary origins when credentials are involved), a malicious page can potentially open a cross-origin `EventSource`/`fetch` stream that rides on the victim's cookies. Test this exactly as you would test CORS misconfiguration on any other credentialed HTTP endpoint: send the request with an attacker-controlled `Origin` header and check whether the response both reflects that origin in `Access-Control-Allow-Origin` **and** sets `Access-Control-Allow-Credentials: true`. Note this is a CORS-layer test, mechanically distinct from CSWSH even though the underlying risk (cookie-riding cross-origin) is conceptually similar.

### 2.2 Token in the URL query string
Because custom headers aren't available to `EventSource`, some implementations pass an auth token directly in the URL: `GET /events?token=eyJhbGc...`.

**Test:**
- This pattern has an inherent information-disclosure risk independent of any application logic flaw: tokens in URLs are far more likely to be logged (server access logs, proxy logs, browser history, `Referer` headers if the page navigates elsewhere while the token is still in the address bar for some implementations) than tokens in headers or cookies. Flag this as a finding on its own even if the token itself is otherwise correctly validated.
- Test token expiry and cross-user reuse exactly as described for WebSocket handshake tokens in `03-authentication-and-authorization-testing.md`, section 2 — the same "validated once, trusted for the connection's full lifetime" risk applies here too, since SSE connections are also long-lived.

### 2.3 Custom client (not the native EventSource API)
Some applications use `fetch()` with a `ReadableStream` reader instead of the native `EventSource` object specifically to work around its no-custom-headers limitation, allowing a proper `Authorization: Bearer` header. If you see this pattern, test it identically to any other bearer-token-authenticated HTTP endpoint.

---

## 3. Information Disclosure Risks Specific to SSE

The requirement to cover here is specific and important: **long-lived connections exposing data across session boundaries if not properly scoped per connection.** This is a distinct risk category from the general auth-testing above — it's about what happens when the *stream itself* isn't correctly isolated to the single authenticated session that opened it.

### 3.1 Stream not re-scoped on reconnect/resume
Recall from section 1 that `EventSource` supports automatic resume via `Last-Event-ID`. Test:
- Open an SSE connection as User A, note event IDs received.
- Disconnect, then reconnect **as a different user (User B)**, manually supplying a `Last-Event-ID` header value that was observed during User A's session.
- Does the server correctly scope the resumed stream to User B's own authorized data, or does it resume from the given event ID within a global/shared event log — potentially replaying User A's private events to User B? This is a realistic flaw pattern in implementations where the event ID space is global (e.g., a monotonically increasing counter across all users) rather than scoped per-user, and the resume logic naively seeks to "give me everything after event ID X" without re-checking whether the requesting user was ever authorized to see events in that ID range.

### 3.2 Shared/broadcast stream without per-connection filtering
Some SSE implementations are built around a single internal event bus that many users' streams all subscribe to (efficient for the server — one internal publish reaches all connected clients), with filtering meant to happen before each event is written to each individual client's stream. Test:
- Trigger an action as User A that should generate a private event (e.g., a notification only User A should see, or an admin-only system event).
- Monitor an SSE connection open under User B's (lower-privileged) session at the same time.
- If User B's stream receives User A's private event data — even if the client-side JS is coded to only *display* events relevant to the logged-in user — this is a server-side finding: the filtering is happening in a place the attacker doesn't have to respect (client-side JS), and the raw private data was already disclosed to User B's browser over the network, fully visible in Burp's HTTP history regardless of what the front-end chooses to render.

### 3.3 Long-lived connection outliving a privilege change
Directly analogous to the WebSocket-specific risk in `03-authentication-and-authorization-testing.md`, section 5: since an SSE connection, once opened, is not naturally re-authorized on any "next request" the way discrete HTTP calls would be, test whether revoking a user's access mid-stream (ban, permission downgrade, session logout elsewhere) actually terminates or restricts an already-open SSE connection, or whether it continues delivering data until the connection is closed for an unrelated reason (network drop, browser tab close, server-side timeout).

### 3.4 Stale data exposure after logout
Test whether closing/logging out the "primary" session (e.g., via the normal logout button, which typically clears cookies via a `Set-Cookie` response and redirects) actually causes the server to close any SSE connections tied to that session server-side, or whether the stream keeps running on the server (and keeps sending data to any client-side code still listening, e.g., a background tab) until it independently times out.

---

## 4. WAF / API Gateway Considerations for SSE

**Relevance:** Limited, and the reason is structural, worth stating explicitly rather than skipping. Most WAF/gateway rules are built around discrete request/response inspection or WebSocket-frame inspection (file 02, section 9). SSE's actual attack surface — the topics covered in sections 2 and 3 above — is almost entirely a **server-side data-scoping and session-management logic problem**, not a payload-injection problem a signature-based WAF could detect or block. There is no equivalent to "malicious frame content" to pattern-match against, because the client doesn't send payload data over the SSE connection at all (section 1) — the only traffic flowing over an SSE connection is server-to-client, so injection-style WAF detection (built to catch malicious *inbound* payloads) has essentially nothing to inspect on this specific channel.

Where gateway-layer controls *are* meaningfully relevant to SSE:
- **Connection limits / timeout enforcement.** API gateways commonly enforce a maximum connection duration or maximum concurrent long-lived connections per client, which can affect testing (a gateway may forcibly terminate your SSE test connection at a fixed interval regardless of application-level session state — don't mistake a gateway-imposed timeout for the application correctly re-validating auth).
- **CORS enforcement**, if handled at the gateway layer rather than in application code — relevant to the cross-origin cookie-riding risk described in section 2.1.

If a target's SSE implementation does sit behind a WAF, the correct testing takeaway is: **the interesting findings for SSE are essentially never going to be a WAF bypass — focus effort on the scoping/session-boundary logic in section 3 instead.**

---

## Next File

`06-final-cheatsheet-and-lab-mapping.md` — condensed reference covering this entire series plus the full PortSwigger WebSocket lab progression.
