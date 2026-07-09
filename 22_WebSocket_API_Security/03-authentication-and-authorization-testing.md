# WebSocket Authentication and Authorization Testing

## Purpose of This File

WebSocket connections are long-lived, and authorization decisions are frequently made once — at the handshake — and then trusted for the entire connection lifetime. This file covers where auth tokens live in a WebSocket flow, how to test broken/expired/stolen-token scenarios, and how BOLA/BFLA manifest when the "request" is a WebSocket message instead of an HTTP call. If you haven't read `01-websocket-protocol-fundamentals.md`, read it first — this file assumes familiarity with the handshake and full-duplex model.

Cross-reference: general BOLA/BFLA methodology, terminology, and the broader OWASP API Top 10 mapping are covered in this library's `API1-BOLA` and `API5-BFLA` series notes — this file applies that same methodology specifically to the WebSocket transport.

---

## 1. Two Places a Token Can Live

### 1.1 Token in the handshake (HTTP layer)

Most commonly seen as:
- An `Authorization: Bearer <token>` header on the handshake `GET` request.
- A session cookie automatically attached by the browser (see file 01, section 2.1).
- A token embedded in the WebSocket URL as a query parameter: `wss://target.com/chat?token=eyJhbGc...`

**Why this matters for testing:** because the handshake is a normal HTTP request, it's fully visible and editable in Burp's HTTP history *before* the upgrade happens. You can modify the token here exactly as you would on any HTTP request — swap it for another user's token, strip it, expire it, truncate it — using Repeater's WebSocket-connect wizard (file 01, section 6) to re-run the handshake with the modified value.

**Design implication:** if the token is only validated at handshake time and never re-checked, then once the connection is established with a valid token, the server has no further opportunity (unless it explicitly re-validates) to notice that the token has since expired, been revoked, or belonged to a now-logged-out session. This is the single most important authorization question to answer for any WebSocket target: **does the server re-validate the token per-message, or only once at connection time?**

### 1.2 Token in the first message after connection (application layer)

Some applications deliberately avoid putting auth tokens in the handshake (e.g., to keep tokens out of URLs/logs, or because the client-side WebSocket API makes setting custom headers difficult in browser JS) and instead require the client to send an authentication message immediately after the connection opens:

```json
{"type":"auth","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
```

The server then holds the connection in an "unauthenticated" state until this message arrives and validates successfully, after which it transitions the connection to "authenticated" and begins accepting other message types.

**Testing implications specific to this pattern:**
- What happens if you skip the auth message entirely and send an application message directly? A common flaw is that the server never actually checks connection state before processing a message — the auth message is a UI convention the legitimate client follows, not an enforced gate.
- What happens if you send the auth message twice, with two different users' tokens, on the same connection? Does the server correctly transition to the second user's context, or does it get confused and process subsequent messages under a mixed/stale identity?
- Is the auth message itself rate-limited or validated server-side at all, or can it be fuzzed/brute-forced with no throttling (since it's not going through the same login-endpoint rate-limiting that protects the HTTP login form)?

---

## 2. Testing Token Absence, Expiry, and Cross-User Reuse

### 2.1 Missing token

1. Capture a legitimate handshake in Burp.
2. Send it to Repeater's WebSocket wizard, strip the `Authorization` header (or the cookie, or the `?token=` query parameter, depending on which pattern the app uses).
3. Attempt to connect. Note the server's behavior: does it reject the handshake outright (`401`/`403` at the HTTP layer, connection never upgrades), or does it upgrade successfully and only then reject application messages (or worse, silently serve anonymous/default data)?
4. If it upgrades successfully, send a normal application message and observe whether it's processed as if authenticated, processed as an anonymous/guest context, or rejected. Any outcome other than a clean rejection at the earliest possible point is worth documenting — a connection that upgrades successfully without a token, even if individual messages are later rejected, is expanding attack surface unnecessarily (e.g., exposing whatever protocol-level information is returned during the handshake response itself).

### 2.2 Expired token

1. Obtain a token, then either wait for it to naturally expire or use one you know has already expired.
2. Attempt the handshake with the expired token attached.
3. If the connection is refused, also test: connect *while the token is still valid*, keep the connection open, and check whether the server terminates or restricts the connection once the token's expiry time passes during the connection's lifetime. Many implementations validate only at connect time and never re-check — meaning a connection opened one second before expiry can remain fully privileged indefinitely, since there's no natural "next request" moment (as there would be with HTTP) that would trigger a fresh validation.

### 2.3 Cross-user token reuse

1. As User A, capture the WebSocket handshake with User A's valid token.
2. As User B (separate account, separate browser/Burp session), attempt to reuse User A's token value in User B's handshake attempt, or vice versa — testing whether tokens are properly scoped/bound to the session that issued them or can simply be replayed by anyone who obtains them.
3. Separately: if the app assigns any connection-level identifier (e.g., a `client_id` sent back by the server after connecting), test whether that identifier can be predicted or reused to hijack or eavesdrop on another user's already-established connection state, if the architecture allows connection resumption/reattachment.

**Real-world note:** because handshake capture/replay is trivial in Burp (unlike, say, replaying a raw TCP-level attack), this category of test is fast to run and frequently uncovers real findings — many WebSocket implementations were built by developers who thought carefully about HTTP-layer auth but treated the WebSocket handshake as "just an implementation detail" rather than a first-class auth boundary.

---

## 3. BOLA via WebSocket (Broken Object Level Authorization)

**Definition recap:** BOLA occurs when an application lets an authenticated user access or manipulate an object (a record, a resource, another user's data) that they should not have access to, because the object-level ownership check is missing or incomplete — the app checks "is this user logged in" but not "does this user own *this specific object*."

**How this manifests over WebSocket:** exactly as it does over HTTP, applied to whatever object identifier the WebSocket message carries.

**Example — chat history retrieval:**
```json
{"action":"getHistory","conversationId":1042}
```
As an authenticated user, test incrementing/decrementing `conversationId` (or substituting a conversation ID belonging to another account you control, or one guessed/enumerated) to see whether the server returns another user's chat history without verifying the requesting user is actually a participant in that conversation.

**Example — action-performing message (more severe than pure data disclosure):**
```json
{"action":"updateProfile","userId":887,"email":"attacker@evil.com"}
```
If `userId` is client-controlled and the server doesn't cross-check it against the identity established at the handshake/auth-message stage, an attacker can perform write actions — not just read another user's data, but modify it — on behalf of an arbitrary user ID.

**Testing methodology:**
1. Establish two accounts under your control (or one account plus known/predictable object IDs from another source).
2. Capture the WebSocket messages that reference object IDs (chat IDs, order IDs, document IDs, user IDs) as Account A.
3. Replay those same messages — same connection/session context as Account A — but with object IDs belonging to Account B substituted in.
4. Confirm whether the server enforces ownership, and specifically test both **read** actions (data disclosure) and **write/action** message types (which carry higher severity), since a WebSocket API may authorize reads correctly but fail to authorize the corresponding write action, or vice versa.

**Why WebSocket delivery doesn't help here either:** the ownership-check logic lives entirely in the server-side handler for that message type. Whether the object ID arrived via a URL path parameter (HTTP) or a JSON field in a WebSocket frame makes no difference to whether that handler correctly checks `object.ownerId == session.userId` before acting.

---

## 4. BFLA via WebSocket (Broken Function Level Authorization) / Privilege Escalation

**Definition recap:** BFLA occurs when a function/action that should be restricted to a certain role (e.g., admin-only) is reachable by a lower-privileged user because the function-level check is missing, even though object-level ownership might be correctly enforced elsewhere.

**How this manifests over WebSocket:**

**Example — hidden/undocumented action types:** WebSocket protocols are often loosely typed JSON message dispatchers (`{"action": "..."}` or `{"type": "..."}` routing to a handler function). Client-side JS may only ever send a known, documented set of action types — but the server-side dispatcher may support additional action types that are never exposed through the normal UI, because they were built for an admin panel that happens to reuse the same WebSocket endpoint and connection-handling code.

Testing methodology:
1. Fully map every distinct `action`/`type` value observed across the entire application by a normal user, admin panel (if you have any access, even limited), and by reviewing client-side JS bundles for string literals matching the message-routing pattern used elsewhere in the app.
2. As a low-privileged user, attempt to send action types that were only ever observed in an admin context, or inferred from JS but never triggered through the normal low-privilege UI:
```json
{"action":"deleteUser","userId":42}
```
```json
{"action":"promoteToAdmin","userId":887}
```
3. Because a WebSocket dispatcher is a single connection handling many action types, this kind of test is often *faster* to run than the HTTP equivalent (no separate endpoint discovery needed — you're fuzzing the `action` field on one already-open connection), which makes function enumeration a high-value, low-effort test against any WebSocket API using this dispatch pattern.

**Example — role/permission field trusted from the client:**
```json
{"action":"getReports","role":"admin"}
```
If the server trusts a client-supplied `role` field to decide what data/functions to expose, rather than deriving the role from the server-side session established at auth time, this is a direct, trivial privilege escalation — test by simply changing the value and observing whether the response changes to reflect elevated access.

---

## 5. Session Context Persistence — the WebSocket-Specific Risk

Recall from file 01 (section 5) that a single handshake's authorization decision can apply to every subsequent message for the connection's entire lifetime. This creates a WebSocket-specific risk category that doesn't have a clean HTTP equivalent: **privilege changes that happen mid-connection are not reflected.**

Concretely test:
1. Open a WebSocket connection as a normal user.
2. While that connection remains open, have an admin (or use a second, separate admin-privileged session) **revoke** the user's privileges, ban the account, or downgrade their role via the normal application flow.
3. Without reconnecting, send an application message on the still-open original connection and observe whether the now-revoked privileges are still honored.

If yes — this is a real, practically exploitable finding: account bans, permission downgrades, and session revocations that are supposed to take effect immediately are silently bypassed for the duration of any WebSocket connection opened before the revocation, which for a persistent chat/dashboard connection could be hours or days.

---

## 6. WAF / API Gateway Considerations for Auth/Authz Testing

**Relevance:** Partial. WAFs and API gateways can meaningfully affect handshake-layer auth testing, but object/function-level authorization logic (BOLA/BFLA) lives in application code that a WAF cannot inspect or enforce, since it has no concept of "does this object belong to this user."

**Where gateway-layer defenses are relevant:**
- **Rate-limiting/brute-force protection on the handshake.** An API gateway sitting in front of the WebSocket-terminating server may throttle repeated handshake attempts with invalid/rotating tokens — relevant when testing token brute-forcing or rapid reconnect-with-different-token attempts. Test whether this throttling is IP-based (bypassable via `X-Forwarded-For` spoofing, proxied requests, or distributed source IPs) or session/token-based (harder to bypass).
- **JWT/token validation at the gateway layer, separate from the application.** Some architectures validate token *signature and expiry* at the gateway (rejecting malformed/expired tokens before they ever reach the application), while leaving all *object and function-level authorization* entirely to the application. This means gateway-layer testing (token tampering, alg confusion, expired-token replay) and application-layer testing (BOLA/BFLA as covered above) are testing genuinely different components — a gateway correctly rejecting a tampered JWT tells you nothing about whether the application enforces object ownership once a legitimately-signed token is used.

**Where gateway-layer defenses are not relevant:**
- BOLA and BFLA are business-logic authorization flaws. No signature-based WAF rule or generic API gateway policy can determine "should this specific user be allowed to access this specific object" — that requires knowledge of the application's data model that only the application itself has. Don't expect a WAF finding or bypass angle for the BOLA/BFLA sections of this file; the fix and the vulnerability both live entirely in application code.

---

## Next File

`04-origin-bypass-summary-cswsh.md` — origin validation, why it exists, and a summary-level pointer to the full CSWSH technique note in the web application security series.
