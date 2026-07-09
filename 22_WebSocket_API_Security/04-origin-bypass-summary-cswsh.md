# Origin Validation Bypass — Summary (Cross-Site WebSocket Hijacking)

## Purpose of This File

This file is intentionally a **summary, not a full technique note**. The complete, piece-by-piece Cross-Site WebSocket Hijacking (CSWSH) methodology — exploit construction, the exploit-server HTML/JS payload breakdown, Collaborator-based exfiltration walkthrough, and the CSRF-on-handshake mechanics — already exists in this library's CSWSH note in the **web application security series**. This file exists only to (a) explain how CSWSH connects to everything else in this WebSocket series, and (b) summarize the mechanism at a level sufficient to understand its role in a WebSocket API testing methodology, without duplicating content that's already documented in full elsewhere.

**For the full technique, go to:** the CSWSH note in the web application security series.

---

## 1. Why Origin Validation Exists (Mechanism Recap)

As covered in `01-websocket-protocol-fundamentals.md` (section 2.1), the browser automatically attaches the `Origin` header — and, if cookie-based sessions are in use, the session cookie itself — to every WebSocket handshake request, exactly as it does for any other same-origin or cross-origin HTTP request. This happens **regardless of which website's JavaScript initiated the connection**, because from the browser's perspective, opening a WebSocket to `wss://target.com/chat` is just another network request to `target.com`, and cookies are attached based on the target domain, not the page that triggered the request.

This is structurally identical to the root cause of CSRF against normal HTTP endpoints: **the browser's automatic credential attachment doesn't care where the request originated from.**

The `Origin` header is the server's *only* reliable signal, at the point of the handshake, for distinguishing "this connection request came from my own application's front-end" from "this connection request came from some other website the victim happened to have open in another tab." If the server does not validate this header — or validates it insufficiently (e.g., a substring match that `evil-target.com` satisfies against an expected `target.com`, or trusting a client-controlled header instead) — an attacker-controlled page can open a WebSocket connection to the target application, and the victim's browser will faithfully attach their valid session cookie to that handshake.

## 2. Why This Matters More Than the Equivalent HTTP CSRF Case

A successful CSWSH attack is often *more* severe than an equivalent form-based CSRF finding, for two reasons directly tied to concepts covered elsewhere in this series:

1. **Full-duplex data exfiltration, not just one-shot action forgery.** A forged HTTP CSRF request can typically only perform a single state-changing action (submitted once, response usually not readable by the attacker due to CORS). A hijacked WebSocket connection stays open, full-duplex (file 01, section 5) — meaning the attacker's page can not only send messages *as* the victim, but also **receive every message the server pushes back**, since the JavaScript that opened the connection has direct access to the `onmessage` event. This turns the attack into an ongoing data-exfiltration channel (e.g., silently streaming a victim's entire chat history to an attacker-controlled server) rather than a single forged action.
2. **Session-duration exposure.** Because authorization for a WebSocket connection is typically decided once at handshake time and trusted for the connection's lifetime (file 03, section 5), a successful hijack captures not just one action but the full scope of whatever that session is authorized to do, for as long as the attacker keeps the hijacked connection open.

## 3. Testing Checklist (Summary Level)

At a testing-methodology level, confirming whether an application is vulnerable involves:

1. Identify the WebSocket handshake request in Burp's HTTP history (it's the `GET` request with `Upgrade: websocket` — see file 01, section 2.1).
2. Check whether the handshake relies on cookies (rather than a token that must be explicitly attached by same-origin JS, which cross-origin pages cannot read or forge) for session authentication — cookie-based auth is the precondition for the attack, exactly as it is for classic CSRF.
3. Test the server's `Origin` validation directly in Repeater: resend the handshake with the `Origin` header stripped entirely, set to an unrelated domain, and set to a domain designed to fool a naive substring/regex check (e.g., `target.com.evil.com`, `evilcom/target.com`, or a null/empty value). If the connection still upgrades successfully under any of these conditions, origin validation is missing or broken.
4. If (3) confirms the flaw, escalate to a working proof-of-concept exploit — this is where you move to the full CSWSH note in the web application security series, which covers the exploit-server HTML/JS payload piece by piece, Collaborator-based exfiltration for out-of-band confirmation, and full write-up structure for reporting.

## 4. Common Origin-Validation Mistakes Worth Recognizing

- **No validation at all** — the server accepts any `Origin` value or ignores the header entirely.
- **Substring matching instead of exact matching** — checking whether `Origin` *contains* the expected domain rather than exactly equals an expected value, defeated by attacker domains like `target.com.attacker.net` or `attacker-target.com`.
- **Trusting a client-controlled alternative header** in place of, or in addition to, `Origin` — e.g., trusting a custom header that a legitimate cross-origin attack page can simply set to any value it wants, since only browser-controlled headers like `Origin` (which JavaScript cannot override) provide a genuine trust signal.
- **Validating `Origin` only on the initial handshake response but not consistently across reconnect/retry logic** — worth testing separately if the application has any automatic reconnection behavior.
- **Confusing `Sec-WebSocket-Key`/`Sec-WebSocket-Accept` for a CSRF protection mechanism** — as explained in file 01, these headers exist purely for handshake integrity between a WebSocket-aware client and server; they provide no protection against a malicious cross-origin page, since that page's browser-issued `WebSocket` object generates a fully valid key/accept exchange like any other client.

## 5. Where This Fits in the Overall WebSocket Testing Methodology

| File | Relationship to CSWSH |
|---|---|
| `01-websocket-protocol-fundamentals.md` | Explains the `Origin` header and handshake mechanics that make CSWSH possible in the first place. |
| `02-message-manipulation-and-injection-testing.md` | Independent vulnerability class — a hijacked connection (via CSWSH) can be used as a *delivery vector* for sending injected messages as the victim, connecting the two files at the exploitation stage. |
| `03-authentication-and-authorization-testing.md` | Explains why a hijacked connection's session-scoped privileges remain valid for the connection's full lifetime, amplifying CSWSH impact. |
| **This file / CSWSH note (web app series)** | The origin-validation-bypass technique itself. |
| `05-server-sent-events-security-testing.md` | SSE has a *related but distinct* cross-origin risk profile — see that file's origin/CORS section for how it differs from CSWSH. |

---

## Next File

`05-server-sent-events-security-testing.md` — a related real-time API pattern with different transport mechanics and a different risk profile.
