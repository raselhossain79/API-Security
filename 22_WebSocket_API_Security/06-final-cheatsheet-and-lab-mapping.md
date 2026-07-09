# Final Cheatsheet and PortSwigger Lab Mapping

## Purpose of This File

A condensed, at-a-glance reference for this entire series, plus the complete PortSwigger Web Security Academy WebSocket lab list mapped in strict Apprentice → Practitioner → Expert order, with honest disclosure of coverage gaps.

---

## 1. Quick-Reference Checklist

### Protocol / recon
- [ ] Check Burp's **WebSockets history** tab (separate from HTTP history) for any live-updating feature.
- [ ] If WebSockets history is empty but the feature is clearly real-time, check **HTTP history** for a long-held `text/event-stream` response — it's SSE, not WebSocket (file 05).
- [ ] Confirm `wss://` is used, not `ws://`. Flag plaintext `ws://` in production as a finding on its own.
- [ ] Capture the handshake request in HTTP history — note `Origin`, `Cookie`, `Authorization`, and any `?token=` query parameter.

### Message manipulation / injection (file 02)
- [ ] Send captured messages to Repeater; confirm the WebSocket-aware Repeater tab (reconnect/clone/attach wizard available).
- [ ] Replicate the legitimate message sequence (e.g., init/"READY" messages) before fuzzing — many apps have connection-level state machines.
- [ ] Test SQLi, XSS, command injection, SSTI in every JSON field, exactly as you would test the HTTP equivalent — remember delivery channel does not equal sanitization.
- [ ] Use Collaborator for OOB confirmation of blind injection classes.
- [ ] If a WAF/gateway bans on malicious frame content, test `X-Forwarded-For` spoofing on reconnect and frame-fragmentation as bypass angles.

### Authentication / authorization (file 03)
- [ ] Identify whether the token lives in the handshake or in a first post-connect auth message.
- [ ] Test missing / expired / cross-user token at the handshake.
- [ ] Test whether privilege revocation mid-connection is honored without reconnecting.
- [ ] Test BOLA: swap object IDs (chat IDs, order IDs, user IDs) in messages between two accounts you control.
- [ ] Test BFLA: enumerate all `action`/`type` values from JS bundles and admin contexts; try them as a low-privileged user.
- [ ] Test client-supplied role/permission fields trusted without server-side verification.

### Origin / CSWSH (file 04)
- [ ] Confirm session auth is cookie-based (precondition for CSWSH).
- [ ] Test `Origin` header: stripped, unrelated domain, substring-bypass domain (`target.com.evil.com`).
- [ ] If origin validation is missing/broken → escalate using the full CSWSH note in the web app security series for exploit construction.

### SSE (file 05)
- [ ] Confirm one-way, plain-HTTP `text/event-stream`, no client→server channel on the same connection.
- [ ] Test cookie-based auth removal; test CORS with attacker `Origin` + `Access-Control-Allow-Credentials`.
- [ ] Test `Last-Event-ID` resume across different user sessions (event ID scoping).
- [ ] Test whether a shared/broadcast event bus leaks other users' private events to your stream.
- [ ] Test whether logout/ban terminates an already-open SSE stream.

---

## 2. PortSwigger Web Security Academy — WebSocket Lab Mapping

PortSwigger's WebSockets topic contains **three dedicated labs**, and only three — there is no Expert-tier lab in this specific topic as of this writing. Listed here in strict Apprentice → Practitioner order; do not skip ahead, since each lab builds directly on the mechanism covered by the previous one.

| Order | Difficulty | Lab Name | Maps to File |
|---|---|---|---|
| 1 | Apprentice | Manipulating WebSocket messages to exploit vulnerabilities | `02-message-manipulation-and-injection-testing.md` — this lab is a direct hands-on match for the XSS-via-WebSocket-message section. |
| 2 | Practitioner | Manipulating the WebSocket handshake to exploit vulnerabilities | `02-message-manipulation-and-injection-testing.md`, section 9 (WAF/reconnect-bypass) and `03-authentication-and-authorization-testing.md`, section 1.1 — this lab requires editing handshake-time headers (including spoofing a trusted header to bypass an IP-based ban) to exploit a message-level vulnerability that's gated behind handshake-layer defenses. |
| 3 | Practitioner | Cross-site WebSocket hijacking | `04-origin-bypass-summary-cswsh.md` and the full CSWSH note in the web application security series — this lab is the canonical CSWSH exploit build: missing origin validation plus cookie-based session auth, exploited via a malicious HTML page that opens a cross-origin WebSocket and exfiltrates data. |

**Honest gap disclosure:** This is the complete list of PortSwigger's dedicated WebSocket-topic labs — there are no additional Apprentice-tier or Expert-tier WebSocket labs to map, and no dedicated SSE lab exists on the platform at all as of this writing. If PortSwigger adds new labs to this topic in the future, re-check `https://portswigger.net/web-security/websockets` before treating this table as exhaustive. Supplementary hands-on practice for the topics in files 02 (message-level injection) and 03 (BOLA/BFLA) that goes beyond what PortSwigger's WebSocket-specific labs cover is available in **crAPI**, which includes a WebSocket-based chat feature suitable for practicing the BOLA/BFLA and injection methodology from this series in a fuller, more application-like context than PortSwigger's single-vulnerability labs.

---

## 3. Cross-References Within This Series

- `01-websocket-protocol-fundamentals.md` — underlies every other file; read first.
- `02-message-manipulation-and-injection-testing.md` — depends on file 01's Burp workflow section (6).
- `03-authentication-and-authorization-testing.md` — depends on file 01's handshake section (2.1) and full-duplex model (5); general BOLA/BFLA methodology lives in this library's `API1-BOLA` and `API5-BFLA` series notes.
- `04-origin-bypass-summary-cswsh.md` — summary only; full technique in the CSWSH note, web application security series.
- `05-server-sent-events-security-testing.md` — related pattern, distinct transport; cross-references file 03's session-persistence risk and file 04's cookie-riding risk (CORS variant, not CSWSH).

---

## 4. External Cross-References (Other Series in This Library)

- Full CSWSH technique, exploit-server payload breakdown, Collaborator exfiltration walkthrough — CSWSH note, web application security series.
- General BOLA methodology (API1) — `API1-BOLA` series.
- General BFLA methodology (API5) — `API5-BFLA` series.
- JWT-specific attacks (algorithm confusion, key confusion, weak signing keys) if the WebSocket/SSE token is a JWT — JWT Attacks series.
- General WAF/API Gateway bypass patterns not specific to WebSocket/SSE — API Gateway Security series.
- Rate limiting and bot-protection bypass, relevant to handshake-layer throttling discussed in file 03 — Rate Limit/Bot Protection Bypass series.
