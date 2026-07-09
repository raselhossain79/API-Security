# WebSocket API Security Testing

A complete methodology series for testing WebSocket-based APIs and the related Server-Sent Events (SSE) real-time pattern, covering protocol mechanics, message manipulation, injection testing, authentication/authorization, origin-validation bypass (CSWSH), and SSE-specific risks — mapped to PortSwigger Web Security Academy labs.

This series does not duplicate the full Cross-Site WebSocket Hijacking (CSWSH) technique, which is documented in the CSWSH note in the web application security series. File 04 here provides a summary and cross-reference only.

## Files

| File | Contents |
|---|---|
| [01-websocket-protocol-fundamentals.md](01-websocket-protocol-fundamentals.md) | HTTP upgrade handshake (header-by-header breakdown), frame structure, ws:// vs wss://, full-duplex model, how WebSocket traffic appears in Burp's WebSockets history tab. |
| [02-message-manipulation-and-injection-testing.md](02-message-manipulation-and-injection-testing.md) | Intercepting, replaying, and fuzzing WebSocket messages in Burp. SQLi, XSS, command injection, and SSTI delivered via WebSocket JSON payloads. WAF/gateway detection and bypass for message-level injection. |
| [03-authentication-and-authorization-testing.md](03-authentication-and-authorization-testing.md) | Tokens in the handshake vs. the first post-connect message. Testing missing/expired/cross-user tokens. BOLA and BFLA via WebSocket messages. Session-persistence risk when privileges change mid-connection. |
| [04-origin-bypass-summary-cswsh.md](04-origin-bypass-summary-cswsh.md) | Summary of origin validation and CSWSH mechanics, testing checklist, and cross-reference to the full CSWSH technique note in the web application security series. |
| [05-server-sent-events-security-testing.md](05-server-sent-events-security-testing.md) | How SSE differs mechanically from WebSockets (one-way, plain HTTP, no upgrade). Authentication testing for SSE endpoints. Information disclosure risks from improperly scoped long-lived connections. |
| [06-final-cheatsheet-and-lab-mapping.md](06-final-cheatsheet-and-lab-mapping.md) | Condensed checklist across the whole series, plus the complete PortSwigger WebSocket lab list in Apprentice → Practitioner order with honest gap disclosure. |

## Reading Order

Read the files in numeric order. File 01 is a prerequisite for all others. File 04 assumes file 01 (handshake mechanics) and points to the standalone CSWSH note for the full exploit. File 05 (SSE) is a related but structurally distinct pattern and can be read independently once file 01 is understood, since it deliberately contrasts against WebSocket mechanics throughout.

## PortSwigger Lab Mapping

Full lab-to-file mapping is in file 06. Summary: PortSwigger's WebSockets topic has exactly three labs (Apprentice: message manipulation, Practitioner: handshake manipulation, Practitioner: CSWSH) — no Expert-tier lab exists in this topic, and no dedicated SSE lab exists on the platform. crAPI is recommended as supplementary practice for BOLA/BFLA and injection testing in a fuller application context.

## Conventions Used in This Series

- Mechanism-first explanations — every workflow and payload is broken down piece by piece.
- Explicit statements of why WAF/API Gateway bypass is or isn't meaningfully relevant to each topic, rather than silent omission.
- PortSwigger lab mappings in strict difficulty order, with gaps disclosed honestly rather than implied to be complete.
- Cross-references to sibling series (BOLA, BFLA, JWT Attacks, API Gateway Security, CSWSH) instead of duplicating shared content.
- Full English only.
