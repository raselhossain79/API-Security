# HTTP/2 Attack Techniques

A protocol-level note series covering HTTP/2-specific attack techniques for web application and API security testing, built to the same depth and conventions as this repository's HTTP Request Smuggling (HTTP/1.1) and OWASP API Security Top 10 series. Increasingly relevant given that most modern API gateways and CDNs now speak HTTP/2 on the client-facing side by default.

## Scope

This series is deliberately scoped to **HTTP/2 protocol-level attacks** — not general web application vulnerabilities that happen to be delivered over HTTP/2. It assumes familiarity with this repository's existing HTTP Request Smuggling (HTTP/1.1) notes for the general CL.TE/TE.CL desync concept; this series covers what's unique to the HTTP/2 and downgrade context specifically.

## Files

| # | File | Covers |
|---|---|---|
| 1 | [`01-http2-protocol-fundamentals.md`](./01-http2-protocol-fundamentals.md) | Binary framing layer (frame structure field-by-field), stream multiplexing, HPACK header compression, and how HTTP/2 traffic differs from HTTP/1.1 in Burp Suite. Mechanism-first foundation for every other file. |
| 2 | [`02-rapid-reset-stream-exhaustion.md`](./02-rapid-reset-stream-exhaustion.md) | HTTP/2 Rapid Reset (CVE-2023-44487): why rapid stream-open/RST_STREAM cycles bypass `SETTINGS_MAX_CONCURRENT_STREAMS`, how this differs from traditional rate-limiting-based DoS, detection signals, and a real-world authorization checklist. **DoS technique — read the authorization notice before testing anything here.** |
| 3 | [`03-http2-downgrade-smuggling.md`](./03-http2-downgrade-smuggling.md) | HTTP/2-to-HTTP/1.1 downgrade smuggling: H2.CL/H2.TE desync mechanics, worked frame-level example, and HTTP/2-specific CRLF injection during downgrade rewriting. Cross-references the existing HTTP/1.1 smuggling series for the general concept. |
| 4 | [`04-hpack-compression-abuse.md`](./04-hpack-compression-abuse.md) | HPACK dynamic table mechanics and cross-contamination risk, CRLF-equivalent injection at the encoding-mechanics level, and CONTINUATION frame flood (resource exhaustion via unbounded header blocks). **Section 4 is a DoS technique — same authorization caveat as file 2 applies.** |
| 5 | [`05-tooling-h2spec-h2csmuggler-burp.md`](./05-tooling-h2spec-h2csmuggler-burp.md) | Full flag-by-flag breakdowns: h2spec (HTTP/2 conformance testing), h2csmuggler (h2c cleartext upgrade smuggling past misconfigured proxies), and Burp Suite HTTP/2 configuration (protocol forcing, raw newline injection, content-length/frame-length discrepancy testing). |
| 6 | [`06-cheatsheet-lab-mapping.md`](./06-cheatsheet-lab-mapping.md) | Consolidated technique summary table, command quick-reference, full PortSwigger Web Security Academy HTTP Request Smuggling lab mapping (Apprentice → Practitioner → Expert, with honest disclosure of which labs are HTTP/2-specific vs. HTTP/1.1-only despite "supporting" HTTP/2), and a consolidated real-world engagement checklist. |

## Conventions Used (Consistent With This Repository)

- Mechanism-first explanations — every technique explains *why* it works at the protocol level before showing any command or payload.
- Every command/frame example is broken down flag-by-flag or field-by-field — nothing is presented as "just send this."
- PortSwigger Web Security Academy lab mappings in strict Apprentice → Practitioner → Expert order, with explicit disclosure of coverage gaps rather than overclaiming.
- WAF/API gateway relevance addressed explicitly in every file where it applies — and explicitly stated as *not* meaningfully applicable where that's the honest answer (e.g., HPACK decoder implementation bugs in file 4).
- Real-world framing throughout, including a dedicated, explicit caution that DoS-style techniques (Rapid Reset, CONTINUATION flood) require separate written authorization for availability testing beyond a standard pentest scope — this is called out in files 2 and 4 and consolidated in file 6's engagement checklist.
- Full English only, no Bangla/Banglish, matching this repository's documentation standard.

## Primary Lab Environment

[PortSwigger Web Security Academy](https://portswigger.net/web-security) — HTTP Request Smuggling topic (see file 6 for the full lab mapping). Note the explicit coverage gap disclosed in file 6: Rapid Reset, CONTINUATION flood, and h2c smuggling do not currently have dedicated interactive Web Security Academy labs, since DoS-oriented techniques don't suit a shared public lab environment. Local test rigs and h2spec conformance probing are the realistic hands-on alternative for those specific techniques.

## Primary Tooling

- **Burp Suite Professional** — HTTP/2 protocol forcing per-request, raw newline injection via Inspector, HTTP/2 frame-level inspection.
- **h2spec** — HTTP/2 and HPACK conformance testing.
- **h2csmuggler** — h2c cleartext upgrade smuggling detection and exploitation.
