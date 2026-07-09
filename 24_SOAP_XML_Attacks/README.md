# SOAP/XML API Security Testing — Note Series

A GitHub-ready note series on testing SOAP and XML-based APIs, built for legacy and enterprise engagements where SOAP backends remain common (banking cores, insurance platforms, government portals, healthcare systems, telecom billing, B2B/EDI integration layers). Written to the same depth and conventions as the accompanying web application and OWASP API Security Top 10 note series: mechanism-first explanations, every payload/command broken down piece by piece, explicit WAF/API Gateway relevance sections with honest non-applicability statements where warranted, and PortSwigger lab mapping in strict Apprentice → Practitioner → Expert order with honest gap disclosure where dedicated SOAP labs don't exist.

## Files

| # | File | Covers |
|---|---|---|
| 1 | [`01-soap-wsdl-fundamentals.md`](01-soap-wsdl-fundamentals.md) | SOAP envelope structure (Envelope/Header/Body), SOAP Faults, WSDL anatomy (types/message/portType/binding/service), SOAPAction header, SOAP 1.1 vs 1.2, common endpoint conventions and stack fingerprinting |
| 2 | [`02-xxe-via-soap.md`](02-xxe-via-soap.md) | Why SOAP is a high-yield XXE target, identifying injectable Body parameters, DOCTYPE injection at the envelope level, confirmation workflow, SSRF pivoting via internal-network SOAP backends. Cross-references the XXE web app series for core entity-injection theory rather than duplicating it |
| 3 | [`03-soap-injection-ws-security.md`](03-soap-injection-ws-security.md) | SOAP structural tag injection with a full worked privilege-escalation example, WS-Security header purpose (auth/signing/encryption), testing for missing/unenforced WS-Security, signature-tampering tests, replay attacks against timestamped messages |
| 4 | [`04-wsdl-enumeration-injection-methodology.md`](04-wsdl-enumeration-injection-methodology.md) | Manual WSDL enumeration workflow, building a complete operation/parameter inventory, converting WSDL to testable formats, SQL injection via SOAP parameters, OS command injection via SOAP parameters, XML-escaping requirements specific to injecting into SOAP element text |
| 5 | [`05-tooling-soapui-wsdl2postman.md`](05-tooling-soapui-wsdl2postman.md) | Full SoapUI workflow (WSDL import, auto-generated request templates, WS-Security configuration UI, Burp proxy integration, bundled sample services) and full wsdl2postman workflow (conversion process, generated collection structure, Postman/Burp integration, key limitations vs SoapUI) |
| 6 | [`06-cheatsheet.md`](06-cheatsheet.md) | Condensed final reference: recon checklist, envelope/payload quick reference, WAF/Gateway bypass summary table, lab progression summary, tooling one-liners |

## How This Series Fits With the Others

- **XXE fundamentals** (entity types, OOB exfiltration, XXE→RCE chains) live in the existing XXE web app series — file 2 here covers only the SOAP-specific delivery mechanism, not the underlying theory.
- **SQL injection and OS command injection technique libraries** (UNION-based, blind, time-based, error-based; full payload/evasion catalogs) live in the existing SQLi and OS Command Injection series — file 4 here covers only SOAP-specific delivery and the XML-escaping requirements that trip testers up when translating known-working REST/form payloads into SOAP parameters.
- This series assumes familiarity with general web app injection testing and focuses purely on what changes when the transport/format is a SOAP envelope instead of REST/JSON or HTML forms.

## Supplementary Practice (Honest Disclosure)

Dedicated SOAP labs are limited on PortSwigger Web Security Academy — there is currently no SOAP-native lab track. Each file maps the closest applicable labs (primarily from the XXE topic, plus general SQLi/CMDi/authentication tracks) in correct Apprentice → Practitioner → Expert progression, and states explicitly where no direct equivalent exists rather than forcing a weak mapping.

- **SoapUI's bundled sample/practice services** — useful for tooling and envelope-syntax familiarization, not for vulnerability-finding practice (they are functional demo services, not intentionally vulnerable targets).
- **TryHackMe** — general XML/SOAP-adjacent rooms build partial, transferable mechanism knowledge; no dedicated SOAP-injection or WS-Security room currently exists on the platform.
- **crAPI** is explicitly **not applicable** to this series — it is REST-only and does not expose SOAP endpoints, unlike its role as standard supplementary practice in the OWASP API Security Top 10 series.

## Conventions Used Throughout

- Mechanism explained before technique — every file assumes you need to understand *why* something works, not just the payload to paste.
- Every XML payload and tool command is broken down piece by piece.
- WAF/API Gateway relevance is addressed explicitly in every applicable file, including honest statements of low/non-relevance where the attack class isn't primarily a signature-detection problem (e.g., WS-Security enforcement gaps).
- Each file closes with a "Real-World Notes" section reflecting practical engagement experience rather than pure theory.
- Written in full English throughout, GitHub-ready formatting (standard Markdown, no external dependencies).
