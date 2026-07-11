# API Security — Real-World Exploitation and Vulnerability Chaining

Capstone series for the API security note library. Assumes prior completion
of all 27 individual API security topic series (BOLA, BFLA, Broken
Authentication, BOPLA/Mass Assignment, GraphQL, JWT, OAuth 2.0, SSRF,
webhook security, API key security, API gateway security, race conditions,
WebSocket/SSE, SOAP/XML, HTTP/2 attack techniques, and the full OWASP API
Security Top 10 series, among others). This series does not re-teach any
individual vulnerability class — it teaches how to combine individually
lower-severity findings into high-impact, real-world chains, and how to
test, document, and report on those chains professionally.

Cross-references the separate `Real_World_Chaining_Notes/` (web application
chaining capstone) for general chaining concepts, generic report structure,
and CVSS fundamentals that are not repeated here. This series focuses only
on what is unique to API security.

Written entirely in English. No Bangla/Banglish content anywhere in this
series.

## File Index

| File | Contents |
|---|---|
| [`01_Overview_and_Chaining_Mindset.md`](01_Overview_and_Chaining_Mindset.md) | Why API chains differ structurally from web app chains; the output-to-input mental model; how CVSS scoring changes for chains; how to use this series while testing |
| [`02_API_Exploit_Chain_Patterns.md`](02_API_Exploit_Chain_Patterns.md) | All 10 real-world API exploit chains, each broken down link by link with PortSwigger/crAPI/HackTheBox practice mapping: BOLA+BFLA→account takeover; JWT algorithm confusion→RCE; OAuth redirect_uri bypass→account takeover; GraphQL introspection→privilege escalation; webhook→SSRF→cloud credential theft; deprecated version→mass exfiltration; leaked API key→database scrape; mass assignment→admin escalation; rate-limit bypass→brute force compromise; GraphQL batching→MFA bypass |
| [`03_Multi_Role_Testing_Methodology.md`](03_Multi_Role_Testing_Methodology.md) | Setting up multi-role sessions in Burp Suite (session handling rules, macros) and Postman (environments); the systematic cross-role test loop; identifying role-specific endpoints efficiently |
| [`04_Chain_Building_Methodology.md`](04_Chain_Building_Methodology.md) | Mapping the full API attack surface; tracking low-severity findings as chain candidates; the output-to-input primitive-matching table; API-specific chain opportunities (versioning, shadow endpoints, service-to-service trust) |
| [`05_Postman_Chain_Documentation.md`](05_Postman_Chain_Documentation.md) | Structuring collections as step-by-step exploit chains; full worked test-script example (Chain 1) broken down line by line; token refresh automation; exporting PoC evidence; testing collection vs. PoC collection |
| [`06_API_Specific_Report_Writing.md`](06_API_Specific_Report_Writing.md) | Documenting BOLA/BFLA impact concretely; two fully worked CVSS v3.1 examples for chains (including Scope: Changed justification); chain reproduction structure; evidence requirements; executive summary writing for non-technical stakeholders |
| [`07_Real_World_Adaptation.md`](07_Real_World_Adaptation.md) | WAF/API gateway behavior on live targets; handling short-lived tokens mid-chain; rate limiting during enumeration-heavy chains; diagnostic checklist for "should work but doesn't" situations |

## Recommended Reading/Testing Order

1. Read Part 1 for the mental model before touching a target.
2. Complete attack surface mapping (Part 4, Step 1) and run the cross-role
   test loop (Part 3) across the mapped surface.
3. Reference Part 2's ten patterns while reviewing logged findings for
   chain candidates, using Part 4's output-to-input methodology.
4. Once a chain is confirmed, rebuild it as a Postman PoC collection
   (Part 5) before writing it up.
5. Write the finding using Part 6's chain-specific report structure.
6. If a chain link behaves unexpectedly on a live target, work through
   Part 7's diagnostic checklist before concluding the link is patched.

## Practice Environments Referenced

- **PortSwigger Web Security Academy** — primary practice source; labs
  referenced by name in Apprentice → Practitioner → Expert order throughout
  Part 2, with honest gap disclosure where no direct lab exists.
- **crAPI (Completely Ridiculous API)** — primary supplementary environment
  for API-specific scenarios PortSwigger does not model (webhook-wrapped
  SSRF, API versioning, mass-assignable role fields, key-management BOLA).
- **HackTheBox** — secondary supplementary environment, particularly for
  API-focused machines combining multiple techniques in a single target.

## Related Series

- `Real_World_Chaining_Notes/` — web application chaining capstone (general
  methodology and report structure this series builds on)
- Individual API security series (BOLA, BFLA, JWT, OAuth, GraphQL, SSRF,
  webhook, API key, API gateway, race conditions, WebSocket/SSE, SOAP/XML,
  HTTP/2, and the full OWASP API Security Top 10 set)
