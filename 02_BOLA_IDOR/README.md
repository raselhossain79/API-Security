# Broken Object Level Authorization (BOLA) — Security Research Notes

**OWASP API Security Top 10 2023 — API1:2023 Broken Object Level Authorization**

This series is a GitHub-ready reference on BOLA, the single most common and most exploited
vulnerability class in production APIs today. It is written as a companion to the existing
Web Application Security note library, and assumes the reader already understands general
access control theory (see the separate Broken Access Control series for that foundation).
This series goes deeper into the API-specific angle: how BOLA differs from classic IDOR in
practice, how to test it across every ID format APIs actually use, and how to find it in the
places most testers miss.

## Why this vulnerability gets its own dedicated series

BOLA is not a new bug class. It is the same broken-authorization root cause that has existed
in web apps for two decades, re-surfacing in APIs because REST and GraphQL endpoints expose
object references far more directly and far more frequently than traditional server-rendered
pages ever did. Every API endpoint that accepts an object identifier is a candidate BOLA
target, and modern applications can have hundreds of such endpoints. Industry API security
reports consistently rank BOLA as the top real-world finding in API penetration tests and bug
bounty submissions, ahead of injection, ahead of broken authentication, ahead of everything
else in the API Top 10.

## File index

| File | Contents |
|---|---|
| `01-BOLA-Overview-and-Concepts.md` | What BOLA is, root cause, BOLA vs IDOR distinction, horizontal vs cross-tenant framing, why APIs make this worse |
| `02-Testing-Methodology.md` | Manual step-by-step testing methodology — horizontal privilege escalation and cross-tenant BOLA covered as distinct workflows |
| `03-ID-Types-and-Bypass-Techniques.md` | Testing technique per ID type: sequential integers, UUID/GUID, hashed IDs, encoded IDs; indirect references in bodies and response fields; BOLA via HTTP method |
| `04-Burp-Suite-Testing-Workflow.md` | Practical Burp Suite Community Edition workflow: manual differential testing, Repeater, Intruder, Autorize, Match and Replace |
| `05-BOLA-Cheatsheet.md` | Compressed reference — checklist, payload patterns, request/response signals, PortSwigger and crAPI lab index |

## Conventions used throughout this series

- Every request and every script is broken down piece by piece — what changed, and why that
  specific change is what bypasses the authorization check.
- Lab references to PortSwigger Web Security Academy are listed in official
  difficulty-progression order, with an honest note wherever PortSwigger's coverage is thin.
  PortSwigger's Access Control category has one lab explicitly titled IDOR and several more
  "User ID controlled by request parameter" labs that are functionally BOLA scenarios once
  reframed against an API. It does **not** have a dedicated multi-tenant / cross-tenant BOLA
  lab, a native JSON-body object-reference lab, or a GraphQL BOLA lab — those gaps are filled
  with OWASP crAPI, which is purpose-built around API-native BOLA scenarios.
- Every file includes a real-world industry framing section connecting the technique to
  disclosed vulnerabilities or well-documented incident patterns.
- Written entirely in English, structured for direct upload to GitHub.

## Suggested reading order

Read the files in numeric order the first time through. After that, `05-BOLA-Cheatsheet.md`
is meant to stand alone as the fast-reference file during live engagements.
