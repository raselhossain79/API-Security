# BOLA Cheatsheet — Fast Reference

Quick-reference companion to the full series. Use this file live during engagements; refer
back to files 01–04 for full explanations.

## Core test (memorize this)

Same account/token. Change **only** the object ID. Everything else byte-identical. A 200 with
the other identity's real data = confirmed BOLA.

## Pre-engagement checklist

- [ ] Two accounts, same tenant, each owning at least one object per resource type (horizontal)
- [ ] Two accounts, **independently registered separate tenants** (cross-tenant)
- [ ] Object ID/ownership table recorded for both account sets before testing starts
- [ ] Full app/API traffic captured in Proxy history logged in as every test account
- [ ] OpenAPI/Swagger spec pulled if available, to catch undocumented-in-UI endpoints

## Testing checklist per endpoint

- [ ] Baseline request confirmed working for the owning account
- [ ] Object ID swapped to foreign identity's object, same token → check response
- [ ] Repeated for **every** HTTP method the resource supports (GET/POST/PUT/PATCH/DELETE)
- [ ] Every object-reference field checked independently if the body has more than one
- [ ] Response body read in full — not just status code — for partial-leak-on-"rejection" cases
- [ ] Multi-step flows: intermediate reference from Account A tested against final step as
      Account B, and vice versa
- [ ] For cross-tenant: both the URL/header tenant parameter *and* the underlying object-lookup
      logic tested separately

## ID type → technique quick map

| ID type | Example | Technique |
|---|---|---|
| Sequential integer | `/orders/8841` | Enumeration (Burp Intruder, Numbers payload) |
| UUID / GUID | `/vehicle/5704f6d9-...` | Disclosure-based — find it leaked elsewhere, never brute-force |
| Hashed | `/documents/a94a8fe5...` | Disclosure-based; check for weak/reversible encoding masquerading as a hash |
| Encoded (base64 etc.) | `/profile/NDQ3MQ==` | Decode → modify underlying value → re-encode |
| Multi-layer encoded | base64(json) / base64(hashid) | Decode one layer at a time before concluding format |

## Non-obvious locations checklist

- [ ] URL path segment (`/api/orders/{id}`)
- [ ] Query string (`?order_id=`)
- [ ] JSON request body, top-level fields
- [ ] JSON request body, **nested** fields (easy to skim past)
- [ ] Reference issued in one response, consumed in a later request (workflow/session tokens)
- [ ] Headers (`X-Object-Id`, `X-Resource-Ref`)
- [ ] GraphQL variables / node IDs, if the API exposes GraphQL

## Severity quick guide

| Scenario | Typical severity driver |
|---|---|
| Horizontal, read-only, low-sensitivity data | Medium |
| Horizontal, read-only, PII/financial data | High |
| Horizontal, write/delete capability | High |
| Cross-tenant, read-only | High–Critical |
| Cross-tenant, write/delete capability | Critical |

Always state explicitly in a report how you proved cross-tenant scope (two independently
registered organizations, not two invited users) — this is what justifies the higher rating.

## Burp Suite Community Edition toolchain

- **Repeater** — manual differential test (baseline tab vs swapped-ID tab)
- **Intruder** — sequential ID enumeration only (Numbers payload type)
- **Autorize** (BApp Store, free) — automates the differential comparison across full traffic;
  always manually verify "Bypassed" results by reading the actual response body
- **Match and Replace** — swap tokens/headers automatically for repetitive tests; disable when
  not actively using it

## PortSwigger Web Security Academy — lab index (progression order)

1. User ID controlled by request parameter
2. User ID controlled by request parameter, with unpredictable user IDs
3. User ID controlled by request parameter with data leakage in redirect
4. User ID controlled by request parameter with password disclosure
5. Insecure direct object references

**Gap:** no multi-tenant, no JSON-body reference, no multi-method lab. Filled by crAPI below.

## crAPI — lab index (fills API-native and cross-tenant gaps)

1. Access another user's vehicle location (GUID, disclosure-based via community feed)
2. Access another user's mechanic report (`report_id`, sequential horizontal escalation)
3. Access another user's order details (`order_id`, sensitive data exposure)

## One-line technique summary per file

- **01** — BOLA = IDOR's root cause, API-native context and terminology; horizontal vs
  cross-tenant differ in scope and proof requirements, not mechanism.
- **02** — Manual methodology: build test accounts first, swap only the ID, test every method,
  read full response bodies, treat cross-tenant as a separate hunting pattern.
- **03** — Technique differs by ID format: enumerate sequential, disclose UUID/hash/GUID,
  decode-modify-reencode encoded IDs; hunt bodies, response-issued references, and methods too.
- **04** — Repeater for manual proof, Intruder only for sequential IDs, Autorize to scale the
  differential comparison, Match and Replace for repetitive token swaps.
- **05** — This file. Keep it open during live testing.
