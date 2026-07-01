# API Fundamentals for Pentesting — Overview

> This is the prerequisite folder for the API Security note series. Read this entire
> folder BEFORE starting any topic in API_Security_Notes/. It covers API-specific
> concepts that are NOT in Web_Fundamentals_Notes/ — so read that folder first, then
> this one.

---

## What Web_Fundamentals_Notes Already Covers (Don't Re-Read)

- HTTP/HTTPS request-response anatomy → `01_HTTP_HTTPS_Fundamentals.md`
- HTTP headers (including auth headers like Authorization, Content-Type) → `02`
- Cookies and sessions → `03`
- Same-Origin Policy (CORS, CSRF, clickjacking basis) → `04`
- URL structure and encoding → `05`
- Web architecture, DOM, REST briefly introduced → `06`
- Burp Suite basics (Proxy, Repeater, Intruder, Decoder) → `07`
- Networking basics (DNS, TCP, ports) → `08`

All of that applies directly to API testing too. This folder does NOT repeat it.

---

## What This Folder Adds (API-Specific Gaps)

| File | Covers |
|---|---|
| `01_API_Types_and_Structures.md` | REST, GraphQL, SOAP, gRPC, WebSocket — what each is, how requests look, how they differ for testing |
| `02_JSON_and_Data_Formats.md` | JSON structure, XML, Protobuf basics — the data formats you'll manipulate in every API test |
| `03_API_Authentication_Overview.md` | Bearer tokens, API keys, OAuth flow overview, JWT structure — mechanism-first, before the attack notes |
| `04_Reading_API_Documentation.md` | OpenAPI/Swagger, Postman collections, GraphQL schemas — how to extract a full attack surface from docs |
| `05_Burp_Suite_for_API_Testing.md` | API-specific Burp setup: JSON handling, GraphQL interception, configuring for non-browser API traffic |
| `06_Postman_Basics_for_Pentesters.md` | Setting up collections, environments, variables — the minimum Postman needed before the tooling note |

---

## Reading Order

```
Web_Fundamentals_Notes/ (all 8 files) → then this folder: 01 → 02 → 03 → 04 → 05 → 06
```

After this folder, start `API_Security_Notes/` from topic #1 (API Recon).

---

## Why This Folder Is Shorter Than Web_Fundamentals

Web fundamentals had 8 files because it had to build everything from scratch —
HTTP, browsers, cookies, encoding, networking. By the time you're here, all of that
is already done. This folder only fills the genuine API-specific gaps: data formats,
API-specific auth mechanisms, how to read API documentation, and how to configure your
tools differently for APIs vs traditional web apps.
