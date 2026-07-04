# API Reconnaissance and Endpoint Discovery — Overview and Methodology

## 1. What This Topic Actually Is

API reconnaissance is the process of mapping the full attack surface of an API
before any exploitation attempt begins: every endpoint, every HTTP method each
endpoint accepts, every parameter each endpoint takes, every API version still
reachable, and every piece of documentation that leaks structural information
about the backend.

This is not a vulnerability class in the way SQLi or XSS are. It is a
**methodology phase**. Nearly every API vulnerability you will later exploit
(BOLA, mass assignment, broken function-level authorization, injection) requires
you to first know an endpoint exists and what it expects as input. Skipping or
rushing this phase is the single most common reason API pentests miss critical
findings — testers hammer the 15 endpoints in the Swagger file they were handed
and never discover the 40 that aren't documented.

## 2. Why Recon Is Different for APIs Than for Web Apps

In traditional web app testing, the UI itself functions as a partial map of the
application — you can click through pages and see what exists. APIs have no UI.
The only "map" is either:

- Documentation the client gives you (often incomplete or outdated), or
- What you can independently discover.

This makes API recon more investigative and less visual. You are reconstructing
a map from fragments: JavaScript files, cached pages, certificate logs, spec
files left exposed by accident, and brute-force enumeration.

## 3. Methodology Flow

The order below is deliberate. Passive techniques come first because they are
silent, free, and non-intrusive — you learn as much as possible before you ever
send a single unexpected request to the target.

```
1. Passive Recon
   ├── Search for exposed Swagger/OpenAPI specs
   ├── Mine JavaScript files for endpoint references
   ├── Google dork for documentation and leaked specs
   ├── Query Wayback Machine for historical endpoints
   └── Query certificate transparency logs for API subdomains
        │
        ▼
2. Documentation Analysis
   ├── If a spec was found, extract every endpoint/parameter/schema from it
   └── Cross-reference documented endpoints against what the client scoped
        │
        ▼
3. Active Discovery
   ├── Brute-force directories/endpoints against a wordlist
   ├── Enumerate HTTP methods per discovered endpoint
   ├── Discover hidden parameters on known endpoints
   ├── Fuzz content-types where behavior differs
   └── Use response codes (404/401/403) to infer existence vs. access control
        │
        ▼
4. Shadow API & Zombie Endpoint Identification
   ├── Check for older API versions still live (v1 still up when v3 is current)
   ├── Look for undocumented admin/internal paths
   └── Look for test/debug/staging endpoints left in production
        │
        ▼
5. Consolidate into a full endpoint map before moving to exploitation phases
```

You move top to bottom, but recon is not strictly linear in practice — a
JavaScript file found during passive recon might reveal a parameter name you
then fuzz for during active discovery, and a discovered `/v2/` endpoint might
prompt you to check whether `/v1/` and `/v3/` also exist.

## 4. Scoping Considerations

Before touching a target:

- Confirm whether subdomain enumeration is in scope. Certificate transparency
  log queries touch domains you may not have explicit permission to test if the
  engagement is scoped to a single host.
- Confirm whether active brute-forcing (high request volume) is acceptable —
  some engagements specify rate limits or blackout windows.
- If historical/Wayback data reveals endpoints outside the current scope
  boundary (e.g., a decommissioned subdomain), flag it to the client rather than
  testing it unprompted.

## 5. WAF / API Gateway Relevance — Read This Before the Other Files

Unlike topics such as SQL injection or XSS, **WAF/API Gateway bypass is only
partially relevant to reconnaissance**, and it's important to be precise about
where it does and doesn't apply rather than bolting on a generic bypass section
to every file.

**Where it IS relevant:**
- **Active discovery (brute-forcing, fuzzing)** can trigger rate-limiting,
  IP-based blocking, or bot-detection at the gateway level. A gateway may throttle
  or block a source IP that sends thousands of requests to guess endpoint names
  in a short window. This is covered in detail in `03_Active_Discovery.md` and
  in the tooling file, since the mitigations (delay/throttle tuning, header
  rotation, distributing requests) are a discovery-phase concern, not an
  exploitation-phase one.
- **Some gateways return a uniform "not found" response for both truly missing
  and access-denied endpoints** specifically to defeat the 404/401/403
  inference technique described in this series. This is a direct
  detection-relevant countermeasure and is covered where that technique is
  introduced.

**Where it is NOT meaningfully relevant:**
- **Passive recon** involves no direct interaction with the target's live
  defenses at all — you are querying third-party services (Wayback Machine,
  certificate transparency logs, search engines) or reading already-public
  JavaScript files. There is no WAF to bypass because you are not sending
  anomalous traffic to the target's own infrastructure.
- **Documentation analysis** is reading a file you already have. No live
  request pattern is involved.
- There is no analog here to a WAF "detecting a SQLi payload" — recon
  techniques aren't payloads, they're enumeration patterns, so the
  detection/bypass framing that applies to injection-class vulnerabilities
  doesn't map onto most of this topic. Where it genuinely does apply (rate
  limiting during brute-force), that section says so explicitly rather than
  implying a bypass exists everywhere.

## 6. Practice Environments

### PortSwigger Web Security Academy — Limited Direct Coverage

This is stated honestly rather than glossed over: **PortSwigger Academy does
not have a dedicated lab category for "API recon."** The Academy's API-labeled
labs focus on exploiting BOLA, mass assignment, and server-side parameter
pollution in APIs — they assume you already have the endpoint map, since the
lab hands you the relevant endpoints in the lab description. There is no
Apprentice → Practitioner → Expert progression for endpoint discovery itself.

The closest applicable labs (useful for the "documentation analysis" and
"parameter discovery" sub-skills, even though they're framed as exploitation
labs) are:

| Difficulty | Lab | Relevance to Recon |
|---|---|---|
| Apprentice | *Exploiting an API endpoint using documentation* | Directly relevant — this lab is the closest thing PortSwigger has to a recon exercise. You're given a spec and must read it to find an endpoint that isn't used by the visible application. |
| Practitioner | *Finding and exploiting an unused API endpoint* | Requires discovering an endpoint not referenced by the front-end — a shadow/undocumented endpoint scenario. |

Beyond these two, Academy labs assume discovery is already done. This series
therefore leans on external environments for hands-on discovery practice.

### crAPI (Completely Ridiculous API) — OWASP

crAPI is a deliberately vulnerable, Docker-deployable API application built
specifically to practice API security testing end to end. For recon practice
specifically, it's useful because:
- It ships with a real Swagger/OpenAPI-documented set of endpoints alongside
  undocumented ones, so you can practice diffing "what's documented" against
  "what's actually reachable."
- It has multiple microservices (community, identity, workshop) with
  inter-service API calls, giving you a realistic multi-host API surface to map
  rather than a single flat list of endpoints.
- It includes shadow/legacy-style endpoints intentionally, making it one of the
  few free environments where you can practice zombie-endpoint identification
  hands-on.

### HackTheBox — API-Focused Challenges and Machines

HTB doesn't have a single "API recon" category, but several challenges and
machines are built around API enumeration as the primary skill tested:
- Challenges in the "Web" category periodically require finding an
  undocumented API version or admin endpoint before any exploitation is
  possible — the box is unsolvable without doing recon properly first.
- HTB's realistic, non-labeled environments (unlike PortSwigger, which tells
  you it's an "API lab") force you to first recognize you're dealing with an
  API at all, then map it — closer to real client engagements than either
  PortSwigger or crAPI.

**Recommended practice order:** PortSwigger's two applicable labs first (to
understand the exploitation payoff of good recon), then crAPI (structured,
repeatable practice with a known-vulnerable target), then HTB API-relevant
boxes (unstructured, realistic practice).

## 7. Real-World Notes

- On real engagements, the biggest recon win is almost never brute-forcing —
  it's finding an exposed Swagger file or a JS bundle with hardcoded endpoint
  strings. Spend real time on passive recon before burning time and request
  budget on active discovery.
- Clients frequently under-scope their own API. It is common to find that the
  Swagger file they handed you documents 30 endpoints, while JS mining and
  brute-forcing reveal 80+ live routes, many undocumented. This gap is often
  the most valuable finding in the entire engagement, independent of any single
  vulnerability found later.
- Mobile app APIs are a common blind spot: many organizations only think about
  their web-facing API when scoping a pentest, forgetting that their mobile app
  talks to the same backend (often with additional undocumented endpoints).
  Decompiling the mobile app or proxying its traffic is out of scope for this
  series but worth flagging to a client if in scope.
