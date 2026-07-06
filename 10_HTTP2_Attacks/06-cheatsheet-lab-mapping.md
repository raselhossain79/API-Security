# HTTP/2 Attack Techniques — Cheatsheet and Lab Mapping

## How to Use This File

This is the consolidated quick-reference for the whole series. It assumes you've read files 1–5; it doesn't re-explain mechanisms, only summarizes them with pointers back to the relevant section. The lab mapping is the primary deliverable of this file — use it to sequence your PortSwigger Web Security Academy practice correctly.

---

## 1. Technique Summary Table

| Technique | Root Cause | File | Authorization Sensitivity |
|---|---|---|---|
| Rapid Reset (CVE-2023-44487) | Stream count limit (`SETTINGS_MAX_CONCURRENT_STREAMS`) measures concurrently-*open* streams, not cumulative open+reset rate; RST_STREAM lets a client discard a stream before server-side work completes, bypassing the limit. | File 2 | **High** — this is a DoS technique; requires explicit written availability-testing authorization. Never test on live/production targets or bug bounty programs without an explicit DoS-testing allowance. |
| H2.CL / H2.TE downgrade smuggling | Front-end trusts HTTP/2 frame-level length when reading the client request, but forwards a text `Content-Length`/`Transfer-Encoding` header to an HTTP/1.1 backend that trusts it literally — the downgrade rewrite step introduces the length ambiguity that HTTP/2 framing itself doesn't have. | File 3 | Low-to-moderate — same general caution as any request smuggling technique (can affect other users' sessions); not an availability-testing concern in itself. |
| HTTP/2 CRLF injection (downgrade context) | HPACK doesn't forbid `\r`/`\n` bytes inside header values; a downgrading front-end that fails to sanitize these before re-serializing to HTTP/1.1 text lets an attacker inject real header/request boundaries into the backend stream. | Files 3 & 4 | Low-to-moderate, same as above. |
| HPACK dynamic table cross-contamination | Implementation bug: dynamic table state is connection-scoped per RFC 7541, but a decoder that fails to correctly isolate per-stream references can let one client's header state leak into another's decoding. | File 4 | Low — primarily an implementation-correctness finding; requires the bug to actually be present, not exploitable by request crafting alone. |
| CONTINUATION flood | Decoder must buffer an entire header block until `END_HEADERS`; an attacker who never sends that flag forces unbounded buffering. | File 4 | **High** — this is also a DoS/resource-exhaustion technique; same authorization requirements as Rapid Reset apply. |
| h2c smuggling (proxy_pass misconfiguration) | Front-end blindly forwards an `Upgrade: h2c` handshake to the backend instead of terminating/rejecting it, letting the client establish a direct HTTP/2 cleartext tunnel to the backend that bypasses front-end access control entirely. | File 5 | Low-to-moderate — primarily an access-control bypass; verify scope covers the specific backend paths reached before pivoting into internal endpoints. |

---

## 2. Command Quick-Reference

```bash
# h2spec — full conformance suite against a TLS target, ignoring cert errors
./h2spec -h target.example -p 443 -t -k

# h2spec — scoped to RST_STREAM / stream-state tests only (Rapid Reset background)
./h2spec -h target.example -p 443 -t -k http2/6.4
./h2spec -h target.example -p 443 -t -k http2/5.1

# h2spec — HPACK conformance only (file 4 background)
./h2spec -h target.example -p 443 -t -k hpack

# h2csmuggler — check whether a front-end insecurely forwards h2c upgrades
./h2csmuggler.py -x https://edgeserver -t

# h2csmuggler — bulk-check a list of candidate paths
./h2csmuggler.py --scan-list paths.txt --threads 5 -t

# h2csmuggler — send a smuggled request past a confirmed-vulnerable edge
./h2csmuggler.py -x https://edgeserver -X POST -d '{"key":"value"}' \
  -H "Content-Type: application/json" -H "X-SYSTEM-USER: true" \
  http://backend/api/internal/endpoint

# h2csmuggler — brute-force internal backend paths via HTTP/2 multiplexing
./h2csmuggler.py -x https://edgeserver -i dirs.txt http://localhost/
```

**Burp Suite quick actions:**
- Force protocol per Repeater tab: Inspector → Request Attributes → Protocol → HTTP/1 or HTTP/2 (file 5, §3.2).
- Inject raw newline into a header value: Inspector → expand header row → place cursor in value → Shift+Return (file 5, §3.3; file 3, §5.2; file 4, §3.2).
- Enable h2c testing: Settings → Network → HTTP → "Enable HTTP/2 for cleartext (h2c) connections" (file 5, §3.1).

---

## 3. PortSwigger Web Security Academy — HTTP Request Smuggling Lab Mapping

This maps the **HTTP Request Smuggling** topic's full lab list in official difficulty order. Labs are grouped by difficulty tier (Apprentice → Practitioner → Expert), consistent with the standing convention across this whole GitHub note series. **Honest gap disclosure**, as always: several labs in this topic officially "support HTTP/2" in Burp, but the *intended solution* is HTTP/1.1-only — these are marked explicitly below so you don't waste time trying to force an HTTP/2 approach where the lab doesn't reward it. Only the labs marked **HTTP/2-specific** are genuinely relevant to this note series' techniques; the others are relevant to your existing HTTP/1.1 smuggling note series instead.

### Apprentice
*(The Request Smuggling topic on PortSwigger currently has no Apprentice-tier labs — the foundational CL.TE/TE.CL labs below are the entry point and are classified Practitioner by PortSwigger despite being the introductory labs for this topic.)*

### Practitioner

| Lab | Protocol Relevance | Notes |
|---|---|---|
| HTTP request smuggling, basic CL.TE vulnerability | HTTP/1.1-only intended solution (lab supports HTTP/2, but you must manually force Burp Repeater to HTTP/1 — file 5, §3.2) | Foundational; covered in your existing HTTP/1.1 smuggling series, not this one. |
| HTTP request smuggling, basic TE.CL vulnerability | HTTP/1.1-only intended solution, same caveat as above | Same as above. |
| **Response queue poisoning via H2.TE request smuggling** | **HTTP/2-specific** | Maps directly to file 3, Section 3.4 (H2.TE / response queue poisoning). Requires forcing Repeater to HTTP/2 explicitly. |
| **H2.CL request smuggling** | **HTTP/2-specific** | Maps directly to file 3, Section 3 (H2.CL desync mechanism, worked example). |
| **HTTP/2 request smuggling via CRLF injection** | **HTTP/2-specific** | Maps directly to file 3, Section 5 and file 4, Section 3 (Shift+Return newline injection technique). |
| **HTTP/2 request splitting via CRLF injection** | **HTTP/2-specific** | Same underlying primitive as the CRLF injection lab above, applied to a request-splitting rather than smuggling outcome — same technique from file 3 §5 / file 4 §3, different exploitation goal. |
| CL.0 request smuggling | HTTP/1.1-focused (a backend that ignores `Content-Length` entirely on requests it doesn't expect a body for); can have an HTTP/2 downgrade angle but the canonical lab is HTTP/1.1-oriented | Borderline relevant — worth attempting after file 3, since the "front-end/backend disagree about body presence" logic is conceptually adjacent to H2.CL, but this is not classified as HTTP/2-specific by PortSwigger. |
| HTTP request smuggling, obfuscating the TE header | HTTP/1.1-only | Not covered by this series; see your HTTP/1.1 smuggling notes. |

### Expert

| Lab | Protocol Relevance | Notes |
|---|---|---|
| Exploiting HTTP request smuggling to perform web cache poisoning | HTTP/1.1-only intended solution | Not this series' focus. |
| Exploiting HTTP request smuggling to perform web cache deception | HTTP/1.1-only intended solution | Not this series' focus. |
| **Bypassing access controls via HTTP/2 request tunnelling** | **HTTP/2-specific** | Builds on the H2.CL/H2.TE mechanism (file 3) applied specifically to bypass front-end access-control logic — attempt only after both Practitioner-tier H2.CL and H2.TE labs above. |
| **Web cache poisoning via HTTP/2 request tunnelling** | **HTTP/2-specific** | Combines the H2.CL/H2.TE mechanism (file 3) with cache-poisoning impact — if you've completed your existing web cache poisoning note series, this is the natural intersection point between that series and this one. |
| Client-side desync | Primarily an HTTP/1.1 browser-driven technique (exploiting normal, protocol-compliant `Content-Length` requests to desync a single-server site using a victim's own browser) | Not HTTP/2-specific, but conceptually related to the "protocol translation/trust boundary" theme of this series — worth knowing exists, not a core focus here. |
| Server-side pause-based request smuggling | HTTP/1.1-focused (timing-based desync exploiting how a server handles a paused/delayed request body) | Not HTTP/2-specific. |

### Recommended Practice Sequence for This Series Specifically

Given the honest gap disclosure above, if your goal is specifically HTTP/2 protocol-level competency (as opposed to completing the full Request Smuggling topic), attempt labs in this order:

1. **H2.CL request smuggling** (Practitioner) — the cleanest single-mechanism introduction to file 3's core desync.
2. **Response queue poisoning via H2.TE request smuggling** (Practitioner) — same family, different length-signal mismatch, higher-impact outcome (response capture).
3. **HTTP/2 request smuggling via CRLF injection** (Practitioner) — shifts from length-mismatch to the newline-injection primitive (file 3 §5 / file 4 §3); this is also where you'll first need the Shift+Return Inspector technique (file 5 §3.3).
4. **HTTP/2 request splitting via CRLF injection** (Practitioner) — same primitive as #3, different exploitation goal; good for confirming you understand the mechanism rather than having memorized one specific lab's steps.
5. **Bypassing access controls via HTTP/2 request tunnelling** (Expert) — first Expert-tier application of the mechanism, now aimed at access-control bypass rather than direct smuggling.
6. **Web cache poisoning via HTTP/2 request tunnelling** (Expert) — highest-complexity lab in this specific list; do this last, and only after your existing web cache poisoning note series' fundamentals are solid, since this lab assumes that background.

**Coverage gap, stated honestly:** PortSwigger's Web Security Academy does **not** currently have a dedicated interactive lab for Rapid Reset (CVE-2023-44487) or CONTINUATION flood — this makes sense given both are resource-exhaustion/DoS techniques, which aren't well-suited to a shared, always-on public lab environment (running either against a shared lab instance would degrade it for other users). For hands-on practice with files 2 and 4's DoS-oriented mechanisms, the realistic options are: (a) a local test rig you control (e.g., a local nginx or Envoy instance, or a small Go/Python HTTP/2 server you stand up yourself) combined with h2spec's relevant conformance test groups to confirm the presence/absence of protective caps, or (b) an authorized engagement with explicit availability-testing scope (file 2, Section 6). There is no substitute lab environment to point you to here, and claiming otherwise would be overclaiming coverage — this is a genuine gap between what PortSwigger's academy covers and what this note series covers.

Similarly, h2c smuggling (file 5, Section 2) has no dedicated PortSwigger Web Security Academy lab at present — the closest practical alternative is deliberately vulnerable local environments such as the workshop setups referenced in community write-ups pairing h2csmuggler against intentionally misconfigured nginx/HAProxy `proxy_pass` instances, or your own local test proxy configured with a bare `proxy_pass` directive to reproduce the misconfiguration yourself.

---

## 4. Real-World Engagement Checklist (Consolidated)

- [ ] Confirm target's actual protocol-negotiation behavior with both automatic ALPN and manually forced HTTP/1 vs. HTTP/2 in Burp Repeater (file 5, §3.2) — test both explicitly, never assume one implies the other.
- [ ] Run h2spec (scoped, not necessarily full-suite against production) to fingerprint implementation maturity before hand-crafting attacks (file 5, §1).
- [ ] For any downgrade-smuggling finding (file 3): identify and document the specific front-end/backend architecture (which component terminates HTTP/2, which speaks HTTP/1.1 onward) — this is essential for accurate remediation guidance, since the fix is almost always "stop downgrading" or "cross-validate length signals during rewrite," and the report needs to name the actual component responsible.
- [ ] For Rapid Reset or CONTINUATION flood (files 2 & 4, §4): confirm explicit written availability-testing authorization exists before any load-generating test; default to conformance-only probing (confirming absence of rate/size caps) rather than full exploitation unless authorization and a coordinated testing window are both confirmed.
- [ ] For h2c smuggling (file 5, §2): if a vulnerable tunnel is confirmed, clearly scope what internal endpoints were actually reached during testing — treat any successfully reached internal-only endpoint as a separate, individually-documented finding (internal admin panels, metadata endpoints, etc. each warrant their own severity assessment, not a single blanket "h2c smuggling" line item).
- [ ] Route every WAF/API-gateway-relevant finding to the correct remediation owner — these are overwhelmingly infrastructure/platform findings (proxy, CDN, gateway configuration), not application-code findings, and misrouting them to an application dev team wastes remediation time.

---

## 5. Series Index

1. `01-http2-protocol-fundamentals.md` — binary framing, multiplexing, HPACK, Burp HTTP/2 basics.
2. `02-rapid-reset-stream-exhaustion.md` — CVE-2023-44487 mechanism, detection, authorization requirements.
3. `03-http2-downgrade-smuggling.md` — H2.CL/H2.TE desync, CRLF injection in the downgrade context.
4. `04-hpack-compression-abuse.md` — dynamic table mechanics, CRLF-equivalent encoding mechanics, CONTINUATION flood.
5. `05-tooling-h2spec-h2csmuggler-burp.md` — full flag/usage breakdowns for all three tools.
6. `06-cheatsheet-lab-mapping.md` — this file.
