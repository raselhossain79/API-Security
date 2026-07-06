# HTTP/2 Rapid Reset and Stream-Based Resource Exhaustion (CVE-2023-44487)

> **Authorization requirement, stated up front:** Everything in this file describes an availability-impacting (denial-of-service) technique. Do not run any Rapid-Reset-style test — even a "low volume" or "just checking" version — against any target, including client production systems, staging environments, or third-party infrastructure, without **explicit written authorization that specifically covers availability/DoS testing**. Standard web/API pentest scope language ("test for vulnerabilities in the application") does **not** automatically cover this. See Section 6 for what to actually put in a scope agreement before you touch this technique on a real engagement. If you want to practice the mechanism hands-on, do it against infrastructure you own (a local nginx/Envoy/h2spec test rig), not a shared lab or bug bounty target's live environment, unless the program explicitly whitelists DoS/rate-limit testing.

---

## 1. What CVE-2023-44487 Actually Is

CVE-2023-44487, publicly disclosed in October 2023, is not a bug in one specific piece of software — it's a **protocol-level design gap** in how HTTP/2 servers were commonly implemented to handle stream cancellation. It affected essentially every major HTTP/2 server implementation at the time (nginx, Apache httpd, IIS, most Go and Java HTTP/2 libraries, cloud load balancers) because they all made the same reasonable-looking implementation assumption, which turned out to be exploitable. Google, Cloudflare, and AWS all reported this being used to generate the largest volumetric DDoS attacks observed up to that point.

---

## 2. The Mechanism, Step by Step

### 2.1 Prerequisite: Recall `SETTINGS_MAX_CONCURRENT_STREAMS`

From file 1, Section 3.2: a server advertises `SETTINGS_MAX_CONCURRENT_STREAMS` (commonly 100–128) to cap how many streams a single client can have **open at the same time** on one connection. This setting exists specifically to bound per-connection resource usage — the server allocates some amount of memory/state/thread-pool-slot per open stream, and this setting is the safety valve.

### 2.2 The Attack Sequence

The attack — sometimes called "Rapid Reset" — works like this, and every step matters:

1. The client opens an HTTP/2 connection (one TCP + TLS handshake).
2. The client sends a `HEADERS` frame on a new stream (say, stream ID 1) — this is a normal-looking request, e.g., `GET /api/search?q=x`.
3. **Immediately**, without waiting for any response, the client sends an `RST_STREAM` frame on that same stream ID (stream 1), which per the HTTP/2 spec (RFC 9113 §6.4) tells the server "abandon this stream, I don't want the response, stop processing it."
4. The client repeats steps 2–3 thousands of times per second, each time using a new odd-numbered stream ID (3, 5, 7, 9, ...), all on the **same single TCP connection**.

### 2.3 Why This Bypasses `SETTINGS_MAX_CONCURRENT_STREAMS`

Here is the actual exploit condition, spelled out explicitly because this is the part that's easy to hand-wave past:

- `SETTINGS_MAX_CONCURRENT_STREAMS` limits how many streams can be **open at once**.
- `RST_STREAM` immediately closes the stream from the client's perspective — the client is done with it the instant it sends the reset.
- Because the client resets the stream *before the server has necessarily finished processing the request*, the client-visible "open stream count" never has a chance to build up against the limit. From the client's side, each stream's lifetime is: open → (server starts processing) → client resets → closed. The client can start the next stream immediately because, as far as the *stream count* is concerned, the previous one is already gone.
- But the **server-side work triggered by step 2 (routing the request, allocating a backend connection or worker thread, possibly opening a database query, logging, etc.) does not necessarily stop the instant the RST_STREAM arrives.** Many server implementations process the incoming HEADERS frame, hand the request off to an application-layer handler (a servlet, a Go handler goroutine, a backend proxy connection), and that handoff is not free to instantly cancel. The server has already committed CPU cycles, memory, and sometimes a backend connection to work that the client discarded before it even started.
- Net effect: the client can generate an essentially unbounded number of "request → immediate cancel" cycles on a single connection, each one costing the server real processing resources, without ever tripping the concurrent-stream-count safety valve, because that valve only measures streams that are simultaneously *open*, not the cumulative rate of streams *opened-and-reset*.

### 2.4 Why This Is Fundamentally Different From Traditional Rate-Limiting-Based DoS

This distinction is the crux of understanding why Rapid Reset needed a new class of mitigation rather than being caught by existing defenses:

| Traditional volumetric/rate-based DoS | Rapid Reset |
|---|---|
| Attacker sends a high **rate of complete requests** (e.g., thousands of full GET requests per second) — visible as high requests-per-second from a given source, easy to catch with connection-level or IP-level rate limiting ("no more than N requests/sec from this client"). | Attacker opens **one connection** and generates thousands of streams/sec on it, but each stream is cancelled by the client itself before completing — the "requests" a naive request-counter would see are actively withdrawn by the client, so a defense that counts *completed or in-flight* requests per connection may never see the count exceed the concurrent-stream limit. |
| Scales primarily with the number of source connections/IPs an attacker can muster — mitigations like per-IP rate limits, SYN cookies, and connection-count caps are effective. | Scales with how fast a *single* connection can pump stream-open/stream-reset cycles — a single client machine, or even a small number of attacker-controlled connections, can generate a very high absolute rate of server-side work, because TCP/TLS handshake overhead (normally the expensive, rate-limiting part of opening new connections) is paid **once** per connection, not once per "request." |
| Amplification typically comes from botnets (many source IPs) or reflection (spoofed source, third-party amplifier). | Amplification comes from the **asymmetry between client cost and server cost per stream**: sending a HEADERS frame + an RST_STREAM frame is cheap for the client (a few dozen bytes, no need to read or process any response), while the server-side cost of routing, allocating, and beginning to process the request is comparatively expensive. This ratio is the entire exploit. |
| Detected by looking at request *volume* patterns (requests/sec, unique paths hit, response codes). | Often invisible to request-volume-based detection because the "requests" never complete — detection needs to look at **stream open/reset ratio per connection** and **RST_STREAM frequency**, which most conventional WAF/API gateway logging pipelines were not instrumented to track before October 2023. |

The practical consequence: an attacker does not need a botnet. A modest number of machines (sometimes even one, depending on server-side per-stream cost) opening a handful of HTTP/2 connections and abusing this pattern can generate the same order of server-side load as a much larger traditional volumetric attack — this is exactly why the disclosure described it as producing "record-breaking" DDoS traffic with comparatively few attacking IPs.

---

## 3. Detection — Recognizing This From the Server/Defender Side

Since your work sits on both the offensive (pentest) and eventual authorized-DoS-testing side, it's worth understanding what defenders look for, because this doubles as what you should watch for as evidence a test is actually exercising the vulnerable condition, versus just generating harmless noise:

- **High ratio of RST_STREAM frames to completed responses on a single connection.** A legitimate client essentially never resets streams it just opened, at high frequency, before receiving any response.
- **Stream churn rate per connection** — number of streams opened-and-closed per second per connection, independent of concurrent-stream count. This is the metric that concurrent-stream-count limits do not capture.
- **Connection-level request-processing CPU/memory cost outpacing the apparent completed-request count** — i.e., the server is doing far more backend work than the number of responses it's actually sending would suggest, because most of the requests are being cancelled mid-flight.

Mitigations deployed post-disclosure (relevant for you to know when scoping a WAF-bypass conversation, Section 5) generally fall into:
1. Capping the **rate** of stream resets per connection, not just concurrent stream count (e.g., closing the connection outright if RST_STREAM frequency exceeds a threshold).
2. Making stream cancellation server-side "free" faster — reducing the window between HEADERS receipt and the point where an RST_STREAM can actually stop backend work, so the asymmetry in Section 2.3 shrinks.
3. Some gateways cap total streams **created** per connection over its lifetime (not just concurrently open), forcing a full reconnect (with its TCP/TLS handshake cost) periodically, which restores much of the "connection cost" the attack was bypassing.

---

## 4. Why You Test This Differently Than Other Vulnerability Classes

Every other technique in this note series (SQLi, XSS, SSRF, JWT attacks, BOLA, etc.) is fundamentally about proving a **logic or trust boundary failure** using a small number of controlled, low-impact requests — you send a handful of crafted requests, observe a response, and you have your proof of concept without meaningfully affecting the target's availability for other users.

Rapid Reset is different in kind: **the proof of concept *is* the impact.** You cannot demonstrate the vulnerability exists without generating a resource-exhaustion condition on the target, because the vulnerability is defined by the resource-exhaustion effect itself — there's no "safe," low-volume way to show "yes, this pattern would exhaust resources at scale" without actually approaching that scale. This is precisely why availability testing requires separate, explicit authorization beyond a general pentest scope, and why the responsible approach on a real client engagement is almost always one of:

- Test against a **staging/non-production replica** with production-equivalent HTTP/2 server configuration, if the client can provide one.
- Do a **conformance check only** (using h2spec or a manual low-volume probe — see file 5) to confirm the server *would* accept the pattern (i.e., it doesn't already reject rapid RST_STREAM sequences or cap stream-creation rate), without actually driving load high enough to cause real impact — and report the finding as "the server does not appear to rate-limit stream resets; full exploitation was not performed against production per engagement scope."
- If genuine load testing is required and authorized, coordinate timing with the client's operations team, have a rollback/kill-switch plan, and treat it with the same care as a production database load test — because that's effectively what it is.

---

## 5. WAF / API Gateway Relevance

This is directly relevant, unlike some sub-techniques in this series where WAF bypass doesn't meaningfully apply.

**Detection methods a WAF/API gateway realistically uses:**
- Per-connection RST_STREAM rate thresholds (close the connection if resets-per-second on a single connection exceeds X).
- Per-connection stream-creation rate thresholds (distinct from concurrent-stream limits) — some gateways now track "streams opened in the last N seconds" as its own metric rather than relying solely on `SETTINGS_MAX_CONCURRENT_STREAMS`.
- Behavioral heuristics: a client that never reads response data before resetting is a strong signal, since legitimate clients (browsers, API SDKs) essentially never do this at volume.

**Realistic bypass considerations (for authorized testing/reporting purposes only):**
- **Distributing the pattern across many connections/source IPs**, each individually staying under a per-connection threshold, defeats connection-scoped rate limiting but reintroduces exactly the volumetric-attack cost profile (many connections, many IPs) that the technique was originally designed to avoid — meaning at that point you've converted it back into a traditional volumetric DoS, which is easier for upstream network-level defenses (Cloudflare, AWS Shield, etc.) to catch.
- **Interleaving legitimate-looking requests** among the rapid-reset streams on the same connection to reduce the RST_STREAM-to-total-stream ratio and stay under behavioral heuristic thresholds — this reduces the achievable exhaustion rate proportionally, so it's a real trade-off for an attacker, not a free bypass.
- **Testing against gateways with known immature or absent Rapid-Reset-specific mitigations** — smaller/self-hosted API gateways, older nginx/Apache versions predating the October 2023 patches, or custom HTTP/2 server implementations that never applied the community-wide mitigation guidance, remain the highest-risk targets. Part of your job in an authorized assessment is confirming whether the specific gateway version and configuration in front of the client's APIs actually received the relevant patch — many organizations patched their edge CDN/load balancer but never checked whether an internal API gateway sitting behind it (which may also terminate HTTP/2 independently) received equivalent protection.

**Reporting note:** because this is a protocol/infrastructure-level finding rather than an application logic bug, the remediation owner is often the platform/infra team, not the application developers — flag this clearly in any report so it routes to the right team.

---

## 6. Real-World Engagement Considerations Checklist

Before touching Rapid-Reset-style testing on any authorized engagement, confirm in writing:

- [ ] The scope document explicitly authorizes **availability/denial-of-service testing**, not just "vulnerability testing" in general.
- [ ] The specific systems in scope for this technique are identified (production vs. staging vs. dedicated test environment).
- [ ] A **testing window** is agreed with the client's operations/on-call team, with a named point of contact reachable during the test.
- [ ] A **stop condition / kill switch** is defined — what observable signal means "stop immediately" (e.g., client reports customer-facing errors, monitoring alerts fire).
- [ ] The client understands and accepts that **third parties sharing infrastructure** (e.g., a shared load balancer, CDN, or multi-tenant API gateway) could be affected, and this has been considered/excluded from scope if relevant.
- [ ] If reporting on a bug bounty program instead of a direct engagement: check the program's policy explicitly for DoS/availability testing — most public bug bounty programs (HackerOne, Bugcrowd) **explicitly exclude denial-of-service testing** from allowed activity by default, and violating this can result in program bans regardless of good intent.
