# API4:2023 — Unrestricted Resource Consumption — Final Cheatsheet

Condensed, quick-reference version of the full series. Use the other files
for mechanism-level depth; use this file during active testing.

---

## 1. Detection Quick Checklist

- [ ] Check response headers: `X-RateLimit-Limit/Remaining/Reset`,
      `RateLimit-*`, `Retry-After`
- [ ] Confirm headers correlate with real enforcement (decrement to 0 →
      actual `429`, not continued `200`)
- [ ] Baseline (spaced requests) vs. burst (rapid requests) timing comparison
- [ ] Check connection-level timing for silent drops (not just HTTP status)
- [ ] Identify a known-protected reference endpoint (e.g., `/login`) and
      confirm it *does* block under the same burst — proves capability
      exists, isolates the target endpoint's gap
- [ ] Test HTTP method / trailing slash / case / API version variants of
      the same logical route
- [ ] Test REST vs. GraphQL vs. any other exposed API paradigm separately

---

## 2. Exploitation Technique Quick Reference

| Technique | Payload Example | Resource Exhausted | Key Proof Point |
|---|---|---|---|
| Pagination abuse | `?limit=5000000&offset=0` | DB query time + result-set memory | Response time delta across escalating `limit`; other endpoints slow during burst |
| File upload abuse | Multipart body, `Content-Length` in GBs | Server memory/disk buffer | Time-to-response at 10MB → 100MB → 1GB; concurrent parallel uploads |
| ReDoS via API | Long repeated chars + trailing invalid char against nested-quantifier regex field | CPU time in regex engine | Exponential (not linear) time growth vs. input length |
| Expensive computation abuse | Legitimate max-scope request (e.g., full date-range report) fired concurrently | CPU/memory for synchronous processing | Concurrency-based degradation; cost-per-call estimate for cloud infra |
| Third-party spend (SMS/OTP) | Repeated `POST /auth/send-otp` | Real $ via SMS provider (Twilio/SNS) | Cite provider's per-message price × achievable request rate |
| Third-party spend (email) | Repeated invoice/notification resend | Real $ via email provider (SendGrid/SES) + sender reputation | Same cost-multiplication framing |
| Third-party spend (payment) | Repeated card-verification calls | Per-authorization processor fee + fraud-flag risk | **Caution: analytical extrapolation preferred over live volume testing** |
| Enumeration via absent rate limit | Sequential user IDs / usernames / emails | Attack surface for account/credential enumeration | Cross-ref Broken Authentication + BOLA series |

---

## 3. Burp Intruder / Turbo Intruder Quick Config

**Standard Intruder (Sniper), escalating single value:**
- Attack type: Sniper
- Payload type: Numbers, custom log-scale list (`100,1000,10000,100000,1000000,5000000`)
- Resource Pool → Delay between requests: fixed (e.g., 1000ms) for clean per-step timing
- Grep-Extract: `X-RateLimit-Remaining:`, `Retry-After:`

**Standard Intruder, concurrency burst:**
- Resource Pool → Max concurrent requests: 20–30
- Delay between requests: 0

**Turbo Intruder, concurrency contention proof:**
```python
engine = RequestEngine(endpoint=target.endpoint,
    concurrentConnections=30, requestsPerConnection=1, pipeline=False)
for i in range(50): engine.queue(target.req)
```

**Turbo Intruder, escalating size (sequential, clean timing):**
```python
engine = RequestEngine(endpoint=target.endpoint,
    concurrentConnections=1, requestsPerConnection=1, pipeline=False)
for v in [100,1000,10000,100000,1000000,5000000]: engine.queue(target.req, v)
```

**Turbo Intruder, threshold-finding (max throughput):**
```python
engine = RequestEngine(endpoint=target.endpoint,
    concurrentConnections=1, requestsPerConnection=100, pipeline=True)
for i in range(500): engine.queue(target.req)
# handleResponse: filter table.add() to non-200 only
```

---

## 4. WAF / API Gateway — One-Line Summary Per File

- **File 02 (resource exhaustion)**: gateways detect via volumetric
  thresholds, payload-size inspection, response-time anomaly detection,
  query-cost estimation. Bypass angle unique here: splitting cost across
  many moderate requests instead of one oversized one; compression-based
  size-inspection evasion; timing spend just outside anomaly-detection
  windows.
- **File 03 (third-party spend)**: detection is often per-destination
  (same phone/email targeted across sources) plus independent
  processor-level fraud/velocity checks. Bypass angle: destination
  normalization gaps (e.g., plus-addressing on email).
- **File 04 (tooling)**: detection via request uniformity / connection
  fingerprinting specific to automated tools. Bypass angle: header-order
  randomization within scripts.
- Generic bypass (IP rotation, header spoofing, distributed sources) is
  intentionally NOT duplicated here — see the **Rate Limit / Bot
  Protection Bypass series**.

---

## 5. PortSwigger Lab Coverage Summary (Honest Gap Disclosure)

PortSwigger Web Security Academy has **no dedicated labs** for:
- Uncapped pagination
- File upload size-based DoS
- ReDoS via API input
- Expensive-computation concurrency abuse
- Third-party spend / Denial of Wallet (Academy has no real external
  service integration to model cost against)

The closest adjacent Academy material:
- API testing / endpoint discovery topic — useful recon step before
  applying these techniques
- Business Logic Vulnerabilities topic — teaches the "find the most
  expensive legitimate parameter combination" mindset relevant to file 02
  section 4

**Practice these techniques primarily against crAPI or an authorized
personal/client lab, not PortSwigger Academy.**

---

## 6. crAPI Supplementary Practice Summary

| crAPI Challenge Area | Maps To |
|---|---|
| Community/forum + product list endpoints (weak pagination caps) | File 02, section 1 (pagination abuse) |
| OTP-based password reset / verification flow | File 03 (entire file — safe sandbox for third-party spend concept) |

crAPI does not currently model ReDoS, expensive-computation concurrency
abuse, or size-based file upload DoS — these gaps require a personal test
harness or authorized live-target testing.

---

## 7. Cross-Reference Map

- Detection of enumeration enabled by absent rate limiting →
  **Broken Authentication series** (credential stuffing mechanics) and
  **BOLA series** (object ID enumeration mechanics)
- Bypassing rate limiting once confirmed to exist →
  **Rate Limit / Bot Protection Bypass series**
- Endpoint discovery before applying any technique in this series →
  **API Reconnaissance and Endpoint Discovery series**

---

## 8. Reporting Reminders

- Always quantify impact: response-time deltas, cost-per-request ×
  achievable rate, or concurrent-degradation evidence — not just "no rate
  limit header observed."
- For third-party spend findings, cite the provider's published pricing
  and extrapolate rather than running high-volume live tests, especially
  for payment endpoints.
- Confirm a known-protected reference endpoint on the same API to
  pre-empt "our WAF handles this" pushback from triagers.
