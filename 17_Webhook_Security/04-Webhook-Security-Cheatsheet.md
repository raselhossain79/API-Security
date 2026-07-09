# Webhook Security — 04: Cheatsheet

Condensed, standalone reference. See files 00–03 for full mechanism explanations — this file
intentionally omits the "why," keep it for the "what to try next."

## 0. First, orient yourself

- **Which side are you testing?** Registering a webhook URL (you control the destination →
  file 01, SSRF) vs. sending to a webhook receiver endpoint (you're forging the sender →
  files 02–03). Confusing these wastes time.
- Read any "Recent Deliveries" / delivery log UI first — it's often a built-in SSRF response
  channel and a free source of captured legitimate requests to tamper with.

## 1. SSRF via webhook registration — checklist

- [ ] Register webhook URL pointed at your own listener (Collaborator/webhook.site/ngrok) —
      confirm mechanism works, capture request shape.
- [ ] Register directly against `127.0.0.1`, `localhost`, internal RFC1918 ranges + common
      internal ports (`6379` Redis, `9200` Elasticsearch, admin panel ports).
- [ ] Register directly against cloud metadata: `169.254.169.254` (AWS/most clouds, GCP
      also needs `Metadata-Flavor: Google` header — usually not settable via redirect),
      `metadata.google.internal`.
- [ ] If direct registration is blocked, host a redirector and register *that* — test
      `301`, `302`, `303`, `307` status codes independently.
- [ ] If filtered, test bypass encodings: IPv4-mapped IPv6 (`[::ffff:169.254.169.254]`),
      decimal/octal/hex IP forms, `nip.io`/`sslip.io` wildcard DNS, DNS rebinding (low-TTL
      alternating resolver), URL-parser confusion (`user@internal-ip`, fragment tricks).
- [ ] Check delivery log for response body first; fall back to OOB/timing-based blind
      confirmation if no response channel exists.
- [ ] WAF/gateway note: string/deny-list filtering is the weak control here; egress network
      filtering and re-resolve-at-connect-time are the strong ones — test which is actually
      present rather than assuming URL-string bypass will always work.

## 2. Signature bypass — checklist

- [ ] Capture one legitimate signed delivery in full (headers + body).
- [ ] Resend with the signature header **stripped entirely** — if processed, no validation
      exists at all.
- [ ] Resend with **body modified, signature unchanged** — if processed, header exists in
      code but isn't actually checked.
- [ ] Identify what's actually covered by the signature (full body? specific fields only?
      headers included?) — modify only excluded parts.
- [ ] If signature genuinely enforced: check comparison function in any available source —
      `==`/string comparison = timing-attackable; `hmac.compare_digest`/
      `Rack::Utils.secure_compare` = constant-time, not directly attackable this way.
- [ ] Brute-force the secret offline against one known (body, signature) pair: short values,
      documented defaults, leaked/reused secrets, no-minimum-length registration.

```python
import hmac
guess = hmac.new(candidate_secret.encode(), known_body, "sha256").hexdigest()
hmac.compare_digest(guess, known_signature)
```

## 3. Replay attacks — checklist

- [ ] Resend a captured, unmodified, legitimate request immediately — if action fires again,
      no replay protection at all.
- [ ] If blocked, find the timestamp tolerance boundary (retry at 1/4/6/10+ min intervals).
- [ ] Test event-ID deduplication independent of timestamp — does a fresh timestamp alone
      let an old event ID through again?
- [ ] Test for race-condition replay: fire the same captured request several times **in
      parallel** (Burp Turbo Intruder / concurrent script), not sequentially — checks for
      non-atomic check-and-mark deduplication.
- [ ] WAF/gateway note: a replay is byte-identical to a previously-accepted request — no
      request-level signature distinguishes them. Only server-side state (seen-ID tracking)
      catches this. Don't expect a WAF finding here.

## 4. Payload tampering — checklist

- [ ] **Event type**: enumerate possible `event`/`type` values from docs/SDK/JS bundles;
      swap a capturable event's type field for a higher-impact one; check if dispatch trusts
      the field with no correlation back to the sender's actual state.
- [ ] **Amount/financial fields**: modify `amount`, `currency`, `status` independently;
      test `0`, negative, huge, decimal-precision, and type-confused (`"4999"` string vs
      `4999` number) values; check whether receiver re-verifies against the payment
      provider's own API or trusts the payload alone.
- [ ] **Privilege fields**: modify `role`, `plan`, `email_verified`, team/tier fields on
      identity-lifecycle webhooks; check if the receiver provisions directly from payload
      without a second authoritative check.
- [ ] Test the **compound case**: missing/broken signature (Section 2) + blind payload trust
      (this section) together — this is where real impact usually lives.
- [ ] WAF/gateway note: a tampered-but-well-formed field is invisible to a WAF unless strict
      schema/bounds validation is enforced at the gateway — check whether it actually is,
      don't assume.

## 5. Endpoint enumeration — checklist

- [ ] Passive first: JS bundles, admin/integration settings pages (which display the
      customer's own webhook URL to paste elsewhere), public partner-integration docs.
- [ ] Active: brute-force `/webhook`, `/webhooks`, `/hook`, `/hooks`, `/callback`,
      `/callbacks`, `/notify`, `/api/webhook`, `/integrations/<vendor>/webhook`,
      vendor-name-specific paths for known integrations (Stripe, Twilio, GitHub, Slack).
- [ ] Check for a dedicated webhook subdomain (`hooks.`, `webhooks-in.`) with potentially
      weaker perimeter controls than the main app.
- [ ] Check for deprecated/legacy receiver endpoints from migrated integrations.
- [ ] On any found endpoint: plain GET/POST with minimal body — generic reject before
      handler logic vs. actual processing tells you if any gate exists at all.
- [ ] WAF/gateway note: active brute-forcing has a real detection signature (burst,
      high-404-rate, sequential paths) — prefer passive discovery to avoid it entirely.

## 6. Header/field quick reference

| Header | Typical purpose | What to test |
|---|---|---|
| `X-Webhook-Signature` / `X-Hub-Signature-256` / `Stripe-Signature` / `X-Twilio-Signature` | HMAC over body (± timestamp) | Strip it; tamper body only; brute-force secret |
| `X-Webhook-Timestamp` | Replay tolerance window | Vary delay; test boundary |
| `X-Webhook-Id` / event ID field | Deduplication | Replay with fresh timestamp, stale ID; race in parallel |
| `url` (registration field) | Delivery destination | SSRF — see Section 1 |
| `secret` (registration field) | Shared HMAC key | Register weak/short value; check min-length enforcement |
| `event` / `type` (body field) | Dispatch routing | Swap for higher-impact event type |

## 7. PortSwigger lab order (consolidated across this series)

No dedicated webhook category exists. In priority order for building relevant skills:

1. SSRF: blacklist-based filter (Apprentice)
2. SSRF: whitelist-based filter (Apprentice)
3. SSRF: filter bypass via open redirection (Practitioner)
4. Blind SSRF with out-of-band detection (Practitioner)
5. Business logic: excessive trust in client-side controls (Apprentice)
6. Business logic: high-level logic vulnerability (Apprentice)
7. Business logic: insufficient workflow validation (Practitioner)
8. Business logic: authentication bypass via flawed state machine (Practitioner)
9. SSRF Expert-tier labs (advanced parser confusion)
10. Business logic Expert-tier labs (chained/advanced trust exploitation)

Supplement with crAPI for hands-on signature/replay practice PortSwigger doesn't currently
offer, and read the real disclosed reports cited in files 01–03 directly — they carry more
of the practical weight for signature/replay/payload topics than any available lab.

## 8. Real-world reports referenced across this series

- Omise — SSRF via webhook redirect (`303`) to AWS metadata — HackerOne #508459
- GitLab — `UrlBlocker` DNS-rebinding bypass to metadata — HackerOne #541169
- Mixmax — unfiltered webhook SSRF to EC2 metadata — HackerOne #243277
- Rocket.Chat — unauthenticated SSRF via Twilio webhook (CVE-2024-39713) — HackerOne #1886954
- Red Darkin & madara_ — IPv6 + redirect webhook SSRF, manual timing port scan (Medium, 2026)
- HackerOne's own developer docs — canonical constant-time signature comparison guidance
- Open-source agent gateway — missing Twilio signature validation, auth bypass via body field
- WakaTime — captured-response replay without server-side invalidation — HackerOne #3120790
- Zomato/Eternal — checkout price tampering (payload-trust analogue) — HackerOne #403783
- WordPress Mercantile — checkout price tampering (payload-trust analogue) — HackerOne #682344

## 9. Reporting reminders

- Demonstrate application **state change**, not just HTTP status code — a `200` can mean
  "processed" or "silently no-op'd," and only checking downstream state distinguishes them.
- For SSRF, capture the actual response content where a delivery log exposes it — this is
  far stronger evidence than a blind timing inference.
- For timing attacks, be honest about noise/practicality in your report; pair a timing
  argument with source-code evidence (`==` vs `compare_digest`) when available rather than
  relying on network timing alone.
- For payload tampering, always test whether the receiver has *any* independent
  source-of-truth check before concluding full impact — some receivers correctly treat
  webhooks as a "go check again" notification rather than ground truth, which meaningfully
  changes severity.
