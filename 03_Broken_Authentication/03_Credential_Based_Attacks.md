# API Broken Authentication — Credential-Based Attacks

Covers: rate limit detection methodology, response-based detection (username/password enumeration via response differences), and the decision + full flag-by-flag breakdown for Burp Intruder vs Turbo Intruder.

---

## 1. Rate Limit Detection — Before You Attack

Attacking a login endpoint without first understanding its rate-limiting behavior wastes time (you may get silently soft-blocked without realizing it) and, in a real engagement, can trigger account lockouts or alerting that burns your window. Always characterize the defense **first**.

### 1.1 Step-by-step detection methodology

**Step 1 — Baseline single request.**
```
curl -s -o /dev/null -D - https://api.target.com/v1/auth/login \
  -X POST -H "Content-Type: application/json" \
  -d '{"username":"nonexistent_user_probe","password":"wrongpass1"}'
```
- `-D -` — dumps response headers to stdout so you can inspect rate-limit-related headers on the very first request.
- `-o /dev/null` — discards the body; at this stage we only care about headers and status code.

**What to look for in the response headers:**
- `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` (or `RateLimit-*` per the newer IETF draft standard) — if present, the API is telling you its policy directly. Read it rather than guessing.
- `Retry-After` — appears on a `429` response, telling you exactly how long to wait.

**Step 2 — Burst test to find the threshold.**
```
for i in $(seq 1 30); do
  curl -s -o /dev/null -w "%{http_code} " https://api.target.com/v1/auth/login \
    -X POST -H "Content-Type: application/json" \
    -d '{"username":"nonexistent_user_probe","password":"wrongpass'"$i"'"}'
done; echo
```
- `seq 1 30` — generates the numbers 1 through 30 for the loop count; using a plain range instead of a fixed small number gives enough requests to actually surface a threshold if one exists in the 10–20 request range (common defaults).
- `-w "%{http_code} "` — prints just the status code (space-separated) for each request instead of the full body, so the output is a compact readable sequence like `401 401 401 429 429 429`.
- `"wrongpass'"$i"'"` — varies the password slightly per request; this is deliberate — if the endpoint dedupes identical request bodies at a WAF/CDN cache layer (rare but happens), varying the payload avoids a false "it's not rate limited" read caused by cache hits rather than real processing.

**Step 3 — Interpret the transition point.**
- If status codes stay `401` (or `403`/`400`, whatever the app's "bad credentials" code is) for all 30 requests with no change: **no observable request-count-based rate limiting** from this single IP. Proceed to Section 3 to select a tool, but plan for the possibility of account-lockout-based limiting instead (tested separately, see Step 4).
- If status flips to `429` (Too Many Requests) after N requests: note **N** exactly — this defines your attack pacing.
- If status flips to a **different error but not 429** (e.g., a `200` with a body saying "account temporarily locked", or a `403`) — this is **account-lockout-style** protection rather than IP/request-rate limiting, and behaves very differently (see Step 4).

**Step 4 — Distinguish IP-based vs account-based limiting.**
Repeat Step 2 but hold the **username constant** and vary only the password (simulating a brute-force against one known account) versus varying **both** username and password (simulating credential stuffing across many accounts). If the block triggers only in the username-constant test, the defense is account-lockout-based (locks *that* account) — meaning credential stuffing across *different* accounts at the same rate may not trigger it at all, changing your tooling choice (see Section 3.1).

**Step 5 — Check whether IP rotation resets the counter (authorized engagements only, and only if the rate-limit key is confirmed to be per-IP).**
```
curl -s -o /dev/null -w "%{http_code}\n" https://api.target.com/v1/auth/login \
  -X POST -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 203.0.113.7" \
  -d '{"username":"nonexistent_user_probe","password":"wrongpassX"}'
```
- `-H "X-Forwarded-For: 203.0.113.7"` — sets a spoofed client IP header; some backends naively trust this header for rate-limit keying (common where the app sits behind a load balancer and reads `X-Forwarded-For` to reconstruct "client IP" without validating it came from a trusted proxy hop). If varying this header resets your allowed-request count, the rate limiter is trivially bypassable and this itself is a separate, reportable finding.

---

## 2. Response-Based Detection (Username/Password Enumeration)

### 2.1 The core check

Compare the API's response across three cases:
1. Valid username + wrong password
2. Invalid username + any password
3. Valid username + valid password

If cases 1 and 2 differ in **any** observable way, the API leaks whether a username exists before the password is even checked — turning a combined brute force into two much cheaper sequential attacks (enumerate usernames first, then brute-force passwords only against confirmed-valid usernames).

### 2.2 What "differs" can mean — check all of these

- **Response body text** — "Invalid username" vs "Invalid password" (the most obvious, and increasingly rare, version of this flaw).
- **HTTP status code** — `404` for unknown user vs `401` for known user with wrong password.
- **Response timing** — a valid username often takes measurably longer if the backend performs a password hash comparison (bcrypt/argon2, which are deliberately slow) only when the username lookup succeeds; an unknown username short-circuits before hashing occurs, returning faster.
- **Response length (byte-for-byte)** — even when body *text* looks identical, whitespace, extra JSON fields (e.g., `"lockout_remaining": null` appearing only for real accounts), or a slightly different field ordering can create a detectable length delta.
- **Response headers** — e.g., a `Set-Cookie` issued even on failed login for valid usernames (pre-auth session tracking) but absent for invalid ones.

### 2.3 Timing-based detection methodology

```
for u in admin administrator jdoe testuser nonexistent_zzz123; do
  T=$( { /usr/bin/time -f "%e" curl -s -o /dev/null \
    -X POST https://api.target.com/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"'"$u"'","password":"wrongpass"}'; } 2>&1 )
  echo "$u -> ${T}s"
done
```
- `/usr/bin/time -f "%e"` — invokes the external `time` binary (not the bash builtin) with a format string; `%e` outputs just elapsed real time in seconds, which is what we need for comparison (the bash builtin `time` doesn't support custom format output the same way and is less reliable to parse here).
- `{ ... } 2>&1` — groups the curl command and redirects stderr to stdout, because `/usr/bin/time` writes its timing output to stderr by default.
- The loop tries several plausible usernames and one deliberately nonexistent one (`nonexistent_zzz123`) as a timing baseline. A cluster of usernames returning notably slower times than the baseline suggests those usernames exist and triggered a real password-hash comparison.

**Caution on timing tests:** network jitter produces noise. Run each username multiple times (5–10 repetitions) and compare **median**, not a single sample, before concluding a timing difference is real signal rather than noise.

---

## 3. Choosing Between Burp Intruder and Turbo Intruder

### 3.1 Decision framework

| Condition | Use | Why |
|---|---|---|
| No rate limiting detected, or a generous threshold (hundreds+ requests/min) | **Burp Intruder** | GUI convenience, built-in payload processing, grep-match/grep-extract for spotting differences — no need for the extra setup cost of a scripted approach when raw speed isn't the bottleneck |
| Rate limiting present, but with a **per-IP** key that can be rotated (confirmed via Section 1, Step 5) | **Turbo Intruder** | Turbo Intruder's Python engine can programmatically rotate the `X-Forwarded-For` (or other spoofable) header per request in ways that are painful to configure through Intruder's GUI-based payload system |
| Very large candidate list (100k+ combinations, e.g., full credential-stuffing dump) needing to run in minutes rather than hours | **Turbo Intruder** | Turbo Intruder uses raw sockets and HTTP pipelining/concurrent connections, achieving dramatically higher throughput than Intruder's connection-pooled model, which matters at this scale |
| Need for fine-grained manual inspection of each response as you go (adjusting attack strategy interactively) | **Burp Intruder** | Turbo Intruder is fire-and-forget script execution; Intruder's live results table is better suited to iterative, exploratory testing |
| Rate limit is account-lockout-based (confirmed via Section 1, Step 4) rather than IP-based | **Burp Intruder**, using **pitchfork** mode with a paced request rate | Rotating IP doesn't help against account lockout since the lock is keyed to the account, not the source; the priority instead becomes pacing requests to stay under the lockout threshold, which Intruder's built-in throttling handles adequately |

### 3.2 Burp Intruder — Full Configuration Breakdown

**Attack type selection:**
- **Sniper** — one payload set, one position at a time; used for single-parameter brute force (e.g., password only, against one known username).
- **Cluster bomb** — multiple payload sets, every combination of all positions tried; used for combined username × password brute force where you don't know either value.
- **Pitchfork** — multiple payload sets, but iterated in lockstep (payload set 1 position 1 pairs with payload set 2 position 1, and so on); used for credential stuffing where you have **pre-paired** username:password combinations from a breach dump, rather than wanting every combination of every username with every password.

**Positions tab:**
- Mark the `username` and `password` JSON field values with the `§` payload markers (e.g., `"username":"§FUZZ§","password":"§FUZZ§"`) — only the marked sections are substituted per request; everything else in the request template stays fixed.

**Payloads tab:**
- **Payload set 1 / 2** — corresponds to each `§marker§` position when using Cluster bomb or Pitchfork; Sniper only has one active payload set applied to each marked position in turn.
- **Payload type: Simple list** — for a straightforward wordlist (most common for both usernames and passwords).
- **Payload type: Runtime file** — reads a wordlist from disk on the fly rather than loading fully into memory; use for very large lists (rockyou.txt-scale) to avoid excessive Burp memory consumption.

**Payload processing rules (used when tokens/passwords need transformation, e.g., matching a `stay-logged-in` cookie format from a prior lab, or hashing a password client-side before sending):**
- Add rule → **Hash** → select algorithm (e.g., MD5) if the API/lab expects a pre-hashed credential.
- Add rule → **Add prefix/suffix** if the transport format wraps the raw value (e.g., `Bearer ` prefix, or a `username:` prefix before base64 encoding).
- Rule ordering matters — rules apply top-to-bottom, so "hash, then base64-encode" must be ordered with hash listed above encode.

**Resource pool (Options tab / separate Resource Pool config in newer Burp versions):**
- **Maximum concurrent requests** — throttle this down (e.g., to 1–2) when your Section 1 testing revealed a tight rate limit, to stay under the threshold and avoid tripping a lockout mid-attack.
- **Delay between requests** — set an explicit millisecond delay as an alternative/additional throttle, directly informed by the threshold you measured earlier (e.g., if the limit resets every 60 seconds after 10 requests, pace at roughly 1 request per 6–7 seconds to stay just under it).

**Grep - Match (Options tab):**
- Add strings you expect to differ between success/failure (e.g., `"error"`, `"welcome"`, a specific error message text identified in Section 2). Burp adds a column showing which responses matched, letting you sort/filter results instantly instead of reading every response body manually.

**Grep - Extract:**
- Define a region of the response (e.g., between two boundary strings) to pull out a dynamic value — useful for extracting a session token immediately from whichever attempt succeeds, without a second manual step.

**Settings — response redirections:**
- Ensure "Follow redirections" is configured deliberately — if the login endpoint issues a `302` on success, decide whether you want Intruder to follow it (to check the destination page) or not (to just check the `302` status itself as your success signal, which is usually simpler and faster).

### 3.3 Turbo Intruder — Full Script Breakdown

Turbo Intruder scripts are Python, run inside Burp via the Turbo Intruder extension. Below is an annotated baseline script for a rate-limit-aware credential attack with IP-rotation.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=5,
        requestsPerConnection=1,
        pipeline=False
    )

    candidates = open('/home/user/wordlists/creds.txt').readlines()

    for line in candidates:
        username, password = line.strip().split(':', 1)
        xff_ip = f"203.0.113.{engine.requestsQueued % 254 + 1}"

        engine.queue(target.req, [username, password, xff_ip])

def handleResponse(req, interesting):
    table.add(req)
```

Piece-by-piece:

- **`def queueRequests(target, wordlists):`** — Turbo Intruder's required entry-point function; called once, responsible for defining the engine and queuing every request you want fired.

- **`engine = RequestEngine(...)`** — instantiates the actual request-sending engine object.
  - **`endpoint=target.endpoint`** — pulls the target host/port automatically from the base request you sent to Turbo Intruder (the request you right-click → "Send to Turbo Intruder" from Burp's proxy history).
  - **`concurrentConnections=5`** — the number of TCP connections held open simultaneously. This is the primary throughput lever — raising it increases requests/second but also increases the chance of tripping a rate limiter, so this value should come directly from your Section 1 findings (start conservative if a tight limit was detected).
  - **`requestsPerConnection=1`** — how many requests are sent down each connection before it's closed and a new one opened. Setting this to `1` avoids relying on HTTP keep-alive/pipelining behavior that some rate limiters specifically watch for (repeated requests on a single persistent connection can itself be a detection signal); higher values increase raw speed against targets known *not* to key on this pattern.
  - **`pipeline=False`** — disables HTTP pipelining (sending multiple requests without waiting for each response) explicitly. Pipelining is Turbo Intruder's biggest raw-speed feature, but many modern APIs (and any Gateway sitting in front of them) don't support pipelining well and will error/reset — setting this `False` produces slower but more reliable behavior, which matters more than raw speed when you specifically need to observe accurate per-attempt response codes for rate-limit interpretation. Flip to `True` once you've confirmed the target handles it, for maximum-throughput runs.

- **`candidates = open(...).readlines()`** — loads the full credential-stuffing wordlist (format `username:password` per line, typical of breach-dump exports) into memory as a Python list; each line still has its trailing newline at this point.

- **`for line in candidates:`** — iterates every credential pair.
  - **`username, password = line.strip().split(':', 1)`** — `.strip()` removes the trailing newline; `.split(':', 1)` splits on the first colon only (the `1` limits it to one split), which matters if a password itself contains a colon character — without the limit, a colon in the password would incorrectly break the line into more than two pieces.
  - **`xff_ip = f"203.0.113.{engine.requestsQueued % 254 + 1}"`** — builds a synthetic IP address for the `X-Forwarded-For` header, cycling through the last octet based on how many requests have been queued so far (`% 254 + 1` keeps the value within a valid host-octet range, 1–254). This is the IP-rotation technique from Section 1, Step 5 — but note this is only relevant/legal to test when you're specifically probing whether the target's rate-limit key naively trusts a client-supplied header, in an engagement where you have authorization to test that exact bypass. It is not a way to "evade" a security control outside authorized scope.

- **`engine.queue(target.req, [username, password, xff_ip])`** — queues one request. `target.req` is the raw HTTP request template (captured from Burp, with placeholder markers `%s` in the body/headers where substitutions go); the list `[username, password, xff_ip]` fills those markers in order.

- **`def handleResponse(req, interesting):`** — Turbo Intruder's second required function, called once per completed response.
  - **`table.add(req)`** — adds every response to Turbo Intruder's results table by default; in practice you'd typically wrap this in a conditional (e.g., `if req.status != 401: table.add(req)`) to only surface non-standard responses, since credential-stuffing runs against large lists produce mostly uniform failure responses you don't need cluttering the table.

### 3.4 Practical selection summary

- Start every engagement with Section 1's rate-limit detection.
- Small-to-medium list + no meaningful rate limit → Burp Intruder, Cluster bomb or Pitchfork depending on whether you have paired credentials.
- Large list, or IP-rotation needed, or raw throughput matters → Turbo Intruder, tuned conservatively at first (`concurrentConnections` low, `pipeline=False`) and increased once target behavior is understood.

---

## 4. Real-World Notes

- Large-scale credential-stuffing campaigns (e.g., the wave of attacks against streaming and food-delivery APIs in 2022–2023) rely almost entirely on the Pitchfork-style paired-credential approach at massive scale — attackers use previously breached username:password pairs from unrelated services, betting on password reuse, which is why response-based **account-existence** leakage (Section 2) is so valuable to attackers even without ever cracking a single password directly.
- Several bug bounty writeups on HackerOne have documented API endpoints where the mobile app's login screen showed a generic "Incorrect credentials" message (masking enumeration at the UI layer) while the underlying API response still contained a distinguishing status code or field — a reminder to always test the raw API response, not just what the client displays.

---

Continue to `04_Authentication_Bypass_Techniques.md`.
