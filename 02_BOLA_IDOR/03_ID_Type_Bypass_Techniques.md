# BOLA — ID Type Bypass Techniques

The technique that actually works against a given endpoint depends entirely on the shape of the object identifier it uses. This file breaks down each ID type, how to recognize it, and the specific approach that applies — because "try changing the ID" means something completely different for a sequential integer than it does for a UUID.

---

## 1. Sequential Integers

### Recognition
Path or body values like `1042`, `8817`, incrementing by roughly 1 each time a new object is created. Easiest to spot by creating two objects back-to-back (e.g., place two orders) and comparing their IDs.

### Why this ID type is fully enumerable
A sequential integer carries no entropy at all — the entire ID space near any known value is trivially guessable. If your own object is `1042`, objects `1` through roughly the current max are all plausible, real targets.

### Step-by-step bypass using Burp Intruder

**Step 1.1 — Capture the baseline request** for your own object and send it to Intruder:
```
GET /api/v1/orders/1042 HTTP/1.1
Authorization: Bearer <your_token>
```

**Step 1.2 — Mark the payload position.** Highlight only the numeric ID and insert Intruder's position markers:
```
GET /api/v1/orders/§1042§ HTTP/1.1
Authorization: Bearer <your_token>
```
**What's being changed and why:** only the digits inside the position markers are substituted per request. The Authorization header stays fixed and untouched throughout the entire attack — this is what proves the finding is an authorization gap and not a session/auth issue, since the same valid token is used against every object ID.

**Step 1.3 — Configure the payload set.** Attack type: **Sniper** (single position). Payload type: **Numbers**, range e.g. `1` to `2000`, step `1`. This generates one request per candidate ID, e.g. `1`, `2`, `3` ... `2000`.

**Step 1.4 — Run and filter results.** After the attack completes, sort the results grid by **Length** or **Status code**. Requests returning a `200` with a response length matching a "real object" pattern (not a generic "not found" template) indicate successful unauthorized access. Manually inspect a sample of the `200` responses to confirm they contain another user's real data rather than an empty/placeholder object that happens to also return `200`.

### Real-world note
Sequential IDs remain extremely common in internal/legacy systems and in APIs that were originally built for internal tooling and later exposed externally without revisiting the ID scheme — auto-increment primary keys are the path of least resistance for any backend developer using a relational database, and migrating away from them is often deprioritized.

---

## 2. UUIDs

### Recognition
A 36-character string in the canonical format `xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx` (32 hex digits plus 4 hyphens), e.g. `5704f6d9-d027-4a47-924c-1d78000de8fd`.

### Why brute force does not apply here
A UUIDv4 has 122 bits of true randomness. Brute-forcing this space is computationally infeasible — this is by design, and it's exactly why many teams move to UUIDs specifically *believing* it fixes BOLA. **It does not fix BOLA; it only removes the enumeration vector.** The authorization check is either present or it isn't — UUIDs just mean an attacker needs to *discover* a valid ID rather than guess one, and discovery is almost always still possible.

### Step-by-step: identify the UUID version first
Look at the third group. The first hex digit of that group tells you the version:
- `M` = `1` → **UUIDv1**: time-based, includes a timestamp and (historically) the generating machine's MAC address embedded in the bits. This is partially predictable if you know approximately when the object was created — the timestamp portion narrows the search space dramatically compared to a full 122-bit space.
- `M` = `4` → **UUIDv4**: fully random. No mathematical shortcut exists. Discovery-based approaches only.

### Step-by-step: disclosure-based discovery (the technique that actually matters for UUIDs)

**Step 2.1 — Systematically search every response in your traffic history for UUID-shaped strings**, not just the ones displayed in the UI. Use Burp's proxy history search with a pattern matching the canonical UUID shape across every captured response body — list/feed/community endpoints are the most common leak point, since they often return partial objects belonging to *other* users as part of a "recent activity" or "public post" feature.

**Step 2.2 — Take a UUID discovered in someone else's context** — e.g., found embedded in another user's public post/comment/profile object returned by a "community" or "feed" endpoint — and substitute it into the object-fetch endpoint using your own token:
```
GET /api/v1/vehicle/5704f6d9-d027-4a47-924c-1d78000de8fd/location HTTP/1.1
Authorization: Bearer <your_own_token>
```
**What's being changed and why:** the UUID itself is swapped for one that was never given to you directly by the system — it was harvested from a different, seemingly unrelated endpoint's response. This proves two separate failures at once: (a) the "community"/list endpoint is over-disclosing an internal object reference it has no reason to expose, and (b) the object-fetch endpoint trusts any syntactically valid UUID without checking whether *this specific caller* has any relationship to that specific object.

**Step 2.3 — Check error messages and support/debug endpoints.** UUIDs frequently leak in verbose error responses, stack traces, `X-Request-Id` correlation headers echoing internal object references, or exported PDF/CSV files that embed the raw object UUID in a filename or metadata field.

### Real-world note
This exact pattern — vehicle location UUIDs disclosed via a "community" feed endpoint and then reused against the location-lookup endpoint — is a documented, practicable example in OWASP's own crAPI training project (see Cheatsheet file for the direct challenge reference), demonstrating that UUID adoption alone is a very common false sense of security in production systems.

---

## 3. Hashed IDs

### Recognition
A fixed-length hex string with no hyphens, commonly:
- 32 hex characters → likely MD5
- 40 hex characters → likely SHA-1
- 64 hex characters → likely SHA-256

Example: `e10adc3949ba59abbe56e057f20f883e` (32 hex chars).

### Step-by-step: identify the hash type
**Step 3.1 — Measure length and character set.** Confirm it is pure lowercase (or mixed-case) hexadecimal with no other characters — this rules out base64 (which uses `+`, `/`, `=`) and confirms a raw hex digest.

**Step 3.2 — Use a hash identification tool** such as `hashid` or `name-that-hash` against the sample string to confirm the likely algorithm, since length alone can be ambiguous between a few algorithm families:
```bash
hashid e10adc3949ba59abbe56e057f20f883e
```

### Step-by-step: test whether the hash is derived from a guessable input
Many systems that "hash the ID for obscurity" actually hash a small, predictable input space — e.g., `MD5(user_id)`, `MD5(email)`, or `MD5(sequential_invoice_number)` — rather than a truly random value. This is the actual bypass vector; the hash itself doesn't need to be "cracked" in the traditional password sense, because you can simply **regenerate the candidate hashes yourself** from a known/guessable input space and compare.

**Step 3.3 — Build a candidate input list.** If you suspect the hash is `MD5(numeric_id)`, generate MD5 hashes for a range of plausible integers:
```bash
for i in $(seq 1 5000); do
  echo -n "$i" | md5sum | awk -v id="$i" '{print id": "$1}'
done > candidate_hashes.txt
```
**What this does and why:** it recreates the exact transformation the server likely performs, over the same plausible input space used in Section 1 (sequential integers), producing a lookup table mapping `plaintext_id → hash`. You then search this table for the specific hash value observed in the target application's URL/response.

**Step 3.4 — Confirm the match by requesting the corresponding object.** If `candidate_hashes.txt` shows `4471: e10adc3949ba59abbe56e057f20f883e`, and that exact hash string is the one seen for a *different* user's object in the target app, request:
```
GET /api/v1/records/e10adc3949ba59abbe56e057f20f883e HTTP/1.1
Authorization: Bearer <your_own_token>
```
using a hash you derived yourself, never disclosed to you by the system for that object, but mathematically equivalent to what the server expects. **What's being changed and why:** you are supplying a legitimate-looking hash the same way an enumerable integer would be supplied — the "hashing for obscurity" layer is defeated entirely because the transformation itself is fully reproducible once the input space is known.

**Step 3.5 — If the underlying input is not obviously guessable** (e.g., a hash of a random salt-and-value combination rather than a small predictable value), fall back to rainbow table lookups against public rainbow table services/datasets for unsalted common hash algorithms, or note in your findings that the hash-based obfuscation is not immediately practically reversible — which is a legitimate (if fragile) partial mitigation, though never a substitute for a real ownership check.

### Real-world note
Hashing an ID is security-by-obscurity, not authorization. It commonly appears in legacy systems trying to retrofit "unguessable" identifiers onto an existing sequential-integer schema without a full data migration to true random UUIDs.

---

## 4. GUIDs

### Recognition and relationship to UUIDs
GUID (Globally Unique Identifier) is Microsoft's terminology for the same 128-bit structure as a UUID — same format, same 36-character canonical representation. In practice, treat GUIDs exactly as UUIDs (Section 2): check the version nibble, treat v1-style GUIDs as timestamp-narrowable, treat v4-style/fully-random GUIDs as discovery-only targets, and apply the same disclosure-based hunting technique across proxy history.

### One GUID-specific note
.NET/Windows-stack applications sometimes generate GUIDs using the older `Guid.NewGuid()` implementation, which historically had version/variant bits that could, in some older runtime versions, reveal generation-time information similarly to UUIDv1. Always check the version nibble rather than assuming full randomness by default just because the value "looks like a UUID."

---

## 5. Base64-Encoded IDs

### Recognition
A string using the base64 character set (`A-Z`, `a-z`, `0-9`, `+`, `/`, possibly trailing `=` padding), often appearing where a developer wanted to "obscure" an underlying value without actually hashing or randomizing it, e.g. `MTA0Mg==`.

### Step-by-step bypass

**Step 5.1 — Decode the value to reveal the underlying pattern.**
```bash
echo "MTA0Mg==" | base64 -d
```
Output: `1042`

**What this reveals:** the base64 layer is pure encoding, not encryption or hashing — it is fully and trivially reversible. In this example, the underlying object reference is the same plain sequential integer covered in Section 1.

**Step 5.2 — Modify the underlying value, then re-encode.**
To target a different object (e.g., `1041`):
```bash
echo -n "1041" | base64
```
Output: `MTA0MQ==`

Send the request using this newly-encoded value:
```
GET /api/v1/orders/MTA0MQ== HTTP/1.1
Authorization: Bearer <your_own_token>
```
**What's being changed and why:** the visible base64 string is swapped, but the meaningful change is the *decoded* underlying integer (`1042` → `1041`) — the base64 layer itself has zero security value and exists purely as surface-level obfuscation. Treat any base64 ID exactly like the plaintext value it decodes to, and apply whichever technique (Section 1, 2, or 3) matches what that decoded value actually looks like.

**Step 5.3 — Watch for compound/structured payloads inside the decoded value.** Some implementations base64-encode a small JSON object or delimited string rather than a bare ID, e.g. decoding to `{"uid":1042,"tenant":55}`. In this case, modify the relevant field inside the decoded JSON, then re-encode the entire modified string before sending — this connects directly to the cross-tenant testing in file 2, since the tenant field may be embedded here rather than in a header or URL segment.

**Step 5.4 — Watch for URL-safe base64 variants.** Some APIs use the URL-safe alphabet (`-` and `_` instead of `+` and `/`, often without padding). If standard `base64 -d` produces garbage, retry with:
```bash
echo "MTA0Mg" | base64 -d --wrap=0 2>/dev/null || echo "MTA0Mg" | tr '_-' '/+' | base64 -d
```

### Real-world note
Base64-encoded IDs are one of the most common "false confidence" patterns encountered in real bug bounty programs — developers often perceive an encoded string as "not a plain ID" and skip adding an authorization check, even though the encoding adds no actual protection and is reversed in a single command.

---

**Next file:** `04_Autorize_Extension_Guide.md` — automating cross-role BOLA detection across an entire application using Burp Suite's Autorize extension.
