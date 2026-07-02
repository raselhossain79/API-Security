# BOLA Testing Workflow in Burp Suite (Community Edition)

This file assumes Burp Suite Community Edition, since that's the toolchain used throughout
this note library. Community Edition does not include the paid Scanner, so this workflow
leans on Proxy, Repeater, Intruder, and the free **Autorize** extension via the BApp Store —
all available in Community Edition.

## 1. Capture full coverage in Proxy before testing anything

Browse or drive the entire application (or run the mobile app / SPA through Burp as the
system proxy) logged in as both Account A and Account B, hitting every feature at least once.
This populates **Proxy > HTTP history** with a full map of every object-referencing endpoint,
which is the raw material for step 2. Skipping this and testing endpoints ad hoc as you think
of them is the single most common way testers under-cover an API — BOLA hunting is a coverage
exercise first, a cleverness exercise second.

## 2. Manual differential test in Repeater — the core technique, tool version

1. Right-click a request in Proxy history (one where you're logged in as Account A, accessing
   Account A's own object) → **Send to Repeater**.
2. In Repeater, send it once as-is to confirm the baseline 200 response.
3. Duplicate the tab (right-click the tab → **Duplicate tab**, or `Ctrl+R` again from
   history), so you have the baseline preserved alongside your test copy.
4. In the duplicate, change **only the object ID** to a value owned by Account B (or the
   disclosure-sourced UUID/hash from file 03). Leave the `Authorization` header, cookies, and
   every other byte of the request untouched — this isolates the object ID as the single
   variable under test, exactly as described in file 02 step 3.
5. Send it. Compare status code, response length, and full response body against the baseline
   tab using Repeater's split-view. A 200 with the target's actual data present is a confirmed
   finding.
6. Repeat for each HTTP method the endpoint supports (file 03, section 7) — duplicate the tab
   again, change only the method and body as needed, keep the token and object ID from the
   confirmed-vulnerable test.

## 3. Automating enumeration with Intruder (sequential IDs only)

Covered in detail in file 03 section 1. Workflow summary specific to Burp:
1. Send the baseline request to **Intruder**.
2. Clear existing payload markers (`Clear §`), then mark only the ID value:
   `GET /api/v1/orders/§8841§ HTTP/1.1`
3. **Payloads** tab → payload type **Numbers** → set range and step.
4. **Options** tab → under **Grep - Match**, add a string that would only appear in a
   *successful* leak (e.g., a field name like `"customerEmail"` that only shows up in a full
   object response, not an error body) — this adds a column to results so you can filter
   confirmed hits instantly instead of reading every response body by hand.
5. Start attack, sort by the grep-match column and by response length, review hits.

Do not use Intruder's brute-force approach against UUID, GUID, or properly-salted hashed IDs —
per file 03 section 2, that ID space is not enumerable and Intruder will just generate noise
and risk rate-limiting/blocking. Intruder is the right tool only for the sequential-ID case.

## 4. Automating the differential comparison at scale with Autorize

Manually duplicating and re-sending every request in Repeater does not scale once you've
mapped dozens of endpoints. **Autorize** (free, BApp Store) automates exactly the comparison
done manually in section 2, across your entire captured traffic, for one account pair at a
time.

**Setup:**
1. **Extensions** tab → **BApp Store** → install **Autorize**.
2. Log in to the target as your **low-privilege account** (the one you're testing whether it
   can improperly reach another user's data) in your normal browser session through Burp's
   proxy.
3. In the Autorize tab, paste that low-privilege account's session token/cookie/Authorization
   header value into the **Configuration** field as the "unauthorized" identity Autorize will
   substitute in.
4. Now browse the application logged in as your **normal/victim account** (Account B) through
   the same Burp proxy. For every request Account B makes, Autorize automatically replays an
   identical copy with Account A's credentials swapped in, and flags the result.

**Reading Autorize's output — this is the part that requires judgment, not just automation:**
Autorize color-codes each replayed request:
- **Red ("Bypassed!")** — the request succeeded (200-class, similar response) using Account
  A's credentials against Account B's object. This is Autorize's raw signal, but it is a
  **candidate**, not a confirmed finding — always open the actual response body and verify it
  genuinely contains Account B's data, not a generic empty-state page that happens to also
  return 200.
- **Yellow ("Enforced?")** — the response differs (different status, different length);
  usually correctly protected, but worth a spot-check on endpoints handling sensitive data,
  since Autorize's length-diffing heuristic can miscategorize responses that are similar
  length but different content.
- **Green ("Enforced")** — clearly blocked.

Because Autorize compares against captured live traffic, it inherits the coverage
limitation from step 1: it can only test endpoints Account B actually triggers during the
browsing session, so drive every feature deliberately rather than relying on incidental
clicking.

## 5. Match and Replace for repetitive header/token swapping

If you're repeatedly testing the same swap (e.g., always substituting Account A's Bearer token
into requests originally captured for Account B) across many manually-sent Repeater requests,
**Proxy > Match and Replace** rules save re-editing headers by hand every time:
1. **Settings > Proxy > Match and Replace** → add a rule.
2. Type: **Request header**. Match: `Authorization: Bearer .*` (regex). Replace:
   `Authorization: Bearer <Account A's token>`.
3. Enable the rule only while actively testing this specific swap, then disable it — leaving
   it on globally will corrupt every other request you send during the session, including
   requests you intend to send as other identities.

## 6. Testing indirect references in JSON bodies with Repeater

For the multi-field body case from file 03 section 5, use Repeater's raw editor to isolate one
field at a time:
1. Send the full legitimate multi-field body request to Repeater.
2. Duplicate it once per object-reference field in the body.
3. In each duplicate, change exactly one field to a foreign-account value, leaving the others
   as your own legitimate values. This tells you precisely which field lacks an ownership
   check, rather than getting a single pass/fail result for the whole endpoint when multiple
   fields are involved.

## 7. Session-per-tab discipline

Keep two separate Burp project tabs or two separate browser profiles (both proxied through
Burp) open simultaneously — one authenticated as Account A, one as Account B (and, for
cross-tenant testing, a third and fourth for the second tenant's accounts). Constantly
re-logging in and out of a single session is slow and is how testers accidentally send a
"foreign account" test request using the wrong token, invalidating the result. Label Repeater
tabs clearly (`A-baseline`, `A-token_vs_B-object`, `B-baseline`) as the request count grows.

## 8. What's next

`05-BOLA-Cheatsheet.md` compresses this entire series into a single fast-reference file:
checklist, payload/request patterns, and the full PortSwigger + crAPI lab index in one place.
