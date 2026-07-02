# BOLA: ID Types, Bypass Techniques, and Non-Obvious Locations

The core BOLA check — swap the object ID, keep everything else identical — stays constant
across every ID format. What changes per format is **how you obtain a valid target ID to swap
in**, since you cannot exploit BOLA against an ID you cannot produce or discover. This file
breaks down the technique per ID type, then covers where BOLA hides outside the obvious URL
path parameter.

## 1. Sequential integer IDs — enumeration-based technique

**Format example:** `/api/v1/orders/8841`

**Why it's the easiest case:** the ID space is small, predictable, and fully guessable from a
single known value. If your own order ID is `8841`, you know with near certainty that valid
orders exist at `8840`, `8839`, `8842`, etc.

**Technique: enumeration.**
1. Capture a request containing your own sequential ID.
2. Send it to Burp Repeater, then Burp Intruder for the range sweep.
3. In Intruder, mark the ID as the payload position:
   `GET /api/v1/orders/§8841§ HTTP/1.1`
4. Set the payload type to **Numbers**, range e.g. 8000–9000, step 1. This is the piece doing
   the actual bypass work: it systematically substitutes every integer in the range into the
   exact position your own valid ID occupied, while every other byte of the request — headers,
   token, method — stays fixed. The authorization bypass isn't in any single request; it's in
   the fact that the *same static token* is reused against IDs that token was never granted
   access to.
5. Sort results by response length and status code. A cluster of 200s with content-length
   values different from your own baseline response (but non-error-looking) indicates you are
   pulling other users' real objects, not empty/error pages.

**Real-world note:** sequential-ID BOLA is disproportionately common in APIs built on ORMs
that auto-increment primary keys and expose that primary key directly as the public object
identifier — a very common default in Rails, Django, and Laravel scaffolding unless the
developer deliberately swaps in a UUID or hashid.

## 2. UUID / GUID — disclosure-based technique (not brute force)

**Format example:** `/api/v1/vehicle/5704f6d9-d027-4a47-924c-1d78000de8fd/location`

**Why enumeration doesn't work here:** a version-4 UUID has 122 bits of randomness. Brute
force is computationally infeasible and will get your source IP blocked long before you find a
valid hit. The mistake many newer testers make is assuming UUID = "safe from BOLA." It is not
safe from BOLA — it is only safe from *enumeration*. The authorization check can still be
completely missing; you just need a different way to obtain a valid target UUID.

**Technique: disclosure-based discovery.** Find the target UUID leaked somewhere else in the
application, then use it directly against the vulnerable endpoint. Common disclosure points:
- A public or semi-public feed, community post, or comment section that embeds another user's
  object ID as metadata (author info, linked resource ID) even though the UI never displays
  the raw UUID.
- A response body from an *unrelated* endpoint that returns more fields than the UI renders —
  inspect every field in every JSON response, not just the ones shown on screen.
- Autocomplete/search/typeahead endpoints that return full object records (including IDs)
  for a broader set of results than the UI displays.
- Export/report features that include internal IDs in a CSV or PDF not meant for that purpose.
- Client-side JavaScript bundles or mobile app binaries containing hardcoded test/demo object
  IDs, or ID-generation logic that reveals the format.

**Example from crAPI:** the community/posts endpoint returns each post's author metadata,
including that author's `vehicleid` (a UUID), even though the UI only ever displays the post
text. Copying that UUID into the vehicle-location endpoint with your own (unrelated) token
returns that other user's live GPS coordinates. The bypass isn't a code trick — it's simply
that the disclosure endpoint and the sensitive endpoint were built by different people, and
nobody connected the fact that leaking the UUID in one place defeats the "you can't guess it"
assumption protecting the other place.

```
GET /identity/api/v2/vehicle/5704f6d9-d027-4a47-924c-1d78000de8fd/location HTTP/1.1
Authorization: Bearer <your own, unrelated token>
```
Every part of this request belongs to you except the UUID, which was sourced from the
community feed response, not guessed. That's the entire technique: authenticate as yourself,
supply an object ID you were never supposed to be able to obtain, and see whether the server
checks ownership before returning the location data.

## 3. Hashed IDs — same disclosure logic, plus algorithm/salt analysis

**Format example:** `/api/v1/documents/a94a8fe5ccb19ba61c4c0873d391e987982fbbd3`

Hashed IDs (often a hash of the underlying sequential integer, sometimes combined with a
secret salt — "hashids" libraries are a common implementation) are meant to look
non-enumerable while still being deterministic and reversible by the backend.

**Technique 1: disclosure-based**, identical to UUID handling above — find the hash leaked
elsewhere in the app and reuse it directly.

**Technique 2: pattern/algorithm analysis**, when you have several hashes tied to sequential
resources of your own (e.g., document 1, 2, 3 created back to back). If the hashing scheme is
unsalted or uses a weak/short custom scheme (some in-house "obfuscation" functions are not
cryptographic hashes at all, just base64 or reversible encoding dressed up to look like a
hash), compare the outputs for your own known-sequential objects. Repeating, short, or
low-entropy hash outputs, or hashes that change length/format for edge-case IDs, are signs the
scheme is a weak or non-cryptographic transform rather than a real hash — decode or reverse it
directly rather than treating it as opaque.

**Technique 3: length/charset fingerprinting** to distinguish a real cryptographic hash from
an encoding. If the "hash" is exactly 24 or 32 characters and only uses base64/base62
alphabet with no padding oddities, and especially if changing one digit of the underlying
integer changes the encoded value in a locally-predictable way, it's very likely a reversible
encoding (see section 4) rather than a one-way hash, and should be treated as such.

## 4. Encoded IDs — decode, modify, re-encode

**Format example:** `/api/v1/profile/NDQ3MQ==` (base64 of `4471`)

**Technique:** decode the ID, confirm it maps to a recognizable underlying value (usually a
sequential integer or a JSON structure), modify the underlying value the same way you would a
plain sequential ID, then re-encode it in the same format before sending.

```
echo "NDQ3MQ==" | base64 -d
# 4471
echo -n "4472" | base64
# NDQ3Mg==
```
Breakdown: the first command reverses the encoding to reveal the real object identifier is
just the integer `4471` — encoding was providing obfuscation, not authorization. The second
command produces the encoded form of `4472` (a neighboring, presumably valid, object ID owned
by someone else), formatted exactly as the API expects it. Swapping `NDQ3MQ==` for `NDQ3Mg==`
in the request is functionally identical to the plain sequential-ID swap in section 1 — the
encoding step is pure ceremony from the authorization check's perspective, since the check
that's actually missing operates on the decoded value, not the encoded string.

Watch for multi-layer encoding (base64 of a JSON object, base64 of a hashid, URL-encoded
base64) — decode fully, one layer at a time, before concluding the underlying format.

## 5. Non-obvious location 1: indirect object references inside request bodies

Most testers reflexively check the URL path and query string and stop there. On modern
JSON APIs, object references frequently live inside the request body instead, especially on
POST/PUT/PATCH endpoints, and are easy to miss on a quick read because they're nested a level
or two deep.

```
PATCH /api/v1/cart/checkout HTTP/1.1
Content-Type: application/json
Authorization: Bearer <Account A's token>

{
  "cartId": 991,
  "shippingAddressId": 55,
  "paymentMethodId": 77,
  "promoCode": "SUMMER10"
}
```
This single request body has **three separate object references** (`cartId`,
`shippingAddressId`, `paymentMethodId`), each of which is an independent BOLA test target.
Testing one and stopping is a coverage gap — an endpoint can correctly check `cartId` ownership
while never validating that `shippingAddressId` and `paymentMethodId` actually belong to the
requesting user, allowing an attacker to check out using their own cart but silently ship to
or bill another user's saved address/payment method. Test each field independently, one swap
at a time, to isolate exactly which reference is unchecked.

## 6. Non-obvious location 2: references disclosed in a response and reused in a later request

Some APIs generate a session-scoped or short-lived object reference in one response and expect
the client to pass it back in a subsequent request (a common pattern in multi-step checkout,
file upload, or workflow-state APIs). The vulnerability here is that the reference, once
issued, is sometimes treated as sufficient proof of authorization all on its own — the backend
checked ownership when it *issued* the reference, but never re-checks it when the reference
comes back in a later request.

**Technique:** trigger the flow as Account A to capture the intermediate reference from the
response, then trigger the same flow as Account B far enough to get a *different* intermediate
reference, and finally submit the *final* step of the flow as Account A but using Account B's
intermediate reference. If the final step succeeds, the backend is trusting the reference
itself as a capability token rather than re-validating ownership at the point of use — a
subtler variant of BOLA that pure URL/body-field scanning will not surface, because it
requires understanding the multi-step flow first.

## 7. Non-obvious location 3: BOLA via HTTP method — protected on GET, unprotected on POST/PUT/DELETE

Covered briefly in file 02 step 4, expanded here because it's a distinct enough technique to
call out on its own. The authorization middleware in many frameworks is attached per-route,
and it is common for a team to write and review the read (GET) path carefully while a write
path (POST/PUT/PATCH/DELETE) on the exact same resource is added later, by a different
developer, without inheriting the same check.

**Technique:** for every object-referencing endpoint, don't stop after confirming GET is
protected. Explicitly try every other method the resource plausibly supports, keeping the same
target object ID and the same non-owning account's token:

```
DELETE /api/v1/documents/8842 HTTP/1.1
Authorization: Bearer <Account A's token>
```
If GET on `/api/v1/documents/8842` correctly returns 403 for Account A, but this DELETE
succeeds and removes Account B's document, the finding is materially worse than a
read-only BOLA — it's unauthorized destruction of another user's data — and should be reported
at higher severity accordingly. Confirm supported methods first with an `OPTIONS` request or
by checking the API's OpenAPI spec, so you're not guessing blindly at what the resource
supports.

## 8. Real-world framing for this file

The pattern across every technique above is the same: obfuscating an object ID (hashing,
encoding, switching to UUIDs) is a defense against *guessing*, not a substitute for an
*authorization check*. Production incidents repeatedly show teams treating "the ID is hard to
guess" as equivalent to "the ID is protected," when the two are unrelated properties. A UUID
with zero ownership validation is exactly as broken as a sequential integer with zero ownership
validation — it just takes a different discovery technique to prove it.

## 9. What's next

`04-Burp-Suite-Testing-Workflow.md` turns the manual techniques in this file and in file 02
into a repeatable Burp Suite Community Edition workflow, including Autorize configuration for
automating the "same request, different account" comparison at scale.
