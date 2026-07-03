# BOPLA Cheatsheet — Quick Reference

Condensed reference for live engagements. Full explanations are in files 1–3.

---

## 1. Two-question mental model

For every field on every object you're already authorized to touch, ask:

1. **Read**: Should this specific role be able to *see* this field? (Excessive Data Exposure)
2. **Write**: Should this specific role be able to *set* this field? (Mass Assignment)

If either answer is "no" but the API allows it anyway — that's BOPLA.

---

## 2. Excessive Data Exposure — quick checklist

- [ ] Diff every response field against what the UI actually renders
- [ ] Repeat the same request with tokens from every available role (unauth, user, premium, admin)
- [ ] Check list/collection endpoints separately from single-object endpoints — same object,
      different serializer, different bug
- [ ] Check every endpoint that returns the same underlying object (`/users/{id}`, `/users/me`,
      nested inside `/orders/{id}`, etc.) — each has its own serializer
- [ ] Log every exposed field name + value as wordlist input for Mass Assignment testing

---

## 3. Mass Assignment — quick checklist

- [ ] Build a hidden-parameter wordlist from GET responses (Source 1, most reliable)
- [ ] Test every `POST` / `PUT` / `PATCH` endpoint, not just "obviously sensitive" ones
- [ ] Baseline → valid injected value → invalid injected value (differential test) → real
      out-of-band impact verification
- [ ] If blocked, run the filter bypass matrix below before concluding it's not exploitable

---

## 4. Candidate field name wordlist

Privilege / role:
```
isAdmin  is_admin  IsAdmin  admin  role  roles  permissions  permission
userType  user_type  accountType  account_type  scope  scopes
```

Verification / trust flags:
```
isVerified  is_verified  emailVerified  email_verified  isActive  is_active
isFlagged  is_flagged  isTrusted  is_trusted  kycVerified  kyc_verified
```

Financial:
```
balance  credits  creditBalance  credit_balance  price  discount  discountPercentage
percentage  amount  quota  limit  walletBalance  wallet_balance
```

Ownership / relational:
```
userId  user_id  ownerId  owner_id  groupId  group_id  organizationId  org_id
tenantId  tenant_id  parentId  parent_id
```

State / lifecycle:
```
status  isDeleted  is_deleted  isPublished  is_published  isApproved  is_approved
isPremium  is_premium  tier  subscriptionTier  subscription_tier  plan
```

Try each in three casing forms minimum: `camelCase`, `snake_case`, and the literal capitalized
class-field form (`IsAdmin`) — see file 3, Section 4.1.

---

## 5. Filter bypass matrix

| Technique | What to try | Why it can work |
|---|---|---|
| Alt casing | `is_admin` → `isAdmin` → `IsAdmin` → `ADMIN` | Filter and binder use different naming transforms |
| Nesting | `{"profile":{"role":"admin"}}` | Filter only inspects top-level keys |
| Array/batch | `{"users":[{"role":"admin"}]}` | Batch endpoints reuse different, less-scrutinized binding code |
| Content-Type swap | JSON → form-urlencoded → XML | Blocklist middleware only runs on one parser's code path |
| Param pollution | Same key in query string + body | Validation reads one location, binding reads the other |
| Unicode variants | Full-width / NFKC-foldable characters | Normalization happens after the filter check |
| GraphQL sibling | Same field via GraphQL mutation instead of REST | Schema and REST validation maintained separately |

Full explanation of each row is in file 3, Section 4.

---

## 6. Burp Suite workflow

1. **Comparer** — role-based response diffing (EDE). Send both raw responses, diff in "words" mode.
2. **Autorize extension** — bulk first pass: re-sends proxied traffic with a lower-privilege
   token and flags responses that still return data.
3. **Param Miner extension** — automated hidden-parameter guessing for Mass Assignment recon
   (Source 3 in file 3, Section 2).
4. **Intruder** — manual wordlist-driven field injection using the list in Section 4 above,
   sniper attack on a single injection position appended to a known-good baseline body.
5. **Repeater** — the actual differential valid/invalid value testing (file 3, Section 3);
   keep baseline, valid-value, and invalid-value requests in separate tabs for fast comparison.

---

## 7. BOLA / BFLA / BOPLA one-line distinction

- **BOLA** — wrong *object* (someone else's data via ID manipulation)
- **BFLA** — wrong *endpoint/function* (an action this role shouldn't be able to call at all)
- **BOPLA** — wrong *field* on an object you're already allowed to access

---

## 8. Mitigation reference (for reports)

- Use dedicated input DTOs / request models, never bind directly onto the database entity/model
- Explicit allowlist of writable fields per role, enforced server-side, not just hidden in the
  frontend form
- Explicit allowlist of returned fields per role via role-aware serializers, not a single shared
  serializer reused across admin and public endpoints
- Reject requests containing unrecognized fields outright (strict schema validation) rather than
  silently ignoring them — silent ignoring makes future regressions invisible
- Apply the same allowlist consistently across single-object, list, batch, and nested-update
  endpoints for the same model

---

## 9. Lab and practice index

| Resource | Covers | Order |
|---|---|---|
| PortSwigger — Exploiting an API endpoint using documentation | EDE-adjacent recon skill | 1st |
| PortSwigger — Access control labs (BOLA-framed, useful for EDE field-reading practice) | EDE-adjacent | 2nd |
| PortSwigger — Exploiting a mass assignment vulnerability | Mass Assignment (baseline, no filter) | 3rd |
| crAPI — vehicle location / user identity endpoints | Excessive Data Exposure | Ongoing |
| crAPI — mechanic report assignment, shop coupon/credit endpoints | Mass Assignment + filter bypass practice | Ongoing |

PortSwigger has no dedicated graduated difficulty ladder for BOPLA yet (see files 2 and 3 for
full gap disclosure) — crAPI is the primary hands-on target for depth beyond the single
PortSwigger lab.

---

## 10. crAPI quick endpoint list

```
/identity/api/v2/user/*        → EDE testing (profile/identity data)
/workshop/api/*                → Mass assignment (mechanic report assignment)
/community/api/*                → EDE testing (forum/community data exposure)
/workshop/api/shop/*            → Mass assignment (coupons, credits, pricing fields)
```
