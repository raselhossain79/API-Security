# BFLA — Cheatsheet

Quick-reference for live engagements. See files 01–05 for full mechanism explanations and worked examples.

---

## 1. One-Line Definition

> BFLA = the API checks **who you are**, but not **whether your role may call this specific function**.

**BOLA vs BFLA, in one line each:**
- BOLA — wrong *object*, right function. ("Can I read someone else's record through a function I'm allowed to use?")
- BFLA — wrong *function*, regardless of object. ("Can I call a function I should never reach at all?")

---

## 2. Discovery Checklist

- [ ] Path-guess admin/internal segments: `admin, administrator, internal, staff, manage, manager, backend, console, _admin`
- [ ] Pull and grep every JS bundle (including lazy-loaded chunks) for `fetch(`, `axios.`, and `/api/` path strings
- [ ] Check for exposed sourcemaps (`*.js.map`)
- [ ] Check for exposed API docs: `/swagger.json`, `/api-docs`, `/openapi.json`, `/v2/api-docs`, `/redoc`
- [ ] Run GraphQL introspection if a `/graphql` endpoint exists
- [ ] Inspect every response body for `role`, `isAdmin`, `permissions`, `_links`, `accountType` fields
- [ ] Send `OPTIONS` to every known path, read the `Allow:` header for undocumented verbs
- [ ] Grep JS for suspicious flags: `admin, debug, override, elevated, bypass, impersonate, sudo`

---

## 3. Exploitation Patterns Quick Reference

| Pattern | Try this |
|---|---|
| **Method switching** | Same path, sweep `GET/POST/PUT/PATCH/DELETE` with low-priv token |
| **Path manipulation** | Insert `admin`/`internal`/`manage` into known paths at every plausible position |
| **Parameter role manipulation** | Add/flip `role`, `isAdmin`, `permissions` in body; try `?asAdmin=true`, `?debug=true`; try headers `X-User-Role`, `X-Admin`, `X-Internal-Request` |

**Golden rule:** always compare **full response body**, not just status code — many APIs return `200 OK` with an error-shaped body instead of `403`.

---

## 4. Escalation Classification

- **Vertical** — lower role reaches higher role's function (user → admin).
- **Lateral (cross-tenant)** — admin of Org A reaches admin functions scoped to Org B.
- **Lateral (cross-role)** — role A reaches role B's function set, neither strictly "above" the other (support agent → billing agent function).

Always state starting role, reached role/scope, isolated vs. systemic, and whether it chains into BOLA or mass assignment.

---

## 5. curl One-Liners

**Baseline vs low-priv replay:**
```bash
# High-privilege baseline
curl -s -X POST https://api.target.com/admin/users/2201/suspend \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"reason":"test"}'

# Low-privilege replay — only the token changes
curl -s -X POST https://api.target.com/admin/users/2201/suspend \
  -H "Authorization: Bearer $LOWPRIV_TOKEN" -H "Content-Type: application/json" \
  -d '{"reason":"test"}'
```

**Verb sweep against one path:**
```bash
for M in GET POST PUT PATCH DELETE; do
  echo "== $M =="
  curl -s -o /dev/null -w "%{http_code}\n" -X $M \
    https://api.target.com/api/users/1042 \
    -H "Authorization: Bearer $LOWPRIV_TOKEN"
done
```

**OPTIONS allow-header check:**
```bash
curl -s -i -X OPTIONS https://api.target.com/api/users/1042 \
  -H "Authorization: Bearer $LOWPRIV_TOKEN" | grep -i allow
```

**GraphQL introspection:**
```bash
curl -s -X POST https://api.target.com/graphql \
  -H "Authorization: Bearer $LOWPRIV_TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{types{name fields{name}}}}"}'
```

---

## 6. Burp Workflow — Condensed

1. Capture privileged action as high-priv role → Send to Repeater.
2. Duplicate tab → swap only `Authorization`/cookie to low-priv token.
3. Compare full response bodies in **Comparer**, not just status codes.
4. Scale up with **Autorize** (live browsing replay) or **AuthMatrix** (fixed role × request matrix).
5. Confirm real persisted effect before reporting state-changing findings.

---

## 7. PortSwigger Lab Order (Function-Level Focus)

1. Unprotected admin functionality
2. Unprotected admin functionality with unpredictable URL
3. User role controlled by request parameter
4. User role can be modified in user profile
5. Multi-step process with no access control on one step
6. Referer-based access control

*(Note: PortSwigger has no dedicated BFLA category — these are selected from "Access Control." IDOR/User-ID-parameter labs are BOLA, not BFLA — see the BOLA series.)*

**crAPI:** workshop/mechanic-role endpoints and vehicle/service management functions — the more accurate API-native BFLA practice ground.

---

## 8. Reporting Severity Signals

Push toward **Critical** when the reached function:
- Writes, deletes, or executes (not just reads)
- Affects other users' accounts/data at scale (bulk/export functions)
- Chains into further privilege gain (impersonation, role self-elevation)
- Reproduces systemically across multiple unrelated admin functions (architectural gap, not one-off bug)

Push toward **Medium** when the reached function:
- Is read-only, low-sensitivity, and isolated to one endpoint
- Requires additional non-trivial preconditions to reach (e.g., a hard-to-guess unpredictable URL with no other disclosure vector found)
