# Shadow and Zombie API Identification

This file covers the highest-value output of the entire recon phase. Shadow and zombie
APIs are consistently the source of the most severe findings in real engagements,
precisely because they exist outside the systems that would normally catch a
vulnerability — no monitoring, no active maintenance, often no authentication that was
ever properly finished being implemented.

## 1. Definitions and the Difference Between Them

The terms get used loosely in industry writing, so it's worth being precise:

- **Shadow API** — an endpoint that exists and is reachable but was never officially
  documented, tracked, or approved through normal API governance. It may be entirely
  new (a developer added a quick endpoint for a feature and never registered it with
  the API gateway/documentation process) rather than old.
- **Zombie API** — an endpoint or entire API version that *was* documented and
  officially released at some point, was later deprecated or superseded, but was never
  actually decommissioned — it's still running, still reachable, and often still
  running on outdated dependencies with none of the security patches applied to the
  current version.
- **Related but distinct: debug/test endpoints** — routes added during development
  (health checks with verbose internal state output, test data seeding endpoints,
  feature flags left toggleable via query parameter) that were never intended to reach
  production at all, as opposed to shadow/zombie APIs which are legitimate business
  functionality that simply fell outside tracking.

All three categories get surfaced by the same discovery techniques from file 3 — this
file is about how to specifically recognize and prioritize them once you have discovery
output in hand.

## 2. Finding Zombie API Versions

### The core technique: version enumeration against confirmed endpoints

Once you've confirmed an endpoint exists at one version (e.g. `/api/v2/users`), test
whether the same resource is reachable under other version prefixes.

```bash
for version in v1 v2 v3 beta internal legacy; do
  echo -n "/api/$version/users: "
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.example.com/api/$version/users"
done
```

Breakdown:
- `for version in v1 v2 v3 beta internal legacy; do ... done` — loops over common
  versioning conventions; the non-numeric entries (`beta`, `internal`, `legacy`) are
  included deliberately because real organizations don't only use numeric versioning —
  these string-based prefixes are extremely common for exactly the kind of
  half-forgotten internal tooling this file is about.
- The rest of the command follows the same silent-request, print-status-code pattern
  established in earlier files.
- A `200` on `/api/v1/users` when the current documented version is `v2` is the
  textbook zombie API signal — confirm it independently rather than assuming it's
  identical to v2's behavior, since older versions frequently have weaker or entirely
  absent access control checks that were only added in later versions.

### Systematic version discovery across a whole endpoint list

Rather than checking one resource at a time, take your full discovered endpoint list
from file 3 and test each one against every version prefix:

```bash
while read -r endpoint; do
  resource=$(echo "$endpoint" | sed -E 's|^/api/v[0-9]+/||')
  for version in v1 v2 v3; do
    curl -s -o /dev/null -w "/api/$version/$resource -> %{http_code}\n" \
      "https://api.example.com/api/$version/$resource"
  done
done < discovered-endpoints.txt
```

Breakdown:
- `while read -r endpoint; do ... done < discovered-endpoints.txt` — reads the
  discovered-endpoints file line by line, assigning each line to `$endpoint`; `-r`
  prevents backslash characters in the input from being interpreted as escape sequences,
  which matters because endpoint paths can legitimately contain backslash-adjacent
  characters in edge cases.
- `resource=$(echo "$endpoint" | sed -E 's|^/api/v[0-9]+/||')` — strips any existing
  version prefix from the endpoint using extended regex (`-E`), so `/api/v2/users`
  becomes just `users`; this isolates the resource name so it can be recombined with
  every version prefix being tested.
- The inner `for version in v1 v2 v3` loop and curl call rebuild the URL with each
  version prefix against the isolated resource name and report the status code for
  each combination.

## 3. Finding Undocumented Admin Endpoints

Admin functionality is disproportionately likely to be under-protected specifically
because it's assumed to be "hidden" rather than properly access-controlled — a security
posture sometimes called security through obscurity, and one that recon exists to
defeat directly.

### Wordlist strategy specific to admin discovery

Generic API wordlists under-represent admin-specific naming. Supplement your combined
wordlist from file 3 with admin-specific terms:

```
admin
administrator
internal
staff
backoffice
console
dashboard
manage
management
_admin
admin-api
internal-api
ops
operator
superuser
```

Run these both as standalone path segments and as prefixes/suffixes combined with
already-discovered resource names (e.g., if `/api/v1/users` is known, also try
`/api/v1/admin/users` and `/api/v1/users/admin`).

### Real-world note on why this specific pattern recurs

Admin panels frequently get built as an afterthought late in a project, using the same
authentication middleware copy-pasted from the main API but missing a role check that
was supposed to be added "later." Finding the admin endpoint via recon and then testing
whether a standard, non-admin authenticated session can reach it is one of the highest
signal-to-effort test sequences in API assessment — it directly chains recon into a
broken access control (BOLA/BFLA-style) finding.

## 4. Finding Test and Debug Endpoints Left in Production

### Common naming patterns to test for

```
/api/v1/debug
/api/v1/test
/api/v1/_test
/api/v1/health/verbose
/api/v1/status/full
/api/v1/config
/api/v1/env
/api/v1/actuator
/api/v1/actuator/env
/api/v1/.env
/api/internal/seed
/api/internal/reset
```

**Note on `/actuator`:** Spring Boot's Actuator module is a recurring, specific example
worth calling out by name — it exposes operational endpoints (`/actuator/env`,
`/actuator/heapdump`, `/actuator/beans`) intended for internal monitoring, and when
accidentally left reachable without authentication, can leak environment variables
(frequently including database credentials or API keys), full heap dumps, and internal
application configuration. This single misconfiguration pattern has been responsible for
a large number of real-world breaches and is always worth a dedicated check against any
Java/Spring-based API target.

```bash
curl -s "https://api.example.com/actuator/env" -o actuator-env.json
curl -s -o /dev/null -w "%{http_code}\n" "https://api.example.com/actuator/env"
```

Breakdown:
- Identical curl pattern to earlier files; the first line saves the body if the endpoint
  responds with actual content, the second confirms the status code independently. A
  `200` with a JSON body containing environment variable names and values is a critical
  severity finding on its own, before any further exploitation.

## 5. Prioritizing What You Find

Not every shadow/zombie endpoint carries equal risk. A practical triage order for a
real engagement report:

1. **Zombie versions with write/delete methods available** — old API versions that
   still accept POST/PUT/DELETE, since they combine outdated (likely unpatched) code
   with destructive capability.
2. **Debug/config endpoints leaking credentials or environment data** — immediate
   critical severity regardless of what else is found, since they often provide direct
   pivot points into other systems (databases, cloud provider APIs).
3. **Undocumented admin endpoints reachable with standard-user authentication** — chains
   directly into a broken access control finding, typically high severity.
4. **Zombie versions that are read-only but expose more data fields than the current
   version** — an excessive data exposure finding, since older API versions frequently
   predate later "field filtering" security work.
5. **Test/seed endpoints** — severity depends heavily on function; a `/reset` endpoint
   that wipes or reseeds data is a business-impact and availability concern even without
   any data exposure component.

## 6. PortSwigger Academy Coverage

**No dedicated coverage.** This is the area of the entire series with the widest gap
between Academy's lab catalog and real-world API testing needs — Academy's access
control and information disclosure labs touch pieces of this conceptually, but there is
no lab built around discovering a deprecated API version or an Actuator-style
misconfiguration.

This is a primary reason this series recommends crAPI specifically: it ships with a
genuine multi-service microservice architecture including intentionally-included
older/internal endpoints that mirror the exact scenario this file describes, making it
by far the most representative hands-on environment for this specific skill among the
three alternatives listed in the README. HackTheBox boxes tagged with API or
web-service categories are the next best option, since several include a deliberately
placed forgotten admin or debug route as part of the intended attack chain.

## 7. Next File

Continue to `05-api-documentation-analysis.md` to learn how to fully extract the attack
surface from any documentation artifacts (specs, Postman collections, GraphQL schemas)
recovered during passive recon, before or alongside running the active techniques in
this and the previous file.
