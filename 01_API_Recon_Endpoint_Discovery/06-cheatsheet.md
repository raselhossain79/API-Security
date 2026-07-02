# API Recon and Endpoint Discovery — Cheatsheet

A condensed, engagement-ready quick reference. Full explanations for every command here
live in the numbered files and `tools/` directory — this file is for lookup during an
active engagement, not for learning the concepts the first time.

## Pre-Engagement Checklist

- [ ] Scope confirmed: which domains/subdomains/API versions are in scope
- [ ] Auth: obtain at least one valid standard-user session/token before active testing
- [ ] Note whether active DNS techniques (Amass `-active`) are authorized

## Phase 1 — Passive Recon

```bash
# Swagger/OpenAPI spec path sweep
for path in swagger.json swagger.yaml api-docs openapi.json v2/api-docs v1/swagger.json; do
  curl -s -o /dev/null -w "%{http_code} /$path\n" "https://api.example.com/$path"
done

# JS endpoint mining
curl -s "https://app.example.com/static/js/main.js" | grep -Eo '"(\/api\/[a-zA-Z0-9\/_\-]+)"' | sort -u

# Google dorks
site:example.com inurl:swagger
site:example.com filetype:json inurl:swagger
site:postman.com "example.com" intitle:"API documentation"

# Wayback Machine
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com/api/*&output=text&fl=original&collapse=urlkey" | sort -u
echo "example.com" | waybackurls | grep "/api/" | sort -u

# Certificate transparency
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u
```

## Phase 2 — Documentation Analysis

```bash
# OpenAPI: list all paths
jq -r '.paths | keys[]' openapi.json

# OpenAPI: paths + methods
jq -r '.paths | to_entries[] | "\(.key): \(.value | keys | join(", "))"' openapi.json

# OpenAPI: all parameters
jq -r '.paths[][] | .parameters[]? | "\(.name) (\(.in)): \(.schema.type // "unspecified")"' openapi.json

# Postman: all request URLs
jq -r '.. | .request?.url?.raw? // empty' collection.json | sort -u

# GraphQL: introspection
curl -s -X POST "https://api.example.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name}}}}"}' -o schema.json

# GraphQL: list mutations
jq -r '.data.__schema.types[] | select(.name=="Mutation") | .fields[].name' schema.json
```

## Phase 3 — Active Discovery

```bash
# Endpoint brute-force (ffuf)
ffuf -u https://api.example.com/FUZZ -w combined-wordlist.txt \
  -mc 200,201,204,301,302,401,403 -t 40

# Route-structure brute-force (kiterunner)
kr scan https://api.example.com -w routes-large.kite -x 20 -H "Authorization: Bearer <token>"

# HTTP method enumeration
for method in GET POST PUT DELETE PATCH OPTIONS HEAD; do
  curl -s -o /dev/null -w "$method: %{http_code}\n" -X "$method" "https://api.example.com/endpoint"
done
curl -s -X OPTIONS -i "https://api.example.com/endpoint" | grep -i "^allow:"

# Parameter discovery (Arjun)
arjun -u https://api.example.com/endpoint -m POST -w custom-params.txt

# Content-type fuzzing
curl -s -X POST "https://api.example.com/endpoint" -H "Content-Type: application/xml" \
  -d '<user><name>test</name></user>' -w "\n%{http_code}\n"
```

## Phase 4 — Shadow / Zombie API Discovery

```bash
# Version enumeration
for version in v1 v2 v3 beta internal legacy; do
  curl -s -o /dev/null -w "/api/$version/users: %{http_code}\n" "https://api.example.com/api/$version/users"
done

# Common debug/config paths
/actuator/env
/actuator/heapdump
/api/v1/debug
/api/v1/health/verbose
/api/v1/.env
/api/internal/seed
/api/internal/reset

# Admin wordlist supplement
admin admin-api internal-api backoffice console dashboard ops superuser
```

## Phase 5 — Subdomain Recon

```bash
subfinder -d example.com -silent -o subfinder-results.txt
amass enum -passive -d example.com -o amass-passive.txt
amass enum -active -d example.com -brute -w subdomain-wordlist.txt -o amass-active.txt

cat amass-active.txt subfinder-results.txt | sort -u | httpx -silent -status-code -title
```

## Severity Triage Quick Reference (from file 4)

1. Zombie API versions with write/delete methods still enabled
2. Debug/config endpoints leaking credentials or environment data
3. Undocumented admin endpoints reachable with standard-user auth
4. Zombie versions exposing more data fields than the current version
5. Test/seed endpoints with destructive or data-altering effects

## Practice Environment Quick Reference

| Technique area | Best environment |
|---|---|
| Passive recon (JS mining, spec discovery) | crAPI |
| Parameter discovery, method enumeration | DVAPI, then crAPI |
| Shadow/zombie API identification | crAPI, then HackTheBox API-tagged boxes |
| GraphQL introspection | PortSwigger Academy (strong dedicated coverage) |
| Everything else | crAPI as primary, HackTheBox as secondary |

## Series Navigation

1. `01-overview-and-methodology.md`
2. `02-passive-reconnaissance.md`
3. `03-active-discovery.md`
4. `04-shadow-and-zombie-apis.md`
5. `05-api-documentation-analysis.md`
6. `06-cheatsheet.md` (this file)
7. `tools/kiterunner.md`
8. `tools/arjun.md`
9. `tools/ffuf-api-fuzzing.md`
10. `tools/amass-subfinder.md`
