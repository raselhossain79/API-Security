# API Reconnaissance — Cheatsheet

Condensed quick-reference for live engagements. Assumes you already understand
the mechanics from the other files in this series — flags here are not
re-explained in depth.

---

## Methodology Order

```
1. Passive recon (silent, no live target interaction)
2. Documentation analysis (if a spec was found)
3. Active discovery (touches live target/gateway defenses)
4. Shadow/zombie API identification
5. Consolidate into full endpoint map
```

---

## Passive Recon Quick Commands

**Swagger/OpenAPI path check:**
```bash
for path in swagger.json swagger.yaml swagger-ui.html api-docs api-docs.json \
  openapi.json openapi.yaml v2/api-docs v3/api-docs redoc docs; do
  echo "$(curl -s -o /dev/null -w '%{http_code}' "https://target.com/$path") - /$path"
done
```

**JS file endpoint mining:**
```bash
for js in $(curl -s https://target.com | grep -oP '(?<=src=")[^"]*\.js'); do
  curl -s "https://target.com$js" | grep -oE '"/api/[a-zA-Z0-9/_-]+"'
done | sort -u
```

**Google dorks:**
```
site:target.com inurl:swagger
site:target.com inurl:api-docs
site:target.com intitle:"swagger ui"
site:target.com filetype:json inurl:api
```

**Wayback Machine historical endpoints:**
```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original&collapse=urlkey" | grep -i "api"
```

**Certificate transparency (crt.sh):**
```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u | grep -iE "api|gateway|gw|graphql"
```

---

## Active Discovery Quick Commands

**Endpoint brute-force (ffuf):**
```bash
ffuf -u https://target.com/api/FUZZ -w api-wordlist.txt -mc 200,201,204,301,302,401,403 -fc 404 -t 40 -o results.json -of json
```

**Endpoint brute-force (kiterunner):**
```bash
kr scan https://target.com -w routes-large.kite -x 20 -j 10 -t 8 --fail-status-codes 400,404,426,502,503
```

**HTTP method enumeration:**
```bash
for m in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo "$m -> $(curl -s -o /dev/null -w '%{http_code}' -X "$m" https://target.com/api/users/123)"
done
```

**OPTIONS header check:**
```bash
curl -s -i -X OPTIONS https://target.com/api/users/123
```

**Parameter discovery (Arjun):**
```bash
arjun -u https://target.com/api/users/123 -m GET -o results.json -t 10 --stable
```

**Content-type fuzzing:**
```bash
for ct in "application/json" "application/xml" "application/x-www-form-urlencoded" "multipart/form-data"; do
  echo "$ct -> $(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: $ct" -d '{"test":"data"}' https://target.com/api/users)"
done
```

**Version fan-out (zombie API check):**
```bash
for v in v1 v2 v3 v4 beta internal legacy; do
  echo "$v -> $(curl -s -o /dev/null -w '%{http_code}' "https://target.com/api/$v/users")"
done
```

**Debug/internal path probing:**
```bash
for path in debug test internal admin _internal health-check actuator staging-only console; do
  echo "$path -> $(curl -s -o /dev/null -w '%{http_code}' "https://target.com/api/$path")"
done
```

**Diff documented vs. discovered endpoints:**
```bash
jq -r '.paths | keys[]' openapi.json | sort -u > documented-endpoints.txt
comm -13 documented-endpoints.txt discovered-endpoints.txt
```

---

## Documentation Analysis Quick Commands

**List every endpoint + method:**
```bash
jq -r '.paths | to_entries[] | .key as $path | .value | keys[] | "\($path) [\(.|ascii_upcase)]"' openapi.json
```

**List parameters for an endpoint:**
```bash
jq -r '.paths."/api/users/{id}".get.parameters[] | "\(.name) (\(.in)) - required: \(.required)"' openapi.json
```

**List request body schema fields/types:**
```bash
jq -r '.paths."/api/users".post.requestBody.content."application/json".schema.properties | to_entries[] | "\(.key): \(.value.type)"' openapi.json
```

---

## Subdomain Recon Quick Commands

**Subfinder:**
```bash
subfinder -d target.com -all -silent | grep -iE "api|gateway|gw|graphql|internal"
```

**Amass (passive):**
```bash
amass enum -passive -d target.com -o amass-passive.txt
```

**Amass (active — only with explicit authorization):**
```bash
amass enum -active -d target.com -brute -w api-subdomain-wordlist.txt -o amass-active.txt
```

**Confirm liveness of discovered subdomains:**
```bash
while read -r sub; do
  ip=$(dig +short "$sub")
  [ -n "$ip" ] && echo "$sub -> $ip"
done < api-subdomains.txt
```

---

## Status Code Interpretation Reference

| Code | Meaning |
|---|---|
| `200/201/204` | Endpoint exists and request succeeded |
| `301/302` | Endpoint exists, redirected |
| `401` | Endpoint exists, missing/invalid auth |
| `403` | Endpoint exists, auth recognized but insufficient permission |
| `404` | No matching route (usually doesn't exist) |
| `405` | Endpoint exists, method not supported on this route |
| `415` | Endpoint exists, content-type not accepted (often correct/secure behavior) |
| `429` | Rate-limited — slow down, rotate UA, or pause |

---

## WAF / Gateway Considerations Summary

- **Relevant to:** active brute-forcing (rate/behavioral detection), response
  normalization defeating 404/401/403 inference.
- **Not relevant to:** passive recon (no live target interaction at all).
- **Mitigations:** throttle (`-p` in ffuf, `--delay` in kiterunner), randomize
  timing, rotate User-Agent, avoid sequential wordlist order, validate
  "successful" hits manually against a baseline before trusting bulk scan
  results.

---

## Practice Environment Quick Reference

| Environment | Best For |
|---|---|
| PortSwigger — *Exploiting an API endpoint using documentation* (Apprentice) | Reading a spec to find an unused endpoint |
| PortSwigger — *Finding and exploiting an unused API endpoint* (Practitioner) | Discovering an endpoint absent from the front-end |
| crAPI (OWASP) | Structured, repeatable practice with known documented + undocumented endpoints across microservices |
| HackTheBox API-relevant boxes/challenges | Unstructured, realistic recon practice without labeled hints |

Note: PortSwigger has no dedicated recon lab category — its two applicable
labs are exploitation labs that happen to require a recon step first. This gap
is intentional to disclose rather than paper over; crAPI and HTB fill it.
