# API Security Testing Tooling — Quick-Reference Cheatsheet

Condensed command reference. Full flag-by-flag explanations live in the numbered
files (01–08) referenced next to each section.

## Recon Order of Operations
1. truffleHog/gitleaks against any git repos in scope (file 04)
2. katana crawl (`-jc -kf all`) + ffuf/kiterunner brute-force (files 03, 07)
3. httpx to validate/fingerprint everything discovered (file 07)
4. Arjun/Param Miner for hidden parameters on confirmed live endpoints (files 02, 03)
5. Manual triage in Burp with Autorize/InQL/JWT Editor as relevant (file 02)
6. nuclei + graphql-cop + RESTler for automated scanning at scale (file 05)
7. grpcurl for any gRPC services (file 06)
8. Build a Postman collection with test-script assertions for regression retesting (file 06)

## ffuf (file 03)
```
ffuf -u https://api.target.com/v1/FUZZ -w wordlist.txt -H "Authorization: Bearer $T" \
     -mc 200,201,204 -t 30 -rate 50 -o out.json -of json
```
JSON body fuzzing:
```
ffuf -u URL -X POST -H "Content-Type: application/json" \
     -d '{"role":"FUZZ"}' -w roles.txt -mc 200,201
```

## kiterunner (file 03)
```
kr scan https://api.target.com -w routes-large.kite -x 20 -j -A "Bearer $T"
```

## Arjun (file 03)
```
arjun -u https://api.target.com/v1/search -m JSON --data '{"q":"test"}' \
      --headers "Authorization: Bearer $T" -oJ out.json
```

## Burp extensions (file 02)
- **Autorize**: paste low-priv token in Headers field → toggle Interception On →
  browse as high-priv user → review red/yellow flags.
- **InQL**: enter GraphQL URL → Run Scan → browse schema tree → Send to Repeater.
- **JWT Editor**: JWT Editor Keys tab to create keys → per-request JWT tab → edit
  claims → Sign, or use Attack → None / Embedded JWK / JWK Key ID.
- **HTTP Request Smuggler**: right-click → Extensions → Smuggle Probe.
- **Param Miner**: right-click → Guess params / Guess headers.

## jwt_tool (file 04)
```
python3 jwt_tool.py <JWT> -t https://api.target.com/v1/profile -M pb    # playbook scan
python3 jwt_tool.py <JWT> -X a -t URL                                    # none-alg attack
python3 jwt_tool.py <JWT> -X k -pk pubkey.pem -t URL                     # key confusion
python3 jwt_tool.py <JWT> -C -d rockyou.txt                              # crack HMAC secret
```

## truffleHog / gitleaks (file 04)
```
trufflehog git https://github.com/org/repo.git --only-verified --json
gitleaks detect --source ./repo --report-format json --report-path out.json
```

## nuclei (file 05)
```
nuclei -l live-endpoints.txt -tags api,exposure,misconfig,swagger,openapi \
       -H "Authorization: Bearer $T" -rl 20 -c 10 -json-export out.json
```

## graphql-cop (file 05)
```
graphql-cop -t https://api.target.com/graphql -H "Authorization: Bearer $T" -o out.json
```

## RESTler (file 05)
```
restler compile --api_spec swagger.json
restler fuzz --grammar_file Compile/grammar.py --dictionary_file Compile/dict.json \
              --settings engine_settings.json --target_ip <ip> --target_port 443 --time_budget 2.0
```

## grpcurl (file 06)
```
grpcurl -plaintext target:50051 list                                     # list services (if reflection on)
grpcurl -plaintext target:50051 describe pkg.Service.Method               # schema
grpcurl -plaintext -d '{"user_id":"1"}' -H "Authorization: Bearer $T" \
        target:50051 pkg.Service/Method
```

## Newman (file 06)
```
newman run collection.json -e environment.json --reporters cli,json \
       --reporter-json-export results.json --delay-request 200
```

## httpx (file 07)
```
cat candidates.txt | httpx -silent -status-code -title -tech-detect -json -o live.json
```

## katana (file 07)
```
katana -u https://app.target.com -d 3 -jc -kf all -H "Authorization: Bearer $T" \
       -mr "/api/" -silent -o endpoints.txt
katana -u URL -headless -xhr -silent   # capture actual runtime API calls on SPAs
```

## jq (file 07)
```
jq '.'                                              # pretty-print
jq -r '.[].email'                                   # raw string extraction
jq '.[] | select(.role == "admin")'                 # filter
jq -s 'sort_by(.info.severity)'                      # slurp + sort
diff <(jq -S '.' before.json) <(jq -S '.' after.json) # retest diff
```

## Wordlists (file 08)
- SecLists: `Discovery/Web-Content/api/`, `swagger.txt`, `graphql.txt`,
  `Discovery/Variables/`
- Assetnote: `httparchive_apiroutes_*`, `automated-api-*`

## crAPI (file 08)
```
docker compose -p crapi up -d       # start
docker compose -p crapi down -v     # stop + full reset
```
Frontend: `http://localhost:8888` · Mail catcher: `http://localhost:8025`
