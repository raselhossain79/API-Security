# API Security Testing Tooling — Scanning Tools (nuclei, graphql-cop, RESTler)

Cross-reference: GraphQL series for GraphQL vulnerability theory, OWASP API Top 10
series for the vulnerability classes nuclei's API templates target.

## 1. nuclei — Template-Based Vulnerability Scanner

nuclei (ProjectDiscovery) runs YAML-defined templates against targets to detect
known CVEs, misconfigurations, and exposure patterns. For API testing, the relevant
template categories are under `exposures`, `misconfiguration`, `vulnerabilities`,
and a dedicated community-maintained `api` template tag.

### 1.1 Installation
```
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

### 1.2 Running API-Specific Templates (Full Flag Breakdown)

```
nuclei -u https://api.target.com -t exposures/ -tags api,exposure,misconfig \
       -H "Authorization: Bearer <token>" -rl 20 -c 10 -o nuclei-results.txt -json-export results.json
```

- `-u <url>`: single target URL. For multiple targets, use `-l <file>` with one
  URL per line instead.
- `-l <file>`: file containing a list of target URLs (typically fed from httpx's
  live-endpoint output — see file 07).
- `-t <path>`: path to a specific template or template directory to run (relative
  to nuclei's templates directory, `~/nuclei-templates` by default, or an absolute
  path to a custom template).
- `-tags <tags>`: comma-separated tags to filter which templates run. Common
  API-relevant tags: `api`, `exposure`, `misconfig`, `graphql`, `swagger`,
  `openapi`, `cors`, `token`, `jwt`, `default-login`. Combine tags to narrow scope,
  e.g., `-tags swagger,openapi` to specifically hunt for exposed API
  specification/documentation files.
- `-etags <tags>`: **exclude** templates with these tags — useful for suppressing
  noisy categories (e.g., `-etags dos` to avoid running any denial-of-service-style
  templates against a production target).
- `-severity <levels>`: filter templates by severity — `info`, `low`, `medium`,
  `high`, `critical`. E.g., `-severity high,critical` for a focused pass on the
  highest-impact findings first.
- `-H "<header>"`: custom header, repeatable — required for any template that needs
  to run against authenticated API endpoints.
- `-rl <n>`: rate limit — max requests per second across all templates/targets
  (analogous to ffuf's `-rate`). Critical to set conservatively (`-rl 10` to `-rl
  20`) against production API gateways with rate-limiting/WAF layers to avoid
  false negatives from throttled/blocked responses or triggering IP bans.
- `-c <n>`: concurrency — number of templates executed in parallel (default 25).
  Lower alongside `-rl` for stealthier/gentler scans.
- `-bs <n>`: bulk-size — number of hosts processed in parallel per template when
  scanning multiple targets via `-l` (distinct from `-c`, which controls template
  parallelism per host).
- `-timeout <n>`: per-request timeout in seconds.
- `-retries <n>`: number of retries on failed requests before giving up on that
  template/target combination — raise on flaky/high-latency targets to reduce
  false negatives from transient network errors.
- `-o <file>`: write results to a plain-text file.
- `-json-export <file>`: write results as JSON (preferred for piping into `jq` —
  file 07 — or ingesting into a reporting pipeline).
- `-markdown-export <dir>`: write results as individual markdown files, one per
  finding — convenient for pulling directly into a report skeleton.
- `-v`: verbose mode — prints every request attempted, not just matches (useful
  for debugging why a template isn't firing as expected).
- `-debug`: full debug mode, printing raw request/response pairs for every
  template execution — heaviest verbosity level, for template development/
  troubleshooting.
- `-nc`: disable colored output (for clean log file output/CI environments).
- `-stats`: print live scan statistics (templates run, requests/sec, matches
  found so far) during a long-running scan.

### 1.3 Writing a Basic Custom API Template

Custom templates are useful when you've identified a target-specific pattern (e.g.,
a specific internal API error message that reveals a debug endpoint, or a known
internal API key format found via truffleHog/gitleaks) and want to check for it
repeatably across many hosts.

```yaml
id: custom-exposed-debug-endpoint

info:
  name: Exposed Internal Debug Endpoint
  author: 4xpl0it-security
  severity: medium
  description: Detects an internal API debug endpoint that should not be exposed.
  tags: api,exposure,custom

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/internal/debug"
      - "{{BaseURL}}/api/v1/_debug"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        part: body
        words:
          - "\"debug\": true"
          - "stack_trace"
        condition: or
```

Field breakdown:
- `id`: unique template identifier (lowercase, hyphenated, no spaces).
- `info.name` / `info.author` / `info.severity` / `info.description`: metadata used
  in reporting output; `severity` drives `-severity` filtering.
- `info.tags`: comma-separated tags this template matches under `-tags` filtering.
- `http`: the request block. `method` and `path` define what's sent — `{{BaseURL}}`
  is substituted with the target URL passed via `-u`/`-l`.
- `matchers-condition: and`: **all** matcher blocks below must pass for this
  template to report a finding (vs `or`, where any single matcher passing is
  sufficient).
- `matchers`: list of conditions checked against the response.
  - `type: status`: matches on HTTP status code(s).
  - `type: word`, `part: body`, `words: [...]`: matches on literal strings found in
    the response body. `condition: or` (nested within this matcher) means any one
    of the listed words is sufficient for *this specific matcher* to pass.

Run it directly:
```
nuclei -u https://api.target.com -t custom-exposed-debug-endpoint.yaml
```

### 1.4 Real-World Notes

- Always run `nuclei -update-templates` before an engagement — the API/exposure/
  misconfiguration template set is actively maintained and grows frequently; a
  stale local template cache means missed known findings.
- The `swagger`/`openapi` tagged templates that detect exposed API specification
  files are consistently high-value on real engagements — an exposed
  `/swagger.json` or `/openapi.yaml` on a production host often reveals the entire
  private API surface (including undocumented/internal-only endpoints) in one
  request, and should be the very first nuclei pass run against any newly
  discovered API host.

## 2. graphql-cop — GraphQL Security Scanner

graphql-cop is a focused Python scanner that checks a GraphQL endpoint against a
fixed set of common GraphQL misconfigurations in a single pass — introspection
exposure, batching/aliasing DoS potential, field suggestion leakage, and CSRF via
GET-based queries. Cross-reference the GraphQL series for the vulnerability theory
behind each check.

### 2.1 Installation
```
pip install graphql-cop
```

### 2.2 Core Flags (Full Breakdown)

```
graphql-cop -t https://api.target.com/graphql -o results.json -H "Authorization: Bearer <token>"
```

- `-t <url>`: target GraphQL endpoint URL.
- `-o <file>`: output file for results (JSON format).
- `-H "<header>"`: custom header, repeatable — needed for authenticated
  introspection/query checks.
- `-p <proxy>`: route all requests through a proxy (e.g., `-p
  http://127.0.0.1:8080` to send traffic through Burp for manual follow-up
  inspection of each automated check).
- `-x`: disable TLS certificate verification — for self-signed/internal targets.
- `-d <ms>`: delay in milliseconds between requests, for rate-limit-sensitive
  targets.
- `-a "<header>"`: shortcut flag specifically for setting an `Authorization`
  header value (some graphql-cop versions separate this from generic `-H` for
  convenience; check `graphql-cop -h` for your installed version's exact flag set
  since this has varied slightly across releases).

### 2.3 What graphql-cop Checks

Each check corresponds to a documented GraphQL security concern (full mechanics in
the GraphQL series):
- **Introspection enabled**: whether `__schema` queries are accessible, exposing
  the full schema.
- **Field suggestions**: whether disabled/mistyped field name errors "suggest" the
  correct field name, leaking schema details even with introspection disabled.
- **Batch query support (aliasing)**: whether the endpoint accepts multiple aliased
  operations in a single request, relevant to rate-limit bypass and brute-force
  amplification.
- **GET-based queries**: whether the endpoint accepts GraphQL queries via `GET`
  with a querystring parameter, which has CSRF implications since GET requests
  aren't protected by the same-origin restrictions that apply to non-simple POST
  requests.
- **Debug mode / verbose errors**: whether error responses leak stack traces or
  internal server details.

### 2.4 Real-World Notes

- graphql-cop is a fast **triage** tool, not a replacement for InQL-driven manual
  schema exploration (file 02) — run graphql-cop first for a quick misconfiguration
  checklist, then move to InQL/Burp for deep manual testing of individual
  queries/mutations it can't automatically assess (business logic, authorization
  per-field, injection in resolvers).

## 3. RESTler — Stateful REST API Fuzzer

RESTler (Microsoft Research) is a stateful fuzzer: unlike ffuf/kiterunner (which
fuzz individual requests independently), RESTler parses an OpenAPI/Swagger
specification, infers producer-consumer dependencies between endpoints (e.g., a
`POST /users` response's `id` field is needed as the path parameter for a later
`GET /users/{id}`), and generates multi-step request sequences that exercise
realistic API workflows — surfacing bugs that only manifest across a sequence of
calls (state-dependent logic flaws, some race conditions, resource lifecycle bugs).
This section is brief coverage as an additional automated option beyond the
manual/semi-automated tools covered elsewhere in this series.

### 3.1 Installation
```
git clone https://github.com/microsoft/restler-fuzzer.git
cd restler-fuzzer && python3 build-restler.py
```

### 3.2 Core Workflow (Summary-Level Flag Breakdown)

RESTler operates in three phases, each a separate command:

**Compile** (parses the OpenAPI spec into RESTler's internal grammar):
```
restler compile --api_spec swagger.json
```
- `--api_spec <file>`: path to the target's OpenAPI/Swagger JSON or YAML
  specification file.

**Test** (a quick single-pass smoke test to confirm the compiled grammar and target
connectivity work before a full fuzzing run):
```
restler test --grammar_file Compile/grammar.py --dictionary_file Compile/dict.json \
              --settings engine_settings.json --target_ip <ip> --target_port 443
```
- `--grammar_file` / `--dictionary_file`: outputs from the `compile` phase —
  the generated request grammar and the value dictionary used to fill in typed
  fields (strings, ints, IDs).
- `--settings <file>`: engine settings JSON, where authentication (e.g., a token
  refresh script) and other run parameters are configured.
- `--target_ip` / `--target_port`: the API host and port to test against.

**Fuzz** (the full stateful fuzzing run):
```
restler fuzz --grammar_file Compile/grammar.py --dictionary_file Compile/dict.json \
              --settings engine_settings.json --target_ip <ip> --target_port 443 \
              --time_budget 2.0
```
- `--time_budget <hours>`: how long to run the fuzzing session, in hours (e.g.,
  `2.0` for a two-hour run) — RESTler will explore as many valid request sequences
  and mutations as it can within this budget.

### 3.3 Real-World Notes

- RESTler requires a reasonably complete and accurate OpenAPI/Swagger spec to be
  effective — its entire value proposition (inferring dependencies between
  endpoints) collapses if the spec is missing response schemas or has inaccurate
  parameter definitions. Validate/lint the spec first if it was provided by the
  client rather than freshly exported from the live API.
- RESTler is best positioned as a **supplementary automated pass** run in parallel
  with manual testing, not a primary methodology — its findings (mostly crashes,
  500 errors, and some authorization-sequence bugs) need manual triage, but it
  reaches request sequences a human tester is unlikely to manually construct
  within engagement time constraints.
