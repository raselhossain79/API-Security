# SQL Injection via API Endpoints

Refer to your web-app SQLi series for UNION-based, boolean-blind, time-blind, and
error-based mechanics. This file covers only the API-specific delivery and testing
methodology layer.

## 1. Injecting Through JSON Body String Values

A typical vulnerable API request:

```http
POST /api/v1/users/search HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "username": "alice",
  "sortBy": "created_at"
}
```

If `username` is concatenated directly into a backend SQL query, the injection point is
the **string value**, not the key. A test payload:

```json
{
  "username": "alice' OR '1'='1",
  "sortBy": "created_at"
}
```

Breakdown of what's happening in this JSON body:

- `"username":` — this is the JSON key, untouched. Never inject into keys unless you are
  specifically testing for key-name-based injection (rare, seen in some ORMs that build
  dynamic `WHERE` clauses from key names — that's a separate, less common finding).
- `"alice' OR '1'='1"` — the JSON string **value**. The outer double-quotes are JSON
  syntax, not part of your payload. Inside those quotes, the payload itself is
  `alice' OR '1'='1` — a classic SQLi boolean payload using single quotes, which is valid
  inside a JSON string because JSON only requires escaping of double-quotes and
  backslashes, not single quotes.
- Why this works: the backend takes the JSON string value (after the JSON parser strips
  the outer double-quotes) and concatenates it into a SQL query, e.g.
  `SELECT * FROM users WHERE username = 'alice' OR '1'='1'`. The single quote in your
  payload closes the SQL string literal early, and `OR '1'='1'` makes the WHERE clause
  always true.

### When the payload needs a literal double-quote or backslash

If your SQLi payload itself needs a double-quote or backslash (rare, but happens with
certain DB-specific syntax), you must JSON-escape it:

```json
{"username": "alice\" OR \"1\"=\"1"}
```

- `\"` — escaped double-quote. Tells the JSON parser "this is a literal quote character
  inside the string, not the end of the string." Without the backslash, the JSON parser
  would terminate the string at the first unescaped `"`, corrupting your payload and
  likely breaking the whole request.
- This escaping step is the single most common thing testers forget when adapting a
  proven web-app SQLi payload into a JSON body — a payload that works perfectly in a
  form field can silently fail in JSON purely because of a missing backslash.

## 2. Burp-Based Testing Workflow for API Endpoints

1. **Capture the request in Burp Proxy** and send to Repeater. Confirm the request has
   `Content-Type: application/json` and a well-formed JSON body.
2. **Identify all injectable leaf values** in the JSON tree — walk every string, number,
   and array element. Use Burp's **Logger** or manually expand nested objects; for large
   or deeply nested bodies, **Param Miner** (Burp extension) can help surface hidden or
   guessable parameters that aren't visible in a single captured request.
3. **Test JSON-safe payloads first** — always validate the request still parses as valid
   JSON after your payload is inserted. A quick sanity check: paste the modified body
   into a JSON linter before sending, or watch for an immediate 400 Bad Request, which
   usually indicates a JSON syntax break rather than a WAF block.
4. **Distinguish JSON-break errors from SQL errors**: a 400 status with a JSON parser
   error message means your payload broke JSON syntax before reaching SQL. A 500 status
   or an application-level SQL error message means your payload reached the database
   layer — that's the signal you're actually testing SQLi behavior, not JSON validity.
5. **Move to Intruder for systematic testing**: set the payload position **inside the
   JSON string value**, between the quotes, not including them. Use the "Sniper" attack
   type with a SQLi payload wordlist. Because Intruder does raw text substitution, you
   are responsible for ensuring each payload in your wordlist is already JSON-escaped —
   Intruder does not auto-escape for you.
6. **Check for numeric-context injection**: some JSON fields are unquoted numbers
   (`"userId": 5`). Numeric SQLi doesn't need quote-breaking at all — test
   `"userId": 5 OR 1=1` directly, since there's no string literal to escape out of.

## 3. sqlmap Usage With JSON Body — Full Flag Breakdown

sqlmap supports JSON body testing directly. Save the captured request to a file
(`request.txt`) via Burp's "Copy to file" or "Save item," including headers and the JSON
body, then run:

```bash
sqlmap -r request.txt --data="{\"username\":\"alice\",\"sortBy\":\"created_at\"}" \
  --level=3 --risk=2 --technique=BT --batch --threads=4 -p username
```

Flag-by-flag breakdown:

- `-r request.txt` — tells sqlmap to read the full HTTP request (method, headers, body)
  from a saved file instead of building the request manually via `-u`. This is the
  preferred method for JSON API testing because it preserves the exact `Content-Type`
  header and JSON body structure sqlmap needs to auto-detect the injection format.
- `--data="{...}"` — an alternative to `-r`: manually specify the JSON body inline on the
  command line when you don't have (or don't want to use) a saved request file. sqlmap
  parses this and, because the `Content-Type: application/json` header is present (either
  auto-detected or passed via `-H`), sqlmap treats the body as JSON rather than
  form-encoded, and will attempt injection inside JSON string values.
- `--level=3` — controls how many injection points and payload types sqlmap tests, on a
  scale of 1–5. Level 1 (default) only tests the most common injection points (GET/POST
  parameters). Level 3 expands testing to include HTTP headers and cookie values as
  potential injection points too — relevant for API testing because APIs frequently pass
  auth tokens or metadata through custom headers that may also reach the database layer.
  Higher levels increase request volume and test time significantly, so level 3 is a
  reasonable default rather than jumping straight to 5 on a first pass.
- `--risk=2` — controls how aggressive/potentially-disruptive the payloads are, scale
  1–3. Risk 1 (default) avoids payloads that could cause data modification. Risk 2 adds
  time-based blind payloads and boolean payloads that are still safe but broader in
  coverage. Risk 3 adds OR-based payloads that can return large or unexpected result sets
  and is generally avoided in production API testing without explicit authorization,
  since OR-based payloads on write endpoints (not just read/search endpoints) can have
  destructive side effects if the endpoint isn't purely a SELECT.
- `--technique=BT` — restricts sqlmap to specific SQLi technique classes: `B` = boolean-
  based blind, `T` = time-based blind. Restricting techniques (rather than testing all six
  default techniques: B, E, U, S, T, Q) is a deliberate choice for API testing — API
  endpoints often have strict response-time SLAs or rate limiting, so narrowing to the
  two most reliable blind techniques reduces request volume and avoids tripping
  rate-limit-based defenses while you confirm basic injectability, before broadening the
  technique set if a hit is found.
- `--batch` — tells sqlmap to use default answers for all interactive prompts instead of
  pausing to ask you questions during the scan. Necessary for any non-interactive or
  scripted run.
- `--threads=4` — runs requests with 4 concurrent threads. For API endpoints behind rate
  limiting (very common), lowering this to 1 or 2 is often necessary to avoid triggering
  429 responses that would abort or corrupt the scan's timing-based inference (especially
  for `--technique=T`, where response timing accuracy matters and concurrent requests can
  skew measured delay).
- `-p username` — restricts testing to the specific parameter named `username`, rather
  than sqlmap testing every parameter it finds in the body. For JSON bodies, sqlmap
  identifies the parameter by its JSON key name. Scoping to a single parameter is standard
  practice once Burp-based manual testing (above) has already narrowed down which field
  looks promising — running sqlmap unscoped against every JSON key in a large nested body
  is slow and generates excessive traffic.

### Handling nested JSON parameters with sqlmap

For a nested body like:

```json
{"user": {"profile": {"username": "alice"}}}
```

sqlmap's `-p` flag targeting works on the flattened parameter name it detects during JSON
parsing. In practice, testing deeply nested parameters with sqlmap directly is often
unreliable — the more robust approach for the deepest nesting levels is:

1. Manually confirm the injection with Burp Repeater first (as in the workflow above).
2. Once confirmed, flatten the request for sqlmap by testing at the shallowest reachable
   level, or use `--data` with the exact nested structure and let sqlmap's parameter
   parser attempt auto-detection — verify with `-v 3` (verbose level 3) that sqlmap is
   actually targeting the intended nested key before trusting scan results.

## 4. WAF/Gateway Note for SQLi via API

WAF/Gateway defenses are highly relevant here. Signature-based WAFs commonly scan for SQL
keywords (`UNION`, `SELECT`, `OR 1=1`) as substrings — but whether that scan happens
*before or after* JSON parsing determines whether nesting or Unicode-escaping the payload
evades detection. Full technique breakdown, including JSON-specific bypass methods, is in
`06-waf-bypass-api-injection.md`.

## 5. PortSwigger Lab Mapping (Adapted for API Context)

No PortSwigger lab delivers SQLi through a JSON REST body natively — all SQLi labs use
form/query-string delivery. Use these labs to learn the underlying SQLi logic, then
manually convert the request to a JSON body shape (as shown in section 1) to practice the
API delivery skill:

- **Apprentice**: "SQL injection vulnerability allowing login bypass" — convert the
  login form request to a JSON body (`{"username": "...", "password": "..."}"`) and
  reproduce the same bypass logic against your own local test app or Burp-modified
  request.
- **Apprentice**: "SQL injection vulnerability in WHERE clause allowing retrieval of
  hidden data" — practice converting a query-string parameter into a JSON body field.
- **Practitioner**: "Blind SQL injection with conditional responses" — directly relevant
  to the boolean-based technique used with `--technique=B` above; practice constructing
  the conditional payload as a JSON string value.
- **Practitioner**: "Blind SQL injection with time delays" — maps directly to
  `--technique=T`; the delay-based confirmation logic is identical, only the delivery
  format changes.
- **Expert**: "SQL injection with filter bypass via XML encoding" — while this lab uses
  XML rather than JSON, the underlying lesson (encoding-based WAF/filter evasion) is the
  closest Expert-tier lab to the JSON-encoding bypass concepts covered in the WAF file.

**Gap**: for hands-on practice against a real JSON-native vulnerable API (rather than a
manually-converted PortSwigger lab), use **crAPI**'s vulnerable endpoints, which are
built JSON-first and include intentionally injectable fields in nested request bodies.

## Real-World Note

In bug bounty and pentest engagements, JSON body SQLi is frequently found in
"internal-only" or "admin" API endpoints that were never load-tested with the same
security scrutiny as public login forms — search fields, filter/sort parameters, and
export endpoints (which build dynamic queries from many combined parameters) are
disproportionately common findings versus the login-form SQLi that dominates lab
environments.
