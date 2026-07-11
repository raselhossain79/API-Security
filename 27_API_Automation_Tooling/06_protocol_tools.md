# API Security Testing Tooling — Protocol Tools (grpcurl, Postman/Newman)

Cross-reference: gRPC series for protocol mechanics (Protocol Buffers, HTTP/2
framing) — this file covers grpcurl usage only, not gRPC theory.

## 1. grpcurl — gRPC Interaction

grpcurl is `curl` for gRPC: a CLI tool for invoking gRPC methods, since gRPC's
binary Protocol Buffers framing over HTTP/2 means you cannot interact with it using
plain curl the way you can a JSON REST API.

### 1.1 Installation
```
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

### 1.2 Core Flags (Full Breakdown)

```
grpcurl -plaintext -d '{"user_id": "123"}' \
        -H "Authorization: Bearer <token>" \
        target.api.com:50051 usersvc.UserService/GetUser
```

- `<host:port>`: target gRPC server address and port (gRPC has no default port the
  way HTTP/HTTPS does — you must specify it, commonly `50051` by convention but
  varies per deployment).
- `<service>/<method>`: the fully-qualified gRPC method to invoke, in
  `package.Service/Method` format (e.g., `usersvc.UserService/GetUser`) — this
  requires knowing the service's Protocol Buffers definition (via reflection,
  below, or a provided `.proto` file).
- `-d '<json>'`: the request message, specified as JSON — grpcurl converts this to
  the appropriate binary Protobuf encoding automatically based on the resolved
  message schema. Use `-d @` to instead read the JSON body from stdin (for piping
  in a large/scripted payload).
- `-plaintext`: use unencrypted HTTP/2 (h2c) instead of TLS — necessary when
  testing an internal/staging gRPC service that isn't fronted by TLS termination.
  Omit this flag (default is TLS) when testing a production endpoint that expects
  TLS.
- `-insecure`: use TLS but **skip certificate verification** — for self-signed
  cert staging/internal environments where you still want encrypted transport but
  can't validate the cert chain.
- `-H "<header>"`: add a custom gRPC metadata header (gRPC's equivalent of an HTTP
  header), repeatable — used for `Authorization`, custom auth tokens, or any other
  metadata the service expects.
- `-rpc-header "<header>"`: same as `-H` but scoped only to the RPC call itself,
  not to reflection/list requests made in the same invocation — relevant when the
  target requires different auth for reflection vs actual method calls.

### 1.3 Service Discovery via Reflection

If the target gRPC server has **server reflection** enabled (a common but not
universal configuration — its presence/absence is itself a security-relevant
finding, since reflection exposes the full service/method/message schema similarly
to GraphQL introspection):

```
grpcurl -plaintext target.api.com:50051 list
```
- `list`: (used in place of a `<service>/<method>` argument) lists every gRPC
  service exposed by the target, if reflection is enabled.

```
grpcurl -plaintext target.api.com:50051 list usersvc.UserService
```
- `list <service>`: lists every method available on a specific service.

```
grpcurl -plaintext target.api.com:50051 describe usersvc.UserService.GetUser
```
- `describe <service.Method>`: prints the full message schema (request and
  response field names, types, and nesting) for a specific method — the gRPC
  equivalent of reading a REST API's OpenAPI schema for one endpoint.

### 1.4 Working Without Reflection (Using a .proto File)

If reflection is disabled (common in hardened production deployments) but you have
access to the `.proto` service definition file (e.g., provided by the client, or
recovered from a mobile app's decompiled assets):

```
grpcurl -plaintext -import-path ./protos -proto usersvc.proto \
        -d '{"user_id": "123"}' target.api.com:50051 usersvc.UserService/GetUser
```
- `-proto <file>`: path to the `.proto` file defining the service/message schema
  to use instead of server reflection.
- `-import-path <dir>`: directory to search for `.proto` files referenced via
  `import` statements inside the main proto file (for schemas split across
  multiple files) — repeatable for multiple search directories.

### 1.5 Additional Useful Flags

- `-format <text|json>`: output format for the response (default `json`).
- `-emit-defaults`: include fields with default/zero values in the JSON output
  (by default, Protobuf's JSON mapping omits fields set to their zero value —
  `0`, `""`, `false` — which can hide information during manual review; this flag
  forces them to be shown explicitly).
- `-max-time <seconds>`: request timeout.
- `-authority <value>`: override the `:authority` HTTP/2 pseudo-header (gRPC's
  equivalent of the `Host` header) — useful for testing virtual-host routing or
  host-header-style injection against a gRPC gateway.
- `-msg-template`: instead of invoking the method, prints a JSON template showing
  every expected field for the request message (generated from the resolved
  schema, via reflection or `-proto`) — useful for quickly building a valid `-d`
  payload for a complex nested message without manually reading the full schema
  output from `describe`.

### 1.6 Real-World Notes

- Check for server reflection **first** against any gRPC target — if enabled, `list`
  and `describe` give you the complete attack surface for free, equivalent in value
  to an exposed OpenAPI spec or unrestricted GraphQL introspection.
- gRPC authentication is almost always carried via metadata headers (`-H`), most
  commonly `Authorization: Bearer <token>` identically to REST — but always
  confirm the exact header/metadata key name expected, since some gRPC services
  use custom metadata keys (e.g., `x-api-token`) rather than the standard
  `Authorization` header.
- Because gRPC uses HTTP/2 framing and binary Protobuf payloads, gRPC traffic does
  not appear in Burp's default HTTP history the way REST/GraphQL traffic does
  unless Burp is specifically configured for HTTP/2 and Protobuf handling — treat
  grpcurl as your primary manual-interaction tool for gRPC rather than expecting
  full Burp Repeater parity (cross-reference the gRPC series for Burp/gRPC
  integration specifics).

## 2. Postman and Newman — Collection-Based Testing and Automation

Postman is a GUI API client used to build, organize, and share collections of API
requests; Newman is Postman's official CLI runner, used to execute those
collections headlessly (in scripts, CI pipelines, or scheduled retests).

### 2.1 Postman — Collection Setup

**Creating a collection**: **New → Collection**, name it, then add requests via
**Add Request** inside the collection, or **Save** any request built in Postman's
main request builder directly into a collection folder. Organize with folders that
mirror the API's structure (e.g., `Auth/`, `Users/`, `Orders/`) for team
readability.

**Environment variables**: **Environments** (left sidebar) → **New Environment**.
Define key-value pairs (e.g., `base_url = https://api.target.com`, `token =
<leave blank, set dynamically>`). Reference any environment variable in a request
using double-curly syntax: `{{base_url}}/v1/users/{{user_id}}`. Switch environments
(e.g., `staging` vs `production` vs a per-tester local environment) via the
environment dropdown in the top-right of the Postman window — this lets the same
collection run against multiple targets without editing individual requests.

**Collection variables** (scoped to the collection rather than a shared
environment) are set via the collection's **Variables** tab — useful for values
specific to one collection (e.g., a fixed resource ID used across a test sequence)
that shouldn't leak into other collections sharing the same environment.

### 2.2 Pre-Request Scripts

Pre-request scripts run in Postman's sandboxed JavaScript environment **before** a
request is sent — the standard mechanism for dynamically generating auth tokens,
timestamps, or signed request signatures per-request rather than hardcoding them.

Example (fetching a fresh bearer token before every request in a folder, set at
the folder level so it applies to every request within it):
```javascript
pm.sendRequest({
    url: pm.environment.get("base_url") + "/auth/token",
    method: "POST",
    header: { "Content-Type": "application/json" },
    body: {
        mode: "raw",
        raw: JSON.stringify({
            client_id: pm.environment.get("client_id"),
            client_secret: pm.environment.get("client_secret")
        })
    }
}, function (err, res) {
    if (!err) {
        pm.environment.set("token", res.json().access_token);
    }
});
```
- `pm.sendRequest(...)`: fires an auxiliary HTTP request from within the script
  (here, a token endpoint) independent of the main request the script is attached
  to.
- `pm.environment.get("<key>")` / `pm.environment.set("<key>", <value>)`: read/write
  environment variables — this is how a token fetched in the pre-request script
  becomes available to the main request via `{{token}}`.
- `res.json()`: parses the auxiliary request's response body as JSON.

### 2.3 Test Scripts (Response Assertions and Chaining)

Test scripts run **after** a response is received, in the **Tests** tab of a
request. They serve two purposes: asserting expected behavior (pass/fail
reporting) and extracting values from the current response to feed into
*subsequent* requests (request chaining).

**Basic assertion**:
```javascript
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});

pm.test("Response contains expected user id", function () {
    const body = pm.response.json();
    pm.expect(body.id).to.eql(pm.environment.get("expected_user_id"));
});
```
- `pm.test("<name>", function() {...})`: defines a named test assertion; Postman
  and Newman report each `pm.test` block's pass/fail individually in the run
  summary.
- `pm.response.to.have.status(<code>)`: Chai-based assertion (Postman bundles
  Chai's BDD assertion syntax) checking the response status code.
- `pm.response.json()`: parses the response body as JSON for further assertions.
- `pm.expect(<value>).to.eql(<expected>)`: general-purpose Chai equality
  assertion.

**Chaining — extracting a value for use in the next request**:
```javascript
const body = pm.response.json();
pm.environment.set("order_id", body.id);
```
Placed in the **Tests** tab of a `POST /orders` request, this captures the newly
created order's `id` from the response and stores it as an environment variable,
which a subsequent `GET /orders/{{order_id}}` request in the same collection run
can then reference — the core mechanism for building multi-step, stateful test
sequences (directly relevant to testing BOLA across a realistic user workflow, or
race condition setups requiring a freshly created resource ID).

**Security-testing-specific test script pattern** (flagging a potential BOLA
finding automatically during a collection run):
```javascript
pm.test("No cross-tenant data leak", function () {
    const body = pm.response.json();
    pm.expect(body.tenant_id).to.eql(pm.environment.get("expected_tenant_id"));
});
```

### 2.4 Running a Collection Automatically (Collection Runner)

Inside Postman's GUI: **Collection → ... (menu) → Run collection** opens the
Collection Runner, where you select an environment, set iteration count and delay
between requests, and execute the full collection with a pass/fail summary per
request — useful for interactive manual regression checks before scripting a
headless run.

### 2.5 Newman — Headless CLI Execution

Newman runs an exported Postman collection (and optionally an exported
environment) from the command line, with no GUI — for CI pipelines or scheduled
retest automation.

### 2.5.1 Installation
```
npm install -g newman
```

### 2.5.2 Core Flags (Full Breakdown)

```
newman run collection.json -e environment.json --reporters cli,json \
       --reporter-json-export results.json --delay-request 200 --bail
```

- `run <collection.json>`: the exported Postman collection file (**Collection →
  ... → Export**, choosing Collection v2.1 format) to execute.
- `-e <environment.json>`: the exported environment file (**Environments → ... →
  Export**) providing the variable values (`base_url`, credentials, etc.) the
  collection references.
- `-g <globals.json>`: exported Postman globals file, for variables scoped across
  all environments/collections rather than one specific environment.
- `--folder <name>`: run only a specific folder within the collection instead of
  the entire thing — useful for running just the `Auth/` or `BOLA-checks/` subset
  during focused retesting.
- `-n <n>` / `--iteration-count <n>`: number of times to repeat the full collection
  run — combine with `-d <data.csv>` (below) to run once per row of a data file
  (e.g., iterating a collection of BOLA-check requests once per test user account).
- `-d <file.csv|json>`: data file supplying per-iteration variable values —
  referenced in requests the same way as environment variables.
- `--delay-request <ms>`: fixed delay in milliseconds between each request in the
  run — for rate-limit-sensitive targets, analogous to ffuf's `-p`/nuclei's `-rl`.
- `--timeout-request <ms>`: per-request timeout.
- `--bail`: stop the entire run immediately on the first failed test assertion —
  useful in CI to fail fast; omit for full-coverage security testing runs where you
  want every finding from a complete pass, not just the first one.
- `--reporters <list>`: comma-separated list of output reporters — `cli` (default
  terminal output), `json`, `html`, `junit` (for CI test-result integration),
  `csv`.
- `--reporter-json-export <file>`: file path for the JSON reporter's output — the
  most useful format for piping results into `jq` (file 07) or a custom reporting
  script.
- `--reporter-html-export <file>`: generates a standalone HTML report, useful for
  including directly in client-facing deliverables/appendices.
- `-k` / `--insecure`: disable TLS certificate verification, for self-signed/
  internal targets.
- `--ssl-client-cert <file>` / `--ssl-client-key <file>`: supply a client
  certificate for mutual TLS (mTLS) protected API targets.
- `-x` / `--suppress-exit-code`: always exit with code 0 regardless of test
  failures — normally Newman exits non-zero on any failed assertion (useful for CI
  gating); suppress this only when you specifically want the pipeline to continue
  regardless of findings (e.g., a reporting-only scheduled scan job).

### 2.6 Real-World Notes

- The Postman pre-request-script token-refresh pattern (2.2) is the standard way
  to keep a long-running collection run authenticated across dozens/hundreds of
  requests without manually re-pasting an expiring bearer token — build this once
  per engagement at the collection level and every request in the collection
  inherits fresh auth automatically.
- Building your manual Burp-driven testing workflow into a Postman collection with
  test-script assertions (2.3) turns one-off manual findings into a **repeatable
  regression suite** — run the same collection via Newman on retest to
  mechanically confirm fixes, rather than manually re-walking every finding by
  hand.
- Export collections in **v2.1** format specifically when planning to run them via
  Newman or import them into other tooling (like InQL's CLI output, file 02) —
  older v1 exports are deprecated and have compatibility gaps with current Newman
  versions.
