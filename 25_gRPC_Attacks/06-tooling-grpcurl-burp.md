# gRPC Pentesting Tooling: grpcurl and Burp gRPC Plugins

## 1. What this file covers

This is the full reference file for the two tool categories used throughout files 2–5: `grpcurl` (command-line) and Burp Suite gRPC/protobuf plugins (interactive). Every flag and workflow step here is broken down individually — this file is meant to be looked up, not read start to finish.

---

## 2. grpcurl — installation

```bash
# macOS
brew install grpcurl

# Go install (any platform with Go toolchain)
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# Linux — download the release binary directly from the GitHub releases page
# and place it on your PATH, or use your distro's package manager if available

# Docker
docker pull fullstorydev/grpcurl:latest
```

Verify installation:

```bash
grpcurl -version
```

**Docker-specific notes**: if the target is on the host machine's loopback interface, use `host.docker.internal` instead of `localhost` (Mac/Windows), or run with `--network="host"` (Linux only). If you need to mount local `.proto` files into the container, bind-mount the directory (`-v $(pwd):/protos`) and adjust `-import-path` to the in-container path. If you're piping request data via stdin (`-d @`), add `-i` to the `docker run` command so stdin stays open.

---

## 3. grpcurl — core concept: descriptor sources

Every grpcurl command needs to know the RPC schema (what services/methods/messages exist) from one of three sources, and which source you're using changes which flags you need:

1. **Server reflection** (default, no extra flags needed) — grpcurl asks the server directly. This is what file 2 covers in depth.
2. **`.proto` source files** — use `-proto` (and `-import-path` if the proto has imports) when reflection is disabled but you have schema files.
3. **Compiled descriptor/protoset files** — use `-protoset` to point at a pre-compiled binary descriptor set (a `.pb`/`.protoset` file), useful when you've exported one from a reflection session earlier (file 2, section 7) and want to reuse it without a live connection.

---

## 4. grpcurl — full flag reference

### 4.1 Connection and transport flags

| Flag | Meaning |
|---|---|
| `-plaintext` | Use unencrypted HTTP/2 (no TLS). Required for internal/non-TLS targets — without it, grpcurl assumes TLS and the connection will fail against a plaintext server. |
| `-insecure` | Use TLS but skip certificate/hostname verification. For self-signed certs (common on staging/internal targets). Not valid together with `-plaintext` — you're choosing one or the other. |
| `-cacert <file>` | Path to a CA certificate file, for verifying a server's certificate against a custom/internal CA. |
| `-cert <file>` | Client certificate file, for mutual TLS (mTLS) authentication. Must be paired with `-key`. |
| `-key <file>` | Client private key file, paired with `-cert` for mTLS. |
| `-connect-timeout <seconds>` | Maximum time to wait for the initial connection before failing. Useful when scripting sweeps across many hosts/ports where some may be unreachable. |
| `-max-time <seconds>` | Maximum total time for the entire RPC call, including streaming calls. Prevents a hung or slow-draining stream from blocking a script indefinitely. |
| `-keepalive-time <seconds>` | Idle time after which grpcurl sends an HTTP/2 keepalive probe; connection is closed if no response arrives within the same window. |

### 4.2 Descriptor source flags

| Flag | Meaning |
|---|---|
| `-proto <file>` | Path to a `.proto` source file to use instead of reflection. Repeatable for multiple files. |
| `-import-path <dir>` | Directory to search for files referenced by `import` statements inside a `-proto` file. Repeatable; searched in the order given. |
| `-protoset <file>` | Path to a compiled binary `FileDescriptorSet` (protoset) file, as an alternative descriptor source to `.proto` files. |
| `-protoset-out <file>` | Exports the resolved descriptors (from reflection or from proto sources) to a protoset file — useful for saving a reflection-derived schema for later offline use. |
| `-proto-out-dir <dir>` | Exports resolved descriptors as `.proto` source files into the given directory, instead of a compiled protoset. |
| `-use-reflection` | Forces use of server reflection even when `-proto`/`-protoset` are also given, so both sources are combined. By default, reflection is used automatically unless a `-proto`/`-protoset` flag is present (in which case grpcurl assumes you want those instead). |

### 4.3 Request and header flags

| Flag | Meaning |
|---|---|
| `-d <string>` | The request body, as JSON by default. Use `-d @` to read the body from stdin instead — required for interactive streaming calls, or when piping a payload from another tool/script. |
| `-format text` | Send/interpret the request/response body as protobuf text format instead of JSON — occasionally needed when a JSON representation is ambiguous for a given message shape. |
| `-H "<header>: <value>"` | Adds a custom HTTP/2 header to the request — this is how you attach an auth token (`-H "authorization: Bearer <token>"`) for authenticated calls in files 4 and 5. Repeatable for multiple headers. |
| `-rpc-header "<header>: <value>"` | Adds a header sent only with the actual RPC call, excluded from any reflection requests made as part of resolving the schema. Useful when reflection and the RPC call need different credentials. |
| `-reflect-header "<header>: <value>"` | The inverse — adds a header sent only with reflection requests, not the actual RPC call. Useful for testing whether reflection access itself is gated separately from RPC method access (file 2, section 8). |
| `-expand-headers` | Expands environment variables inside header values (e.g., `-H 'authorization: Bearer ${TOKEN}'`), so you can keep tokens out of shell history/scripts and pull them from the environment instead. |

### 4.4 Output and behavior flags

| Flag | Meaning |
|---|---|
| `-v` | Verbose output — includes response headers, trailers (this is where you'll see `grpc-status`/`grpc-message` explicitly, relevant throughout files 3–5), and metadata, not just the response body. Use this by default during testing rather than only when something looks wrong. |
| `-msg-template` | When used with `describe`, prints a filled JSON template with placeholder values for every field of the described message — a fast way to scaffold a valid request body for a method you've just enumerated (file 2, section 7). |
| `-emit-defaults` | Includes fields with default/zero values in JSON output, instead of omitting them — useful when you specifically need to see whether a field is present-but-zero versus genuinely absent, relevant to proto3's optional-field ambiguity (file 1, section 4). |

### 4.5 The three verbs

grpcurl's behavior depends on whether you provide `list`, `describe`, or neither:

- **`list`** — with no symbol argument, lists all services. With a service name argument, lists that service's methods.
- **`describe`** — with a symbol (service, method, or message name) argument, prints its full schema in `.proto`-like syntax.
- **Neither (a method path directly)** — invokes the method, using `-d` for the request body.

---

## 5. grpcurl — worked commands, fully explained

### 5.1 Reflection enumeration (full breakdown; see file 2 for testing logic)

```bash
grpcurl -plaintext -v target.internal:50051 list
```

- `-plaintext` — unencrypted connection (section 4.1).
- `-v` — verbose, so you see any headers/trailers returned even on a `list` call, useful for spotting reflection-layer authentication prompts.
- `target.internal:50051` — host:port.
- `list` — enumerate all services (no symbol given).

### 5.2 Describing a method with a request template

```bash
grpcurl -plaintext target.internal:50051 describe ecommerce.v1.OrderService.GetOrder --msg-template
```

- `describe ecommerce.v1.OrderService.GetOrder` — full schema of this specific method.
- `--msg-template` — additionally emits a JSON template you can copy directly into a `-d` payload for the next command, saving manual reconstruction of the request shape.

### 5.3 Calling a unary method with an auth header

```bash
grpcurl -plaintext \
  -H "authorization: Bearer eyJhbGciOi..." \
  -d '{"order_id": "ord_88213"}' \
  target.internal:50051 \
  ecommerce.v1.OrderService/GetOrder
```

- `-H "authorization: Bearer ..."` — attaches the session token, exactly the way you'd add an `Authorization` header to a REST call.
- `-d '{"order_id": "ord_88213"}'` — the request body as JSON; grpcurl serializes this into protobuf using the resolved schema (reflection, by default, since no `-proto`/`-protoset` is given).
- `target.internal:50051` — target.
- `ecommerce.v1.OrderService/GetOrder` — the method path. Note the `/` here versus the `.` used in `list`/`describe` symbol arguments — grpcurl accepts either `Service/Method` or `Service.Method` format for the actual invocation, but `/` is the conventional form since it mirrors the real wire-level method path from file 1, section 8.

### 5.4 Calling a method with data piped from stdin

```bash
echo '{"order_id": "ord_88213", "refund_amount": 25.00}' | \
  grpcurl -plaintext -d @ \
  -H "authorization: Bearer eyJhbGciOi..." \
  target.internal:50051 \
  ecommerce.v1.OrderService/RefundOrder
```

- `-d @` — tells grpcurl to read the request body from stdin instead of inline. Useful for scripting payload generation (e.g., a loop generating many test bodies) or when a payload is long/complex enough that inlining it in the command is unwieldy.

### 5.5 Server-streaming call

```bash
grpcurl -plaintext -H "authorization: Bearer <token>" \
  -d '{"customer_id": "cust_5521"}' \
  target.internal:50051 \
  ecommerce.v1.OrderService/ListOrders
```

No special flag is needed to receive a stream — grpcurl detects from the resolved schema that `ListOrders` returns `stream Order` (file 1, section 4) and automatically prints each received message to stdout as it arrives, one after another, until the stream closes.

### 5.6 Health-check probe (useful recon/availability check)

```bash
grpcurl -plaintext target.internal:50051 grpc.health.v1.Health/Check
```

Many gRPC servers expose the standard `grpc.health.v1.Health` service for load-balancer health checks — calling it with an empty or omitted service name (`-d '{}'`) returns overall server health, and can be a useful low-noise way to confirm a target is alive and speaking gRPC before you commit to a full reflection sweep.

### 5.7 Scripted BFLA sweep (ties together file 4, section 4.2)

```bash
for method in $(grpcurl -plaintext target.internal:50051 list ecommerce.v1.OrderService); do
  echo "=== $method (unauthenticated) ==="
  grpcurl -plaintext -v -d '{}' target.internal:50051 "$method" 2>&1 | grep -E "grpc-status|ERROR"
done
```

- Iterates every method on a service (from `list`, file 2 section 5), calls each with an empty body and no auth header, and greps the verbose output for the `grpc-status` line or an error, giving you a fast first-pass table of which methods reject unauthenticated calls and which don't. An empty `-d '{}'` body will sometimes trigger `INVALID_ARGUMENT` rather than an authorization error for methods with required fields — treat that as inconclusive and follow up with a properly populated body per section 5.3 rather than reading it as "protected."

---

## 6. Burp Suite gRPC/protobuf plugins — landscape overview

There is no single official, universally adopted "the gRPC plugin" — the ecosystem is a handful of BApp Store and GitHub-distributed extensions, each with different strengths. Pick based on what you're actually looking at (file 1, section 6 distinction between native gRPC and gRPC-Web matters here):

| Extension | Targets | Schema requirement | Notes |
|---|---|---|---|
| **gRPC-Web Coder** (PortSwigger BApp Store) | gRPC-Web (`application/grpc-web-text`, `application/grpc-web+proto`) | None — automatic decode/encode | Good default choice for browser-facing gRPC-Web targets; actively maintained by PortSwigger, straightforward setup |
| **Protobuf Decoder** (BApp Store) | Generic `application/x-protobuf` content, response-focused | Optional `.proto` for full accuracy | Older, community-maintained; useful for plain protobuf-over-HTTP APIs, not gRPC-specific framing |
| **ProtoBurp++** (doyensec, GitHub) | Protobuf/gRPC, with fuzzing support | `.proto` file for full serialization support | Adds Repeater/Intruder/Active Scanner fuzzing of protobuf fields; strongest current gRPC-specific schema-mode support at the time of writing |
| **bRPC-Web** (Compass Security, GitHub) | gRPC-Web | None — heuristic/backtracking decode | No `.proto` required; displays messages in the human-readable Protoscope format; good blackbox-mode option |
| **ProtoME** (GitHub) | Protobuf/gRPC, both schema and blackbox modes | Optional | Supports right-click blackbox decode of any binary protobuf body, plus schema mode with a loaded `.proto`; also includes deliberate wire-level mutation/fuzzing headers for stress-testing parsers |

**Practical selection guidance**: if you're testing a browser-facing web app, start with **gRPC-Web Coder** or **bRPC-Web** since they target gRPC-Web specifically and need no setup beyond installation. If you have a `.proto` file or exported protoset (file 2, section 7) and want the most accurate schema-aware editing plus fuzzing, use **ProtoBurp++**. If you're working blackbox with no schema at all against either native gRPC or gRPC-Web, **ProtoME** or **bRPC-Web**'s heuristic modes are your best fit.

---

## 7. Burp plugin installation

### 7.1 Via BApp Store (gRPC-Web Coder, Protobuf Decoder)

1. Burp Suite → Extensions tab → BApp Store sub-tab.
2. Search for the extension by name.
3. Select it, click **Install**.
4. Confirm it appears under Extensions → Installed, with no load errors in the Output/Errors panes.

### 7.2 Via manual JAR/Python install (ProtoBurp++, bRPC-Web, ProtoME — GitHub-distributed)

1. Download the release (JAR for Java-based extensions, or the `.py` extension file plus any listed dependencies for Python/Jython-based ones) from the project's GitHub releases page.
2. Burp Suite → Extensions tab → Installed sub-tab → **Add**.
3. Set Extension type to match the file (Java or Python).
4. For Python/Jython extensions, confirm Burp's Python environment is configured first (Extensions → Extension settings → Python environment, pointing at a Jython standalone JAR) — this is a one-time setup step required before any Jython-based extension will load at all.
5. Browse to the downloaded extension file, click **Next**, confirm no errors in the load output.

### 7.3 Loading a `.proto` file into schema mode

Exact UI varies by extension, but the general pattern:

1. Open the extension's dedicated settings tab (added to Burp's top-level tab bar, or nested under Extensions depending on the plugin).
2. Look for a "Load proto" / "Import schema" / "Add descriptor" action.
3. Point it at your `.proto` file (or a `.protoset` exported per section 5.2 / file 2 section 7).
4. Confirm the plugin reports successful parsing — most will list the services/messages it found as a sanity check.
5. Re-open a previously decoded request/response tab (or intercept a new one) to confirm field names now resolve correctly instead of showing generic `field_1`/`field_2` placeholders.

---

## 8. Real-world notes

- `grpcurl` should be your default tool for anything scriptable or repetitive — full attack-surface dumps (file 2, section 7), BFLA sweeps (section 5.7 above), and payload delivery for injection testing (file 5) are all faster and more reproducible from the command line than clicking through Burp for each one individually. Reserve Burp for the interactive, judgment-heavy parts of testing — reading a decoded response carefully, iterating on a single field during BOLA testing, or fuzzing via Intruder once ProtoBurp++ or a similar extension has a field wired up.
- Because this is a fragmented, community-maintained plugin ecosystem rather than a single official tool, expect version churn — an extension that worked cleanly on one Burp version can break on the next, and some of these projects update infrequently. Test your plugin setup against a known-good local gRPC test service (many of these projects ship one, e.g., a bundled Echo/Greeter service for exactly this purpose) before relying on it against a live engagement target.
- When `grpcurl` reports a `-plaintext` connection error against a target you expected to be plaintext, double-check the port before assuming reflection is disabled or the service is down — the same host frequently serves both a plaintext internal port and a TLS-terminated external port for the same gRPC service, and hitting the wrong one produces a connection-level error easy to misread as a reflection or schema problem.
- Keep a local library of exported protosets (`-protoset-out`, section 4.2) per target/engagement — once you've done a full reflection sweep, saving the descriptor set means you can keep testing with `-protoset` even if reflection later gets disabled mid-engagement, or if you need to work offline from a captured schema.

---

## 9. Where this series goes next

- **File 7** — consolidated cheatsheet pulling the highest-frequency commands and workflows from this file and the rest of the series into one quick-reference document.
