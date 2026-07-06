# Tooling: h2spec, h2csmuggler, and Burp Suite HTTP/2 Configuration

## Real-World Note

These three tools cover three different layers of HTTP/2 testing: **h2spec** checks whether a server's HTTP/2 implementation is spec-conformant (useful for surfacing the kind of decoder bugs discussed in file 4, and for confirming whether known-vulnerable behavior around Rapid Reset / CONTINUATION handling is still present); **h2csmuggler** targets a specific real-world misconfiguration (insecure forwarding of h2c upgrade requests past a reverse proxy); and **Burp Suite** is your general-purpose manual testing and request-crafting environment for everything else in this series. None of these substitutes for the others.

---

## 1. h2spec — HTTP/2 Conformance Testing

### 1.1 What It Is and Why It Matters for Pentesting

`h2spec` is a conformance test suite that sends a battery of requests designed to probe whether an HTTP/2 server correctly implements the behaviors mandated by RFC 9113 (and RFC 7541 for HPACK). It was built primarily for *server developers* to validate their own implementations, but it's directly useful offensively/defensively because:

- A server that **fails** conformance tests around frame size limits, stream state transitions, or HPACK decoding is telling you exactly where its implementation deviates from spec — and deviations are frequently where the attacks in files 2–4 of this series become exploitable (a server that doesn't correctly cap CONTINUATION frame counts, for example, will fail the relevant h2spec test group *and* be vulnerable to the CONTINUATION flood pattern in file 4, Section 4).
- Running h2spec against a target **before** attempting the manually-crafted attacks in this series is a legitimate, low-impact way to fingerprint likely weak points without generating the kind of load or malformed traffic that a hand-rolled exploit attempt would.

### 1.2 Installation and Basic Invocation

```bash
# via pre-built binary (recommended, avoids a Go toolchain dependency)
curl -L https://github.com/summerwind/h2spec/releases/latest/download/h2spec_linux_amd64.tar.gz -o h2spec.tar.gz
tar -xzf h2spec.tar.gz
chmod +x h2spec

# basic run against a target
./h2spec -h target.example -p 443 -t -k
```

Breaking down every flag, because "just run it" without understanding the flags means you can't interpret partial or unexpected results:

| Flag | Meaning | Why it matters |
|---|---|---|
| `-h target.example` | Hostname to connect to. | Straightforward, but note h2spec connects directly — it does not go through your Burp proxy by default, so if you need to observe the raw traffic h2spec generates, you'd need to route it through a proxy separately (e.g., via a local TLS-terminating proxy) or rely on h2spec's own verbose output. |
| `-p 443` | Port to connect to. | Defaults to 80 for cleartext, 443 for TLS — always specify explicitly if the target uses a non-standard port, which is common for internal API gateways. |
| `-t` | Use TLS. | Without this flag, h2spec attempts a cleartext (h2c) connection via the `Upgrade` mechanism — required if you're actually testing an HTTPS-fronted HTTP/2 API (the overwhelmingly common case for public-facing APIs). |
| `-k` | Skip TLS certificate verification. | Necessary against internal targets, staging environments, or anything using a self-signed/internal CA cert — without this, h2spec will fail immediately on the TLS handshake rather than running any actual conformance tests. |
| `-o <seconds>` | Timeout per test case (not shown above; useful when testing targets with high latency or intentionally slow responses, to avoid false "timeout" failures being misread as conformance failures). | |
| `--strict` | (not shown above) Enables strict-mode checks that go beyond MUST-level RFC requirements into SHOULD-level recommendations — useful when you want a more exhaustive fingerprint, but expect more false "failures" on implementations that are spec-compliant but non-strict. | |
| `<section>` (positional, optional) | Restricts the run to a specific RFC section/test group, e.g., `./h2spec http2/6.4` for RST_STREAM-related tests (relevant to file 2's Rapid Reset), or `./h2spec hpack` for the full HPACK conformance suite (relevant to file 4). | Running the full suite against a production target can generate a meaningful amount of malformed/edge-case traffic across dozens of test groups — scoping to the specific section relevant to your current hypothesis (e.g., only HPACK tests when you're specifically investigating file 4's concerns) is both faster and lower-impact. |

### 1.3 Reading Output and What It Tells You

h2spec output groups results by RFC section, each test case marked pass/fail/skip. A failing test case number maps directly to a specific spec requirement — for example, a failure under the `4.2` (frame size) test group indicates the server doesn't correctly enforce `SETTINGS_MAX_FRAME_SIZE` boundaries, which is directly relevant background when constructing CONTINUATION-based tests (file 4). A failure under the `5.1` (stream states) group indicates the server may mishandle stream state transitions — worth investigating in the context of Rapid Reset (file 2), since Rapid Reset fundamentally exploits a gap in how "stream is closed" (from the client's RST_STREAM) interacts with "server-side work for this stream is actually finished."

**Important interpretation note:** h2spec conformance failures are *indicators*, not proof of exploitability. A server can pass every h2spec test and still be vulnerable to Rapid Reset (because Rapid Reset isn't a spec violation at all — it's spec-conformant behavior being abused, which is exactly why it required an out-of-band mitigation rather than a spec fix). Use h2spec to build a picture of implementation maturity and likely weak points, not as a pass/fail exploitability verdict.

---

## 2. h2csmuggler — HTTP/2 Cleartext (h2c) Smuggling

### 2.1 What Vulnerability This Targets

`h2csmuggler` (originally by Bishop Fox researcher Jake Miller) targets a specific, distinct misconfiguration from the H2.CL/H2.TE downgrade smuggling in file 3. Where file 3's attacks exploit a front-end that **terminates TLS/HTTP2 and rewrites to HTTP/1.1** for the backend, h2csmuggler exploits front-ends (commonly reverse proxies configured with a bare `proxy_pass` directive and no explicit handling of the `Upgrade` header) that **insecurely forward an `Upgrade: h2c` request straight through to the backend**, allowing the client to establish a raw HTTP/2-over-cleartext connection **directly with the backend**, tunneled through the front-end's TCP connection — completely bypassing whatever access-control logic the front-end (e.g., a WAF, an auth-enforcing reverse proxy, path-based routing rules) was supposed to apply.

Mechanistically: the client sends an HTTP/1.1 request with `Connection: Upgrade`, `Upgrade: h2c`, and an `HTTP2-Settings` header. A correctly configured front-end should either reject this upgrade attempt entirely (if it doesn't support/intend h2c) or handle it itself. A **misconfigured** front-end that blindly proxies the raw bytes of the connection through to the backend (common with simplistic `proxy_pass` setups that don't specifically strip or intercept `Upgrade` headers) allows the backend to see and honor the upgrade request directly — at which point the TCP connection is upgraded to HTTP/2 cleartext, and every subsequent HTTP/2 stream on that connection goes **straight to the backend**, with the front-end now acting as a dumb byte-forwarding pipe rather than an inspecting/enforcing proxy.

### 2.2 Installation and Full Usage Breakdown

```bash
git clone https://github.com/BishopFox/h2csmuggler.git
cd h2csmuggler
pip3 install -r requirements.txt --break-system-packages
```

Usage syntax:
```
h2csmuggler.py [-h] [--scan-list SCAN_LIST] [--threads THREADS] [--upgrade-only]
               [-x PROXY] [-i WORDLIST] [-X REQUEST] [-d DATA] [-H HEADER]
               [-m MAX_TIME] [-t] [-v] [url]
```

Flag-by-flag breakdown:

| Flag | Purpose | Why it matters mechanically |
|---|---|---|
| `-x PROXY` | The front-end/edge server URL to send the initial upgrade request through — this is the proxy you suspect insecurely forwards h2c upgrades. | This is the connection the tool actually opens; everything else (the target `url` positional argument) describes what gets requested *after* the tunnel is established. |
| `-t` | Test/check-only mode: attempts the h2c upgrade and reports success/failure without sending a full smuggled request. | Use this first, always — confirm the upgrade path exists before attempting to smuggle anything through it. Output looks like `[INFO] h2c stream established successfully.` on success. |
| `--scan-list SCAN_LIST` | Provide a file with a list of candidate front-end URLs (e.g., discovered subdirectories from directory enumeration: `/api/`, `/admin/`, `/auth/`) to bulk-test for the insecure-forwarding condition. | Different path prefixes on the same front-end may route to different backend services with different `proxy_pass` configurations — one path may forward upgrades insecurely while a sibling path doesn't, so bulk-testing across discovered paths is worthwhile rather than testing only the root. |
| `--threads THREADS` | Parallelism for scan-list mode. | Straightforward; keep conservative against production-adjacent targets to avoid inadvertently causing load issues, especially since this establishes real backend connections, not lightweight probes. |
| `--upgrade-only` | Perform the upgrade handshake only, without sending any application-layer request afterward. | Useful for the most minimal possible confirmation of the vulnerable condition — narrower footprint than even `-t`, if you need to be extremely conservative about target impact. |
| `-X REQUEST` | HTTP method for the smuggled request sent *after* the h2c tunnel is established (e.g., `POST`, `PUT`). | This is the method used on the request that reaches the backend directly, bypassing the front-end's own method-based access control if any exists. |
| `-d DATA` | Body data for the smuggled request. | e.g., a JSON payload targeting an internal API endpoint the front-end would normally have blocked or authenticated before allowing through. |
| `-H HEADER` | Add a custom header to the smuggled request (repeatable). | This is how internal-trust-boundary headers get forged — e.g., `-H "X-SYSTEM-USER: true"` or `-H "X-Forwarded-For: 127.0.0.1"` to impersonate an internally-trusted caller, since the backend now believes it's receiving a direct, already-filtered connection rather than raw internet traffic. |
| `-i WORDLIST` | A wordlist of paths to brute-force *on the backend*, using HTTP/2 multiplexing to send many requests efficiently over the single tunneled connection. | This exploits the same multiplexing property from file 1, Section 3 — once the h2c tunnel exists, the tool can fire off many concurrent stream-based requests to enumerate backend-only paths (e.g., internal admin panels never meant to be internet-reachable) far faster than sequential HTTP/1.1 requests would allow. |
| `-m MAX_TIME` | Maximum time to wait for the tunnel/response before giving up. | Useful tuning against slow or unreliable backends to avoid false negatives from premature timeouts. |
| `-v` | Verbose output — shows the underlying frame-level exchange. | Use this when you need to actually understand *why* an attempt failed (e.g., did the upgrade get rejected outright, or did it succeed but the subsequent request get a 403 from a still-enforcing backend). |
| `url` (positional) | The actual request target once the tunnel exists — note it requires a full scheme (`http://` or `https://`) because, per the tool's own documentation, the HTTP/2 `:scheme` pseudo-header is mandatory (file 1, Section 2.2), and the tool needs an explicit value to populate it. | |

### 2.3 Worked Example Breakdown

```bash
./h2csmuggler.py -x https://edgeserver -t
```
- `-x https://edgeserver`: attempt the h2c upgrade handshake against `edgeserver`, over TLS (the front-end's public-facing HTTPS listener).
- `-t`: test-only — report whether the upgrade succeeded, don't proceed further.
- **What "success" means here**: the front-end forwarded the raw `Upgrade: h2c` handshake through to something behind it that responded with a `101 Switching Protocols` and then correctly speaks HTTP/2 framing afterward — meaning the front-end is not intercepting/terminating this handshake itself, which is the vulnerable condition.

```bash
./h2csmuggler.py -x https://edgeserver -X POST -d '{"user":128457,"role":"admin"}' \
  -H "Content-Type: application/json" -H "X-SYSTEM-USER: true" \
  http://backend/api/internal/user/permissions
```
- Having confirmed the tunnel works (previous command), this sends an actual `POST` request, with a JSON body attempting a privilege-escalation-style payload, and a forged `X-SYSTEM-USER: true` header — targeting an internal API path (`/api/internal/user/permissions`) that the front-end's routing rules would ordinarily block from direct internet access, but which is now reachable because the tunneled connection goes straight to the backend, with the front-end acting as a transparent pipe rather than an enforcing gateway.
- The `http://` (not `https://`) scheme in the target URL reflects that, internally, the tunneled connection to the backend is typically cleartext (h2**c** — the "c" specifically means cleartext) even though the initial handshake with the front-end happened over TLS.

---

## 3. Burp Suite HTTP/2 Configuration — Full Breakdown

### 3.1 Enabling HTTP/2 Support

- **Settings → Tools → Repeater / Proxy → HTTP/2**: confirm "Enable HTTP/2" is checked. This governs whether Burp will negotiate HTTP/2 via ALPN when acting as a client toward the target.
- **Settings → Network → HTTP → "Enable HTTP/2 for cleartext (h2c) connections"**: off by default; enable specifically when testing h2c-related scenarios (Section 2) so that Burp's own tooling (Repeater, Intruder) can construct and send h2c upgrade requests manually if you want to build/inspect the handshake yourself rather than relying solely on h2csmuggler.

### 3.2 Repeater — Forcing Protocol Version Per-Request

This is the single most important HTTP/2-specific control in Burp for this whole note series:

- Open the **Inspector** panel on a Repeater tab, expand **Request Attributes**.
- The **Protocol** dropdown lets you force that specific tab to **HTTP/1**, **HTTP/2**, or follow **auto-negotiation** (whatever ALPN would normally select) — independent of what the original captured request actually used.
- **Why this matters for every file in this series**: many targets support both protocol versions simultaneously, and the vulnerability under test may only manifest on one specific version. The classic CL.TE/TE.CL smuggling labs explicitly require forcing the protocol down to HTTP/1.1 even when the lab "supports HTTP/2" (because the intended vulnerable behavior is HTTP/1.1-specific); conversely, H2.CL/H2.TE and CRLF-injection labs (file 3) require explicitly forcing HTTP/2, since the vulnerable condition is the downgrade-rewrite path, which only triggers when the *client* actually speaks HTTP/2 to the front-end.
- Practical workflow: capture or construct your base request once, then duplicate the Repeater tab and set one copy to HTTP/1 and one to HTTP/2, testing the same logical request under both protocols to see if behavior diverges — divergence itself is often the first signal worth investigating.

### 3.3 Inspector — Editing Pseudo-Headers and Injecting Raw Newlines

- Pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`) appear as distinct, directly-editable fields in the Inspector when viewing an HTTP/2 request — unlike HTTP/1.1 view, where these concepts are embedded in the request line and `Host` header rather than shown as discrete fields.
- To inject a literal newline character into a header **value** (the mechanism behind file 3, Section 5 and file 4, Section 3): drill down into the specific header row in the expanded Inspector view (not the quick double-click-to-edit shortcut, which doesn't support this), place your cursor within the value, and press **Shift+Return**. This inserts a raw newline byte into the HPACK-encoded string content, which Burp will then encode and send faithfully — exactly the "legal-in-HPACK, dangerous-once-downgraded" primitive described in files 3 and 4.

### 3.4 Content-Length / Frame-Length Discrepancy Testing

- In HTTP/2 view, Burp exposes a `content-length` header field as independently editable text, separate from the actual frame-level byte accounting it performs internally when transmitting the DATA frame. This lets you directly construct the H2.CL scenario from file 3, Section 3: set `content-length` to a value that doesn't match the actual body you're sending, and observe how the target's front-end handles the mismatch.
- There's no "Update Content-Length" auto-fix checkbox behavior in HTTP/2 view in the same sense as HTTP/1.1 Repeater — because at the framing layer, Burp always sends the correct frame length regardless of what you type into the `content-length` header text field. This is precisely why the technique works: the header value and the true frame length can be made to diverge deliberately, and Burp will not "fix" this divergence for you (which is exactly the behavior you need to reproduce the vulnerability).

### 3.5 Detecting HTTP/2 Support Burp Wouldn't Otherwise Notice

Some servers support HTTP/2 but fail to advertise it correctly via ALPN during the TLS handshake (a misconfiguration, not a deliberate choice) — clients including Burp will, by default, fall back to HTTP/1.1 in this case since ALPN negotiation determines protocol selection automatically. To manually check for this: force a Repeater tab's protocol to HTTP/2 (Section 3.2) even against a target that appeared to only offer HTTP/1.1 — if the request succeeds, you've found HTTP/2 attack surface that would otherwise be missed entirely by relying on automatic negotiation, which is exactly the scenario file 3's advanced-smuggling material warns testers not to overlook.

---

## 4. What's Next

File 6 ties h2spec test-group names, h2csmuggler workflow, and Burp's protocol-forcing technique together into a single cheatsheet, alongside the complete PortSwigger Web Security Academy HTTP Request Smuggling lab list mapped in Apprentice → Practitioner → Expert order, with honest disclosure of which labs are HTTP/2-specific versus which are HTTP/1.1-only despite "supporting" HTTP/2.
