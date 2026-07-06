# HPACK Header Compression Abuse

## Cross-Reference Note

This file builds directly on file 1, Section 4 (HPACK mechanism: static table, dynamic table, Huffman coding) and file 3, Section 5 (CRLF-equivalent injection via downgrade rewriting). If you haven't read those sections, the "why" behind the attacks below won't land — this file assumes you know what the dynamic table is and why CONTINUATION frames exist.

---

## 1. Two Distinct Abuse Categories

HPACK abuse splits into two mechanistically different categories that are easy to conflate but require different testing approaches:

1. **Header injection via compression table manipulation** — abusing the *stateful* nature of the dynamic table to make one request's header state bleed into another, or to smuggle content through header values that survive HPACK encoding but become dangerous once decoded/re-serialized elsewhere.
2. **CRLF-equivalent attacks in a binary framing context** — getting characters that HTTP/1.1 treats as structural delimiters (`\r`, `\n`) through HPACK encoding intact, so they cause damage at a downstream point that parses the value as text (this overlaps with file 3, Section 5, but here we focus on the HPACK encoding mechanics specifically, not the downgrade-rewrite consequence).

---

## 2. Dynamic Table Mechanics — What an Attacker Actually Controls

Recall from file 1: the dynamic table is built incrementally, per-connection, as headers are sent. Every time a header is sent with the **"incremental indexing"** representation (as opposed to "without indexing" or "never indexed" — HPACK defines three literal representations per RFC 7541 §6.2), both peers add that header name/value pair to their dynamic table, growing it by one entry, evicting the oldest entry if the table is at its negotiated `SETTINGS_HEADER_TABLE_SIZE` capacity.

This means an attacker who can send arbitrary header sequences on a connection (which, on a shared/pooled backend connection behind a downgrading front-end — file 3 — may include influence over what "shares" that connection) can:

- **Deliberately grow the dynamic table with attacker-chosen name/value pairs**, then reference them by index in a later frame — this only matters as an attack primitive when the *decoder* on the other end is not the intended isolated recipient, i.e., when connection reuse or improper request isolation lets one logical request's dynamic-table contributions affect another's decoding.
- **Deliberately evict entries** the attacker wants gone from the table (by pushing enough new entries to force FIFO eviction) — relevant in more exotic timing/side-channel scenarios (see Section 4) where table state is used to infer information about other requests on the same connection.

### 2.1 Why This Matters Behind a Downgrading Front-End

The realistic exploitation path (rather than a purely theoretical HPACK-internals concern) is this: many front-ends maintain **one persistent backend connection per front-end worker**, reused across many different client requests, each independently HPACK-decoded by the front-end before being rewritten to HTTP/1.1. If the front-end's HPACK decoder implementation has any bug in how it isolates per-stream header state versus per-connection dynamic-table state (e.g., failing to fully reset or correctly scope table references between distinct client streams multiplexed on the same connection), an attacker on stream A could reference or influence a dynamic-table entry that was actually populated by a different, concurrent client's stream B on the same connection — a header-value cross-contamination bug. This is a decoder-implementation-correctness issue, not something guaranteed present on any given target, but it's exactly the class of bug h2spec conformance testing (file 5) is designed to surface, because RFC 7541 is explicit about per-connection (not per-stream) dynamic table scope, and a conformant implementation must handle multiplexed streams referencing a shared table correctly without cross-stream leakage.

---

## 3. CRLF-Equivalent Injection — HPACK Encoding Mechanics

### 3.1 Why HPACK Doesn't Stop You

HTTP/1.1 header parsing treats `\r\n` as a hard, unconditional delimiter — there is no way to encode a literal CRLF sequence inside an HTTP/1.1 header value using standard syntax; any parser that sees `\r\n` mid-header will interpret it as the end of that header line. HPACK has **no equivalent restriction**. A header value in HPACK is just a length-prefixed (or Huffman-coded) byte string — the encoding format does not forbid any particular byte value, including `0x0D` (`\r`) or `0x0A` (`\n`), from appearing inside a header value's string content. This is a deliberate, correct design choice for a binary protocol (there's no reason a binary format should reserve those bytes as special), but it means: **whatever validation exists to prevent this must be application/gateway logic added on top of HPACK, not something HPACK itself enforces.**

### 3.2 The Injection Path, Piece by Piece

1. The attacker constructs an HTTP/2 request where a chosen header's value (say, a custom header, or in some cases a less-scrutinized standard header) contains an embedded `\r\n` (or bare `\n`) byte sequence, injected via Burp's Inspector Shift+Return mechanism (file 1, Section 5.2) since normal text-entry UI doesn't let you type a raw control character into a value field directly.
2. This request is entirely valid HTTP/2 — the frame's `Length` field correctly accounts for every byte, HPACK encodes the string faithfully including the embedded newline bytes, and nothing aboutframing or compression breaks. **This is the key point: there is no protocol violation here at the HTTP/2 layer.** A strict h2spec conformance check would not necessarily flag this request as malformed, because it isn't — the vulnerability is entirely in what happens *after* decoding, at the point of re-serialization.
3. If the receiving component **decodes** the HPACK value (recovering the literal string, newline bytes included) and then treats that decoded string as safe to insert directly into an HTTP/1.1 text stream (during downgrade rewriting — file 3) or into any other text-based protocol/log/header-forwarding mechanism without escaping or rejecting control characters, the embedded newline becomes a real structural delimiter in that downstream context.
4. Depending on exactly where in the header block the injected newline lands, this can: (a) inject an entirely new, attacker-controlled header line into the backend's view of the request, (b) prematurely terminate the header block from the backend's perspective and cause subsequent attacker-controlled bytes to be interpreted as the start of a new request (the smuggling case covered in file 3, Section 5), or (c) in less common cases, corrupt logging or observability pipelines that naively write decoded header values to line-oriented log files, enabling log injection/forgery as a side effect.

### 3.3 Distinguishing This From File 3's CRLF Coverage

File 3 covers the CRLF injection technique specifically as a **request-smuggling enabler** (the practical PortSwigger lab scenario: injected newline → backend misinterprets request boundary → next real request gets glued to a smuggled prefix). This file covers the **encoding-layer mechanics** that make that possible — i.e., *why* HPACK lets this through at all, and that the same underlying byte-smuggling primitive has consequences beyond just request smuggling (log injection, header injection into any text-based downstream consumer, not only the HTTP/1.1 request-boundary case). If you're documenting a finding, file 3's framing is right for "this leads to request smuggling"; this file's framing is right for "here is the root HPACK-level primitive, and here's why it isn't caught by protocol-conformance checking alone."

---

## 4. CONTINUATION Frame Abuse

Recall file 1, Section 4.3: if a header block doesn't fit in one HEADERS frame, it continues across one or more CONTINUATION frames, and a decoder must buffer the entire block until it sees the `END_HEADERS` flag — it cannot safely begin processing early, because HPACK's dynamic-table-referencing scheme means a later frame in the sequence could reference (or even redefine, via table-size-update instructions embedded in the encoding) state that changes how earlier bytes should be interpreted.

### 4.1 The Abuse Pattern

An attacker sends a HEADERS frame, then an effectively unbounded sequence of CONTINUATION frames, **never setting `END_HEADERS`**. Because the decoder is spec-required to keep buffering until it sees that flag, this forces the server to:

- Keep allocating memory to buffer the ever-growing, still-incomplete header block.
- Keep the stream (and often, depending on implementation, the entire connection-handling worker/thread) tied up waiting for a header block that will never complete, since the attacker simply never sends the terminating flag.

This is mechanistically a resource-exhaustion primitive (related to file 2's Rapid Reset in that both target server-side resource accounting gaps, but operating on entirely different mechanisms — Rapid Reset abuses stream-count/RST_STREAM timing; CONTINUATION flood abuses header-block buffering with no size or frame-count cap). This class of issue is what CVE-2024-27316 and related 2024 disclosures (affecting Apache httpd's mod_http2, several Go-based HTTP/2 servers, and others) addressed — patches generally added explicit caps on cumulative CONTINUATION frame count/size per header block, and on how long a stream may remain in the "awaiting END_HEADERS" state before the server forcibly resets it.

### 4.2 Testing Consideration — Same Authorization Caveat as File 2

Because this is fundamentally a resource-exhaustion technique (like Rapid Reset), **the same authorization requirements from file 2, Section 6, apply here.** Do not send a genuinely unbounded CONTINUATION sequence against any target without explicit written authorization for availability testing. A low-volume conformance probe (send a modest, clearly-bounded number of CONTINUATION frames without `END_HEADERS` and observe whether the server has an enforced cap — then close the connection cleanly yourself rather than exhausting it) is a reasonable way to check for the *presence* of a cap without actually causing impact, and is the approach h2spec-style conformance testing takes (file 5).

---

## 5. WAF / API Gateway Relevance

**Detection methods:**
- For dynamic-table cross-contamination concerns (Section 2): this is fundamentally an implementation-correctness issue in the HPACK decoder itself, not something a WAF sitting in front of a correct decoder can meaningfully add a layer of defense against — if the underlying HTTP/2 library correctly scopes dynamic table state per RFC 7541, there's nothing for a WAF to "detect" here, because there's no exploitable condition. This is one of the sub-techniques where **WAF/gateway-level bypass discussion is not the right frame at all** — the relevant question in a report is "which HTTP/2 library/version is in use, and is it patched against known HPACK decoder isolation bugs," not "did the WAF block this."
- For CRLF-equivalent injection (Section 3): detection requires the gateway to validate decoded header values for control characters (`\r`, `\n`, and other characters outside RFC 7230's allowed header-value character set) *after* HPACK decoding but *before* re-serializing to any text-based downstream format — this is the same defensive principle as file 3, Section 6, since it's the same underlying primitive viewed from the encoding-mechanics angle.
- For CONTINUATION flood (Section 4): detection is a server/library-level cap on cumulative header-block size and CONTINUATION frame count per stream, plus a timeout on "awaiting END_HEADERS" state — this is squarely an infrastructure patching question (confirm the specific HTTP/2 server version and whether it received the 2024 CONTINUATION-flood mitigations), not something a WAF sitting in front of an unpatched server can meaningfully compensate for, since the exhaustion happens in the underlying HTTP/2 parsing library itself, often before a WAF module even gets a fully-formed request to inspect.

**Realistic bypass considerations:**
- Where header-value sanitization exists but is applied inconsistently across header names (common in gateways that were patched reactively for the CRLF-injection lab class specifically, rather than comprehensively), test every distinct header field independently — custom application headers, less common standard headers (`Referer`, `X-Forwarded-*` variants), and trailers are common gaps.
- Where a gateway caps CONTINUATION frame *count* but not cumulative *byte size*, an attacker can still achieve significant buffering pressure using fewer, larger CONTINUATION frames — always test both the count-based and size-based variants of the CONTINUATION flood pattern (within the authorization constraints of Section 4.2) rather than assuming a count cap alone closes the issue.

---

## 6. What's Next

File 5 covers h2spec (which includes dedicated HPACK conformance test groups directly relevant to Sections 2 and 4 of this file) and h2csmuggler, plus full Burp HTTP/2 configuration detail. File 6 consolidates everything into a single cheatsheet with the full PortSwigger lab mapping.
