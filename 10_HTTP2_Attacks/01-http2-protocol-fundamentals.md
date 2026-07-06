# HTTP/2 Protocol Fundamentals for Pentesters

## Real-World Context

Most modern API gateways (Envoy, Kong, Apigee, AWS ALB, Cloudflare, nginx 1.25+) speak HTTP/2 on the client-facing side by default, even when the origin/backend only supports HTTP/1.1. This makes HTTP/2 protocol-level testing directly relevant to API security assessments, not just a theoretical curiosity. Every attack in this note series (Rapid Reset, downgrade smuggling, HPACK abuse, multiplexing abuse) depends on understanding the four mechanisms covered in this file. Skipping this file and jumping straight to "payloads" will make the later files look like magic instead of engineering.

---

## 1. Why HTTP/2 Exists and What Changed

HTTP/1.1 has three structural problems that HTTP/2 was designed to fix:

1. **Head-of-line blocking at the application layer.** On a single HTTP/1.1 connection, requests are processed strictly in order. If request #1 is slow, request #2 cannot be answered first, even though the TCP connection could carry more data. Browsers worked around this by opening 6-8 parallel TCP connections per host, which is wasteful (TCP handshake, TLS handshake, and slow-start overhead per connection).
2. **Verbose, repetitive headers.** Every HTTP/1.1 request re-sends full text headers (Cookie, User-Agent, Accept-*, etc.) with no compression across requests. This wastes bandwidth on high-latency mobile connections.
3. **No true multiplexing.** HTTP/1.1 pipelining (sending multiple requests without waiting for responses) exists on paper but is barely deployed because if the *first* response frame in a pipelined stream is malformed or slow, everything after it stalls — and intermediary proxies handle pipelining inconsistently.

HTTP/2 (RFC 7540, then RFC 9113 which obsoletes 7540) solves this by:
- Introducing a **binary framing layer** instead of text-based messages.
- Splitting a connection into independent **streams** that can be multiplexed.
- Compressing headers with **HPACK** instead of sending them as raw repeated text.

Every one of these three design choices — binary framing, multiplexing, HPACK — is also the *root cause* of a distinct attack surface. That is not a coincidence; it is the recurring theme of this whole note series.

---

## 2. The Binary Framing Layer

### 2.1 Mechanism

In HTTP/1.1, a request is a sequence of ASCII text terminated by CRLF (`\r\n`) sequences, with the message body length determined by `Content-Length` or `Transfer-Encoding: chunked`. Everything is delimited by *text conventions* that a parser has to interpret.

In HTTP/2, there are no CRLF delimiters at all. Instead, every unit of communication is a **frame** with a fixed 9-byte header:

```
+-----------------------------------------------+
|                 Length (24)                    |
+---------------+---------------+---------------+
|   Type (8)    |   Flags (8)   |
+-+-------------+---------------+-------------------------------+
|R|                 Stream Identifier (31)                      |
+=+=============================================================+
|                   Frame Payload (0...)                       ...
+---------------------------------------------------------------+
```

Breaking this down field by field, because this exact structure is what every later attack manipulates:

| Field | Size | What it does | Why it matters for testing |
|---|---|---|---|
| **Length** | 24 bits (3 bytes) | States the exact byte length of the frame payload that follows, up to 16,777,215 bytes (though negotiated `SETTINGS_MAX_FRAME_SIZE` usually caps this at 16,384 by default). | This replaces `Content-Length` ambiguity entirely *for framing purposes*. The frame boundary is never in question — the parser reads exactly `Length` bytes, no more, no less. This is why HTTP/2 end-to-end is structurally immune to the classic CL.TE/TE.CL desync (see file 3 for why downgrading reintroduces the problem). |
| **Type** | 8 bits (1 byte) | Identifies what kind of frame this is: `0x0` DATA, `0x1` HEADERS, `0x2` PRIORITY, `0x3` RST_STREAM, `0x4` SETTINGS, `0x5` PUSH_PROMISE, `0x6` PING, `0x7` GOAWAY, `0x8` WINDOW_UPDATE, `0x9` CONTINUATION. | Rapid Reset (file 2) abuses HEADERS + RST_STREAM in sequence. HPACK abuse (file 4) abuses HEADERS + CONTINUATION. Knowing frame types tells you what to look for in a packet capture or Burp's HTTP/2 frame view. |
| **Flags** | 8 bits (1 byte) | Type-specific bit flags. For HEADERS: `END_STREAM` (0x1, no more data coming on this stream) and `END_HEADERS` (0x4, the header block is complete, no CONTINUATION frames follow). For DATA: `END_STREAM`, `PADDED`. | `END_STREAM` is the *actual* mechanism HTTP/2 uses to mark "this request/response is done" — this is what replaces `Content-Length`/chunked-encoding as a boundary signal. Get this wrong when crafting frames by hand (e.g., with a raw socket script) and you will hang the connection or corrupt the stream state. |
| **R (reserved)** | 1 bit | Must be unset; reserved for future use. | Irrelevant to testing, but some malformed-frame conformance tests (h2spec, file 5) specifically check that implementations ignore this bit rather than rejecting the frame. |
| **Stream Identifier** | 31 bits | Which logical stream (see Section 3) this frame belongs to. Client-initiated streams use odd numbers (1, 3, 5, ...); server-initiated (PUSH_PROMISE) use even numbers. Stream 0 is reserved for connection-level frames (SETTINGS, PING, GOAWAY, WINDOW_UPDATE at connection scope). | This is the field Rapid Reset abuses directly — an attacker opens thousands of new odd-numbered stream IDs in rapid succession, each carrying a HEADERS frame, then immediately follows each with an RST_STREAM on the same stream ID. |

### 2.2 What This Means Practically

When you inspect raw HTTP/2 traffic (e.g., via `nghttp -v`, Wireshark with the HTTP/2 dissector, or Burp's Inspector in HTTP/2 mode), you are not reading a request — you are reading a **sequence of frames**, several of which combine to form what looks like one HTTP request. A single logical request is typically:

1. One or more `HEADERS` frames (plus `CONTINUATION` frames if the header block doesn't fit in one frame) — carries the `:method`, `:path`, `:authority`, `:scheme` pseudo-headers and regular headers.
2. Zero or more `DATA` frames — carries the body.
3. The final frame in the sequence sets the `END_STREAM` flag to signal completion.

Note there is no HTTP/2 equivalent of an HTTP/1.1 status line or request line as raw text — `:method: GET`, `:path: /api/v1/users`, `:authority: example.com`, and `:scheme: https` are **pseudo-headers**, sent as regular HPACK-encoded header fields distinguished only by their leading colon. This matters directly for HPACK abuse (file 4): pseudo-headers must appear before regular headers in the block, and a conformant server must reject a HEADERS block that violates this ordering — many home-grown or older HTTP/2 implementations don't enforce it correctly.

---

## 3. Stream Multiplexing

### 3.1 Mechanism

A single HTTP/2 connection (one TCP socket, one TLS session) carries many **independent streams**. Each stream is identified by its Stream Identifier and has its own state machine (idle → open → half-closed → closed), but all streams share the same underlying TCP connection.

This is fundamentally different from HTTP/1.1's approach of "one TCP connection can carry one request at a time (or, with pipelining, several — but responses must return strictly in the order requests were sent)." In HTTP/2:

- The client can send HEADERS for stream 1, then HEADERS for stream 3, then more DATA for stream 1, then HEADERS for stream 5 — all interleaved on the wire, distinguished only by the Stream Identifier field in each frame.
- The server can respond to stream 5 *before* it finishes responding to stream 1, because nothing about the protocol requires in-order completion. This is what solves head-of-line blocking.

### 3.2 Why This Matters for Testing

Two direct consequences:

1. **Concurrency-based race conditions become trivial to trigger with precision.** In HTTP/1.1, achieving true "single-packet" simultaneity for race-condition testing (e.g., double-spend, TOCTOU on a coupon-redemption endpoint) requires last-byte-synchronization tricks across multiple TCP connections (Burp's "single-packet attack" feature does this by holding back the final bytes of each request on separate connections and releasing them together). In HTTP/2, because multiple streams share one connection, you can send the final frames of several requests within the same TCP write, achieving tighter synchronization more reliably — this is why Burp's Repeater "send group in parallel" feature specifically prefers HTTP/2 when available.
2. **Resource exhaustion moves from "requests per second" to "streams per connection."** A server has to allocate state (stream table entries, buffers, sometimes a backend connection or thread) per open stream. `SETTINGS_MAX_CONCURRENT_STREAMS` (default often 100–128) is supposed to cap how many streams a client can have open *at once* on a single connection — but "at once" is doing a lot of work in that sentence, which is exactly what Rapid Reset (file 2) exploits.

### 3.3 Flow Control Interaction

Each stream, and the connection as a whole, has its own flow-control window (managed via `WINDOW_UPDATE` frames), independent of every other stream. This is worth knowing because some resource-exhaustion variants (distinct from Rapid Reset) abuse flow control instead of stream cancellation: a client advertises a large window, sends a request that would produce a large response, then never sends `WINDOW_UPDATE` frames to let the server actually deliver the data — tying up server-side buffers holding the unsent response. This is not the focus of file 2, but it's worth knowing as a related resource-exhaustion primitive when a WAF/gateway claims "Rapid Reset protection" — flow-control-based exhaustion is a different mechanism and isn't necessarily covered by the same mitigation.

---

## 4. HPACK Header Compression

### 4.1 Mechanism

Sending full header text on every request (`Cookie: session=abc123...`, `User-Agent: Mozilla/5.0 ...`, `Accept-Language: en-US,en;q=0.9`) on every single request in a page-load burst of 50+ requests is wasteful — much of it is byte-for-byte identical across requests. HPACK (RFC 7541) solves this with two complementary techniques:

1. **Static Table** — a fixed table of 61 common header name/value pairs baked into the spec (e.g., index 2 is always `:method: GET`, index 8 is always `:status: 200`). Both sides know this table by heart; referencing "index 2" is far cheaper than sending `:method: GET` as text.
2. **Dynamic Table** — a table that both the client and server build up *as the connection progresses*. When a header is sent in full once, both sides add it to their dynamic table. On subsequent requests, that header can be referenced by a small index number instead of being re-sent in full. The dynamic table has a negotiated maximum size (via `SETTINGS_HEADER_TABLE_SIZE`) and evicts oldest entries when full (FIFO).
3. **Huffman coding** — an optional per-string compression scheme using a static Huffman table defined in the HPACK spec, applied to literal header values that aren't in either table.

### 4.2 Why the Dynamic Table Is Dangerous

The dynamic table is **stateful and per-connection**. This has two security implications that file 4 covers in depth:

- **Cross-request header injection risk.** Because the dynamic table persists across streams sharing a connection, index references are connection-scoped, not stream-scoped. If a server-side component that decompresses HPACK is later re-serialized to HTTP/1.1 text (i.e., downgraded) incorrectly, or if two "logical requests" from different trust levels end up sharing a dynamic table state through a proxy that doesn't fully re-encode HPACK per hop, unexpected header values can leak or collide between what should be isolated requests.
- **Decompression bomb potential.** Because dynamic table entries can be referenced repeatedly by index, and because HPACK allows incremental "never indexed" vs "indexed" literal encodings, a maliciously crafted header block can force a decoder to do far more work (or allocate far more memory) than the wire size of the block suggests — this is the same class of amplification risk as zip bombs, scoped to header compression. RFC 7541 §7 explicitly calls out implementation guidance to bound dynamic table size and reject unreasonable requests; not every implementation does this correctly, and h2spec (file 5) includes conformance tests for exactly this.

### 4.3 CONTINUATION Frames

If a single HEADERS frame's compressed header block doesn't fit within `SETTINGS_MAX_FRAME_SIZE`, the block is split across a HEADERS frame followed by one or more `CONTINUATION` frames. Critically: **the HPACK header block is logically one unit spanning all these frames** — a decoder must buffer everything until it sees `END_HEADERS`, and cannot safely start decoding early. This "must buffer until complete" requirement is the root cause of the 2024 "HTTP/2 CONTINUATION Flood" class of vulnerabilities (CVE-2024-27316 and related, affecting Apache, node, and others): sending an unbounded stream of CONTINUATION frames without ever setting `END_HEADERS` forces the server to keep buffering indefinitely. This is a distinct but related resource-exhaustion primitive to Rapid Reset — where Rapid Reset abuses stream *count*, CONTINUATION flood abuses header-block *size/duration* on a single stream. File 4 covers the header-block-manipulation angle of CONTINUATION frames; file 2 focuses specifically on the Rapid Reset stream-cancellation pattern.

---

## 5. HTTP/2 in Burp Suite — What's Different

### 5.1 Enabling and Verifying HTTP/2

Burp negotiates HTTP/2 automatically via ALPN during the TLS handshake when both the browser/client and the target server support it — you don't toggle this per-request by default. What you need to check and control explicitly:

- **Project options → HTTP → HTTP/2**: confirm "Enable HTTP/2" is checked (on by default in current Burp Suite Professional). There's also an option to enable HTTP/2 for cleartext connections (h2c) if you need to test h2c smuggling (relevant to file 5's h2csmuggler coverage) — this is off by default because h2c is rare in the wild outside internal/misconfigured proxy_pass setups.
- **Repeater → Request attributes → Protocol**: this is the critical control. Burp lets you force a specific Repeater tab to use HTTP/1.1 or HTTP/2 *independent of what the browser negotiated*, which is essential because many downgrade-smuggling labs and real targets support both, and the vulnerability only manifests over one protocol version. If a lab "supports HTTP/2" but the intended solution is HTTP/1.1-only (this is explicitly the case for the classic CL.TE/TE.CL labs), you must manually force the protocol down to HTTP/1.1 in this panel — Burp won't do it for you based on what "should" work.
- **Inspector panel**: when viewing an HTTP/2 request, Burp shows pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`) as distinct from regular headers, and lets you edit them directly — something that has no equivalent concept in HTTP/1.1 view.

### 5.2 Injecting Raw Newlines (CRLF-equivalent) in HTTP/2

Because HTTP/2 has no CRLF delimiters, you cannot "inject a header" the way you would in HTTP/1.1 by typing `\r\nX-Injected: value` into a text field — there is no text field being parsed that way. Instead, Burp's Inspector has a specific mechanism: drill down into an individual header row, then press **Shift+Return** to insert a literal newline character *inside* the header's name or value in the HPACK-encoded field. This is only available when editing via the expanded Inspector view (not the raw double-click-to-edit shortcut). This exact technique is the intended solution mechanism for the PortSwigger "HTTP/2 request smuggling via CRLF injection" lab (file 6 lab mapping) — the newline is legal inside an HPACK-encoded string (HPACK doesn't forbid it, unlike HTTP/1.1 syntax, which treats `\r\n` as a hard delimiter), but becomes dangerous the moment a downgrading front-end serializes that header value back into HTTP/1.1 text, because the embedded newline is then interpreted by the backend as a real header delimiter.

### 5.3 Content-Length Handling Differs

In Burp Repeater's HTTP/1.1 view, "Update Content-Length" is a checkbox that auto-fixes the length header when you edit the body — this is well known to anyone who has done classic CL.TE smuggling labs. In HTTP/2 view, there usually is no body-length header to "fix" in the same sense, because DATA frame length is computed by the frame's own Length field — but Burp still exposes a `content-length` *header* (not the frame-level length) as an editable field, and this is exactly the discrepancy H2.CL smuggling (file 3) exploits: the HTTP/2 frame layer has one true length (unambiguous), but the `content-length` *header value* is just a string that a downgrading front-end will trust when constructing the HTTP/1.1 request line for the backend, and that string can be made to lie.

---

## 6. What's Next

- **File 2** — Rapid Reset (CVE-2023-44487): abusing the Stream Identifier + RST_STREAM mechanism from Section 3 to exhaust server resources.
- **File 3** — HTTP/2-to-HTTP/1.1 downgrade smuggling: abusing the gap between the binary framing layer's unambiguous length (Section 2) and the HTTP/1.1 text length headers a downgrading front-end has to reconstruct.
- **File 4** — HPACK abuse in depth: dynamic table poisoning and CONTINUATION-based attacks, building on Section 4.
- **File 5** — Tooling: h2spec, h2csmuggler, and Burp HTTP/2 configuration, expanding on Section 5.
- **File 6** — Consolidated cheatsheet and full PortSwigger lab mapping.
