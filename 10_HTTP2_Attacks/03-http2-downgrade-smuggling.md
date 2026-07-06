# HTTP/1.1 to HTTP/2 Downgrade Smuggling

## Cross-Reference Note

This file assumes you already have the general CL.TE / TE.CL request smuggling mental model from your existing HTTP Request Smuggling (HTTP/1.1) note series — specifically: request smuggling arises when a front-end and back-end server **disagree about where one request ends and the next begins**, letting an attacker "smuggle" a prefix of a second request hidden inside the body of the first, which gets glued onto the front of whatever the next real user sends. If that core mental model isn't fresh, review that series' CL.TE/TE.CL fundamentals first — this file only covers what's **unique to the HTTP/2 downgrade context**, not the general smuggling concept.

---

## 1. Why HTTP/2 End-to-End Is Supposed to Be Immune to This

Recall from file 1, Section 2: every HTTP/2 frame carries an explicit, unambiguous `Length` field. There is no `Content-Length` header to lie about and no `Transfer-Encoding: chunked` parsing ambiguity to exploit, because the frame boundary is determined by a field the protocol itself defines and enforces — not by a text header that two different parsers might interpret differently. **If a website speaks HTTP/2 all the way from the client to the origin application, with no protocol translation anywhere in the chain, classic request smuggling is structurally impossible**, because there is no length ambiguity for an attacker to introduce.

## 2. Where the Immunity Breaks: HTTP/2 Downgrading

In practice, almost no origin/backend application server speaks HTTP/2 natively end-to-end. The overwhelmingly common real-world architecture is:

```
Client  --[HTTP/2]-->  Front-end (CDN / load balancer / reverse proxy)  --[HTTP/1.1]-->  Backend / origin
```

The front-end terminates the client's HTTP/2 connection, then **re-encodes each request as HTTP/1.1 text** to forward it to a backend that only understands HTTP/1.1. This re-encoding step is called **HTTP/2 downgrading** (or "downgrade rewriting"), and it is where the vulnerability class in this file lives. The front-end has to translate the frame-level `Length` field it received (unambiguous, binary) back into a `Content-Length` **header** (a text string) for the backend — and this translation step is exactly the kind of glue code where an attacker's malformed input can produce a value the front-end trusts but the backend interprets differently, or vice versa.

This isn't a hypothetical architecture — it's the majority case. Front-ends that support downgrading include most major reverse proxies and CDNs where HTTP/2 support was added as a client-facing feature without every backend integration being redesigned to speak HTTP/2 natively.

---

## 3. H2.CL Desync — The Core Mechanism

### 3.1 Setup

The front-end receives an HTTP/2 request. It reads the frame-level length (correct, unambiguous, from the DATA frame's `Length` field) to know how much body data the client sent. It then constructs an HTTP/1.1 request to forward to the backend, and — this is the vulnerable step — it sets the outgoing `Content-Length` header based on **what the client claimed in the request's `content-length` header value**, rather than (or in addition to, inconsistently) the actual frame-level byte count it received.

### 3.2 The Desync

If the client sends an HTTP/2 request with:
- A `content-length` header claiming a value (say, `0`), **and**
- An actual DATA frame body that is longer than that claimed value (say, it actually contains `GET /resources HTTP/1.1\r\nHost: foo\r\nContent-Length: 5\r\n\r\nx=1`),

...then two different things can happen depending on which "length" a given component trusts:

- HTTP/2 framing already told the front-end the true byte length (via the DATA frame's `Length` field) — the front-end can read the *entire* body correctly regardless of what the `content-length` header claims, because at the HTTP/2 framing layer, the header field value is just a string; it isn't what determines the frame boundary.
- But when the front-end downgrades and forwards to the backend over HTTP/1.1, it forwards the **stated** `content-length: 0` header along with the **full body it actually received** (the "0" plus the smuggled data appended after it).
- The backend, now speaking HTTP/1.1 and trusting the `Content-Length: 0` header literally, reads **zero bytes** as the body of this request and considers the request complete after the headers — treating everything past that point (the smuggled `GET /resources HTTP/1.1 ...` fragment) as the **start of the next request** on the connection.

This is functionally the same end result as a classic CL.0-style desync in pure HTTP/1.1, but the ambiguity is introduced specifically by the **downgrade rewriting step**, not by anything ambiguous in the wire format the client sent to the front-end.

### 3.3 Concrete Frame-Level Breakdown

Using Burp's HTTP/2 message representation (as flat text for readability, matching PortSwigger's own convention of representing HTTP/2 messages as single entities rather than separate raw frames):

```
POST / HTTP/2
Host: target.example
Content-Length: 0

GET /resources HTTP/1.1
Host: foo
Content-Length: 5

x=1
```

Piece by piece, what's happening and why:

- `POST / HTTP/2` and `Host: target.example` — a completely ordinary, well-formed HTTP/2 request. Nothing here looks malformed at the framing layer; the frame's `Length` field correctly reflects the entire body shown below, including the smuggled portion.
- `Content-Length: 0` — this is the **header value**, sent as an HPACK-encoded header field. It's a lie relative to the actual DATA frame body, but HTTP/2 framing doesn't care — the frame boundary is defined by the frame's own `Length` field, not by this header. The front-end reads the full body correctly because it trusts framing, not this header, at the point of *receiving* the request.
- Everything after the blank line (`GET /resources HTTP/1.1 ... x=1`) — this is **all one HTTP/2 DATA frame payload** from the protocol's point of view. There is nothing here that "ends" the request at the frame layer; it's just bytes inside a DATA frame that happens to look like HTTP/1.1 text, because that's what we're choosing to smuggle.
- When the front-end downgrades this to HTTP/1.1 for the backend, it forwards the **stated** `Content-Length: 0` as a literal HTTP/1.1 header, but the **actual bytes it sends** include everything (the fake "0"-length claim, plus the entire smuggled payload). The backend, parsing this as HTTP/1.1 text and trusting `Content-Length: 0`, considers the request done immediately after the header block — and treats `GET /resources HTTP/1.1\r\nHost: foo\r\nContent-Length: 5\r\n\r\nx=1` as the **beginning of the next HTTP/1.1 request** on the same backend connection.
- The net effect: whichever real request the backend would otherwise process next (from a legitimate victim, if the backend connection is shared/pooled across clients — which it usually is behind a reverse proxy) gets **glued onto the end of this smuggled prefix**, producing a request the attacker partially controls, sent under the victim's session.

### 3.4 What Makes This "H2.CL" Specifically

The naming convention (matching PortSwigger's terminology, used directly in file 6's lab mapping) describes *which* length signal is trusted at *which* end:

- **H2.CL**: the front-end trusts the HTTP/2 framing length when reading the request from the client, but when downgrading, forwards a `Content-Length` header to the backend that the backend then trusts literally — creating the mismatch described above.
- **H2.TE**: analogous, but the mismatch involves `Transfer-Encoding` semantics being reintroduced or mishandled during the downgrade rewrite (e.g., the front-end strips or ignores an incoming `Transfer-Encoding` header during translation in a way that lets an attacker's declared chunked-encoding-like structure desync the backend's interpretation, even though transfer-encoding chunking has no direct HTTP/2-frame-layer equivalent to begin with). The PortSwigger materials describe this as enabling **response queue poisoning** specifically — because the desync causes the backend's response *stream* to become misaligned with what the front-end expects to receive next, letting an attacker capture responses meant for other users.

---

## 4. What Is Unique to the HTTP/2 Downgrade Context (vs. Pure HTTP/1.1 Smuggling)

This is the section that most directly answers "what's different here" relative to your existing HTTP/1.1 smuggling notes:

1. **The attacker never has to construct an ambiguous HTTP/1.1 request themselves.** In classic CL.TE/TE.CL smuggling, the attacker's entire craft is in making an HTTP/1.1 request that *two different parsers* disagree about. In the HTTP/2 downgrade case, the client-facing request is **perfectly well-formed HTTP/2** — there's no ambiguity at all in what the client sent. The ambiguity is manufactured entirely by the front-end's **downgrade/rewrite logic**, which the attacker never touches directly — they just supply inputs (a lying `content-length` header value, or newline-containing header values — Section 5) that the rewrite logic mishandles.
2. **CRLF becomes an available injection primitive again, in a place it "shouldn't" be.** HTTP/2 has no CRLF-based header delimiters (file 1, Section 2) — header names/values are HPACK-encoded length-prefixed strings, and a literal `\r\n` inside a header *value* is not inherently meaningful to HTTP/2 framing. But the moment a downgrading front-end serializes that header back into HTTP/1.1 **text** (where `\r\n` is the header delimiter), an embedded newline the attacker snuck into an HPACK-encoded value suddenly becomes a real, backend-interpreted header boundary. This is functionally a "CRLF injection" attack, but the injection point is a protocol **translation boundary**, not a parsing inconsistency between two things speaking the same protocol — see Section 5 and file 4 for the HPACK-specific mechanics.
3. **Browser-only/HTTP/2-exclusive delivery.** Because the vulnerable step only exists when the client actually speaks HTTP/2 to the front-end, and modern browsers negotiate HTTP/2 by default over TLS, some of these attacks are exploitable **purely through a victim's ordinary browser traffic** with no need for the attacker to control any unusual client behavior — unlike some HTTP/1.1 smuggling techniques that require the attacker to control raw socket-level request construction that a browser would never produce.
4. **Detection requires deliberately testing both protocol versions.** Because many origins "support HTTP/2" at the front-end but the vulnerable rewrite behavior only manifests when you actually send an HTTP/2 request with a mismatched length claim (as opposed to testing the classic CL.TE/TE.CL patterns, which by design require dropping down to HTTP/1.1 — see file 1 Section 5.1), you have to explicitly test **both** protocol paths against the same target. A target can be immune to classic CL.TE/TE.CL (because the front-end correctly normalizes HTTP/1.1 length headers) while still being vulnerable to H2.CL/H2.TE (because the *downgrade* rewrite path was never audited with the same rigor).

---

## 5. HTTP/2 CRLF Injection — Downgrade-Specific Mechanics

Building on Section 4, point 2: the attack described in PortSwigger's "HTTP/2 request smuggling via CRLF injection" lab works like this:

1. The front-end downgrades HTTP/2 requests to HTTP/1.1, **and** fails to adequately sanitize incoming header values for characters that are meaningless in HTTP/2 but dangerous in HTTP/1.1 text — specifically bare `\r` or `\n` characters.
2. The attacker crafts an HTTP/2 request where a header **value** contains an embedded newline (inserted via Burp's Inspector Shift+Return mechanism described in file 1, Section 5.2, since there's no text-field way to "type" a raw newline into an HPACK-encoded value through normal UI editing).
3. When the front-end serializes this header for the HTTP/1.1 backend, the embedded newline is written out literally as `\r\n` (or `\n`) in the text stream — which the backend's HTTP/1.1 parser interprets as **the end of that header and the start of a new one** (or, depending on placement, as the boundary that lets a smuggled request prefix begin).
4. This gives the attacker a way to inject **arbitrary additional header lines, or an entire smuggled request prefix**, into the HTTP/1.1 stream the backend sees — using nothing but a legal (if unusual) HTTP/2 header value, with no length-mismatch trickery required at all. This is a **distinct primitive** from the H2.CL/H2.TE length-mismatch technique in Section 3 — it doesn't rely on lying about length; it relies on the front-end failing to escape/reject newline characters during protocol translation.

---

## 6. WAF / API Gateway Relevance

**Detection methods:**
- Gateways/WAFs that specifically validate header values for control characters (`\r`, `\n`, and other characters outside the allowed HTTP/1.1 header-value character set) **before** performing HTTP/2-to-HTTP/1.1 downgrade rewriting can catch the CRLF-injection variant (Section 5) directly, since the malicious payload is present as a literal newline in a header value at the point the gateway itself controls.
- For H2.CL/H2.TE length-mismatch (Section 3), detection generally requires the gateway to **cross-validate** the frame-level byte count it actually received against the `content-length`/`transfer-encoding` header values it's about to forward, and reject (rather than silently forward) any request where these disagree — this is the same principle as HTTP/1.1 smuggling mitigation (reject ambiguous requests outright) applied at the downgrade boundary specifically.
- Some modern gateways mitigate this entire class by **not downgrading at all** — maintaining native HTTP/2 (or HTTP/1.1-only) all the way to the backend, eliminating the translation boundary where the ambiguity is introduced. This is PortSwigger's own stated recommendation: use HTTP/2 end-to-end and disable downgrading wherever backend infrastructure allows it.

**Realistic bypass considerations:**
- If a gateway validates header values for `\r\n` but only checks a subset of headers (e.g., only checks headers it itself sets or commonly-abused headers like `Host`, missing custom/application headers), an attacker may find an unvalidated header field to carry the injected newline.
- If length cross-validation exists but only compares `content-length` header vs. frame length, and doesn't separately validate `transfer-encoding`-related rewriting during downgrade, the H2.TE variant may remain viable even where H2.CL is blocked — always test both variants independently, never assume a fix for one covers the other.
- **This is one of the sub-techniques where WAF/gateway-level defense is highly relevant and should always get a dedicated bypass-consideration writeup in a report** — unlike some purely application-logic vulnerabilities, this is fundamentally an infrastructure/protocol-translation defense question, so findings should explicitly state which specific downgrade-rewrite behavior was tested and which was blocked vs. exploitable.

---

## 7. What's Next

File 4 goes deeper into HPACK-specific header manipulation (dynamic table poisoning, CONTINUATION-based abuse) as a complementary primitive to the CRLF-injection mechanism in Section 5. File 5 covers h2csmuggler, which automates detection and exploitation of a related-but-distinct primitive: h2c (cleartext HTTP/2) upgrade smuggling past misconfigured `proxy_pass` rules, which is a different vulnerability class from the TLS-based H2.CL/H2.TE desync covered here but shares the "protocol translation boundary creates a trust gap" root cause.
