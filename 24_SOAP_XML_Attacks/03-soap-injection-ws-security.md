# SOAP Injection and WS-Security Attacks

## Part A: SOAP Injection

### 1. What SOAP Injection Actually Is

SOAP injection is the SOAP-specific analogue of XML injection: instead of injecting a malicious *value* into a parameter, you inject **structural XML tags** into a parameter's text content, with the goal of altering the SOAP message's actual document tree as interpreted by the backend parser — adding new sibling elements, closing tags early to escape the intended element context, or manipulating which values the backend business logic actually reads.

This differs from XXE (file 2) in intent: XXE abuses DTD/entity processing to read files or trigger SSRF. SOAP injection abuses **insufficient output encoding of user input placed into XML element text**, letting you break out of the intended element and inject new elements the application never intended to receive.

It also differs from generic XSS/HTML injection in mechanism only — the underlying root cause (unescaped user input placed into a markup document) is the same category of bug, just landing in an XML document consumed by a backend SOAP deserializer instead of a browser DOM.

### 2. Root Cause

A SOAP request field is built server-side (or client-side, if you're manipulating a client that talks to the SOAP backend) by string-concatenating user input directly into the envelope, without XML-escaping special characters (`<`, `>`, `&`, `"`, `'`). If your input contains raw `<` and `>` characters, and the resulting string is parsed rather than treated as an inert text node, the parser interprets them as real tag boundaries.

### 3. Worked Example

**Legitimate request** — a password change operation taking a username and new password:

```xml
<soapenv:Body>
   <web:ChangePassword>
      <web:Username>john.doe</web:Username>
      <web:NewPassword>NewPass123</web:NewPassword>
   </web:ChangePassword>
</soapenv:Body>
```

Suppose the WSDL/schema also defines an (undocumented in the client UI, but still schema-valid) `<web:IsAdmin>` boolean field on the same operation — common in legacy services where an admin-only code path reuses the same operation with an extra flag, gated only by client-side UI restriction rather than server-side authorization.

**Injected request** — attacker submits a crafted `Username` value containing raw XML:

Submitted value for the Username field (as typed into a vulnerable client form, or directly if you're crafting the raw SOAP request yourself in Burp/SoapUI):

```
john.doe</web:Username><web:IsAdmin>true</web:IsAdmin><web:Username>john.doe
```

If the server builds the envelope by naive string concatenation, the resulting document becomes:

```xml
<soapenv:Body>
   <web:ChangePassword>
      <web:Username>john.doe</web:Username><web:IsAdmin>true</web:IsAdmin><web:Username>john.doe</web:Username>
      <web:NewPassword>NewPass123</web:NewPassword>
   </web:ChangePassword>
</soapenv:Body>
```

Piece by piece — what the injected string achieves:

- **`john.doe`** — Harmless prefix, keeps the original element's opening content intact so the request doesn't immediately look malformed to casual inspection.
- **`</web:Username>`** — Deliberately closes the `Username` element **early**. This is the escape step: everything that follows is now interpreted as a **sibling** of `Username`, not its content, because the parser has been told the element ended here.
- **`<web:IsAdmin>true</web:IsAdmin>`** — A complete, new, well-formed element injected at the sibling level inside `<web:ChangePassword>`. If the backend's deserializer maps this operation's Body children directly onto an object (common with frameworks like JAX-WS/Axis using automatic data binding), this line silently populates an `IsAdmin` field the client-side form never exposed, potentially escalating privilege on an operation that otherwise has no admin-gating logic beyond "the UI doesn't show this field to non-admins."
- **`<web:Username>john.doe`** — Re-opens a fresh `Username` element to "absorb" the rest of your originally intended value plus whatever the legitimate application code appends afterward, keeping the overall document well-formed so the parser doesn't reject it outright on a structural error. This is the same closing/reopening trick used in classic HTML/attribute injection, just applied to XML element boundaries instead of HTML tag/attribute boundaries.
- The final `</web:Username>` that the *server's own template* was going to append closes your re-opened tag, completing a well-formed document overall — from the parser's perspective, nothing is malformed; it just has an extra sibling element that wasn't supposed to be there.

### 4. Where to Look for Injectable Fields

- Any Body parameter reflected verbatim into a **new outgoing SOAP request** the backend makes to a downstream service (SOAP-to-SOAP proxying/orchestration is common in ESB-fronted architectures) — this is actually a higher-value target than the initial request, because the second hop's server-side code is often less defensively written than the externally-facing gateway.
- Free-text `xsd:string` fields, same reasoning as XXE targeting in file 2 — less likely to hit strict type validation before your raw angle brackets reach string-concatenation logic.
- Fields whose corresponding WSDL `<types>` schema shows **sibling elements you as an external client aren't supposed to control** (admin flags, internal routing fields, role/permission fields) — always read the full `<types>` block for every operation you test, not just the fields the client application's UI actually populates. This is the single most important reconnaissance step for this attack class.

### 5. Detecting It Without Guessing the Full Schema

If you don't have WSDL access or the schema doesn't obviously expose a privilege-relevant sibling field, use these confirmation steps:

1. Submit a value containing a single unescaped `<` character. If the server returns a raw XML parse error (malformed document) rather than an application-level validation error, that confirms your input reaches the XML document *before* parsing completes — i.e., it's being concatenated into the raw document string, not properly escaped/bound as a text value. This is your core "is this exploitable" signal.
2. Submit a closing tag matching the current field name plus a **duplicate** of the same element (`</web:Username><web:Username>test</web:Username><web:Username>`) — a purely structural test, safe to run without knowing any other schema fields, just to confirm structural breakout works at all before attempting to add semantically meaningful siblings.
3. Once structural breakout is confirmed, pull the full WSDL `<types>` schema (file 4) to identify real target fields worth injecting, rather than blind-guessing field names.

---

## Part B: WS-Security

### 6. What WS-Security Provides

WS-Security is a SOAP extension (standardized as OASIS WS-Security) that adds security metadata to the `<soapenv:Header>` block, independent of transport-layer security (TLS). It exists because SOAP messages historically travel through multiple intermediaries (ESBs, gateways, orchestration layers) where TLS terminates at each hop — meaning transport security alone doesn't guarantee end-to-end message integrity or confidentiality across the whole chain. WS-Security provides three things, each independently optional and independently testable:

- **Authentication** — via `<wsse:UsernameToken>`, carrying credentials (plaintext, digest, or with nonce+timestamp) inside the Header rather than relying solely on HTTP-level auth (Basic Auth, cookies, bearer tokens).
- **Message signing (integrity)** — via `<ds:Signature>` (XML Digital Signature), proving the message wasn't tampered with in transit and confirming sender identity via public-key cryptography.
- **Message encryption (confidentiality)** — via `<xenc:EncryptedData>` (XML Encryption), encrypting all or part of the Body so intermediaries that shouldn't see the plaintext payload can't, even though they can still route the message.

Example Header with a UsernameToken and a Timestamp:

```xml
<soapenv:Header>
   <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wsu:Timestamp wsu:Id="TS-1">
         <wsu:Created>2026-07-10T09:00:00Z</wsu:Created>
         <wsu:Expires>2026-07-10T09:05:00Z</wsu:Expires>
      </wsu:Timestamp>
      <wsse:UsernameToken wsu:Id="UT-1">
         <wsse:Username>john.doe</wsse:Username>
         <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-username-token-profile-1.0#PasswordDigest">
            Xk9dP3mQz7vL2wR8sT1yF0hJ4kN6bC5A==
         </wsse:Password>
         <wsse:Nonce EncodingType="...#Base64Binary">MTIzNDU2Nzg5MA==</wsse:Nonce>
         <wsu:Created>2026-07-10T09:00:00Z</wsu:Created>
      </wsse:UsernameToken>
   </wsse:Security>
</soapenv:Header>
```

Piece by piece:

- **`<wsu:Timestamp>`** with `Created`/`Expires` — Defines the validity window for the entire security block. Its core purpose is **replay protection**: a message received after `Expires` should be rejected outright by a correctly implemented server, regardless of whether the credentials/signature are otherwise valid.
- **`<wsse:UsernameToken>`** — Carries the credential. `PasswordDigest` type means the password isn't sent in plaintext; instead it's `Base64(SHA1(Nonce + Created + Password))` — a hashed combination the server can verify against its own stored password (or its hash) plus the supplied nonce and timestamp, without the plaintext password crossing the wire. Compare against `PasswordText` type, which does send plaintext, and which you should always flag as a finding if TLS isn't independently enforced, since it defeats the entire purpose of using a digest scheme elsewhere.
- **`<wsse:Nonce>`** — A single-use random value, meant to be combined with the timestamp so that even if an attacker captures a valid digest token, they can't simply replay the exact same request after its nonce/timestamp validity has been correctly tracked and invalidated server-side.

### 7. Testing for Missing WS-Security

Real-world reality check: **plenty of production SOAP services either never implemented WS-Security at all, or only partially implemented it** (e.g., signature present but never actually verified server-side, timestamp present but expiry never checked). Test methodology:

1. **Baseline capture.** Intercept a legitimate authenticated SOAP request and inspect the Header. Confirm what's actually present (UsernameToken? Signature? Encryption? Timestamp?) versus what the service's documentation/WSDL policy annotations claim should be present.
2. **Strip and resend.** Remove the entire `<wsse:Security>` block (or individual sub-elements — Timestamp only, UsernameToken only) and resend. If the operation still succeeds, server-side enforcement of that WS-Security element is missing or misconfigured — the Header content is present in legitimate traffic purely as client-side convention, not as an enforced server-side control. This is one of the most common and highest-impact findings on real SOAP engagements, because developers frequently assume "the client always sends it" is equivalent to "the server requires it."
3. **Check WSDL policy assertions.** Some WSDLs embed a `<wsp:Policy>` (WS-Policy) block declaring which WS-Security elements are mandatory for a binding. If the WSDL declares a UsernameToken as required but step 2 shows the server accepts requests without one, that's a direct contract-vs-enforcement mismatch worth documenting explicitly in your report, since it demonstrates the gap between design intent and actual implementation.
4. **Tamper with signed content, if signing is present.** If `<ds:Signature>` exists, modify a Body parameter value post-signing (i.e., change the business data but leave the Header's Signature block untouched) and resend. If the operation still succeeds with the modified data, the server isn't actually validating the signature against the current Body content — it may be checking only that *a* signature element exists structurally, not that it cryptographically matches the message.

### 8. Replay Attacks on Timestamped Messages

Even when WS-Security is present and enforced, replay protection depends entirely on correct server-side tracking of nonce+timestamp combinations. Test methodology:

1. Capture one fully valid, successfully-processed authenticated SOAP request (with its `Timestamp` and `Nonce` intact).
2. Resend the **exact same request, unmodified**, before the `Expires` timestamp elapses.
3. **If it succeeds a second time**, the server is validating timestamp freshness (message isn't "too old") but **not tracking nonce uniqueness** — meaning any captured valid request can be replayed indefinitely within its validity window. This is a genuine, reportable finding: an attacker who intercepts one valid request (e.g., via a compromised intermediary, logging system, or network position) can replay a state-changing operation (funds transfer, password reset, order submission) repeatedly.
4. Also test resending **after** `Expires` has passed — a correctly implemented server should reject this outright with a `MessageExpired`-type fault. If it's still accepted post-expiry, timestamp enforcement itself is broken, which is a more severe version of the same underlying gap.
5. For high-value operations (funds movement, account modification), always test replay specifically — it's frequently overlooked because a tester confirms "auth works" via the happy path and doesn't go back to test whether the *same* authenticated message can be reused.

---

## 9. WAF / API Gateway Relevance

**SOAP injection**: Moderately relevant. Generic WAFs rarely have SOAP-injection-specific signatures (unlike XXE, which has recognizable DOCTYPE/ENTITY keyword patterns) because structural tag injection looks, at the raw HTTP body level, like ordinary well-formed XML — there's no obviously malicious keyword to pattern-match against, since the injected content (`<web:IsAdmin>true</web:IsAdmin>`) is syntactically identical to any other legitimate SOAP element. The realistic defense against this class sits at the **application/schema validation layer**, not the WAF layer: strict XML Schema (XSD) validation against the WSDL-defined type at the gateway will reject a Body containing unexpected sibling elements not defined in the operation's schema, functioning as an incidental but effective control. Test whether that schema validation is actually strict (rejects unknown elements) or permissive (`xsd:any` wildcards, lax processing) — permissive schemas are common in services designed for extensibility and directly enable this attack class to succeed even behind an otherwise well-configured gateway.

**WS-Security bypass/replay**: Not meaningfully a WAF/Gateway pattern-matching problem — this is a server-side (or gateway-side, if the gateway itself is meant to be the WS-Security enforcement point in the architecture) **logic and configuration correctness issue**, not something a signature-based defense catches or misses. A WAF has no way to know whether nonce-tracking is implemented correctly on the backend. Where an API Gateway *is* explicitly positioned as the WS-Security policy enforcement point (common in ESB architectures — the gateway validates/strips WS-Security before forwarding a "trusted" plain request internally), that gateway's own configuration is exactly what you're testing in sections 7 and 8 — there's no separate "bypass the gateway to get around it" step, because the gateway *is* the object under test at that point, not an obstacle in front of it.

---

## 10. PortSwigger Lab Mapping

No dedicated SOAP injection or WS-Security labs exist on PortSwigger Web Security Academy — this is a genuine, honest gap; these attack classes are largely absent from the platform's current lab catalog since it's REST/web-app oriented.

Closest transferable concept, in progression order:
1. **Apprentice** — *XXE injection* topic labs (structural XML understanding transfers directly to recognizing well-formed-document breakout, the same core skill used in section 3's worked example).
2. General **authentication** topic labs (Apprentice → Practitioner, e.g., *Password reset broken logic*, *2FA broken logic*) — build the mental model for "is this security control actually enforced server-side, or just assumed" that directly transfers to WS-Security enforcement testing in section 7.

**Supplementary practice:** SoapUI's bundled sample SOAP services (file 5) support manually adding/stripping WS-Security headers via its built-in WS-Security configuration UI, making it the most practical hands-on environment for sections 7–8's testing workflow. TryHackMe does not currently offer a dedicated WS-Security or SOAP-injection room; general XML/SOAP-adjacent rooms build partial transferable skills only.

---

## 11. Cross-References

- SOAP envelope and Body structure: file 1.
- WSDL `<types>` schema extraction for identifying undocumented sibling fields: file 4.
- SoapUI's WS-Security configuration panel walkthrough: file 5.

## Real-World Notes

- The single most reportable finding pattern in this file, seen repeatedly on real engagements: WS-Security Header present and cosmetically correct in every legitimate request, but **completely unenforced server-side** — confirmed by simply stripping the entire block and resending. Always test this before anything more elaborate; it's a five-minute check with consistently high impact.
- SOAP injection via privilege-relevant sibling fields is highest-yield on services where the same operation is reused across UI-differentiated access levels (admin panel and user panel calling the same underlying `ChangePassword`/`UpdateProfile`/`SubmitOrder` operation with extra fields gated only client-side) — a very common legacy architecture pattern, since adding a second operation was historically more development effort than adding a field and hiding it in one UI.
- Nonce-replay gaps are frequently missed by testers who stop at "authentication works" — always circle back and explicitly test message replay on any WS-Security-protected state-changing operation.
