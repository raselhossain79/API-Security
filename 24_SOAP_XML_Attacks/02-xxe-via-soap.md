# XXE via SOAP

## Scope of This File

This file does **not** re-teach XXE fundamentals — DTD structure, entity types (general/parameter), out-of-band exfiltration via XXE, blind XXE detection theory, or XXE-to-RCE chains are all covered in depth in your existing **XXE web application security note series**. Cross-reference that series for the underlying mechanism.

This file covers only what's SOAP-specific: **why SOAP services are a historically high-yield XXE target, how to identify the injectable point inside a SOAP envelope, and how to structure the XXE payload so it survives SOAP's envelope syntax and the server's XML parser without breaking the message.**

---

## 1. Why SOAP Is a High-Yield XXE Target

Every SOAP request **is** an XML document, parsed by an XML parser before any business logic runs. This is different from REST/JSON APIs, where XML parsing (if it happens at all) is usually confined to specific endpoints that explicitly accept XML/file uploads. With SOAP:

- **100% of traffic to a SOAP endpoint is XML** — there is no "does this endpoint even parse XML" question the way there is with REST. The question is only whether the parser is configured to resolve external entities.
- Legacy SOAP toolkits (older Apache Axis 1.x, early Axis2 versions, PHP's `SoapServer` with certain libxml configurations, older JAX-WS/JAXB stacks, .NET Framework's `XmlDocument`/`XmlTextReader` prior to secure defaults being introduced) historically shipped with **DTD processing and external entity resolution enabled by default**. Many of these deployments are still running in production enterprise environments precisely because SOAP services tend to be legacy and rarely re-audited once "working."
- SOAP's own spec doesn't prohibit DTDs in the message — a compliant SOAP message is still just XML, and the SOAP envelope wrapping doesn't inherently sanitize or restrict the document type declaration.

This combination — guaranteed XML parsing + historically permissive legacy parser defaults — is why XXE testing should be treated as a **default checklist item on every SOAP engagement**, not a conditional test.

---

## 2. Identifying the Injectable Point

Unlike REST JSON bodies where you inject into a specific field value, SOAP XXE testing happens at the **document structure level**, above the individual parameter. There are two distinct injection strategies depending on what the server's parser allows.

### 2.1 Full-envelope DOCTYPE injection (most common, try first)

Because the entire SOAP request is one XML document, you can prepend a `DOCTYPE` declaration before the `<soapenv:Envelope>` root element itself, exactly as you would with any standalone XML document:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soapenv:Envelope [
   <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:web="http://example.com/webservice">
   <soapenv:Header/>
   <soapenv:Body>
      <web:GetUserDetails>
         <web:UserID>&xxe;</web:UserID>
      </web:GetUserDetails>
   </soapenv:Body>
</soapenv:Envelope>
```

Piece by piece:

- **`<!DOCTYPE soapenv:Envelope [ ... ]>`** — Declares a Document Type Definition scoped to the root element name. The name here must match your document's actual root element (`soapenv:Envelope`), or some strict parsers will reject the document as malformed before even reaching the entity declaration. This is a common reason a first XXE attempt against a SOAP endpoint fails silently — mismatched DOCTYPE root name, not a hardened parser.
- **`<!ENTITY xxe SYSTEM "file:///etc/passwd">`** — Standard external general entity declaration (identical mechanism to any other XXE — see your XXE web app notes for the full entity-type breakdown: `SYSTEM` vs `PUBLIC`, general vs parameter entities, and out-of-band variants for blind cases).
- **`&xxe;`** — The entity reference, placed as the **text content of a parameter element inside the Body**. When the parser resolves this document, it substitutes the file contents in place of `&xxe;` before the value ever reaches the SOAP deserialization/business logic layer — meaning if reflected back in the response or a fault message, you get direct file content exposure.

The critical SOAP-specific detail: **the entity reference must be placed inside a Body element that is actually reflected back to you, logged verbatim, or used in a way that surfaces its resolved value** — otherwise you're dealing with blind XXE and need the out-of-band techniques from your XXE web app series (external DTD via attacker-controlled server, OOB data exfiltration via parameter entities).

### 2.2 Which Body parameters to target

Any leaf element inside `<soapenv:Body>` is a candidate, but prioritize by likely reflection/logging:

- Parameters that appear in **success response echoes** (e.g., a "confirmation" field that repeats back what you submitted) — highest chance of direct in-band XXE confirmation.
- Parameters likely to hit **verbose fault/error paths** when malformed — SOAP faults frequently leak parsed values in `<detail>` blocks (see file 1, section 2), giving you an error-based XXE oracle even without direct reflection.
- **Free-text/string-typed fields** per the WSDL `<types>` schema (e.g., `xsd:string` fields like comments, descriptions, search queries) — these are less likely to hit strict type/format validation before the XML parser processes the entity, compared to strictly-typed fields like `xsd:int` or `xsd:dateTime` which some frameworks validate at the schema layer, potentially truncating or rejecting your payload before parsing.

### 2.3 Attribute-based injection (secondary technique)

Some SOAP toolkits/frameworks expose SOAP-encoding style attributes on Body elements (`xsi:type`, encoding arrays). If you see attribute-heavy parameter markup in captured traffic, external entities can also be referenced within attribute values — the mechanism is identical, just placed in an attribute rather than element text. Less common in practice; try element-text injection first.

---

## 3. Handling SOAP 1.1 vs SOAP 1.2 Content-Type Requirements

From file 1: SOAP 1.1 uses `Content-Type: text/xml`, SOAP 1.2 uses `application/soap+xml`. This matters for XXE testing specifically because:

- Sending an XXE payload with the wrong Content-Type for the SOAP version in use can cause the request to be rejected by strict routing/validation **before** reaching the XML parser stage — producing a false negative that looks like "XXE is patched" when actually your envelope version and header don't match.
- Always confirm SOAP version from the WSDL namespace (`http://schemas.xmlsoap.org/soap/envelope/` = 1.1, `http://www.w3.org/2003/05/soap-envelope` = 1.2) before crafting your DOCTYPE-injected request, and set the matching Content-Type header manually in Burp Repeater/SoapUI.

---

## 4. Confirming XXE — Practical Workflow

1. **Baseline request first.** Send a clean, valid SOAP request and confirm you get a normal 200 response with expected Body content. This establishes your "known good" comparison point.
2. **Local file read test.** Inject `SYSTEM "file:///etc/passwd"` (Linux) or `file:///c:/windows/win.ini` (Windows) targeting a reflected/logged parameter. Compare response — direct file content in the Body or Fault `detail` confirms in-band XXE.
3. **If no direct reflection: error-based confirmation.** Point the entity at a file guaranteed to cause a parse or type error when substituted into a strictly-typed field (e.g., resolve `/etc/passwd` content into an `xsd:int` parameter) — many toolkits leak the resolved-but-invalid value in the resulting SOAP Fault's `faultstring` or `detail`, even when the happy-path response wouldn't reflect it.
4. **If still nothing: blind/OOB.** Stand up a listener (Burp Collaborator or your own server) and use an external DTD reference to trigger outbound DNS/HTTP interaction — full technique in your XXE web app notes, section on out-of-band exfiltration. This confirms the parser is vulnerable even with zero in-band feedback, and with parameter-entity OOB techniques you can still exfiltrate file contents blind.
5. **SSRF pivot check.** Try `SYSTEM "http://internal-host:port/"` — many SOAP backends sit deep inside internal networks (see file 1's ESB/gateway note), making XXE-driven SSRF against internal services one of the higher-impact outcomes on enterprise engagements, sometimes more valuable than the file-read primitive itself.

---

## 5. WAF / API Gateway Relevance

**Highly relevant** — XXE is one of the attack classes WAFs and API/XML gateways are specifically designed to catch, because the signature is structurally distinctive (a `DOCTYPE` declaration inside an XML/SOAP payload is rarely legitimate in normal application traffic).

**Common detection methods:**
- Static pattern matching on `<!DOCTYPE`, `<!ENTITY`, `SYSTEM`, `PUBLIC` keywords anywhere in the request body.
- XML schema validation at the gateway layer — many enterprise API Gateways (e.g., dedicated XML/SOAP gateways like legacy IBM DataPower, Layer7/CA API Gateway, Oracle API Gateway) perform full XML schema validation against the WSDL-derived schema *before* forwarding to the backend, which incidentally blocks malformed DOCTYPE-injected documents as a side effect of strict schema conformance rather than dedicated XXE detection.
- Dedicated "XML threat protection" / "XML firewall" modules — a distinct product category specifically built for SOAP/XML gateways, checking for entity expansion bomb patterns (billion laughs), external entity declarations, and oversized/deeply nested XML as a bundled ruleset.
- Content-Type/size-based heuristics: unusually large request bodies or unexpected nesting depth can trigger generic anti-DoS rules that incidentally catch some XXE/entity-expansion attempts.

**Realistic bypass considerations:**
- **Parameter entity obfuscation** — using `%` parameter entities to construct the `SYSTEM`/`ENTITY`/`DOCTYPE` keywords indirectly can evade naive string-matching WAF rules that only look for literal keyword strings, though this is decreasingly effective against modern XML-aware gateways that actually parse the DTD structure rather than regex-matching it.
- **Encoding tricks** — UTF-16/UTF-7 encoding of the payload, or unusual but valid XML character references, have historically bypassed WAFs that decode/inspect only UTF-8 content; this is largely patched in current-generation gateways but still worth testing against older/unpatched deployments common in legacy SOAP environments specifically.
- **Case variation and whitespace manipulation** in DOCTYPE/ENTITY keywords against WAFs using case-sensitive or whitespace-sensitive regex.
- **External DTD hosted on an allow-listed domain** — if the gateway blocks internal-looking SYSTEM identifiers but doesn't inspect the *content* of an externally-fetched DTD, hosting your entity declarations on an external server and referencing only the DTD URL in the payload can slip past keyword-based body inspection, since the malicious `ENTITY` declaration itself never appears in the intercepted request.
- Realistically: dedicated XML/SOAP security gateways (as opposed to generic web-app WAFs bolted onto a REST API) tend to be **meaningfully harder to bypass for XXE specifically**, because full DTD/schema parsing is their core function rather than an add-on regex layer. Don't assume the same bypass techniques that work against a generic WAF on a REST endpoint will transfer directly to a dedicated SOAP/XML gateway — always test empirically per target.

---

## 6. PortSwigger Lab Mapping

PortSwigger's XXE labs are written against generic XML/REST-style endpoints, not SOAP specifically — there is currently no dedicated SOAP-XXE lab on the platform. Honest gap: **use the standard XXE lab track to build the entity-injection mechanism, then apply it manually to a SOAP envelope structure as covered in this file.** The underlying XXE technique transfers directly; only the envelope wrapping differs.

Apprentice → Practitioner → Expert progression (from the XML External Entity (XXE) Injection topic):
1. **Apprentice** — *Exploiting XXE using external entities to retrieve files* — builds the core `SYSTEM` entity file-read mechanism you'll reuse inside the SOAP Body.
2. **Apprentice** — *Exploiting XXE to perform SSRF attacks* — directly maps to the SSRF pivot technique in section 4, step 5 above, highly relevant given SOAP backends' typical internal network placement.
3. **Practitioner** — *Blind XXE with out-of-band interaction* — maps to section 4, step 4 (Collaborator-based confirmation for non-reflective SOAP endpoints).
4. **Practitioner** — *Blind XXE with out-of-band interaction via XML parameter entities* — maps to the parameter-entity obfuscation bypass in section 5.
5. **Practitioner** — *Exploiting blind XXE to exfiltrate data using a malicious external DTD* — core technique for extracting file contents when the SOAP response gives zero direct reflection.
6. **Expert** — *Exploiting XInclude to retrieve files* — relevant when your injection point is a Body parameter value only (not the full document), and you cannot control the DOCTYPE declaration at the envelope root — a scenario more common in SOAP than REST, since some gateways strip/reject a client-supplied DOCTYPE outright while still parsing XInclude namespaces within the Body if the backend parser supports it.
7. **Expert** — *Exploiting XXE via image file upload* — lower direct relevance to SOAP unless the service accepts base64-encoded document/image attachments (MTOM/SwA — SOAP with Attachments) that are themselves XML-based formats (e.g., SVG); worth testing on services that support file attachments over SOAP.

**Supplementary practice:** SoapUI ships bundled sample/practice SOAP services useful for building comfort with envelope syntax before attempting XXE injection live — full breakdown in file 5. No dedicated TryHackMe room targets SOAP-XXE specifically as of this writing; general XXE rooms (e.g., rooms covering OWASP Top 10 XXE) build transferable mechanism knowledge but use REST/XML endpoints, not SOAP envelopes.

---

## 7. Cross-References

- Full XXE mechanism, entity types, OOB exfiltration technique, and XXE-to-RCE chains: your existing **XXE web app security note series**.
- SOAP envelope structure and namespace requirements: file 1.
- WSDL-derived schema validation as a defensive control: file 4.

## Real-World Notes

- On real enterprise engagements, the single highest-value XXE outcome via SOAP has consistently been **SSRF against internal services** (billing systems, internal auth servers, cloud metadata endpoints when the SOAP service runs on cloud infra) rather than direct file read — because SOAP backends are so often deployed deep inside internal network segments with minimal egress filtering, on the assumption that "only internal systems talk to this."
- Don't skip testing XXE against WSDL retrieval itself in rare cases where the WSDL is dynamically generated from a template that incorporates request parameters — this is uncommon but has been observed in custom-built SOAP gateways.
- Attachments (MTOM/SwA) are an undertested XXE surface — testers fixate on the Body text parameters and skip file-attachment operations entirely, which is often where legacy validation is weakest.
