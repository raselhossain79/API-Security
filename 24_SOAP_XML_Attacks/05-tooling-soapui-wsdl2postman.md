# Tooling: SoapUI and wsdl2postman

## Overview

SOAP testing is far more workable with dedicated tooling than by hand-crafting every envelope in Burp Repeater. This file breaks down the two tools you'll rely on most: **SoapUI** (the standard dedicated SOAP-testing application, purpose-built for this protocol) and **wsdl2postman** (a conversion utility for teams whose workflow is centered on Postman rather than a dedicated SOAP client). Burp Suite remains your interception/proxy layer for both — these tools handle SOAP-specific request construction, and you still proxy their traffic through Burp for interception, modification, and injection testing.

---

## Part A: SoapUI

### 1. What It Is and Why It's the Standard

SoapUI (open-source edition is sufficient for testing purposes — the paid ReadyAPI tier adds automation/CI features not essential for manual pentesting) is purpose-built for SOAP/WSDL workflows: it natively understands WSDL structure, auto-generates request templates per operation, provides a dedicated WS-Security configuration UI, and handles namespace/envelope construction automatically so you don't hand-write boilerplate for every test. This is the direct SOAP equivalent of what Burp/Postman are for REST.

### 2. Installation

```bash
# Download from the official SmartBear site (soapui.org) — always verify checksum against the published SHA256
wget https://dl.eviware.com/soapuios/5.x.x/SoapUI-5.x.x-linux-bin.tar.gz
tar -xzf SoapUI-5.x.x-linux-bin.tar.gz
cd SoapUI-5.x.x/bin
./soapui.sh
```
- On Kali/most pentest distros, SoapUI is also available via `apt` in some repos, or as a direct `.deb`/`.rpm` from the vendor. Verify the version isn't ancient if pulling from a distro repo — SoapUI itself has had its own historical CVEs (notably around its own XML parsing), so keep your testing tool current even while you're hunting for the same class of bug in your target.

### 3. Importing a WSDL — Project Setup

1. **File → New SOAP Project.**
2. **Project Name**: descriptive, e.g., `TargetCo-UserService`.
3. **Initial WSDL**: paste the full WSDL URL (`https://target.com/services/UserService?wsdl`).
4. Leave **"Create Requests"** checked — this tells SoapUI to auto-generate a sample request for every operation it finds in the WSDL immediately on import, saving you from doing this by hand (this automates file 4, section 2's manual template-building step).
5. SoapUI parses the WSDL and builds a project tree: **Project → Binding → Operation → Request 1**, mirroring the WSDL's own `<binding>`/`<operation>` structure directly.

If the WSDL isn't reachable via a direct URL (e.g., it requires prior authentication to view, or you only have a locally-saved copy from Burp history), use **File → Import WSDL** with a local file path instead — same resulting project structure.

### 4. Auto-Generated Request Templates

For every operation, SoapUI generates a complete envelope with placeholder values matching the schema types:

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:web="http://example.com/webservice">
   <soapenv:Header/>
   <soapenv:Body>
      <web:GetUserDetails>
         <web:UserID>?</web:UserID>
      </web:GetUserDetails>
   </soapenv:Body>
</soapenv:Envelope>
```

The `?` placeholders mark exactly where the schema expects a value for each parameter — this directly gives you the per-operation parameter map from file 4, section 2, step 3 without manually cross-referencing `<types>` yourself. Replace placeholders with real values, XXE payloads, injection payloads, etc., directly in this editor. SoapUI validates the request is well-formed XML before sending, which helps you immediately catch structural mistakes (unescaped characters breaking the document) separate from whether your actual payload logic works — a useful debugging signal when a test "fails" and you need to know whether it's a payload problem or a malformed-XML problem.

### 5. Configuring WS-Security in SoapUI

This is SoapUI's most valuable feature for file 3's testing workflow — it has a dedicated UI for constructing, modifying, and stripping WS-Security headers without hand-writing the XML.

1. Right-click the request → **Add WSS Security Configuration**, or access via the request editor's **Outgoing WSS** tab.
2. **Add a Username Token entry**: specify username, password, password type (`PasswordText` or `PasswordDigest` — directly lets you test both, per file 3 section 6's finding that `PasswordText` in production without enforced TLS is a reportable weakness), and whether to include Nonce/Created timestamp.
3. **Add a Timestamp entry**: configure the time-to-live (TTL) window — useful for testing whether the server actually enforces short-lived timestamps (file 3, section 8) by deliberately setting an already-expired or unusually long TTL and observing server behavior.
4. **Signature/Encryption configuration**: requires importing a keystore (client certificate) if the target requires signed requests — under **Outgoing WSS → Add → Signature**, reference your keystore and configure which parts of the message get signed. For testing purposes, you'll mostly use this to confirm whether the server actually validates signatures at all (file 3, section 7, step 4) by signing correctly once, then tampering with Body content afterward without re-signing.
5. To test the "strip Security header entirely" scenario (file 3, section 7, step 2), simply **remove the WSS Security Configuration entry** from the request, or toggle it off, and resend — SoapUI cleanly removes the entire block rather than requiring manual XML editing.

### 6. Routing SoapUI Through Burp

SoapUI's own request/response editor is useful for construction, but Burp remains your primary interception and manipulation surface for actual testing (Repeater for iterative payload tuning, Intruder for automated fuzzing across parameters).

1. **SoapUI → File → Preferences → Proxy Settings.**
2. Set **Host**: `127.0.0.1`, **Port**: `8080` (or whatever your Burp proxy listener is configured to).
3. Enable **"Use system proxy"** off, and manually set SoapUI's HTTP/HTTPS proxy fields to match.
4. If the target uses HTTPS, import Burp's CA certificate into SoapUI's trust store (or Java's default truststore, since SoapUI runs on the JVM) to avoid TLS validation errors — same underlying requirement as configuring any HTTPS client to trust Burp's intercepting certificate.
5. Send a request from SoapUI; confirm it appears in Burp's **Proxy → HTTP history**. From there, send to Repeater for manual payload iteration (XXE injection, SOAP tag injection, SQLi/CMDi payloads from files 2–4) exactly as you would with any other intercepted request — SoapUI's role at this point is done; it got you a well-formed baseline request, and Burp handles the actual injection testing workflow.

### 7. Bundled Sample/Practice Services

SoapUI ships with (or links to) publicly available sample SOAP services useful for building comfort with the tool and envelope syntax before testing live targets — referenced as supplementary practice throughout files 2–4. Common examples include public demo WSDLs for weather/currency-conversion services and SmartBear's own bundled tutorial project. These are **not** intentionally vulnerable services — treat them purely as syntax/tooling practice (learning to read a WSDL, build a request, configure WS-Security) rather than vulnerability-finding practice, since none of these public demo services will actually be exploitable. For genuine vulnerable-target practice, see file 4 section 12's honest note on the lack of a dedicated vulnerable-SOAP training platform.

### 8. SoapUI Real-World Notes

- SoapUI's auto-generated requests sometimes don't perfectly match what a real client actually sends (particularly around optional elements it may omit that a real client includes, or namespace prefix conventions that differ cosmetically) — always compare against a genuine captured request from Burp history when precision matters, rather than assuming the auto-generated template is bit-for-bit identical to production traffic.
- Keep a separate SoapUI project per target/engagement; the tool's project files (`.xml` project format) are easy to archive alongside your engagement notes and re-open later if retesting is required.

---

## Part B: wsdl2postman

### 9. What It Is and When to Use It Instead of SoapUI

wsdl2postman-style conversion (available as standalone open-source scripts/tools, and via some online converters — always verify you're not uploading a target's WSDL to an untrusted third-party web service, given client confidentiality; prefer a local/offline conversion tool for anything client-related) converts a WSDL's operations into a Postman collection: one Postman request per SOAP operation, with the envelope pre-built as the raw request body and Content-Type/SOAPAction headers pre-populated.

Use this path instead of SoapUI when:
- Your team's existing workflow, environment variables, and collection-sharing conventions are already built around Postman, and introducing a second dedicated tool (SoapUI) adds friction for collaborative engagements.
- You want SOAP requests to live alongside REST requests for the same target in a single unified Postman collection/workspace, useful on mixed SOAP+REST enterprise engagements (very common — legacy SOAP core services fronted by a newer REST API layer) where you're testing both surfaces and want one consistent tool.
- You need to script/automate SOAP requests using Postman's Collection Runner or Newman (CLI runner) for repeatable regression checks across a retest.

### 10. Conversion Workflow

Using a common CLI-based wsdl2postman tool (exact package name varies by implementation; conceptually all of them follow this pattern):

```bash
# Example using a Node-based wsdl-to-postman converter
npm install -g wsdl2postman
wsdl2postman -f UserService.wsdl -o UserService.postman_collection.json
```

Piece by piece:
- **`-f UserService.wsdl`** — Path to your locally-saved WSDL file (retrieved per file 1/4's enumeration workflow — always save a local copy rather than re-fetching live each time, both for offline reference and in case the endpoint becomes unreachable later in the engagement).
- **`-o UserService.postman_collection.json`** — Output path for the generated Postman collection file, in standard Postman Collection v2.1 JSON schema, importable directly into Postman via **Import → File**.

If using a GUI-based converter/import instead (some Postman workflows support pasting a WSDL URL directly into Postman's own import dialog under **Import → Link**), the resulting structure is functionally identical — one folder per `<portType>`/binding, one request per operation.

### 11. What the Generated Collection Looks Like

Each generated Postman request contains:
- **Method**: `POST` (SOAP over HTTP is always POST).
- **URL**: pulled from the WSDL's `<service><port><soap:address location="...">` — same value you'd extract manually per file 4, section 2, step 4.
- **Headers**: `Content-Type: text/xml; charset=utf-8` (or `application/soap+xml` for SOAP 1.2 — verify the converter correctly detected your WSDL's SOAP version; some older converter tools default to 1.1 regardless, which you'd then need to correct manually) and `SOAPAction: "..."` pulled from the binding, exactly as file 1 section 4 describes.
- **Body (raw)**: a pre-built envelope with placeholder values for every parameter, structurally equivalent to SoapUI's auto-generated template (section 4 above) but in Postman's raw-body editor instead of a dedicated SOAP request editor.

### 12. Testing Workflow From Here

Once imported into Postman:
1. Populate placeholder values with real/test data per operation, same as SoapUI's workflow.
2. Use Postman's **environment variables** to parameterize the target host, auth tokens, or WS-Security credentials across requests in the collection — useful for quickly repointing the entire collection between staging/production or between different test accounts with different privilege levels.
3. Route Postman through Burp identically to section 6's SoapUI proxy setup: Postman's own **Settings → Proxy** panel, pointing at `127.0.0.1:8080`, with Burp's CA cert trusted (or SSL certificate verification disabled in Postman settings for testing convenience, accepting the reduced rigor that implies).
4. From Burp Proxy history, send to Repeater for the actual injection testing (XXE, SOAP injection, SQLi/CMDi) — Postman/wsdl2postman's role, like SoapUI's, is request construction and baseline-establishment; Burp remains where the actual payload iteration happens.

### 13. Key Limitation vs SoapUI

wsdl2postman-generated collections do **not** include WS-Security configuration tooling — Postman has no native WS-Security UI equivalent to SoapUI's Outgoing WSS panel. If your target requires WS-Security headers (signed/encrypted/UsernameToken requests) to reach any testable operation at all, you'll need to either hand-construct the WS-Security Header XML manually within Postman's raw body editor (tedious, error-prone, particularly for signature/encryption blocks which require actual cryptographic computation, not just static XML), or use SoapUI for the WS-Security-dependent portions of testing and reserve Postman/wsdl2postman for WS-Security-free operations. In practice: **use SoapUI as your primary tool whenever WS-Security is in play; reach for wsdl2postman/Postman mainly for simpler UsernameToken-only or unauthenticated SOAP surfaces, or when unifying with an existing REST testing workflow matters more than WS-Security tooling convenience.**

---

## 14. Cross-References

- WSDL structure being converted: file 1, section 3.
- WS-Security header testing methodology (SoapUI's primary use case here): file 3, sections 6–8.
- Full enumeration methodology this tooling automates: file 4, Part A.

## Real-World Notes

- On engagements involving a large WSDL (100+ operations), the auto-generation step in either tool saves substantial time versus manual template-building — but always spot-check a handful of auto-generated requests against genuine captured traffic before trusting the bulk output, since converter bugs (missing namespace declarations, incorrect SOAP version detection) are common enough to silently produce non-functional requests for a subset of operations.
- Never upload a client's WSDL to a third-party online conversion service without explicit client authorization — this is an implicit data-handling/confidentiality consideration on client engagements; prefer local CLI-based conversion tools you control end to end.
- Keep both toolchains available; mixed SOAP+REST enterprise engagements are common enough that having SOAP requests both in a dedicated SoapUI project and, when convenient, unified into your main Postman workspace alongside the REST surface, is a reasonable dual-tooling approach rather than a wasted duplication of effort.
