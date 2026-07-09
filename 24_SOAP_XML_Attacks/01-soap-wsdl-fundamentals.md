# SOAP and WSDL Fundamentals for Pentesters

## Overview

SOAP (Simple Object Access Protocol) is an XML-based messaging protocol still heavily used in legacy enterprise systems: banking cores, insurance platforms, government portals, healthcare (HL7/FHIR-adjacent SOAP services), telecom billing, and B2B integration layers (EDI-over-SOAP). You will encounter it far more often on legacy/enterprise engagements than on modern greenfield apps, which is exactly why this series exists.

Unlike REST, SOAP is a **protocol**, not an architectural style. It has a fixed message envelope, a strict (if verbose) contract file (WSDL), and historically shipped with its own security framework (WS-Security) rather than relying purely on transport-layer TLS. This note covers only what you need to test SOAP effectively — not the full W3C spec.

This file assumes zero prior SOAP exposure and builds the mechanism from the ground up.

---

## 1. The SOAP Envelope — Structure and Purpose

Every SOAP message, request or response, is wrapped in a single XML document called the **Envelope**. Nothing meaningful in a SOAP conversation exists outside it.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:web="http://example.com/webservice">
   <soapenv:Header>
      <!-- optional metadata: auth tokens, WS-Security, routing info -->
   </soapenv:Header>
   <soapenv:Body>
      <web:GetUserDetails>
         <web:UserID>1001</web:UserID>
      </web:GetUserDetails>
   </soapenv:Body>
</soapenv:Envelope>
```

Piece by piece:

- **`<?xml version="1.0" encoding="UTF-8"?>`** — Standard XML declaration. Every SOAP message is a well-formed XML document first. This matters for testing: anything that accepts arbitrary XML parsing is a potential XXE surface (covered in file 2).
- **`<soapenv:Envelope>`** — The root element. The `soapenv` prefix is a namespace alias (arbitrary name, commonly `soap` or `soapenv`) bound to `xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"`. This URL is a **fixed identifier**, not a location the server fetches — it tells the XML parser which schema/ruleset to interpret the document under. SOAP 1.1 uses this namespace; SOAP 1.2 uses `http://www.w3.org/2003/05/soap-envelope`. Knowing which version you're dealing with matters because error formats, fault codes, and the Content-Type header differ between them (covered below).
- **`xmlns:web="http://example.com/webservice"`** — A second namespace, specific to this service's data types/methods. This is usually derived from the WSDL's `targetNamespace`. When you inject or replay requests, you must preserve this namespace exactly, or the server's XML parser will reject the message before your payload is even evaluated.
- **`<soapenv:Header>`** — Optional. Carries metadata that isn't part of the actual business call: authentication tokens, WS-Security blocks, session/correlation IDs, routing directives. A missing or empty Header on an endpoint that should require auth is itself a finding (see file 3).
- **`<soapenv:Body>`** — Mandatory. Contains the actual method call and its parameters. This is your primary injection surface for XXE, SOAP injection, SQLi, and command injection, because it's the part guaranteed to be parsed and typically passed into backend business logic.
- **`<web:GetUserDetails>`** — This is the **operation name**, equivalent to calling a function. It maps directly to an `<operation>` defined in the WSDL.
- **`<web:UserID>1001</web:UserID>`** — A parameter to that operation. Every child element inside the operation tag is one parameter. This is where user-controllable data lives, and therefore where most of your testing focus goes.

### Why this structure matters for testing

Because the Body is just XML, and most legacy SOAP toolkits (Apache Axis, .NET WCF/ASMX, PHP SoapServer, older Spring-WS deployments) historically shipped with permissive XML parsers, **anything landing inside a `<soapenv:Body>` element is a candidate for XML-based attacks**, not just business-logic parameter tampering. Testing SOAP means testing at two layers simultaneously: the XML document layer (can I break parsing, inject entities, inject sibling tags?) and the application layer (does the UserID parameter get used in a SQL query? a shell command?).

---

## 2. SOAP Faults (Error Handling)

When something goes wrong, SOAP returns a `<Fault>` element instead of a normal Body response:

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <soapenv:Fault>
         <faultcode>soapenv:Server</faultcode>
         <faultstring>Internal Server Error: Invalid UserID format</faultstring>
         <detail>
            <exception>java.sql.SQLException: unexpected token near '1001'</exception>
         </detail>
      </soapenv:Fault>
   </soapenv:Body>
</soapenv:Envelope>
```

- **`faultcode`** — A short machine-readable category (`VersionMismatch`, `MustUnderstand`, `Client`, `Server`).
- **`faultstring`** — Human-readable message. **This is your primary error-based feedback channel during testing** — verbose faultstrings frequently leak stack traces, SQL fragments, file paths, and internal class names, which is exactly what you want when probing for injection.
- **`<detail>`** — Optional, freeform, application-defined. This is where the richest leakage tends to live (raw exception objects, ORM query fragments). Treat any populated `<detail>` block as a high-value information disclosure during recon.

Real-world note: many enterprise SOAP services are configured to return generic faults in production but verbose faults in staging/UAT environments that are still internet-reachable because someone forgot to lock them down. Always fingerprint the environment (staging headers, non-prod namespaces in the WSDL, internal hostnames leaking in fault `detail` blocks) — verbose faults are one of the fastest tells.

---

## 3. WSDL — The Service Contract

WSDL (Web Services Description Language) is an XML document that defines **everything a client needs to know to call a SOAP service**: available operations, expected parameter types, data structures, and the endpoint URL. Functionally, it's the SOAP equivalent of an OpenAPI/Swagger spec — and just as valuable to you as an attacker, because it's often exposed and rarely access-controlled.

### 3.1 Finding the WSDL

Convention: append `?wsdl` to a suspected SOAP endpoint.

```
https://target.com/services/UserService?wsdl
https://target.com/UserService.asmx?wsdl      (ASP.NET legacy convention)
```

Other common discovery paths:
- `/services/`, `/soap/`, `/ws/`, `/webservices/` directories
- Robots.txt and sitemap.xml entries referencing `.wsdl` or `.asmx`
- JS/mobile app source referencing SOAP endpoints
- Google/Shodan dorking: `filetype:wsdl`, `inurl:wsdl`

If `?wsdl` returns the raw XML contract, WSDL enumeration (file 4) becomes trivial. If it's disabled, you still test the endpoint blind using intercepted traffic or documentation.

### 3.2 WSDL Structure, Piece by Piece

A WSDL document has five core sections. Understanding what each one is for tells you exactly what to extract during recon.

```xml
<definitions name="UserService"
             targetNamespace="http://example.com/webservice"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="http://example.com/webservice"
             xmlns="http://schemas.xmlsoap.org/wsdl/">

  <!-- 1. types -->
  <types>
    <xsd:schema targetNamespace="http://example.com/webservice">
      <xsd:element name="GetUserDetails">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element name="UserID" type="xsd:int"/>
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
    </xsd:schema>
  </types>

  <!-- 2. message -->
  <message name="GetUserDetailsRequest">
    <part name="parameters" element="tns:GetUserDetails"/>
  </message>
  <message name="GetUserDetailsResponse">
    <part name="parameters" element="tns:GetUserDetailsResponse"/>
  </message>

  <!-- 3. portType -->
  <portType name="UserServicePortType">
    <operation name="GetUserDetails">
      <input message="tns:GetUserDetailsRequest"/>
      <output message="tns:GetUserDetailsResponse"/>
    </operation>
  </portType>

  <!-- 4. binding -->
  <binding name="UserServiceBinding" type="tns:UserServicePortType">
    <soap:binding transport="http://schemas.xmlsoap.org/soap/http" style="document"/>
    <operation name="GetUserDetails">
      <soap:operation soapAction="http://example.com/webservice/GetUserDetails"/>
      <input><soap:body use="literal"/></input>
      <output><soap:body use="literal"/></output>
    </operation>
  </binding>

  <!-- 5. service -->
  <service name="UserService">
    <port name="UserServicePort" binding="tns:UserServiceBinding">
      <soap:address location="https://target.com/services/UserService"/>
    </port>
  </service>

</definitions>
```

What each section tells you as a tester:

1. **`<types>`** — Defines the actual data structures (via embedded XSD schema) used by every operation: field names, data types (`xsd:int`, `xsd:string`, `xsd:dateTime`), whether fields are optional (`minOccurs="0"`), and nested complex objects. This is where you learn the exact parameter names and types you need to fuzz — including parameters that might not be exercised by the client application's UI at all (hidden/legacy fields still accepted server-side).
2. **`<message>`** — Defines the abstract request/response envelopes: what goes in, what comes out, referencing the types above. Mostly relevant for building well-formed requests, less for vulnerability discovery directly.
3. **`<portType>`** (SOAP 1.1) / **`<interface>`** (SOAP 1.2 / WSDL 2.0) — Lists every available **operation** (method) the service exposes, mapping each to its request/response messages. **This is your attack surface enumeration list** — every operation here is a callable function, and services frequently expose administrative or debug operations (`DeleteUser`, `ResetPassword`, `ExportDatabase`, `DebugEcho`) that aren't linked anywhere in the client UI but are fully callable if you know the operation name from the WSDL.
4. **`<binding>`** — Specifies transport details: HTTP as the transport, `style` (`document` vs `rpc` — affects how the Body XML is structured), and critically, the **`soapAction`** value for each operation (see section 4 below).
5. **`<service>`** — Gives the actual **endpoint URL** (`soap:address location`) you send requests to. Note this can differ from the WSDL's own URL — e.g., WSDL served from a dev/doc server while `location` points to the real production or internal endpoint. Always sanity-check this URL; sometimes it leaks internal hostnames or ports not reachable from outside, which is itself useful recon (internal naming conventions, network topology hints).

### 3.3 style="document" vs style="rpc"

Two ways the Body payload gets structured, defined in the `<binding>`:

- **`rpc` style**: Body wraps parameters in an element named after the operation, each parameter as a direct child — closer to a literal function call representation.
- **`document` style** (more common today): Body contains a single element (often matching a `<types>` schema element) representing the whole message as a document, not explicitly tied to method-call semantics.

For testing purposes, the practical difference is just where in the XML tree your injection point sits — `document` style often has one more level of nesting. Always build your test requests by mirroring the WSDL's actual message structure rather than guessing, or the server's schema validation will reject the request before it reaches business logic.

---

## 4. The SOAPAction HTTP Header

SOAP 1.1 requests over HTTP require a `SOAPAction` header identifying which operation is being invoked — historically used by some servers for request routing *before* parsing the Body XML.

```http
POST /services/UserService HTTP/1.1
Host: target.com
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://example.com/webservice/GetUserDetails"
Content-Length: 412

<soapenv:Envelope ...>...</soapenv:Envelope>
```

Testing notes:

- The value comes directly from `soap:operation soapAction="..."` in the WSDL binding section — copy it exactly, including whether the WSDL wraps it in quotes.
- Some server implementations route purely on the SOAPAction header and ignore the actual operation name in the Body, or vice versa. **Test both**: send a mismatched SOAPAction header against a different operation's Body to see which one the server actually trusts. Inconsistent routing logic between the two has historically enabled access-control bypasses (calling an operation your session shouldn't reach by manipulating which "channel" the server uses to decide the method).
- **SOAP 1.2 does not use the SOAPAction header** at all — the operation is instead identified via an `action` parameter on the `Content-Type` header: `Content-Type: application/soap+xml; action="http://example.com/GetUserDetails"`. If your SOAPAction header injection attempts silently do nothing, check whether you're actually talking to a SOAP 1.2 endpoint (Content-Type will read `application/soap+xml` rather than `text/xml`).
- Content-Type itself is a fingerprinting signal: `text/xml` strongly suggests SOAP 1.1, `application/soap+xml` indicates SOAP 1.2. Get this wrong in your request headers and many strict servers will reject the call outright, which can look like a false negative during testing if you don't realize why.

---

## 5. Common SOAP Endpoint Conventions

Fingerprints to look for during recon:

| Pattern | Stack indicator |
|---|---|
| `*.asmx`, `*.asmx?wsdl` | ASP.NET Web Services (legacy .NET Framework) |
| `*.svc`, `*.svc?wsdl` | WCF (Windows Communication Foundation) |
| `/axis2/services/*` | Apache Axis2 (Java) |
| `/ws/*`, `/services/*` | Generic Java (Spring-WS, CXF), often behind an ESB |
| `?wsdl`, `?WSDL` (case varies) | Universal query-string convention across stacks |

Stack fingerprinting matters here more than in REST testing, because SOAP toolkit choice directly predicts which historical XXE/deserialization CVEs are relevant (e.g., older Axis/Axis2 versions, legacy .NET `XmlDocument` default entity resolution behavior — both covered in file 2).

---

## 6. Cross-References

- XXE mechanics and full payload theory: see your existing **XXE web app security note series** — this series' file 2 covers only SOAP-specific delivery, not XXE fundamentals.
- WSDL enumeration workflow and tooling: file 4 and file 5 of this series.
- WS-Security header testing: file 3.

## Real-World Notes

- Expect to find WSDL files still exposed on production long after the client-side application was migrated to REST — SOAP backends frequently outlive their original consumers and get left reachable "because nothing else uses it anymore," which is exactly the mindset that makes them worth testing.
- Namespace mismatches are the #1 reason a manually-crafted SOAP request gets silently rejected during testing. If you get an immediate parser-level fault with no business logic engagement, check your namespaces against the WSDL before assuming the endpoint is hardened.
- Many enterprise SOAP deployments sit behind an ESB (Enterprise Service Bus) or API Gateway that terminates and re-issues SOAP calls to internal services — meaning the WSDL you're testing against externally may not reflect the actual internal operation set. Gateway-level WSDL "views" sometimes hide operations that are still callable if you can reach the internal contract (e.g., via SSRF pivoting, or a leaked internal WSDL URL in error messages).
