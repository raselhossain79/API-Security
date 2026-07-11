# gRPC Security Testing — Cheatsheet

Quick-reference companion to files 1–6. Use this for fast lookup during an active engagement; refer back to the numbered files for the full explanation behind any item here.

---

## 1. Testing workflow, start to finish

1. **Identify transport**: native gRPC (HTTP/2 direct) or gRPC-Web (browser, via proxy)? Check `Content-Type`: `application/grpc*` = native, `application/grpc-web*` = gRPC-Web. → File 1, section 6.
2. **Check reflection**: `grpcurl -plaintext host:port list`. If it works, dump the full attack surface immediately. → File 2.
3. **Set up Burp decoding**: pick a plugin matching the transport (gRPC-Web Coder / bRPC-Web for gRPC-Web; ProtoBurp++ / ProtoME for native or schema-mode work). Load a `.proto`/protoset if available. → File 6, section 6–7.
4. **Map methods to test categories**: for every method from reflection, note whether it looks object-scoped (BOLA candidate), privilege-scoped (BFLA candidate), and which string fields look injection-relevant. → File 4, section 4.2; File 5, section 3.
5. **Run BOLA**: swap object identifiers across accounts, same auth. → File 4, section 3.
6. **Run BFLA**: call every method unauthenticated, then low-privilege. → File 4, section 4.
7. **Run injection**: SQLi/command injection/SSTI through flagged string fields. → File 5, sections 4 and 6.
8. **Always check `grpc-status`/`grpc-message` trailers**, never just the HTTP status line. → File 1, section 5.

---

## 2. grpc-status codes quick reference

| Code | Name | Testing meaning |
|---|---|---|
| 0 | OK | Call succeeded — check whether it should have |
| 3 | INVALID_ARGUMENT | Malformed request, not an auth signal — fix payload before concluding anything |
| 5 | NOT_FOUND | Object doesn't exist, or server is hiding it from you — compare against a control |
| 7 | PERMISSION_DENIED | Authorization check fired correctly |
| 12 | UNIMPLEMENTED | Wrong method path, or method genuinely doesn't exist — re-check `describe` output |
| 16 | UNAUTHENTICATED | No/invalid credentials |

---

## 3. grpcurl one-liners

```bash
# Check reflection availability
grpcurl -plaintext host:port list

# Enumerate methods on a service
grpcurl -plaintext host:port list pkg.Service

# Full schema for a service
grpcurl -plaintext host:port describe pkg.Service

# Full schema + JSON template for one method
grpcurl -plaintext host:port describe pkg.Service.Method --msg-template

# Call a method, authenticated
grpcurl -plaintext -H "authorization: Bearer <token>" \
  -d '{"field": "value"}' host:port pkg.Service/Method

# Call a method, unauthenticated (BFLA baseline)
grpcurl -plaintext -d '{"field": "value"}' host:port pkg.Service/Method

# Export full schema to a protoset for offline reuse
grpcurl -plaintext host:port describe -protoset-out attack_surface.protoset

# Health check
grpcurl -plaintext host:port grpc.health.v1.Health/Check

# TLS with self-signed cert
grpcurl -insecure host:port list

# mTLS
grpcurl -cert client.crt -key client.key -cacert ca.crt host:port list
```

Full flag definitions: File 6, section 4.

---

## 4. Injection payload quick list

**SQLi** (File 5, section 4.1):
```
' OR '1'='1
'; WAITFOR DELAY '0:0:5'--
' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--
```

**Command injection** (File 5, section 4.2):
```
; id
| whoami
$(whoami)
`whoami`
```

**SSTI** (File 5, section 4.3):
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
```

Always confirm command injection with an out-of-band listener rather than relying on response content. Always check `grpc-message` for reflected DB errors on SQLi. Always track where a field's value is consumed downstream, not just in the immediate response, for SSTI.

---

## 5. WAF/Gateway relevance by topic

| File | Relevance | Why |
|---|---|---|
| 1 — Fundamentals | Not applicable | Conceptual, no delivery |
| 2 — Reflection | Not applicable (authz concern instead) | Reflection access itself is gated by auth, not signatures |
| 3 — Protobuf manipulation | Marginal | Framing errors, not signature evasion |
| 4 — Authorization | Narrow | Gateway-level route auth can mask/duplicate backend checks |
| 5 — Injection | **Substantial — dedicated section** | Binary framing changes signature-detection coverage; verify before assuming protection exists or attempting bypass |

Full detail: File 1, section 9 and File 5, section 6.

---

## 6. Practice environments

### PortSwigger Web Security Academy

There is currently **no dedicated gRPC lab category** on PortSwigger Academy. This isn't an omission in this series — it reflects the actual state of their lab catalog. What transfers conceptually:

- **API Testing labs** (BOLA/broken authentication/mass assignment on REST and GraphQL APIs) — the authorization logic in File 4 is directly transferable; only the transport and message format differ. Work these in Apprentice → Practitioner → Expert order if you haven't already as part of your API security series, since the reasoning pattern is identical.
- **GraphQL labs** — useful for the general muscle of "here's a schema-introspectable API, map the full attack surface before testing" that reflection (File 2) asks of you on gRPC.

Treat PortSwigger's API-focused labs as reasoning practice, not gRPC-specific practice — you'll need to bring your own gRPC target (see below) to practice the transport-specific mechanics in Files 1–3 and 6.

### HackTheBox

Search HTB's Challenges section (not the main machine catalog) for gRPC-tagged entries — coverage varies over time as new challenges are added and retired, so check current availability directly rather than relying on a fixed list here. When present, HTB gRPC challenges typically focus on:
- Reflection-based enumeration against a target with no provided `.proto` file (direct practice for File 2).
- Protobuf message manipulation to reach unintended application state (direct practice for File 3).
- Occasionally, custom-built vulnerable gRPC services designed around a specific authorization or injection flaw (practice for Files 4–5).

### TryHackMe

Search for gRPC-tagged rooms; availability and content change over time, so verify what's currently live rather than assuming a fixed catalog. When present, TryHackMe gRPC content typically leans introductory — walking through `grpcurl` basics and reflection enumeration hands-on, which pairs well as a first practical pass before applying Files 4–5's testing logic against something more open-ended like an HTB challenge.

### Build your own target (recommended supplement)

Given the thin lab coverage above, standing up a small self-hosted gRPC service (the official gRPC "Hello World" quickstart, or a deliberately vulnerable example) gives you a controlled environment to practice the full File 2 → File 6 workflow end to end, including scenarios you fully control the vulnerability class of — genuinely useful for confirming your Burp plugin setup (File 6) and your grpcurl commands (File 6, section 5) work correctly before you need them live on an engagement.

---

## 7. Common mistakes checklist

- [ ] Judging call success/failure from HTTP status instead of `grpc-status` trailer
- [ ] Trusting a blackbox/heuristic protobuf decode without sanity-checking field types
- [ ] Forgetting the 5-byte gRPC length prefix needs recalculating after a manual edit
- [ ] Testing only the fields the client UI populates, ignoring fields visible in the full schema
- [ ] Testing only unary methods, skipping streaming methods for BOLA/injection
- [ ] Assuming a WAF/gateway inspects gRPC content the same way it inspects REST/JSON without verifying first
- [ ] Stopping BFLA sweeps at "obviously admin-named" methods instead of testing every enumerated method
- [ ] Missing downstream/asynchronous rendering of an injected field (SSTI in particular)

---

## 8. Series index

1. gRPC Fundamentals for Pentesters
2. Service Enumeration via Reflection
3. Protobuf Message Manipulation in Burp Suite
4. Authorization Testing: BOLA and BFLA
5. Injection Testing via gRPC Fields
6. Tooling: grpcurl and Burp gRPC Plugins
7. This cheatsheet
