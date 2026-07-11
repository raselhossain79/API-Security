# Protobuf Message Manipulation in Burp Suite

## 1. What this file covers

File 1 explained how protobuf is structured on the wire. File 2 covered how to learn a service's schema via reflection. This file is the practical middle step: getting Burp to intercept gRPC traffic, decode the binary body into something you can read and edit, modify field values, and send the modified request back correctly. Authorization testing (file 4) and injection testing (file 5) both depend on the workflow in this file — they're really just "what values do I put in the decoded fields," which assumes you can already get to the decoded fields in the first place.

Tool installation and setup specifics live in file 6. This file assumes a gRPC-capable protobuf decoder plugin is already installed and focuses entirely on the testing workflow.

---

## 2. Why you need a plugin at all

As covered in file 1, Burp Suite handles the HTTP/2 transport layer natively — it can proxy, intercept, and forward gRPC/gRPC-Web traffic without any plugin. What Burp does **not** do natively is understand that the binary blob inside the request/response body is a protobuf-encoded message with structure. Without a plugin, you'd see something like:

```
CgZjYXJsb3MSB3Bhc3MxMjM=
```

or raw non-printable binary — technically intercepted, practically useless. A gRPC/protobuf-aware plugin adds a parsing layer on top: it recognizes the gRPC content type, strips the 5-byte gRPC framing header (file 1, section 7), parses the remaining bytes into tag-length-value fields (file 1, section 3), and renders them in a dedicated editable tab. When you finish editing, it reverses the process: reserializes your edits into valid protobuf, re-adds the 5-byte header with a corrected length, and lets the modified request go out.

---

## 3. Two decoding modes, and why the difference matters

Every protobuf-aware Burp plugin operates in one of two modes, and knowing which one you're in changes how much you can trust what you're looking at.

**Schema mode** (`.proto` file loaded): the plugin knows real field names, real types, and correctly distinguishes nested messages from plain strings/bytes. This is the accurate mode — use it whenever you have a `.proto` file, whether it was handed to you, leaked, or reconstructed from reflection (file 2, section 7).

**Blackbox/heuristic mode** (no `.proto` file): the plugin guesses structure purely from wire types. It can tell you "field 3 is length-delimited" but not whether that means a string, bytes, or an embedded sub-message — it typically renders these as raw bytes or attempts a UTF-8 decode and shows you the result, letting you judge by eye. This mode is what you fall back to when reflection is disabled and no `.proto` file is available (file 2, section 9).

**Practical implication**: in blackbox mode, always sanity-check a field's guessed type before you trust an edit. If a decoder shows you what looks like a nested message inside a field you assumed was a plain string, that's a signal you're looking at an embedded message, not raw text — edit it as structured data (drill into the sub-fields) rather than overwriting the whole blob, or you'll corrupt the message and get a parse error back instead of a real test result.

---

## 4. Step-by-step workflow: intercept, decode, view

**Step 1 — Get gRPC traffic into Burp's history.**
Configure your client (browser for gRPC-Web, or a proxy-aware mobile/desktop client for native gRPC) to route through Burp's proxy listener the same way you would for any traffic. For native gRPC over HTTP/2, confirm Burp's HTTP/2 support is enabled in Proxy settings — it is by default in current Burp versions, but worth a one-time check if traffic isn't appearing.

**Step 2 — Identify a gRPC request in Proxy history.**
Look for `POST` requests where the `Content-Type` header is `application/grpc`, `application/grpc+proto`, `application/grpc-web+proto`, or `application/grpc-web-text`, and the path looks like `/package.Service/Method`. A correctly configured plugin will usually flag or auto-decode these automatically based on that same content-type match — that's the trigger condition the plugin is watching for.

**Step 3 — Open the decoded tab.**
Select the request, and in the message editor you'll see an extra tab alongside "Pretty," "Raw," "Hex" — typically named something like "Protobuf," "gRPC," or "Decoded" depending on the plugin. Click it. If the plugin auto-detected the content type correctly, you'll see structured field output immediately; if not, most plugins offer a right-click "send to decoder" or "decode as protobuf" action as a manual trigger.

**Step 4 — Load a `.proto` file if you have one.**
If your plugin supports schema mode, there's usually a settings tab or right-click option to load a `.proto` file (or a compiled descriptor set, `.pb`/`.protoset`, exported from reflection per file 2 section 7). Once loaded, field names and correct types replace the generic `field_1`, `field_2` placeholders.

**Step 5 — Read the output structurally, not linearly.**
Decoded protobuf output typically groups nested messages visually (indentation or collapsible tree nodes). Match this against the schema from file 2 before editing — confirm the field you intend to modify is the one you think it is by field number, not just by guessing from position, especially in blackbox mode.

---

## 5. Step-by-step workflow: modify a field and send it

This is the core loop you'll repeat constantly across files 4 and 5.

**Step 1 — Send the request to Repeater.**
Right-click the intercepted or history request → Send to Repeater, exactly as you would with any other request type. The decoded protobuf tab carries over into Repeater.

**Step 2 — Edit the field value in the decoded tab.**
Click into the field's value (e.g., `order_id: "ord_88213"`) and change it directly (e.g., to `ord_88214`, another user's order — this is the BOLA pattern detailed fully in file 4). Most plugins let you edit inline the same way you'd edit a JSON body in a normal Burp tab.

**Step 3 — Confirm re-encoding before sending.**
Some plugins re-encode live as you type; others require you to click an explicit "encode"/"apply" action, or they encode automatically only at send-time. Check the Raw or Hex tab after editing — if the plugin is working correctly, you should see the binary body has changed length/content to reflect your edit, and the 5-byte gRPC length prefix (file 1, section 7) should have updated automatically to match the new payload length. If the length prefix is wrong, the server will reject the frame outright with a transport-level error before your payload is ever evaluated — this is the most common reason a manipulated gRPC request silently fails, so treat a mismatched length prefix as the first thing to rule out when a modified request doesn't behave as expected.

**Step 4 — Send and read the response the gRPC way.**
Click Send. Per file 1 section 5, do **not** judge success/failure from the HTTP status line — it will almost always read `200 OK` regardless of outcome. Instead:
- Open the response's decoded protobuf tab to see the actual returned data (or lack of it).
- Check the `grpc-status` and `grpc-message` trailers — in Burp's response view these typically appear as HTTP/2 trailer pseudo-headers at the end of the response headers section, after the body, depending on how your plugin surfaces them. `grpc-status: 0` means OK; anything else is an error, and `grpc-status: 7` (`PERMISSION_DENIED`) or `grpc-status: 16` (`UNAUTHENTICATED`) are exactly the results you're watching for in authorization testing.

**Step 5 — Iterate.**
Once the loop above works for one field, it works for all of them — swap IDs for BOLA, call unauthorized methods for BFLA (file 4), or drop payload strings into text fields for injection (file 5). The mechanics don't change; only the value you type and what you're checking for in the response does.

---

## 6. Injecting test values into decoded fields

Because the decoded tab renders string fields as plain editable text, injecting a test value is mechanically identical to editing a JSON body field in a REST tester — the only difference is that the plugin, not Burp core, handles turning your typed text back into correctly wire-encoded protobuf bytes on send.

A few field-type-specific considerations that come up constantly:

- **String fields** — edit directly; this is your delivery point for SQLi/command injection/SSTI payloads (file 5).
- **Numeric fields (int32/int64/double)** — most plugins validate that you've typed a number and will refuse or error on non-numeric input in a strictly-typed field. If you need to test type confusion (sending a string where a number is expected, or an out-of-range number), you may need to switch that specific field to blackbox/raw editing mode within the plugin, or hand-craft the bytes, since schema-mode editors often enforce the schema's type as a client-side guardrail.
- **Enum fields** — usually rendered as a dropdown of known valid values in schema mode. To test an out-of-range enum value (file 1, section 4's `status = 99` example), you again typically need to drop to raw/blackbox editing for that field, since the schema-aware UI won't let you type an invalid enum by design.
- **Repeated fields** — rendered as a list; most plugins let you add/remove/duplicate entries. Duplicating entries or sending an extremely long repeated list is a reasonable resource-exhaustion/DoS-adjacent test, distinct from injection but worth noting if scope includes availability testing.
- **Nested messages** — expand and edit the inner fields the same way; the outer message just re-serializes correctly as long as the inner edit is valid.

---

## 7. Adding a field the client never sends

One of the most valuable things schema mode gives you: the `.proto` schema (or reflection output) may define fields that the real client UI never populates — the protobuf equivalent of a hidden or unused form parameter. If reflection (file 2) showed you a field like `bypass_approval` in `AdminRefundRequest` that the legitimate client never sets, most plugins let you manually add that field into the decoded tree even though it wasn't present in the original captured request, then send it. This is functionally the gRPC equivalent of mass-assignment testing on a REST API, and it's a very high-value test — request/response schemas that were clearly designed for internal/admin use often ship in the same compiled service as the public-facing methods, with the assumption that "the app doesn't expose a UI for this" is sufficient protection.

---

## 8. Common failure modes and what they actually mean

| Symptom | Likely cause | What to do |
|---|---|---|
| Decoded tab shows nothing / raw bytes only | Plugin didn't recognize content-type, or you're in blackbox mode against a message it can't parse | Check `Content-Type` header matches what the plugin watches for; manually trigger decode if there's a right-click option |
| Response comes back as immediate transport error, no `grpc-status` at all | 5-byte length prefix mismatch after edit (section 5, step 3) | Check Hex tab, confirm the 4-byte length matches actual payload byte count |
| `grpc-status: 3` (`INVALID_ARGUMENT`) | Your edited value violates a server-side validation rule (not an auth issue) | Legitimate finding path — note this as validation behavior, distinct from authorization testing (file 4) |
| `grpc-status: 12` (`UNIMPLEMENTED`) | You're calling a method path that doesn't exist on this server, often a typo in the method path copied from reflection | Re-check the exact fully-qualified path from `grpcurl describe` output (file 2) |
| Field you added in schema mode gets silently dropped on send | Some plugins strictly enforce the loaded `.proto` — if the field number isn't in your loaded schema, it may not serialize | Cross-check the field number exists in the schema/descriptor you loaded, or fall back to raw byte editing to force it in |

---

## 9. Real-world notes

- In practice, blackbox/heuristic decoding is what you'll use more often than schema mode on external engagements, simply because `.proto` files and working reflection endpoints are the exception rather than the rule outside of internal/graybox tests. Get comfortable reading raw tag-length-value output by eye (file 1, section 3) — you will need to sanity-check heuristic guesses regularly, and misreading a heuristic decode as ground truth is a common source of wasted testing time.
- Response trailers are the detail testers most often overlook when they're new to gRPC, because every instinct built on REST testing says "check the status code" and gRPC's status code is buried after the body instead of on the response line. Build the habit of checking `grpc-status` explicitly on every single request during this kind of testing, not just when something looks obviously wrong.
- When a decoded field renders as gibberish even in schema mode, double check you've loaded the *correct* `.proto` — mismatched message types (e.g., trying to decode a `GetOrderRequest` body using the `CreateOrderRequest` schema) produce plausible-looking but wrong output rather than an obvious error, because protobuf's untyped wire format (file 1, section 3.1) doesn't inherently reject a mis-typed decode attempt.
- Save decoded/edited requests as Repeater tabs per method as you go — with dozens of RPC methods to work through for files 4 and 5, a consistently named tab per method (`OrderService.GetOrder — BOLA test`, etc.) pays for itself quickly once you're deep into systematic authorization testing.

---

## 10. Where this series goes next

- **File 4** — using this exact edit-and-send workflow to systematically test authorization on every enumerated method.
- **File 5** — using this exact workflow to deliver injection payloads through string fields.
- **File 6** — full setup instructions and flag/option breakdowns for the specific tools referenced in this file.
