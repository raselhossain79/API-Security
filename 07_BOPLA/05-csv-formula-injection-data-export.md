# BOPLA — Broken Object Property Level Authorization
### File 5 of 6: CSV / Formula Injection via Data Export Features

---

## 1. Why This Belongs in a BOPLA Series

CSV/Formula Injection is included here as a **data-export-specific property exposure
issue**: it is what happens when an object's properties (a user's name, a comment field,
a ticket title) are exported verbatim into a spreadsheet-consumable format without the
export layer treating those properties as untrusted data. It is the same underlying
failure pattern as Excessive Data Exposure and Mass Assignment — an object property
crossing a trust boundary without a dedicated check for that specific boundary — applied
to the CSV/XLS export boundary instead of the JSON API response boundary.

It is a distinct vulnerability class from Excessive Data Exposure and Mass Assignment
(it is formally CWE-1236, not part of OWASP's API3 definition), but it is grouped into
this series because it arises from the exact same root pattern this series already
covers: admin dashboards and reporting features that take user-controlled API object
fields (names, notes, comments — the same fields covered in files 2–4) and pipe them
into a downstream sink (a spreadsheet) without a boundary-specific sanitization step.

---

## 2. The Mechanism

### 2.1 How spreadsheet formula interpretation works

When a spreadsheet application (Microsoft Excel, LibreOffice Calc, Google Sheets) opens a
CSV file, it inspects the **first character of every cell**. If that character is one of:

```
=    +    -    @    (tab, 0x09)    (carriage return, 0x0D)
```

the spreadsheet application treats the entire cell content as a **formula** to be
evaluated, not as literal text — regardless of whether the file was ever intended to
contain formulas. CSV is a plain-text format with no concept of "this cell is data, not
code," so the interpretation is entirely up to the spreadsheet application's parsing
rules, applied uniformly to every cell.

### 2.2 Why this becomes exploitable

If an API's data-export feature (a "Download as CSV" button on an admin dashboard, an
automated weekly report, an analytics export) writes a user-controlled object property
— a display name, a comment, a support ticket title, a company name field — directly into
a CSV cell without checking whether that value begins with one of the formula-trigger
characters, an attacker can set that property (through a completely normal, legitimate-
looking API call, e.g., updating their own profile `full_name` field) to a value that
starts with `=`. The attack payload sits dormant in the database as ordinary text. It only
"detonates" later, when a different user — usually an **administrator**, since admin
dashboards are the most common export feature — opens the exported file in a spreadsheet
application.

### 2.3 Example — end to end

**Step 1 — attacker sets their own profile field** (a completely normal, authenticated
API call within their own privileges — no authorization bypass required at this stage):
```
PATCH /api/users/me HTTP/2
Authorization: Bearer <attacker-token>
Content-Type: application/json

{"company_name": "=cmd|' /C calc'!A0"}
```

**Field-by-field breakdown:** `company_name` is a completely ordinary, writable field the
attacker is authorized to set on their own object — this is not a mass assignment or
authorization bypass, it's a legitimate write to a legitimate field. The payload
`=cmd|' /C calc'!A0` is a formula using Excel's legacy DDE (Dynamic Data Exchange) syntax:
`=cmd|'/C calc'!A0` instructs Excel to invoke `cmd.exe` with `/C calc` (launching the
Windows Calculator, used here purely as a harmless proof-of-concept payload — a real
attacker would substitute a PowerShell download-and-execute one-liner). This value is
stored as-is in the database; nothing about the write operation itself is anomalous.

**Step 2 — an administrator exports user data**, e.g., clicking "Export all users to CSV"
on an admin dashboard:
```
GET /api/admin/users/export?format=csv HTTP/2
Authorization: Bearer <admin-token>
```

**Step 3 — the server builds the CSV**, naively concatenating each user's fields into
rows:
```csv
id,username,company_name,email
8841,rasel_t,"=cmd|' /C calc'!A0",rasel@example.com
```

**Step 4 — the administrator opens the downloaded file in Excel.** Excel sees a cell
whose content begins with `=` and evaluates it as a formula. On a system with legacy DDE
support enabled (or via other formula-based techniques on modern Excel, such as
`HYPERLINK()` or `WEBSERVICE()` calls that make outbound network requests without needing
DDE at all), this executes attacker-controlled code or exfiltrates data — **on the
administrator's machine**, entirely outside the scope of what the API's own authorization
model was ever designed to protect.

### 2.4 Why quoting the CSV field does not prevent this

Note in the example above that `company_name` was written as a quoted CSV field
(`"=cmd|'...'!A0"`) — proper CSV quoting/escaping (handling embedded commas and quotes
correctly) is a **separate concern from formula-character sanitization**. A perfectly
valid, RFC 4180-compliant CSV field can still begin with `=` inside its quotes, and Excel
still evaluates it as a formula. Developers frequently confuse "I'm using a proper CSV
writer library, so injection isn't possible" with the actual required control, which is
specifically checking and neutralizing the **leading formula-trigger characters**,
independent of quoting.

---

## 3. How to Test For This Safely

This is a client-side-execution vulnerability — the payload does nothing until a human
opens the file in vulnerable software. Safe testing means proving the **export mechanism
fails to sanitize**, without actually attempting to trigger code execution against a real
person (especially not against a real administrator in a live environment, which would be
both an ethical and likely an authorization-scope violation).

### 3.1 Safe proof-of-concept payloads

Use **non-executing, purely diagnostic** formulas that only prove formula evaluation
occurred, never payloads that call `cmd`, PowerShell, or external URLs, unless you have
explicit written authorization for a controlled, isolated test (e.g., a dedicated test
machine you control, opened by you, never sent to or opened by another party):

```
=1+1
```
If this cell, once opened in a spreadsheet, displays `2` instead of the literal text
`=1+1`, formula evaluation occurred — sanitization is absent. This alone is sufficient
proof for a report; you do not need to escalate to a code-execution payload to
demonstrate the vulnerability class.

```
=SUM(1,1)
```
Same diagnostic principle, a slightly more distinctive result to rule out coincidence
with an already-present value of `2` elsewhere.

### 3.2 What NOT to do during testing

- Do not use payloads with `cmd|`, PowerShell invocations, `WEBSERVICE()`, or
  `HYPERLINK()` pointed at attacker-controlled infrastructure in any file that another
  real person (an admin, a client stakeholder, anyone outside your own controlled test
  machine) might open.
- Do not export and open the file "as the admin" using shared/production admin
  credentials unless that is explicitly the sanctioned test path in your engagement scope
  — prefer opening the exported file yourself, on your own isolated test machine, using
  your own authorized test account's export permission if you have one.
- If your test account cannot access the admin export feature, and impact can only be
  demonstrated by an actual administrator's action, this is a case to **document the
  injection point and stop there** in the report — noting "confirmed unsanitized formula
  characters reach the export; full impact requires the export to be opened, which is out
  of scope for direct testing" — rather than attempting to induce an admin to open a file,
  which would constitute unauthorized social engineering outside a typical pentest's
  technical scope unless phishing/social-engineering is separately in scope.

### 3.3 Systematic sweep across the API surface

Apply the same field-by-field testing discipline as files 2–4: for **every** field that
(a) is user-writable via a normal API call, and (b) later appears in **any** CSV, XLS, or
similar export feature (admin dashboards, reporting endpoints, "export my data" GDPR-style
downloads, scheduled report emails), test the `=1+1` diagnostic. Common high-value target
fields: display name, company name, bio/notes, support ticket titles, comment bodies,
address fields, custom form responses.

---

## 4. Real-World 2025 CVEs Demonstrating This Exact Pattern

These are documented, real 2025 disclosures showing the escalation path from a normal
API field write to code execution via export — the same mechanism as the walkthrough
above, in production software:

- **CVE-2025-11279 / CVE-2025-12249 (Axosoft Scrum and Bug Tracking, v22.1.1.11545)**:
  <cite index="21-1">the vulnerability occurs in the Edit Ticket functionality, where the Title field is exported without sanitization into CSV reports, allowing an attacker to inject spreadsheet formulas into exported files that can later be used as a pivot point in client-side attacks</cite>. This is a direct match to the walkthrough in section 2: a normal, authorized ticket-title edit becomes a dormant payload that fires when the CSV export is opened.

- **CVE-2025-62417 (Bagisto, an open-source e-commerce platform)**: <cite index="24-1">the vulnerability is a classic case of CSV Formula Injection, where the application fails to sanitize user-provided input before including it in a CSV export</cite>, with the root cause traced to unsanitized product attributes fed by a rich-text editor field. <cite index="24-1">the vulnerability is triggered when a user with privileges to edit products injects a string starting with a formula character into a product field</cite>, and the fix location confirms the same architectural lesson as file 3's mass-assignment root-cause analysis: <cite index="24-1">the fix was applied at the point of data entry, since the vulnerability manifests upon CSV export but validation needed to happen at write time</cite>, not export time.

- **CVE-2025-55745 (UnoPim, a product information management platform)**: a quick-export CSV feature let any user with product-edit privileges inject a formula into a product field; per the advisory, <cite index="25-1">when the victim opens the exported CSV, an injected formula can fetch and execute a PowerShell reverse-shell script from an attacker-controlled server</cite>, escalating from a benign text field write to a full reverse shell on whoever opens the export — a direct, modern demonstration of the exact escalation chain described in section 2.4 of this file.

The consistent pattern across all three 2025 CVEs: a completely ordinary, authorized
write to an object property (a ticket title, a product field, a company name) becomes a
dormant client-side code-execution primitive purely because the export feature trusted
that property's content instead of re-validating it at the export boundary — precisely
the "authorization/trust boundary was never enforced at the property level" theme that
defines BOPLA as a whole, extended here to the export sink rather than the API response.

---

## 5. Mitigation Reference (for report-writing context)

Per OWASP guidance, the most reliable Excel-specific mitigation is prefixing any cell
value that begins with a formula-trigger character with a tab character inside the quoted
field, which causes Excel to display the value as text while leaving the underlying data
otherwise intact for programmatic consumers — noting <cite index="26-1">there is no universal CSV sanitization strategy that is safe for all spreadsheet applications and all downstream consumers</cite>, so recommend defense-in-depth (both input-time flagging and export-time neutralization) rather than a single fix point.

---

## 6. WAF / API Gateway Relevance

As noted in file 1, section 4: this is a request-side payload (the formula string is
submitted through a normal field write), so a WAF/gateway *can* in principle inspect
submitted field values for leading formula-trigger characters (`=`, `+`, `-`, `@`, tab,
carriage return) and flag or reject them. In practice this control is rarely deployed at
the gateway layer, for a legitimate reason: those same characters are common in
completely benign data — a note starting with a math expression, a name with a hyphenated
prefix, a comment beginning with an `@mention`. A gateway-level blanket block on leading
`-` or `@` produces significant false positives on ordinary user input. This is why the
correct mitigation is almost always application-layer, at the specific export code path
(section 5), rather than a generic gateway rule — worth stating explicitly in a report so
a client doesn't mistake "add a WAF rule" for a complete fix.

---

## 7. PortSwigger Lab Mapping — Honest Gap Disclosure

**PortSwigger Web Security Academy does not have a lab for CSV/Formula Injection.** This
is a complete coverage gap; the vulnerability class (CWE-1236) sits outside Academy's
current topic list entirely (it is not part of the core web-app or API-testing learning
paths). This should be disclosed plainly rather than force-fitting an unrelated lab as a
substitute.

For hands-on practice, use:
- **crAPI** does not currently include a dedicated CSV export challenge either, as of the
  version referenced in file 1 — confirm against your locally deployed version rather than
  assuming coverage.
- A locally deployed **intentionally vulnerable app with an export feature** (e.g.,
  OWASP's other training apps, or a small self-built Flask/Express app that exports
  user-submitted fields to CSV without sanitization) is the most reliable way to practice
  this safely and legally, since it avoids the "who opens the exported file" authorization
  question entirely — you control both ends.
- Review the public CVE write-ups referenced in section 4 (Axosoft, Bagisto, UnoPim
  GitHub Security Advisories) for detailed, safe, already-disclosed proof-of-concept
  walkthroughs to study the pattern without needing a live target.

---

Continue to **File 6 — Final Cheatsheet**.
