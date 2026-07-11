# Writeup Template — Copy This For Every Practice Session

> Copy this entire template into a new file for every lab/session you complete.
> Suggested filename: `YYYY-MM-DD_topic-name_lab-name.md`
> Suggested storage: a `Practice_Logs/` folder at the repo root, with one subfolder
> per topic matching your existing numbered folders (e.g. `Practice_Logs/01_SQLi/`).

This format deliberately mirrors real pentest report / bug bounty writeup structure —
practicing this format now means you're building report-writing muscle memory at the
same time as technical skill, and these logs double as a portfolio you can reference
later (some hunters publish sanitized versions of these on GitHub).

---

## TEMPLATE (copy everything below this line)

```markdown
# [Lab Name / Target Name] — [Vulnerability Type]

**Date:** YYYY-MM-DD
**Source:** PortSwigger Web Security Academy / crAPI / HackTheBox / Live target (name if bug bounty)
**Vulnerability Class:** e.g. SQL Injection — UNION-based
**Difficulty:** Apprentice / Practitioner / Expert
**Time Taken:** e.g. 45 minutes
**Repo Reference:** Link to the specific note file(s) you used, e.g. `SQLi_Notes/01_InBand_SQLi_Union_Error.md`

## Objective

One or two sentences — what was I trying to achieve in this lab/session?
e.g. "Retrieve the administrator's password hash from the users table via a
UNION-based SQL injection in the product category filter."

## Environment / Target Setup

- URL or lab link
- Any relevant context (auth required? multiple user roles involved? API vs web app?)

## Steps to Reproduce

Numbered, specific, in order. Include actual requests/responses where useful —
paste the raw HTTP request from Burp Repeater, not a paraphrase.

1. Identified the injection point at `GET /filter?category=Gifts`
2. Confirmed injection with:
   ```
   GET /filter?category=Gifts'--
   ```
   Response: [what happened — error, blank page, different content, etc.]

3. Determined column count using:
   ```
   GET /filter?category=Gifts' ORDER BY 3--
   GET /filter?category=Gifts' ORDER BY 4--
   ```
   Result: 3 columns confirmed (4 caused an error)

4. [Continue for every meaningful step until the lab is solved]

## Payload(s) Used and WHY They Worked

This is the most important section — do not skip the mechanism explanation.

**Payload:**
```
' UNION SELECT username, password FROM users--
```

**Why it worked:**
Explain the underlying query structure I inferred, what each part of my payload
did to that structure, and why the response contained what it did. If I'm not
confident explaining this without notes, I go back and re-read before finishing
this writeup.

## Root Cause

One or two sentences on what the underlying code mistake was — e.g. "User input
from the category parameter was concatenated directly into the SQL query string
without parameterization."

## Impact (Written As If This Were a Real Client Report)

What could an attacker actually do with this in a real environment? Practice
writing this the way you'd write it for a client, not just "I got the flag."
e.g. "An unauthenticated attacker could extract the full user table including
password hashes, enabling credential-based attacks against the application or
against reused passwords on other services."

## Remediation (Practice Writing This Too)

How would I fix this if I were the developer? e.g. "Use parameterized queries /
prepared statements instead of string concatenation. Apply least-privilege database
account permissions so the web app's DB user cannot read unrelated tables even if
injection occurs."

## What I Got Stuck On (Be Honest — This Is the Valuable Part)

Write down exactly where I struggled, what I tried that didn't work, and what
finally unstuck me. This section is for future-me, not for showing off. This is
often the most useful part of the writeup six months later.

## Screenshot / Evidence

[Attach or link screenshots of key requests/responses — Burp Repeater view,
the solved confirmation, extracted data, etc.]

## Tags

`#sqli` `#union-based` `#portswigger` `#apprentice` `#solved`
(Use consistent tags across all writeups so you can search/filter your practice
log later — e.g. by vulnerability type, by difficulty, or by "still need review")
```

---

## Notes on Using This Template

- **Fill in every section, even briefly** — an empty "What I Got Stuck On" section
  usually means I rushed the writeup, not that I didn't struggle at all.
- **Don't wait** — write this the same day, ideally right after solving the lab,
  while the request/response details and reasoning are still fresh in memory.
- **Redact before sharing publicly** — if any writeup is based on a real bug bounty
  target (not a lab), never publish it publicly until the program has explicitly
  authorized disclosure. Lab-based writeups (PortSwigger, crAPI, HackTheBox) are
  generally safe to make public since the environments are designed for this.
- **Revisit old writeups periodically** — every month or so, skim through old
  writeups for topics marked 🔴 High priority. If something feels unfamiliar on
  re-read, that's a signal to redo that lab rather than assume it's retained.

---

## Suggested Storage Structure

```
Practice_Logs/
├── README.md                     (index of all writeups, updated as you go)
├── 01_SQLi/
│   ├── 2026-08-01_union-based-column-count.md
│   ├── 2026-08-02_blind-boolean-conditional-responses.md
├── 02_XSS/
│   ├── 2026-08-05_reflected-xss-basic.md
├── ...one folder per topic, matching your existing numbered note folders...
```

Keeping this **separate** from your reference note folders (`SQLi_Notes/`, etc.) is
intentional — reference notes are the polished "how it works" material, practice
logs are your personal, honest, evolving record of what you actually did and where
you struggled. Mixing them makes both worse.
