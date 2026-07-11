# API Security — Real-World Exploitation and Vulnerability Chaining
## Part 6: API-Specific Report Writing

This section covers what differs from generic report writing (already
covered in the web app chaining capstone's report skeleton) when the
findings are API-based and, specifically, when they are chains.

### Documenting BOLA and BFLA to Demonstrate Actual Impact

The most common weakness in API report write-ups is describing BOLA/BFLA
findings purely mechanically — "the endpoint does not verify object
ownership" — without demonstrating what that actually gets an attacker.
Every BOLA/BFLA finding write-up should include:

1. **The mechanical description** (for the engineering team implementing
   the fix): which check is missing, at which layer (route middleware,
   resolver, service layer), and why.
2. **A concrete before/after data example**, redacted but structurally
   real: show the actual JSON field names and (redacted) values returned
   for the victim account when accessed with the attacker's token, not a
   generic placeholder description. A reviewer should see, at a glance,
   that real PII/sensitive fields (`ssn`, `date_of_birth`, `internal_notes`)
   were actually returned, not just "user data."
3. **A quantified exposure statement**: how many records are affected? If
   IDs are sequential and enumerable, state the observed ID range and
   extrapolate total affected record count (e.g., "IDs observed ranging
   from 1 to 84,213 during testing; assuming sequential allocation, this
   indicates the full user base of approximately 84,000 accounts is
   exposed") rather than only demonstrating access to one victim account.
4. **For BFLA specifically, explicitly name the privilege boundary
   crossed**: "a standard user role was able to invoke a function
   documented and access-control-labeled as admin-only" is a stronger,
   more auditable statement than "unauthorized access to a function was
   possible."

### CVSS v3.1 Scoring for API-Specific Findings — Worked Examples

The web app capstone covers the base metric definitions generically. Below
are two fully worked examples specific to chained API findings, since
scoring the chain (not each link) is the API-specific skill this series
adds.

**Worked example 1 — Chain 1 (BOLA + BFLA → Account Takeover):**

Score the chain's cumulative end state, not the BOLA link and the BFLA link
separately.

- **Attack Vector (AV): Network** — exploitable over the API from anywhere
  with network access to the endpoint.
- **Attack Complexity (AC): Low** — no race condition, no timing
  dependency, no special configuration required of the victim; the ID
  enumeration and forced reset are deterministic.
- **Privileges Required (PR): Low** — the attacker needs their own valid
  (even free-tier/self-registered) authenticated account to hold the
  Role A token used in both links; this is not None, because an entirely
  unauthenticated caller cannot reach either endpoint.
- **User Interaction (UI): None** — the victim does not need to click
  anything, visit anything, or take any action; the attacker fully drives
  both requests.
- **Scope (S): Unchanged** — impact remains within the same API/application
  security authority; no separate security-scoped component (like
  underlying cloud infrastructure) is affected by this particular chain.
- **Confidentiality (C): High** — full read access to any account's
  profile data via the BOLA link, then full account access via takeover.
- **Integrity (I): High** — the attacker can modify any account's data
  once logged in as the victim, including changing the victim's own
  password to lock out the legitimate user.
- **Availability (A): Low** — some availability impact via account
  lockout of the legitimate user, but no broader service disruption.
- **Resulting vector:**
  `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` → **Base Score: 9.1
  (Critical)**.
- **Scoring note to include in the report:** explicitly state that this
  score reflects the chain's combined access, and separately note what
  each individual link would have scored in isolation (the BOLA link alone,
  read-only PII disclosure, would score in the 6.5-7.5 Medium/High range;
  the BFLA link alone, without a way to identify targets at scale, would
  likely be scored lower due to a more limited realistic attack scenario)
  — this comparison is what makes the value of chaining legible to a
  client security team reviewing the report against their own historical
  finding data.

**Worked example 2 — Chain 5 (Webhook → SSRF → Cloud Metadata → AWS
Credential Theft → Lateral Movement):**

- **Attack Vector (AV): Network.**
- **Attack Complexity (AC): Low** — the metadata endpoint address is fixed
  and well-documented; no race condition or guessing involved.
- **Privileges Required (PR): Low** — requires an authenticated account
  able to register a webhook, typically a standard user-tier feature.
- **User Interaction (UI): None** — the attacker triggers the qualifying
  event themselves (e.g., places their own order).
- **Scope (S): Changed** — this is the key scoring decision for this
  chain, and it should be explicitly justified in the report: the
  vulnerability exists in the API's webhook feature (the vulnerable
  component), but the impact — stolen IAM credentials, and everything
  reachable with them — extends into cloud infrastructure resources that
  are a separate security authority from the API application itself (S3
  buckets, other EC2 instances, IAM policy surface). Under CVSS v3.1, Scope
  changes whenever an exploited vulnerability in one component impacts
  resources beyond its own security scope, which is exactly this case.
- **Confidentiality (C): High**, **Integrity (I): High**, **Availability
  (A): High** — the IAM role's actual permission set determines the true
  ceiling, but assume High across all three unless the engagement
  specifically confirmed a narrowly scoped role (state this assumption
  explicitly in the report and note it as a factor the client should
  verify against their actual IAM policy).
- **Resulting vector:**
  `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` → **Base Score: 10.0
  (Critical)** — note that Scope: Changed combined with High/High/High
  produces the maximum possible base score, which is itself worth calling
  out in the executive summary as the report's top finding.

### Documenting Multi-Step Chains: Reproduction Structure

Use a consistent per-chain finding structure across the report (this
extends, rather than replaces, the generic finding template from the web
app capstone):

1. **Finding title** naming the chain's start and end state (e.g., "Chain:
   Public Webhook Registration to AWS Account Compromise via SSRF").
2. **CVSS score and vector** for the chain as a whole (per the worked
   examples above), with individual-link scores given as a secondary
   comparison point, not the headline number.
3. **Chain summary** — 2-3 sentences, written for a technically literate
   but non-specialist reader (an engineering manager, not necessarily a
   security engineer), stating what the attacker starts with and what they
   end with.
4. **Step-by-step reproduction**, one numbered step per chain link, each
   with:
   - **Input:** what the attacker supplies or already has at this point.
   - **Request:** the actual HTTP request (redact only what must be
     redacted for the client's safety — e.g., replace live stolen
     credentials with `<<REDACTED - see attached PoC>>` rather than
     omitting the request structure entirely).
   - **Output:** what the response reveals or grants.
   - **Why this is trusted/accepted:** the specific root cause at this
     link (missing check, weak validation, implicit trust assumption) —
     this is what lets engineering teams fix the right thing, since
     "output was X" alone doesn't explain why the system allowed it.
5. **Cumulative impact statement** — one paragraph stating, in business
   terms, what the fully executed chain grants an attacker, explicitly
   connecting back to data classification/business risk categories the
   client already uses if known (e.g., "constitutes unauthorized access to
   regulated PII for the full customer base, a reportable event under
   [applicable regulation] in most jurisdictions the client operates in" —
   only include regulatory framing if you have a factual basis for it from
   the client's own scoping documents; otherwise keep this business-impact
   paragraph framed around the client's stated crown-jewel assets from the
   engagement kickoff rather than speculating about specific legal
   obligations).
6. **Evidence** — reference to attached PoC materials (see below).
7. **Remediation guidance per link**, not just for the chain overall —
   since fixing any single link breaks the chain, list each link's fix
   separately and note that defense-in-depth (fixing more than one link)
   is recommended even though fixing any one is theoretically sufficient.

### Evidence Requirements

For every chain finding, attach:

- **Raw HTTP requests/responses from Burp** for the initial discovery
  (Burp's "Save item" or a exported Logger view) — this documents how the
  chain was *found*, which is distinct from documenting how it is
  *reproduced*.
- **The Postman collection export** (per Part 5) as the reproduction
  artifact — this is what the client will actually re-run.
- **Response diffs showing cross-role access** where relevant (BOLA/BFLA
  links) — a side-by-side or highlighted diff of Role A's response vs
  Role B's response against the identical endpoint, generated via Burp
  Comparer or Postman's response comparison, makes the authorization gap
  visually unambiguous in a way a text description alone does not.
- **A results export from an actual successful Collection Runner
  execution** (per Part 5) as time-stamped proof the chain was executed
  successfully during the engagement window, not merely theoretically
  constructed from the API's design.

### Executive Summary Writing for API Findings — Non-Technical Stakeholders

The executive summary is frequently the only section read by non-technical
stakeholders (CISOs focused on business risk, engineering directors,
occasionally board-level audiences for critical findings). API-specific
guidance for this section:

- **Lead with the chain's end state in plain language, not the
  vulnerability class names.** "An attacker with only a free account could
  take over any customer's account, including administrator accounts,
  without needing a password" communicates more than "BOLA and BFLA
  vulnerabilities were identified in the user management API."
- **Quantify scale wherever the technical findings support it.** "Affects
  all ~84,000 user accounts" or "grants access to the full customer
  database" lands with non-technical stakeholders far more effectively
  than a vulnerability count.
- **State the skill/access barrier honestly.** If a chain requires only a
  free self-registered account and basic HTTP tooling (true for most
  chains in Part 2), say so explicitly — "no specialized tools or insider
  access required" is a more urgent statement to a non-technical reader
  than a CVSS number they may not know how to interpret.
- **Avoid vulnerability-class jargon in the summary section entirely**
  where possible (save BOLA/BFLA/SSRF terminology for the technical
  findings section) — describe mechanisms in plain functional terms
  ("the system did not check whether the requesting user actually owned
  the data being requested") instead.
- **Group chains, don't list every link as a separate bullet.** A summary
  listing ten sub-findings under one chain reads as noisy and understates
  how connected the risk actually is; present each chain as a single
  summary bullet with its cumulative severity, and let the detailed
  technical section carry the link-by-link breakdown.

### Real-World Notes

- Clients occasionally push back on Scope: Changed scoring for
  cloud-metadata chains, arguing the underlying vulnerability is "just"
  SSRF; be prepared to explicitly walk through the CVSS v3.1 Scope
  definition and the specific security-authority boundary crossed (API
  application vs. cloud IAM) rather than simply asserting the score.
- Report reviewers (client-side security teams doing intake triage) move
  faster through chained findings that follow the exact structure above
  consistently across every chain in the report — inconsistent structure
  between findings measurably slows down client-side review and remediation
  ticket creation.
- Always retain the individual-link severity comparison (see Worked
  Example 1) even when it makes the report longer — it is frequently the
  single most persuasive piece of the writeup for engineering teams
  deciding how to prioritize the fix relative to their existing backlog.

---
Next: `07_Real_World_Adaptation.md`
