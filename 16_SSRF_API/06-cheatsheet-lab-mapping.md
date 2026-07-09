# API SSRF — Cheatsheet and PortSwigger Lab Mapping

## Quick Reference Cheatsheet

### Recon checklist
- [ ] Pull OpenAPI/Swagger/GraphQL schema; grep field names for URL-purpose prefixes
      (webhook, callback, notify, redirect, return, cancel, ipn, import, source,
      avatar, logo, image, document, file, metadata, jwks, oidc).
- [ ] Check `/settings/integrations`, `/webhooks`, `/sso` paths specifically.
- [ ] Check for `POST /webhooks/{id}/test` or similar synchronous-trigger actions.
- [ ] Test any free-text field that later renders a link preview.
- [ ] Note which candidate fields are synchronous (immediate feedback) vs.
      asynchronous (require file 4's OOB workflow).

### Cloud metadata quick paths

| Provider | Base | Required header/method | Credential path |
|---|---|---|---|
| AWS IMDSv1 | `169.254.169.254` | none | `/latest/meta-data/iam/security-credentials/<role>` |
| AWS IMDSv2 | `169.254.169.254` | `PUT /latest/api/token` + `X-aws-ec2-metadata-token` header | same path as v1, with token header |
| GCP | `metadata.google.internal` | `Metadata-Flavor: Google` header | `/computeMetadata/v1/instance/service-accounts/default/token` |
| Azure | `169.254.169.254` | `Metadata: true` header + `api-version` query param | `/metadata/identity/oauth2/token?api-version=2018-02-01&resource=<target>` |

### Blind confirmation quick steps
1. Generate unique Collaborator (or interactsh/self-hosted) subdomain.
2. Insert as `http://` payload in the candidate field (plain HTTP for dual DNS+HTTP
   signal).
3. Trigger the async flow (real event, or test-fire action if available).
4. Poll; interpret DNS-only vs. DNS+HTTP; record `Client IP` and `User-Agent`.
5. Escalate: check delivery-log endpoints for leaked response data; check timing
   oracle as fallback only.

### Internal pivot quick steps
1. Derive internal CIDR from metadata response or Collaborator `Client IP`.
2. Sweep common internal ports (22, 80, 443, 3000, 5432, 6379, 8080, 8443, 9200,
   27017; add 6443/2379/8081/50000 for Kubernetes/CI-heavy environments) against a
   small host range, using response/timing differential.
3. Check for unauthenticated internal admin dashboards first — highest hit rate.
4. Check recovered cloud credentials (from metadata) for direct API access before
   manual sweeping further.

### Severity framing notes
- Blind SSRF confirmed via OOB only, no further data/access: still report, but note
  what escalation was and wasn't achievable, and why (e.g., URL-only primitive
  couldn't satisfy IMDSv2 token step).
- SSRF with cloud credential recovery: high severity by default; scope the actual
  IAM/service-account permissions before claiming maximum impact.
- SSRF with internal service reachability confirmed but not exploited further
  (e.g., a database port found open): report reachability as the finding; don't
  overstate impact you didn't demonstrate.
- Two-hop SSRF via a third-party provider callback (file 2): explicitly distinguish
  this from same-origin SSRF in severity language — the trust boundary crossed is
  different and usually less severe.

## PortSwigger Web Security Academy — SSRF Lab Mapping

Mapped in strict Apprentice → Practitioner → Expert order, exactly as they appear
under the SSRF and Blind SSRF topics on the Academy.

| Order | Difficulty | Lab | Core technique it teaches | API-context relevance |
|---|---|---|---|---|
| 1 | Apprentice | Basic SSRF against the local server | Direct URL parameter pointing at `localhost`/internal loopback service | Foundational — maps directly onto the avatar/import synchronous-fetch pattern in file 2 |
| 2 | Apprentice | Basic SSRF against another back-end system | Reaching a second internal host on the same private network | Foundational for the internal pivot concept in file 5, though the lab's back-end is a fixed target rather than a swept range |
| 3 | Practitioner | SSRF with blacklist-based input filter | Bypassing a denylist of strings like `localhost`/`127.0.0.1` | General bypass technique — full coverage in Web Application Security — SSRF series; directly applicable if a webhook field applies naive string filtering (file 2) |
| 4 | Practitioner | SSRF with whitelist-based input filter | Bypassing an allowlist check via URL parsing inconsistencies (embedded credentials syntax, etc.) | Same as above — general bypass, referenced not duplicated |
| 5 | Practitioner | SSRF with filter bypass via open redirection vulnerability | Chaining an open redirect to reach a blocked destination | Directly relevant to file 2's egress-allowlist bypass discussion and file 3's note on redirect-based IMDS access when a primitive doesn't natively support headers |
| 6 | Practitioner (Blind SSRF sub-topic) | Blind SSRF with out-of-band detection | Using Collaborator to confirm a fire-and-forget SSRF (the lab uses a `Referer`-header-triggered back-end analytics fetch) | **Highest direct relevance to file 4** — this lab is the closest PortSwigger analogue to async webhook-delivery SSRF, even though the trigger mechanism (header-based, not a JSON body field) differs from the typical API case |
| 7 | Expert (Blind SSRF sub-topic) | Blind SSRF with Shellshock exploitation | Chaining blind SSRF into remote code execution via a Shellshock-vulnerable back-end | Demonstrates the "confirm, then escalate" pattern discussed in file 4's post-confirmation section, though the specific RCE vector (Shellshock) is dated and unlikely to appear in modern API backends |

### Honest gap disclosure

None of the PortSwigger SSRF labs are built around a JSON API request body or a
webhook-registration/async-delivery pattern specifically — every lab's vulnerable
parameter is a web-app-style form field, query string, or header, and every lab
resolves synchronously or via a directly observable mechanism. This means:

- Labs 1–5 transfer their *filter-bypass mechanics* directly and completely, but do
  not exercise the API-specific recon step (finding the vulnerable field inside a
  spec/JSON body) covered in file 2 — that recon skill has to be practiced against
  real or intentionally-vulnerable API targets, not these labs.
- Lab 6 is the best available analogue for the async/blind confirmation workflow in
  file 4, but its trigger (a `Referer` header read by a back-end analytics service)
  is structurally simpler than a true webhook-delivery-worker pattern — there is no
  PortSwigger lab that models the "register now, fires later on an unrelated event"
  timing structure described in file 1.
- None of the labs include a cloud metadata endpoint target (file 3) or an
  IMDSv2-style token-gated metadata service — PortSwigger's labs predate widespread
  IMDSv2 adoption in their design and, being self-contained lab environments, have no
  reason to simulate cloud metadata services at all.
- None of the labs involve a multi-host internal sweep (file 5) — each lab's
  "internal back-end system" is a single fixed, known target rather than something
  you have to discover.

### Supplementary practice: crAPI

Because of the gaps above, **crAPI (Completely Ridiculous API)** is the recommended
supplementary target for the API-specific angle of this series, consistent with its
use elsewhere in this note library. crAPI includes an SSRF-relevant flow around its
image/avatar-upload-by-URL feature (community/workshop endpoints), which is a closer
structural match to the webhook/avatar/import pattern in file 2 than any PortSwigger
lab. It does not natively include a cloud-metadata-service simulation either — for
that specific gap, standing up a local IMDS emulator (several open-source ones exist,
e.g. tools that mimic the AWS IMDSv1/v2 response format on `169.254.169.254` inside a
test VM or container) alongside a self-built vulnerable API endpoint is the most
realistic way to practice file 3's content hands-on, since no widely-used training
platform currently bundles this scenario.

## Cross-References

- Full technique detail for every lab's core bypass mechanic: Web Application
  Security — SSRF series.
- API-specific recon methodology not exercised by any lab above: file 2.
- Async/blind workflow detail beyond what Lab 6 models: file 4.
- Cloud metadata technique detail (no lab equivalent exists): file 3.
- Internal pivot methodology (no lab equivalent exists): file 5.
