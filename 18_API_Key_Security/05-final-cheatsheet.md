# API Key Security Testing — Final Cheatsheet

Condensed quick-reference. This is not a substitute for Files 1–4 — read those
first for the mechanism/reasoning behind each item. Use this during an active
engagement once you already understand *why* each check matters.

## Key Format Recognition (Quick Table)

| Provider | Prefix | Length |
|---|---|---|
| AWS Access Key ID | `AKIA` / `ASIA` | 20 |
| Google API Key | `AIza` | 39 |
| Stripe Secret | `sk_live_` / `sk_test_` | ~24-107 |
| GitHub PAT (classic / fine-grained) | `ghp_` / `github_pat_` | 40 / variable |
| Slack | `xoxb-` / `xoxp-` / `xoxs-` | variable |
| SendGrid | `SG.` | ~69 |
| Mailgun | `key-` | 32 hex + prefix |

Unknown/custom format → use entropy analysis, not pattern matching.

## Testing Checklist by Phase

### Phase 1 — Leakage Discovery
- [ ] Enumerate all JS bundles (initial HTML + lazy-loaded chunks via
      Network tab); grep for provider prefixes and generic
      `key|secret|token` variable patterns.
- [ ] Check for source maps (`.js.map`) to de-minify context around any hit.
- [ ] `git grep` across `$(git rev-list --all)` if repo is cloned.
- [ ] `git log --all --full-history -- "**/.env"` (and similar sensitive
      filenames) for deleted-but-recoverable secrets.
- [ ] GitHub dork: `org:target-org "AKIA" in:file`,
      `filename:.env "api_key"`, `filename:.postman_environment.json`.
- [ ] Trigger verbose errors (malformed input, wrong content-type) and inspect
      full response bodies, not just rendered UI fields.
- [ ] Check integration/settings/webhook GET endpoints for unmasked stored
      keys.
- [ ] DevTools Network tab: filter Fetch/XHR, check full URLs (query
      strings), headers, and response bodies across every app feature.
- [ ] Search Postman public network + GitHub for exposed
      `.postman_collection.json` / `.postman_environment.json`.

### Phase 2 — Entropy / Predictability
- [ ] Collect multiple key samples if possible (test accounts, key
      regeneration).
- [ ] Visual inspection for sequential/timestamp patterns before formal
      analysis.
- [ ] Shannon entropy calc on individual keys (informative but not
      sufficient alone).
- [ ] Cross-sample comparison to detect a generation pattern (more reliable
      than single-key entropy).
- [ ] If sequential suspected: small, deliberate candidate-key test batch —
      escalate to Rate Limit/Bot Bypass engagement if a real brute-force
      becomes necessary; don't run large-volume guessing silently.

### Phase 3 — Scope / Permission
- [ ] Establish documented/expected scope (provider docs or UI context of
      issuance).
- [ ] Test read access outside documented scope (systematically, across all
      enumerated endpoints).
- [ ] Test write/destructive methods even against a "read-only" key —
      highest-value check in this phase.
- [ ] Test cross-tenant/cross-resource access via ID substitution (BOLA
      overlap).
- [ ] Test key-tier substitution — does an endpoint check key *class*, or
      just key *validity*?

### Phase 4 — Rotation Gap
- [ ] Generate → confirm working → revoke through platform's own
      UI/API → note exact revocation timestamp.
- [ ] Immediately retest revoked key.
- [ ] If immediate retest fails correctly, retest at intervals (1 min / 5
      min / 30 min) to characterize any cache-TTL-based gap window.
- [ ] Repeat for "rotate" (new key issued) separately from pure "revoke" —
      different code paths, test both.

## Command Quick Reference

```bash
# JS bundle enumeration
curl -s https://target.com/ | grep -oE 'src="[^"]+\.js"'

# Grep bundle for AWS-shaped key
grep -EoI '(AKIA|ASIA)[0-9A-Z]{16}' main.js

# Generic secret-variable pattern
grep -EoI '(api[_-]?key|apikey|secret|token|auth)["\047]?\s*[:=]\s*["\047][A-Za-z0-9_\-\.]{16,}["\047]' main.js

# Git full-history grep
git grep -nE '(AKIA|ASIA)[0-9A-Z]{16}' $(git rev-list --all)

# Find deleted .env across all history
git log --all --full-history -- "**/.env"

# View file as of a specific commit
git show <commit-hash>:path/to/.env

# GitHub dork (org-scoped)
org:target-org "AKIA" in:file

# Shannon entropy of a key
python3 -c "
import math, collections
s = 'PASTE_KEY_HERE'
counts = collections.Counter(s)
length = len(s)
entropy = -sum((c/length) * math.log2(c/length) for c in counts.values())
print(f'{entropy:.3f} bits/char, {entropy*length:.1f} bits total')
"

# Sequential key candidate sweep (small, deliberate batch only)
for i in $(seq -f "%05g" 1 20); do
  curl -s -o /dev/null -w "%{http_code} key_${i}\n" \
    -H "X-API-Key: key_${i}" https://target.com/api/v1/whoami
done

# Scope test — out-of-scope read
curl -s -o /dev/null -w "%{http_code}\n" -H "X-API-Key: <key>" \
  https://target.com/api/v1/admin/users

# Scope test — write on supposedly read-only key
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE \
  -H "X-API-Key: <key>" https://target.com/api/v1/orders/12345

# Rotation gap — immediate retest
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "X-API-Key: <revoked-key>" https://target.com/api/v1/whoami

# Rotation gap — delayed retest
sleep 300 && curl -s -o /dev/null -w "%{http_code}\n" \
  -H "X-API-Key: <revoked-key>" https://target.com/api/v1/whoami
```

```bash
# truffleHog — git full history, only verified live secrets
docker run --rm -v "$(pwd):/repo" trufflesecurity/trufflehog:latest \
  git file:///repo --since-commit HEAD~200 --only-verified --json

# truffleHog — filesystem scan
docker run --rm -v "$(pwd):/data" trufflesecurity/trufflehog:latest \
  filesystem /data --exclude-paths /data/.trufflehog-exclude.txt

# truffleHog — full GitHub org
docker run --rm trufflesecurity/trufflehog:latest \
  github --org=target-org --only-verified --json

# gitleaks — full history
gitleaks git /path/to/repo --report-format json --report-path findings.json -v

# gitleaks — date-range scoped
gitleaks git /path/to/repo --log-opts="--since=2024-01-01 --until=2024-06-01"

# gitleaks — pre-commit / staged only
gitleaks git /path/to/repo --pre-commit

# gitleaks — custom rule config
gitleaks git /path/to/repo --config /path/to/.gitleaks.toml

# nuclei — update templates first, always
nuclei -update-templates

# nuclei — exposure/token tagged templates against a target
nuclei -u https://target.com -tags exposure,token,tokens \
  -severity medium,high,critical -o nuclei-findings.txt

# nuclei — against a list of discovered JS bundle URLs
nuclei -l js-bundle-urls.txt -tags exposure \
  -include-templates ~/nuclei-templates/exposures/apikey/
```

## Severity Judgment Quick Guide

| Finding | Typical severity driver |
|---|---|
| Leaked test-tier key (`sk_test_`) | Low — confirm it truly can't touch production |
| Leaked live-tier key, narrow scope confirmed | Medium |
| Leaked live-tier key, broad/write scope confirmed | High–Critical |
| Sequential/predictable key generation (design flaw) | High — affects *all* keys, not just one instance |
| Revoked key still functional (rotation gap) | Medium–High depending on window length and access |
| Key-tier substitution (low-tier reaching high-tier endpoints) | High–Critical |

Always report leakage and the resulting access/scope as chained but
**separate** findings, per File 1 Section 4 — don't collapse "found a key"
and "the key had admin access" into a single bug entry.

## PortSwigger Lab Quick List (Apprentice → Practitioner → Expert)

- Information Disclosure, Apprentice: Information disclosure in error messages
- Information Disclosure, Practitioner: Information disclosure via version
  control history
- Access Control, Apprentice: Unprotected admin functionality / User role
  controlled by request parameter
- Access Control, Practitioner: Multi-step process with no access control on
  one step
- Authentication, Practitioner: Broken brute-force protection labs

**Gap disclosure:** PortSwigger has no dedicated API-key topic and no lab for
JS-bundle key hunting, Postman/GitHub dorking, entropy/predictability
testing, or key-tier privilege escalation specifically. Supplement with
HackTheBox API-focused challenges/machines for those, and disclosed
HackerOne reports for real-world severity calibration.

## Cross-References

Full reasoning, mechanism explanations, and flag-by-flag breakdowns live in:
- `01-overview-and-api-key-types.md`
- `02-leakage-discovery-methodology.md`
- `03-entropy-scope-rotation-testing.md`
- `04-tooling-truffleHog-gitleaks-nuclei.md`
