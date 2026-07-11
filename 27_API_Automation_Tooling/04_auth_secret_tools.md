# API Security Testing Tooling — Authentication & Secret Discovery Tools

Cross-reference: JWT series for full attack theory (alg confusion, `none` alg, key
confusion, kid injection, weak secret cracking), API key security series for key
lifecycle/management theory. This file covers CLI tool mechanics only.

## 1. jwt_tool — JWT Attack Automation

jwt_tool (`ticarpi/jwt_tool`) is a Python CLI for decoding, tampering, cracking, and
attacking JSON Web Tokens across every major known attack class.

### 1.1 Installation
```
git clone https://github.com/ticarpi/jwt_tool.git && cd jwt_tool
pip install -r requirements.txt
python3 jwt_tool.py -h
```

### 1.2 Core Usage and Modes

```
python3 jwt_tool.py <JWT> [options]
```

**Basic decode (no flags beyond the token itself)**:
```
python3 jwt_tool.py eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123
```
Prints the decoded header and payload JSON, with no tampering — the default
inspection mode.

### 1.3 Attack Mode Flags (Full Breakdown)

- `-T`: **Tamper mode** — interactive mode that lets you edit each claim value one
  at a time via CLI prompts, then choose how to re-sign the result (matches the
  manual editing that Burp's JWT Editor does visually — see file 02).
- `-X <mode>`: **Exploit mode**, the primary automated-attack flag. Sub-modes:
  - `-X a`: **alg=none attack** — strips the signature and sets `alg` to `none`
    (and its case variants `None`, `NONE`, `nOnE`) to test if the server skips
    signature verification entirely for this algorithm value.
  - `-X n`: **Null signature attack** — sets the signature segment to an empty
    string while keeping a signing algorithm specified, testing a related but
    distinct verification-bypass path from `-X a`.
  - `-X k`: **Key confusion attack (RS256 → HS256)** — re-signs the token as HS256
    using a supplied RSA **public** key (via `-pk <file>`) as the HMAC secret. This
    tests whether the server, expecting RS256, can be tricked into verifying an
    HS256-signed token using its own public key as a shared secret (a classic
    algorithm-confusion vulnerability). Requires `-pk <path to PEM public key>`.
  - `-X i`: **kid (Key ID) injection** — lets you inject a payload into the `kid`
    header claim, testing for path traversal, SQL injection, or command injection
    in server-side key-lookup logic driven by the `kid` value. Combine with `-ju
    <value>` (below) to specify the exact injected `kid` string.
- `-C`: **Crack mode** — brute-forces a weak HMAC signing secret against a
  wordlist. Requires `-d <wordlist>`; e.g.:
  ```
  python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt
  ```
  Tries each wordlist line as the HMAC secret and reports a match if the resulting
  signature equals the token's actual signature — only meaningful against
  HS256/384/512-signed tokens.
- `-I`: **Injection/claim-tampering mode** — combine with `-hc <claim>=<value>` or
  `-pc <claim>=<value>` (below) to modify specific header or payload claims while
  keeping everything else intact, then re-sign.
- `-hc <claim>=<value>`: set/override a specific **header** claim (e.g., `-hc
  kid=../../../../dev/null`).
- `-pc <claim>=<value>`: set/override a specific **payload** claim (e.g., `-pc
  role=admin`, `-pc sub=1`).
- `-S <alg>`: specify the signing algorithm to use when re-signing a tampered token
  — `hs256`, `hs384`, `hs512`, `rs256`, `none`, etc.
- `-p <secret>`: the HMAC secret string to sign with (for HS256/384/512), when you
  already know or have cracked the secret.
- `-pk <file>`: path to a private key PEM file to sign with (for RS/ES/PS
  algorithms) — or, for the `-X k` key-confusion attack, the **public** key used as
  the HMAC secret.
- `-jw <file>`: path to a JWKS (JSON Web Key Set) file to use for signing/key
  lookups, when the target exposes a `/.well-known/jwks.json` endpoint you've
  downloaded locally.
- `-t <url>`: target URL — when provided, jwt_tool automatically fires the tampered
  token at this URL as the `Authorization: Bearer` header (or the header specified
  via `-rh`) and prints the server's response, turning jwt_tool into a full
  send-and-observe attack tool rather than just a token generator.
- `-rh "<header>: <value>"`: override which request header the tampered token is
  sent in (default `Authorization: Bearer <token>`) — use for APIs that pass JWTs
  via a custom header or cookie instead.
- `-rc "<name>=<value>"`: send the tampered token as a cookie instead of a header,
  specifying the cookie name.
- `-M <mode>`: **Scan mode** — `-M pb` (playbook scan) runs jwt_tool's full built-in
  battery of common JWT vulnerability checks (none-alg, weak secrets from its
  bundled small wordlist, common misconfigurations) against `-t <url>` in one
  command — the fastest way to get initial coverage before manual deep-diving:
  ```
  python3 jwt_tool.py <JWT> -t https://api.target.com/v1/profile -M pb
  ```
- `-cv`: **Claim value fuzzing** — combine with `-t` to auto-fuzz numeric/ID claims
  (e.g., incrementing `sub` or `user_id`) against the live target, useful for quick
  BOLA checks via JWT claim manipulation.

### 1.4 Real-World Notes

- Always run `-M pb` (playbook scan) first against a live target — it is the
  fastest way to rule in/out the most common misconfigurations (`none` alg, weak
  HMAC secret from a small built-in list) before investing time in manual `-X k`
  key-confusion or `-X i` kid-injection testing.
- The `-X k` key-confusion attack only works if you can obtain the server's RSA
  **public** key — commonly available via a `/.well-known/jwks.json` endpoint, an
  exposed `.pem`/`.crt` file, or the TLS certificate itself if the same key pair is
  reused (uncommon but has occurred in real engagements).
- For `-C` crack mode against real targets, rockyou.txt is a poor first choice for
  API signing secrets (it's built for human passwords, not machine-generated
  secrets) — prefer a wordlist of common default/example secrets (e.g., `secret`,
  `changeme`, project-name-derived guesses) or secrets found via truffleHog/gitleaks
  (below) against the target's own source code first.

## 2. truffleHog — Secret Discovery in Git History

truffleHog scans git repository history (not just the current working tree) for
committed secrets — API keys, JWT signing secrets, database credentials — using both
regex pattern matching and (in v3) live verification against the actual provider
API where possible.

### 2.1 Installation
```
# Go install (v3, recommended — includes verification)
go install github.com/trufflesecurity/trufflehog/v3@latest
```

### 2.2 Core Flags (Full Breakdown)

```
trufflehog git https://github.com/target-org/api-repo.git --only-verified --json
```

- `git <target>`: scan mode for a git repository. `<target>` can be a remote URL
  (cloned automatically) or a local path (`file:///path/to/repo`).
- `--only-verified`: **critical flag** — restricts output to secrets truffleHog
  successfully verified are live/active by making a real (safe, read-only) API call
  to the relevant provider (e.g., testing an AWS key against the AWS STS
  `GetCallerIdentity` API). Dramatically cuts noise from expired/rotated/fake-
  looking secrets — always start with this flag on large repos.
- `--json`: output as newline-delimited JSON, for piping into `jq` (file 07) or
  ingesting into a report pipeline.
- `--since-commit <hash>`: only scan commits after this hash — useful for
  incremental re-scans on repos you've already fully scanned once.
- `--branch <name>`: scan a specific branch only (default scans all branches
  reachable from HEAD, which can be slow on large multi-branch repos).
- `--max-depth <n>`: limit how many commits back in history to scan — trades
  thoroughness for speed on repos with very long histories.
- `other <path>`: (alternative scan mode) scan a local filesystem path directly
  (not git-aware — no history traversal, just scans files as they currently exist)
  — useful for scanning an extracted JS bundle, a downloaded mobile app's decompiled
  assets, or a directory of config files rather than a git repo.
- `s3 --bucket <name>`: scan mode for an AWS S3 bucket (if scope permits, checking
  for secrets left in publicly/improperly accessible buckets — cross-reference the
  API key security series for storage-related exposure).
- `github --org <org>` / `github --repo <owner/repo>`: GitHub-native scan mode —
  requires `--token <github_pat>` for authenticated scanning of private repos in
  scope, and can enumerate and scan every repo in an org in one command.
- `--concurrency <n>`: number of concurrent workers, for tuning scan speed against
  large repos or rate-limited scan targets (like GitHub's API).
- `--filter-entropy <n>`: sets the Shannon entropy threshold for truffleHog's
  legacy high-entropy-string detector (a supplementary detection method alongside
  its regex detectors) — lower values catch more candidates at the cost of more
  false positives.

### 2.3 Real-World Notes

- `--only-verified` is the single most important flag for engagement efficiency —
  unverified regex-only output on a real-world repo is frequently 90%+ false
  positives (test fixtures, example `.env.sample` files, documentation snippets).
  Only fall back to unverified/full output when the provider doesn't support
  truffleHog's verification (e.g., a bespoke internal API key format) and you need
  to manually triage.
- Any secret found here (especially JWT signing secrets or API keys) should be fed
  directly into jwt_tool's `-p`/`-C` flags or the API key security series'
  methodology, not just reported in isolation — a leaked signing secret often
  enables full authentication bypass.

## 3. gitleaks — Secret Discovery (Alternative/Complementary Scanner)

gitleaks is another git-history secret scanner, commonly used alongside truffleHog
since the two use different detection rule sets and occasionally catch different
findings on the same repo.

### 3.1 Installation
```
# Go install
go install github.com/gitleaks/gitleaks/v8@latest
```

### 3.2 Core Flags (Full Breakdown)

```
gitleaks detect --source /path/to/repo --report-format json \
                 --report-path gitleaks-report.json --verbose
```

- `detect`: gitleaks' primary scan subcommand (scans git history of a local repo).
- `--source <path>`: path to the local git repository to scan (gitleaks does not
  clone remote URLs directly the way truffleHog does — clone first with `git
  clone`).
- `--report-format <fmt>`: output format — `json`, `csv`, `sarif` (SARIF is useful
  for direct ingestion into CI/CD security dashboards like GitHub's Security tab).
- `--report-path <file>`: file to write the report to.
- `--verbose`: print each finding to stdout as it's found, in addition to writing
  the report file.
- `--redact`: redact the actual secret value from the output report (shows only
  the finding's location/rule/context) — use when generating a report that will be
  shared more broadly than the immediate testing team, to avoid the report itself
  becoming a secret-leak vector.
- `--config <file>`: path to a custom `gitleaks.toml` rules file — use to add
  target-specific secret patterns (e.g., a known internal API key format like
  `ACME_[A-Z0-9]{32}`) beyond gitleaks' bundled default ruleset.
- `--baseline-path <file>`: path to a previous scan's report to diff against — only
  reports *new* findings not present in the baseline, essential for CI integration
  on a repo you've already triaged once (avoids re-flagging accepted-risk findings
  every run).
- `--no-git`: scan the target path as a plain directory rather than a git
  repository (equivalent use-case to truffleHog's `other` mode) — for scanning
  extracted archives, decompiled mobile apps, or non-git directories.
- `--log-opts "<git log options>"`: pass raw `git log` options through to scope the
  scan (e.g., `--log-opts="--since=2025-01-01"` to only scan commits after a date,
  or `--log-opts="branch1..branch2"` to scan a specific commit range).
- `protect --staged`: a separate subcommand for pre-commit-hook usage (scans only
  staged changes, not full history) — mentioned here for completeness since teams
  building their own API sometimes ask pentesters to review their gitleaks
  pre-commit setup as part of a secure SDLC assessment, not primarily an attacker-
  side tool.

### 3.3 Real-World Notes

- Run both truffleHog and gitleaks against the same repo when secret discovery is
  in scope — their differing rule sets and verification approaches (truffleHog's
  live API verification vs gitleaks' broader default regex rule library) produce a
  meaningfully different result set, not just duplicate confirmation.
- Both tools scan **full git history**, including commits that were later reverted
  or force-pushed over — a secret removed in a later commit is often still fully
  recoverable from history unless the repo's history itself was rewritten
  (`git filter-repo`/BFG) and force-pushed, which most target orgs never do.
