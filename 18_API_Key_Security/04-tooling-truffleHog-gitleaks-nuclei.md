# API Key Security Testing — Tooling (truffleHog, gitleaks, nuclei)

This file covers the three dedicated tools used to automate the manual
techniques from File 2 (leakage discovery) and parts of File 3 (scope
probing). Read File 2 first — these tools automate detection, but you still
need the manual methodology to know what to do with a hit, judge false
positives, and understand what the tool *can't* see (custom key formats,
context-dependent scope issues).

## 1. truffleHog

### 1.1 What It Does and Why It's Different from grep

truffleHog scans git repositories (full history, not just the working tree)
and filesystems for secrets using two complementary detection strategies:
regex pattern matching against known credential formats (the same kind of
patterns built manually in File 2), and Shannon entropy analysis (the same
concept from File 3 Part A, but applied automatically across every string in
every file/commit rather than one key at a time). This is why truffleHog can
catch custom/in-house key formats that a pure regex-based scanner would miss
entirely — it flags any suspiciously high-entropy string, not just strings
matching a known provider pattern.

### 1.2 Installation

```
docker pull trufflesecurity/trufflehog:latest
```
- `docker pull` — the maintained, recommended installation path is the
  official Docker image rather than building from source, since it bundles
  the correct Go runtime and all detector definitions without local
  dependency management.
- `trufflesecurity/trufflehog:latest` — the official image name and tag; using
  `:latest` here since detector rules (new provider key formats) are updated
  frequently and you want current coverage for an engagement, but pin to a
  specific version tag in a CI/reproducible-scan context if consistent results
  across runs matter more than newest coverage.

### 1.3 Scanning a Git Repository (Full History)

```
docker run --rm -v "$(pwd):/repo" trufflesecurity/trufflehog:latest \
  git file:///repo --since-commit HEAD~200 --only-verified --json
```
- `docker run --rm` — run the container and automatically remove it on exit
  (`--rm`) so scan runs don't accumulate stopped containers.
- `-v "$(pwd):/repo"` — bind-mounts your current directory into the container
  at `/repo`, since the containerized truffleHog binary otherwise has no
  access to your local filesystem; `$(pwd)` inserts your current working
  directory's absolute path.
- `git file:///repo` — tells truffleHog to run its `git` scan mode against the
  local repository at the mounted path, using the `file://` URI scheme
  (truffleHog also accepts `https://` git URLs directly if you want it to
  clone the repo itself instead of scanning a local copy).
- `--since-commit HEAD~200` — limits history traversal to the last 200 commits
  rather than the entire repo history; useful on large/old repos to keep scan
  time reasonable during initial recon, and to be re-run without this flag
  (full history) once you've confirmed the tool works as expected on the
  target.
- `--only-verified` — this is one of truffleHog's most important flags:
  detected candidate secrets are not just pattern-matched, they're actively
  checked against the relevant provider's API to confirm the credential is
  currently live (e.g., an AWS key candidate gets a real, harmless
  authenticated API call attempted against AWS to confirm it's valid). This
  flag restricts output to only secrets confirmed live this way, which
  dramatically cuts false positives compared to pattern/entropy matching
  alone. Be aware this makes an outbound network call to the third-party
  provider for every candidate — confirm this is acceptable under your
  engagement's rules of engagement before using it, since it technically
  constitutes using the discovered credential (even if only for a harmless
  identity-check call).
- `--json` — output structured JSON instead of human-readable text, so results
  can be piped into other tooling or a report-generation script rather than
  manually parsed from console output.

### 1.4 Scanning a Filesystem (Not a Git Repo)

```
docker run --rm -v "$(pwd):/data" trufflesecurity/trufflehog:latest \
  filesystem /data --exclude-paths /data/.trufflehog-exclude.txt
```
- `filesystem /data` — switches scan mode from `git` to `filesystem`, which
  recursively walks a directory tree rather than parsing git objects/history
  — the mode you want for scanning downloaded JS bundles (File 2 Section 1),
  extracted mobile app binaries, or any non-git source tree.
- `--exclude-paths /data/.trufflehog-exclude.txt` — points to a file listing
  regex patterns of paths to skip (e.g., `node_modules/`, `vendor/`,
  `*.min.css`), reducing noise and scan time from vendored dependencies that
  are extremely unlikely to contain the target's own secrets and that would
  otherwise dominate scan time on a typical JS project.

### 1.5 Scanning a Public GitHub Organization Directly

```
docker run --rm trufflesecurity/trufflehog:latest \
  github --org=target-org --only-verified --json
```
- `github --org=target-org` — a dedicated scan mode that uses the GitHub API
  to enumerate and scan every public repository under the given organization,
  rather than requiring you to clone each repo manually first. Requires a
  GitHub token for reasonable API rate limits — pass one with
  `--token=<github-pat>` (omitted above for brevity, but effectively required
  for anything beyond a handful of small repos).
- Same `--only-verified` and `--json` reasoning as Section 1.3.

### 1.6 Interpreting Output and False Positives

Even with `--only-verified`, review each hit manually before reporting:
- Confirm the finding is genuinely in *scope* (a fork of an unrelated
  open-source project under the org's account is a common false-positive
  source for org-wide scans).
- Check whether the "verified" key is a test/sandbox-tier credential
  (`sk_test_` from File 1's table) rather than a production credential — still
  worth reporting, but at lower severity, and truffleHog's verification only
  confirms the key is *live*, not which tier it belongs to.
- Cross-reference the commit date against whether the repo/branch is still
  deployed — an old feature branch's leaked key for a service that's since
  been decommissioned is a different severity than one on `main`.

## 2. gitleaks

### 2.1 What It Does Differently from truffleHog

gitleaks is primarily a regex/rule-based scanner (it does support entropy
checks in custom rules, but its default and most common usage is
pattern-based) with a strong focus on speed, git-native integration (designed
to be dropped into CI as a pre-commit hook or pipeline gate), and a
highly customizable TOML rule configuration. Where truffleHog's strength is
active verification against providers, gitleaks' strength is fast, scriptable
scanning with rules you can tune precisely to a target's known key formats.
Run both where thoroughness matters — they don't have identical rule sets and
each catches things the other's default rules miss.

### 2.2 Installation

```
go install github.com/gitleaks/gitleaks/v8@latest
```
- `go install` — installs directly via the Go toolchain, which is the primary
  supported installation method; this compiles the binary from the module
  path and places it in your Go bin directory (typically `$GOPATH/bin` or
  `$HOME/go/bin` — ensure that's on your `PATH`).
- `github.com/gitleaks/gitleaks/v8` — the Go module path, with `/v8` reflecting
  the major version per Go's module versioning convention.
- `@latest` — installs the newest tagged release rather than a specific
  pinned version, same tradeoff noted for truffleHog in Section 1.2.

### 2.3 Scanning a Git Repository (Full History)

```
gitleaks git /path/to/repo --report-format json --report-path findings.json -v
```
- `git` — gitleaks' subcommand for scanning a git repository's full commit
  history (as opposed to `gitleaks dir` for a plain filesystem scan, or
  `gitleaks stdin` for piping arbitrary content in).
- `/path/to/repo` — the local path to the repository; gitleaks scans this
  in place rather than requiring a Docker-style mount.
- `--report-format json` — outputs structured JSON rather than the default
  colorized terminal summary, for the same downstream-parsing reason as
  truffleHog's `--json`.
- `--report-path findings.json` — writes the report to this file instead of
  (or in addition to) stdout, useful for archiving results as engagement
  evidence.
- `-v` — verbose mode, prints each finding to the console as it's found in
  addition to writing the final report, useful for watching progress on a
  large repo rather than waiting silently for the full scan to complete.

### 2.4 Scanning Only a Specific Commit Range

```
gitleaks git /path/to/repo --log-opts="--since=2024-01-01 --until=2024-06-01"
```
- `--log-opts` — passes arguments straight through to the underlying `git log`
  invocation gitleaks uses internally, letting you scope the scan using
  native git log filtering syntax rather than a gitleaks-specific flag.
- `--since=2024-01-01 --until=2024-06-01` — standard git date-range filters
  (these are git's own flags, not gitleaks'), useful when you have reason to
  believe a leak happened in a specific window (e.g., correlating with a known
  incident date or a specific developer's tenure) and want a faster, narrower
  scan than full history.

### 2.5 Scanning Uncommitted/Working Directory Changes (Pre-Commit Use Case)

```
gitleaks git /path/to/repo --pre-commit
```
- `--pre-commit` — restricts the scan to staged changes only, matching the
  intended use as a git pre-commit hook that blocks a commit before a secret
  ever reaches history in the first place. Worth knowing this flag exists even
  as an external tester/auditor, since it's the mechanism you'd recommend a
  client adopt as a remediation control after reporting a leaked-secret
  finding — prevention, not just detection.

### 2.6 Custom Rules for Target-Specific/Custom Key Formats

Default gitleaks rules cover major providers (matching File 1's table) but
won't catch an in-house/custom key format. Define a custom rule in a
`.gitleaks.toml` config:

```toml
[[rules]]
id = "target-custom-api-key"
description = "Target's internal API key format"
regex = '''target_(live|test)_[a-f0-9]{32}'''
tags = ["key", "target-app"]
```
- `[[rules]]` — TOML syntax for an array-of-tables entry, allowing multiple
  `[[rules]]` blocks in one config file, each defining a separate detector.
- `id` — a unique identifier for the rule, shown in findings output so you
  know which custom rule fired.
- `description` — human-readable explanation, shown in reports for context.
- `regex` — the actual detection pattern, here matching a hypothetical
  observed format like `target_live_a1b2c3...` (32 hex chars) — build this
  from a real confirmed sample of the target's key format found manually
  during File 2's discovery work, not guessed blindly.
- `tags` — free-form labels for filtering/categorizing findings when running
  large scans with many custom rules.

Run with the custom config:

```
gitleaks git /path/to/repo --config /path/to/.gitleaks.toml
```
- `--config` — points gitleaks at your custom TOML file instead of (by
  default, merging with) its built-in ruleset, ensuring the target-specific
  pattern is included in the scan.

### 2.7 Real-World Note

gitleaks is the more commonly seen tool in CI/CD pipelines specifically
because of its speed and native pre-commit hook design (Section 2.5) —
when you find evidence during an engagement that a client already runs
gitleaks in CI but a secret still leaked, that's itself worth noting in a
report (their gate has a gap, either an outdated ruleset missing a custom
key format per Section 2.6, or the hook isn't actually enforced/blocking on
all branches).

## 3. Nuclei Templates for API Key Detection

### 3.1 What Nuclei Adds Beyond truffleHog/gitleaks

truffleHog and gitleaks scan *source* (git repos, filesystems). Nuclei is a
request-based scanner — its relevant templates for this series scan *live
HTTP responses* for exposed keys, covering File 2 Section 3's error-message/
response-body leakage and Section 1's live-served-JS-bundle leakage, without
requiring you to have already downloaded and manually grepped every file.
It's the automation layer for the "check what's actually being served right
now" half of File 2, complementary to truffleHog/gitleaks automating the
"check source history" half.

### 3.2 Installation

```
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```
- Same `go install` pattern and version-pinning tradeoff as gitleaks
  (Section 2.2); `-v` here is nuclei's own install-time verbose flag for the
  build process, separate from any runtime flag.

### 3.3 Running Exposure/Secret-Focused Templates Against a Target

```
nuclei -u https://target.com -tags exposure,token,tokens -severity medium,high,critical -o nuclei-findings.txt
```
- `-u https://target.com` — the single target URL to scan; nuclei also accepts
  `-l targets.txt` for a list of URLs when scanning many hosts/subdomains at
  once (useful after a subdomain enumeration pass).
- `-tags exposure,token,tokens` — restricts the run to nuclei's community
  template library entries tagged with these categories, rather than running
  every template in the entire library (which includes many unrelated
  categories like CVE checks, misconfigurations, etc. that aren't relevant to
  this series). `exposure` and `token`/`tokens` are the tag categories
  covering hardcoded secret/key detection patterns.
- `-severity medium,high,critical` — filters out `info`/`low` severity
  template matches, keeping signal-to-noise reasonable on a first pass; drop
  this filter on a follow-up run if you want full coverage including lower-
  confidence matches.
- `-o nuclei-findings.txt` — writes results to a file for engagement evidence,
  same reasoning as the `--report-path`/`--json` flags in the other tools.

### 3.4 Running Against Discovered JS Bundle URLs Specifically

```
nuclei -l js-bundle-urls.txt -tags exposure -include-templates ~/nuclei-templates/exposures/apikey/
```
- `-l js-bundle-urls.txt` — a file with one JS bundle URL per line, e.g. the
  URLs enumerated manually via File 2 Section 1's `grep -oE 'src="[^"]+\.js"'`
  workflow, letting nuclei apply its detection templates directly against
  each live bundle URL instead of you manually curling and grepping each one.
- `-include-templates ~/nuclei-templates/exposures/apikey/` — explicitly
  points at the subdirectory of the community template repo containing
  API-key-specific exposure templates, useful when you want a tighter,
  faster run than the broader tag-based filter in Section 3.3.

### 3.5 Updating Templates Before a Scan

```
nuclei -update-templates
```
- `-update-templates` — pulls the latest community template definitions
  before scanning; run this before every engagement, since new provider key
  formats and new exposure patterns are added to the community repo
  regularly, and a stale local template set will silently miss recently-added
  detection patterns the same way an outdated gitleaks ruleset would (Section
  2.7's point applies here too).

### 3.6 Real-World Note

Nuclei's exposure templates are pattern-based (regex against response bodies),
so they inherit the same limitation flagged in File 2 for manual grep-based
searching — they won't catch a custom/in-house key format unless you write
a custom nuclei template for it, which follows the same YAML template
structure as the community templates (not covered in depth here, since
gitleaks' custom-rule workflow in Section 2.6 covers the same underlying
methodology of "build a detector from a confirmed real sample" — the
principle transfers directly even though the config syntax differs).

## WAF / API Gateway Relevance for This File

truffleHog and gitleaks operate entirely off-wire (git/filesystem scanning) —
same reasoning as File 2, not applicable. Nuclei is the one tool in this file
that does send live HTTP requests to the target, and at the volume of a full
template-tagged scan (Section 3.3), those requests can trigger rate-limiting
or WAF anomaly detection purely on request *volume*, even though the requests
themselves are simple GETs with no attack payload for a WAF signature to
match syntactically. If a nuclei scan against a defended target starts
returning `429`s or generic block-page responses partway through, that's the
volume-based crossover flagged in Files 1 and 3 — throttle nuclei's request
rate (`-rate-limit` flag) rather than treating it as a signature-bypass
problem, since there's no payload to disguise here.

## Cross-References

- **File 2** — the manual methodology these tools automate; read it first so
  you can judge tool output rather than trusting it blindly.
- **File 3** — Section 1.6/2.7's "verified but what tier/scope" question feeds
  directly into File 3 Part B's scope testing once a tool confirms a key is
  live.
- **File 5** — condensed flag reference for all three tools.
