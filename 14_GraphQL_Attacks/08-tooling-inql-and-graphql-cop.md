# Tooling: InQL and graphql-cop

File 8 of 9. Assumes the whole series so far — this file exists to give you
full setup and flag-by-flag command breakdowns for the two dedicated
GraphQL security tools referenced throughout files 2–7, so you're not
treating them as black boxes.

---

## Part A — InQL (Burp Suite extension)

### A1. What it does and why it matters

InQL is a Burp Suite extension purpose-built for GraphQL testing. It
directly automates the manual work described in file 2 (schema
extraction, including a Clairvoyance-based fallback for when introspection
is disabled) and file 3 (batch/alias attack generation), and gives you a
dedicated GraphQL-aware view inside Burp's normal message editor. Treat it
as your primary daily-driver tool for GraphQL engagements; graphql-cop
(Part B) complements it as a fast, scriptable vulnerability checklist
runner rather than a replacement.

### A2. Setup

Requirements: Burp Suite (Professional or Community edition — support
targets the most recent Burp version), and Java 17+ for the current
Montoya-API-based version of the extension.

```bash
# Install Java 17+ if not already present
sudo apt install -y openjdk-17-jdk
java --version

# Clone and build
git clone https://github.com/doyensec/inql
cd inql
```

Building the project produces a `InQL.jar` (or similarly named) file in the
repo root. Load it into Burp:

1. Burp → **Extensions** tab → **Installed** → **Add**.
2. Extension type: **Java**.
3. Extension file: point to the built `.jar`.
4. Confirm the Burp Extender output panel shows the extension loaded
   successfully — a startup message confirms it.

InQL also ships as a standalone Python/Jython CLI/UI that doesn't require
Burp at all (useful for headless/CI use, or a quick schema dump without
opening the full Burp UI):

```bash
pip install inql
```

### A3. Core workflow inside Burp

Once loaded, InQL adds:

- **A dedicated "GraphQL (InQL)" tab** on Burp's native message editor for
  any request Burp detects as GraphQL — separates the query from variables,
  and applies schema-aware syntax highlighting, directly replacing the
  manual "read raw JSON body" workflow from earlier files.
- **A Scanner panel** — the core feature. Point it at a live GraphQL
  endpoint URL or an existing introspection JSON file, and it:
  - Runs (or accepts an existing) introspection query.
  - Auto-generates ready-to-send query, mutation, and subscription
    templates for every operation in the schema — this is the automated
    equivalent of manually reading through file 2's introspection output
    and building queries by hand for each interesting field/mutation you
    found.
  - Offers customizable scan options: **query depth** (how deeply to
    auto-expand nested selections when generating templates — directly
    relevant background for file 4's depth-attack payloads, since InQL can
    generate a maximally-deep template for you as a starting point rather
    than hand-writing one), indentation, and **points-of-interest
    analysis** to help you triage which generated queries look most worth
    manual attention.
  - Implements **circular reference / cycle detection** on the schema,
    surfacing potentially-vulnerable query paths directly in the scan
    results — this is InQL doing the type-graph cycle analysis from file
    4, section 1 automatically instead of you tracing it by hand.
  - If introspection is disabled, InQL's scanner falls back to a
    Clairvoyance-based schema-reconstruction mode using the field-suggestion
    leakage technique from file 2, section 7 — confirming that
    Clairvoyance-style suggestion-based extraction is exactly what's running
    under the hood here, not a separate independent technique.
- **A "Batch Queries" panel** (also referred to as the Attacker tab in
  older versions) — lets you run batch/alias-based GraphQL attacks directly
  from the UI, i.e. an automated implementation of file 3's manual
  alias-generation script. Useful for quickly testing whether an endpoint
  tolerates high alias counts (a rate-limit-bypass smoke test) without
  writing your own generator script first.
- **Send to Repeater / Send to GraphiQL** — any auto-generated template can
  be sent directly to Burp Repeater for manual editing and follow-up
  attacks (e.g. taking a generated mutation template and manually applying
  the BOLA/BFLA testing methodology from file 5), or to an embedded
  GraphiQL console for interactive, autocomplete-assisted query building.
- **Custom headers per domain** — the domain list auto-populates from
  observed Burp traffic, so you can set an `Authorization` header once per
  target domain rather than re-adding it to every request manually.
- **Schema visualization** — send the analyzed schema to embedded GraphiQL
  or GraphQL Voyager servers for a browsable graph view, addressing file
  2 section 5's suggestion to visualize rather than read raw JSON.

### A4. Standalone CLI usage and flag breakdown

The standalone `inql` CLI (installed via `pip install inql`, no Burp
required) is useful for scripted/headless schema dumps and documentation
generation:

```
usage: inql [-h] [-t TARGET] [-f SCHEMA_JSON_FILE] [-k KEY] [-p PROXY]
            [--header HEADERS HEADERS] [-d] [--generate-html]
            [--generate-schema] [--generate-queries] [--insecure]
            [-o OUTPUT_DIRECTORY]
```

Flag-by-flag:
- `-t TARGET` — the remote GraphQL endpoint URL to introspect
  (`https://target/graphql`). Mutually usable alongside `-f` if you already
  have a saved schema and just want to regenerate documentation from it.
- `-f SCHEMA_JSON_FILE` — use a previously-saved introspection result (JSON)
  instead of hitting the network again; useful when you've already run
  introspection manually (file 2) or via Burp and just want InQL's
  documentation/template generation applied to that existing data.
- `-k KEY` — an API authentication key/token to include when introspecting
  a target that requires auth to even reach the schema.
- `-p PROXY` — route the introspection request through a proxy
  (`http://127.0.0.1:8080`), e.g. to capture InQL's own introspection
  traffic in Burp for inspection/logging.
- `--header HEADERS HEADERS` — add a custom header (name and value as two
  arguments) to the introspection request; repeatable for multiple headers.
- `-d` — replace known GraphQL argument types with placeholder values in
  generated templates (e.g. a `String!` argument becomes a literal
  placeholder string) — specifically useful because it produces
  immediately-syntactically-valid templates ready to paste into Burp
  Repeater without manual placeholder cleanup first.
- `--generate-html` — output an HTML documentation page listing every
  Query/Mutation/Subscription with types and arguments — good deliverable
  to attach directly to a pentest report appendix as evidence of full API
  surface enumeration.
- `--generate-schema` — output the schema as a JSON documentation file.
- `--generate-queries` — output ready-to-use query template files, one per
  operation, mirroring what the Burp Scanner panel generates interactively.
- `--insecure` — accept any TLS certificate, needed for lab/staging
  environments with self-signed certs.
- `-o OUTPUT_DIRECTORY` — where generated documentation/templates are
  written.

Typical usage:

```bash
inql -t https://target.example/graphql --generate-html --generate-queries -o ./inql-output
```

This introspects the live target and drops both an HTML documentation
report and per-operation query template files into `./inql-output` — a fast
way to get file 2's full schema-extraction payoff into a reviewable,
report-ready format in one command.

---

## Part B — graphql-cop

### B1. What it does and why it matters

graphql-cop (by Dolev Farhi and Nick Aleks) is a lightweight, scriptable
Python CLI that runs a fixed battery of known GraphQL security checks
against a target and reports findings with severity ratings — think of it
as a GraphQL-specific vulnerability checklist runner, complementary to
InQL's more interactive, exploration-oriented workflow. It's the fastest
way to get an initial signal on an engagement before doing manual testing
per files 2–6.

### B2. Setup

```bash
git clone https://github.com/dolevf/graphql-cop.git
cd graphql-cop
python3 -m venv path/to/venv
source path/to/venv/bin/activate
python3 -m pip install -r requirements.txt
```

Breakdown: the first command creates an isolated Python virtual
environment so graphql-cop's dependencies don't conflict with anything else
on your system; the second activates it; the third installs everything
listed in `requirements.txt`.

Docker is also supported as an alternative, avoiding the venv setup
entirely:

```bash
docker run --rm -it graphql-cop:latest -t <GRAPHQL_ENDPOINT> -H '{"<HEADER_KEY>": "<HEADER_VALUE>"}'
```

### B3. Full flag breakdown

```
Usage: graphql-cop.py -t http://example.com -o json

Options:
  -h, --help              show this help message and exit
  -t URL, --target=URL    target url with the path - if a GraphQL path is
                          not provided, GraphQL Cop will iterate through a
                          series of common GraphQL paths
  -H HEADER, --header=HEADER
                          Append Header(s) to the request
                          '{"Authorization": "Bearer eyjt"}' - use multiple
                          -H for additional Headers
  -o FORMAT, --output=FORMAT
                          json
  -e EXCLUDED_TESTS, --excluded-tests=EXCLUDED_TESTS
                          Exclude specific tests (comma separated)
  -l, --list-tests        List available tests
  -f, --force             Forces a scan when GraphQL cannot be detected
  -d, --debug             Append a header with the test name for debugging
  -x PROXY, --proxy=PROXY
                          HTTP(S) proxy URL, e.g. http://127.0.0.1:8080
  -T, --tor               Enable Tor proxy
  -v, --version           Print out the current version and exit
```

Flag-by-flag explanation:

- **`-t URL`** — the target. If you give it a bare host without a GraphQL
  path, graphql-cop automatically tries a list of common GraphQL paths
  itself (`/graphql`, `/api`, etc. — the same universal-endpoint-discovery
  step described in file 2, section 2, automated for you). Give it the full
  path directly if you already know it, to skip the discovery pass.
- **`-H HEADER`** — attach a header, formatted as a JSON object string.
  Essential for authenticated testing — repeat `-H` for multiple headers
  (e.g. `Authorization` plus a custom `X-Tenant-ID`).
- **`-o FORMAT`** — currently supports `json` output, which dumps full
  structured results including, for each finding, a ready-to-run **cURL
  reproduction command** — genuinely useful for pasting straight into a
  report as evidence, since it's the exact request that triggered the
  finding, not a paraphrase.
- **`-e EXCLUDED_TESTS`** — comma-separated list of test names to skip, for
  when a specific check is noisy, not applicable, or you've already
  verified it manually and don't want it re-flagged in output.
- **`-l, --list-tests`** — prints the full list of available test names
  (useful before using `-e`, so you know the exact names to exclude).
- **`-f, --force`** — forces the scan to proceed even if graphql-cop's own
  detection logic doesn't recognize the target as GraphQL — use this if
  you've independently confirmed a GraphQL endpoint (via the `__typename`
  probe from file 2) but graphql-cop's own path-based detection missed it,
  e.g. because the endpoint is at a nonstandard path with no common-path
  match.
- **`-d, --debug`** — appends a header naming the specific test being run
  to each request, useful when correlating graphql-cop's traffic against
  your own Burp proxy history during a run.
- **`-x PROXY`** — routes all graphql-cop traffic through a proxy, most
  commonly `http://127.0.0.1:8080` to capture every check it runs inside
  Burp for manual follow-up on anything interesting.
- **`-T, --tor`** — routes traffic through Tor.
- **`-v, --version`** — prints the tool version.

### B4. Basic usage and reading output

```bash
python3 graphql-cop.py -t https://target.example/graphql
```

Example output:

```
[HIGH] Introspection Query Enabled (Information Leakage)
[LOW] GraphQL Playground UI (Information Leakage)
[HIGH] Alias Overloading with 100+ aliases is allowed (Denial of Service)
[HIGH] Queries are allowed with 1000+ of the same repeated field (Denial of Service)
```

Each line maps directly onto a topic already covered in this series:
- **Introspection Query Enabled** — file 2.
- **GraphQL Playground UI** — an exposed interactive query console
  (GraphiQL/Playground), itself an information-leakage finding since it
  typically ships with introspection-driven autocomplete and documentation
  browsing built in, functionally handing an attacker the same schema
  access as file 2's manual introspection, through a friendly UI.
- **Alias Overloading** — file 3's aliasing technique, confirmed
  practically exploitable at 100+ aliases in one request.
- **Field Duplication** ("Queries are allowed with N+ of the same repeated
  field") — a width-based DoS check closely related to file 4's
  complexity-attack coverage, testing repeated (non-aliased) field
  requests specifically.

Other tests in graphql-cop's battery worth knowing by name (visible via
`-l`) map onto earlier files directly:
- **Array-based Query Batching** — the array-of-operations batching
  mechanism from file 3, section 3, tested independently from
  alias-based batching.
- **Directive Overloading** — repeated duplicated directives
  (`@aa@aa@aa...`) in one query, a DoS variant adjacent to file 4's
  depth/complexity attacks but targeting directive processing specifically
  rather than field nesting.
- **Field Suggestions** — the field-suggestion leakage technique from file
  2, section 7, confirming automatically whether the target is vulnerable
  to that specific bypass.
- **Introspection-based Circular Query** — schema-cycle detection feeding a
  generated circular query, the automated equivalent of file 4's
  self-referential-type depth attack.
- **GET Method Query Support** / **POST-based URL-encoded query support**
  — checks for the alternate-transport introspection bypasses from file 2,
  section 6b, flagged here as a possible CSRF concern (since GET-based
  state-changing GraphQL requests are CSRF-able in ways POST-with-JSON
  typically isn't, due to how browsers handle simple GET requests
  cross-site).

### B5. Excluding tests and getting JSON output

```bash
python3 graphql-cop.py -t https://target.example/graphql -e field_duplication
python3 graphql-cop.py -t https://target.example/graphql -o json
```

The first skips the field-duplication check specifically (useful if it's
noisy against a target with legitimately large valid result sets and you
want cleaner signal on everything else). The second switches to full JSON
output, which includes each finding's `curl_verify` field — a
complete, copy-pasteable `curl` command reproducing the exact request that
triggered the finding, directly usable as report evidence without you
having to reconstruct it by hand.

---

## Part C — how these two tools fit into your overall workflow

Recommended order for a new GraphQL target:

1. **graphql-cop first** — fast, low-effort initial signal across the
   whole vulnerability battery (files 2, 3, 4 topics all get an automated
   first pass in under a minute).
2. **InQL Scanner next** — full schema extraction (live introspection, or
   Clairvoyance fallback if graphql-cop's introspection check came back
   negative), template generation, and cycle detection, feeding directly
   into your manual BOLA/BFLA testing (file 5) and injection testing
   (file 6) using the generated, ready-to-edit templates as your starting
   point instead of hand-building every query.
3. **Manual follow-up in Burp Repeater/Intruder** on anything graphql-cop
   or InQL flagged, applying the specific methodology from the
   corresponding file in this series — neither tool replaces the manual
   authorization-testing workflow in file 5, since that requires business
   context and multi-account testing that no automated scanner can do for
   you.

---

## Summary checklist for this file

- [ ] InQL installed and loaded into Burp (or standalone CLI available for
      headless use).
- [ ] graphql-cop installed in a venv, verified with `-h`.
- [ ] Run graphql-cop with `-o json` and archive the output (with
      `curl_verify` commands) as first-pass evidence.
- [ ] Run InQL Scanner against the target; use Clairvoyance fallback mode
      if introspection is disabled.
- [ ] Use InQL's generated templates as the starting point for manual
      testing per files 3–6, rather than hand-writing every query from
      scratch.

**Next: file 9 — Final Cheatsheet and Lab Mapping**, the last file in the
series, consolidating quick-reference material and mapping every
PortSwigger GraphQL lab to the file in this series that covers it.
