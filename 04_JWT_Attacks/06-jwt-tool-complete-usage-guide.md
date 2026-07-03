# 06 — jwt_tool: Complete Flag-by-Flag Usage Guide

## About This File

This file is a standalone reference for jwt_tool (https://github.com/ticarpi/jwt_tool),
consolidating every flag used across files 2–5 plus additional modes not
otherwise covered, each broken down individually. Use this file as the
lookup reference while working through the attack files rather than reading
it start to finish.

## Installation

```bash
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
pip3 install -r requirements.txt
python3 jwt_tool.py -h
```

- `git clone ...` — pulls the tool's source repository.
- `pip3 install -r requirements.txt` — installs Python dependencies
  (`pycryptodome`, `requests`, `termcolor`, etc.) listed in the repo's
  requirements file.
- `python3 jwt_tool.py -h` — prints the help menu, confirming a working
  install and listing all available flags.

## Core Invocation Pattern

```bash
python3 jwt_tool.py <token> [mode flag] [options]
```

- `<token>` — the target JWT, supplied as a positional argument, either
  pasted directly or read via `-t` from a request (see the request-based
  usage below).

## Basic Inspection (No Attack)

```bash
python3 jwt_tool.py <token>
```

With no additional flags, jwt_tool simply parses and pretty-prints the
header and payload, and reports the detected signing algorithm — useful as a
first step on any captured token before deciding which attack file applies.

## Mode Flags (the `-X` Family — Automated Exploit Modes)

`-X` selects a pre-built exploit mode. Each letter after `-X` corresponds to
a distinct, fully automated attack:

| Flag | Attack | Covered In |
|------|--------|-----------|
| `-X a` | `alg:none` attack — generates all case-variant `none` algorithm forgeries | File 2, Part A |
| `-X k` | Algorithm confusion (RS256→HS256, etc.) using a supplied public key as the HMAC secret | File 3 |
| `-X i` | Header injection — used for both JWK injection and `kid` injection (path traversal / SQLi), depending on which additional flags are combined with it | File 4 |
| `-X s` | Signature-stripping / null-signature testing, checking whether the server verifies the signature at all | File 2, related to Part A |

Each `-X` mode typically requires an accompanying key or secret flag (below)
depending on the target algorithm.

## Key and Secret Flags

| Flag | Meaning |
|------|---------|
| `-S <alg>` | Sets the signing algorithm to use when producing the output token, e.g. `-S hs256`, `-S rs256`, `-S none`. This controls what jwt_tool writes into the `alg` header of the forged token and which signing routine it runs. |
| `-p "<secret>"` | Supplies a plaintext HMAC secret/password, used for signing (once you have a secret, e.g. from cracking) or for the `-C` cracking mode's dictionary target. |
| `-pk <keyfile>` | Supplies a key **file** — either a private key (to actually sign, e.g. for RS256/PS256 forgery or JWK injection) or a public key (for the algorithm-confusion HMAC-secret use case in file 3). jwt_tool infers usage from the selected `-X` mode. |
| `-ju "<field>=<value>"` | Sets or injects an arbitrary **header** field/value pair — used for `kid` injection (file 4, Part B) and for manually crafting JWK-related fields. Can be repeated for multiple fields. |
| `-jp "<field>=<value>"` | Same as `-ju` but targets the **payload** instead of the header — used for scripted/non-interactive claim edits as an alternative to `-T`'s interactive prompts. |

## Cracking Mode

```bash
python3 jwt_tool.py <token> -C -d <wordlist>
```

- `-C` — activates dictionary-based secret cracking against an HS256-signed
  token (file 2, Part B, Method 2).
- `-d <wordlist>` — path to the wordlist file used as the source of
  candidate secrets.

## Tamper Mode (Interactive Claim Editing)

```bash
python3 jwt_tool.py <token> -T
```

- `-T` — launches an interactive prompt that walks through every header and
  payload field, letting you accept the existing value or type a new one,
  then re-encodes and (if a signing flag is also supplied) re-signs the
  result. This is the primary mode used throughout file 5 for claim
  manipulation.

Combine with signing flags to produce an immediately usable forged token in
one command:

```bash
python3 jwt_tool.py <token> -T -S hs256 -p "recovered_secret"
```

## Playbook Mode (Automated Full Scan)

```bash
python3 jwt_tool.py <token> -M pb
```

- `-M pb` — runs jwt_tool's built-in "playbook" scan: automatically attempts
  a broad set of known attacks (none-alg variants, common weak secrets,
  basic algorithm confusion checks, and known library-specific bypass
  patterns) against the supplied token in a single pass, printing a summary
  of which ones succeeded. Treat this as a fast triage step to identify
  which specific technique from files 2–4 is worth pursuing manually and in
  depth, not as a replacement for the manual methodology in those files.

## Sending Requests Directly (Integrated HTTP Testing)

jwt_tool can fire the forged token directly at a target endpoint instead of
just printing it for you to paste elsewhere:

```bash
python3 jwt_tool.py <token> -X a -t "https://target.example/api/profile" -rc "Authorization: Bearer <replaceme>" -rh "Authorization: Bearer TOKEN"
```

- `-t "<url>"` — the target URL to send the forged token against.
- `-rc "<header>: <value>"` — (regex-cookie / request-config in some
  versions) defines how the original request should be reconstructed; check
  `-h` output for the exact current syntax, as this has evolved across
  jwt_tool releases.
- `-rh "Authorization: Bearer TOKEN"` — defines the request header template,
  with the literal string `TOKEN` marking where jwt_tool should substitute
  the freshly forged token value before sending.

In practice, many testers find it more reliable to generate the forged token
with jwt_tool and then send it manually via `curl` or Burp Repeater, to keep
full control over the rest of the request (cookies, other headers, body) —
both workflows are valid; use the integrated request mode for quick
automated testing across many endpoints, and manual sending when precise
request reconstruction matters.

## Verbose / Debug Output

```bash
python3 jwt_tool.py <token> -X k -pk public_key.pem -v
```

- `-v` — verbose mode, prints additional internal detail about each step
  jwt_tool takes (useful when an attack "doesn't work" and you need to see
  exactly what key material or header values were actually used, per the
  PEM-formatting caution noted in file 3).

## Real-World Notes

- jwt_tool is actively maintained and flag names/behavior have shifted
  across major versions — always run `python3 jwt_tool.py -h` against the
  installed version before an engagement rather than trusting flag syntax
  memorized from an older writeup (including this one); cross-check anything
  that doesn't behave as expected here against the current `-h` output.
- On real engagements, jwt_tool's playbook mode (`-M pb`) is a fast, safe
  first move on any newly discovered JWT-based auth endpoint — it's quick,
  low-noise, and often immediately reveals which of files 2–4's attack
  classes is worth investing manual time into for that specific target.
