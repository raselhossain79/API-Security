# Webhook Security — Note Series

A mechanism-first, exploit-focused note series on webhook security, built as a companion
to the existing Web Application Security and API Security note libraries. Webhooks sit at
the intersection of both worlds — they are server-to-server API calls triggered by events —
and they introduce an attack surface that is frequently missed because it doesn't look like
a normal "endpoint." Nobody browses to a webhook URL; it's called by the application itself,
which is exactly what makes it dangerous.

## Why this series exists

Most API security testing focuses on requests a client sends *to* the server. Webhooks
invert that: the server becomes a client and sends requests *out*, based on configuration
the attacker often controls (the destination URL) or based on data the attacker can forge
(the inbound event payload, if the receiving side is what's being tested). That inversion
is the source of almost every vulnerability class covered here.

## Files in this series

| # | File | Covers |
|---|------|--------|
| 00 | `00-Overview-Webhook-Model.md` | What a webhook is, the registration/delivery flow as raw HTTP, the trust boundaries involved, why this topic needs its own series distinct from generic API testing |
| 01 | `01-SSRF-via-Webhook-Registration.md` | Registering a webhook pointed at localhost, internal IPs, or cloud metadata endpoints; full step-by-step attack; filter and redirect-based bypasses |
| 02 | `02-Signature-Bypass-and-Replay-Attacks.md` | HMAC signature validation, missing-signature testing, timing attacks on signature comparison, secret brute-forcing, replay attacks and their defenses (timestamps, nonces) |
| 03 | `03-Payload-Tampering-and-Endpoint-Enumeration.md` | Modifying the webhook event body to change triggered actions (event type, amount, privilege fields); discovering unauthenticated webhook receiver endpoints |
| 04 | `04-Webhook-Security-Cheatsheet.md` | Condensed reference: test checklist, request/response patterns, tool commands, quick-reference payloads |

## How to use this series

- Read `00` first regardless of experience level — the direction of the request (who is
  calling whom) determines which vulnerability classes even apply, and getting that
  backwards wastes testing time.
- `01` assumes you already understand SSRF fundamentals from the SSRF file in the web
  application series. This file does not re-derive what SSRF is; it applies it specifically
  to the webhook registration surface.
- `02` assumes familiarity with HMAC and general cryptographic concepts from the
  Cryptographic Failures file in the web application series, and cross-references the JWT
  series for signature-handling parallels.
- `03` assumes familiarity with Mass Assignment and BOLA/BFLA from the API series — payload
  tampering on webhooks is those same primitives applied to an event body instead of a
  request body.
- `04` is a standalone quick-reference once you've read the rest.

## Standing conventions (same as the rest of the library)

- Mechanism explained before technique. You should understand *why* an attack works before
  you're shown *how* to run it.
- Every command, flag, header, and payload field is broken down piece by piece.
- Every file includes a WAF/API Gateway-relevant section — either concrete detection and
  bypass considerations, or an explicit statement of why that layer isn't the meaningful
  control for that specific vulnerability class (see `00` for the general reasoning that
  applies across this series).
- PortSwigger Web Security Academy lab mappings are given in strict
  Apprentice → Practitioner → Expert order, with **honest disclosure of coverage gaps** —
  PortSwigger has no dedicated "Webhooks" category, so mappings point to the underlying
  primitive labs (SSRF, authentication bypass) and gaps are stated rather than papered over.
- Where PortSwigger coverage is thin, real, disclosed HackerOne reports are used as
  practical worked examples, with an explanation of what each one actually demonstrates —
  not just a link.
- Full English only. No exact reproduction of third-party report text — all real-world
  examples are described in paraphrase, with a link to the original disclosed report for
  primary-source reading.
- Delivered as a single ZIP archive.

## Relationship to sibling series

- **SSRF (Web App series)** — foundational SSRF mechanics, internal network addressing,
  cloud metadata endpoints. This series applies those mechanics to the specific case where
  the URL comes from a *webhook registration field* rather than a generic "import from URL"
  feature.
- **JWT Attacks / Cryptographic Failures (Web App series)** — signature and MAC concepts
  underlying HMAC-based webhook signing.
- **BOLA / BFLA / Mass Assignment (API series)** — the same "trust the client-controlled
  field" failure, applied here to webhook event payloads instead of API request bodies.
- **API Rate Limit / Bot Protection Bypass (API series)** — relevant background for the
  WAF/gateway sections in this series, since webhook abuse detection reuses much of the
  same infrastructure.
