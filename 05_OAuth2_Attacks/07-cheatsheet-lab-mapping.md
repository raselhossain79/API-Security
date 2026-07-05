# OAuth 2.0 Attack Cheatsheet and PortSwigger Lab Mapping

## How to Use This File

This is the quick-reference summary of the whole series — use it for a fast recall pass before an engagement or a lab session. For the full mechanism-first explanation behind any line here, go back to the numbered file it references.

---

## Quick Reference: Attack Techniques by File

### File 1 — Flow Mechanics
| Flow | Key parameter | Where token/code lands |
|---|---|---|
| Authorization Code | `response_type=code` | Query string (`code`), token via back-channel |
| Client Credentials | `grant_type=client_credentials` | Direct response, no browser |
| Device Code | `grant_type=...device_code` | Polled server-to-server after user enters `user_code` |
| Implicit | `response_type=token` | URL fragment (`#access_token=...`) |

### File 2 — redirect_uri
| Technique | Core idea |
|---|---|
| Path/query "starts-with" bypass | Server checks prefix, not exact match |
| Encoding/parser-differential | `@`, backslashes, encoding confuse validator vs. redirecting component |
| Parameter pollution | Duplicate `redirect_uri`; validation and redirect logic read different copies |
| `localhost` special-casing | `localhost.evil-user.net` abuses substring-based localhost exception |
| response_mode interaction | Switching `query`/`fragment`/`web_message` re-opens validation gaps |
| Open redirect chaining | Whitelisted host has its own open redirect elsewhere |
| Subdomain takeover chaining | Wildcard whitelist + dangling DNS record on a subdomain |

### File 3 — state / CSRF
| Concept | What to check |
|---|---|
| Purpose of `state` | CSRF protection for the client's own `/callback`, not code/token theft prevention |
| Detecting weak state | Missing entirely / identical across sessions / not validated server-side |
| Login CSRF | OAuth-only login apps: force victim into attacker's account |
| Forced account linking | Victim's existing account gets attacker's OAuth identity attached |

### File 4 — Scope Elevation and Leakage
| Concept | Core idea |
|---|---|
| Scope upgrade (code flow) | Attacker's own client adds scope at token exchange, beyond consented scope |
| Scope upgrade (implicit flow) | Stolen token + added `scope` param on resource-server request |
| Referer leakage | Code in query string sent to third-party resources loaded on callback page |
| Browser history leakage | Code/token persist in local history, shared devices, sync |
| Server log leakage | Access logs, APM tools, error trackers capture full query string |
| Error message leakage | Debug/error output echoes the failing request verbatim |

### File 5 — Account Takeover Chains
| Chain | Core idea |
|---|---|
| Attacker-controlled provider linking | Victim's account linked to attacker's OAuth identity via CSRF or social engineering |
| Pre-account-takeover | Attacker registers victim's unverified email at a loosely-verifying provider first |
| redirect_uri → full takeover | Intercepted code/token replayed against legitimate client's real callback |

### File 6 — PKCE
| Bypass | Core idea |
|---|---|
| `plain` method downgrade | Challenge = verifier in cleartext; no hashing separation at all |
| Optional (non-enforced) PKCE | Attacker's own request simply omits `code_challenge` |
| Cross-client substitution | Missing `client_id` binding at redemption (uncommon in mature servers) |
| Mobile URL scheme interception | Malicious app intercepts code but lacks in-memory verifier |

---

## PortSwigger Web Security Academy — OAuth Authentication Labs (Official Difficulty Order)

PortSwigger's OAuth authentication topic contains six labs, in this progression:

### Apprentice

**1. Authentication bypass via OAuth implicit flow**
- Maps to: File 1, Flow 4, Step 3 (implicit-flow `/authenticate` trust bypass).
- Core bug: the client's backend trusts attacker-supplied email/username fields in the post-token `POST /authenticate` request without verifying they match the identity the access token actually belongs to.
- Solve approach: capture the `POST /authenticate` request, change the email to the target account's email, keep your own valid token, and forward it.

### Practitioner

**2. Forced OAuth profile linking**
- Maps to: File 3 (Forced Account Linking) and File 5, Chain 1.
- Core bug: the `/oauth-linking?code=...` endpoint links whichever identity the code resolves to onto whatever account the requesting browser is currently logged into, with no `state`/CSRF protection.
- Solve approach: log in normally, start the linking flow with your own social account, intercept and drop the request to `/oauth-linking` to capture the code unused, then deliver it via an iframe to the admin victim while they have an active session — this links your identity to their account.

**3. OAuth account hijacking via redirect_uri**
- Maps to: File 2 (redirect_uri attacks, specifically unrestricted/loosely validated redirect_uri) and File 5, Chain 3.
- Core bug: the OAuth server accepts an attacker-supplied `redirect_uri` (in this lab, the exploit server domain) on the authorization request, letting the code be delivered to an attacker-controlled endpoint.
- Solve approach: build an iframe pointing to the authorization endpoint with `redirect_uri` set to your exploit server, deliver it to the victim (who has an active OAuth session so no login prompt appears), capture the leaked code from your exploit server's access log, then use that code against the real client's `/oauth-callback` endpoint to log in as the victim.

**4. Stealing OAuth access tokens via an open redirect**
- Maps to: File 2 (Open Redirect Chaining) and File 4 (token exposure via implicit flow's fragment).
- Core bug: the OAuth server restricts `redirect_uri` to the legitimate client's domain, but that domain has its own separate open-redirect vulnerability which can be chained to forward the implicit flow's fragment token off-domain.
- Solve approach: identify the open redirect on the client application, set `redirect_uri` to point through it toward your exploit server, and trigger the implicit flow (`response_type=token`) so the token is forwarded to a page you control.

**5. SSRF via OpenID dynamic client registration**
- Maps to: adjacent to this series (OpenID Connect dynamic client registration is a related but distinct OpenID-layer topic, not covered as its own file here since the requirements scope this series to core OAuth 2.0 flows and attacks) — conceptually connects to File 2's theme of "the server trusts attacker-supplied URLs" but applies it to a client-registration endpoint (`/reg`) rather than the authorization/redirect flow, allowing an attacker to register a malicious client with a `logo_uri` or similar field that the server fetches server-side, producing SSRF.
- Note: included here for completeness of the official lab list, since it is filed under the same "OAuth authentication" category on PortSwigger, but it is fundamentally an SSRF vulnerability reached via an OAuth-adjacent registration endpoint rather than a redirect_uri/state/scope/PKCE attack — cross-reference PortSwigger's own SSRF material for the exploitation mechanics if you want to go deeper on this one specifically.

### Expert

**6. Stealing OAuth access tokens via a proxy page**
- Maps to: File 2 ("Stealing codes and access tokens via a proxy page" — directory traversal on redirect_uri to reach an unintended path) combined with File 4 (HTML injection leaking a code via Referer).
- Core bug: direct external `redirect_uri` values are rejected, but directory-traversal sequences within the registered path (`/oauth-callback/../...`) are not properly normalized before validation, allowing the attacker to redirect to a different, unintended page on the whitelisted domain — one with an HTML-injection flaw that can be used to leak the code via a crafted `Referer`-triggering element.
- Solve approach: use traversal sequences to find another reachable path under the whitelisted host, locate an HTML-injection point on that path, inject an element that causes the browser to leak the `Referer` (carrying the code) to your exploit server, and deliver the full chain to the victim.

---

## Recommended Practice Order

1. Lab 1 (Apprentice) to internalize the implicit-flow trust gap from File 1.
2. Labs 2–4 (Practitioner) in any order, since they exercise three independent mechanisms (linking/CSRF, redirect_uri, open-redirect chaining) covered in Files 2–3.
3. Lab 5 (Practitioner) as an optional side quest into OpenID-adjacent SSRF, not essential to this series's core OAuth focus but worth completing for full topic coverage.
4. Lab 6 (Expert) last, since it requires chaining traversal-based redirect_uri bypass (File 2) with HTML-injection-driven Referer leakage (File 4) — the most demanding combination in the set.

## Honest Gap Disclosure

- PortSwigger's OAuth authentication topic does not currently include a dedicated lab for PKCE bypass, pure scope-upgrade-via-malicious-client, or pre-account-takeover via unverified email — these are covered in Files 4–6 of this series based on documented real-world vulnerability patterns and the OAuth 2.0 Security BCP, not because a specific matching lab exists in this topic. If a lab covering these is added in the future, it should be slotted into the practice order above based on its assigned difficulty tag at that time.
- The Client Credentials and Device Code flows (File 1) also have no dedicated PortSwigger lab under this topic, since PortSwigger's OAuth material is scoped to the authentication (SSO-style) use case built on the authorization code and implicit grants — those two flows are included in File 1 for mechanism completeness since real-world engagements (especially API and internal-service assessments) encounter them regularly, not because a corresponding lab exists here.

## WAF/Gateway Relevance Summary Across This Series

- **Directly relevant:** File 2 (redirect_uri manipulation) — encoding tricks, traversal, and parameter pollution are exactly the shapes generic WAF/gateway rules are built to catch, with realistic bypasses via double-encoding, case variation, and pollution blind spots, as detailed in that file.
- **Not meaningfully relevant, addressed by design rather than by a network control:** File 3 (state/CSRF) and File 6 (PKCE) are logic and cryptographic-binding defenses implemented in application/authorization-server code; a WAF cannot meaningfully detect "this state value wasn't validated" or "this PKCE verifier doesn't match," since those checks require request-to-request session correlation and knowledge of values the WAF never sees together. File 5's account-takeover chains are compositions of the other techniques and inherit whichever WAF relevance their component techniques carry individually. File 4's scope elevation is a back-channel, server-to-server request in the code-flow case (invisible to any WAF sitting in front of the browser-facing endpoints) and, in the token-leakage half, is a passive data-exposure issue (Referer headers, logs) rather than an attack pattern a WAF blocks — the fix there is response-header and logging hygiene, not edge filtering.

---

*End of series. Cross-reference: 01–06 for full mechanism-first detail behind every row in this cheatsheet.*
