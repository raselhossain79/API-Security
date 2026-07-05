# Account Takeover via OAuth Chains

This file builds full account-takeover scenarios by combining mechanisms from earlier files with one additional trust assumption unique to OAuth authentication: **the client application trusts that whatever identity data the OAuth provider hands back is accurate and belongs to whoever is completing the flow.** Every attack here is really an attack on that assumption, approached from a different angle.

## Recap: How OAuth Authentication (Not Just Authorization) Works

From file 1's "OAuth authentication" framing: when OAuth is used for login rather than pure data-access delegation, the client application does roughly this after receiving a token:

1. Calls the OAuth provider's `/userinfo` (or equivalent) endpoint with the access token.
2. Receives a JSON blob — typically containing `email`, `sub` (subject/user ID), `name`, sometimes `email_verified`.
3. Looks up (or creates) a local account matching that identity data — most commonly matched by **email address**.
4. Logs the user into that local account.

Every attack below targets a different point where this identity-matching logic can be manipulated or where its underlying trust is misplaced.

## Chain 1: Attacker-Controlled OAuth Provider (Linking a Victim Account to an Attacker Identity)

**Precondition:** The client application allows a user to change or add which OAuth provider is linked to their account, or supports **multiple** OAuth providers (e.g., "log in with Google" *or* "log in with GitHub") without strict re-verification when adding a second one.

**Concept:** This is the general form of the forced-linking CSRF attack from file 3, but framed here as an identity-trust problem rather than purely a missing-`state` problem — because it can also succeed through channels other than CSRF, such as:

- **Session fixation-adjacent flow:** if the client's account-linking page ties the linked identity to *whatever session cookie the browser presents*, without re-confirming the user's password immediately beforehand, any technique that gets a linking request executed under the victim's session — not just CSRF, but also a shared/leaked session token, or an XSS-driven request — achieves the same result: the victim's account becomes permanently accessible via credentials the attacker controls.
- **Social-engineering variant:** an attacker convinces a victim (via phishing pretext — "verify your account by linking your social profile," a fake support flow, or a manipulated UI) to manually click "link account" and then complete the OAuth consent screen using **the attacker's** already-prepared, attacker-controlled OAuth account credentials rather than their own — the victim does the linking themselves, believing they're securing their own account, but they authenticate the flow with an identity that isn't theirs at all. This variant needs no CSRF or session bug whatsoever; it's pure trust manipulation of the human, exploiting the fact that most users don't distinguish "I am linking my account" from "I am authenticating as whoever's credentials are entered on this screen."

**Impact once linked (either path):** the attacker can subsequently visit the client application, select "log in with [provider]," authenticate using their own OAuth credentials, and land directly in the victim's account — a durable backdoor that survives password resets on the victim's original credentials, since the linked OAuth identity is a completely separate authentication path.

**Detection/testing approach:**
1. Locate the account-linking flow in the client application (usually in account settings).
2. Test whether it requires re-authentication (password re-entry) immediately before allowing a link/relink operation — if not, flag this regardless of whether you can fully weaponize it via CSRF, since it lowers the bar for the social-engineering variant considerably.
3. Test whether linking a **second** OAuth provider silently changes which identity is considered "primary" for login, or whether the original login method still functions independently — the more login paths that remain valid after linking, the more different ways an attacker's link can be abused.

## Chain 2: Pre-Account-Takeover via Unverified Email Claims

This is a distinct and often more dangerous pattern because it requires **no interaction with the victim at all** — the attacker acts before the victim ever creates an account.

**The trust assumption being broken:** many client applications, on receiving an OAuth `/userinfo` response, treat the `email` field as verified and unique, and use it as the sole key for account matching — "if an account with this email already exists, log this OAuth identity into it; if not, create a new account with this email." This is convenient because it lets a user register via password first and later add "log in with Google" as a second option that lands in the same account, matched by email.

**The flaw this exposes:** if the OAuth *provider* the attacker chooses to abuse allows account registration with an email address **without verifying that the registrant actually controls that email** (or allows registration before verification completes, or has a flow where an unverified email is still returned by `/userinfo` without any `email_verified: false` flag the client bothers to check), the attacker can register an OAuth identity claiming to own the **victim's** email address — one the victim hasn't used with this OAuth provider yet, and possibly hasn't used with the client application yet either.

**Attack construction:**
1. Attacker identifies a target victim's email address, e.g. `victim@company.com` (from a data breach, public profile, guessed corporate naming convention, etc.).
2. Attacker registers an account with a **loosely-verifying OAuth provider** using `victim@company.com` as the claimed email — many providers allow you to add an email to a profile without immediate proof of ownership, or send a verification link that the attacker simply never clicks (because the flow doesn't gate `/userinfo` on verification completing).
3. Attacker completes an OAuth login flow against the **target client application** using this fraudulent identity.
4. The client application queries `/userinfo`, receives `{"email": "victim@company.com", ...}`, sees no existing local account with that email (assuming the real victim has never used this specific client application before), and — trusting the email as verified — **creates a brand-new account** for the attacker, pre-populated with the victim's real email address as the account identifier.
5. **Two distinct impact paths from here:**
   - **Pre-takeover proper:** later, the real victim discovers or is invited to use the client application, tries to register normally with `victim@company.com`, and either (a) is told the email is already in use and is directed to log in — at which point they may attempt a password reset that goes to an email inbox they *do* control, potentially recovering the account and unknowingly inheriting an account the attacker has been quietly monitoring, or more dangerously (b) some applications, on seeing a matching email arrive via a *different* login method (e.g., victim tries "log in with Microsoft" while the attacker's fraudulent account was created via "log in with a different provider" using the same claimed email), silently **merge** the identities, handing the attacker's pre-existing session or linked data access to what is now the victim's real, verified account.
   - **Direct impersonation:** even without any later merge, if the client application uses OAuth-provided email as a trusted identifier for anything else — invitations, permissions, being added to a team or shared resource by a colleague who only knows the victim's email address — the attacker's pre-registered account receives those invitations and access grants instead of the real victim, because the client application has no way to know the account isn't legitimately the victim's.

**Why this is called "pre"-account-takeover:** the attacker's action (fraudulent registration) happens *before* the real victim ever interacts with the target application at all — there's no CSRF, no session to hijack, no credential to steal. The attack is purely a race to register an identity claim first, exploiting the gap between "an email string was submitted" and "ownership of that email was actually proven," at whichever OAuth provider has the weakest verification.

**Detection/testing approach:**
1. Identify every OAuth provider a target client application accepts.
2. For each provider, determine whether it requires email verification **before** that email appears in `/userinfo` responses, or whether an `email_verified: false` claim is returned and whether the *client* actually checks that flag (many implementations request the `email` scope and blindly trust the returned address without ever inspecting `email_verified`).
3. If feasible in a controlled test environment, register a test OAuth identity claiming an email address you also independently control, but deliberately skip that provider's own verification step, and observe whether the client application still creates/matches an account using that unverified email.
4. Check whether the client's account-merge logic (if any) re-verifies email ownership at merge time, or whether it merges purely on string equality between the newly claimed email and an existing account's stored email.

## Chain 3: Combining Redirect_uri Interception with Account Takeover

This ties Chain 1 back to file 2's mechanics for a complete, single walkthrough of how a code-interception attack ultimately becomes full account access, since the earlier files show the interception but stop short of the login itself:

1. Attacker crafts a malicious `redirect_uri` (file 2 technique of choice — open redirect chaining, subdomain takeover, or a raw parser-confusion payload) pointing to an attacker-controlled collector.
2. Attacker delivers this crafted authorization URL to the victim (embedded iframe, malicious link, or a compromised page the victim visits) while the victim has an active session with the OAuth provider — meaning the victim doesn't need to enter credentials again; the provider silently completes the authorization step because the browser is already authenticated there.
3. The victim's browser is redirected through the OAuth provider and lands on the attacker's collector carrying the victim's authorization `code` (or token, for implicit flow) in the URL.
4. **For the authorization code flow specifically:** the attacker cannot redeem this code directly against the token endpoint themselves in most configurations, because the code exchange also requires the registered `client_secret` (file 1, Step 4) which the attacker — acting as a third party, not the legitimate client — does not have. Instead, the attacker takes the stolen code and simply **navigates their own browser to the legitimate client application's real callback URL**, appending the stolen code:
```
GET /callback?code=STOLEN_VICTIM_CODE&state=ATTACKER_OWN_STATE HTTP/1.1
Host: client-app.com
```
This works because the *client application itself* (not the attacker) performs the actual server-to-server code exchange using its own valid `client_secret` — the client has no way to know this code was minted for the victim's browser rather than the attacker's, especially if (per file 3) `state` validation is weak or the client doesn't independently verify that the `code` "belongs" to this specific browser's flow. The client dutifully exchanges the code, receives a token proving the victim's identity, and logs the attacker's own browser in — as the victim.
5. **For the implicit flow:** no exchange step exists at all — the attacker's collector directly captures a live, immediately usable `access_token` in the URL fragment, and can use it straight away, either to call the resource server directly or to replay it against the client's own `/authenticate`-style endpoint (file 1, Flow 4, Step 3) to establish a full logged-in session as the victim.

This is the complete, end-to-end version of what files 1–3 covered separately: flow mechanics, redirect_uri interception, and the missing validation that lets an intercepted artifact convert into a real session.

## Consolidated Account-Takeover Testing Checklist

1. Map every OAuth provider a target accepts, and for each one, determine its email-verification guarantees before you rely on `email` as a trusted identifier anywhere in your testing.
2. Test the account-linking flow specifically for missing re-authentication and missing CSRF protection (cross-reference file 3).
3. Attempt a full redirect_uri interception (cross-reference file 2) and carry it through to an actual login, not just a captured code/token, to establish real impact for a report.
4. If registration via a given OAuth provider is possible under your control, test whether unverified emails propagate into the client application's account-matching logic.
5. Check whether the client merges accounts across different OAuth providers (or between password and OAuth) based on email string matching alone, and whether that merge logic re-checks verification status at merge time.

## Real-World Notes

- Pre-account-takeover via unverified OAuth email claims has affected numerous SaaS products with "log in with any of these providers" support, precisely because different providers have inconsistent email-verification guarantees and the client application rarely audits all of them individually.
- This class of bug is a favorite in bug bounty programs specifically because it requires zero interaction with the victim and zero exploitation of any bug in the target client's *code* — it's a logic flaw in trust assumptions, which means it's often missed by automated scanners entirely and found only through manual account-flow review.
- When reporting these findings, be explicit about which specific trust assumption failed (unverified email, missing re-auth on linking, missing state validation) rather than describing the finding only as "account takeover" — the remediation is different for each root cause even though the end impact category is the same.

## What Comes Next

File 6 covers PKCE — the mechanism specifically designed to close the authorization-code-interception gap for public clients (SPAs, mobile apps) that can't hold a `client_secret` — and the ways its implementation can still be bypassed.
