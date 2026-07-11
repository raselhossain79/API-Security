# mTLS and Service Authentication Testing

## 1. Overview

This file covers the two dominant mechanisms used to authenticate service-to-service
requests in a microservices architecture:

1. **Mutual TLS (mTLS)** — transport-layer identity verification
2. **JWT-based service tokens** — application-layer identity/authorization claims

Both exist to solve the same problem raised in File 1: proving that a request
actually originates from a legitimate internal service rather than an attacker who
has reached the network segment. Both are also frequently implemented incompletely,
which is what this file teaches you to detect.

---

## 2. mTLS Fundamentals

### 2.1 What mTLS is

Standard TLS (as used for HTTPS) is **one-way**: the client verifies the server's
certificate, but the server does not verify the client's identity beyond the network
connection itself. **Mutual TLS** requires *both* sides to present a certificate:

- The server presents a certificate; the client verifies it (standard TLS behavior)
- The client *also* presents a certificate; the server verifies it before accepting
  the request

In a microservices context, every service is issued its own client certificate
(typically by an internal Certificate Authority, often managed by a service mesh like
Istio, Linkerd, or Consul Connect). When Service A calls Service B, Service B's TLS
layer checks that Service A presented a certificate signed by the trusted internal CA
*before the request ever reaches Service B's application code*.

### 2.2 Why mTLS matters specifically for service-to-service trust

mTLS is the most architecturally sound way to satisfy the "prove you're really an
internal service" requirement, because the check happens at the transport layer,
before any application logic runs, and it cannot be forged without possessing a valid
private key signed by the trusted CA. This is strictly stronger than IP-based or
network-segment-based trust (Section 4.4/4.5 of File 1), which can be satisfied by
merely being present on the network.

### 2.3 How the handshake works (simplified)

1. Client initiates TLS handshake, server presents its certificate
2. Client verifies server certificate against trusted CA (standard TLS)
3. Server sends a `CertificateRequest` (this is the "mutual" part — standard TLS
   servers don't do this)
4. Client presents its own certificate
5. Server verifies the client certificate:
   - Is it signed by a CA the server trusts?
   - Is it within its validity period?
   - Has it been revoked (CRL/OCSP check)?
   - Does the certificate's Subject/SAN match an identity the server expects?
6. If all checks pass, the TLS session is established and the request proceeds

**Critical point for testers:** every one of these checks is a separate place
implementation can go wrong, and each is testable independently.

---

## 3. Testing for Weak or Missing mTLS

### 3.1 Step 1 — Determine whether mTLS is enforced at all

From a position with internal network access (whitebox engagement, or after an
initial pivot — see File 3):

```bash
# Attempt a plain TLS connection without presenting a client cert
openssl s_client -connect inventory-service.internal:8443
```

- If the connection succeeds and you can send an HTTP request that gets a normal
  application response → **mTLS is not enforced**. The service accepts any TLS
  client regardless of certificate. This is a critical finding: authentication
  believed to exist architecturally does not exist in practice.
- If the connection is rejected at the TLS layer (handshake failure,
  `alert certificate required`) → mTLS is being enforced at least at the transport
  level; proceed to Step 2.

**Why this works:** many services are configured with `tls.ClientAuth =
RequestClientCert` (Go) or equivalent "optional" mTLS modes instead of
`RequireAndVerifyClientCert`. The optional mode was often chosen during initial
rollout to avoid breaking traffic during a migration, and the more secure "required"
setting never got enabled — a very common real-world gap.

### 3.2 Step 2 — Test certificate validation rigor

If mTLS is enforced, test whether validation is genuinely rigorous or superficial:

```bash
# Generate a self-signed certificate NOT signed by the internal CA
openssl req -x509 -newkey rsa:2048 -keyout attacker.key -out attacker.crt -days 1 -nodes -subj "/CN=inventory-service"

# Attempt to connect presenting this untrusted certificate
openssl s_client -connect payment-service.internal:8443 -cert attacker.crt -key attacker.key
```

- If this succeeds → the server is not actually verifying the certificate chain
  against the trusted CA (e.g., misconfigured trust store, or validation
  accidentally disabled in a debug/dev code path that shipped to production).
- **What trust assumption this exploits:** the assumption that "if mTLS is
  configured, it must be working correctly." Configuration and enforcement are two
  different things, and TLS libraries frequently have footguns (e.g., `InsecureSkipVerify: true`
  in Go accidentally left enabled, or a custom `VerifyPeerCertificate` callback that
  always returns nil) that silently disable the check while appearing configured.

### 3.3 Step 3 — Test whether the Common Name / SAN is actually checked against identity

Even if the certificate is properly signed by the trusted internal CA, many
implementations stop there and never confirm that the specific *identity* in the
certificate (CN or SAN) matches what's expected for that calling relationship.

```bash
# Request a legitimately-signed certificate from the internal CA for a LOW-privilege
# service identity (e.g., notification-service), if your access level allows requesting
# one (common in cert-manager/Istio citadel setups with permissive issuance policies)

# Then use that low-privilege, but validly-signed, certificate to call a HIGH-privilege
# service (e.g., payment-service) that should only accept calls from order-service
```

- If `payment-service` accepts the request purely because the certificate is signed
  by the trusted CA — regardless of *which* service identity it represents — this
  is a **certificate identity confusion** vulnerability. The server verified
  "is this a legitimate internal service?" but never verified "is this the *specific*
  service that's supposed to be calling me?"
- **Why this happens:** service mesh sidecars (Istio, Linkerd) often handle the mTLS
  handshake transparently, and the application code behind the sidecar never inspects
  which service identity is attached to the connection — it just trusts "the sidecar
  already checked this," which is often only a chain-validity check, not a
  policy-based identity check (see Istio `AuthorizationPolicy` / `PeerAuthentication`
  distinction — many teams configure the former but skip fine-grained `principals`
  restrictions in the latter).

### 3.4 Step 4 — Test certificate expiry/revocation handling

```bash
# Use an expired certificate
openssl s_client -connect user-service.internal:8443 -cert expired.crt -key expired.key
```

Also check whether revoked certificates are actually rejected — many internal CAs
issue certificates but never wire up CRL/OCSP checking on the consuming side, meaning
a compromised/rotated-out service identity's old certificate remains valid
indefinitely.

---

## 4. JWT-Based Service Tokens

### 4.1 What they are

Instead of (or in addition to) mTLS, many architectures authenticate service-to-service
calls with a JWT issued to each service — a "service token" or "machine token" —
analogous to a user's JWT but representing a service identity (e.g.,
`sub: "inventory-service"`, with claims describing what it's allowed to call).

This is common where mTLS/service-mesh infrastructure is too heavy to deploy, or
alongside mTLS as a second, application-layer authorization signal.

### 4.2 Service-to-service specific weaknesses

These are distinct from the general JWT weaknesses covered in the JWT series —
cross-reference that series for `alg:none`, weak-secret brute-force, and signature
verification bypass fundamentals. **This section covers weaknesses specific to the
service-to-service use case.**

#### 4.2.1 Missing audience (`aud`) validation

Service tokens are frequently issued from a single central identity provider for all
services, differing only in the `sub` (subject/service identity) and `aud`
(intended-recipient service) claims. If the receiving service validates the
signature but not the `aud` claim:

- A valid token issued for `notification-service` to call `logging-service` can be
  replayed against `payment-service`, because `payment-service` only checks "is this
  signature valid and did it come from our trusted issuer?" — not "was this token
  actually meant for me?"

**Step-by-step test:**
1. Obtain (or generate, if you control a low-privilege service in a whitebox test) a
   validly-signed service token issued for a low-privilege service/audience.
2. Replay it, unmodified, against a higher-privilege internal service's API.
3. If accepted → audience validation is missing. This is a critical finding because
   it means possession of *any* valid service token compromises *every* service.

**Trust assumption exploited:** "if the signature is valid, the token is legitimate
for this request" — conflating *authenticity* (who issued it) with *intended scope*
(who it was issued for).

#### 4.2.2 Overprivileged/static service tokens

Many teams issue a single, long-lived, static service token (sometimes literally a
shared secret stored in a Kubernetes Secret or environment variable) used by *every*
internal service to call *every* other internal service, rather than per-relationship,
short-lived, narrowly-scoped tokens.

**Why this happens:** per-relationship token issuance (e.g., via SPIFFE/SPIRE or a
mesh control plane) requires infrastructure investment; a shared static token is the
path of least resistance during initial build-out and frequently never gets replaced.

**What this means for testers:** if you compromise *any single service* (via SSRF,
RCE, a leaked config file, or a container escape) and can read its environment
variables or mounted secrets, you likely have the credential to authenticate as *any*
service to *any* other service. This collapses the entire internal trust model to the
security of your weakest single service.

#### 4.2.3 No token expiry / no rotation

Service tokens are often issued once at deployment time and never expire (unlike user
session JWTs, which usually have short lifetimes because they're understood to be
higher-risk). A token leaked in a log file, a Git commit, or a crash dump remains
valid indefinitely.

**Test:** decode any service token you obtain and check the `exp` claim. Absent or
set to a multi-year value is a finding.

#### 4.2.4 Confusion between user tokens and service tokens

In architectures where the API gateway forwards the *original user's* JWT downstream
(rather than minting a separate service token) so that internal services can make
authorization decisions based on the original requester's identity, a common flaw is
that internal services fail to distinguish "this request came with a legitimate
forwarded user token" from "this request came with a forged/replayed one," because
internal services assume network placement already guarantees the token's
authenticity (Section 4.2/4.3 of File 1). Test by crafting a request directly to an
internal service with an arbitrary user JWT (even an expired or self-signed one) and
observing whether the internal service performs its own signature verification or
simply trusts the claims because the request "came from inside."

---

## 5. WAF / API Gateway Relevance for This Topic

mTLS and service-token authentication are **not primarily WAF/gateway detection
concerns** — they operate below (mTLS, transport layer) or orthogonal to (service
JWTs, application layer between services rather than at the internet-facing edge)
where a WAF typically inspects traffic. A WAF sitting at the API gateway generally
never sees internal service-to-service traffic at all, since that traffic doesn't
transit the gateway.

The one place gateway configuration is genuinely relevant here: some teams
**substitute API gateway network policy for mTLS**, reasoning "the gateway only
routes to services within the mesh, so mTLS is unnecessary." This is precisely the
Section 4.1/4.4 trust assumption from File 1, and it's testable by attempting to reach
internal services *without* going through the gateway at all — which is exactly the
subject of File 4. If that succeeds, any gateway-level policy substituting for mTLS is
proven insufficient, because the gateway itself was bypassed.

---

## 6. PortSwigger Web Security Academy Mapping

As noted in File 1, PortSwigger has no dedicated mTLS or service-token labs (mTLS is
an infrastructure-layer concern outside PortSwigger's single-app lab model). The
closest applicable labs teach general JWT attack technique that transfers directly to
service tokens:

**Apprentice:**
- *JWT authentication bypass via unverified signature*
- *JWT authentication bypass via flawed signature verification*

**Practitioner:**
- *JWT authentication bypass via weak signing key*
- *JWT authentication bypass via jwk header injection*
- *JWT authentication bypass via jku header injection*
- *JWT authentication bypass via kid header path traversal*

**Expert:**
- *JWT authentication bypass via algorithm confusion*
- *JWT authentication bypass via algorithm confusion with no exposed key*

Practice these against the standard JWT series content first if you haven't already —
this file assumes that mechanical grounding and focuses only on the service-to-service
specific angle (audience confusion, shared static tokens, missing expiry) that
PortSwigger's user-authentication-focused labs don't model at all.

---

## 7. Supplementary Practice

- **HTB Pro Labs (RastaLabs/Offshore/APTLabs)** — internal networks occasionally
  expose internal service auth misconfigurations; useful for practicing discovery of
  service credentials in config files/environment variables after an initial
  foothold, which is the realistic path to the Section 4.2.2 finding above.
- **TryHackMe "Internal"** — practice pivoting to reach internal-only authenticated
  services and testing whether captured credentials/tokens are over-scoped.
- **Istio/Linkerd/Consul Connect documentation + local lab setup** — because
  PortSwigger and most CTF-style platforms don't model service mesh mTLS at all, the
  highest-value practice for this specific topic is standing up a local Kubernetes
  cluster (`kind` or `minikube`) with Istio installed, deliberately misconfiguring
  `PeerAuthentication` to `PERMISSIVE` mode, and practicing Section 3's tests against
  your own cluster. This is the single best way to internalize the difference between
  "mTLS configured" and "mTLS enforced."

---

## 8. Real-World Notes

- The single most common real-world finding in this category is not a broken crypto
  implementation — it's `PeerAuthentication` (Istio) or equivalent left in
  `PERMISSIVE` mode during a migration and never tightened, meaning plaintext
  connections are silently accepted alongside mTLS ones indefinitely.
- Static shared service tokens (Section 4.2.2) show up constantly in
  smaller/mid-size engineering orgs that adopted microservices before adopting the
  infrastructure (SPIFFE/SPIRE, mesh control planes) needed to do per-service identity
  properly. Treat "we use microservices" and "we have proper service identity" as two
  separate claims to verify independently.
- When reporting findings in this category, always state explicitly which specific
  check failed (chain validation vs. identity/SAN matching vs. audience claim vs.
  expiry) — "weak mTLS" is not an actionable finding on its own.

---

## 9. Cross-References

- See **File 1** for the trust assumptions (Section 4.1–4.5) that these tests are
  designed to disprove.
- See **File 3** for what happens after you've found weak/missing service
  authentication — lateral movement and impersonation.
- See the existing **JWT series** for foundational JWT attack mechanics referenced in
  Section 6.
- See the existing **API Gateway Security series** for gateway-level authentication
  configuration that this file's Section 5 references.
