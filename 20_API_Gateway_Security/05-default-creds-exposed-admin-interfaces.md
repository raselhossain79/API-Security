# Default Credentials & Exposed Admin Interfaces

## Trust Assumption Being Exploited

Gateway products ship with a management/admin plane separate from the data
plane that proxies actual API traffic — because operators need to
configure routes, plugins, and policies somehow. Vendors assume operators
will bind this admin plane to a private network interface or place it
behind its own authentication before going to production. In practice,
default installations frequently bind the admin interface to all
interfaces (`0.0.0.0`) out of the box, and "we'll secure it before
production" is a step that gets skipped under deployment time pressure,
especially in cloud environments where "internal-only" is assumed from the
network topology rather than actually enforced (the same root assumption
failure as file 02, but applied to the control plane instead of the data
plane). Compromising the admin plane is typically far more severe than any
single data-plane bypass, because it grants control over routing, auth
plugins, and traffic for every API behind that gateway instance.

---

## Kong Admin API

### Mechanism

Kong's Admin API (default port `8001`, or `8444` for HTTPS) is a separate
RESTful API used to configure services, routes, plugins (including
`key-auth`, `jwt`, `rate-limiting`, `acl`), consumers, and certificates.
**By default, in Kong OSS, the Admin API has no authentication at all** —
it is expected to be protected by network placement (bound to localhost or
an internal-only interface) or an operator-added authentication layer (a
reverse proxy in front of it, or Kong Enterprise's RBAC feature). A
significant number of production Kong deployments — especially
containerized ones where `KONG_ADMIN_LISTEN` is left at a
permissive default or explicitly set to `0.0.0.0:8001` to "make it work"
inside a container network without deeper thought about external exposure
— leave this reachable from outside the intended network boundary.

### Step-by-Step Testing

1. **Identify the Admin API port.** Default is `8001` (HTTP) /
   `8444` (HTTPS); scan the target's IP range (once real IPs are known —
   see file 02 for backend/infra discovery techniques applied to the
   gateway host itself) for these ports alongside the standard proxy ports
   (`8000`/`8443`).
2. **Confirm it's actually the Admin API, not the proxy port.**
   ```
   curl -s http://target:8001/
   ```
   A reachable, unauthenticated Kong Admin API returns a JSON document
   describing the Kong node (version, plugins, configuration) at the root
   path — this alone is a significant information disclosure even before
   further action.
3. **Enumerate configured services/routes/consumers** to understand the
   full scope of what's exposed:
   ```
   curl -s http://target:8001/services
   curl -s http://target:8001/routes
   curl -s http://target:8001/consumers
   curl -s http://target:8001/plugins
   ```
4. **Demonstrate impact without causing damage** (for authorized
   engagements — always confirm scope/rules of engagement before any
   write action against a production admin API):
   - Read existing plugin configuration for a route to check whether an
     `acl`/`key-auth` config reveals consumer credentials or overly
     permissive settings.
   - If a write action is authorized in scope, the highest-signal
     proof-of-impact is typically adding a new route pointing at a
     backend service already defined in Kong, or adding a plugin to an
     existing route, rather than modifying an existing production route's
     behavior. Document what *could* be done (delete a `key-auth` plugin
     from a route, entirely removing authentication for that route
     globally) rather than actually doing it unless explicitly authorized.
5. **Check for Kong Enterprise RBAC** if the version fingerprint
   (from the root path response) indicates Enterprise — the equivalent
   exposure with RBAC properly configured requires an admin token; test
   whether default/example tokens from Kong's own documentation were left
   in place (a real, recurring finding).

---

## AWS API Gateway Misconfigured Resource Policies

### Mechanism

An API Gateway resource policy is an IAM-style JSON policy attached
directly to the API that controls *who* (which AWS principals, source
VPCs, or source IPs) can invoke it, independent of any application-level
authorizer (API keys, Lambda authorizers, Cognito). It's commonly used to
restrict a private or internal API to a specific VPC endpoint. Because it's
written in the same IAM policy JSON syntax used elsewhere in AWS, it
inherits the same class of mistakes: overly broad `Principal: "*"`, a
`Condition` block that was intended to restrict access but references the
wrong VPC endpoint ID or uses an incorrect condition operator (e.g.,
`StringEquals` against a value that should have used `StringLike` with a
wildcard, or vice versa, silently making the condition never match and
therefore never restrict), or a policy that correctly restricts `execute-api:Invoke`
but forgets that the API is *also* reachable via its default
`execute-api` endpoint URL in addition to any custom domain, if "disable
default endpoint" wasn't explicitly configured.

### Step-by-Step Testing

1. **Always test the default `execute-api` endpoint directly**, even if a
   custom domain with additional protections (e.g., a WAF, a CloudFront
   distribution with auth) is the intended public entry point:
   ```
   https://{api-id}.execute-api.{region}.amazonaws.com/{stage}/{resource}
   ```
   If the API was intended to be "private" (accessible only via a VPC
   endpoint) but "Disable default endpoint" was never explicitly enabled
   in the API Gateway console/IaC, the default endpoint may still route
   publicly regardless of the resource policy's VPC endpoint condition,
   because that setting — not just the resource policy — is what
   actually blocks the public endpoint path for private APIs.
2. **Enumerate API IDs.** API Gateway IDs are not secret by design and are
   sometimes discoverable via JS bundle analysis of a related frontend
   application, CloudFormation/Terraform state files accidentally exposed
   (check public S3 buckets and GitHub repos for the organization), or
   subdomain/CNAME records pointing at `execute-api.*.amazonaws.com`.
3. **Test the deployed stage's methods without any AWS SigV4 signing or
   API key**, to check whether the resource policy (which should require
   specific conditions) actually gates access, or whether a Lambda
   authorizer/API key requirement is the *only* thing standing between the
   request and a response — meaning the resource policy is either absent
   or ineffective and you're really only testing whichever authorizer is
   configured on the method itself (a different, and expected, control —
   the resource-policy-specific bug is when the policy was *believed* to
   restrict source but doesn't).
4. **If any level of legitimate access is available (e.g., a low-privilege
   authorized account for a cloud security assessment)**, directly review
   the resource policy JSON via `aws apigateway get-rest-api` /
   `get-resource-policy`-equivalent calls, checking specifically for:
   - `"Principal": "*"` combined with no `Condition` block at all.
   - `Condition` keys referencing `aws:SourceVpce` or `aws:SourceIp` with
     values that don't match any real VPC endpoint/IP currently in use
     (stale from a prior environment), which typically means the
     condition never evaluates true and — depending on `Effect` — either
     silently denies everyone (an availability bug, not a security bug) or,
     if combined with a broader `Allow` statement elsewhere in the same
     policy document, is simply redundant/ignorable in practice.

---

## Apigee Management UI

### Mechanism

Apigee's management plane (the Edge/X UI and Management API,
`api.enterprise.apigee.com` for Edge public cloud, or a customer-specific
hostname for Private Cloud/hybrid deployments) is where proxies, target
endpoints, and policies (including `VerifyAPIKey`, `OAuthV2`, `SpikeArrest`
— Apigee's rate-limiting policy) are configured. Unlike Kong's Admin API,
Apigee's management plane requires authentication by default (organization
credentials or OAuth). The realistic exposure here is less "no auth at
all" and more: overly broad organizational role assignment (an
`orgadmin`-equivalent role granted to accounts that only needed
read/deploy access to a single proxy), leaked management API tokens/service
account keys in client-side code, CI/CD pipeline configuration, or public
repos, and Private Cloud/hybrid deployments where the management UI itself
(not just the API) was exposed on a public interface without the
organization's SSO/IdP integration properly enforced in front of it.

### Step-by-Step Testing

1. **Search for exposed Apigee management API tokens/service account keys**
   the same way you'd search for any leaked cloud credential: GitHub code
   search (`apigee` combined with `token`/`client_secret`/`.json` service
   account key patterns), CI/CD configuration files, JS bundles of related
   frontend apps that might embed a management token for a dev/preview
   environment inadvertently pointed at production credentials.
2. **For Private Cloud/hybrid deployments, check whether the management UI
   hostname is resolvable and reachable externally** the same way you'd
   check for any exposed internal admin panel — DNS/subdomain enumeration,
   direct port checks on common Apigee management ports if the
   organization's IP ranges are known.
3. **If any credential is obtained, scope-check before further action**:
   confirm what organizational role it maps to
   (`read-only`/`orgadmin`/custom role) via the Management API's
   `userinfo`/role-listing endpoints before attempting anything further,
   since the impact of a leaked token varies enormously by assigned role.
4. **Check `SpikeArrest` and `VerifyAPIKey` policy configuration** (read
   access only) for proxies in scope, looking for the same
   route-coverage gaps described in file 03 — proxies added later that
   never had the org's standard policy set attached.

---

## PortSwigger Lab Relevance

PortSwigger doesn't have gateway-admin-plane-specific labs, since this is
inherently a product/infrastructure exposure rather than an application
logic flaw. The closest transferable skill set:

- **Broken Access Control > Apprentice**: "Unprotected admin functionality"
  — directly transferable reasoning (an admin interface reachable without
  authentication because the operator assumed obscurity or network
  placement was sufficient).
- General **information disclosure** testing methodology from the OWASP
  Top 10-aligned sections of the Academy applies to Step 1–2 techniques
  above (root-path fingerprinting, version disclosure).

## Supplementary Practice (Vendor-Based)

1. Deploy Kong OSS via the official Docker quickstart with default
   settings (no `KONG_ADMIN_LISTEN` override) and confirm the Admin API is
   reachable exactly as described above — this is the fastest way to
   internalize what "default, unhardened" actually looks like in traffic,
   before testing against a real target.
2. Deploy an AWS API Gateway (sandbox account) with an intentionally
   misconfigured resource policy (e.g., a stale `aws:SourceVpce`
   condition) to practice the recognize-a-broken-condition skill in
   Step 4 above.

---

## Real-World Notes

- Publicly reachable Kong Admin APIs on default port 8001 have been a
  recurring finding across internet-wide scanning research and bug bounty
  disclosures for years — it remains one of the highest-confidence,
  fastest checks to run early in any engagement where Kong is fingerprinted
  (via the `Via: kong/x.x.x` response header on the data plane).
- AWS API Gateway "private API" misconfigurations where the default
  `execute-api` endpoint was never explicitly disabled are a commonly
  cited cloud security assessment finding — teams frequently configure the
  VPC endpoint and resource policy correctly but skip the separate step of
  disabling the public default endpoint, not realizing it's a distinct
  setting.
- Apigee credential leakage most often traces back to CI/CD pipeline
  configuration (management API service account keys used for automated
  proxy deployment) committed to source control or exposed via
  misconfigured CI logs, rather than the management UI itself being
  directly attacked.
