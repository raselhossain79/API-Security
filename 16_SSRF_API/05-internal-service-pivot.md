# SSRF to Internal Service Pivot

## Mechanism

Once API-originated SSRF is confirmed, the vulnerable server's network position
becomes your network position for the duration of that request. In API/microservice
architectures this is disproportionately valuable compared to a typical monolithic web
app, because the worker issuing the SSRF request often sits inside the same private
network/VPC/cluster as every other backend service — internal APIs, databases, admin
panels, message queues, CI/CD tooling — none of which were designed to be reachable
from the internet and therefore frequently have weak or no authentication, on the
assumption that network-level isolation was the real security boundary.

## Recon: Mapping What's Reachable

Before targeting anything specific, establish what internal network range you're
actually inside. Useful signals gathered from earlier steps:

- The `Client IP` from a Collaborator interaction (file 4) tells you the real source
  IP/subnet of the worker.
- Cloud metadata responses (file 3) — AWS `local-ipv4`, GCP
  `instance/network-interfaces/0/ip`, Azure `network/interface` — give you the exact
  subnet, and often the VPC/subnet ID, letting you infer the CIDR range in use
  (commonly `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16` internally, but cloud
  environments frequently use custom-sized subnets within those ranges — the metadata
  response tells you the actual one rather than requiring a guess).

Internal port/service discovery via the same SSRF primitive (adapt to whichever field
you have — synchronous fields give faster feedback per file 2; blind fields require the
timing/Collaborator methods in file 4):

```http
POST /api/v2/import HTTP/1.1
Host: target-api.example.com
Authorization: Bearer <token>
Content-Type: application/json

{"sourceUrl": "http://10.0.1.15:8080/"}
```

Piece-by-piece: incrementing the IP octet and/or port across repeated requests
(scriptable — see below) turns a single SSRF field into a crude internal port scanner.
The response/error differential (as covered in file 2's avatar-URL example) —
connection refused vs. timeout vs. an actual HTTP response with distinguishable
content — is the signal used to map live hosts and open ports without ever directly
touching the internal network yourself.

A minimal scripted sweep (adjust field name/endpoint per target):

```python
import requests

base = "https://target-api.example.com/api/v2/import"
headers = {"Authorization": "Bearer <token>", "Content-Type": "application/json"}
ports = [22, 80, 443, 3000, 5432, 6379, 8080, 8443, 9200, 27017]

for host_last_octet in range(1, 20):
    ip = f"10.0.1.{host_last_octet}"
    for port in ports:
        r = requests.post(base, headers=headers,
                           json={"sourceUrl": f"http://{ip}:{port}/"}, timeout=5)
        print(ip, port, r.status_code, len(r.text))
```

Piece-by-piece: this iterates a small internal subnet (`10.0.1.1`–`10.0.1.19`) against
a list of commonly-interesting internal ports — `5432` (PostgreSQL), `6379` (Redis),
`9200` (Elasticsearch), `27017` (MongoDB), `3000`/`8080`/`8443` (common internal
API/admin web ports), `22` (SSH, unlikely to return a meaningful HTTP-layer signal but
still distinguishable by timing/connection behavior). Response length and status code
are used as a coarse fingerprint — a database port typically returns a quick
connection-reset or a protocol-mismatch error distinguishable from a real HTTP
service's `200`/`404`. This script targets the *API's* import endpoint on each
iteration, not the internal hosts directly — the API server is always the one making
the actual connection.

**Caution on engagement scope:** an internal sweep like this generates a large volume
of outbound requests *from the target's own infrastructure against its own internal
network* — confirm this is within authorized scope and rate-limit appropriately before
running it; this is meaningfully more invasive than a handful of confirmation
requests and can trigger internal IDS/monitoring or degrade internal services under
load.

## Pivoting to Internal Admin APIs

Internal admin interfaces are frequently unauthenticated or use a weak/default
mechanism specifically because they were assumed unreachable from outside the private
network. If your SSRF primitive supports reading responses (synchronous field, or a
data-leak channel identified per file 4), fetching an internal admin API's response
directly is often possible:

```http
POST /api/v2/import HTTP/1.1
...
{"sourceUrl": "http://10.0.1.22:9090/api/internal/users"}
```

If the field only supports GET-style fetches and you need to interact with an internal
API that expects POST/authenticated calls, note this as a genuine limitation of
URL-only SSRF primitives (as discussed in file 3 regarding IMDSv2) — escalate by
looking for an SSRF primitive elsewhere in the same API surface with more request
control (custom method/headers/body), since different endpoints on the same backend
frequently use different underlying HTTP client configurations.

## Pivoting to Internal Databases

Direct database SSRF (pointing a URL-fetching field at a database's native port) will
not usually let you execute meaningful commands — a database protocol is not HTTP, and
an HTTP-fetching client (`requests`, `axios`, etc.) will typically fail to parse the
database's response — but it remains useful for two things: (1) confirming the port is
open/reachable, informing severity ("internal PostgreSQL instance reachable from a
customer-facing worker process" is a legitimate, reportable finding on its own even
without further exploitation), and (2) for Redis specifically, the `gopher://` protocol
technique lets an HTTP-based SSRF primitive that supports arbitrary schemes send raw
Redis protocol commands — this technique itself is general SSRF protocol-smuggling
technique and is covered in full (including the `gopher://` payload construction) in
the Web Application Security — SSRF series; it is not duplicated here, only flagged as
relevant once you've confirmed a Redis port is reachable via the sweep above.

## Pivoting to Internal Message Queues / CI Systems

Increasingly common in API-heavy microservice environments: internal Kubernetes API
server (`https://kubernetes.default.svc:443` from inside a cluster, using a
service-account token if the pod's own token is somehow accessible — a separate,
container-escape-adjacent vector beyond pure SSRF, but worth checking for since a
misconfigured pod can expose its own mounted token to an SSRF-reachable path), internal
CI/CD dashboards (Jenkins, internal GitLab), and internal package registries. These are
worth a dedicated pass in the port sweep (add ports `6443`, `8443`, `2379` for etcd, and
common CI ports like `8081`/`50000` to the list above) specifically in Kubernetes-hosted
API backends, since a single SSRF finding chained into cluster API server access is a
severity escalation worth calling out distinctly in a report rather than lumping in
with generic internal-service reachability.

## Chaining With Other API Vulnerability Classes

- **BOLA/BFLA on the internal admin API you've reached:** internal admin APIs
  frequently have *weaker* object/function-level access control than the external
  API, on the same "assumed unreachable" logic — once you can reach one via SSRF,
  re-apply BOLA/BFLA testing methodology (see the BOLA and BFLA series) against it.
- **API4 resource consumption:** a wide internal port sweep, run repeatedly, is itself
  a resource-consumption vector against the SSRF-vulnerable worker pool — useful to
  note if resource exhaustion is in scope, but avoid running sweeps at a volume that
  causes actual denial of service unless that impact is specifically what you intend
  to demonstrate and it's authorized.
- **Cloud metadata credentials (file 3) feeding back into this file:** credentials
  recovered from a metadata endpoint may themselves grant access to internal
  cloud-native services (an RDS instance, an internal load balancer's admin API) that
  are a more direct and higher-fidelity path than blind port-sweeping — check
  recovered IAM/service-account permissions before investing time in a manual sweep.

## WAF / API Gateway Considerations

This is the pattern where network-layer egress controls matter most and where they are
most commonly actually implemented, because "can this service reach our internal
database subnet" is a more intuitive security question for infra teams to reason about
than "can this service reach 169.254.169.254." Where a service mesh (Istio, Linkerd) or
Kubernetes NetworkPolicy restricts egress to an explicit allowlist of internal
service DNS names, the sweep above will fail uniformly (every internal IP times out
identically) rather than showing per-host variation — that uniform-failure pattern is
itself informative and worth distinguishing from "the target has no other internal
services" in your notes. Bypassing a properly-configured NetworkPolicy/mesh egress
allowlist through the SSRF primitive alone is generally not possible without an
independent vulnerability in the mesh/policy configuration itself (out of scope for
this note) — the general SSRF bypass techniques (DNS rebinding, redirect chaining) in
the web application series apply to *URL-based* filtering, not to network-layer policy
enforcement, and should not be assumed to work against the latter without verification.

## Real-World Note

The single most consistent finding across real API engagements involving SSRF-to-pivot
is an internal Kibana, Grafana, or internal-only admin dashboard with no
authentication at all, reachable on a non-standard port that would never appear in
external recon. These rarely show up in the "expected" high-value list (databases,
Kubernetes API) but are disproportionately likely to actually be there and actually be
open.

## Cross-References

- Establishing the initial SSRF primitive: file 2.
- Cloud credential recovery that may shortcut this entire pivot: file 3.
- Confirming reachability for blind primitives before attempting a full sweep:
  file 4.
- Post-pivot access control testing: BOLA and BFLA series.
- General SSRF protocol-smuggling (gopher://, Redis): Web Application Security —
  SSRF series.
