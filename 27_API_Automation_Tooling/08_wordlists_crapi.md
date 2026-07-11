# API Security Testing Tooling — Wordlist Reference & crAPI Setup

## 1. API-Specific Wordlists

### 1.1 SecLists

SecLists (`danielmiessler/SecLists`) is the standard general-purpose security
wordlist collection. The subsets most relevant to API testing:

```
git clone https://github.com/danielmiessler/SecLists.git
```

- **`Discovery/Web-Content/api/`**: a directory containing several API-endpoint-
  focused wordlists, including `api-endpoints.txt` (common REST path segments like
  `users`, `orders`, `admin`, `health`, `status`, `metrics`) and `api-mounts.txt`
  (common base paths where an API is mounted, e.g., `/api`, `/api/v1`, `/rest`,
  `/graphql`). Use these as the `-w` input for ffuf path brute-forcing (file 03)
  when you don't yet have a target-specific wordlist.
- **`Discovery/Web-Content/common-api-endpoints-mazen160.txt`**: a large,
  community-contributed flat list of common API endpoint path segments — a good
  general-purpose first pass before moving to more targeted lists.
- **`Discovery/Web-Content/swagger.txt`**: paths commonly used to host exposed
  Swagger/OpenAPI documentation (`/swagger.json`, `/api-docs`, `/v2/api-docs`,
  `/openapi.yaml`) — run this specifically as an early, high-value pass since a
  hit here (cross-reference nuclei's `swagger`/`openapi` tags in file 05) can
  expose the entire API surface in one request.
- **`Discovery/Web-Content/graphql.txt`**: common GraphQL endpoint paths
  (`/graphql`, `/graphql/console`, `/api/graphql`, `/v1/graphql`) — the starting
  wordlist for locating a GraphQL endpoint when its path isn't already known.
- **`Discovery/Variables/`**: contains wordlists of common variable/parameter
  names (e.g., `top-parameters.txt` at various size tiers) — feed these into
  Arjun's `-w` or Param Miner's wordlist field (file 02/03) for hidden parameter
  discovery, since they're tuned for common naming conventions (`id`, `token`,
  `debug`, `admin`, `callback`) rather than API-path-specific terms.
- **`Passwords/`**: general password wordlists — relevant to jwt_tool's `-C` crack
  mode (file 04) when testing for weak HMAC signing secrets, though a
  purpose-built small "common secrets" list (below) is usually more efficient
  than a full password list for this specific use case.

### 1.2 Assetnote Wordlists

Assetnote publishes wordlists specifically derived from real-world API
specifications scraped at scale (the same underlying data source that powers
kiterunner's route dictionaries — file 03).

```
# Published under Assetnote's wordlists repository/releases
# e.g., https://wordlists.assetnote.io
```

- **`httparchive_apiroutes_*`**: API route wordlists mined from HTTP Archive
  (httparchive.org) crawl data — segmented by size tier (small/medium/large/xlarge)
  trading coverage for scan time. These are the same family of route dictionaries
  kiterunner consumes natively in `.kite` format, but the raw `.txt` versions can
  also be used directly as ffuf `-w` input for teams that prefer ffuf's flag set
  over kiterunner's for a given scan.
- **`automated-api-*`**: wordlists specifically built from scraped Swagger/OpenAPI
  specification path definitions — higher precision (more likely to be real API
  paths) but somewhat lower raw coverage than the httparchive-derived lists, since
  they only include paths that appeared in an actual discovered spec somewhere.
- **Parameter-name wordlists**: Assetnote also publishes parameter-name lists
  derived from the same spec-scraping process, usable as Arjun `-w` input as an
  alternative/supplement to SecLists' `Discovery/Variables/` lists — generally
  higher hit rate specifically for REST/JSON API parameter names since they were
  mined from real API specs rather than general web parameter usage.

### 1.3 Choosing Which Wordlist to Use When

| Situation | Recommended wordlist |
|---|---|
| First pass against an unknown API, no other intel | SecLists `common-api-endpoints-mazen160.txt` or Assetnote `httparchive_apiroutes_small` |
| Target uses versioned RESTful conventions (`/api/v2/resource/{id}/sub-resource`) | kiterunner with Assetnote route dictionaries (`.kite`) — file 03 |
| Checking for exposed API documentation | SecLists `swagger.txt` |
| Locating a GraphQL endpoint | SecLists `graphql.txt` |
| Hidden parameter discovery on a known endpoint | Assetnote parameter list, or SecLists `Discovery/Variables/top-parameters.txt`, via Arjun/Param Miner |
| Cracking a weak JWT HMAC secret | a small purpose-built "common API secrets" list (project-name-derived guesses, common defaults like `secret`/`changeme`) before falling back to a general password list |
| Time-constrained engagement, need best coverage-per-request | Assetnote's spec-derived lists (`automated-api-*`) — higher precision means fewer wasted requests than a general web wordlist |

## 2. crAPI Setup

**crAPI (Completely Ridiculous API)** is a deliberately vulnerable, Docker-based
API application (OWASP-adjacent community project) covering a wide range of
realistic API security flaws across a mock vehicle-marketplace/community
application. It is the primary practice environment for this entire tooling
series, as established in file 01.

### 2.1 Prerequisites

- Docker and Docker Compose installed.
- At least 4 GB RAM available for the Docker environment (crAPI runs several
  microservices — identity, community, workshop — plus supporting infrastructure
  like a message queue and mail catcher).

### 2.2 Running crAPI Locally

```
curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml
docker compose pull
docker compose -p crapi up -d
```

- `curl -o docker-compose.yml <url>`: downloads crAPI's official Docker Compose
  definition file.
- `docker compose pull`: pulls all required container images defined in the
  compose file before starting (avoids a slow first-run pull happening
  mid-startup).
- `docker compose -p crapi up -d`: starts the full multi-container stack.
  - `-p crapi`: sets the Docker Compose project name, namespacing the containers
    (useful when running multiple unrelated Docker Compose projects on the same
    host, to avoid container name collisions).
  - `up -d`: starts all defined services in detached (background) mode.

Once started, crAPI is typically accessible at `http://localhost:8888` (the web
frontend) with its various API services reachable at their own sub-paths
(`/identity/api/...`, `/community/api/...`, `/workshop/api/...`) — confirm exact
ports/paths against the compose file's port mappings, as these have occasionally
shifted across crAPI releases.

**Mail catcher**: crAPI includes a local mail-catching service (typically at
`http://localhost:8025` via MailHog or similar) since several of its flows (email
verification, password reset) send real emails within the local Docker network —
check this UI to retrieve verification links/OTPs needed to complete signup and
password-reset testing flows.

### 2.3 Stopping and Resetting

```
docker compose -p crapi down -v
```
- `down`: stops and removes the containers.
- `-v`: also removes the named volumes (database state) — use this for a full
  reset to a clean initial state between practice sessions; omit `-v` if you want
  to preserve accumulated test data (created users, orders, etc.) across restarts.

### 2.4 crAPI Vulnerabilities Mapped to Topics in This Note Library

| crAPI Feature/Endpoint Area | Vulnerability Practiced | Related Series in This Library |
|---|---|---|
| `/identity/api/auth/*` (signup, login, password reset) | Broken authentication, weak password reset OTP, JWT issues | Broken Authentication series, JWT series |
| `/identity/api/v2/user/videos` and profile picture upload | SSRF via video conversion, insecure file upload | SSRF series |
| `/identity/api/v2/user/{id}` and related object access | BOLA — accessing/modifying other users' profile data | BOLA series |
| `/workshop/api/shop/orders` and coupon/pricing endpoints | Business logic flaws, excessive data exposure, BOPLA | API6 Unsafe Business Flows, BOPLA/Mass Assignment series |
| `/workshop/api/mechanic/*` (mechanic-only endpoints reachable by regular users) | BFLA — function-level authorization bypass | BFLA series |
| `/community/api/v2/community/posts` | BOLA/IDOR on community posts, stored injection in post content | BOLA series, injection series |
| `/identity/api/v2/vehicle/vin` (VIN/location endpoints) | Excessive data exposure, BOLA on vehicle location data | BOLA series, API3-equivalent excessive data exposure content |
| Rate limiting on OTP/login endpoints | Missing rate limiting enabling brute-force | Rate limit/bot protection bypass series |
| Overall JSON API surface | General target for every tool in this series (ffuf, kiterunner, Arjun, httpx, katana, nuclei, jq pipelines) | This entire series |

### 2.5 Real-World Notes

- crAPI's microservice architecture (separate identity/community/workshop
  services, each with its own API surface) makes it a realistic target for
  practicing the recon-phase tooling in this series (katana crawling the web
  frontend, ffuf/kiterunner brute-forcing each service's API base path
  independently, httpx validating and fingerprinting each discovered service) —
  don't treat it as a single flat API; scan each service's base path separately
  to mirror how a real microservice-based target would be approached.
- crAPI is intentionally reset-friendly (`docker compose down -v` + `up -d`) —
  use this to get a clean state before practicing tools that create persistent
  side effects (e.g., testing mass assignment by creating many test users/orders)
  so accumulated test data doesn't distort a later practice session's baseline.
