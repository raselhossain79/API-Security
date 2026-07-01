# Reading API Documentation

> API documentation is often your single best source of attack surface before you
> start testing. A well-documented API hands you every endpoint, every parameter,
> every data type — this is why finding exposed Swagger/OpenAPI specs is considered
> a security misconfiguration finding in its own right.

---

## 1. OpenAPI / Swagger

OpenAPI (formerly Swagger) is the standard format for documenting REST APIs.
Usually available at predictable paths:

```
/swagger
/swagger-ui
/swagger-ui.html
/api-docs
/openapi.json
/openapi.yaml
/v1/swagger.json
/api/v1/docs
```

**What an OpenAPI spec looks like (YAML format):**
```yaml
openapi: "3.0.0"
paths:
  /users/{id}:
    get:
      summary: Get user by ID
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
      security:
        - bearerAuth: []
      responses:
        "200":
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/User"
  /admin/users:
    delete:
      summary: Delete all users
      security:
        - bearerAuth: []
```

**What to look for when reading an OpenAPI spec:**

1. **All endpoints** — especially ones not visible in the UI (`/admin/`, `/internal/`,
   `/debug/`, `/v1/` vs current version)
2. **All HTTP methods per endpoint** — spec might list GET and POST but the actual
   server also accepts DELETE/PUT
3. **Parameters** — every path parameter (`{id}`), query parameter, header, and
   request body field is a test target
4. **Security schemes** — which endpoints require auth (none listed = no auth required,
   which is immediately worth testing)
5. **Response schemas** — what fields the API returns, including any fields that
   might be sensitive or useful for further attacks
6. **Deprecated/old version paths** — specs sometimes document v1 endpoints as
   deprecated but still working

---

## 2. Postman Collections

Teams often share Postman collections for their APIs — sometimes these are public
(on Postman's public API network), sometimes found in git repos. A collection is a
JSON file containing every request with pre-filled parameters.

**How to use a found Postman collection:**
1. Import it into Postman (File → Import)
2. Set up an Environment with your test credentials (`base_url`, `auth_token`)
3. Every request in the collection is a pre-built test case — your job is to modify
   the parameters to test for vulnerabilities

**What to look for in a Postman collection:**
- Hardcoded credentials or API keys in request headers (a finding by itself)
- Admin/internal endpoints included in the collection alongside regular user endpoints
- Parameter examples that reveal expected data formats
- Pre-request scripts that show authentication flow

---

## 3. GraphQL Schema via Introspection

When GraphQL introspection is enabled (it often is in dev/staging, sometimes in
production), you can extract the entire schema with one query:

```json
POST /graphql
{
  "query": "{ __schema { types { name fields { name type { name } } } } }"
}
```

Breaking this down:
- `__schema` — GraphQL's built-in introspection entry point
- `types` — all object types in the schema
- `name` — the type name (User, Order, Admin, etc.)
- `fields` — all fields on each type, with their types

**What to look for in the schema:**
- Types named `Admin`, `Internal`, `Debug`, `System` — these often have privileged
  mutations not exposed in the UI
- Mutations (write operations) that aren't in the official docs
- Fields on objects that the UI doesn't display but the API returns

---

## 4. WSDL Files (SOAP)

WSDL (Web Services Description Language) is the SOAP equivalent of OpenAPI.
Usually found at `?wsdl` appended to the service URL:
```
http://api.example.com/service?wsdl
```

It describes every method, input/output parameters, and data types in XML format.
Import into SoapUI or convert to Postman using `wsdl2postman` to get testable
request templates.

---

## 5. Undocumented Endpoint Discovery (When Docs Are Missing)

When there's no documentation available:

**From JavaScript files:** Modern SPAs store API endpoint paths in JS bundles.
```bash
# Download all JS files and grep for API paths
curl https://example.com/app.js | grep -oE '"/api/[^"]*"'
```

**From mobile apps:** APK/IPA decompilation often reveals hardcoded API endpoints,
keys, and base URLs.

**From browser Network tab:** Browse the application normally while watching the
Network tab (filtered to Fetch/XHR) — every API call your user actions trigger
is recorded with full request/response details.

**From Burp Target → Site Map:** Everything proxied through Burp gets recorded in
the site map tree automatically.

Continue to → `05_Burp_Suite_for_API_Testing.md`
