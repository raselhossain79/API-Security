# Server-Side Template Injection (SSTI) via API

> Prerequisite: core SSTI mechanics (template engine identification, sandbox escape
> chains, RCE payloads per engine) from the standalone SSTI series. This file covers
> how SSTI delivery and confirmation change when the vulnerable parameter arrives
> through an API's JSON string field rather than a rendered HTML form/template
> context.

## 1. Why APIs Are a Common SSTI Delivery Surface

SSTI requires user input to be concatenated into a template string that is then
*rendered* by a template engine (Jinja2, Twig, Freemarker, Velocity, Handlebars,
etc.), rather than merely inserted as data. API endpoints that generate dynamic
content are a common source of this pattern:

- Email/notification generation APIs (`POST /api/notifications/send` with a
  `template` or `message` field used to personalize content — "Hello {{username}}")
- Report/document generation APIs building PDF or HTML output from a JSON-supplied
  template string
- "Preview" or "test render" endpoints exposed by CMS-like or marketing-tool backends
  that let a user preview how a template renders before saving it
- Configuration/customization APIs where a user-supplied field (e.g., a custom
  "welcome message") is later rendered as a template rather than displayed as static
  text

The critical distinguishing feature versus other injection classes in this series:
**the vulnerable value doesn't need to look like code at all in the request** — it
can be an entirely innocuous-looking string field like `"displayName"` or
`"welcomeMessage"` that only becomes dangerous because of *how* the backend later
processes it (as a template) rather than anything unusual about the request itself.
This makes SSTI one of the harder-to-spot classes purely from reading API traffic —
identification depends on testing every string field for template syntax reflection,
not on the field name suggesting danger.

## 2. The Vulnerable Pattern

```python
# Vulnerable Flask + Jinja2 example
@app.route('/api/v1/notifications/preview', methods=['POST'])
def preview_notification():
    data = request.get_json()
    template_str = f"Hello {data['username']}, {data['message']}"
    rendered = render_template_string(template_str)
    return jsonify({"preview": rendered})
```

`data['message']` is concatenated directly into a string that is then passed to
Jinja2's `render_template_string()` — meaning the *content* of `message` is treated
as template source code, not as inert display data.

## 3. Basic SSTI Confirmation — Payload Breakdown

### 3.1 Baseline Request

```json
{
  "username": "Rasel",
  "message": "Welcome to the platform!"
}
```

Normal response: `{"preview": "Hello Rasel, Welcome to the platform!"}` — the message
is echoed back unchanged.

### 3.2 Injected Request (Jinja2 Target)

```json
{
  "username": "Rasel",
  "message": "{{7*7}}"
}
```

**Breakdown, piece by piece:**

| Fragment | Role |
|---|---|
| `{{` | Opens a Jinja2 expression block — everything between `{{` and `}}` is evaluated as a Python expression by the template engine, not displayed literally |
| `7*7` | Arithmetic expression used purely as a detection probe — its result (`49`) cannot occur by coincidence in a normal string echo, making it an unambiguous confirmation signal |
| `}}` | Closes the expression block |

If the JSON response comes back as `{"preview": "Hello Rasel, 49"}` instead of
echoing `{{7*7}}` literally, this confirms the `message` field is being *rendered*,
not just displayed — this is the SSTI equivalent of the SQLi single-quote probe or
the command injection `whoami` probe: a minimal, unambiguous confirmation payload
before escalating to exploitation.

**Why no JSON escaping is required:** the payload uses only `{`, `}`, `*`, and
digits — none of which are JSON-reserved characters. It drops into the JSON string
value as-is. This is a recurring pattern across this series: **template and
expression-language syntax rarely collides with JSON syntax**, which is why SSTI
payloads are usually simpler to deliver via JSON body than SQLi payloads are — the
double-escaping problem from file 02 is far less common here.

## 4. Template Engine Fingerprinting via API Response Behavior

Because API responses are structured JSON rather than rendered HTML pages, engine
fingerprinting relies more heavily on **exact response body comparison** than visual
page inspection. Test each of the following payloads as the `message` value and
compare the returned `preview` field:

| Payload | Engine if evaluated | Expected result in response |
|---|---|---|
| `{{7*7}}` | Jinja2 (Python) | `49` |
| `${7*7}` | Freemarker / some EL-based engines | `49` |
| `#{7*7}` | Ruby-based (Slim, some ERB contexts) | `49` |
| `{{7*'7'}}` | Jinja2 specifically (disambiguates from Twig, which errors on type mismatch) | `7777777` (Python string repetition) |
| `{{ 7*7 }}` (with spaces) | Twig (PHP) | `49` |

**Breakdown of the disambiguation payload `{{7*'7'}}`:** in Python (Jinja2), the `*`
operator on a string performs repetition, so `7 * '7'` evaluates to `'7777777'` — a
distinctive, engine-specific result that confirms Jinja2 specifically rather than
just "some engine using `{{ }}` delimiters," since Twig would raise a type error on
the same expression rather than silently repeating the string.

## 5. Escalating to RCE — Payload Breakdown (Jinja2 Example)

Once the engine is confirmed as Jinja2, escalate toward code execution using Python's
object introspection to reach `os.popen` or `subprocess` indirectly (standard Jinja2
sandbox-escape chain, covered in depth in the standalone SSTI series — summarized
here only for the JSON-delivery-specific escaping consideration):

```json
{
  "username": "Rasel",
  "message": "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"
}
```

**Breakdown, piece by piece:**

| Fragment | Role |
|---|---|
| `self.__init__.__globals__` | Walks from the template's `self` object back to the Python global namespace, escaping the Jinja2 sandbox's restricted variable scope |
| `.__builtins__` | Reaches Python's built-in functions namespace from the globals dict |
| `.__import__('os')` | Dynamically imports the `os` module without needing `import os` to already be available in scope |
| `.popen('id').read()` | Executes the shell command `id` and reads its captured stdout — this is the actual code-execution payload, structurally identical in purpose to the command injection payloads in file 04, but reached via template sandbox escape rather than direct shell concatenation |

**JSON escaping note:** this specific payload contains single quotes (`'os'`,
`'id'`) but no double quotes, so it remains JSON-safe as written directly inside a
JSON string value with standard double-quote delimiters — no backslash-escaping
needed. If your specific payload variant requires double quotes (some Jinja2 escape
chains use `"os"` instead of `'os'` depending on the exact gadget), escape each `"`
as `\"` exactly per the two-layer encoding principle established in file 02, Section
2.3.

## 6. Testing Workflow (Burp)

1. Enumerate every string-typed field in every JSON request body across the target
   API — not just fields with names suggesting template/message content, per Section
   1's note that SSTI-vulnerable fields often look completely innocuous.
2. Send the minimal detection payload (`{{7*7}}`) as each field's value in turn,
   using Repeater, watching for `49` appearing anywhere in the JSON response.
3. On a hit, run the fingerprinting table (Section 4) to identify the specific
   engine before selecting an exploitation payload — using the wrong engine's syntax
   wastes requests and can produce misleading errors.
4. Escalate carefully and incrementally: confirm arithmetic evaluation first, then
   object introspection (`{{self}}` or `{{7*7}}{{config}}` in Flask/Jinja2 context to
   dump accessible config objects, a lower-risk information-disclosure step), before
   attempting full RCE payloads — this matches responsible testing practice and
   avoids unnecessary system impact during initial confirmation.
5. If the response doesn't reflect the rendered value directly (blind SSTI — e.g.,
   the template is rendered into a PDF report or email that isn't returned in the
   HTTP response), use the same OOB technique from file 04 Section 5.2: inject a
   payload that triggers a DNS/HTTP callback via the same `os.popen`/`__import__`
   introspection chain, substituting `curl` or `nslookup` as the executed command.

## 7. PortSwigger Lab Mapping

Complete in this order:

1. **Basic server-side template injection** — establishes the core detection
   (`{{7*7}}`) and direct exploitation flow in a rendered-page context.
2. **Basic server-side template injection (code context)** — teaches injecting into a
   context where input is already inside a template expression rather than plain
   text, a distinction relevant to API fields that might feed directly into an
   expression argument (e.g., a "formula" or "condition" field) rather than free text.
3. **Server-side template injection using documentation** — teaches the
   engine-fingerprinting methodology (Section 4 here mirrors this lab's approach)
   for engines you haven't memorized payloads for.
4. **Server-side template injection in an unknown language with a documented
   exploit** and **...with a custom exploit** — advanced escalation practice, directly
   transferable to Section 5's introspection-chain approach for engines beyond
   Jinja2.

**Gap disclosure:** as with SQLi and command injection, all current PortSwigger SSTI
labs deliver the payload via a form field or URL parameter, not a JSON API body. The
JSON-delivery consideration (Section 5's escaping note) is not tested by any lab and
should be practiced against real JSON API targets.

## 8. Real-World Notes

- Notification/email-templating microservices are a disproportionately common source
  of API-delivered SSTI because "let admins customize the welcome email text" is a
  common product feature, and the customization field frequently ends up passed
  through the same template engine used for the email's *structural* template
  (subject, layout, etc.) rather than being treated as inert user data — the
  developer intends only *admin-supplied* templates to be trusted, but the same
  rendering code path often gets reused for *end-user-supplied* fields like display
  names or custom messages without that trust boundary being re-evaluated.
- SSTI findings via API are frequently **blind** in production (the rendered output
  goes into a PDF, email, or internal report rather than back into the HTTP
  response), making OOB confirmation (Section 6, step 5) the default expectation
  rather than a fallback — plan Collaborator/interactsh setup before starting SSTI
  testing against any API target, not after boolean/direct methods fail.
- Handlebars (`{{ }}`) is intentionally designed to be logic-less and resistant to
  arbitrary code execution by default, unlike Jinja2/Twig/Freemarker — confirming
  Handlebars as the engine (via the fingerprinting table) does not mean the
  vulnerability is unexploitable, but it does mean the exploitation path is
  meaningfully different (prototype pollution / helper-abuse chains rather than
  direct Python/Java object introspection) and is outside this file's scope — treat a
  Handlebars confirmation as a signal to consult SSTI-engine-specific research rather
  than assuming the Jinja2-style escalation chain applies.
