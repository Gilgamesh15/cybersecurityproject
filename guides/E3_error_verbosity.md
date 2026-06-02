# E3 — Verbose Error Messages / Stack Trace Leakage

## What it is

A well-hardened GraphQL server returns a small, generic `errors` array when a query is malformed: it tells the client *what* went wrong (e.g., "Cannot query field X") without saying *where* in the server-side code the error originated. A poorly hardened server returns the raw exception object — stack trace, file paths, framework version, ORM internals, sometimes even environment variables or secrets that the framework happened to interpolate into the error message.

OWASP names "excessive error messages" as a reconnaissance vector that lets attackers fingerprint the framework, locate vulnerable libraries by version, and identify code paths worth attacking next.

## How it works

The GraphQL response format guarantees an `errors` array for any operation that fails validation or execution. Each entry can carry an arbitrary `message` plus an `extensions` object whose contents are entirely up to the server. The default behaviour of common frameworks is:

| Framework | Default in development | Default in production (if `NODE_ENV`/equivalent is set) |
|---|---|---|
| `apollo-server` v3+ | `errors[].extensions.exception.stacktrace` included | omitted, but only if `NODE_ENV=production` is actually set |
| `apollo-server` v2 | full stack trace included | depends on `debug` constructor option |
| `graphene-python` | exception class name and traceback in `message` | same — must be overridden by middleware |
| `graphql-java` | wrapping exception serialised with full chain | requires custom `DataFetcherExceptionHandler` |
| `express-graphql` | `formatError` defaults to returning `error.stack` | same — must be overridden |
| `hot-chocolate` (.NET) | full exception details | requires `IErrorFilter` |

In practice, many deployments either forget to set `NODE_ENV=production`, or run a dev container in prod, or leave a debug-mode override flag on for "easier troubleshooting". The result is that stack traces leak.

### Why it matters

A leaked stack trace reveals:

1. **Framework + version** — feeds directly into CVE lookups (e.g., specific `apollo-server` releases with known vulnerabilities).
2. **Internal file paths** — discloses the container image layout, suggests language, hints at deployment platform (`/usr/src/app/` → Node Docker, `/var/www/` → traditional LAMP-style).
3. **Library names in the stack** — reveals ORMs (`sequelize`, `mongoose`, `prisma`, `typeorm`), authentication libraries, etc., each of which has its own CVE history.
4. **Code paths** — function names and module paths suggest where input validation happens (or doesn't).

## How to reproduce (single benign request)

The diagnostic request is **a deliberately malformed query — structurally identical to a developer typo**. No exploit payload, no resource cost, no side effects.

### Step 1 — Set the endpoint

```bash
EP="https://countries.trevorblades.com"
```

### Step 2 — Send a query referencing a clearly nonsense field

```bash
curl -sS -X POST "$EP" \
     -H 'Content-Type: application/json' \
     -H 'User-Agent: GraphQL-Academic-Survey/1.0' \
     -d '{"query":"{ __nonexistent_field_xyz_diagnostic }"}' \
     | tee "site_${SITE_ID}_E3.json"
```

The field name is intentionally absurd (`__nonexistent_field_xyz_diagnostic`) so there is zero risk of accidentally hitting a real field, and so it is obvious in any operator's logs that the request was diagnostic.

### Step 3 — Scan the response for verbosity markers

```bash
grep -Eoi 'stacktrace|stack trace|at [A-Z][a-zA-Z]+|/(usr|app|home|var|src)/|apollo-server@|graphql-core|graphql-java|Sangria|HotChocolate|node_modules|Traceback' "site_${SITE_ID}_E3.json"
```

Specific patterns to look for:

| Pattern in response | What it reveals |
|---|---|
| `errors[].extensions.stacktrace` (array of strings) | Apollo `debug: true` mode |
| `errors[].extensions.exception` object | Apollo with `includeStacktraceInErrorResponses: true` |
| File paths: `/usr/src/app/`, `/app/`, `/home/`, `/var/www/`, `C:\\` | Deployment layout |
| Function frames: `at GraphQLError`, `at executeImpl`, `at Object.<anonymous>` | Node + graphql-js |
| `Traceback (most recent call last):` | Python (graphene / strawberry) |
| `at graphql.execution.` | Java (graphql-java) |
| Version strings: `apollo-server@3.10.2`, `graphql-core 3.x` | Direct version disclosure |

### Step 4 — Classify

| Observation | Verdict |
|---|---|
| Stack trace **or** any internal file path **or** a version string in the response | **Vulnerable — verbose errors** |
| Only `{"errors":[{"message":"Cannot query field \"__nonexistent_field_xyz_diagnostic\" on type \"Query\"","locations":[...]}]}` or similar generic shape | Safe — errors masked |
| HTTP 401/403 (request rejected before query parse) | Cannot diagnose unauthenticated; mark *unknown* |
| HTTP 200 + `data` with the bogus field as `null` and no error | Schema is unusually permissive (effectively safe for this check, but worth noting) |

## Browser-based reproduction (preferred for documentation screenshots)

### Approach A — If E2 reports an IDE is exposed: use the target's own IDE

1. Visit the endpoint URL in the browser; the embedded GraphiQL / Sandbox loads.
2. In the editor pane, replace any default query with:
   ```graphql
   { __nonexistent_field_xyz_diagnostic }
   ```
3. Press `Ctrl-Enter` (or click the Run button). The result panel on the right will display the JSON error response.
4. If the response includes a `stacktrace` array under `extensions`, or any file paths, or a framework version, screenshot the result panel as evidence of verbose errors.

### Approach B — Hosted in-browser GraphQL client (works on any endpoint)

1. Open <https://hoppscotch.io/graphql> in the browser.
2. Paste the endpoint URL.
3. In the query editor put: `{ __nonexistent_field_xyz_diagnostic }`. Click **Send**.
4. The response panel displays the parsed JSON. Use the JSON tree view to expand `errors[0].extensions` and look for `stacktrace`, `exception`, `code`, etc.
5. Screenshot the response panel.

### Approach C — Browser DevTools Console (universal fallback)

1. Open DevTools → **Console** on any page.
2. Run:

   ```js
   fetch("https://countries.trevorblades.com", {
     method: "POST",
     headers: { "Content-Type": "application/json" },
     body: JSON.stringify({ query: "{ __nonexistent_field_xyz_diagnostic }" })
   }).then(r => r.json()).then(j => console.log(JSON.stringify(j, null, 2)));
   ```

3. The pretty-printed JSON response appears in the Console. Look in `errors[].extensions` for any of:
   - `stacktrace: [...]` (Apollo debug mode)
   - `exception: { ... }`
   - File paths (`/usr/src/app/`, `/home/`, drive letters)
   - Framework version strings
4. Screenshot the Console output. For a richer artefact, switch to the **Network** tab, click the matching `POST` request, and screenshot the Preview/Response sub-tab — the formatted error tree is easier to read than raw text.

## OWASP recommended mitigation

The cheat sheet recommends masking errors in production:

- `apollo-server`: set `NODE_ENV=production`, plus `formatError` to strip `extensions.exception` and `extensions.stacktrace`.
- `graphene-python`: replace `GraphQLView.format_error` with a function that returns `{"message": "Internal server error"}` for any unhandled exception.
- `graphql-java`: implement `DataFetcherExceptionHandler` that logs server-side and returns a generic `GraphQLError` to the client.
- Generally: log full errors server-side, return only the error class and a request ID to clients.

## What to record per target

- HTTP status
- Whether a stack trace, file path, or version string was found (booleans)
- The exact framework signature identified (free-text, e.g., `apollo-server@3.10.2`)
- Raw response saved as `raw/<site_id>_E3.json`
