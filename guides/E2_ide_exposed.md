# E2 — GraphiQL / Apollo Sandbox IDE Exposed in Production

## What it is

**GraphiQL**, **GraphQL Playground**, and **Apollo Sandbox** are interactive in-browser IDEs for exploring a GraphQL API. They provide a schema browser, an autocompleting query editor, and a "run" button. They are intended for use during development on a local machine, but many frameworks ship them enabled by default. When the operator forgets to disable them, anyone with the endpoint URL gets a polished reconnaissance UI in their browser.

The OWASP cheat sheet explicitly names these tools as default-on hardening failures and recommends turning them off in production.

## How it works

GraphQL endpoints conventionally negotiate response format on the basis of the `Accept` header:

- `Accept: application/json` → the server returns API data.
- `Accept: text/html` → the server returns the IDE's HTML shell (an HTML page that bundles or fetches the IDE's JavaScript).

When the browser visits the endpoint, it sends `Accept: text/html,application/xhtml+xml,...` and the server happily returns the IDE. The IDE then runs in the browser, calls the same endpoint with `Accept: application/json` to run an introspection query (see E1), and renders the entire schema in a navigable side panel. From there the user can compose any query the schema supports.

Three IDEs dominate:

| IDE | Default-on frameworks | HTML fingerprint |
|---|---|---|
| **GraphiQL** | `express-graphql`, `graphql-yoga`, older `apollo-server`, most Python servers | `<title>GraphiQL</title>`, `id="graphiql"`, `react-dom`, `graphiql.min.css` |
| **GraphQL Playground** | older `apollo-server`, `prisma`, `hasura` | `<title>GraphQL Playground</title>`, `react-root`, `playground` CSS |
| **Apollo Sandbox** | `apollo-server` ≥ 3 | `Apollo Sandbox`, `embeddable-sandbox`, `studio.apollographql.com/sandbox/embed` |

### Why it matters

A publicly exposed IDE turns reconnaissance from a scripting task into a point-and-click experience. Even when introspection is disabled at the API layer (E1), Apollo Sandbox can sometimes infer schema from cached responses, and the IDE itself confirms the framework and version. It also lowers the skill floor — an attacker without GraphQL fluency can browse and craft queries in a friendly UI.

## How to reproduce (single benign request)

This is **a single HTTP GET with an HTML Accept header — exactly what a browser sends when a user opens the URL**. No exploit logic, no automation surface; this is the same request as `firefox $EP`.

### Step 1 — Set the endpoint

```bash
EP="https://countries.trevorblades.com"
```

### Step 2 — Request the HTML view

```bash
curl -sS -L "$EP" \
     -H 'Accept: text/html,application/xhtml+xml' \
     -H 'User-Agent: GraphQL-Academic-Survey/1.0' \
     -o "site_${SITE_ID}_E2.html"
head -c 4000 "site_${SITE_ID}_E2.html"
```

The `-L` flag follows redirects (some services redirect `/graphql` → `/graphql/`). The response body is saved so it can be archived as evidence.

### Step 3 — Fingerprint the response

Grep the first few KB for the markers in the table above:

```bash
grep -Eoi 'GraphiQL|graphql-playground|Apollo Sandbox|embeddable-sandbox|playground' "site_${SITE_ID}_E2.html" | sort -u
```

### Step 4 — Classify

| Observation | Verdict |
|---|---|
| Any of the IDE fingerprints present and HTTP status is 200 | **Vulnerable — IDE exposed** (record which IDE) |
| JSON response like `{"errors":[{"message":"Must provide query string."}]}` | Safe — endpoint returns API, not IDE |
| HTTP 404 / 405 / 403 / 401 on GET | Safe — endpoint refuses HTML clients |
| HTTP 200 but body is unrelated HTML (homepage, login page, marketing site) | Endpoint URL is wrong or behind a reverse proxy; mark as *unknown* |

### Step 5 (optional, for documentation only)

Open the URL in a real browser to confirm the IDE is interactive, then take **one** screenshot for the writeup. Do not click "Run" inside the IDE — that would issue further requests against the target.

## Browser-based reproduction (this exploit IS the browser test)

E2 is uniquely well-suited to browser reproduction — visiting the endpoint *is* the test.

### Approach A — Direct browser visit (the canonical test)

1. Open the target endpoint URL in any browser, e.g. `https://countries.trevorblades.com`.
2. Observe what loads in the tab:
   - A polished IDE with editor, schema panel, run button → **vulnerable**. Identify which IDE from the title bar / page header (GraphiQL, GraphQL Playground, Apollo Sandbox).
   - A raw JSON error like `{"errors":[{"message":"Must provide query string."}]}` → **safe**.
   - A 404 / 405 page → **safe**.
3. Screenshot the entire viewport. This is the primary evidence for the writeup.
4. Optional: take a second screenshot after clicking the *Docs* / *Schema* panel; that demonstrates the introspection-fed schema browser (cross-evidence for E1).
5. **Do not press the IDE's "Run" / "Play" button on real data.** The page being rendered is the finding; running a query is unnecessary and would send further traffic to the target.

### Approach B — DevTools Network tab (for documenting the HTTP exchange)

1. Open the endpoint URL with DevTools already open on the **Network** tab.
2. Find the main document request; right-click → **Save as HAR with content**. The HAR captures the GET, the response headers, and the HTML body — a self-contained archival artefact for the writeup.
3. Inspect the response headers panel for `Content-Type: text/html` and any framework hints in `Server` or `X-Powered-By`.

### Approach C — `curl` then open the saved HTML locally (offline-safe)

If you prefer not to load the IDE's JavaScript live, use the curl command from the *How to reproduce* section to download the HTML to disk, then open the saved file in a browser locally with the network disabled (via DevTools → Network → "Offline"). You get the IDE shell but without it fetching the live schema. Useful if you want to take a screenshot purely for documentation without generating additional traffic against the target.

## OWASP recommended mitigation

Disable the IDE on production endpoints. Concretely:

- `apollo-server` v3+: `introspection: false` plus omit the `ApolloServerPluginLandingPageLocalDefault` plugin, or replace it with `ApolloServerPluginLandingPageProductionDefault` (which is a static page without a query runner).
- `express-graphql`: pass `graphiql: false`.
- `graphql-yoga`: pass `graphiql: false`.
- `hasura`: set `HASURA_GRAPHQL_ENABLE_CONSOLE=false` and `HASURA_GRAPHQL_ENABLED_APIS=graphql` (omitting `graphiql`).

## What to record per target

- HTTP status code on the GET request
- Whether an IDE was detected, and which one (GraphiQL / Playground / Sandbox / none)
- The first 2 KB of the HTML body, saved as `raw/<site_id>_E2.html`
- (If vulnerable) one screenshot saved as `raw/<site_id>_E2.png`
