# E1 — Introspection Query Exposure

## What it is

GraphQL servers can answer a special meta-query that returns the entire schema — every type, field, argument, and description. OWASP describes introspection as allowing *"the consumer of your API to learn everything about API, schemas, mutations, deprecated fields."* When left enabled on a production endpoint, this hands an attacker a complete map of the API for free, without any authentication.

Introspection itself is not "an attack" — it is a legitimate feature of the GraphQL specification used by every GraphQL client (GraphiQL, Apollo Studio, Insomnia, Postman) to discover the schema. The vulnerability is **leaving the feature enabled in production**, where it gives attackers the same reconnaissance capability as legitimate developers.

## How it works

The GraphQL specification reserves two field names beginning with double underscores:

- `__schema` — returns the entire schema (types, queries, mutations, subscriptions, directives).
- `__type(name: String!)` — returns the full definition of a single named type.

A query selecting these fields is syntactically a normal GraphQL query. The server's execution engine resolves them by serialising its internal schema representation. To disable introspection a server must opt in to a validation rule that rejects any query referencing these reserved fields:

- **`graphql-js`** — apply the `NoSchemaIntrospectionCustomRule` validation rule.
- **`graphql-java`** — install `NoIntrospectionGraphqlFieldVisibility.NO_INTROSPECTION_FIELD_VISIBILITY` on the `GraphQLCodeRegistry`.
- **`graphene-python`** — wrap the schema with a custom validator that rejects `__schema`/`__type`.
- **`apollo-server`** — set `introspection: false` in the constructor.

Default configurations of all four leave introspection **on**. This makes E1 the most common GraphQL misconfiguration in the wild and the typical entry point for further reconnaissance.

### Why it matters

With the schema in hand, an attacker:

1. Enumerates every query and mutation, including hidden admin operations exposed by accident.
2. Reads field-level documentation that often hints at internal data shapes (PII fields, internal IDs, deprecated-but-still-resolvable fields).
3. Crafts precise targeted queries instead of blindly probing.
4. Maps the surface for downstream attacks (BOLA, injection, batching).

OWASP cites this as the foundation that enables most other GraphQL-specific attacks.

## How to reproduce (single benign request)

This is **a single HTTP POST identical to what every GraphQL client sends on startup**. It is non-intrusive, requires no authentication, and produces no side effects on the server.

### Step 1 — Set the endpoint

```bash
EP="https://countries.trevorblades.com"
```

Replace with any endpoint from `targets/targets.csv`.

### Step 2 — Send the minimal introspection probe

```bash
curl -sS -X POST "$EP" \
     -H 'Content-Type: application/json' \
     -H 'User-Agent: GraphQL-Academic-Survey/1.0' \
     -d '{"query":"{ __schema { queryType { name } types { name kind } } }"}'
```

This query asks for just the top-level query type name and a list of every type's name + kind — enough to confirm whether introspection works without pulling the entire schema.

### Step 3 — Read the response

Three outcomes are possible:

| Response pattern | Verdict |
|---|---|
| HTTP 200 + JSON body containing `"data": { "__schema": { ... } }` | **Vulnerable — introspection enabled** |
| HTTP 200 or 400 + `"errors": [{"message": "GraphQL introspection has been disabled, but the requested query contained __schema"}]` (or similar wording) | Safe — introspection disabled |
| HTTP 400 + `"errors": [{"message": "Cannot query field \"__schema\" on type \"Query\""}]` | Safe — fields hidden |
| HTTP 401/403 | Endpoint requires authentication — cannot diagnose unauthenticated; report as *unknown* |

### Step 4 (optional, only when vulnerable) — Pull the full schema for documentation

If introspection is enabled and you want to include a schema sample in the writeup, issue the canonical full introspection query (this is exactly what GraphiQL sends when you open the IDE — still a single benign request):

```bash
curl -sS -X POST "$EP" \
     -H 'Content-Type: application/json' \
     -H 'User-Agent: GraphQL-Academic-Survey/1.0' \
     -d @- > "site_${SITE_ID}_schema.json" <<'JSON'
{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}
JSON
```

Save it locally; the schema JSON is the evidence artefact for the writeup.

## Browser-based reproduction (preferred for documentation screenshots)

Three browser-only approaches; pick whichever produces the clearest screenshot.

### Approach A — Use the target's own IDE (only if E2 reports it as exposed)

1. Open the endpoint URL directly in any browser (e.g., `https://countries.trevorblades.com`).
2. If E2 is vulnerable, the embedded GraphiQL / Apollo Sandbox loads. **It automatically issues the introspection query on startup.**
3. Open the *Docs* / *Schema* panel on the side — if it populates with every type and field, introspection is **enabled**.
4. Screenshot the Docs panel for the writeup. This screenshot is also the evidence for E2.

### Approach B — Hosted in-browser GraphQL client (works on any endpoint without install)

1. Open <https://hoppscotch.io/graphql> in any browser. No account, no install — runs entirely client-side.
2. Paste the target endpoint URL into the URL bar.
3. Click the **Schema** tab on the left → press **Introspect**.
4. If introspection is enabled the schema tree populates. Screenshot the schema panel + the URL field as evidence.
5. Alternative hosted clients with identical behaviour: <https://studio.apollographql.com/sandbox/explorer>, <https://altairgraphql.dev/>.

### Approach C — Browser DevTools Console (universal fallback)

1. Open any browser tab and navigate to *any* page on the same origin as the target (or `about:blank` if CORS is permissive — most public GraphQL APIs set `Access-Control-Allow-Origin: *`).
2. Press `F12` / `Cmd-Option-I` to open DevTools → **Console** tab.
3. Paste this JavaScript and press Enter:

   ```js
   fetch("https://countries.trevorblades.com", {
     method: "POST",
     headers: { "Content-Type": "application/json" },
     body: JSON.stringify({
       query: "{ __schema { queryType { name } types { name kind } } }"
     })
   }).then(r => r.json()).then(j => console.log(JSON.stringify(j, null, 2)));
   ```

4. Read the printed JSON in the Console:
   - `data.__schema.types: [...]` populated → **enabled**.
   - `errors[0].message: "GraphQL introspection has been disabled..."` → **disabled**.
5. Screenshot the Console output **and** the Network tab entry for the `POST` (status, headers, response body). Both screenshots together are strong evidence of the request and response.

## OWASP recommended mitigation

Disable introspection in production. The cheat sheet links to framework-specific switches (`NoIntrospection` rule for JS, `NoIntrospectionGraphqlFieldVisibility` for Java). When introspection is disabled, **also** disable field-suggestion hints (see E4) — otherwise the suggested-name bypass reconstructs the schema anyway.

## What to record per target

For each of the 20 sites:

- HTTP status code
- Verdict: `enabled` / `disabled` / `unknown (auth-required)`
- If enabled: number of types reported (a single integer summarising schema size)
- Raw response body saved as `raw/<site_id>_E1.json`
