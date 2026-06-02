# E5 — Query Batching Accepted

## What it is

GraphQL allows multiple operations to be sent in a single HTTP request by encoding the request body as a JSON array of query objects. The server unpacks the array, executes each operation, and returns a parallel array of results. OWASP describes the feature as enabling *"a form of brute force attack specific to GraphQL"* — because most rate-limit infrastructure (WAFs, API gateways, login throttlers) counts HTTP requests, not GraphQL operations, an attacker can multiply effective request volume by however many operations they pack into one batch.

**This check does not perform a batching attack.** It only verifies whether the server *accepts* the batch request shape, by sending a one-element batch whose operation is trivial (`{ __typename }`). The single-element batch performs the same work as one ordinary query — the difference is purely in the request body envelope.

## How it works

A regular GraphQL request body is a JSON object:

```json
{ "query": "{ field }", "variables": {...}, "operationName": "..." }
```

A batched request body is a JSON array of the same:

```json
[
  { "query": "{ field1 }" },
  { "query": "{ field2 }" },
  { "query": "{ field3 }" }
]
```

Whether the server accepts the array form is **a configuration choice**, not a spec requirement:

| Framework | Default | How to disable |
|---|---|---|
| `apollo-server` v3+ | rejects arrays unless `allowBatchedHttpRequests: true` | leave default off |
| `apollo-server` v2 | accepts arrays | upgrade to v3, or use `apollo-server-express` with custom middleware |
| `express-graphql` | accepts arrays | not directly configurable; reject at proxy level |
| `graphql-java` | accepts arrays via the HTTP module | configure batching limit to 1 |
| `graphene-django` | accepts arrays | override `BaseGraphQLView.parse_body` |

When batching is accepted, three attacks become trivially scalable:

1. **Password / OTP brute-force** — wrap N login mutations in one POST; the rate limiter sees one request.
2. **ID enumeration** — wrap N `user(id:i)` queries in one POST; bypasses per-request counters.
3. **WAF bypass** — many WAFs only inspect the first operation in a body; later ones go unfiltered.

E5 is the *precondition* test: confirming acceptance flags the server as exposed to all three follow-on attacks **without performing any of them**.

### Why this is non-intrusive

The single-element batch `[{ "query": "{ __typename }" }]` performs exactly the same work as the corresponding non-batched request `{ "query": "{ __typename }" }`. The `__typename` meta-field is resolved without touching any data source — it returns the literal string `"Query"`. The request costs the server one trivial schema lookup. The only thing being measured is whether the JSON parser at the HTTP-layer accepts an array as the top-level request body.

## How to reproduce (single benign request)

### Step 1 — Set the endpoint

```bash
EP="https://countries.trevorblades.com"
```

### Step 2 — Send the single-element batch

```bash
curl -sS -X POST "$EP" \
     -H 'Content-Type: application/json' \
     -H 'User-Agent: GraphQL-Academic-Survey/1.0' \
     -d '[{"query":"{ __typename }"}]' \
     | tee "site_${SITE_ID}_E5.json"
```

### Step 3 — Inspect response shape

The response body is the key signal:

| Response body | Verdict |
|---|---|
| JSON **array** like `[{"data":{"__typename":"Query"}}]` | **Vulnerable — batching accepted** |
| JSON object with `"errors":[{"message":"Batched queries are not allowed"}]` (or "Expected single operation") | Safe — batching rejected |
| JSON object with `"errors":[{"message":"Expected JSON object, got array"}]` | Safe — parser rejects arrays |
| HTTP 400 / 415 with non-GraphQL parse error | Safe — body never reached the GraphQL layer |
| HTTP 200 + JSON object (not array) that contains only one set of `data`/`errors` keys | Server "flattened" the batch — treat as **vulnerable** but record the quirk |

A quick programmatic check:

```bash
python3 -c "import json,sys; b=json.load(open('site_${SITE_ID}_E5.json')); print('VULNERABLE' if isinstance(b,list) else 'SAFE')"
```

### Step 4 — Do not escalate

A two-element or larger batch would risk being interpreted as the start of an actual batching attack and would offer no additional academic value — the precondition has already been confirmed (or refuted) by step 2. Stop here.

## OWASP recommended mitigation

- Reject batched HTTP requests (`allowBatchedHttpRequests: false` in `apollo-server`).
- If batching is required for legitimate client reasons, apply per-operation rate limits — not per-request.
- Use server-side data-loading layers (Facebook's **DataLoader** pattern) so that batching benefits coalesce on the server's data-source side rather than being exposed to the HTTP boundary.
- Cap batch size at the gateway/WAF layer if batching is on.

## What to record per target

- HTTP status code
- Whether the response top-level JSON value was an array (boolean)
- Verdict: `accepted` / `rejected` / `parse-error` / `unknown`
- Raw response saved as `raw/<site_id>_E5.json`
