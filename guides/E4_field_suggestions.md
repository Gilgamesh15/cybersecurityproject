# E4 — Field-Name Suggestion Hints

## What it is

When a GraphQL query references a field that does not exist, many servers respond with a "did you mean" hint that names real fields whose spelling is close to the requested one. This is a developer-experience feature copied from compilers — but on a production GraphQL endpoint it becomes an **introspection-bypass leak**: even when introspection is explicitly disabled (E1), an attacker can iteratively send near-miss queries and reconstruct the schema field by field.

OWASP highlights this defence gap implicitly by recommending tools such as *Shapeshifter*, which exists specifically to strip these hints from error responses. E4 is the most pedagogically interesting of the five chosen exploits because it demonstrates that **disabling introspection alone is not sufficient hardening**.

## How it works

The reference implementation `graphql-js`, and most ports that mirror its behaviour, compute the Levenshtein distance between the unrecognised field name and each defined field on the target type. Fields within a small edit distance are appended to the error message as:

```
Cannot query field "contries" on type "Query". Did you mean "countries"?
```

The same logic applies to:

- Field names on object types
- Argument names on field arguments
- Enum value names
- Input object field names
- Variable names

An attacker who knows the rough domain of the API (e.g., an e-commerce site likely has `product`, `order`, `customer`, etc.) can issue a handful of one-letter-off probes and recover real field names with high reliability. With ~50 well-chosen probes, a typical schema is mostly reconstructed.

### Why the bypass works

The "no introspection" mitigation usually disables only the `__schema` and `__type` meta-fields. The Levenshtein suggestion runs at the **validation** layer, which executes *before* introspection rules even apply — so a server that has shut off introspection can still leak schema content via the suggestion mechanism. This is exactly the gap OWASP warns about.

## How to reproduce (single benign request per probe)

The diagnostic remains structurally identical to the E3 test: one HTTP POST with a malformed query. The only change is the choice of field name — instead of a clearly absurd name (`__nonexistent_field_xyz`), use a **near-miss** of a plausible real field.

### Step 1 — Set the endpoint

```bash
EP="https://countries.trevorblades.com"
```

### Step 2 — Choose a near-miss probe field

The choice depends on the API's domain. Reasonable defaults for a one-shot E4 test:

- Generic: `nme`, `usr`, `quer`, `prodct`, `serch`, `tite`
- For the example endpoint above (countries data): `contries` (typo for `countries`)

Pick **one** probe per target. The point is to verify whether the server emits a "Did you mean" hint at all — not to brute-force the schema.

### Step 3 — Send the probe

```bash
curl -sS -X POST "$EP" \
     -H 'Content-Type: application/json' \
     -H 'User-Agent: GraphQL-Academic-Survey/1.0' \
     -d '{"query":"{ contries { code } }"}' \
     | tee "site_${SITE_ID}_E4.json"
```

### Step 4 — Look for the hint

Search the response for the case-insensitive phrase `did you mean`:

```bash
grep -i 'did you mean' "site_${SITE_ID}_E4.json"
```

### Step 5 — Classify

| Observation | Verdict |
|---|---|
| Response contains `Did you mean "..."?` (one or more suggested field names) | **Vulnerable — suggestion hints enabled** |
| Generic `"Cannot query field \"contries\" on type \"Query\""` with no suggestion | Safe — hints disabled |
| HTTP 401/403 | Mark *unknown* |

### Step 6 — Cross-reference with E1

The pedagogically interesting outcome is the combination:

| E1 (introspection) | E4 (suggestions) | Significance |
|---|---|---|
| Enabled | Enabled | Both leaks present; E4 is redundant from the attacker's perspective |
| Disabled | Disabled | Fully hardened against the field-recon vector |
| Enabled | Disabled | Inconsistent hardening; uncommon |
| **Disabled** | **Enabled** | **The documented OWASP bypass — partial hardening that fails to close the recon gap** |

The last row is the headline finding. When recording per-target results, flag this combination explicitly.

## Browser-based reproduction (preferred for documentation screenshots)

### Approach A — If E2 reports an IDE is exposed: use the target's own IDE

1. Visit the endpoint URL in the browser; the embedded GraphiQL / Sandbox loads.
2. Pick a near-miss field name (see Step 2 above). For the example endpoint use `contries`.
3. Paste in the editor pane: `{ contries { code } }` and press `Ctrl-Enter`.
4. The result panel shows the error. Screenshot the result panel; the `Did you mean "countries"?` phrase is the headline evidence.

### Approach B — Hosted in-browser GraphQL client

1. Open <https://hoppscotch.io/graphql>.
2. Paste the endpoint URL.
3. Type the near-miss query `{ contries { code } }` and click **Send**.
4. Expand `errors[0].message` in the response. Screenshot.

### Approach C — Browser DevTools Console (universal fallback)

1. Open DevTools → **Console**.
2. Run:

   ```js
   fetch("https://countries.trevorblades.com", {
     method: "POST",
     headers: { "Content-Type": "application/json" },
     body: JSON.stringify({ query: "{ contries { code } }" })
   }).then(r => r.json()).then(j => console.log(JSON.stringify(j, null, 2)));
   ```

3. Look for the substring `Did you mean` inside `errors[0].message`. Screenshot both the Console output and the Network tab's Response preview.

### Cross-evidence with E1 — what the OWASP-flagged bypass looks like

When E1 reports introspection as **disabled** but Approach A/B/C above still surface a `Did you mean "..."` hint, take a side-by-side screenshot of the two responses. This composite — introspection blocked + suggestions leaking — is the canonical illustration of the OWASP-named bypass that motivates Shapeshifter.

## OWASP recommended mitigation

The cheat sheet explicitly references **Shapeshifter** for stripping suggestion hints from error responses. Framework-level fixes:

- `graphql-js` / `apollo-server`: install a custom validation rule that overrides the default `FieldsOnCorrectType` rule with a version that emits a generic message and drops the suggestion array.
- `graphql-java`: configure a `GraphQLError` formatter to strip the `did you mean` substring from `message`.
- Or: post-process all GraphQL error responses through a reverse-proxy filter that regex-strips `Did you mean ".*?"\\?` before forwarding to the client.

## What to record per target

- HTTP status
- Whether `did you mean` appeared in the response (boolean)
- If yes: the suggested field names (free-text, comma-separated)
- The interesting `E1=disabled, E4=enabled` flag (boolean derived from cross-reference)
- Raw response saved as `raw/<site_id>_E4.json`
