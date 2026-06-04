#!/usr/bin/env python3
"""Re-classify existing E3 raw responses with OWASP-aligned verbose-error signals.

OWASP's "Don't return excessive errors" rule covers more than just stack traces.
A response is verbose when ANY of these are present:
- Stack frames / file paths / drive letters / `node_modules`
- Framework class names in the error: FieldUndefined, GRAPHQL_VALIDATION_FAILED,
  ValidationError, GraphQLError, etc.
- Source-position info beyond bare line/column: caret pointers (`^`), embedded
  source snippets in the error message, sourceName fields.
- Schema-revealing extension fields: `extensions.typeName`, `extensions.fieldName`,
  `extensions.classification`, `extensions.stacktrace`, `extensions.exception`.
- `path` field reflecting the rejected field back at the attacker.
- Framework library / version strings.

Does NOT re-probe. Reads results/E3/site_NNN_E3.json files and rewrites
results/E3/findings_E3.csv.
"""
import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "E3"
SUMMARY_CSV = RESULTS / "findings_E3.csv"

# --- Pattern groups ---

STACK_PATTERNS = [
    re.compile(r'"stacktrace"\s*:\s*\['),
    re.compile(r'"exception"\s*:\s*\{'),
    re.compile(r'(?:/usr/|/app/|/home/|/var/|/src/|/opt/|/node_modules/)'),
    re.compile(r'[A-Z]:\\\\[A-Za-z]'),
    re.compile(r'\bat [A-Z][a-zA-Z]+\.', re.IGNORECASE),
    re.compile(r'\bat Object\.<anonymous>'),
    re.compile(r'\bat executeImpl'),
    re.compile(r'\bat GraphQLError'),
    re.compile(r'\bgraphql\.execution'),
    re.compile(r'Traceback \(most recent call last\)'),
    re.compile(r'apollo-server@[\d\.]+'),
    re.compile(r'graphql-core[/ ][\d\.]+', re.IGNORECASE),
    re.compile(r'\bSangria\b'),
    re.compile(r'Hot ?Chocolate', re.IGNORECASE),
    re.compile(r'\bnode_modules\b'),
]

# Framework / classifier strings that identify the implementation
FRAMEWORK_PATTERNS = [
    re.compile(r'\bFieldUndefined\b'),
    re.compile(r'\bundefinedField\b'),
    re.compile(r'GRAPHQL_VALIDATION_FAILED'),
    re.compile(r'GRAPHQL_PARSE_FAILED'),
    re.compile(r'"classification"\s*:\s*"[A-Z]'),
    re.compile(r'"type"\s*:\s*"ValidationError"'),
    re.compile(r'"type"\s*:\s*"GraphQLError"'),
    re.compile(r'Validation error of type', re.IGNORECASE),
    re.compile(r'Validation error \([A-Za-z]+@'),
]

# Schema-revealing extension fields
SCHEMA_REVEAL_PATTERNS = [
    re.compile(r'"typeName"\s*:'),
    re.compile(r'"fieldName"\s*:'),
    re.compile(r'"sourceName"\s*:'),
    re.compile(r'"path"\s*:\s*\[[^\]]+\]'),  # path array with content
]

# Source-position leak: caret pointer + embedded source snippet
SOURCE_SNIPPET_PATTERNS = [
    re.compile(r'GraphQL request:\d+:\d+\s*[\\n]+\s*\d+ \|'),  # graphene-python
    re.compile(r'\\n\s*\|\s*\^'),  # caret pointer
    re.compile(r'[\\n]\s*1\s*\|\s*\{'),  # source listing
]


def classify_body(text):
    """Return (verdict, evidence_list)."""
    evidence = []

    # Layer 1: classic debug leaks (highest severity)
    stack_hits = []
    for p in STACK_PATTERNS:
        m = p.search(text)
        if m:
            stack_hits.append(m.group(0)[:60])
            if len(stack_hits) >= 3:
                break
    if stack_hits:
        evidence.append("DEBUG-LEAK: " + " | ".join(stack_hits))

    # Layer 2: framework identification
    fw_hits = []
    for p in FRAMEWORK_PATTERNS:
        m = p.search(text)
        if m:
            fw_hits.append(m.group(0)[:40])
            if len(fw_hits) >= 3:
                break

    # Layer 3: schema-revealing extensions
    schema_hits = []
    for p in SCHEMA_REVEAL_PATTERNS:
        m = p.search(text)
        if m:
            schema_hits.append(m.group(0)[:40])
            if len(schema_hits) >= 3:
                break

    # Layer 4: source snippet/caret in message
    src_hits = []
    for p in SOURCE_SNIPPET_PATTERNS:
        m = p.search(text)
        if m:
            src_hits.append("source-snippet/caret")
            break

    # Decision: VERBOSE if any of layers 1-4 fire
    if stack_hits or fw_hits or schema_hits or src_hits:
        if fw_hits:
            evidence.append("FRAMEWORK: " + " | ".join(fw_hits))
        if schema_hits:
            evidence.append("SCHEMA-REVEAL: " + " | ".join(schema_hits))
        if src_hits:
            evidence.append("SOURCE-LEAK: caret/snippet in message")
        return "VERBOSE", " ; ".join(evidence)

    # Try to parse as JSON for non-verbose classification
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return "non_graphql", "body not JSON"

    if isinstance(parsed, dict):
        errors = parsed.get("errors") or ([parsed.get("error")] if parsed.get("error") else None)
        if errors and isinstance(errors, list):
            first = errors[0] if isinstance(errors[0], dict) else {}
            msg = str(first.get("message", "") or first.get("detail", ""))
            low = msg.lower()
            if "cannot query field" in low or "field" in low and "undefined" in low:
                return "generic", f"clean 'Cannot query field' message"
            return "errored", f"errors[]: {msg[:100]}"

    return "unknown", "unrecognized shape"


def main():
    # Load existing classifications to preserve status/endpoint/etc.
    existing = list(csv.DictReader(SUMMARY_CSV.open()))
    by_id = {r["id"]: r for r in existing}

    new_rows = []
    flips = []
    for sid, r in sorted(by_id.items()):
        body_path = RESULTS / f"site_{sid}_E3.json"
        if not body_path.exists():
            new_rows.append(r)
            continue

        body = body_path.read_bytes()
        text = body.decode("utf-8", errors="replace")

        # Preserve auth_required / unreachable / endpoint_dead — those are
        # transport-layer verdicts, not response analysis
        status = r.get("http_status", "0")
        keep_as_is = {"auth_required", "unreachable", "endpoint_dead",
                      "upstream_error", "non_graphql"}
        if r["verdict"] in keep_as_is:
            new_rows.append(r)
            continue

        new_verdict, new_evidence = classify_body(text)
        if new_verdict != r["verdict"]:
            flips.append((sid, r["name"], r["verdict"], new_verdict))
        new_row = dict(r)
        new_row["verdict"] = new_verdict
        new_row["evidence"] = new_evidence
        new_rows.append(new_row)

    fieldnames = ["id", "name", "endpoint_used", "http_status", "verdict", "evidence"]
    with SUMMARY_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(new_rows)

    print(f"Re-classified {len(new_rows)} rows (no new probes — only classifier change).")
    print(f"Verdict flips: {len(flips)}")
    for sid, name, old, new in flips:
        marker = "✓" if new == "VERBOSE" else "·"
        print(f"  {marker} {sid} {name:30s}  {old} → {new}")

    # Summary
    by_v = {}
    for r in new_rows:
        by_v.setdefault(r["verdict"], []).append(r["id"])
    print("\n=== New E3 distribution ===")
    for v, ids in sorted(by_v.items()):
        print(f"  {v:14s} ({len(ids):2d}): {', '.join(sorted(ids))}")


if __name__ == "__main__":
    main()
