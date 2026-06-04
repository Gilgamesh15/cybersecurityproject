#!/usr/bin/env python3
"""E3 — Verbose error message / stack-trace leakage probe.

Sends one POST with a deliberately malformed query (indistinguishable from a
developer typo). Classifies whether the server's error response leaks
implementation details: stack traces, file paths, framework versions.

Same rules of engagement as run_E1.py.
"""
import csv
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_E1

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results" / "E3"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
SUMMARY_CSV = RESULTS_DIR / "findings_E3.csv"

PROBE = json.dumps({
    "query": "{ __nonexistent_field_xyz_diagnostic }"
}).encode("utf-8")

# Patterns that indicate the server leaked implementation details.
LEAK_PATTERNS = [
    # Apollo / graphql-js debug output
    re.compile(r'"stacktrace"\s*:\s*\['),
    re.compile(r'"exception"\s*:\s*\{'),
    # File paths
    re.compile(r'(?:/usr/|/app/|/home/|/var/|/src/|/opt/|/node_modules/)'),
    re.compile(r'[A-Za-z]:\\\\[A-Za-z]'),  # Windows drive letters
    # Stack frame patterns
    re.compile(r'\bat [A-Z][a-zA-Z]+\.', re.IGNORECASE),
    re.compile(r'\bat Object\.<anonymous>'),
    re.compile(r'\bat executeImpl'),
    re.compile(r'\bat GraphQLError'),
    re.compile(r'\bgraphql\.execution'),
    re.compile(r'Traceback \(most recent call last\)'),
    # Library version strings
    re.compile(r'apollo-server@[\d\.]+'),
    re.compile(r'graphql-core[/ ][\d\.]+', re.IGNORECASE),
    re.compile(r'\bSangria\b'),
    re.compile(r'Hot ?Chocolate', re.IGNORECASE),
    re.compile(r'\bnode_modules\b'),
]


def probe(endpoint):
    req = urllib.request.Request(
        endpoint, data=PROBE, method="POST",
        headers={"Content-Type": "application/json",
                 "Accept": "application/json",
                 "User-Agent": run_E1.UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=run_E1.TIMEOUT_S) as r:
            return r.status, r.read(run_E1.MAX_BODY_BYTES)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(run_E1.MAX_BODY_BYTES)
        except Exception:
            body = b""
        return e.code, body
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}".encode()[:512]


def classify(status, body):
    """Returns (verdict, evidence)."""
    if status == 0:
        return "unreachable", body.decode("utf-8", errors="replace")[:120]
    if status in (401, 403):
        return "auth_required", f"http {status}"
    if status in (404, 410):
        return "endpoint_dead", f"http {status}"
    if status in (502, 503, 504):
        return "upstream_error", f"http {status}"

    text = body.decode("utf-8", errors="replace")
    matches = []
    for pat in LEAK_PATTERNS:
        m = pat.search(text)
        if m:
            matches.append(m.group(0))
            if len(matches) >= 3:
                break
    if matches:
        return "VERBOSE", "leak markers: " + " | ".join(matches[:3])

    # Try to parse and check for a clean error response
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return "non_graphql", f"http {status}, body not JSON"

    if isinstance(parsed, dict):
        errors = parsed.get("errors") or ([parsed.get("error")] if parsed.get("error") else None)
        if errors and isinstance(errors, list):
            first = errors[0] if isinstance(errors[0], dict) else {}
            msg = str(first.get("message", "") or first.get("detail", ""))
            low = msg.lower()
            if "cannot query field" in low or "no field" in low or "unknown field" in low:
                return "generic", f"generic 'Cannot query field' (no leak): {msg[:100]}"
            return "errored", f"errors[]: {msg[:120]}"
        if parsed.get("data") and isinstance(parsed.get("data"), dict) and parsed["data"].get("__nonexistent_field_xyz_diagnostic") is None:
            return "lenient", "schema accepted unknown field as null"

    return "unknown", f"http {status}, unrecognized shape"


def main():
    targets_csv = ROOT / "targets" / "targets.csv"
    rows = list(csv.DictReader(targets_csv.open()))
    print(f"Loaded {len(rows)} targets\nUA: {run_E1.UA}\n")

    results = []
    for i, row in enumerate(rows):
        sid = row["id"]
        name = row["name"]
        endpoint = run_E1.ENDPOINT_OVERRIDES.get(sid, row["endpoint_url"])
        overridden = sid in run_E1.ENDPOINT_OVERRIDES

        print(f"[{i+1:2d}/{len(rows)}] {sid} {name}{' [override]' if overridden else ''}")
        print(f"         POST {endpoint}")
        t0 = time.time()
        status, body = probe(endpoint)
        verdict, evidence = classify(status, body)
        elapsed = time.time() - t0

        (RESULTS_DIR / f"site_{sid}_E3.json").write_bytes(body[:run_E1.MAX_BODY_BYTES])
        print(f"         http={status} verdict={verdict} ({elapsed:.1f}s) {evidence[:120]}")

        results.append({
            "id": sid, "name": name, "endpoint_used": endpoint,
            "http_status": status, "verdict": verdict, "evidence": evidence,
        })
        if i < len(rows) - 1:
            time.sleep(run_E1.DELAY_BETWEEN_HOSTS_S)

    fieldnames = ["id", "name", "endpoint_used", "http_status", "verdict", "evidence"]
    with SUMMARY_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(results)
    print(f"\nWrote {SUMMARY_CSV}\n=== Summary ===")
    by = {}
    for r in results:
        by.setdefault(r["verdict"], []).append(r["id"])
    for v, ids in sorted(by.items()):
        print(f"  {v:14s} ({len(ids):2d}): {', '.join(sorted(ids))}")


if __name__ == "__main__":
    main()
