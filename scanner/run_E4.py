#!/usr/bin/env python3
"""E4 — Field-name suggestion hint probe.

Sends one POST with a near-miss of the spec-required `__typename` field. If the
server's error message contains "did you mean", the Levenshtein suggestion
logic is active — which is OWASP-flagged because it bypasses an
introspection-disabled defense.
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
RESULTS_DIR = ROOT / "results" / "E4"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
SUMMARY_CSV = RESULTS_DIR / "findings_E4.csv"

# OWASP E4 probe — must NOT use a `__`-prefixed field. graphql-js and many
# ports suppress suggestion hints specifically for double-underscore meta-fields
# (they're treated as introspection internals). To exercise the suggestion path
# we send near-misses of plausible ordinary field names. We try multiple probes
# per host because the suggestion heuristic only fires if Levenshtein distance
# to a real field is small — different schemas have different field names.
PROBE_FIELDS = ["usr", "user_", "users", "produkt", "prodct", "nme", "searh", "data_"]
DID_YOU_MEAN_RE = re.compile(r'did you mean[^"\']*[\'"]([^\'"]+)[\'"]', re.IGNORECASE)


def make_probe(field_name):
    return json.dumps({"query": f"{{ {field_name} }}"}).encode("utf-8")


def _single_probe(endpoint, payload):
    req = urllib.request.Request(
        endpoint, data=payload, method="POST",
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


def probe(endpoint):
    """Try multiple near-miss probes; stop at first 'did you mean' hit, else
    return the most-informative response. Spacing of 1 s between same-host
    probes keeps us courteous."""
    best_status, best_body = 0, b""
    for i, field in enumerate(PROBE_FIELDS):
        if i > 0:
            time.sleep(1)
        status, body = _single_probe(endpoint, make_probe(field))
        text = body.decode("utf-8", errors="replace").lower()
        # If we hit a 'did you mean', return immediately
        if "did you mean" in text:
            return status, body
        # Track the most-informative response for fallback
        if status and (best_status == 0 or len(body) > len(best_body)):
            best_status, best_body = status, body
    return best_status, best_body


def classify(status, body):
    if status == 0:
        return "unreachable", body.decode("utf-8", errors="replace")[:120]
    if status in (401, 403):
        return "auth_required", f"http {status}"
    if status in (404, 410):
        return "endpoint_dead", f"http {status}"
    if status in (502, 503, 504):
        return "upstream_error", f"http {status}"

    text = body.decode("utf-8", errors="replace")
    if "did you mean" in text.lower():
        m = DID_YOU_MEAN_RE.search(text)
        suggestion = m.group(1) if m else "(unparsed)"
        return "SUGGESTS", f"'Did you mean' → {suggestion!r}"

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
                return "generic", f"generic 'Cannot query field' (no hint): {msg[:100]}"
            return "errored", f"errors[]: {msg[:120]}"

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
        print(f"[{i+1:2d}/{len(rows)}] {sid} {name}")
        t0 = time.time()
        status, body = probe(endpoint)
        verdict, evidence = classify(status, body)
        elapsed = time.time() - t0
        (RESULTS_DIR / f"site_{sid}_E4.json").write_bytes(body[:run_E1.MAX_BODY_BYTES])
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
