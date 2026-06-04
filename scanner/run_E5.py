#!/usr/bin/env python3
"""E5 — Query batching probe.

Sends a one-element batch (`[{...}]`) containing the trivial __typename query.
If the server accepts the array envelope and returns an array response, batching
is enabled — which OWASP describes as a precondition for batching brute-force
attacks (we do NOT send a multi-element batch).
"""
import csv
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_E1

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results" / "E5"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
SUMMARY_CSV = RESULTS_DIR / "findings_E5.csv"

PROBE = json.dumps([{"query": "{ __typename }"}]).encode("utf-8")


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
    if status == 0:
        return "unreachable", body.decode("utf-8", errors="replace")[:120]
    if status in (401, 403):
        return "auth_required", f"http {status}"
    if status in (404, 410):
        return "endpoint_dead", f"http {status}"
    if status in (502, 503, 504):
        return "upstream_error", f"http {status}"

    text = body.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return "non_graphql", f"http {status}, body not JSON"

    if isinstance(parsed, list):
        if parsed and isinstance(parsed[0], dict):
            first_data = parsed[0].get("data")
            if first_data and first_data.get("__typename"):
                return "ACCEPTS", f"array response with data.__typename={first_data['__typename']!r}"
            if parsed[0].get("errors"):
                return "ACCEPTS", "array response with errors[] in batch element"
        return "ACCEPTS", f"top-level JSON array (len={len(parsed)})"

    if isinstance(parsed, dict):
        errors = parsed.get("errors") or ([parsed.get("error")] if parsed.get("error") else None)
        if errors and isinstance(errors, list):
            msg = str((errors[0] if isinstance(errors[0], dict) else {}).get("message", ""))
            low = msg.lower()
            if "batch" in low or "expected" in low and "object" in low:
                return "rejected", f"batching rejected: {msg[:100]}"
            return "rejected", f"object response with errors[]: {msg[:100]}"
        if parsed.get("data"):
            return "rejected", "object response (single-op result, not array)"

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
        (RESULTS_DIR / f"site_{sid}_E5.json").write_bytes(body[:run_E1.MAX_BODY_BYTES])
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
