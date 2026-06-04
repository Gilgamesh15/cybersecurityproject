#!/usr/bin/env python3
"""Endpoint-discovery probe — runs over scanner/candidates.csv.

For each candidate, sends one benign POST: {"query":"{__typename}"} to the
probe URL, with the identifying User-Agent. Classifies the response per the
inclusion table in the Phase-2 plan (data/errors envelope → INCLUDE; HTML,
REST, or absent → EXCLUDE).

Writes results/verification/verification.csv plus per-candidate raw response
bodies under results/verification/raw/.

Rules of engagement (mirrors run_E1.py):
- 6 s spacing between hosts
- 15 s timeout per request
- 1 request per candidate (no retries except for transport errors? No — single shot.)
- Identifying UA, HTTPS preferred
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
import run_E1  # for UA, DELAY_BETWEEN_HOSTS_S, TIMEOUT_S, MAX_BODY_BYTES

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES_CSV = HERE / "candidates.csv"
OUT_DIR = ROOT / "results" / "verification"
RAW_DIR = OUT_DIR / "raw"
SUMMARY_CSV = OUT_DIR / "verification.csv"

PROBE = json.dumps({"query": "{ __typename }"}).encode("utf-8")

# Heuristic GraphQL error markers — when a non-2xx response body contains these,
# the GraphQL execution layer responded (not a generic gateway).
GQL_ERROR_MARKERS = [
    "cannot query field", "did you mean", "syntax error",
    "graphql_validation_failed", "graphql validation",
    "must provide query", "unknown field", "field \"",
    "graphqlerror", "GraphQLError",
]
GQL_EXT_CODES = [
    "UNAUTHENTICATED", "UNAUTHORIZED", "FORBIDDEN", "BAD_USER_INPUT",
    "GRAPHQL_VALIDATION_FAILED", "GRAPHQL_PARSE_FAILED",
    "INTERNAL_SERVER_ERROR", "PERSISTED_QUERY_NOT_FOUND", "AUTHENTICATION",
    "NOT_AUTHENTICATED",
]


def probe(url: str):
    req = urllib.request.Request(
        url,
        data=PROBE,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": run_E1.UA,
        },
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
        # Catch-all for transport-layer issues: URLError, TimeoutError,
        # ConnectionResetError, OSError, ssl.SSLError, http.client errors, etc.
        return 0, f"{type(e).__name__}: {e}".encode()[:512]


def classify(status, body):
    """Returns (decision, evidence, body_excerpt)."""
    if status == 0:
        return "exclude", "network error: " + body.decode("utf-8", errors="replace")[:80], ""

    text = body.decode("utf-8", errors="replace")
    excerpt = text[:200].replace("\n", " ").replace("\r", "")

    if status in (404, 410):
        return "exclude", f"http {status} (endpoint absent)", excerpt
    if status in (405,):
        return "exclude", f"http 405 (method not allowed at /graphql)", excerpt

    # Try to parse as JSON
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        # Non-JSON: is it HTML?
        if text.lstrip().lower().startswith(("<!doctype", "<html", "<head")):
            return "exclude", f"http {status} returned HTML (not a GraphQL endpoint)", excerpt
        return "exclude", f"http {status} returned non-JSON, non-HTML body", excerpt

    # 1. data.__typename populated → definitive
    if isinstance(parsed, dict):
        data = parsed.get("data")
        if data and isinstance(data, dict):
            tn = data.get("__typename")
            if tn:
                return "include", f"data.__typename = {tn!r}", excerpt

        # 2. errors[] array with GraphQL-shaped content
        errors = parsed.get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0] if isinstance(errors[0], dict) else {}
            msg = str(first.get("message", "") or first.get("detail", ""))
            ext = first.get("extensions") or {}
            code = str(ext.get("code", "")) or str(ext.get("errorClass", ""))

            low = (msg + " " + code).lower()
            if any(m in low for m in (s.lower() for s in GQL_ERROR_MARKERS)):
                return "include", f"errors[0].message ~ {msg[:80]!r}", excerpt
            if code and code.upper() in GQL_EXT_CODES:
                return "include", f"errors[0].extensions.code = {code!r}", excerpt
            # Auth-gated with errors array shaped per GraphQL spec → include
            if status in (401, 403) and msg:
                # Heuristic: presence of errors[] array on an auth-gate suggests GraphQL
                return "include", f"http {status} with GraphQL errors[] envelope: {msg[:80]!r}", excerpt
            # Otherwise, errors[] exists but doesn't look GraphQL-spec; lean exclude
            return "exclude", f"errors[] present but no GraphQL signature: {msg[:80]!r}", excerpt

        # 3. Non-spec but identifiable: `data` exists with `error` (singular) — some servers
        if data is not None and "error" in parsed:
            err = parsed["error"]
            if isinstance(err, dict):
                m = str(err.get("message", ""))
                return "include", f"non-spec data+error envelope: {m[:80]!r}", excerpt

        # 4. Welcome / routing page with hints
        if "welcome" in text.lower() and "graphql" in text.lower() and len(text) < 500:
            return "include", "welcome/routing page mentions GraphQL", excerpt

    # 5. Non-GraphQL JSON (REST/custom) or empty 200
    if status == 200:
        return "exclude", f"http 200 JSON without GraphQL envelope", excerpt
    if status in (401, 403):
        return "exclude", f"http {status} non-GraphQL body (gateway-level)", excerpt
    return "exclude", f"http {status} unrecognized shape", excerpt


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    rows = list(csv.DictReader(CANDIDATES_CSV.open()))

    # Resume mode: read any prior verification.csv and skip candidates we already
    # finished. This makes recovery from a crash cheap.
    already_done = {}  # candidate_id -> existing row
    if SUMMARY_CSV.exists():
        for r in csv.DictReader(SUMMARY_CSV.open()):
            already_done[r["candidate_id"]] = r
        print(f"Found {len(already_done)} already-probed candidates in {SUMMARY_CSV.name}; "
              f"will skip those.\n")

    pending = [r for r in rows if r["candidate_id"] not in already_done]
    print(f"Verifying {len(pending)} new candidates "
          f"({run_E1.DELAY_BETWEEN_HOSTS_S}s spacing)\n")

    results = list(already_done.values())
    n_inc = sum(1 for r in results if r.get("decision") == "include")

    fieldnames = ["candidate_id", "name", "source", "probe_url",
                  "http_status", "decision", "evidence", "body_excerpt"]

    def flush():
        with SUMMARY_CSV.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            # Preserve candidate order by sorting on candidate_id
            for r in sorted(results, key=lambda x: x["candidate_id"]):
                w.writerow(r)

    for i, row in enumerate(pending):
        cid = row["candidate_id"]
        name = row["name"]
        url = row["probe_url"]
        source = row["source"]

        print(f"[{i+1:3d}/{len(rows)}] {cid} {name[:30]:30s} ({source}) {url}")
        t0 = time.time()
        status, body = probe(url)
        decision, evidence, excerpt = classify(status, body)
        elapsed = time.time() - t0

        # Save raw body
        (RAW_DIR / f"{cid}.bin").write_bytes(body[:run_E1.MAX_BODY_BYTES])

        marker = "✓" if decision == "include" else "·"
        if decision == "include":
            n_inc += 1
        print(f"          {marker} {decision.upper():7s} http={status} ({elapsed:.1f}s) {evidence[:90]}")

        results.append({
            "candidate_id": cid,
            "name": name,
            "source": source,
            "probe_url": url,
            "http_status": status,
            "decision": decision,
            "evidence": evidence,
            "body_excerpt": excerpt,
        })
        flush()  # incremental save in case of crash

        if i < len(pending) - 1:
            time.sleep(run_E1.DELAY_BETWEEN_HOSTS_S)

    flush()
    print(f"\nWrote {SUMMARY_CSV}")
    print(f"INCLUDE: {n_inc}  EXCLUDE: {len(results) - n_inc}")
    print(f"Combined with 20 Phase-1 sites, final sample size: {min(100, 20 + n_inc)}")


if __name__ == "__main__":
    main()
