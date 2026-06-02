#!/usr/bin/env python3
"""E1 — Introspection probe against the 20 targets in targets.csv.

Sends exactly one POST per target, identical to the introspection request every
GraphQL client issues on startup. Records verdict + raw response.

Rules of engagement:
  - One request per host. No retries on application-level failure.
  - 6 seconds spacing between hosts.
  - 15-second hard timeout per request.
  - Identifying, contactable User-Agent.
  - HTTPS preferred; HTTP only where the public listing specifies it.
"""
import csv
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS_CSV = ROOT / "targets" / "targets.csv"
RESULTS_DIR = ROOT / "results" / "E1"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
SUMMARY_CSV = RESULTS_DIR / "findings_E1.csv"

UA = ("GraphQL-Academic-Survey/1.0 "
      "(university project; contact: brunoraw675@gmail.com)")
DELAY_BETWEEN_HOSTS_S = 6
TIMEOUT_S = 15
MAX_BODY_BYTES = 512 * 1024

# Where the CSV lists an IDE/explorer/docs URL rather than the actual GraphQL
# API endpoint, substitute the real endpoint the IDE itself talks to. Recorded
# in the 'endpoint_used' column for transparency.
ENDPOINT_OVERRIDES = {
    "01": "https://graphql.anilist.co",
    "11": "https://api.digitransit.fi/routing/v2/finland/gtfs/v1",
    "12": "https://portal.ehri-project.eu/api/graphql",
    "15": "https://api.github.com/graphql",
    "16": "https://gitlab.com/api/graphql",
    "18": "https://hivdb.stanford.edu/graphql",
    "19": "https://api.pipefy.com/graphql",
}

PROBE = json.dumps({
    "query": "{ __schema { queryType { name } types { name kind } } }"
}).encode("utf-8")


def probe(endpoint: str):
    req = urllib.request.Request(
        endpoint,
        data=PROBE,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": UA,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            return r.status, r.read(MAX_BODY_BYTES)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(MAX_BODY_BYTES)
        except Exception:
            body = b""
        return e.code, body
    except (urllib.error.URLError, TimeoutError) as e:
        return 0, str(e).encode()


def classify(status, body):
    text = body.decode("utf-8", errors="replace")
    if status == 0:
        return "unreachable", -1, text[:120]
    if status in (401, 402, 403):
        return "auth_required", -1, f"http {status}"
    if status in (404, 410):
        return "endpoint_dead", -1, f"http {status}"
    if status in (502, 503, 504):
        return "upstream_error", -1, f"http {status}"

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return ("non_graphql" if status == 200 else "parse_error",
                -1, f"http {status}, body not JSON ({len(text)} chars)")

    if isinstance(parsed, dict):
        data = parsed.get("data")
        if data and isinstance(data, dict) and data.get("__schema"):
            schema = data["__schema"]
            types = schema.get("types") or []
            types_count = len(types) if isinstance(types, list) else -1
            return "ENABLED", types_count, f"types={types_count}"

        errors = parsed.get("errors") or parsed.get("error")
        # Some non-spec servers (e.g. Memair) use `error: { ... }` instead of `errors: [...]`.
        if errors and not isinstance(errors, list):
            errors = [errors]
        if errors:
            msgs = " | ".join(
                str(e.get("message", ""))
                for e in errors if isinstance(e, dict)
            )
            classes = " | ".join(
                str((e.get("extensions") or {}).get("errorClass", ""))
                for e in errors if isinstance(e, dict)
            )
            low = (msgs + " " + classes).lower()
            if "introspection" in low and any(
                k in low for k in ("disabled", "not allowed", "denied", "forbidden")
            ):
                return "disabled", -1, msgs[:160]
            if "cannot query field" in low and "__schema" in low:
                return "disabled", -1, "schema field hidden"
            auth_signals = (
                "unauthorized", "unauthenticated", "authentication",
                "authorization", "access token", "api key", "api-key",
                "x-api-key", "bearer", "credentials",
            )
            if any(k in low for k in auth_signals):
                return "auth_required", -1, msgs[:160]
            return "errored", -1, msgs[:160]

    return "unknown", -1, f"http {status}, unrecognized shape"


def main():
    rows = list(csv.DictReader(TARGETS_CSV.open()))
    print(f"Loaded {len(rows)} targets")
    print(f"Spacing: {DELAY_BETWEEN_HOSTS_S}s between hosts, timeout {TIMEOUT_S}s")
    print(f"User-Agent: {UA}\n")

    results = []
    for i, row in enumerate(rows):
        sid = row["id"]
        name = row["name"]
        endpoint = ENDPOINT_OVERRIDES.get(sid, row["endpoint_url"])
        overridden = sid in ENDPOINT_OVERRIDES

        flag = " [override]" if overridden else ""
        print(f"[{i+1:2d}/{len(rows)}] {sid} {name}{flag}")
        print(f"         -> {endpoint}")

        t0 = time.time()
        status, body = probe(endpoint)
        verdict, types_count, note = classify(status, body)
        elapsed = time.time() - t0

        out_path = RESULTS_DIR / f"site_{sid}_E1.json"
        out_path.write_bytes(body[:MAX_BODY_BYTES])

        print(f"         http={status} verdict={verdict} ({elapsed:.1f}s) {note}")

        results.append({
            "id": sid,
            "name": name,
            "endpoint_used": endpoint,
            "csv_endpoint_overridden": "yes" if overridden else "no",
            "http_status": status,
            "verdict": verdict,
            "types_count": types_count,
            "note": note,
        })

        if i < len(rows) - 1:
            time.sleep(DELAY_BETWEEN_HOSTS_S)

    with SUMMARY_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "id", "name", "endpoint_used", "csv_endpoint_overridden",
            "http_status", "verdict", "types_count", "note",
        ])
        w.writeheader()
        w.writerows(results)

    print(f"\nWrote {SUMMARY_CSV}\n")
    print("=== Summary ===")
    by_verdict = {}
    for r in results:
        by_verdict.setdefault(r["verdict"], []).append(r["id"])
    for verdict, ids in sorted(by_verdict.items()):
        print(f"  {verdict:18s} ({len(ids):2d}): {', '.join(ids)}")


if __name__ == "__main__":
    main()
