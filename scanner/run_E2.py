#!/usr/bin/env python3
"""E2 — GraphiQL / Apollo Sandbox IDE exposure probe.

Sends exactly one HTTP GET per target with `Accept: text/html` — identical to
what a browser does when you paste the URL into the address bar. Classifies
whether a GraphQL IDE (GraphiQL, GraphQL Playground, Apollo Sandbox/Studio,
Banana Cake Pop, Altair) is rendered.

Same rules of engagement as run_E1.py: one request per host, 6-second spacing,
15-second timeout, identifying User-Agent. Endpoint URL is taken from
targets.csv, with the same override map E1 uses to map IDE/docs URLs in the
APIs-guru listing to the actual GraphQL endpoint.
"""
import csv
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_E1  # reuse TARGETS_CSV, ENDPOINT_OVERRIDES, UA, delay & timeout

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results" / "E2"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
SUMMARY_CSV = RESULTS_DIR / "findings_E2.csv"

MAX_BODY_BYTES = 256 * 1024

# Distinct IDE fingerprints. Each entry: (label, list of substrings — match if any present)
IDE_SIGNATURES = [
    ("GraphiQL", [
        "<title>GraphiQL</title>",
        "<title>GraphiQL",
        ">GraphiQL<",
        'id="graphiql"',
        "id=graphiql",
        "graphiql.min.css",
        "graphiql.min.js",
        "unpkg.com/graphiql",
        "cdn.jsdelivr.net/npm/graphiql",
        "yoga-graphiql",
        "@graphql-yoga/graphiql",
        "renderYogaGraphiQL",
    ]),
    ("GraphQL Playground", [
        "<title>GraphQL Playground</title>",
        "<title>GraphQL Playground",
        "graphql-playground",
        "//cdn.jsdelivr.net/npm/graphql-playground",
        'id="playground"',
        "data-react-class=\"playground\"",
    ]),
    ("Apollo Sandbox", [
        "Apollo Sandbox",
        "embeddable-sandbox",
        "studio.apollographql.com/sandbox/embed",
        "embeddable-explorer",
        "apollographql.com/sandbox",
    ]),
    ("Banana Cake Pop", [
        "Banana Cake Pop",
        "BananaCakePop",
        "banana-cake-pop",
        "<title>Banana Cake Pop",
    ]),
    ("Altair", [
        "<title>Altair</title>",
        "<title>Altair",
        "altair-graphql",
        "Altair GraphQL Client",
        "AltairGraphQL.init",
        'alt="Altair"',
    ]),
    ("Ruru", [  # Postgraphile / Graphile's GraphiQL successor
        "RURU_CONFIG",
        "ruru-root",
        "ruru.min.js",
        "unpkg.com/ruru",
        "ruru@",
    ]),
    ("Hasura Console", [
        "hasura-console",
        '"appName":"console"',
    ]),
    ("Apollo Server landing page (production)", [
        "ApolloServerPluginLandingPageProductionDefault",
        "Welcome to Apollo Server",
    ]),
]

# Strong title-based heuristic for IDE pages whose body is JS-rendered (SPA shells).
# Matched against <title>...</title> contents only.
TITLE_HINTS = [
    "graphql ide",
    "graphql editor",
    "graphql playground",
    "graphql explorer",
]


def get(endpoint: str):
    req = urllib.request.Request(
        endpoint,
        method="GET",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en",
            "User-Agent": run_E1.UA,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=run_E1.TIMEOUT_S) as r:
            return r.status, r.read(MAX_BODY_BYTES), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(MAX_BODY_BYTES)
        except Exception:
            body = b""
        return e.code, body, dict(e.headers or {})
    except (urllib.error.URLError, TimeoutError) as e:
        return 0, str(e).encode(), {}


def detect_ide(body: bytes, headers: dict):
    text = body.decode("utf-8", errors="replace")
    low = text.lower()
    found = []
    for label, sigs in IDE_SIGNATURES:
        if any(s.lower() in low for s in sigs):
            found.append(label)
    # Title-based hint when no direct fingerprint matched but the <title> reveals
    # an IDE shell whose body is JS-rendered.
    if not found:
        title_m = re.search(r"<title[^>]*>([^<]+)</title>", text, re.IGNORECASE)
        title = (title_m.group(1) if title_m else "").lower()
        if any(h in title for h in TITLE_HINTS):
            found.append(f"IDE-suggestive title ({title.strip()!r})")
    return found


def classify(status: int, body: bytes, headers: dict, endpoint: str):
    """Returns (verdict, ide_label, note)."""
    if status == 0:
        return "unreachable", "", body.decode("utf-8", errors="replace")[:120]
    if status in (401, 403):
        # API-gateway / WAF blocks; we cannot tell if an IDE would be served.
        return "auth_required", "", f"http {status} before content"
    if status in (404, 405, 410):
        return "not_exposed", "", f"http {status}"
    if status in (502, 503, 504):
        return "upstream_error", "", f"http {status}"

    ides = detect_ide(body, headers)
    ctype = (headers.get("Content-Type") or headers.get("content-type") or "").lower()

    if ides:
        return "EXPOSED", ", ".join(ides), f"matched: {', '.join(ides)}"

    text = body.decode("utf-8", errors="replace")
    is_html = "text/html" in ctype or text.lstrip().lower().startswith(("<!doctype", "<html"))

    if is_html:
        title_m = re.search(r"<title[^>]*>([^<]+)</title>", text, re.IGNORECASE)
        title = title_m.group(1).strip() if title_m else ""
        # URL-pattern heuristic: known hosted-IDE conventions.
        url = urlparse(endpoint)
        host = (url.hostname or "").lower()
        path = (url.path or "").lower()
        if (host.startswith("playground.")
                or "/playground" in path
                or "/graphiql" in path
                or path.endswith("/explorer")):
            return ("EXPOSED",
                    f"hosted IDE (SPA — JS-rendered; URL pattern {host}{path})",
                    f"http {status} SPA shell, title={title[:80]!r}, URL declares IDE")
        return ("not_exposed", "",
                f"http {status} html page, no IDE fingerprint; title={title[:80]!r}")

    # JSON or other — the endpoint refused to serve HTML.
    return "not_exposed", "", f"http {status} non-html response ({len(text)} bytes)"


def main():
    rows = list(csv.DictReader(run_E1.TARGETS_CSV.open()))
    print(f"Loaded {len(rows)} targets")
    print(f"User-Agent: {run_E1.UA}\n")

    results = []
    for i, row in enumerate(rows):
        sid = row["id"]
        name = row["name"]
        endpoint = run_E1.ENDPOINT_OVERRIDES.get(sid, row["endpoint_url"])
        overridden = sid in run_E1.ENDPOINT_OVERRIDES

        flag = " [override]" if overridden else ""
        print(f"[{i+1:2d}/{len(rows)}] {sid} {name}{flag}")
        print(f"         GET {endpoint}")
        t0 = time.time()
        status, body, headers = get(endpoint)
        verdict, ide_label, note = classify(status, body, headers, endpoint)
        elapsed = time.time() - t0

        ext = ".html" if status and 200 <= status < 400 else ".bin"
        out_path = RESULTS_DIR / f"site_{sid}_E2{ext}"
        out_path.write_bytes(body[:MAX_BODY_BYTES])

        print(f"         http={status} verdict={verdict} ide={ide_label} ({elapsed:.1f}s) {note}")

        results.append({
            "id": sid,
            "name": name,
            "endpoint_used": endpoint,
            "csv_endpoint_overridden": "yes" if overridden else "no",
            "http_status": status,
            "verdict": verdict,
            "ide_label": ide_label,
            "note": note,
        })

        if i < len(rows) - 1:
            time.sleep(run_E1.DELAY_BETWEEN_HOSTS_S)

    fieldnames = [
        "id", "name", "endpoint_used", "csv_endpoint_overridden",
        "http_status", "verdict", "ide_label", "note",
    ]
    with SUMMARY_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(results)

    print(f"\nWrote {SUMMARY_CSV}\n")
    print("=== Summary ===")
    by_verdict = {}
    for r in results:
        by_verdict.setdefault(r["verdict"], []).append(r["id"])
    for verdict, ids in sorted(by_verdict.items()):
        print(f"  {verdict:18s} ({len(ids):2d}): {', '.join(sorted(ids))}")

    print("\n=== IDEs identified ===")
    for r in results:
        if r["ide_label"]:
            print(f"  {r['id']} {r['name']:30s} -> {r['ide_label']}")


if __name__ == "__main__":
    main()
