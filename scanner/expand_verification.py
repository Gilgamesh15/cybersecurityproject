#!/usr/bin/env python3
"""Expanded endpoint-discovery pass — multi-path probing + HTML inspection.

For every user-list candidate that the strict `/graphql` pass rejected, try:
  1. POST {scheme}://{host}/api/graphql      (most common alternative)
  2. POST {scheme}://{host}/v1/graphql
  3. POST {scheme}://{host}/api/v1/graphql
  4. POST {scheme}://{host}/api/v2/graphql
  5. GET  {scheme}://{host}/                 — fetch homepage, grep for
     `graphql` URLs embedded in script tags / fetch() calls, then POST whatever
     we find.

Stop at first success. Update verification.csv with the newly included entries.

Same etiquette as run_E1.py: identifying UA, 15 s timeout, 6 s between hosts.
"""
import csv
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_E1
from verify_endpoints import classify as classify_endpoint, PROBE, OUT_DIR, RAW_DIR, SUMMARY_CSV

ALT_PATHS = ["/api/graphql", "/v1/graphql", "/api/v1/graphql", "/api/v2/graphql"]

# Patterns to find GraphQL endpoints embedded in HTML
HTML_GQL_PATTERNS = [
    re.compile(r'["\']([^"\']{1,200}/(?:api/)?graphql[a-zA-Z0-9_/\-]*)["\']'),
    re.compile(r'fetch\(["\']([^"\']{1,200}/graphql[a-zA-Z0-9_/\-]*)["\']'),
    re.compile(r'(?:uri|url|endpoint)\s*[:=]\s*["\']([^"\']{1,200}/graphql[a-zA-Z0-9_/\-]*)["\']'),
]


def http_post(url):
    req = urllib.request.Request(
        url, data=PROBE, method="POST",
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


def http_get(url):
    req = urllib.request.Request(
        url, method="GET",
        headers={"Accept": "text/html,application/xhtml+xml",
                 "User-Agent": run_E1.UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=run_E1.TIMEOUT_S) as r:
            return r.status, r.read(min(run_E1.MAX_BODY_BYTES, 1024 * 1024))
    except urllib.error.HTTPError as e:
        try:
            body = e.read(min(run_E1.MAX_BODY_BYTES, 1024 * 1024))
        except Exception:
            body = b""
        return e.code, body
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}".encode()[:512]


def discover_in_html(html_text, base_host):
    """Pull candidate graphql endpoint URLs from the HTML body.

    Returns list of absolute URLs."""
    hits = set()
    for pat in HTML_GQL_PATTERNS:
        for m in pat.finditer(html_text):
            u = m.group(1).strip()
            if not u or " " in u or len(u) > 200:
                continue
            if u.startswith("/"):
                u = f"https://{base_host}{u}"
            elif not u.startswith(("http://", "https://")):
                continue
            hits.add(u)
            if len(hits) >= 5:
                break
        if len(hits) >= 5:
            break
    return sorted(hits)


def try_paths(host, scheme="https"):
    """Try each alternative path; return (probe_url, status, body, found?)."""
    for path in ALT_PATHS:
        url = f"{scheme}://{host}{path}"
        status, body = http_post(url)
        decision, evidence, _excerpt = classify_endpoint(status, body)
        time.sleep(2)  # brief spacing between same-host probes
        if decision == "include":
            return url, status, body, evidence
    return None, None, None, None


def try_html_discovery(host, scheme="https"):
    """Fetch homepage, look for embedded GraphQL endpoint URL, probe it."""
    home_status, home_body = http_get(f"{scheme}://{host}/")
    if home_status == 0 or home_status >= 400 or not home_body:
        return None, None, None, None
    text = home_body.decode("utf-8", errors="replace")
    candidates = discover_in_html(text, host)
    if not candidates:
        return None, None, None, None
    for url in candidates[:3]:  # try up to 3 found URLs
        time.sleep(2)
        status, body = http_post(url)
        decision, evidence, _excerpt = classify_endpoint(status, body)
        if decision == "include":
            return url, status, body, f"html-discovered: {evidence}"
    return None, None, None, None


def main():
    rows = list(csv.DictReader(SUMMARY_CSV.open()))
    by_id = {r["candidate_id"]: r for r in rows}

    targets_to_retry = [
        r for r in rows
        if r["decision"] == "exclude" and r["source"] == "user-list"
    ]
    print(f"Re-trying {len(targets_to_retry)} excluded user-list candidates")
    print(f"({len(ALT_PATHS)} alternative paths + HTML-fallback discovery)\n")

    new_includes = []
    for i, r in enumerate(targets_to_retry):
        cid = r["candidate_id"]
        name = r["name"]
        host = urlparse(r["probe_url"]).hostname

        print(f"[{i+1:2d}/{len(targets_to_retry)}] {cid} {name}")

        # Phase A: alternative paths
        url, status, body, evidence = try_paths(host)
        if not url:
            # Phase B: HTML discovery
            url, status, body, evidence = try_html_discovery(host)

        if url:
            print(f"         ✓ FOUND at {url}  ({evidence[:80]})")
            r["decision"] = "include"
            r["probe_url"] = url
            r["http_status"] = str(status)
            r["evidence"] = f"deeper-pass: {evidence}"
            r["body_excerpt"] = body.decode("utf-8", errors="replace")[:200].replace("\n", " ")
            (RAW_DIR / f"{cid}.bin").write_bytes(body[:run_E1.MAX_BODY_BYTES])
            new_includes.append(cid)
        else:
            print(f"         · still excluded (none of the alt paths or HTML hints returned GraphQL)")

        # Inter-host spacing
        if i < len(targets_to_retry) - 1:
            time.sleep(run_E1.DELAY_BETWEEN_HOSTS_S)

    # Persist updated verification.csv
    fieldnames = ["candidate_id", "name", "source", "probe_url",
                  "http_status", "decision", "evidence", "body_excerpt"]
    with SUMMARY_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    n_inc = sum(1 for r in rows if r["decision"] == "include")
    print(f"\n=== Result ===")
    print(f"New INCLUDEs this pass: {len(new_includes)}  ({', '.join(new_includes)})")
    print(f"Total verification INCLUDEs: {n_inc}")
    print(f"Final sample size (incl. 20 Phase-1): {20 + n_inc}")


if __name__ == "__main__":
    main()
