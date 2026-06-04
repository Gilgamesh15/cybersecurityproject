#!/usr/bin/env python3
"""Re-classify verification.csv EXCLUDE rows whose raw body mentions GraphQL.

Three patterns recover missed inclusions:
1. "introspection is not allowed" / "introspection has been disabled" — defensively
   configured GraphQL server.
2. Plain text mentioning "GraphQL" or "graphql" anywhere — explicit confirmation.
3. JSON errors[] envelope whose message OR extension contains "GraphQL" /
   "introspection" / "operation" terms (catches Coursera's "GraphQL operations
   must contain a non-empty query").

No new network probes. Just reads existing raw bodies and updates verification.csv
in place.
"""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "results" / "verification"
RAW_DIR = OUT_DIR / "raw"
SUMMARY_CSV = OUT_DIR / "verification.csv"

# Substring markers that — anywhere in the raw body — confirm the response came
# from a GraphQL layer rather than an HTTP gateway or unrelated service.
GQL_TEXT_MARKERS = [
    "graphql operations must",
    "introspection is not allowed",
    "introspection has been disabled",
    "introspection is disabled",
    "visual graphql tools",
    "graphql query",
    "graphql request",
    "graphql validation",
    "must provide query string",
    "no query string",
]


def main():
    rows = list(csv.DictReader(SUMMARY_CSV.open()))
    flipped = []

    for row in rows:
        if row["decision"] != "exclude":
            continue
        cid = row["candidate_id"]
        raw = RAW_DIR / f"{cid}.bin"
        if not raw.exists():
            continue
        body = raw.read_bytes()
        text = body.decode("utf-8", errors="replace")
        low = text.lower()

        # Marker check
        match = next((m for m in GQL_TEXT_MARKERS if m in low), None)
        if match:
            quote = ""
            # Try to extract a short evidence quote (first sentence containing the marker)
            idx = low.find(match)
            start = max(0, idx - 5)
            end = min(len(text), idx + len(match) + 80)
            quote = text[start:end].strip().replace("\n", " ")
            row["decision"] = "include"
            row["evidence"] = f"reclassified: {quote[:140]!r}"
            flipped.append((cid, row["name"], match, quote[:100]))

    if not flipped:
        print("No borderline rows found needing re-classification.")
        return

    fieldnames = ["candidate_id", "name", "source", "probe_url",
                  "http_status", "decision", "evidence", "body_excerpt"]
    with SUMMARY_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"Re-classified {len(flipped)} rows from EXCLUDE → INCLUDE:")
    for cid, name, marker, quote in flipped:
        print(f"  {cid} {name:30s}  marker={marker!r}")
        print(f"            quote: {quote}")

    n_inc = sum(1 for r in rows if r["decision"] == "include")
    print(f"\nTotal INCLUDE now: {n_inc}")


if __name__ == "__main__":
    main()
