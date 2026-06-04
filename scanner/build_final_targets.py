#!/usr/bin/env python3
"""Build the final targets.csv from the verified-only pool.

Inputs:
- Existing targets.csv slots 001..020 (Phase-1 verified)
- results/verification/verification.csv rows marked decision=include

Output:
- targets/targets.csv (n verified entries)
"""
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS_CSV = ROOT / "targets" / "targets.csv"
VERIFICATION_CSV = ROOT / "results" / "verification" / "verification.csv"


def main():
    existing = list(csv.DictReader(TARGETS_CSV.open()))
    phase1 = [r for r in existing if int(r["id"]) <= 20]
    by_name = {r["name"].lower(): r for r in existing}

    verified = [
        r for r in csv.DictReader(VERIFICATION_CSV.open())
        if r["decision"] == "include"
    ]

    rows = []
    fieldnames = ["id", "name", "category", "endpoint_url", "source",
                  "verification_evidence"]

    # Phase-1 rows first, with auto-filled verification_evidence
    for r in phase1:
        rows.append({
            "id": r["id"],
            "name": r["name"],
            "category": r["category"],
            "endpoint_url": r["endpoint_url"],
            "source": "apis-guru",
            "verification_evidence": "Phase-1 E1 (already classified)",
        })

    # Verified candidates next
    next_id = 21
    for v in verified:
        # Prefer the original detailed row from existing targets.csv if present
        ex = by_name.get(v["name"].lower())
        category = ex["category"] if ex else ""
        rows.append({
            "id": f"{next_id:03d}",
            "name": v["name"],
            "category": category,
            "endpoint_url": v["probe_url"],
            "source": v["source"],
            "verification_evidence": v["evidence"],
        })
        next_id += 1

    with TARGETS_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {TARGETS_CSV} — n={len(rows)} verified GraphQL endpoints")
    for r in rows:
        ev = r['verification_evidence'][:60]
        print(f"  {r['id']} {r['name'][:35]:35s} ({r['source']:10s}) {ev}")


if __name__ == "__main__":
    main()
