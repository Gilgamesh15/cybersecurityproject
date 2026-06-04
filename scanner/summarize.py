#!/usr/bin/env python3
"""Build the aggregate results/summary.csv.

Per user spec: 1 row per exploit. Columns:
  exploit, name, vulnerable_count, safe_count, pct_vulnerable.
Denominator is the actual sample size n (printed in header).
"""
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FINDINGS = ROOT / "results" / "findings.csv"
OUT = ROOT / "results" / "summary.csv"

NAMES = {
    "E1": "Introspection enabled",
    "E2": "GraphQL IDE exposed",
    "E3": "Verbose errors / stack-trace",
    "E4": "Field-suggestion hints",
    "E5": "Query batching accepted",
}


def main():
    rows = list(csv.DictReader(FINDINGS.open()))
    n_sites = len(set(r["site_id"] for r in rows))
    by_exploit = {}
    for r in rows:
        by_exploit.setdefault(r["exploit"], []).append(r["verdict"])

    out_rows = []
    for ek in ("E1", "E2", "E3", "E4", "E5"):
        verdicts = by_exploit.get(ek, [])
        vuln = sum(1 for v in verdicts if v == "yes")
        safe = sum(1 for v in verdicts if v == "no")
        total = vuln + safe
        pct = (100.0 * vuln / total) if total else 0.0
        out_rows.append({
            "exploit": ek,
            "name": NAMES[ek],
            "n_sites": n_sites,
            "vulnerable_count": vuln,
            "safe_count": safe,
            "pct_vulnerable": f"{pct:.1f}%",
        })

    with OUT.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "exploit", "name", "n_sites",
            "vulnerable_count", "safe_count", "pct_vulnerable",
        ])
        w.writeheader()
        w.writerows(out_rows)

    print(f"Wrote {OUT} (n = {n_sites})\n")
    print(f"{'Exploit':<6} {'Name':<32} {'Vuln':>5} {'Safe':>5} {'%':>7}")
    for r in out_rows:
        print(f"{r['exploit']:<6} {r['name']:<32} "
              f"{r['vulnerable_count']:>5} {r['safe_count']:>5} "
              f"{r['pct_vulnerable']:>7}")


if __name__ == "__main__":
    main()
