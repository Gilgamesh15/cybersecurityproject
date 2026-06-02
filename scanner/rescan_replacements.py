#!/usr/bin/env python3
"""Re-scan the 7 replacement slots and merge into findings_E1.csv.

The first E1 run revealed that slots 03, 07, 10, 13, 14, 17, 20 in the
original target list pointed at dead hosts (404, DNS gone, obsolete TLS).
Those slots have been refilled with the next entries from the APIs-guru
README; this script probes the new ones and folds results into the CSV.
"""
import csv
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_E1  # noqa: E402

# Allow up to 8 MB so we don't truncate large schemas (e.g. GitLab-style).
run_E1.MAX_BODY_BYTES = 8 * 1024 * 1024

REPLACED_IDS = {"20"}


def main():
    # 1. Delete stale raw files for the removed sites.
    for sid in sorted(REPLACED_IDS):
        p = run_E1.RESULTS_DIR / f"site_{sid}_E1.json"
        if p.exists():
            p.unlink()
            print(f"deleted {p.name}")

    # 2. Load current findings, keep rows we are NOT replacing.
    kept = []
    if run_E1.SUMMARY_CSV.exists():
        with run_E1.SUMMARY_CSV.open() as f:
            for row in csv.DictReader(f):
                if row["id"] not in REPLACED_IDS:
                    kept.append(row)
    print(f"\nKept {len(kept)} existing findings rows.")

    # 3. Probe the 7 replacement targets.
    rows = [
        r for r in csv.DictReader(run_E1.TARGETS_CSV.open())
        if r["id"] in REPLACED_IDS
    ]
    print(f"Probing {len(rows)} replacement slots ({run_E1.DELAY_BETWEEN_HOSTS_S}s spacing)\n")

    new_findings = []
    for i, row in enumerate(rows):
        sid = row["id"]
        name = row["name"]
        endpoint = run_E1.ENDPOINT_OVERRIDES.get(sid, row["endpoint_url"])
        overridden = sid in run_E1.ENDPOINT_OVERRIDES

        print(f"[{i+1}/{len(rows)}] {sid} {name}")
        print(f"         -> {endpoint}")
        t0 = time.time()
        status, body = run_E1.probe(endpoint)
        verdict, types_count, note = run_E1.classify(status, body)
        elapsed = time.time() - t0

        out_path = run_E1.RESULTS_DIR / f"site_{sid}_E1.json"
        out_path.write_bytes(body[:run_E1.MAX_BODY_BYTES])

        print(f"         http={status} verdict={verdict} ({elapsed:.1f}s) {note}")

        new_findings.append({
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
            time.sleep(run_E1.DELAY_BETWEEN_HOSTS_S)

    # 4. Merge + sort by id, then rewrite the CSV.
    all_rows = kept + new_findings
    all_rows.sort(key=lambda r: r["id"])
    fieldnames = [
        "id", "name", "endpoint_used", "csv_endpoint_overridden",
        "http_status", "verdict", "types_count", "note",
    ]
    with run_E1.SUMMARY_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(all_rows)

    print(f"\nUpdated {run_E1.SUMMARY_CSV} ({len(all_rows)} rows)")
    print("\n=== Updated full summary ===")
    by_verdict = {}
    for r in all_rows:
        by_verdict.setdefault(r["verdict"], []).append(r["id"])
    for verdict, ids in sorted(by_verdict.items()):
        print(f"  {verdict:18s} ({len(ids):2d}): {', '.join(sorted(ids))}")


if __name__ == "__main__":
    main()
