#!/usr/bin/env python3
"""Build the combined results/findings.csv.

Per user spec: 1 row per (site, exploit) — n × 5 rows total.
Columns: site_id, name, exploit, verdict (yes/no), explanation.

`verdict` collapses every per-exploit verdict that is NOT a "yes-state" to "no":
- E1 yes = "ENABLED"
- E2 yes = "EXPOSED"
- E3 yes = "VERBOSE"
- E4 yes = "SUGGESTS"
- E5 yes = "ACCEPTS"
Everything else (auth_required, disabled, errored, generic, unknown, etc.) → "no".
"""
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
TARGETS_CSV = ROOT / "targets" / "targets.csv"
OUT = RESULTS / "findings.csv"

EXPLOITS = [
    ("E1", "Introspection enabled",       "ENABLED"),
    ("E2", "GraphQL IDE exposed",         "EXPOSED"),
    ("E3", "Verbose errors / stack-trace", "VERBOSE"),
    ("E4", "Field-suggestion hints",      "SUGGESTS"),
    ("E5", "Query batching accepted",     "ACCEPTS"),
]


def shorten(s, n=110):
    s = (s or "").replace("\n", " ").replace("\r", "")
    return s[:n]


def main():
    target_names = {r["id"]: r["name"] for r in csv.DictReader(TARGETS_CSV.open())}
    rows_out = []

    for ek, name_human, yes_state in EXPLOITS:
        per = list(csv.DictReader((RESULTS / ek / f"findings_{ek}.csv").open()))
        for r in per:
            sid = r["id"]
            verdict = "yes" if r["verdict"] == yes_state else "no"
            # Compose a one-sentence explanation
            ev = r.get("evidence") or r.get("note") or ""
            ide = r.get("ide_label") or ""
            types = r.get("types_count")
            v = r["verdict"]
            if verdict == "yes":
                if ek == "E1":
                    expl = f"introspection returned schema ({types} types)" if types and types != "-1" else f"introspection enabled — {shorten(ev,80)}"
                elif ek == "E2":
                    expl = f"IDE exposed: {ide}"
                elif ek == "E3":
                    expl = f"verbose error response: {shorten(ev, 90)}"
                elif ek == "E4":
                    expl = f"server emitted 'Did you mean' hint: {shorten(ev, 80)}"
                elif ek == "E5":
                    expl = f"server accepted array batch envelope: {shorten(ev, 70)}"
            else:
                # not vulnerable — collapse to one sentence with the actual reason
                if v == "auth_required":
                    expl = "auth gate intercepted before GraphQL layer could respond"
                elif v == "endpoint_dead":
                    expl = "endpoint returned 404 / 410 (no GraphQL at this path)"
                elif v == "unreachable":
                    expl = "host unreachable (DNS / TLS / connection error)"
                elif v == "disabled":
                    expl = f"introspection explicitly disabled: {shorten(ev, 70)}"
                elif v == "generic":
                    expl = f"server returned generic 'Cannot query field' with no leak"
                elif v == "rejected":
                    expl = f"batching rejected: {shorten(ev, 70)}"
                elif v == "errored":
                    expl = f"server returned non-vuln error: {shorten(ev, 80)}"
                elif v == "non_graphql":
                    expl = "response body was not JSON (likely HTML or empty)"
                elif v == "unknown":
                    expl = "response did not match any known vulnerability or safe pattern"
                elif v == "tenant_routing":
                    expl = "endpoint requires per-tenant routing path"
                elif v == "upstream_error":
                    expl = "server returned 5xx upstream error"
                elif v == "not_exposed":
                    expl = "no GraphQL IDE served at this URL"
                elif v == "lenient":
                    expl = "schema accepted unknown field as null (not a leak)"
                elif v == "parse_error":
                    expl = "response body could not be parsed as JSON"
                else:
                    expl = f"non-vuln response: {v}"

            rows_out.append({
                "site_id": sid,
                "name": target_names.get(sid, r.get("name", "")),
                "exploit": ek,
                "verdict": verdict,
                "explanation": expl,
            })

    rows_out.sort(key=lambda r: (r["site_id"], r["exploit"]))
    with OUT.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["site_id", "name", "exploit", "verdict", "explanation"])
        w.writeheader()
        w.writerows(rows_out)
    print(f"Wrote {OUT} — {len(rows_out)} rows")


if __name__ == "__main__":
    main()
