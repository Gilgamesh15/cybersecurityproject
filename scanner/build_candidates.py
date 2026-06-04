#!/usr/bin/env python3
"""Build scanner/candidates.csv — every URL we will run endpoint-discovery on.

Sources:
1. Slots 021..062 of the current targets.csv (parsed from APIs-guru README).
2. User-provided domain lists (TheirStack tech-stack + traffic-rank lists).

Slots 001..020 are NOT in candidates — they are already verified in Phase 1
and will be carried forward into the final targets.csv unchanged.

Slots 063..100 (the fabricated vendor-docs entries) are discarded.
"""
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS_CSV = ROOT / "targets" / "targets.csv"
CANDIDATES_CSV = ROOT / "scanner" / "candidates.csv"

# User-provided domains, deduped. Each becomes probe URL https://{domain}/graphql.
# Source = "user-list" (combines TheirStack + traffic-rank data).
USER_DOMAINS = [
    # Top-traffic GraphQL list
    "app.clickup.com", "app.hubspot.com", "app-na2.hubspot.com",
    "expedia.com", "u.gg", "lowes.com", "infosecwriteups.com",
    "velog.io", "app.welcometothejungle.com", "isc2.org",
    "medium.com", "loom.com", "coursera.org", "account.godaddy.com",
    "tokopedia.com", "homedepot.com", "admin.typeform.com",
    "afisha.yandex.ru", "eneba.com", "lg.com", "blog.stackademic.com",
    "id.jobstreet.com", "justwatch.com", "vrbo.com", "thumbtack.com",
    # Top-50 companies list
    "adobe.com", "apple.com", "bbc.co.uk", "bloomberg.com",
    "booking.com", "calendly.com", "cisco.com", "cnn.com",
    "dailymail.co.uk", "dailymotion.com", "digitalocean.com",
    "dropbox.com", "etsy.com", "eventbrite.com", "ft.com",
    "gartner.com", "google.com", "houzz.com", "ibm.com",
    "jd.com", "kickstarter.com", "linkedin.com", "marriott.com",
    "nbcnews.com", "networksolutions.com", "nytimes.com",
    "parallels.com", "patreon.com", "paypal.com", "photobucket.com",
    "pinterest.com", "quora.com", "researchgate.net", "salesforce.com",
    "shopify.com", "soundcloud.com", "stripe.com", "surveymonkey.com",
    "theatlantic.com", "time.com", "tripadvisor.com", "wix.com",
    "wsj.com", "xing.com", "zendesk.com", "zoom.us",
    # TheirStack tech-stack CSV companies
    "epam.com", "dice.at", "walmart.com", "jpmorganchase.com",
    "deloitte.com", "ebayinc.com", "jerry.ai", "netflix.com",
    "wayfair.com", "fidelitycareers.com", "cognizant.com",
    "tcs.com", "mercor.com", "virtusa.com", "cgi.com",
    "ciandt.com", "atlassian.com", "americanexpress.com",
    "optum.com", "photon.com",
]


def main():
    # 1. Read slots 021..062 from current targets.csv (the APIs-guru remainder).
    existing = list(csv.DictReader(TARGETS_CSV.open()))
    apis_guru_remainder = [r for r in existing if 21 <= int(r["id"]) <= 62]

    rows = []
    cid = 0

    for r in apis_guru_remainder:
        cid += 1
        rows.append({
            "candidate_id": f"C{cid:03d}",
            "name": r["name"],
            "source": "apis-guru",
            "probe_url": r["endpoint_url"],
            "category": r.get("category", ""),
        })

    # 2. Deduplicate user-provided domains against APIs-guru hosts already in candidates
    #    and against the 20 already-verified Phase-1 sites.
    phase1 = [r for r in existing if int(r["id"]) <= 20]
    p1_hosts = set()
    for r in phase1 + apis_guru_remainder:
        u = r["endpoint_url"]
        h = u.split("//", 1)[-1].split("/", 1)[0].lower()
        p1_hosts.add(h)

    seen = set(p1_hosts)
    for d in USER_DOMAINS:
        d_clean = d.lower().strip()
        if d_clean in seen:
            continue
        seen.add(d_clean)
        cid += 1
        rows.append({
            "candidate_id": f"C{cid:03d}",
            "name": d_clean,
            "source": "user-list",
            "probe_url": f"https://{d_clean}/graphql",
            "category": "",
        })

    CANDIDATES_CSV.parent.mkdir(parents=True, exist_ok=True)
    with CANDIDATES_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["candidate_id", "name", "source",
                                          "probe_url", "category"])
        w.writeheader()
        w.writerows(rows)

    by_source = {}
    for r in rows:
        by_source.setdefault(r["source"], 0)
        by_source[r["source"]] += 1
    print(f"Wrote {CANDIDATES_CSV} with {len(rows)} candidates")
    for s, n in sorted(by_source.items()):
        print(f"  {s}: {n}")


if __name__ == "__main__":
    main()
