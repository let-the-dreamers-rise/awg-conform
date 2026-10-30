"""Run every client x server x config combination and write a report.

usage: sudo python3 -m awgconform.matrix [--impls a,b,...] [--configs DIR] [--out DIR]
"""

import argparse
import glob
import json
import os

from . import impls
from .run import run_pair

V3_KEYS = impls.V3_KEYS


def needs_v3(cfg):
    return any(k in cfg for k in V3_KEYS)


def summarize(r):
    issues = r["client_stream"]["findings"] + r["server_stream"]["findings"]
    return {
        "ping": r.get("ping_ok", False),
        "ping_summary": r.get("ping_summary"),
        "bulk": r.get("bulk_summary"),
        "error": r.get("error"),
        "spec_findings": issues,
        "leaks_client": [l["id"] for l in r["client_stream"]["leaks"]],
        "leaks_server": [l["id"] for l in r["server_stream"]["leaks"]],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--impls", default=",".join(impls.IMPLS))
    ap.add_argument("--configs", default="configs")
    ap.add_argument("--out", default="out")
    a = ap.parse_args()
    names = [n for n in a.impls.split(",") if n]
    rows = []
    for cpath in sorted(glob.glob(os.path.join(a.configs, "*.json"))):
        cname = os.path.splitext(os.path.basename(cpath))[0]
        cfg = json.load(open(cpath))
        for c in names:
            for s in names:
                unsupported = needs_v3(cfg) and not (impls.IMPLS[c].supports_v3 and impls.IMPLS[s].supports_v3)
                if unsupported:
                    rows.append({"config": cname, "client": c, "server": s, "skipped": "AWG 3.x keys not supported"})
                    continue
                r = run_pair(c, s, cfg, os.path.join(a.out, cname, f"{c}__{s}"))
                row = {"config": cname, "client": c, "server": s}
                row.update(summarize(r))
                rows.append(row)
                print(f"{cname:16} {c:15} -> {s:15} ping={row['ping']} findings={len(row['spec_findings'])} "
                      f"bulk={row['bulk']}", flush=True)
    os.makedirs(a.out, exist_ok=True)
    json.dump(rows, open(os.path.join(a.out, "matrix.json"), "w"), indent=2)
    write_md(rows, os.path.join(a.out, "REPORT.md"))


def write_md(rows, path):
    lines = ["# awg-conform matrix", "",
             "| config | client | server | tunnel | bulk loss | spec findings | client leaks | server leaks |",
             "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        if r.get("skipped"):
            lines.append(f"| {r['config']} | {r['client']} | {r['server']} | skipped | | {r['skipped']} | | |")
            continue
        bulk = ""
        if r.get("bulk"):
            bulk = r["bulk"][0].split(",")[2].strip() if len(r["bulk"][0].split(",")) > 2 else r["bulk"][0]
        f = "; ".join(sorted({x["id"] for x in r["spec_findings"]})) or "none"
        lines.append(f"| {r['config']} | {r['client']} | {r['server']} | {'ok' if r['ping'] else 'FAIL'} | {bulk} | {f} | "
                     f"{', '.join(r['leaks_client']) or 'none'} | {', '.join(r['leaks_server']) or 'none'} |")
    lines += ["", "## Spec findings (detail)", ""]
    for r in rows:
        for x in r.get("spec_findings", []):
            lines.append(f"- {r['config']} {r['client']} -> {r['server']}: **{x['id']}** {x['message']}")
    open(path, "w").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
