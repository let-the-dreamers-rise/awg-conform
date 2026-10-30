"""Differential config validation: feed the same edge-case parameter sets to
every implementation and compare accept / reject, and whether the tunnel
still comes up afterwards.

A config one implementation accepts and another rejects is an interop
problem: a server operator exports a config that some clients cannot load.

usage: sudo python3 -m awgconform.configdiff [--impls a,b] [--out FILE]
"""

import argparse
import json
import os
import time

from . import impls
from .run import (IP_S, NS_C, NS_S, PORT_C, PORT_S, TUN_C, TUN_S, keypair, netns_down, netns_up, sh,
                  wait_if)

BASE = {"jc": 4, "jmin": 40, "jmax": 70, "s1": 20, "s2": 20, "s3": 20, "s4": 20,
        "h1": "100000-200000", "h2": "300000-400000", "h3": "500000-600000", "h4": "700000-800000"}

CASES = {
    "baseline": {},
    "jmin_gt_jmax": {"jmin": 90, "jmax": 50},
    "headers_overlap": {"h2": "150000-350000"},
    "header_range_reversed": {"h1": "200000-100000"},
    "same_size_init_resp": {"s1": 0, "s2": 56},
    "i1_b_without_0x": {"i1": "<b c0ffee00>"},
    "i1_counter_tag": {"i1": "<b 0xc0ffee00><c>"},
    "i1_unknown_tag": {"i1": "<b 0xc0ffee00><zz 4>"},
    "i1_empty": {"i1": ""},
    "i1_large_r": {"i1": "<r 1400>"},
    "hp_short_padding": {"header_protection_key": "11" * 32, "s1": 8},
    "hp_ok": {"header_protection_key": "11" * 32, "s1": 16, "s2": 16, "s3": 16, "s4": 16},
}


def attempt(impl, awg, out_dir):
    """Start server+client of the same implementation with `awg`; report what happened."""
    os.makedirs(out_dir, exist_ok=True)
    cpriv, cpub = keypair()
    spriv, spub = keypair()
    netns_up()
    procs = []
    res = {}
    try:
        procs.append(impls.start(impl, NS_S, "awgs0", awg, os.path.join(out_dir, "server.log")))
        procs.append(impls.start(impl, NS_C, "awgc0", awg, os.path.join(out_dir, "client.log")))
        try:
            wait_if(NS_S, "awgs0")
            wait_if(NS_C, "awgc0")
        except RuntimeError:
            res["result"] = "refused-at-start"
            return res
        try:
            impls.configure(impl, "awgs0", spriv, PORT_S, awg, {"public_key": cpub, "allowed_ip": TUN_C + "/32"})
            impls.configure(impl, "awgc0", cpriv, PORT_C, awg,
                            {"public_key": spub, "allowed_ip": TUN_S + "/32", "endpoint": f"{IP_S}:{PORT_S}"})
        except RuntimeError as e:
            res["result"] = "rejected"
            res["detail"] = str(e)[:200]
            return res
        for ns, dev, ip in ((NS_C, "awgc0", TUN_C), (NS_S, "awgs0", TUN_S)):
            sh("ip", "-n", ns, "addr", "add", ip + "/24", "dev", dev)
            sh("ip", "-n", ns, "link", "set", dev, "up")
        p = sh("ip", "netns", "exec", NS_C, "ping", "-c", "5", "-i", "0.3", "-W", "2", TUN_S, check=False)
        alive = all(pr.poll() is None for pr in procs)
        res["result"] = "accepted-tunnel-up" if p.returncode == 0 else "accepted-no-tunnel"
        if not alive:
            res["result"] += "-process-exited"
        return res
    finally:
        time.sleep(0.3)
        for pr in procs:
            pr.terminate()
        for pr in procs:
            try:
                pr.wait(timeout=5)
            except Exception:  # noqa: BLE001
                pr.kill()
        netns_down()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--impls", default=",".join(impls.IMPLS))
    ap.add_argument("--out", default="out/configdiff")
    a = ap.parse_args()
    names = [n for n in a.impls.split(",") if n]
    table = {}
    for case, delta in CASES.items():
        awg = dict(BASE, **delta)
        awg = {k: v for k, v in awg.items() if v != "" or k.startswith("i")}
        row = {}
        for n in names:
            impl = impls.IMPLS[n]
            if any(k in impls.V3_KEYS for k in awg) and not impl.supports_v3:
                row[n] = "n/a"
                continue
            row[n] = attempt(impl, awg, os.path.join(a.out, case, n)).get("result")
        table[case] = row
        print(f"{case:24} " + "  ".join(f"{n}={row[n]}" for n in names), flush=True)
    os.makedirs(a.out, exist_ok=True)
    json.dump(table, open(os.path.join(a.out, "configdiff.json"), "w"), indent=2)
    lines = ["# Config validation differential", "", "| case | " + " | ".join(names) + " | agree |",
             "|---|" + "---|" * (len(names) + 1)]
    for case, row in table.items():
        vals = {v for v in row.values() if v != "n/a"}
        lines.append(f"| {case} | " + " | ".join(row[n] for n in names) + f" | {'yes' if len(vals) <= 1 else '**no**'} |")
    open(os.path.join(a.out, "CONFIGDIFF.md"), "w").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
