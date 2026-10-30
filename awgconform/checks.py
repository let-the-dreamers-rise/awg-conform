"""Conformance and detectability checks over one sender's datagrams."""

import struct
from collections import Counter

from .spec import (BASE, COOKIE, INIT, RESP, TRANSPORT, Config, classify,
                   match_tags, tag_len)


def finding(fid, sev, msg, **kw):
    d = {"id": fid, "severity": sev, "message": msg}
    d.update(kw)
    return d


def check_stream(cfg: Config, dgrams, role: str) -> dict:
    """dgrams: Datagram list sent by one peer, in capture order."""
    cls = [classify(cfg, d.payload) for d in dgrams]
    counts = Counter(c.kind for c in cls)
    out = []

    # --- pre-handshake packets (I1-I5 then Jc junk) before each initiation
    if role == "initiator":
        expected_i = len(cfg.ipackets)
        pending = []
        n_init = 0
        for d, c in zip(dgrams, cls):
            if c.kind != INIT:
                if c.kind == "other":
                    pending.append(d)
                continue
            n_init += 1
            pre = pending
            pending = []
            want = expected_i + cfg.jc
            if len(pre) != want:
                out.append(finding("SPEC-PRE-COUNT", "error",
                                   f"initiation #{n_init}: {len(pre)} pre-handshake datagrams, spec expects "
                                   f"{expected_i} I-packets + Jc={cfg.jc} junk = {want}"))
            ipk, junk = pre[:expected_i], pre[expected_i:]
            for idx, (tags, d2) in enumerate(zip(cfg.ipackets, ipk), start=1):
                why = match_tags(tags, d2.payload, now=d2.ts)
                if why:
                    out.append(finding("SPEC-I", "error", f"initiation #{n_init}: I{idx} does not match its tags: {why}"))
            for j in junk:
                n = len(j.payload)
                if not (cfg.jmin <= n <= cfg.jmax):
                    out.append(finding("SPEC-JUNK-SIZE", "error",
                                       f"initiation #{n_init}: junk datagram of {n} bytes outside [Jmin={cfg.jmin}, Jmax={cfg.jmax}]"))
        if n_init == 0:
            out.append(finding("NO-INIT", "error", "no handshake initiation recognised in capture"))

    # --- header ranges actually used (only meaningful for ranges)
    for kind in (INIT, RESP, TRANSPORT):
        lo, hi = cfg.hdr[kind]
        vals = [c.header for c in cls if c.kind == kind]
        if hi > lo and len(vals) >= 8 and len(set(vals)) == 1:
            out.append(finding("SPEC-H-FIXED", "warn",
                               f"{kind}: header range {lo}-{hi} configured but every packet used {vals[0]}"))

    # --- detectability (independent of config)
    tr = [d.payload for d, c in zip(dgrams, cls) if c.kind == TRANSPORT]
    leaks = detectability(dgrams, cls, tr, cfg)
    return {"role": role, "counts": dict(counts), "findings": out, "leaks": leaks}


def detectability(dgrams, cls, tr, cfg):
    leaks = []
    # L1: classic WireGuard type field (1..4 followed by three zero bytes) at offset 0
    wg = sum(1 for d in dgrams if len(d.payload) >= 4 and 1 <= d.payload[0] <= 4 and d.payload[1:4] == b"\0\0\0")
    if wg:
        leaks.append({"id": "L1-WG-TYPE", "count": wg,
                      "message": f"{wg} datagrams start with a plain WireGuard message type (x 00 00 00)"})
    # L2: unpadded WireGuard handshake sizes
    sz = Counter(len(d.payload) for d in dgrams)
    fixed = {n: sz[n] for n in (148, 92, 64) if sz.get(n)}
    if fixed:
        leaks.append({"id": "L2-WG-SIZE", "sizes": fixed,
                      "message": f"datagrams with stock WireGuard handshake sizes: {fixed}"})
    if len(tr) >= 20:
        # L3: byte positions in the first 32 bytes constant across all transport packets
        width = min(32, min(len(p) for p in tr))
        const = [i for i in range(width) if len({p[i] for p in tr}) == 1]
        if const:
            leaks.append({"id": "L3-CONST-BYTES", "offsets": const,
                          "message": f"{len(const)} byte offsets constant across {len(tr)} transport packets: {const}"})
        # L4: incrementing little-endian counter at a fixed offset
        for off in range(0, width - 7):
            vals = [struct.unpack("<Q", p[off:off + 8])[0] for p in tr]
            steps = Counter(b - a for a, b in zip(vals, vals[1:]))
            if steps and steps.most_common(1)[0][0] == 1 and steps[1] >= 0.8 * (len(vals) - 1):
                leaks.append({"id": "L4-COUNTER", "offset": off,
                              "message": f"8-byte little-endian packet counter visible at offset {off}"})
                break
        # L5: all transport lengths share one residue mod 16
        res = {len(p) % 16 for p in tr}
        if len(res) == 1:
            leaks.append({"id": "L5-LEN-MOD16", "residue": res.pop(),
                          "message": f"all {len(tr)} transport lengths are congruent mod 16"})
    return leaks
